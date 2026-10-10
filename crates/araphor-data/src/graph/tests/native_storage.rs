use super::*;

pub(crate) struct CommitFixture {
    pub(crate) owner: GraphAndFindingOwner,
    pub(crate) store: Arc<AnalysisStore>,
    pub(crate) snapshot: GraphSnapshotV1,
    pub(crate) request: AnalysisResultCommitV1,
    pub(crate) directory: tempfile::TempDir,
}

impl CommitFixture {
    pub(crate) fn add_findings(&mut self, count: usize) -> TestResult {
        for index in 0..count {
            let mut finding = self.snapshot.findings[0].clone();
            finding.finding_id = format!("finding-{index}");
            self.snapshot.findings.push(finding);
        }
        self.snapshot
            .findings
            .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        self.request.body = serde_json::to_vec(&self.snapshot)?;
        Ok(())
    }

    pub(crate) fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
        let observation = record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?;
        accept(&store, std::slice::from_ref(&observation))?;
        coverage(&store, 1, 1, "HEALTHY")?;
        let mut snapshot = GraphAndFindingOwner::derive(&input(vec![observation]))?;
        snapshot.witness_deadline_utc_ns = 10 + GRAPH_WITNESS_TTL_NS;
        let request = AnalysisResultCommitV1 {
            scope: snapshot.scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 1,
            context_revision: 0,
            result_id: "graph:native-storage".into(),
            body: serde_json::to_vec(&snapshot)?,
            created_utc_ns: 10,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source().into(),
                cursor: 1,
                expires_utc_ns: snapshot.witness_deadline_utc_ns,
            }],
            context_refs: vec![],
        };
        Ok(Self {
            directory,
            owner,
            store,
            snapshot,
            request,
        })
    }
}

#[test]
fn graph_native_commit_retry() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &fixture.request.result_id)?,
        Some(fixture.request.body.clone())
    );
    let result = fixture
        .store
        .processor_result(&fixture.request.scope)?
        .ok_or("result")?;
    assert_eq!(result.body, fixture.request.body);
    assert_eq!(result.commit_revision, receipt.commit_revision);
    assert_eq!(
        fixture.owner.snapshot(&source())?,
        Some(fixture.snapshot.clone())
    );

    let mut changed = fixture.request.clone();
    let mut snapshot = fixture.snapshot.clone();
    snapshot.findings[0].limits.push("RETRY_CHANGED".into());
    snapshot.findings[0].limits.sort();
    changed.body = serde_json::to_vec(&snapshot)?;
    assert!(matches!(
        fixture.store.commit_graph(&changed, true),
        Err(Error::AnalysisConflict { .. })
    ));
    changed = fixture.request.clone();
    changed.created_utc_ns += 1;
    assert!(matches!(
        fixture.store.commit_graph(&changed, true),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.store.meta()?.commit_revision,
        receipt.commit_revision
    );

    let CommitFixture {
        directory,
        owner,
        store,
        request,
        snapshot,
    } = fixture;
    drop(owner);
    drop(store);
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    assert_eq!(store.commit_graph(&request, true)?, receipt);
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &request.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        store.read_result(source().tenant_id, &request.result_id)?,
        Some(request.body)
    );
    Ok(())
}

#[test]
fn graph_native_commit_rollback() -> TestResult {
    let fixture = CommitFixture::new()?;
    let meta = fixture.store.meta()?;
    let usage = fixture.store.witness_usage(source().tenant_id, 10)?;
    fixture
        .store
        .set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
            GraphInvalidSnafu {
                field: "injected graph commit failure",
            }
            .fail()
        })?;
    assert!(fixture.store.commit_graph(&fixture.request, true).is_err());
    assert_eq!(fixture.store.meta()?, meta);
    assert_eq!(fixture.store.witness_usage(source().tenant_id, 10)?, usage);
    assert!(fixture
        .store
        .read_result(source().tenant_id, &fixture.request.result_id)?
        .is_none());
    assert!(fixture
        .owner
        .current_findings(source().tenant_id)?
        .is_empty());
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.request.scope)?
            .ok_or("health")?
            .consumed_cursor,
        0
    );
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    assert_eq!(fixture.owner.current_findings(source().tenant_id)?.len(), 1);
    Ok(())
}

#[test]
fn graph_native_encoding_exact() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut request = fixture.request.clone();
    request.body = serde_json::to_vec_pretty(&fixture.snapshot)?;
    let receipt = fixture.store.commit_graph(&request, true)?;
    assert_eq!(fixture.store.commit_graph(&request, true)?, receipt);
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &request.result_id)?,
        Some(request.body)
    );
    assert_eq!(fixture.owner.snapshot(&source())?, Some(fixture.snapshot));
    assert!(matches!(
        fixture.store.commit_graph(&fixture.request, true),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.store.meta()?.commit_revision,
        receipt.commit_revision
    );
    assert!(fixture
        .store
        .read_result([99; 16], &request.result_id)?
        .is_none());
    Ok(())
}

#[test]
fn graph_native_replacement_removal() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let original = fixture.snapshot.findings[0].clone();
    let mut replacement = fixture.snapshot.clone();
    replacement.findings.clear();
    replacement.previous_result_id = Some(fixture.request.result_id.clone());
    let mut request = fixture.request.clone();
    request.expected_cursor = 1;
    request.result_id = "graph:native-replacement".into();
    request.created_utc_ns += 1;
    request.body = serde_json::to_vec(&replacement)?;
    fixture.store.commit_graph(&request, false)?;
    assert!(fixture
        .owner
        .current_findings(source().tenant_id)?
        .is_empty());
    assert!(fixture
        .owner
        .current_finding(source().tenant_id, &original.finding_id)?
        .is_none());
    assert!(fixture
        .owner
        .next_current_finding(source().tenant_id, None)?
        .is_none());
    assert_eq!(
        fixture.owner.finding_result(
            source().tenant_id,
            &fixture.request.result_id,
            &original.finding_id
        )?,
        Some(original.clone())
    );
    assert!(fixture
        .owner
        .finding_result(source().tenant_id, &request.result_id, &original.finding_id)?
        .is_none());
    assert_eq!(
        fixture
            .owner
            .snapshot_result(source().tenant_id, &request.result_id)?,
        Some(replacement)
    );
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &fixture.request.result_id)?,
        Some(fixture.request.body)
    );
    Ok(())
}
