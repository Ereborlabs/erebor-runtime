use std::sync::mpsc::TryRecvError;

use super::*;

struct Fixture {
    owner: GraphAndFindingOwner,
    execution: InstalledAnalysis,
    provider: Arc<NoticeInputs>,
    store: Arc<AnalysisStore>,
    observation: DiscoveryRecordV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let fixture = Self::uncovered()?;
        coverage(&fixture.store, 1, 1, "HEALTHY")?;
        Ok(fixture)
    }

    fn uncovered() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let provider = Arc::new(NoticeInputs::default());
        let execution = InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
        let owner = GraphAndFindingOwner::new(store.clone(), provider.clone(), execution.clone())?;
        let observation = record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?;
        accept(&store, std::slice::from_ref(&observation))?;
        Ok(Self {
            owner,
            execution,
            provider,
            store,
            observation,
            _directory: directory,
        })
    }

    fn commit(&self) -> TestResult {
        assert_eq!(self.owner.process(10)?, 1);
        Ok(())
    }

    fn process(&self, now: u64) -> Result<usize> {
        assert_eq!(self.owner.process(now)?, 0);
        self.owner.process(now)
    }

    fn set_facts(&self, facts: Vec<AnalysisContextVersionV1>) -> TestResult {
        *self.provider.facts.0.lock().map_err(|_| "fixture facts")? = facts;
        Ok(())
    }

    fn unrelated_coverage(&self, revision: u64, interval: u8) -> TestResult {
        use prost::Message as _;

        let report = CoverageReport {
            source_id: source().source_id.to_vec(),
            cpu_id: 0,
            source_epoch: source().source_epoch,
            revision,
            intervals: vec![CoverageInterval {
                interval_id: vec![interval; 16],
                source_epoch: source().source_epoch,
                revision,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(1),
                opening_counters: Some(Default::default()),
                closing_counters: Some(CoverageCounters {
                    attempted: 1,
                    requested: 1,
                    emitted: 1,
                    next_sequence: 2,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        self.store.accept_validated_coverage(ValidatedCoverageV1 {
            identity: source(),
            cpu_id: 0,
            revision,
            encoded_report: report.encode_to_vec(),
        })?;
        Ok(())
    }
}

#[test]
fn unchanged_notice_skips_guest() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit()?;
    let head = fixture
        .store
        .processor_result(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("graph head")?;
    let snapshot = fixture
        .owner
        .snapshot_result(source().tenant_id, &head.result_id)?
        .ok_or("graph snapshot")?;
    let body = fixture
        .store
        .read_result(source().tenant_id, &head.result_id)?;
    let health = fixture.store.processor_health(&snapshot.scope)?;
    let entered = fixture.execution.testing_owner().observe_guest()?;
    fixture.provider.revision.store(1, Ordering::SeqCst);
    assert_eq!(fixture.process(11)?, 0);
    assert_eq!(entered.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .store
            .graph_notice(&snapshot.scope, &head.result_id, head.commit_revision)?,
        Some((1, 1))
    );
    assert_eq!(fixture.store.processor_health(&snapshot.scope)?, health);
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &head.result_id)?,
        body
    );
    fixture.set_facts(vec![
        policy(&fixture.observation, 1)?,
        activation(&fixture.observation)?,
    ])?;
    fixture.provider.revision.store(2, Ordering::SeqCst);
    assert_eq!(fixture.process(12)?, 1);
    assert_eq!(entered.try_recv(), Ok(()));
    let current = fixture.owner.current_findings(source().tenant_id)?;
    let id = &current.first().ok_or("replacement finding")?.0;
    assert_ne!(id, &head.result_id);
    let replacement = fixture
        .owner
        .snapshot_result(source().tenant_id, id)?
        .ok_or("replacement snapshot")?;
    assert_eq!(
        replacement.previous_result_id.as_ref(),
        Some(&head.result_id)
    );
    assert_ne!(replacement.input_manifest, snapshot.input_manifest);
    assert_eq!(
        replacement.witness_deadline_utc_ns,
        snapshot.witness_deadline_utc_ns
    );
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &head.result_id)?,
        body
    );
    Ok(())
}

#[test]
fn forced_refresh_runs_guest() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit()?;
    let head = fixture
        .store
        .processor_result(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("graph head")?;
    let body = fixture
        .store
        .read_result(source().tenant_id, &head.result_id)?;
    let entered = fixture.execution.testing_owner().observe_guest()?;
    assert!(!fixture.owner.refresh(&source(), 11)?);
    assert_eq!(entered.try_recv(), Ok(()));
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &head.result_id)?,
        body
    );
    assert_eq!(
        fixture.store.graph_notice(
            &GraphAndFindingOwner::scope(&source()),
            &head.result_id,
            head.commit_revision,
        )?,
        Some((0, 1))
    );
    Ok(())
}

#[test]
fn unrelated_coverage_runs_guest() -> TestResult {
    let fixture = Fixture::uncovered()?;
    fixture.unrelated_coverage(1, 8)?;
    fixture.commit()?;
    let scope = GraphAndFindingOwner::scope(&source());
    let head = fixture
        .store
        .processor_result(&scope)?
        .ok_or("graph head")?;
    let snapshot = fixture
        .owner
        .snapshot_result(source().tenant_id, &head.result_id)?
        .ok_or("graph snapshot")?;
    assert!(snapshot.input_manifest.coverage.is_empty());
    let status = fixture
        .store
        .source_status(&source())?
        .ok_or("source status")?;
    assert_eq!(status.receipt.coverage_revision, 1);
    let (before, keys) =
        fixture
            .owner
            .coverage(&status, std::slice::from_ref(&fixture.observation), &[])?;
    assert!(keys.is_empty());
    let body = fixture
        .store
        .read_result(source().tenant_id, &head.result_id)?;
    let entered = fixture.execution.testing_owner().observe_guest()?;
    fixture.unrelated_coverage(2, 9)?;
    let status = fixture
        .store
        .source_status(&source())?
        .ok_or("new source status")?;
    assert_eq!(status.receipt.coverage_revision, 2);
    let (after, keys) = fixture.owner.coverage(
        &status,
        std::slice::from_ref(&fixture.observation),
        &snapshot.input_manifest.coverage,
    )?;
    assert!(keys.is_empty());
    assert_ne!(before, after);
    assert_eq!(fixture.provider.revision.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.process(11)?, 0);
    assert_eq!(entered.try_recv(), Ok(()));
    assert_eq!(
        fixture
            .store
            .graph_notice(&scope, &head.result_id, head.commit_revision)?,
        Some((0, 2))
    );
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &head.result_id)?,
        body
    );
    assert_eq!(fixture.store.processor_result(&scope)?, Some(head));
    Ok(())
}

#[test]
fn changed_context_precedes_reuse() -> TestResult {
    let fixture = Fixture::new()?;
    let mut original = policy(&fixture.observation, 1)?;
    original.valid_from_utc_ns = Some(1);
    original.valid_until_utc_ns = Some(10_000);
    let active = activation(&fixture.observation)?;
    fixture.set_facts(vec![original.clone(), active.clone()])?;
    fixture.commit()?;
    let scope = GraphAndFindingOwner::scope(&source());
    let head = fixture
        .store
        .processor_result(&scope)?
        .ok_or("graph head")?;
    let body = fixture
        .store
        .read_result(source().tenant_id, &head.result_id)?;
    let entered = fixture.execution.testing_owner().observe_guest()?;
    for change in ["json", "valid-from", "valid-until", "sensitivity"] {
        let mut changed = original.clone();
        match change {
            "json" => changed.body.push(b' '),
            "valid-from" => changed.valid_from_utc_ns = Some(2),
            "valid-until" => changed.valid_until_utc_ns = Some(10_001),
            "sensitivity" => changed.sensitivity = ContextSensitivityV1::HostRestricted,
            _ => unreachable!(),
        }
        fixture.set_facts(vec![changed, active.clone()])?;
        fixture.provider.revision.fetch_add(1, Ordering::SeqCst);
        let error = fixture.process(11).expect_err("changed context accepted");
        assert!(
            matches!(
                &error,
                Error::GraphInvalid {
                    field: "changed immutable context",
                    ..
                }
            ),
            "{change}: {error:?}"
        );
        assert_eq!(entered.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(
            fixture
                .store
                .read_result(source().tenant_id, &head.result_id)?,
            body
        );
        assert_eq!(fixture.store.processor_result(&scope)?, Some(head.clone()));
        assert_eq!(
            fixture.store.context_version(&original.key)?,
            Some(original.clone())
        );
        assert_eq!(
            fixture
                .store
                .graph_notice(&scope, &head.result_id, head.commit_revision)?,
            Some((0, 1))
        );
        assert_eq!(
            fixture
                .store
                .processor_health(&scope)?
                .ok_or("failed health")?
                .state,
            ProcessorStateV1::ProcessingFailed
        );
    }
    fixture.set_facts(vec![original, active])?;
    fixture.provider.revision.fetch_add(1, Ordering::SeqCst);
    assert_eq!(fixture.process(12)?, 0);
    assert_eq!(entered.try_recv(), Ok(()));
    assert_eq!(
        fixture
            .store
            .processor_health(&scope)?
            .ok_or("recovered health")?
            .state,
        ProcessorStateV1::Current
    );
    assert_eq!(
        fixture
            .store
            .graph_notice(&scope, &head.result_id, head.commit_revision)?,
        Some((5, 1))
    );
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &head.result_id)?,
        body
    );
    assert_eq!(fixture.store.processor_result(&scope)?, Some(head));
    Ok(())
}
