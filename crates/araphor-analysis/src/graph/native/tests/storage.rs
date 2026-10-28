use super::*;

use araphor_data::analysis::CanonicalGraph;
use araphor_data::AnalysisResultCommitV1;

struct NoAuthority;

impl araphor_data::NotificationAuthorization for NoAuthority {
    fn check(&self, _: &araphor_data::NotificationGrantV1, _: u64) -> araphor_data::Result<()> {
        Err(araphor_data::NotificationSnafu {
            code: araphor_data::NotificationErrorCodeV1::Denied,
            field: "Graph recovery fixture",
        }
        .build())
    }
}

impl Fixture {
    fn image_contexts(
        &self,
        publication: &GraphPublication,
    ) -> TestResult<Vec<AnalysisContextVersionV1>> {
        let mut contexts = publication
            .prepared
            .images()
            .map(|bundle| {
                AnalysisContextVersionV1::from_package(
                    bundle,
                    self.source.tenant_id,
                    &bundle.bundle().root,
                    "detect",
                    "subjects",
                )
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        contexts.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(contexts.len(), 3);
        Ok(contexts)
    }
}

#[tokio::test]
async fn graph_refs_use_header() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let expected = fixture.image_contexts(&publication)?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "storage-header",
            "SELECT * FROM events",
        )
        .await?;
    let receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let store = fixture.query.store();
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, receipt.commit_revision);
    assert_eq!(receipt.results.len(), 3);
    let id = head.result_id;
    let tenant = fixture.source.tenant_id;
    assert!(!store
        .graph_result(tenant, &id)?
        .ok_or("graph result")?
        .graph
        .subjects
        .is_empty());
    let before = store.meta()?;
    store.fault_write(
        "UPDATE graph_subject_values SET subject_kind = 255 WHERE tenant_id = ?",
        &[&tenant.as_slice()],
    )?;
    assert!(store.graph_result(tenant, &id).is_err());
    assert_eq!(
        store.graph_source(tenant, &id)?,
        Some(fixture.source.clone())
    );
    let (_, contexts) = store.package_evidence(tenant, std::slice::from_ref(&id))?;
    let pins = contexts
        .into_iter()
        .filter(|reference| reference.key.owner_id == "native-package-v1")
        .collect::<Vec<_>>();
    let references = expected
        .iter()
        .map(|context| AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: receipt.commit_revision,
        })
        .collect::<Vec<_>>();
    assert_eq!(pins, references);
    for (reference, context) in pins.iter().zip(expected) {
        assert_eq!(store.context_version(&reference.key)?, Some(context));
    }
    assert!(store.graph_source([0; 16], &id).is_err());
    assert!(store.graph_source(tenant, "").is_err());
    assert!(store.graph_source(tenant, "missing")?.is_none());
    assert!(store.graph_source([2; 16], &id)?.is_none());
    assert_eq!(
        store.package_evidence([2; 16], std::slice::from_ref(&id))?,
        (Vec::new(), Vec::new())
    );
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[tokio::test]
async fn graph_package_commit_refs() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let expected = fixture.image_contexts(&publication)?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "storage-original",
            "SELECT * FROM events",
        )
        .await?;
    let first = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let store = fixture.query.store();
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first.commit_revision);
    assert_eq!(first.results.len(), 3);
    let consumed = store
        .processor_health(&scope)?
        .ok_or("native Graph progress")?
        .consumed_cursor;
    assert_eq!(consumed, 3);
    let original = head.result_id;
    let tenant = fixture.source.tenant_id;
    let mut snapshot = store
        .graph_result(tenant, &original)?
        .ok_or("original graph")?;
    let (witnesses, contexts) = store.package_evidence(tenant, std::slice::from_ref(&original))?;
    snapshot.previous_result_id = Some(original);
    let pins = contexts
        .iter()
        .filter(|reference| reference.key.owner_id == "native-package-v1")
        .cloned()
        .collect::<Vec<_>>();
    let references = expected
        .iter()
        .map(|context| AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: first.commit_revision,
        })
        .collect::<Vec<_>>();
    assert_eq!(pins, references);
    let mut expected_refs = snapshot
        .input_manifest
        .context
        .iter()
        .map(|key| AnalysisContextRefV1 {
            key: key.clone(),
            commit_revision: first.commit_revision,
        })
        .chain(references.iter().cloned())
        .collect::<Vec<_>>();
    expected_refs.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(contexts, expected_refs);
    let reference = pins.first().ok_or("native package context")?;
    let context = store
        .context_version(&reference.key)?
        .ok_or("package context absent")?;
    let source = store
        .source_receipt(&fixture.source)?
        .ok_or("source receipt")?;
    let request = AnalysisResultCommitV1 {
        scope: snapshot.scope.clone(),
        expected_cursor: consumed,
        consumed_cursor: source.contiguous_cursor,
        coverage_revision: source.coverage_revision,
        context_revision: contexts
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0),
        result_id: "graph:storage-committed".into(),
        body: Vec::new(),
        created_utc_ns: snapshot
            .witness_deadline_utc_ns
            .checked_sub(araphor_data::GRAPH_WITNESS_TTL_NS)
            .ok_or("capture time")?,
        witnesses,
        context_refs: contexts.clone(),
    };
    let commit = |request| {
        store.commit_graph_snapshot(
            request,
            CanonicalGraph::new(snapshot.clone())?,
            &[],
            &pins,
            &[],
            true,
            || fixture.authority.check(&grant, PackageActionV1::Run),
        )
    };
    let before = store.meta()?;
    let mut changed = request.clone();
    changed
        .context_refs
        .iter_mut()
        .find(|value| value.key == reference.key)
        .ok_or("captured package reference")?
        .key
        .entity_key = b"other-result".to_vec();
    changed
        .context_refs
        .sort_by(|left, right| left.key.cmp(&right.key));
    assert!(commit(changed).is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.read_result(tenant, &request.result_id)?.is_none());
    store.fault_write(
        "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
        &[&b"invalid".as_slice(), &tenant.as_slice(), &reference.key.owner_id, &reference.key.entity_key, &reference.key.lifetime_key, &reference.key.owner_revision],
    )?;
    assert!(commit(request.clone()).is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.read_result(tenant, &request.result_id)?.is_none());
    store.fault_write(
        "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
        &[&context.body, &tenant.as_slice(), &reference.key.owner_id, &reference.key.entity_key, &reference.key.lifetime_key, &reference.key.owner_revision],
    )?;
    let receipt = commit(request.clone())?;
    let committed = store.meta()?;
    assert_eq!(committed.commit_revision, before.commit_revision + 1);
    assert_eq!(commit(request.clone())?, receipt);
    assert_eq!(store.meta()?, committed);
    let mut changed = request.clone();
    changed.created_utc_ns += 1;
    assert!(matches!(
        commit(changed),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, committed);
    assert_eq!(
        store.graph_result(tenant, &request.result_id)?,
        Some(snapshot.clone())
    );
    let (_, retained) = store.package_evidence(tenant, std::slice::from_ref(&request.result_id))?;
    assert_eq!(retained, contexts);
    assert_eq!(
        retained
            .iter()
            .filter(|reference| reference.key.owner_id == "native-package-v1")
            .cloned()
            .collect::<Vec<_>>(),
        references
    );
    for (reference, context) in pins.iter().zip(expected) {
        assert_eq!(store.context_version(&reference.key)?, Some(context));
    }
    let retained = store
        .processor_result(&request.scope)?
        .ok_or("committed graph absent")?;
    assert_eq!(retained.result_id, request.result_id);
    assert_eq!(retained.commit_revision, receipt.commit_revision);
    assert_eq!(
        store.graph_result(tenant, &retained.result_id)?,
        Some(snapshot.clone())
    );
    let original = snapshot
        .previous_result_id
        .as_ref()
        .ok_or("Original Graph ID")?;
    let original_body = store
        .read_result(tenant, original)?
        .ok_or("Original Graph bytes")?;
    let finding = snapshot
        .findings
        .first()
        .ok_or("Historical Graph finding")?
        .clone();
    let router = crate::NotificationRouter::new(Arc::clone(store), Arc::new(NoAuthority))?;
    assert_eq!(
        router.route_finding(
            tenant,
            &araphor_data::NotificationFindingRefV1 {
                result_id: request.result_id.clone(),
                finding_id: finding.finding_id.clone(),
            },
            request.created_utc_ns
        )?,
        1
    );
    let notification = store
        .notification_states(
            tenant,
            araphor_data::analysis::NotificationLookup::Finding(
                &finding.finding_id,
                finding.required_action.as_deref(),
            ),
        )?
        .remove(0);
    let obligation = araphor_data::NotificationObligationV1::try_from(&notification)?;
    assert_eq!(
        obligation
            .finding
            .as_ref()
            .ok_or("Notification finding")?
            .result_id,
        request.result_id
    );
    let mut empty = snapshot.clone();
    empty.findings.clear();
    empty.previous_result_id = Some(request.result_id.clone());
    let mut replacement = request.clone();
    replacement.result_id = "graph:storage-removed".into();
    replacement.expected_cursor = receipt.consumed_cursor;
    replacement.created_utc_ns += 1;
    replacement.body.clear();
    store.commit_graph_snapshot(
        replacement.clone(),
        CanonicalGraph::new(empty.clone())?,
        &[],
        &pins,
        &[],
        false,
        || fixture.authority.check(&grant, PackageActionV1::Run),
    )?;
    assert!(store
        .graph_findings(tenant, None, None, usize::MAX)?
        .is_empty());
    assert!(store
        .graph_finding(tenant, &replacement.result_id, &finding.finding_id)?
        .is_none());
    let check = |store: &AnalysisStore| -> TestResult {
        assert_eq!(
            store.read_result(tenant, original)?,
            Some(original_body.clone())
        );
        assert_eq!(
            store.read_result(tenant, &request.result_id)?,
            Some(retained.body.clone())
        );
        assert_eq!(
            store.graph_result(tenant, &replacement.result_id)?,
            Some(empty.clone())
        );
        assert_eq!(
            store.graph_finding(tenant, &request.result_id, &finding.finding_id)?,
            Some((finding.clone(), snapshot.input_manifest.clone()))
        );
        assert_eq!(
            store.graph_result(tenant, &replacement.result_id)?,
            Some(empty.clone())
        );
        assert_eq!(
            store.context_version(&notification.key)?,
            Some(notification.clone())
        );
        let progress = store
            .processor_result(&request.scope)?
            .ok_or("Restored Graph progress")?;
        assert_eq!(progress.result_id, request.result_id);
        assert_eq!(progress.body, retained.body);
        store.verify_state()?;
        Ok(())
    };
    check(store)?;
    let backup = fixture._directory.path().join("data/backups/graph-history");
    let manifest = store.backup(&backup)?;
    let target = fixture._directory.path().join("graph-restored");
    let restored = AnalysisStore::restore(&backup, &target)?;
    assert_eq!(
        restored.meta()?.schema_version,
        araphor_data::analysis::ANALYSIS_SCHEMA_VERSION as u32
    );
    assert_eq!(restored.meta()?.store_uuid, store.meta()?.store_uuid);
    assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
    assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
    check(&restored)?;
    drop(restored);
    check(&AnalysisStore::open(&target)?)?;
    for (index, fault) in [
        "DELETE FROM graph_finding_membership",
        "UPDATE graph_subject_values SET subject_kind = 255",
        "UPDATE graph_finding_membership SET lineage_id = 999999",
        "UPDATE graph_finding_values SET tenant_id = 'foreign'::BLOB",
        "DROP TABLE graph_relationships",
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE processor_id = 'graph-findings'",
        "UPDATE analysis_results SET method_version = 99 WHERE processor_id = 'graph-findings'",
        "UPDATE analysis_results SET first_cursor = 99 WHERE processor_id = 'graph-findings'",
    ]
    .into_iter()
    .enumerate()
    {
        let root = fixture
            ._directory
            .path()
            .join(format!("graph-corrupt-{index}"));
        let corrupted = AnalysisStore::restore(&backup, &root)?;
        corrupted.fault_write(fault, &[])?;
        drop(corrupted);
        assert!(AnalysisStore::open(&root).is_err(), "Accepted {fault}");
    }
    Ok(())
}
