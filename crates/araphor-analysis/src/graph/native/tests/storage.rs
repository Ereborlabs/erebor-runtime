use super::*;

use araphor_data::analysis::CanonicalGraph;
use araphor_data::AnalysisResultCommitV1;

impl Fixture {
    fn image_contexts(
        &self,
        publication: &GraphPublication,
    ) -> TestResult<Vec<AnalysisContextVersionV1>> {
        let mut contexts = publication
            .prepared
            .images()
            .map(|(bundle, digest)| {
                PackageBundleRef::retained(bundle, digest).context(
                    self.source.tenant_id,
                    &bundle.root,
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
    let (id, receipt) = publication.refresh("graph:storage-header".into()).await?;
    let store = fixture.query.store();
    let tenant = fixture.source.tenant_id;
    assert!(!store
        .graph_result(tenant, &id)?
        .ok_or("graph result")?
        .graph
        .subjects
        .is_empty());
    let before = store.meta()?;
    store.fault_write(
        "UPDATE graph_subjects SET subject_kind = repeat('X', length(subject_kind)) WHERE result_id = ?",
        &[&id],
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
    let (original, first) = publication.refresh("graph:storage-original".into()).await?;
    let store = fixture.query.store();
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
        expected_cursor: 0,
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
            CanonicalGraph::bounded(snapshot.clone(), usize::MAX)?,
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
    assert_eq!(retained.body, serde_json::to_vec(&snapshot)?);
    Ok(())
}
