use super::*;
use araphor_analysis_builtins::causal::{
    model::{Action, Audit, Credential, Outcome},
    Causal,
};
use araphor_analysis_types::{
    source::DiscoveryRecordIdV1,
    values::{
        LocalSubjectBindingV1, OperationResultAuthorityV1, ProofIntegrityV1, ProofQualityV1,
        RemoteSubjectBindingV1, SourceAuthorityV1, TemporalCoverageV1,
    },
};

fn image() -> araphor_package::Result<PackageBundle> {
    let descriptor = Causal::descriptor();
    let artifact = PackageArtifactV1 {
        implementations: vec![PackageImplementationV1::Wasm {
            exports: descriptor
                .exports
                .iter()
                .map(|model| model.name.clone())
                .collect(),
            artifact: araphor_analysis_builtins::components::CAUSAL.to_vec(),
        }],
        descriptor,
        fixtures: Vec::new(),
    };
    PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })
}

fn audit(revision: u64) -> TestResult<AnalysisContextVersionV1> {
    let audit = Audit {
        schema_version: 1,
        record: DiscoveryRecordIdV1 {
            stream: source(TENANT),
            durable_cursor: revision,
            cpu_id: 0,
        },
        task: 10,
        process: [7; 16],
        outcome: Outcome::Succeeded,
        status_code: None,
        proof: ProofQualityV1 {
            source_authority: SourceAuthorityV1::AuthoritativeProvider,
            local_subject_binding: LocalSubjectBindingV1::ExactTask,
            remote_subject_binding: RemoteSubjectBindingV1::ExactObject,
            operation_result_authority: OperationResultAuthorityV1::AuthoritativeSucceeded,
            temporal_coverage: TemporalCoverageV1::Complete,
            integrity: ProofIntegrityV1::AuthenticatedChannel,
        },
        action: Action::CredentialAccess {
            credential: Credential {
                authority: "cluster".into(),
                lease: format!("lease-{revision}"),
                principal: "service".into(),
            },
            object: [8; 16],
            completion: format!("read-{revision}"),
            result: 8,
            bytes: 8,
        },
    };
    let mut value = context(Audit::OWNER, revision);
    value.body = audit.encode()?;
    Ok(value)
}

fn links(store: &NativeStore) -> TestResult<Vec<[Vec<u8>; 3]>> {
    let view = store.view()?;
    let mapping = view
        .managed_graph(TENANT, "native-query", &AnalysisReadControl::default())?
        .ok_or("graph mapping")?;
    let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
        view.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    let relation = mapping.relations["causal_links_v1"].0;
    let writer = *mapping.writers.values().next().ok_or("graph writer")?;
    let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
    let mut links = Vec::new();
    graph.visit(
        relation,
        araphor_graph::Read::Owned(writer),
        &keys,
        &|_, _, _| Ok(None),
        |member| {
            links.push(member.endpoints.ok_or_else(|| {
                araphor_graph::Error::backend(Code::Missing.error("edge endpoints"))
            })?);
            Ok(())
        },
    )?;
    links.sort();
    Ok(links)
}

#[tokio::test]
async fn package_graph_and_consumption_commit_together() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_contexts(&[audit(1)?])?;
    let (definition, publication) = prepare(
        &engine,
        &image()?,
        &sql(r#"SELECT * FROM "HF-CAUSAL-001"."1".index('frontier')"#),
    )
    .await?;
    let mut stream = subscribe(&engine, definition.clone(), publication.clone())?;
    let first = next(&mut stream).await?;
    let first_receipt = publication.receipt();
    assert_eq!(first.calls.len(), 1);
    assert!(first.calls.values().next().ok_or("call")?.graph().is_some());
    let before = links(&store)?;
    assert_eq!(before.len(), 3);
    publication.assert_consumed(first.cursor.position())?;
    store.commit_contexts(&[audit(2)?])?;
    event(&store, TENANT, 2)?;
    publication
        .reject
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(next(&mut stream).await.is_err());
    assert_eq!(links(&store)?, before);
    publication.assert_consumed(first.cursor.position())?;
    stream.cancel_and_join().await?;
    publication.finish_cancelled()?;
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let retried = next(&mut stream).await?;
    let (&call, returned) = retried.calls.first_key_value().ok_or("retried call")?;
    assert_eq!(
        returned.changes().ok_or("indexed changes")?.base.as_ref(),
        Some(&first_receipt.results[&call])
    );
    let descriptor = Causal::descriptor();
    let model = descriptor
        .exports
        .iter()
        .find(|model| model.name == "index")
        .ok_or("index model")?;
    assert!(!model
        .change_inputs
        .as_ref()
        .ok_or("change contract")?
        .is_reset(returned.evaluation())?);
    for name in ["audit_affected", "audit_after"] {
        let input = returned
            .evaluation()
            .inputs
            .iter()
            .find(|input| input.data.name == name)
            .ok_or("changed audit input")?;
        assert_eq!(input.data.rows(), 1);
    }
    publication.assert_consumed(retried.cursor.position())?;
    let changed = links(&store)?;
    assert_eq!(changed.len(), 6);
    assert!(before.iter().all(|link| changed.contains(link)));
    assert_ne!(changed, before);
    stream.cancel_and_join().await?;
    Ok(())
}
