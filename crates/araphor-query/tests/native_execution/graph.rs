use super::*;

pub(super) fn descriptor() -> sdk::Package {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, true)]);
    let mut model = sdk::Model::new(
        "index",
        vec![
            sdk::Port::new("after", schema.clone()),
            sdk::Port::new("before", schema.clone()),
            sdk::Port::new("affected", schema.clone()),
            sdk::ChangeInputs::reset_port("reset"),
        ],
        vec![sdk::Port::new("frontier", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    let query = |image: &str| {
        format!(
            "SELECT owner_revision AS value FROM {image}context_versions WHERE owner_id = 'graph-fixture'"
        )
    };
    for (input, query) in model.inputs.iter_mut().zip([
        query(""),
        format!(
            "SELECT source.* FROM ({}) source JOIN affected USING (value)",
            query("before.")
        ),
        "SELECT value FROM inserted.after UNION SELECT value FROM removed.after".into(),
    ]) {
        input.source = sdk::InputSource::Query(query);
    }
    model.change_inputs = Some(sdk::ChangeInputs {
        reset: "reset".into(),
        ports: vec![sdk::ChangeInput {
            affected: "affected".into(),
            before: "before".into(),
            after: "after".into(),
            current: Some(format!(
                "SELECT source.* FROM ({}) source JOIN affected USING (value)",
                query("after.")
            )),
        }],
    });
    model.graph = Some(sdk::GraphSpec {
        access: sdk::GraphAccess::ReadWrite,
        relations: vec![
            sdk::GraphRelation {
                name: "nodes".into(),
                kind: sdk::GraphKind::Node,
                properties: schema.clone(),
            },
            sdk::GraphRelation {
                name: "links".into(),
                kind: sdk::GraphKind::Edge {
                    from: "nodes".into(),
                    to: "nodes".into(),
                },
                properties: schema,
            },
        ],
    });
    sdk::Package::new("runtime-fixture", "1", vec![model])
}

pub(super) fn image() -> araphor_package::Result<PackageBundle> {
    let descriptor = descriptor();
    let artifact = PackageArtifactV1 {
        implementations: vec![PackageImplementationV1::Wasm {
            exports: descriptor
                .exports
                .iter()
                .map(|model| model.name.clone())
                .collect(),
            artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
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

pub(super) fn input(revision: u64) -> TestResult<AnalysisContextVersionV1> {
    Ok(context("graph-fixture", revision))
}

pub(super) fn links(store: &NativeStore) -> TestResult<Vec<[Vec<u8>; 3]>> {
    let view = store.view()?;
    let mapping = view
        .managed_graph(TENANT, "native-query", &AnalysisReadControl::default())?
        .ok_or("graph mapping")?;
    let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
        view.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    let relation = mapping.relations["links"].0;
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
    store.commit_contexts(&[input(1)?])?;
    let (definition, publication) = prepare(
        &engine,
        &image()?,
        &sql(r#"SELECT * FROM "runtime-fixture"."1".index('frontier')"#),
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
    store.commit_contexts(&[input(2)?])?;
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
    let descriptor = descriptor();
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
    for name in ["affected", "after"] {
        let input = returned
            .evaluation()
            .inputs
            .iter()
            .find(|input| input.data.name == name)
            .ok_or("changed fixture input")?;
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
