use super::*;
use araphor_data::analysis::native::{ManagedCommit, ManagedReturn};

fn fixture(
    store: &NativeStore,
) -> Result<(ManagedInstance, sdk::Model), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(store, [1; 16], "qualified-graph", true)?;
    let descriptor = store
        .view()?
        .package_revision(
            [1; 16],
            "managed-graph",
            "1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("package")?;
    let package: sdk::Package = serde_json::from_slice(&descriptor.descriptor)?;
    let model = package.exports[0].clone();
    let mut second = model.clone();
    second.graph.as_mut().ok_or("second Graph")?.relations = vec![sdk::GraphRelation {
        name: "unreturned".into(),
        kind: sdk::GraphKind::Node,
        properties: model.outputs[0].schema.clone(),
    }];
    let second = Fixture::with_package(store, [1; 16], "unreturned", second, "unreturned-graph")?;
    let mut call = second.spec.manifest.calls[&10].clone();
    call.dependencies.insert(10);
    fixture.spec.manifest.calls.insert(20, call);
    let sql = r#"WITH unused AS (SELECT * FROM "unreturned-graph"."1".count()) SELECT * FROM "managed-graph"."1".count()"#;
    fixture.spec.definition = definition(&fixture.spec, sql)?;
    fixture.spec.manifest.definition =
        store.admit_definition([1; 16], &fixture.spec.definition, || Ok(()))?;
    let admitted = fixture.admit(store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    Ok((instance, model))
}

fn definition(
    spec: &ManagedSpec,
    sql: &str,
) -> araphor_discovery_definition::Result<ResolvedDefinition> {
    ResolvedDefinition::new(
        Definition {
            name: "qualified-graph".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        },
        sql.into(),
        vec![
            spec.manifest.calls[&10].image.clone(),
            spec.manifest.calls[&20].image.clone(),
        ],
    )
}

fn journal(
    store: &NativeStore,
    attempt: &Arc<araphor_data::ManagedAttempt>,
    model: &sdk::Model,
) -> Result<Arc<araphor_data::analysis::native::ManagedGraphJournal>, Box<dyn std::error::Error>> {
    let control = AnalysisReadControl::default();
    let producer = ManagedGraphTransaction::new(
        store,
        Arc::clone(attempt),
        10,
        model,
        Vec::new(),
        Arc::new(Budget),
        &control,
    )?;
    producer.stage(
        store,
        "task",
        node(&producer, b"task-a")?,
        Arc::new(()),
        &control,
    )?;
    Ok(producer.freeze(store, &control)?)
}

#[test]
fn publication_checks_unreturned_relation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (instance, model) = fixture(&store)?;
    let captured = super::super::attempts::capture(&store, &instance, false)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &captured.state,
        &super::super::attempts::request("partial", false),
        || Ok(()),
    )?);
    let journal = journal(&store, &attempt, &model)?;
    let evaluation = super::super::publication::evaluation(&attempt);
    let output = super::super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: Some(&journal),
        retained: None,
    }];
    let control = AnalysisReadControl::default();
    let input = ManagedCommit {
        control: &control,
        budget: &Budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let prepared = store.prepare_managed(&input)?;
    let view = store.view()?;
    let mut mapping = view
        .managed_graph([1; 16], &instance.spec.id, &control)?
        .ok_or("mapping")?;
    let key = [b"\0data/G".as_slice(), &mapping.graph.to_be_bytes()].concat();
    let original = view.snapshot().get(&key)?.ok_or("stored mapping")?;
    mapping
        .relations
        .get_mut("unreturned")
        .ok_or("unreturned relation")?
        .1
        .properties = sdk::Schema::new(vec![sdk::Field::new(
        "count",
        sdk::DataType::Boolean,
        false,
    )]);
    let mut bytes = vec![0];
    bytes.extend(rmp_serde::to_vec_named(&mapping)?);
    let mut tx = store.write()?;
    tx.native().insert(&key, bytes);
    tx.commit([])?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let error = store
        .commit_managed(prepared, || Ok(()))
        .err()
        .ok_or("unreturned relation change accepted")?;
    assert!(matches!(
        error,
        Error::Package {
            code: Code::Conflict,
            field: "Graph relation declaration changed",
            ..
        }
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut tx = store.write()?;
    tx.native().insert(key, original);
    tx.commit([])?;
    let receipt = store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
    assert_eq!(receipt.results.len(), 1);
    assert!(receipt.results.contains_key(&10));
    assert!(!receipt.results.contains_key(&20));
    let view = store.view()?;
    let mapping = view
        .managed_graph([1; 16], &instance.spec.id, &control)?
        .ok_or("mapping")?;
    let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
        view.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert!(graph.head(mapping.writers[&10])?.is_some());
    assert_eq!(graph.head(mapping.writers[&20])?, None);
    Ok(())
}

#[test]
fn publication_keeps_candidate_mappings() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (instance, model) = fixture(&store)?;
    let captured = super::super::attempts::capture(&store, &instance, false)?;
    let control = AnalysisReadControl::default();
    let mut updated = instance.spec.clone();
    let mut extra = updated.manifest.calls[&20].clone();
    extra.dependencies.insert(20);
    updated.manifest.calls.insert(30, extra);
    let sql = r#"WITH one AS (SELECT * FROM "managed-graph"."1".count()), two AS (SELECT * FROM "unreturned-graph"."1".count()) SELECT * FROM "unreturned-graph"."1".count()"#;
    updated.definition = definition(&updated, sql)?;
    updated.manifest.definition =
        store.admit_definition([1; 16], &updated.definition, || Ok(()))?;
    store.prepare_managed_version(&instance, &updated, || Ok(()))?;
    let extended = store
        .view()?
        .managed_graph([1; 16], &instance.spec.id, &control)?
        .ok_or("extended mapping")?;
    assert_eq!(extended.writers.len(), 3);
    assert!(extended.writers.contains_key(&30));
    let attempt = Arc::new(store.register_managed_attempt(
        &captured.state,
        &super::super::attempts::request("candidate", false),
        || Ok(()),
    )?);
    let journal = journal(&store, &attempt, &model)?;
    let evaluation = super::super::publication::evaluation(&attempt);
    let output = super::super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: Some(&journal),
        retained: None,
    }];
    let input = ManagedCommit {
        control: &control,
        budget: &Budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let prepared = store.prepare_managed(&input)?;
    let receipt = store.commit_managed(prepared, || Ok(()))?;
    assert_eq!(receipt.results.len(), 1);
    let current = store.view()?;
    let mapping = current
        .managed_graph([1; 16], &instance.spec.id, &control)?
        .ok_or("current mapping")?;
    assert_eq!(mapping, extended);
    assert_eq!(
        current
            .managed_instance([1; 16], &instance.spec.id, &control)?
            .ok_or("current instance")?
            .generation,
        instance.generation
    );
    let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
        current.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert!(graph.head(mapping.writers[&10])?.is_some());
    assert_eq!(graph.head(mapping.writers[&20])?, None);
    assert_eq!(graph.head(mapping.writers[&30])?, None);
    drop((graph, current, journal, attempt, captured, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .view()?
            .managed_graph([1; 16], &instance.spec.id, &control)?
            .ok_or("reopened mapping")?,
        extended
    );
    Ok(())
}
