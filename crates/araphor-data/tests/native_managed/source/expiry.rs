use super::*;
use araphor_data::analysis::native::{ManagedGraphJournal, ManagedGraphTransaction};

#[test]
fn retained_healthy_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = super::super::domain::fixture_source(&store, true)?;
    let scope = ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    super::super::domain::commit(&store, &model, &observation, 0)?;
    let control = AnalysisReadControl::default();
    let first = store.processor_result(&scope)?.ok_or("source result")?;
    let first = PackageResultRefV1 {
        result_id: first.result_id,
        commit_revision: first.commit_revision,
    };
    let resume = store.managed_resume([1; 16], "domain", &control)?;
    let requests = ["events", "context_versions"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect::<araphor_data::AnalysisTableRequests>();
    let selection = resume
        .instance
        .spec
        .destination
        .selection(&resume.instance.grant.selection)?
        .project(&requests)?;
    let page = store.read_managed_tables_filtered(
        &selection,
        &araphor_data::ManagedRead {
            instance: resume.instance.clone(),
            expected: None,
            rebuild: true,
            follow: false,
            source: Some(araphor_data::ManagedSourceRead::Initial),
            completed: Some(resume.completed),
            execution: None,
        },
        araphor_data::AnalysisTableRead {
            requests: &requests,
            mode: araphor_data::AnalysisReadModeV1::Complete,
            now: 3000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let frame = page.state.source().ok_or("source frame")?;
    let input = GraphReplayInputV1 {
        source,
        records: Vec::new(),
        input_positions: Vec::new(),
        facts: Vec::new(),
        coverage: Vec::new(),
        coverage_keys: Vec::new(),
        missing_ranges: Vec::new(),
    };
    let derived = frame.seal_derived(&input, &BTreeMap::new(), &[], None, Arc::new(()))?;
    frame.select_graph_input(
        &page.state,
        None,
        &input,
        &derived,
        Some(&first),
        (1, 1, 2000),
        (false, false, true),
        Arc::new(()),
    )?;
    let mut request = super::super::attempts::request("expired", true);
    request.rebuild = true;
    request.time_utc_ns = 3000;
    request.witness_expiry = 4000;
    let attempt = Arc::new(store.register_managed_attempt(&page.state, &request, || Ok(()))?);
    let budget = super::super::graph::Budget;
    let schema = &attempt.instance().spec.manifest.selected_schema;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![sdk::RecordBatch::new_empty(Arc::new(schema.clone()))],
    };
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 3000,
        returns: &[],
        selected: &selected,
        selected_schema: schema,
    };
    let before = store.view()?.revision();
    let error = store
        .commit_managed_graph(
            store.prepare_managed(&input)?,
            Some(packet(scope.clone(), 3000)),
            || Ok(()),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Package {
            code: Code::Denied,
            field: "expired source proof claim",
            ..
        }
    ));
    assert_eq!(store.view()?.revision(), before);
    let mut journals: Vec<Arc<ManagedGraphJournal>> = Vec::new();
    for call in [10, 20] {
        let transaction = ManagedGraphTransaction::new(
            &store,
            attempt.clone(),
            call,
            &model,
            journals.clone(),
            Arc::new(super::super::graph::Budget),
            &control,
        )?;
        journals.push(transaction.freeze(&store, &control)?);
    }
    let journals = journals.try_into().map_err(|_| "journals")?;
    let error =
        super::super::publication::publish(&store, &attempt, &model, &journals, false).unwrap_err();
    assert!(
        error.downcast_ref::<Error>().is_some_and(|error| matches!(
            error,
            Error::Package {
                code: Code::Denied,
                field: "expired source proof claim",
                ..
            }
        )),
        "{error}"
    );
    assert_eq!(store.view()?.revision(), before);
    assert_eq!(
        store
            .processor_result(&scope)?
            .ok_or("preserved result")?
            .result_id,
        first.result_id
    );
    drop(journals);
    let mut journals = Vec::new();
    for call in [10, 20] {
        let transaction = ManagedGraphTransaction::new(
            &store,
            attempt.clone(),
            call,
            &model,
            journals.clone(),
            Arc::new(super::super::graph::Budget),
            &control,
        )?;
        degrade(&store, &transaction, &model)?;
        journals.push(transaction.freeze(&store, &control)?);
    }
    let journals = journals.try_into().map_err(|_| "degraded journals")?;
    let receipt = super::super::publication::publish(&store, &attempt, &model, &journals, false)?;
    assert_eq!(receipt.graph, Some(receipt.selected.clone()));
    let saved = store
        .managed_attempt([1; 16], "domain", "expired", &control)?
        .ok_or("saved expiry")?;
    let wanted = BTreeSet::from([observation.id.clone()]);
    let (summary, _, _) = store.graph_frozen_facts(
        &page.state,
        Some(&saved),
        &receipt.selected,
        &wanted,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert!(summary.expired);
    assert_eq!(summary.manifest.missing_ranges, vec![(1, 1)]);
    assert_eq!(
        store.graph_record_keys(
            &page.state,
            Some(&saved),
            &receipt.selected,
            AnalysisExtractLimits::default(),
            &control
        )?,
        vec![observation.id]
    );
    drop((journals, attempt, page));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .processor_result(&scope)?
            .ok_or("reopened expiry")?
            .result_id,
        receipt.selected.result_id
    );
    Ok(())
}

fn properties(
    input: sdk::Input,
    port: sdk::Port,
) -> Result<sdk::Dataset, Box<dyn std::error::Error>> {
    let mut batches = Vec::new();
    for batch in input.data.batches {
        let properties = batch
            .column_by_name("properties")
            .ok_or("properties")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::StructArray>()
            .ok_or("properties type")?;
        batches.push(sdk::RecordBatch::try_new(
            Arc::new(port.schema.clone()),
            properties.columns().to_vec(),
        )?);
    }
    Ok(sdk::Dataset {
        name: port.name,
        batches,
    })
}

fn degrade(
    store: &NativeStore,
    transaction: &ManagedGraphTransaction,
    model: &sdk::Model,
) -> TestResult {
    use araphor_analysis_types::{values::RelationshipChange, DomainRelations, FindingMember};
    let control = AnalysisReadControl::default();
    let arguments =
        sdk::RecordBatch::new_empty(Arc::new(transaction.spec().argument_schema("owned")?));
    transaction.read(
        store,
        "owned",
        DomainRelations::SUBJECTS,
        &arguments,
        |_| Ok(Arc::new(())),
        &control,
    )?;
    let edges = transaction.read(
        store,
        "owned",
        DomainRelations::RELATIONSHIPS,
        &arguments,
        |_| Ok(Arc::new(())),
        &control,
    )?;
    let edges = RelationshipChange::decode(&properties(edges, RelationshipChange::port())?)?;
    for edge in edges {
        let endpoints = [
            DomainRelations::key(&edge.key.from)?,
            DomainRelations::key(&edge.key.to)?,
            DomainRelations::key(&edge.key.edge_type)?,
        ];
        for (edge, remove) in [(&edge, true), (&edge.retained_expiry(), false)] {
            let command = super::super::domain::command(
                model,
                DomainRelations::RELATIONSHIPS,
                b"owner",
                &[DomainRelations::key(&edge.key)?],
                Some(endpoints.clone()),
                RelationshipChange::encode(std::slice::from_ref(edge))?,
                remove,
            )?;
            transaction.stage(
                store,
                DomainRelations::RELATIONSHIPS,
                command,
                Arc::new(()),
                &control,
            )?;
        }
    }
    let findings = transaction.read(
        store,
        "owned",
        DomainRelations::FINDINGS,
        &arguments,
        |_| Ok(Arc::new(())),
        &control,
    )?;
    for finding in FindingMember::decode(&properties(findings, FindingMember::port())?)? {
        let finding = finding.retained_expiry();
        let command = super::super::domain::command(
            model,
            DomainRelations::FINDINGS,
            b"owner",
            &[DomainRelations::key(&finding.value.finding_id)?],
            None,
            FindingMember::encode(&[finding])?,
            false,
        )?;
        let mut columns = command.columns().to_vec();
        columns[2] = Arc::new(sdk::arrow_array::UInt8Array::from(vec![
            araphor_graph::Write::Update as u8,
        ]));
        let command = sdk::RecordBatch::try_new(command.schema(), columns)?;
        transaction.stage(
            store,
            DomainRelations::FINDINGS,
            command,
            Arc::new(()),
            &control,
        )?;
    }
    Ok(())
}
