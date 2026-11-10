use super::*;
use araphor_analysis_types::{values as algorithm, DomainRelations, FindingMember};
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    ContextSensitivityV1, DeclaredFindingReasonV1, DiscoveryRecordV1, EvidenceBasis,
    EvidenceIntakeIdentityV1, EvidenceRecord, FindingReasonV1, FindingSeverityV1, FindingStateV1,
    FindingV1, GraphCauseV1, GraphEdgeTypeV1, GraphReplayInputV1, GraphSubjectKeyV1,
    GraphSubjectKindV1, ManagedPage, ManagedRead, ManagedSourceRead, ValidatedEvidenceBatchV1,
};
use sdk::arrow_array::{ArrayRef, BinaryArray, StructArray, UInt8Array};

fn fixture(
    store: &NativeStore,
) -> Result<
    (
        ManagedInstance,
        sdk::Model,
        EvidenceIntakeIdentityV1,
        algorithm::Observation,
    ),
    Box<dyn std::error::Error>,
> {
    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("rows", schema.clone())],
    );
    model.graph = Some(sdk::GraphSpec {
        access: sdk::GraphAccess::ReadWrite,
        relations: DomainRelations::declarations(),
    });
    model.reasons = vec![sdk::Reason {
        code: "managed-graph.PROJECTION".into(),
        details: schema,
    }];
    let mut fixture = Fixture::with_model(store, [1; 16], "domain", model.clone())?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let mut dependent = fixture.spec.manifest.calls[&10].clone();
    dependent.dependencies.insert(10);
    fixture.spec.manifest.calls.insert(20, dependent);
    let admitted = fixture.admit(store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    store.commit_contexts(&[super::attempts::context(99)])?;
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "domain-node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let framed = Vec::<u8>::try_from(&EvidenceRecord {
        task_cookie: 1,
        observed_boottime_ns: 10,
        ingested_utc_ns: 100,
        execution_set_id: vec![5; 16].into(),
        coverage_interval_id: vec![4; 16].into(),
        effect_family: erebor_interceptor_abi::KernelEffectFamilyV1::File as u32,
        operation: erebor_interceptor_abi::KernelEffectOperationV1::Read as u32,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            frame_ends: vec![framed.len()],
            framed_records: framed.into(),
        },
    )?;
    let view = store.view()?;
    let page = store.read_page_at(&view, &source, 1, &AnalysisReadControl::default())?;
    let record = DiscoveryRecordV1::try_from((&source, 0, &page.records[0]))?;
    let input = GraphReplayInputV1 {
        source: source.clone(),
        records: vec![record.clone()],
        input_positions: vec![(record.id.clone(), page.records[0].position)],
        coverage: Vec::new(),
        coverage_keys: Vec::new(),
        missing_ranges: Vec::new(),
        facts: Vec::new(),
    };
    let observation = EvidenceBasis::qualify(&input)?.remove(0);
    Ok((instance, model, source, observation))
}

fn capture(
    store: &NativeStore,
    instance: &ManagedInstance,
    completed: u64,
    rebuild: bool,
) -> araphor_data::Result<ManagedPage> {
    let requests: AnalysisTableRequests = ["events", "context_versions"]
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
        .collect();
    let selection = instance.grant.selection.project(&requests)?;
    store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            instance: instance.clone(),
            expected: None,
            rebuild,
            follow: false,
            completed: Some(completed),
            execution: None,
            source: Some(ManagedSourceRead::Initial),
        },
        AnalysisTableRead {
            requests: &requests,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

fn finding(
    observation: &algorithm::Observation,
    details: &sdk::RecordBatch,
) -> Result<FindingMember, Box<dyn std::error::Error>> {
    let subject = observation.task_subject();
    Ok(FindingMember {
        anchor: algorithm::Anchor {
            record: observation.id.clone(),
            fact: None,
        },
        value: FindingV1 {
            tenant_id: [1; 16],
            finding_id: FindingV1::identity("managed-graph", &observation.id, &subject)?,
            package_id: "managed-graph".into(),
            package_version: 1,
            subject_id: subject,
            state: FindingStateV1::Provisional,
            window_start_utc_ns: 100,
            window_end_utc_ns: 100,
            evidence: vec![observation.id.clone()],
            required_coverage_interval_ids: vec![[4; 16]],
            policy_provenance: Vec::new(),
            effects: vec![observation.resolved_effect()],
            reason: FindingReasonV1::Declared(DeclaredFindingReasonV1::from_details(
                "managed-graph.PROJECTION".into(),
                details,
            )?),
            severity: FindingSeverityV1::Info,
            sensitivity: ContextSensitivityV1::Tenant,
            required_action: None,
            limits: Vec::new(),
        },
    })
}

fn command(
    model: &sdk::Model,
    relation: &str,
    owner: &[u8],
    keys: &[Vec<u8>],
    endpoints: Option<[Vec<u8>; 3]>,
    data: sdk::Dataset,
    remove: bool,
) -> Result<sdk::RecordBatch, Box<dyn std::error::Error>> {
    let spec = model.graph.as_ref().ok_or("Graph spec")?;
    let declaration = spec.relation(relation)?;
    let count = keys.len();
    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(BinaryArray::from_iter_values(std::iter::repeat_n(
            owner, count,
        ))),
        Arc::new(BinaryArray::from_iter_values(
            keys.iter().map(Vec::as_slice),
        )),
        Arc::new(UInt8Array::from(vec![
            if remove {
                araphor_graph::Write::Remove
            } else {
                araphor_graph::Write::Add
            } as u8;
            count
        ])),
    ];
    if let Some(endpoints) = endpoints {
        for endpoint in endpoints {
            columns.push(Arc::new(BinaryArray::from_iter_values([
                endpoint.as_slice()
            ])));
        }
    }
    let batch = &data.batches[0];
    columns.push(Arc::new(StructArray::new(
        declaration.properties.fields().clone(),
        batch.columns().to_vec(),
        None,
    )));
    Ok(sdk::RecordBatch::try_new(
        Arc::new(spec.command_schema(relation)?),
        columns,
    )?)
}

fn commit(
    store: &NativeStore,
    model: &sdk::Model,
    observation: &algorithm::Observation,
    step: u8,
) -> TestResult {
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume([1; 16], "domain", &control)?;
    let page = capture(store, &resume.instance, resume.completed, step != 0)?;
    let frame = page.state.source().ok_or("source frame")?;
    let batch = page.page.tables["events"]
        .iter()
        .position(|batch| batch.num_rows() != 0)
        .ok_or("event")?;
    let rows = Arc::new(
        frame
            .row_handles("events", batch)?
            .select(&[0], Arc::new(()))?,
    );
    frame.record_rows(&rows)?;
    let (batch, index) = page.page.tables["context_versions"]
        .iter()
        .enumerate()
        .find_map(|(batch, values)| {
            let revisions = values
                .column_by_name("owner_revision")?
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()?;
            (0..values.num_rows())
                .find(|index| revisions.value(*index) == 99)
                .map(|index| (batch, index))
        })
        .ok_or("proof context row")?;
    let contexts = Arc::new(
        frame
            .row_handles("context_versions", batch)?
            .select(&[index], Arc::new(()))?,
    );
    frame.record_rows(&contexts)?;
    let view = store.view()?;
    let raw = store.read_page_at(&view, &observation.id.stream, 1, &control)?;
    let record = DiscoveryRecordV1::try_from((&observation.id.stream, 0, &raw.records[0]))?;
    let mut fact = super::attempts::context(1);
    fact.body = araphor_data::GraphFactV1 {
        record_id: observation.id.clone(),
        value: araphor_data::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: false,
            reviewed_policy_revision: "reviewed".into(),
        },
    }
    .encode_context()?;
    let input = GraphReplayInputV1 {
        source: observation.id.stream.clone(),
        records: vec![record],
        input_positions: vec![(observation.id.clone(), raw.records[0].position)],
        facts: vec![fact],
        coverage: vec![araphor_data::DiscoveryCoverageV1 {
            stream: observation.id.stream.clone(),
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            expected_records: 1,
            coverage_revision: 0,
            coverage_interval_id: [4; 16],
            state: araphor_data::DiscoveryCoverageStateV1::Unknown,
            gap_reasons: vec!["MISSING_COVERAGE_REPORT".into()],
        }],
        coverage_keys: Vec::new(),
        missing_ranges: Vec::new(),
    };
    let derived = frame.seal_derived(
        &input,
        &BTreeMap::new(),
        &[(observation.id.clone(), contexts.contexts()[0].clone())],
        None,
        Arc::new(()),
    )?;
    for call in [10, 20] {
        frame.attribute_input(
            call,
            &[Arc::clone(&rows), Arc::clone(&contexts)],
            &[Arc::clone(&derived)],
            Arc::new(()),
        )?;
    }
    let mut request = super::attempts::request(&format!("domain-{step}"), true);
    request.rebuild = step != 0;
    let attempt = Arc::new(store.register_managed_attempt(&page.state, &request, || Ok(()))?);
    let output = super::publication::output(model)?;
    let finding = finding(observation, &output.datasets[0].batches[0])?;
    let anchor = finding.anchor.clone();
    let task = observation.task_subject();
    let execution = GraphSubjectKeyV1::native(
        &observation.id.stream,
        GraphSubjectKindV1::ExecutionSet,
        observation.effect.execution_set_id.to_vec(),
    );
    let subjects = [
        algorithm::SubjectChange {
            anchor: anchor.clone(),
            key: task.clone(),
        },
        algorithm::SubjectChange {
            anchor: anchor.clone(),
            key: execution.clone(),
        },
    ];
    let edge = algorithm::RelationshipChange {
        anchor,
        key: algorithm::RelationshipIdentity {
            from: task,
            to: execution,
            edge_type: GraphEdgeTypeV1::TaskInExecutionSet,
            package_id: "managed-graph".into(),
            evidence: vec![observation.id.clone()],
            cause: GraphCauseV1::Contextual,
        },
        proof_quality: observation.proof_quality,
        required_coverage_interval_ids: vec![[4; 16]],
        first_boottime_ns: 10,
        last_boottime_ns: 10,
    };
    let mut journals = Vec::new();
    for call in [10, 20] {
        let transaction = araphor_data::analysis::native::ManagedGraphTransaction::new(
            store,
            Arc::clone(&attempt),
            call,
            model,
            journals.clone(),
            Arc::new(super::graph::Budget),
            &control,
        )?;
        if step == 0 {
            let keys = subjects
                .iter()
                .map(|row| DomainRelations::key(&row.key))
                .collect::<sdk::Result<Vec<_>>>()?;
            transaction.stage(
                store,
                DomainRelations::SUBJECTS,
                command(
                    model,
                    DomainRelations::SUBJECTS,
                    b"owner",
                    &keys,
                    None,
                    algorithm::SubjectChange::encode(&subjects)?,
                    false,
                )?,
                Arc::new(()),
                &control,
            )?;
            let endpoints = [
                DomainRelations::key(&edge.key.from)?,
                DomainRelations::key(&edge.key.to)?,
                DomainRelations::key(&edge.key.edge_type)?,
            ];
            transaction.stage(
                store,
                DomainRelations::RELATIONSHIPS,
                command(
                    model,
                    DomainRelations::RELATIONSHIPS,
                    b"owner",
                    &[DomainRelations::key(&edge.key)?],
                    Some(endpoints),
                    algorithm::RelationshipChange::encode(std::slice::from_ref(&edge))?,
                    false,
                )?,
                Arc::new(()),
                &control,
            )?;
        }
        if step == 0 || call == 10 {
            transaction.stage(
                store,
                DomainRelations::FINDINGS,
                command(
                    model,
                    DomainRelations::FINDINGS,
                    if step == 2 { b"replacement" } else { b"owner" },
                    &[DomainRelations::key(&finding.value.finding_id)?],
                    None,
                    FindingMember::encode(std::slice::from_ref(&finding))?,
                    step == 1,
                )?,
                Arc::new(()),
                &control,
            )?;
        }
        journals.push(transaction.freeze(store, &control)?);
    }
    let journals = journals.try_into().map_err(|_| "Graph journals")?;
    super::publication::publish(store, &attempt, model, &journals, false)?;
    Ok(())
}

fn row(
    store: &NativeStore,
    prefix: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (key, value) = store
        .view()?
        .snapshot()
        .prefix(prefix)
        .next()
        .ok_or("index")??;
    Ok((key.to_vec(), value.to_vec()))
}

#[test]
fn canonical_finding_survives_removed_producer_and_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, _, observation) = fixture(&store)?;
    commit(&store, &model, &observation, 0)?;
    let canonical = row(&store, b"\0data/graph/finding/")?;
    let mapping = store
        .view()?
        .managed_graph([1; 16], "domain", &AnalysisReadControl::default())?
        .ok_or("mapping")?;
    #[derive(serde::Deserialize)]
    struct Producer {
        writer: u64,
    }
    let key = [b"\0data/graph/property/".as_slice(), canonical.1.as_slice()].concat();
    let bytes = store
        .view()?
        .snapshot()
        .get(key)?
        .ok_or("canonical property")?;
    let producer: Producer = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(producer.writer, mapping.writers[&10]);
    commit(&store, &model, &observation, 1)?;
    assert_eq!(row(&store, b"\0data/graph/finding/")?, canonical);
    {
        let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
            store.view()?.snapshot().clone(),
            BTreeMap::new(),
            &|_, _, _| Ok(None),
        )?;
        let finding = finding(
            &observation,
            &super::publication::output(&model)?.datasets[0].batches[0],
        )?;
        let key = DomainRelations::key(&finding.value.finding_id)?;
        let relation = mapping.relations[DomainRelations::FINDINGS].0;
        assert!(graph
            .member(
                mapping.writers[&10],
                relation,
                b"owner",
                &key,
                &|_, _, _| Ok(None)
            )?
            .is_none());
        assert!(graph
            .member(
                mapping.writers[&20],
                relation,
                b"owner",
                &key,
                &|_, _, _| Ok(None)
            )?
            .is_some());
    }
    commit(&store, &model, &observation, 2)?;
    assert_eq!(row(&store, b"\0data/graph/finding/")?, canonical);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(row(&store, b"\0data/graph/finding/")?, canonical);
    Ok(())
}

#[path = "domain/recovery.rs"]
mod recovery;
