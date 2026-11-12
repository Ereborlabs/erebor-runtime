use super::*;

pub(super) fn identity() -> araphor_data::EvidenceIntakeIdentityV1 {
    araphor_data::EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

pub(crate) fn append(store: &NativeStore, cursor: u64) -> araphor_data::Result<()> {
    let framed = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        task_cookie: cursor,
        observed_boottime_ns: cursor,
        ingested_utc_ns: 100,
        coverage_interval_id: vec![4; 16].into(),
        effect_family: 1,
        operation: 1,
        temporal_coverage: 1,
        decision_context: Some(araphor_data::EvidenceDecisionContext {
            schema_version: 1,
            original_kernel_sequence: cursor,
            ..Default::default()
        }),
        ..Default::default()
    })?;
    store.accept_validated_batch(
        identity(),
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 100,
            frame_ends: vec![framed.len()],
            framed_records: framed.into(),
        },
    )?;
    Ok(())
}

pub(super) fn scope() -> ProcessorScopeV1 {
    ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: identity(),
    }
}

pub(super) fn instance(store: &NativeStore) -> Result<ManagedInstance, Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(store, [1; 16], "source", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    fixture.spec.destination = ManagedDestination::Graph {
        source: identity(),
        events_sql: "SELECT * FROM events".into(),
        control_sql: "SELECT * FROM graph_state".into(),
        calls: BTreeSet::from([10]),
        operation: ManagedGraphOperation::Evaluate,
    };
    let admitted = fixture.admit(store)?;
    Ok(store.set_managed_running([1; 16], "source", admitted.lifecycle, true, || Ok(()))?)
}

pub(super) fn capture(
    store: &NativeStore,
    resume: &araphor_data::ManagedResume,
) -> araphor_data::Result<araphor_data::ManagedPage> {
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
    store.read_managed_tables_filtered(
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
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

pub(crate) fn select(
    store: &NativeStore,
    page: &araphor_data::ManagedPage,
    cursors: &[u64],
    base: Option<&PackageResultRefV1>,
) -> Result<GraphReplayInputV1, Box<dyn std::error::Error>> {
    select_window(store, page, cursors, base, 1)
}

pub(super) fn select_window(
    store: &NativeStore,
    page: &araphor_data::ManagedPage,
    cursors: &[u64],
    base: Option<&PackageResultRefV1>,
    first: u64,
) -> Result<GraphReplayInputV1, Box<dyn std::error::Error>> {
    let frame = page.state.source().ok_or("source frame")?;
    let source = identity();
    let view = store.view()?;
    let raw = store.read_page_at(&view, &source, 1, &AnalysisReadControl::default())?;
    let report = view
        .source_receipt(&source)?
        .ok_or("receipt")?
        .coverage_revision;
    let mut input = GraphReplayInputV1 {
        source: source.clone(),
        records: Vec::new(),
        input_positions: Vec::new(),
        facts: Vec::new(),
        coverage: Vec::new(),
        coverage_keys: Vec::new(),
        missing_ranges: Vec::new(),
    };
    for raw in raw
        .records
        .iter()
        .filter(|raw| cursors.contains(&raw.cursor))
    {
        let record = DiscoveryRecordV1::try_from((&source, 0, raw))?;
        input
            .input_positions
            .push((record.id.clone(), raw.position));
        let mut context = super::attempts::context(raw.cursor);
        context.body = GraphFactV1 {
            record_id: record.id.clone(),
            value: GraphFactValueV1::Baseline {
                role_id: 1,
                state_id: 1,
                outside_reviewed_baseline: false,
                reviewed_policy_revision: "reviewed".into(),
            },
        }
        .encode_context()?;
        input.facts.push(context);
        input.coverage.push(DiscoveryCoverageV1 {
            stream: source.clone(),
            cpu_id: 0,
            first_cursor: raw.cursor,
            last_cursor: raw.cursor,
            expected_records: 1,
            coverage_revision: report,
            coverage_interval_id: [4; 16],
            state: if report == 0 {
                DiscoveryCoverageStateV1::Unknown
            } else {
                DiscoveryCoverageStateV1::Closed
            },
            gap_reasons: if report == 0 {
                vec!["MISSING_COVERAGE_REPORT".into()]
            } else {
                Vec::new()
            },
        });
        input.records.push(record);
    }
    if report != 0 {
        input.coverage_keys.push(araphor_data::GraphCoverageKeyV1 {
            source: source.clone(),
            cpu_id: 0,
            report_revision: report,
            interval_id: [4; 16],
            interval_revision: 1,
            state: DiscoveryCoverageStateV1::Closed,
            gap_reasons: Vec::new(),
        });
    }
    let mut selected = Vec::new();
    for (batch, values) in page.page.tables["events"].iter().enumerate() {
        let values = values
            .column_by_name("source_cursor")
            .ok_or("cursor")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("cursor type")?;
        let indices = (0..values.len())
            .filter(|index| cursors.contains(&values.value(*index)))
            .collect::<Vec<_>>();
        if indices.is_empty() {
            continue;
        }
        let rows = Arc::new(
            frame
                .row_handles("events", batch)?
                .select(&indices, Arc::new(()))?,
        );
        frame.record_rows(&rows)?;
        selected.push(rows);
    }
    let mut proofs = Vec::new();
    for (batch, values) in page
        .page
        .tables
        .get("context_versions")
        .into_iter()
        .flatten()
        .enumerate()
    {
        let revisions = values
            .column_by_name("owner_revision")
            .ok_or("context revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("revision type")?;
        let indices = (0..values.num_rows())
            .filter(|index| revisions.value(*index) == 99)
            .collect::<Vec<_>>();
        if indices.is_empty() {
            continue;
        }
        let rows = Arc::new(
            frame
                .row_handles("context_versions", batch)?
                .select(&indices, Arc::new(()))?,
        );
        frame.record_rows(&rows)?;
        for record in &input.records {
            proofs.push((record.id.clone(), rows.contexts()[0].clone()));
        }
        selected.push(rows);
    }
    let derived = frame.seal_derived(&input, &BTreeMap::new(), &proofs, None, Arc::new(()))?;
    frame.attribute_input(10, &selected, &[derived.clone()], Arc::new(()))?;
    let append = matches!(frame.read(), araphor_data::ManagedSourceRead::Changes(_));
    frame.select_graph_input(
        &page.state,
        None,
        &input,
        &derived,
        base,
        (first, *cursors.last().ok_or("last")?, 2000),
        (append, report != 0, false),
        Arc::new(()),
    )?;
    Ok(input)
}

pub(super) fn publish(
    store: &NativeStore,
    attempt: &ManagedAttempt,
    reject: bool,
) -> araphor_data::Result<araphor_data::ManagedReceipt> {
    let control = AnalysisReadControl::default();
    let descriptor = store
        .view()?
        .package_revision([1; 16], "managed-count", "1", &control)?
        .ok_or_else(|| Code::Missing.error("descriptor"))?;
    let descriptor: sdk::Package = serde_json::from_slice(&descriptor.descriptor).unwrap();
    let output = super::publication::output(&descriptor.exports[0]).unwrap();
    let evaluation = super::publication::evaluation(attempt);
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &attempt.instance().spec.manifest.selected_schema,
    };
    store
        .commit_managed_graph(store.prepare_managed(&input)?, || {
            if reject {
                Err(Code::Denied.error("test guard"))
            } else {
                Ok(())
            }
        })
        .map(|(receipt, _)| receipt)
}

pub(super) fn records(cursors: &[u64]) -> Vec<DiscoveryRecordIdV1> {
    cursors
        .iter()
        .map(|cursor| DiscoveryRecordIdV1 {
            stream: identity(),
            cpu_id: 0,
            durable_cursor: *cursor,
        })
        .collect()
}

pub(super) fn follow(
    store: &NativeStore,
    resume: &araphor_data::ManagedResume,
    execution: &Arc<araphor_data::ManagedExecution>,
) -> araphor_data::Result<araphor_data::ManagedPage> {
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
    let source = resume
        .source
        .as_ref()
        .map_or(araphor_data::ManagedSourceRead::Initial, |source| {
            araphor_data::ManagedSourceRead::Changes(source.clone())
        });
    let mode = resume
        .source
        .as_ref()
        .map_or(araphor_data::AnalysisReadModeV1::Complete, |source| {
            araphor_data::AnalysisReadModeV1::Changes(source.position)
        });
    store.read_managed_tables_filtered(
        &selection,
        &araphor_data::ManagedRead {
            instance: resume.instance.clone(),
            expected: None,
            rebuild: false,
            follow: true,
            source: Some(source),
            completed: Some(resume.completed),
            execution: Some(execution.clone()),
        },
        araphor_data::AnalysisTableRead {
            requests: &requests,
            mode,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}
