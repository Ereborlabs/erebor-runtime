use super::*;
use araphor_data::{TraceBindingV1, TraceIdentityV1, TraceIntentV1, TraceSourceV1};

fn trace_intent(request: u8) -> araphor_data::Result<TraceIntentV1> {
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    Ok(TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: [request; 16],
        bindings: vec![TraceBindingV1 {
            binding_id: [9; 16],
            identity: TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                request_id: [request; 16],
                execution_id: [request; 16],
                source_sha256: source.sha256,
            },
            namespace_uid: "namespace-a".into(),
        }],
        source,
        authority: b"authorized-input".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    })
}

#[test]
fn reference_keeps_trace_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let intent = trace_intent(3)?;
    let state = store.accept_trace(&intent)?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.traces = araphor_data::Selection::All;
    let fixture = Fixture::new_scope(
        &store,
        "counter",
        "Retain independent call state.".into(),
        selection.clone(),
    )?;
    let fields = ["request_revision", "cancel_requested", "last_sequence"];
    let requests = BTreeMap::from([(
        "traces".into(),
        Some(
            fields
                .iter()
                .map(|name| araphor_data::AnalysisStore::table_schemas()["traces"].index_of(name))
                .collect::<std::result::Result<BTreeSet<_>, _>>()?,
        ),
    )]);
    let read = || AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        mode: AnalysisReadModeV1::Metadata,
        now: 10,
    };
    let control = AnalysisReadControl::default();
    let captured = store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            source: None,
            execution: None,
            follow: false,
            expected: None,
            instance: fixture.instance.clone(),
            rebuild: false,
            completed: None,
        },
        read(),
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let input = request("trace-cut");
    let attempt = store.register_managed_attempt(&captured.state, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured.state))?,
        fixture.continued(&input, 11, Some(&captured.state))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let (reference, _, _) = store.managed_reference(
        &fixture.current(&store)?,
        &receipt.selected.result_id,
        10,
        &control,
    )?;
    let identity = &intent.bindings[0].identity;
    store.append_trace(
        identity,
        &araphor_data::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![araphor_data::TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: araphor_data::TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        },
        100,
    )?;
    let cancelled = store.update_trace(&araphor_data::TraceStateV1 {
        cancel_requested: true,
        ..state.clone()
    })?;
    store.accept_trace(&trace_intent(4)?)?;
    let before = store.meta()?;
    for historical in [false, true, false] {
        let page = if historical {
            store
                .read_managed_reference(
                    &selection,
                    &reference,
                    read(),
                    AnalysisExtractLimits::default(),
                    &control,
                    None,
                )?
                .page
        } else {
            store.read_tables(
                &selection,
                read(),
                AnalysisExtractLimits::default(),
                &control,
            )?
        };
        let batches = &page.tables["traces"];
        assert_eq!(
            batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            if historical { 1 } else { 2 }
        );
        if historical {
            let batch = batches
                .iter()
                .find(|batch| batch.num_rows() != 0)
                .ok_or("trace row")?;
            assert_eq!(
                batch
                    .column_by_name("request_revision")
                    .ok_or("request revision")?
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .ok_or("request type")?
                    .value(0),
                state.revision
            );
            assert!(!batch
                .column_by_name("cancel_requested")
                .ok_or("cancellation")?
                .as_any()
                .downcast_ref::<sdk::arrow_array::BooleanArray>()
                .ok_or("cancel type")?
                .value(0));
            assert_eq!(
                batch
                    .column_by_name("last_sequence")
                    .ok_or("sequence")?
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .ok_or("sequence type")?
                    .value(0),
                0
            );
        }
    }
    assert_eq!(store.meta()?, before);
    store.update_trace(&araphor_data::TraceStateV1 {
        read_revoked: true,
        ..cancelled
    })?;
    let before = store.meta()?;
    assert!(matches!(
        store.read_managed_reference(
            &selection,
            &reference,
            read(),
            AnalysisExtractLimits::default(),
            &control,
            None
        ),
        Err(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    assert_eq!(store.meta()?, before);
    drop(store);
    AnalysisStore::open(&root)?;
    Ok(())
}
