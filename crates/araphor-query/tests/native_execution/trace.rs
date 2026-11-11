use super::*;
use araphor_data::{
    Selection, TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceIntentV1, TraceSourceV1,
};
use araphor_query::{definition::Invocation, Failure};

#[tokio::test]
async fn captured_trace_revocation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    let image = image()?;
    store.install_package_image(TENANT, &image, || Ok(()))?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: TENANT,
        node_id: "input-trace".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    store.accept_trace(&TraceIntentV1 {
        tenant_id: TENANT,
        request_id: identity.request_id,
        source,
        bindings: vec![TraceBindingV1 {
            identity: identity.clone(),
            binding_id: [6; 16],
            namespace_uid: "input-namespace".into(),
        }],
        authority: b"accepted".to_vec(),
        accepted_unix_ns: NOW - 3_000_000_000,
        deadline_unix_ns: NOW + 60_000_000_000,
        host_sensitive: false,
    })?;
    store.append_trace(
        &identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"trace-input".to_vec(),
            }],
            terminal: None,
        },
        NOW - 2_000_000_000,
    )?;
    let parent = AnalysisReadControl::default();
    store.check_trace_reads(TENANT, &[identity.request_id], &parent)?;
    for (tenant, request) in [(TENANT, [99; 16]), ([99; 16], identity.request_id)] {
        assert!(matches!(
            store.check_trace_reads(tenant, &[request], &parent),
            Err(araphor_data::Error::AnalysisReadDenied { .. })
        ));
    }
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.check_trace_reads(TENANT, &[], &cancelled),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    let mut selection = AnalysisSelectionV1::tenant(TENANT);
    selection.traces = Selection::Exact(vec![identity.clone()]);
    let session = engine.session(selection, &parent, NOW)?;
    let prepared = session
        .prepare_definition(
            &sql(r#"SELECT * FROM "native-fixture"."1".copy(
            input => (SELECT sequence AS value FROM trace_output))"#),
            None,
        )
        .await?;
    let invocation = |id: &str| Invocation {
        id: id.into(),
        seed: Some(7),
        time_utc_ns: None,
        checkpoints: BTreeMap::new(),
        previous_outputs: BTreeMap::new(),
        inputs: BTreeMap::new(),
    };
    let first = session
        .execute_definition(&prepared, invocation("trace-readable"))
        .await?;
    assert_eq!(values(&first.batches)?, [1]);
    assert_eq!(
        first.snapshot.page.extraction.trace_reads(),
        &[identity.request_id]
    );
    engine.check_read(&first.snapshot).await?;
    let captured = session
        .capture_definition(&prepared, invocation("trace-revoked"))
        .await?;
    assert_eq!(
        captured.snapshot().page.extraction.meta,
        first.snapshot.page.extraction.meta
    );
    assert_eq!(
        captured.snapshot().page.extraction.trace_reads(),
        &[identity.request_id]
    );
    let (mut state, _) = store
        .trace_intent(TENANT, identity.request_id)?
        .ok_or("trace intent")?;
    state.cancel_requested = true;
    state.read_revoked = true;
    store.update_trace(&state)?;
    let before = store.meta()?;
    assert!(matches!(
        store.check_trace_reads(TENANT, &[identity.request_id], &parent),
        Err(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    let error = engine
        .check_read(&first.snapshot)
        .await
        .err()
        .ok_or("revoked receipt accepted")?;
    assert_eq!(Failure::from(&error), Failure::Denied);
    let error = captured
        .execute()
        .await
        .err()
        .ok_or("revoked captured result returned")?;
    assert_eq!(Failure::from(&error), Failure::Denied);
    assert_eq!(store.meta()?, before);
    parent.check()?;
    Ok(())
}
