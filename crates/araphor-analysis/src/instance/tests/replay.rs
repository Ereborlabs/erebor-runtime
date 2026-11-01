use super::*;

#[tokio::test]
async fn replay_keeps_captured_state() -> TestResult {
    replay_state("sql").await
}

#[tokio::test]
async fn replay_wasm_captured_state() -> TestResult {
    replay_state("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn replay_native_captured_state() -> TestResult {
    replay_state("native").await
}

async fn replay_state(target: &str) -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = bundle(target)?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let moving = fixture.admit("replay-source", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    let source = moving
        .run(request("source"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("replay-source", "source").await?, [1]);
    let reference = source.results.values().next().ok_or("source result")?;
    let original = moving
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    let original_call = original
        .calls
        .values()
        .next()
        .ok_or("original replay call")?;
    let original_context = original_call.evaluation().context.clone();
    let original_packet = sdk::wire::Output::encode_model(
        original_call.output(),
        &image.artifacts[0].descriptor.exports[0],
    )?;
    drop(original);
    fixture.context(2)?;
    let before = fixture.query.store().meta()?;
    let replayed = moving
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [1]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("replayed source call")?;
    assert_eq!(call.evaluation().context, original_context);
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original_packet
    );
    assert_eq!(fixture.query.store().meta()?, before);
    drop(replayed);
    let constant = fixture.admit("replay-state", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = constant
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let second = constant
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    let third = constant
        .run(request("third"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("replay-state", "third").await?, [9]);
    let reference = second
        .results
        .values()
        .next()
        .ok_or("second result")?
        .clone();
    let original = constant
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    let original_call = original
        .calls
        .values()
        .next()
        .ok_or("original replay call")?;
    let original_context = original_call.evaluation().context.clone();
    let original_packet = sdk::wire::Output::encode_model(
        original_call.output(),
        &image.artifacts[0].descriptor.exports[0],
    )?;
    drop(original);
    let before = fixture.query.store().meta()?;
    let replayed = constant
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [6]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("replayed state call")?;
    assert_eq!(call.evaluation().context, original_context);
    assert!(call.evaluation().checkpoint.is_some());
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original_packet
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("replay-state")?, third.commit_revision);
    drop(replayed);
    let definition = constant.admitted().spec.definition.clone();
    drop(constant);
    drop(moving);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Default::default(),
    )?;
    let instance = Instance::admit(
        Arc::clone(&query),
        authority,
        grant.clone(),
        "replay-state".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    let before = query.store().meta()?;
    let replayed = instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [6]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("reopened replay call")?;
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original_packet
    );
    assert_eq!(query.store().meta()?, before);
    assert_eq!(
        query.store().managed_history(
            &grant.selection,
            "replay-state",
            &AnalysisReadControl::default()
        )?,
        [first, second, third]
    );
    Ok(())
}

#[tokio::test]
async fn replay_checks_current_authority() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    let instance = fixture.admit("replay-guards", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt.results.values().next().ok_or("replay result")?;
    let before = fixture.query.store().meta()?;
    let retained = fixture.query.memory().input_reserved();
    fixture.authority.set(false);
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    fixture.authority.set(true);
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .clear();
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .insert(image.digest()?);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(instance
        .replay(&reference.result_id, &cancelled)
        .await
        .is_err());
    let held = fixture.query.memory().reserve_input(CAPACITY - retained)?;
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    drop(held);
    fixture.authority.deny_next.store(true, Ordering::SeqCst);
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    assert!(!fixture.authority.deny_next.load(Ordering::SeqCst));
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    assert_eq!(fixture.query.store().meta()?, before);
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "replay-guards", &AnalysisReadControl::default())?
        .ok_or("current replay instance")?;
    let mut grant = fixture.grant.clone();
    grant.revision += 1;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let renewed = host
        .renew(
            grant,
            current.spec.id.clone(),
            current.lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let before = fixture.query.store().meta()?;
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    let replayed = renewed
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [3]);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn replay_keeps_expired_metadata() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(4 * 1024 * 1024),
        output_capacity: Some(64 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    fixture.query.store().accept_validated_batch(
        araphor_data::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "retained-expiry".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    let source = fixture
        .admit(
            "retained-source",
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (
                SELECT CAST(7 AS BIGINT UNSIGNED) AS value FROM events
                WHERE EXISTS (SELECT 1 FROM context_versions)))"#,
        )
        .await?;
    let mut step = request("expiry-source");
    step.time_utc_ns = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let expiry = step.time_utc_ns + 3_600_000_000_000;
    step.witness_expiry = expiry;
    let control = AnalysisReadControl::default();
    let receipt = source.run(step, &control).await?;
    let (&id, reference) = receipt
        .results
        .first_key_value()
        .ok_or("expiry source receipt")?;
    let original = fixture.query.store().managed_result(
        source.admitted(),
        &reference.result_id,
        expiry - 1,
        &control,
    )?;
    assert!(original.current);
    let (witnesses, contexts) = fixture
        .query
        .store()
        .package_evidence([1; 16], std::slice::from_ref(&reference.result_id))?;
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].expires_utc_ns, expiry);
    assert!(contexts.iter().any(|context| {
        context.key.owner_id == "instance-context" && context.key.owner_revision == 1
    }));
    let held = fixture.query.memory().input_reserved();
    let before = fixture.query.store().meta()?;
    for now in [expiry - 1, expiry, expiry + 1] {
        let metadata = fixture.query.store().managed_result(
            source.admitted(),
            &reference.result_id,
            now,
            &control,
        )?;
        assert_eq!(metadata.current, now < expiry);
        assert_eq!(metadata.result, original.result);
        assert_eq!(call_context(&metadata)?, call_context(&original)?);
        assert_eq!(metadata.source, original.source);
        assert_eq!(metadata.prior, original.prior);
        assert_eq!(metadata.receipt, original.receipt);
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(fixture.query.memory().input_reserved(), held);
        control.check()?;
    }
    let replayed = source.replay(&reference.result_id, &control).await?;
    assert_eq!(values(&replayed.batches)?, [7]);
    let returned = replayed.calls.get(&id).ok_or("expiry replay call")?;
    let context = call_context(&original)?;
    assert_eq!(returned.evaluation().context, context.context);
    assert!(context.matches(&returned.evaluation().inputs));
    drop(replayed);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(
        fixture.progress("retained-source")?,
        receipt.commit_revision
    );
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.memory().reserve_output(64 * 1024)?);
    Ok(())
}

#[tokio::test]
async fn replay_fences_trace_revocation() -> TestResult {
    use araphor_data::{
        Selection, TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1, TraceStateV1,
    };

    let mut fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let text = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "retained-source".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: text.sha256,
    };
    let state = fixture.query.store().accept_trace(&TraceIntentV1 {
        tenant_id: identity.tenant_id,
        request_id: identity.request_id,
        source: text,
        bindings: vec![TraceBindingV1 {
            identity: identity.clone(),
            binding_id: [6; 16],
            namespace_uid: "retained-namespace".into(),
        }],
        authority: b"accepted".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    })?;
    fixture.query.store().append_trace(
        &identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"retained-input".to_vec(),
            }],
            terminal: None,
        },
        200,
    )?;
    fixture.grant.selection.traces = Selection::Exact(vec![identity.clone()]);
    fixture.install(&bundle("wasm")?)?;
    let source = fixture
        .admit("retained-trace", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT sequence AS value FROM trace_output))"#)
        .await?;
    let mut step = request("trace-source");
    step.time_utc_ns = 300;
    let control = Arc::new(AnalysisReadControl::default());
    let receipt = source.run(step, &control).await?;
    assert_eq!(
        fixture.selected("retained-trace", "trace-source").await?,
        [1]
    );
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("trace source result")?
        .clone();
    let held = fixture.query.memory().input_reserved();
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let stage = Arc::clone(&control);
    let active = Arc::clone(&source);
    let worker = tokio::spawn(async move { active.replay(&reference.result_id, &stage).await });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        control.cancel()?;
        let result = worker.await?.err();
        return Err(format!("guest entry failed: {error}; replay: {result:?}").into());
    }
    fixture.query.store().update_trace(&TraceStateV1 {
        cancel_requested: true,
        read_revoked: true,
        ..state
    })?;
    let before = fixture.query.store().meta()?;
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), worker)
        .await??
        .err()
        .ok_or("revoked trace replay delivered")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("retained-trace")?, receipt.commit_revision);
    control.check()?;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    let session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 400)?;
    let healthy = session
        .prepare_definition(&Fixture::definition(
            "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
        ))
        .await?;
    assert_eq!(
        values(
            &session
                .execute_definition(&healthy, Default::default())
                .await?
                .batches
        )?,
        [1]
    );
    Ok(())
}
