use super::*;

use araphor_query::follow::{Subscription, SystemClock};
use futures_util::TryStreamExt as _;

#[tokio::test]
async fn retained_elision_keeps_proof() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        output_capacity: Some(64 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let (source, reference) = producer(&fixture).await?;
    let baseline = fixture.query.memory().input_reserved();
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    session
        .register_retained("saved", "retained-source", reference.clone(), "data")
        .await?;
    let prepared = session
        .prepare_definition(&Fixture::definition(
            "WITH unused AS (SELECT value FROM saved) SELECT CAST(9 AS BIGINT UNSIGNED) AS value",
        ))
        .await?;
    assert!(prepared.sources().is_empty());
    let before = fixture.query.store().meta()?;
    let output = session.execute_definition(&prepared, invocation()).await?;
    assert_eq!(values(&output.batches)?, [9]);
    assert!(output.calls.is_empty());
    assert_eq!(output.snapshot.results().collect::<Vec<_>>(), [&reference]);
    assert_eq!(fixture.query.store().meta()?, before);
    drop(output);
    let held = fixture.query.memory().input_reserved();
    let error = session
        .capture_managed(
            &prepared,
            invocation(),
            araphor_data::ManagedRead {
                execution: None,
                expected: None,
                instance: source.admitted().clone(),
                rebuild: false,
                completed: None,
                follow: false,
            },
        )
        .await
        .err()
        .ok_or("elided retained source entered managed capture")?;
    assert_eq!(Failure::from(&error), Failure::Unsupported);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    let mut replacement = request("elided-replacement");
    replacement.rebuild = true;
    let replacement = source.run(replacement, &control).await?;
    assert_ne!(
        replacement
            .results
            .values()
            .next()
            .ok_or("replacement result")?,
        &reference
    );
    let held = fixture.query.memory().input_reserved();
    let before = fixture.query.store().meta()?;
    let error = session
        .capture_definition(&prepared, invocation())
        .await
        .err()
        .ok_or("elided stale retained source captured")?;
    assert_eq!(Failure::from(&error), Failure::StorageUnavailable);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    control.check()?;
    drop(prepared);
    drop(session);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.memory().reserve_output(64 * 1024)?);
    Ok(())
}

#[tokio::test]
async fn retained_follow_rejects_capture() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        output_capacity: Some(64 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        global_streams: Some(1),
        tenant_streams: Some(1),
        ..Default::default()
    })?;
    let (source, reference) = producer(&fixture).await?;
    let cursor_control = AnalysisReadControl::default();
    let cursor_session =
        fixture
            .query
            .session(fixture.grant.selection.clone(), &cursor_control, 30)?;
    let plain = cursor_session
        .prepare_definition(&Fixture::definition(
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        ))
        .await?;
    let mut stream = Subscription::new(
        cursor_session,
        Arc::new(plain.plan.clone()),
        plain.sources().clone(),
        b"retained-alias",
        None,
        Arc::new(SystemClock::default()),
        true,
    )?;
    let update = tokio::time::timeout(Duration::from_secs(30), stream.try_next())
        .await??
        .ok_or("native cursor update")?;
    let cursor = update.cursor.clone();
    drop(update);
    stream.cancel_and_join().await?;
    drop(plain);
    for mode in 0..3 {
        let follow = mode != 1;
        let control = AnalysisReadControl::default();
        let mut session = fixture
            .query
            .session(fixture.grant.selection.clone(), &control, 30)?;
        session
            .register_retained("saved", "retained-source", reference.clone(), "data")
            .await?;
        let prepared = session
            .prepare_definition(&Fixture::definition("SELECT value FROM saved"))
            .await?;
        let held = fixture.query.memory().input_reserved();
        let before = fixture.query.store().meta()?;
        let result = Subscription::new(
            session,
            Arc::new(prepared.plan.clone()),
            prepared.sources().clone(),
            b"retained-alias",
            (mode != 0).then(|| cursor.clone()),
            Arc::new(SystemClock::default()),
            follow,
        );
        let error = match result {
            Ok(mut stream) => {
                let next = tokio::time::timeout(Duration::from_secs(30), stream.try_next()).await?;
                stream.cancel_and_join().await?;
                next.err().ok_or("retained follow returned data")?
            }
            Err(error) => error,
        };
        assert_eq!(
            Failure::from(&error),
            if mode == 0 {
                Failure::InvalidQuery
            } else {
                Failure::InvalidCheckpoint
            }
        );
        if mode == 0 {
            assert!(matches!(
                error,
                araphor_query::Error::Data {
                    source: araphor_data::Error::Package {
                        code: araphor_data::PackageErrorCodeV1::Invalid,
                        field: "retained source admission",
                        ..
                    }
                }
            ));
        } else {
            let expected = if mode == 1 {
                "cursor request"
            } else {
                "cursor binding"
            };
            assert!(matches!(
                error,
                araphor_query::Error::Invalid {
                    field,
                    ..
                } if field == expected
            ));
        }
        assert_eq!(fixture.query.memory().input_reserved(), held);
        assert_eq!(fixture.query.store().meta()?, before);
        drop(fixture.query.reserve_evaluation([1; 16])?);
        drop(fixture.query.reserve_stream([1; 16])?);
        drop(fixture.query.memory().reserve_output(64 * 1024)?);
    }
    let receipt = source
        .run(request("follow-healthy"), &AnalysisReadControl::default())
        .await?;
    assert!(!receipt.results.is_empty());
    Ok(())
}

#[tokio::test]
async fn retained_trace_denies_delivery() -> TestResult {
    use araphor_data::{
        Selection, TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1, TraceStateV1,
    };

    let mut fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        output_capacity: Some(64 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "retained-source".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    let state = fixture.query.store().accept_trace(&TraceIntentV1 {
        tenant_id: identity.tenant_id,
        request_id: identity.request_id,
        source,
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
    fixture.install(&bundle("sql")?)?;
    let source = fixture
        .admit("retained-trace", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT sequence AS value FROM trace_output))"#)
        .await?;
    let mut step = request("trace-source");
    step.time_utc_ns = 300;
    let receipt = source.run(step, &AnalysisReadControl::default()).await?;
    assert_eq!(fixture.selected("retained-trace", "trace-source")?, [1]);
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("trace source result")?
        .clone();
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 400)?;
    session
        .register_retained("saved", "retained-trace", reference.clone(), "data")
        .await?;
    let prepared = session
        .prepare_definition(&Fixture::definition("SELECT value FROM saved"))
        .await?;
    assert!(prepared.sources().is_empty());
    let held = fixture.query.memory().input_reserved();
    let captured = session.capture_definition(&prepared, invocation()).await?;
    assert_eq!(
        captured.snapshot().results().collect::<Vec<_>>(),
        [&reference]
    );
    assert_eq!(
        captured.snapshot().page.extraction.trace_reads(),
        [identity.request_id]
    );
    fixture.query.store().update_trace(&TraceStateV1 {
        cancel_requested: true,
        read_revoked: true,
        ..state
    })?;
    let before = fixture.query.store().meta()?;
    let error = captured
        .execute()
        .await
        .err()
        .ok_or("revoked inherited trace delivered")?;
    assert_eq!(Failure::from(&error), Failure::Denied);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    control.check()?;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.memory().reserve_output(64 * 1024)?);
    let healthy = session
        .prepare_definition(&Fixture::definition(
            "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
        ))
        .await?;
    assert_eq!(
        values(
            &session
                .execute_definition(&healthy, invocation())
                .await?
                .batches
        )?,
        [1]
    );
    Ok(())
}
