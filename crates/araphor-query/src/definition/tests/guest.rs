use std::sync::mpsc;
use std::time::Duration;

use araphor_data::AnalysisSelectionV1;
use araphor_package_runtime::{Runtime, TaskTracker};
use futures_util::FutureExt as _;
use sdk::arrow_array::UInt64Array;

use super::execution::{component, invocation};
use super::*;

const BYTES: usize = 16 * 1024;

async fn fixture(limits: Limits) -> TestResult<(Fixture, PackageBundleV1)> {
    let bundle = component("wasm", "evaluate")?;

    let fixture = Fixture::image_limits(limits, &bundle, &definition("'echo'")).await?;
    Ok((fixture, bundle))
}

fn definition(mode: &str) -> Definition {
    Fixture::sql(format!(
        r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => {mode}, amount => 7)"#,
    ))
}

async fn entered(receiver: mpsc::Receiver<()>) -> TestResult {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(30))).await??;
    Ok(())
}

#[tokio::test]
async fn guest_input_precedes_entry() -> TestResult {
    let (fixture, _) = fixture(Limits {
        input_bytes: BYTES * 4,
        output_capacity: Some(BYTES * 4),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })
    .await?;
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let prepared = fixture
        .prepare(&definition(&format!("'{}'", "x".repeat(BYTES * 8))))
        .await?;
    let before = fixture.engine.store().meta()?;
    let retained = fixture.engine.memory().input_reserved();
    let error = fixture
        .execute(&prepared, invocation("oversized-parameters"))
        .await
        .err()
        .ok_or("oversized invocation entered guest")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::InputTooLarge);
    assert!(
        matches!(&error, crate::Error::Sql { source }
            if matches!(source.find_root(), datafusion::common::DataFusionError::ResourcesExhausted(resource)
                if resource == "package input bytes")),
        "{error:?}"
    );
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert_eq!(fixture.engine.memory().input_reserved(), retained);
    drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(prepared);
    let prepared = fixture.prepare(&definition("'echo'")).await?;
    let output = fixture
        .execute(&prepared, invocation("valid-parameters"))
        .await?;
    assert_eq!(
        output
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        output.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("UInt64 output")?
            .values()
            .as_ref(),
        &[7]
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((output, prepared));
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn guest_transfer_reserved_before_entry() -> TestResult {
    let capacity = BYTES * 4;
    let (fixture, _) = fixture(Limits {
        output_bytes: capacity,
        output_capacity: Some(capacity),
        ..Default::default()
    })
    .await?;
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let prepared = fixture.prepare(&definition("'echo'")).await?;
    let pressure = fixture.engine.memory().reserve_output(capacity)?;
    let before = fixture.engine.store().meta()?;
    let error = fixture
        .execute(&prepared, invocation("output-quota"))
        .await
        .err()
        .ok_or("guest transfer exceeded its reservation")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Busy);
    assert!(
        std::iter::successors(
            Some(&error as &(dyn std::error::Error + 'static)),
            |source| source.source(),
        )
        .any(|source| matches!(
            source.downcast_ref::<crate::Error>(),
            Some(crate::Error::Capacity {
                resource: "shared output",
                source: datafusion::common::DataFusionError::ResourcesExhausted(_),
            })
        )),
        "{error:?}"
    );
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    drop(pressure);
    drop(fixture.engine.memory().reserve_output(capacity)?);
    Ok(())
}

#[tokio::test]
async fn guest_copy_obeys_reservation() -> TestResult {
    let capacity = BYTES * 4;
    let (fixture, _) = fixture(Limits {
        output_bytes: capacity,
        output_capacity: Some(capacity),
        ..Default::default()
    })
    .await?;
    let prepared = fixture
        .prepare(&Fixture::sql(format!(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'oversized', amount => {})"#,
            capacity * 2,
        )))
        .await?;
    let error = fixture
        .execute(&prepared, invocation("copy-budget"))
        .await
        .err()
        .ok_or("oversized component return was lifted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::InputTooLarge);
    let mut source: &(dyn std::error::Error + 'static) = &error;
    let runtime = loop {
        if let Some(runtime) = source.downcast_ref::<araphor_package_runtime::Error>() {
            break runtime;
        }
        source = source
            .source()
            .ok_or_else(|| format!("missing Runtime error: {error:?}"))?;
    };
    let araphor_package_runtime::Error::PackageWasm {
        code: araphor_data::PackageErrorCodeV1::Limit,
        source,
        ..
    } = runtime
    else {
        return Err(format!("expected Wasm copy limit: {error:?}").into());
    };
    let mut root: &dyn std::error::Error = source.as_ref();
    while let Some(next) = root.source() {
        root = next;
    }
    assert_eq!(
        root.to_string(),
        concat!(
            "too much data is being copied between the host and the guest: ",
            "fuel allocated for hostcalls has been exhausted"
        ),
        "{error:?}"
    );
    drop(fixture.engine.memory().reserve_output(capacity)?);
    let prepared = fixture.prepare(&definition("'echo'")).await?;
    let output = fixture
        .execute(&prepared, invocation("after-copy-failure"))
        .await?;
    assert_eq!(
        output.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("UInt64 output")?
            .value(0),
        7
    );
    drop(output);
    drop(fixture.engine.memory().reserve_output(capacity)?);
    Ok(())
}

#[tokio::test]
async fn guest_scratch_reserved_before_entry() -> TestResult {
    let mut bundle = component("wasm", "evaluate")?;
    bundle.root.revision = "scratch".into();
    bundle.artifacts[0].descriptor.revision = "scratch".into();

    let source = Fixture::sql(format!(
        r#"SELECT * FROM "runtime-fixture"."scratch".evaluate(mode => '{}', amount => 7)"#,
        "echo".repeat(8192),
    ));
    let fixture = Fixture::image_limits(
        Limits {
            input_bytes: BYTES * 4,
            input_capacity: Some(BYTES * 4),
            ..Default::default()
        },
        &bundle,
        &source,
    )
    .await?;
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let prepared = fixture.prepare(&source).await?;
    let retained = fixture.engine.memory().input_reserved();
    assert_eq!(
        fixture.engine.limits().input_capacity,
        Some(retained + BYTES * 4)
    );
    drop(fixture.engine.memory().reserve_input(BYTES * 4)?);
    let error = fixture
        .execute(&prepared, invocation("input-quota"))
        .await
        .err()
        .ok_or("guest input scratch exceeded its reservation")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::Busy,
        "{error:?}"
    );
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if let Some(crate::Error::Capacity { resource, source }) =
            cause.downcast_ref::<crate::Error>()
        {
            assert_eq!(*resource, "shared input");
            let datafusion::common::DataFusionError::ResourcesExhausted(message) = source else {
                return Err(format!("scratch allocation lost native cause: {error:?}").into());
            };
            assert!(
                message.contains("for araphor input with 0.0 B already allocated"),
                "{error:?}"
            );
            break;
        }
        cause = cause
            .source()
            .ok_or_else(|| format!("scratch allocation lost capacity cause: {error:?}"))?;
    }
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(fixture.engine.memory().input_reserved(), retained);
    drop(prepared);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_capacity_held_until_join() -> TestResult {
    let limits = Limits {
        input_bytes: BYTES * 32,
        output_bytes: BYTES * 4,
        input_capacity: Some(BYTES * 32),
        output_capacity: Some(BYTES * 4),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    };
    let (fixture, _) = fixture(limits).await?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.engine.guest_entry(entry, Some(waiting))?;
    let prepared = fixture.prepare(&definition("'cancel'")).await?;
    let control = AnalysisReadControl::default();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, 123)?;
    let worker = tokio::spawn(async move {
        session
            .execute_definition(&prepared, invocation("held"))
            .await
    });
    if let Err(error) = entered(observed).await {
        let _released = release.send(());
        let result = worker.await?;
        return Err(format!(
            "guest entry failed: {error}; execution error: {:?}",
            result.err()
        )
        .into());
    }
    assert!(fixture.engine.memory().reserve_input(BYTES * 32).is_err());
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    control.cancel()?;
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), worker)
        .await??
        .err()
        .ok_or("cancelled guest completed")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn guest_drop_keeps_worker_lease() -> TestResult {
    let fixture = Fixture::limits(Limits {
        input_bytes: BYTES,
        output_bytes: BYTES,
        input_capacity: Some(BYTES),
        output_capacity: Some(BYTES),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let bundle = component("wasm", "evaluate")?;
    let runtime = Runtime::new(Default::default())?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    runtime.guest_entry(entry, Some(waiting))?;
    let descriptor = &bundle.artifacts[0].descriptor;
    let model = &descriptor.exports[0];
    let evaluation = sdk::Evaluation {
        previous_outputs: Vec::new(),
        export: "evaluate".into(),
        inputs: Vec::new(),
        checkpoint: None,
        parameters: araphor_data::decode_parameters(
            &model.parameters,
            Some(&serde_json::json!({"mode": "cancel", "amount": 7})),
        )?,
        context: sdk::EvaluationContext {
            id: "dropped".into(),
            time_utc_ns: 123,
            seed: None,
        },
    };
    let lease = (
        fixture.engine.memory().reserve_input(BYTES)?,
        fixture.engine.memory().reserve_output(BYTES)?,
        fixture.engine.reserve_evaluation([1; 16])?,
    );
    let workers = TaskTracker::new();
    let package = bundle.root.clone();
    let mut call = Box::pin(runtime.evaluate_reserved(
        Arc::new(araphor_package::PackageBundle::try_from(bundle)?),
        package,
        evaluation,
        AnalysisReadControl::default(),
        &workers,
        None,
        None,
        None,
        lease,
    ));
    assert!(call.as_mut().now_or_never().is_none());
    if let Err(error) = entered(observed).await {
        let _released = release.send(());
        return Err(format!(
            "guest entry failed: {error}; execution error: {:?}",
            call.await.err()
        )
        .into());
    }
    drop(call);
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    workers.close();
    tokio::time::timeout(Duration::from_secs(30), workers.wait()).await?;
    drop(fixture.engine.memory().reserve_input(BYTES)?);
    drop(fixture.engine.memory().reserve_output(BYTES)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn guest_defaults_disable_quotas() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(fixture.engine.limits().input_capacity, None);
    assert_eq!(fixture.engine.limits().output_capacity, None);
    let bundle = component("wasm", "evaluate")?;
    fixture.install(&bundle)?;
    let prepared = fixture.prepare(&definition("'echo'")).await?;
    let result = fixture
        .execute(&prepared, crate::definition::Invocation::default())
        .await?;
    assert_eq!(
        result.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("output type")?
            .value(0),
        7
    );
    Ok(())
}

#[tokio::test]
async fn wasm_preserves_input_capacity() -> TestResult {
    let capacity = BYTES * 4;
    let fixture = Fixture::limits(Limits {
        output_bytes: capacity,
        output_capacity: Some(capacity),
        ..Default::default()
    })?;
    let bundle = component("wasm", "accumulate")?;
    fixture.install(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(
                input => (SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM range(4096)))"#,
        ))
        .await?;
    let result = fixture
        .execute(&prepared, invocation("wasm-output-capacity"))
        .await?;
    let call = result.calls.values().next().ok_or("call")?;
    assert_eq!(
        call.evaluation().inputs[0]
            .data
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        4096
    );
    assert!(call.evaluation().inputs[0].data.allocated_bytes() > capacity / 4);
    assert_eq!(
        result.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("output type")?
            .value(0),
        4096
    );
    assert_eq!(
        call.output()
            .checkpoint
            .as_ref()
            .ok_or("checkpoint")?
            .datasets[0]
            .batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("checkpoint type")?
            .value(0),
        4096
    );
    assert!(call.output().allocated_bytes() <= capacity / 4);
    drop(result);
    drop(fixture.engine.memory().reserve_output(capacity)?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_capacity_preserves_input() -> TestResult {
    let fixture = Fixture::limits(Limits {
        output_bytes: BYTES,
        output_capacity: Some(BYTES),
        ..Default::default()
    })?;
    let bundle = component("native", "count-input")?;

    fixture.install(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
        input => (SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM range(4096)),
        mode => 'sum-input', amount => 0)"#,
        ))
        .await?;
    let result = fixture
        .execute(&prepared, invocation("native-output-quota"))
        .await?;
    let call = result.calls.values().next().ok_or("call")?;
    assert_eq!(
        call.evaluation().inputs[0]
            .data
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        4096
    );
    assert_eq!(
        result.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("output type")?
            .value(0),
        4096
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_checkpoint_shares_output_budget() -> TestResult {
    let bundle = component("native", "accumulate")?;
    let source = Fixture::sql(
        r#"SELECT * FROM "runtime-fixture"."1".accumulate(
            input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#,
    );
    let baseline = Fixture::installed(&bundle)?;
    let prepared = baseline.prepare(&source).await?;
    let result = baseline.execute(&prepared, invocation("baseline")).await?;
    let output = result.calls.values().next().ok_or("call")?.output();
    let bytes = output.allocated_bytes();
    let checkpoint = output.checkpoint.as_ref().ok_or("checkpoint")?;
    assert!(output.datasets[0].allocated_bytes() < bytes - 1);
    assert!(checkpoint.datasets[0].allocated_bytes() < bytes - 1);
    for capacity in [bytes - 1, bytes] {
        let fixture = Fixture::limits(Limits {
            output_bytes: capacity,
            output_capacity: Some(capacity),
            ..Default::default()
        })?;
        fixture.install(&bundle)?;
        let prepared = fixture.prepare(&source).await?;
        let result = fixture
            .execute(&prepared, invocation("stateful-budget"))
            .await;
        if capacity < bytes {
            let error = result
                .err()
                .ok_or("combined native output exceeded its budget")?;
            let source = format!("{error:?}");
            assert!(
                source.contains("native stream data")
                    || source.contains("native bytes")
                    || source.contains("native output bytes"),
                "{source}"
            );
        } else {
            let result = result?;
            let output = result.calls.values().next().ok_or("call")?.output();
            assert_eq!(output.allocated_bytes(), bytes);
            let checkpoint = output.checkpoint.as_ref().ok_or("checkpoint")?;
            for data in [&output.datasets[0], &checkpoint.datasets[0]] {
                assert_eq!(
                    data.batches[0]
                        .column(0)
                        .as_any()
                        .downcast_ref::<UInt64Array>()
                        .ok_or("output type")?
                        .value(0),
                    7
                );
            }
            assert!(fixture.engine.memory().reserve_output(1).is_err());
        }
        drop(fixture.engine.memory().reserve_output(capacity)?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_cancel_joins_worker() -> TestResult {
    use futures_util::StreamExt as _;

    for preparing in [false, true] {
        let (fixture, _) = fixture(Limits {
            input_bytes: BYTES * 32,
            input_capacity: Some(BYTES * 32),
            output_bytes: BYTES * 4,
            output_capacity: Some(BYTES * 4),
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })
        .await?;
        let prepared = fixture.prepare(&definition("'cancel'")).await?;
        let (entry, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        if preparing {
            fixture.engine.preparation_entry(entry, waiting)?;
        } else {
            fixture.engine.guest_entry(entry, Some(waiting))?;
        }
        let session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            123,
        )?;
        let sources = prepared.sources().clone();
        let PreparedDefinition { plan, admission } = prepared;
        drop(admission);
        let mut stream = session.subscribe(plan, sources, b"join worker", true)?;
        tokio::select! {
            result = entered(observed) => result?,
            result = stream.next() => return Err(format!("worker did not enter: {result:?}").into()),
        }
        let mut joined = Box::pin(stream.cancel_and_join());
        assert!(futures_util::poll!(joined.as_mut()).is_pending());
        assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
        if !preparing {
            assert!(fixture.engine.memory().reserve_input(BYTES * 32).is_err());
            assert!(fixture.engine.memory().reserve_output(1).is_err());
        }
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(30), joined).await??;
        drop(
            fixture
                .engine
                .memory()
                .reserve_input(
                    fixture
                        .engine
                        .limits()
                        .input_capacity
                        .ok_or("input capacity")?,
                )
                .map_err(|error| format!("cancel preparing={preparing}: {error:?}"))?,
        );
        drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        if !preparing {
            let prepared = fixture.prepare(&definition("'echo'")).await?;
            let session = fixture.engine.session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                123,
            )?;
            let sources = prepared.sources().clone();
            let PreparedDefinition { plan, admission } = prepared;
            drop(admission);
            let mut stream = session.subscribe(plan, sources, b"retained output", true)?;
            let update = tokio::time::timeout(Duration::from_secs(30), stream.next())
                .await?
                .ok_or("completed subscription ended")?
                .map_err(|error| format!("retained output: {error:?}"))?;
            assert_eq!(update.calls.len(), 1);
            tokio::time::timeout(Duration::from_secs(30), stream.cancel_and_join()).await??;
            assert_eq!(
                update
                    .calls
                    .values()
                    .next()
                    .ok_or("call")?
                    .output()
                    .datasets[0]
                    .batches[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("UInt64 output")?
                    .value(0),
                7
            );
            drop(fixture.engine.reserve_evaluation([1; 16])?);
            drop(update);
            drop(
                fixture
                    .engine
                    .memory()
                    .reserve_input(BYTES * 32)
                    .map_err(|error| format!("retained output release: {error:?}"))?,
            );
            drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_revocation_joins_guest() -> TestResult {
    use futures_util::StreamExt as _;

    let (fixture, _) = fixture(Limits {
        input_bytes: BYTES * 32,
        input_capacity: Some(BYTES * 32),
        output_bytes: BYTES * 4,
        output_capacity: Some(BYTES * 4),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })
    .await?;
    let prepared = fixture.prepare(&definition("'cancel'")).await?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.engine.guest_entry(entry, Some(waiting))?;
    let session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        123,
    )?;
    let (authority, changes) = tokio::sync::watch::channel(0u64);
    let sources = prepared.sources().clone();
    let PreparedDefinition { plan, admission } = prepared;
    drop(admission);
    let mut stream = session
        .subscribe(plan, sources, b"join revoked", true)?
        .until_change(changes);
    tokio::select! {
        result = entered(observed) => result?,
        result = stream.next() => return Err(format!("guest did not enter: {result:?}").into()),
    }
    authority.send_replace(1);
    let mut denied = Box::pin(stream.next());
    assert!(futures_util::poll!(denied.as_mut()).is_pending());
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), denied)
        .await?
        .ok_or("revoked subscription ended without denial")?
        .err()
        .ok_or("revoked subscription emitted output")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    stream.cancel_and_join().await?;
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    drop(fixture.engine.memory().reserve_output(BYTES * 4)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_cancel_joins_capture() -> TestResult {
    use futures_util::StreamExt as _;

    let capacity = 2 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_bytes: capacity,
        input_capacity: Some(capacity),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.event(1)?;
    let prepared = fixture
        .prepare(&Fixture::sql("SELECT source_cursor FROM events"))
        .await?;
    let control = AnalysisReadControl::default();
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    control.on_read_step(move || {
        entry.send(()).map_err(|_| {
            araphor_data::PackageErrorCodeV1::Incomplete.error("capture test entry")
        })?;
        waiting.recv_timeout(Duration::from_secs(30)).map_err(|_| {
            araphor_data::PackageErrorCodeV1::Incomplete.error("capture test release")
        })?;
        Ok(())
    })?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, 123)?;
    let sources = prepared.sources().clone();
    let PreparedDefinition { plan, admission } = prepared;
    drop(admission);
    let mut stream = session.subscribe(plan, sources, b"join capture", true)?;
    tokio::select! {
        result = entered(observed) => result?,
        result = stream.next() => return Err(format!("capture did not enter: {result:?}").into()),
    }
    let mut joined = Box::pin(stream.cancel_and_join());
    assert!(futures_util::poll!(joined.as_mut()).is_pending());
    assert!(fixture.engine.memory().reserve_input(capacity).is_err());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), joined).await??;
    drop(fixture.engine.memory().reserve_input(capacity)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}
