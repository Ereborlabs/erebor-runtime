use std::sync::Arc;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_package::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1};
use sdk::arrow_array::{StringArray, UInt64Array};

use crate::{AnalysisReadControl, Error, PackageErrorCodeV1 as Code, WasmLimits};

use super::{TestResult, WasmExecution};

mod admission;
mod batches;
mod concurrency;
mod prepared;
mod quotas;

const COMPONENT: &[u8] = araphor_analysis_builtins::components::RUNTIME;

fn package() -> sdk::Package {
    let mut model = sdk::Model::new(
        "evaluate",
        vec![],
        vec![sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    sdk::Package::new("runtime-fixture", "1", vec![model])
}

fn evaluation(package: &sdk::Package, mode: &str, amount: u64) -> sdk::Result<sdk::Evaluation> {
    Ok(sdk::Evaluation {
        export: "evaluate".into(),
        inputs: Vec::new(),
        checkpoint: None,
        parameters: Some(sdk::RecordBatch::try_new(
            Arc::new(package.exports[0].parameters.clone()),
            vec![
                Arc::new(StringArray::from(vec![mode])),
                Arc::new(UInt64Array::from(vec![amount])),
            ],
        )?),
        context: sdk::EvaluationContext {
            id: "runtime-test".into(),
            time_utc_ns: 123,
            seed: Some(7),
        },
    })
}

fn bundle(package: &sdk::Package) -> Arc<PackageBundleV1> {
    Arc::new(PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: package.id.clone(),
            revision: package.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor: package.clone(),
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["evaluate".into()],
                artifact: COMPONENT.to_vec(),
            }],
            fixtures: Vec::new(),
        }],
    })
}

fn value(output: &sdk::Output) -> std::result::Result<u64, &'static str> {
    output
        .datasets
        .first()
        .and_then(|data| data.batches.first())
        .and_then(|batch| batch.column(0).as_any().downcast_ref::<UInt64Array>())
        .map(|values| values.value(0))
        .ok_or("fixture output")
}

#[test]
fn component_state_is_separate() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    runtime.admit(COMPONENT, &control)?;
    {
        let _compiler = runtime.compiler.lock().map_err(|_| "compiler lock")?;
        runtime.admit(COMPONENT, &control)?;
        let uncached = wat::parse_str("(component)")?;
        assert!(matches!(
            runtime.admit(&uncached, &control),
            Err(Error::AnalysisBusy { .. })
        ));
    }
    let package = package();
    for (mode, amount, expected) in [
        ("echo", 42, 42),
        ("isolation", 0, 1),
        ("isolation", 0, 1),
        ("clock", 0, 123),
        ("seed", 0, 7),
    ] {
        let result = runtime.evaluate(
            &package,
            &evaluation(&package, mode, amount)?,
            COMPONENT,
            &control,
        )?;
        assert_eq!(value(&result)?, expected);
    }
    Ok(())
}

#[test]
fn component_recovers_after_failure() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        fuel: Some(100_000_000),
        memory_bytes: Some(256 * 1024 * 1024),

        timeout: Some(Duration::from_secs(5)),
        allocation_bytes: Some(32 * 1024 * 1024),
        host_calls: Some(4096),
        ..Default::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    runtime.admit(COMPONENT, &control)?;
    let package = package();
    for (mode, amount) in [
        ("trap", 0),
        ("loop", 0),
        ("hostcalls", 0),
        ("recurse", 1_000_000),
        ("memory", 512 * 1024 * 1024),
        ("oversized", 40 * 1024 * 1024),
    ] {
        let error = runtime.evaluate(
            &package,
            &evaluation(&package, mode, amount)?,
            COMPONENT,
            &control,
        );
        assert!(
            matches!(
                error,
                Err(Error::PackageWasm { .. })
                    | Err(Error::Data {
                        source: araphor_data::Error::AnalysisReadDeadline { .. }
                    })
            ),
            "{mode}: {error:?}"
        );
        if mode == "oversized" {
            let Err(Error::PackageWasm {
                code: Code::Limit,
                source,
                ..
            }) = &error
            else {
                return Err(format!("{mode}: {error:?}").into());
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
                )
            );
        }
        let result = runtime.evaluate(
            &package,
            &evaluation(&package, "echo", 9)?,
            COMPONENT,
            &control,
        )?;
        assert_eq!(value(&result)?, 9);
    }
    Ok(())
}

#[test]
fn component_validates_error_output() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    for (mode, code, field) in [
        ("denied", sdk::ErrorCode::Unauthorized, "fixture-denied"),
        ("limit", sdk::ErrorCode::Limit, "fixture-limit"),
        ("invalid-name", sdk::ErrorCode::Invalid, "dataset name"),
        (
            "invalid-evidence",
            sdk::ErrorCode::Invalid,
            "evidence or reason reference",
        ),
    ] {
        let error = runtime.evaluate(
            &package,
            &evaluation(&package, mode, 0)?,
            COMPONENT,
            &control,
        );
        assert!(
            matches!(
                error,
                Err(Error::AnalysisContract {
                    source: sdk::Error::Contract {
                        code: actual,
                        field: ref actual_field,
                        ..
                    },
                    ..
                }) if actual == code && actual_field == field
            ),
            "{mode}: {error:?}"
        );
    }
    Ok(())
}

#[test]
fn component_control_interrupts_runs() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    runtime.admit(
        COMPONENT,
        &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
    )?;
    let package = package();
    let input = evaluation(&package, "loop", 0)?;
    let deadline = AnalysisReadControl::with_timeout(Duration::from_millis(2))?;
    assert!(matches!(
        runtime.evaluate(&package, &input, COMPONENT, &deadline),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadDeadline { .. }
        })
    ));
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    control.cancel()?;
    assert!(matches!(
        runtime.evaluate(&package, &input, COMPONENT, &control),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let input = evaluation(&package, "cancel", 0)?;
    let (entered, entering) = std::sync::mpsc::channel();
    *runtime.entered.lock().map_err(|_| "test gate lock")? =
        Some(super::super::execution::GuestEntry {
            entered,
            release: None,
        });
    std::thread::scope(|scope| -> TestResult {
        let control = &control;
        let cancel = scope.spawn(move || -> TestResult {
            entering.recv_timeout(Duration::from_secs(10))?;
            control.cancel()?;
            Ok(())
        });
        let result = runtime.evaluate(&package, &input, COMPONENT, control);
        cancel.join().map_err(|_| "cancel worker")??;
        assert!(
            matches!(
                result,
                Err(Error::Data {
                    source: araphor_data::Error::AnalysisReadCancelled { .. }
                })
            ),
            "{result:?}"
        );
        Ok(())
    })?;
    Ok(())
}

#[tokio::test]
async fn runtime_cancellation_joins_guest_and_releases_capacity() -> TestResult {
    use std::future::Future as _;
    use std::task::Context;

    let runtime = crate::Runtime::new(crate::Limits {
        wasm: WasmLimits {
            evaluations: Some(1),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let wasm = runtime.wasm()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    wasm.admit(COMPONENT, &control)?;
    let package = package();
    let input = evaluation(&package, "cancel", 0)?;
    let bundle = bundle(&package);
    let reference = bundle.root.clone();
    let workers = crate::TaskTracker::new();
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    wasm.guest_entry(entered, Some(released))?;
    let call = runtime.evaluate(bundle, reference, input, control.within(None)?, &workers);
    tokio::pin!(call);
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(call.as_mut().poll(&mut context).is_pending());
    tokio::task::spawn_blocking(move || entering.recv_timeout(Duration::from_secs(10))).await??;

    control.cancel()?;
    assert!(call.as_mut().poll(&mut context).is_pending());
    let subsequent = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let input = evaluation(&package, "echo", 9)?;
    assert!(matches!(
        wasm.evaluate(&package, &input, COMPONENT, &subsequent),
        Err(Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    let result = call.await;
    assert!(
        matches!(
            result,
            Err(Error::Data {
                source: araphor_data::Error::AnalysisReadCancelled { .. }
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        value(&wasm.evaluate(&package, &input, COMPONENT, &subsequent)?)?,
        9
    );
    Ok(())
}

#[tokio::test]
async fn dropped_runtime_future_retains_worker_until_completion() -> TestResult {
    use std::future::Future as _;
    use std::task::Context;

    let runtime = crate::Runtime::new(crate::Limits {
        wasm: WasmLimits {
            evaluations: Some(1),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let wasm = runtime.wasm()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    wasm.admit(COMPONENT, &control)?;
    let package = package();
    let bundle = bundle(&package);
    let reference = bundle.root.clone();
    let workers = crate::TaskTracker::new();
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    wasm.guest_entry(entered, Some(released))?;
    let mut call = Box::pin(runtime.evaluate(
        bundle,
        reference,
        evaluation(&package, "cancel", 0)?,
        control.within(None)?,
        &workers,
    ));
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(call.as_mut().poll(&mut context).is_pending());
    tokio::task::spawn_blocking(move || entering.recv_timeout(Duration::from_secs(10))).await??;
    drop(call);
    assert!(matches!(
        control.check(),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    workers.close();
    let completed = workers.wait();
    tokio::pin!(completed);
    assert!(completed.as_mut().poll(&mut context).is_pending());
    let subsequent = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let input = evaluation(&package, "echo", 9)?;
    assert!(matches!(
        wasm.evaluate(&package, &input, COMPONENT, &subsequent),
        Err(Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    completed.await;
    let image = self::bundle(&package);
    assert!(matches!(
        runtime
            .evaluate(
                Arc::clone(&image),
                image.root.clone(),
                evaluation(&package, "echo", 9)?,
                subsequent.within(None)?,
                &workers,
            )
            .await,
        Err(Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Incomplete,
                field: "runtime scope is closed",
                ..
            }
        })
    ));
    assert_eq!(
        value(&wasm.evaluate(&package, &input, COMPONENT, &subsequent)?)?,
        9
    );
    Ok(())
}

#[test]
fn runtime_deadline_joins_queued_worker() -> TestResult {
    use std::future::Future as _;
    use std::task::Context;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?
        .block_on(async {
            let runtime = crate::Runtime::new(crate::Limits::default())?;
            runtime
                .wasm()?
                .admit(COMPONENT, &AnalysisReadControl::default())?;
            let package = package();
            let image = bundle(&package);
            let workers = crate::TaskTracker::new();
            let (entered, entering) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                let _sent = entered.send(());
                released.recv()
            });
            entering.await?;
            let control = AnalysisReadControl::with_timeout(Duration::from_secs(1))?;
            let call = runtime.evaluate(
                Arc::clone(&image),
                image.root.clone(),
                evaluation(&package, "echo", 42)?,
                control.within(None)?,
                &workers,
            );
            tokio::pin!(call);
            let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
            assert!(call.as_mut().poll(&mut context).is_pending());
            control.expired().await;
            assert!(call.as_mut().poll(&mut context).is_pending());
            assert!(!workers.is_empty());
            release.send(())?;
            blocker.await??;
            let result = call.await;
            assert!(
                matches!(
                    result,
                    Err(Error::Data {
                        source: araphor_data::Error::AnalysisReadDeadline { .. }
                    })
                ),
                "{result:?}"
            );
            workers.close();
            workers.wait().await;
            Ok(())
        })
}

#[test]
fn fixture_code_separates_state() -> TestResult {
    let limits = WasmLimits {
        evaluations: Some(4),
        ..Default::default()
    };
    let first = WasmExecution::fixture_code(limits)?;
    let second = WasmExecution::fixture_code(limits)?;
    assert!(wasmtime::Engine::same(&first.engine, &second.engine));
    let package = package();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let permits = (0..4)
        .map(|_| first.try_acquire_evaluation())
        .collect::<crate::Result<Vec<_>>>()?;
    let input = evaluation(&package, "isolation", 0)?;
    assert!(matches!(
        first.evaluate(&package, &input, COMPONENT, &control),
        Err(Error::AnalysisBusy { .. })
    ));
    assert_eq!(
        value(&second.evaluate(&package, &input, COMPONENT, &control)?)?,
        1
    );
    drop(permits);
    assert_eq!(
        value(&first.evaluate(&package, &input, COMPONENT, &control)?)?,
        1
    );
    let deadline = AnalysisReadControl::with_timeout(Duration::from_millis(2))?;
    assert!(matches!(
        first.evaluate(
            &package,
            &evaluation(&package, "loop", 0)?,
            COMPONENT,
            &deadline
        ),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadDeadline { .. }
        })
    ));
    assert_eq!(
        value(&second.evaluate(&package, &input, COMPONENT, &control)?)?,
        1
    );
    Ok(())
}
