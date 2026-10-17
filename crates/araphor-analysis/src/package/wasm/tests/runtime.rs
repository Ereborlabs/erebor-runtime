use std::sync::Arc;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{StringArray, UInt64Array};

use crate::{AnalysisReadControl, Error, PackageErrorCodeV1 as Code, WasmLimits};

use super::{TestResult, WasmExecution};

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
            limits: package.exports[0].limits,
        },
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
        data_bytes: Some(32 * 1024 * 1024),
        timeout: Some(Duration::from_secs(5)),
        allocation_bytes: Some(32 * 1024 * 1024),
        host_calls: Some(4096),
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
fn component_enforces_transfer_limits() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        data_bytes: Some(32 * 1024 * 1024),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let mut package = package();
    package.exports[0].limits = sdk::Limits {
        max_batches: u32::MAX,
        max_rows: u64::MAX,
        max_bytes: u64::MAX,
        max_checkpoint_bytes: u64::MAX,
    };
    let input = evaluation(&package, "echo", 42)?;
    let result = runtime.evaluate(&package, &input, COMPONENT, &control)?;
    assert_eq!(value(&result)?, 42);
    assert_eq!(input.context.limits, package.exports[0].limits);

    let input = evaluation(&package, &"x".repeat(32 * 1024 * 1024), 0)?;
    let result = runtime.evaluate(&package, &input, COMPONENT, &control);
    assert!(
        matches!(
            result,
            Err(Error::AnalysisContract { ref source, .. })
                if source.code() == sdk::ErrorCode::Limit
        ),
        "{result:?}"
    );
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

#[test]
fn fixture_code_separates_state() -> TestResult {
    let first = WasmExecution::fixture_code(WasmLimits::default())?;
    let second = WasmExecution::fixture_code(WasmLimits::default())?;
    assert!(Arc::ptr_eq(&first.epoch, &second.epoch));
    let package = package();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let permits = (0..4)
        .map(|_| {
            super::super::execution::EvaluationPermit::acquire(&first.running, &first.capacity)
        })
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
