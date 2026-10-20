use std::time::Duration;

use crate::{AnalysisReadControl, WasmLimits};

use super::{admission::CompileBudget, WasmExecution};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

mod runtime;

#[test]
fn admission_rejects_native_images() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let image = runtime
        .engine
        .precompile_component(&wat::parse_str("(component)")?)?;
    assert!(matches!(
        wasmtime::Engine::detect_precompiled(&image),
        Some(wasmtime::Precompiled::Component)
    ));
    assert!(matches!(
        runtime.admit(&image, &AnalysisReadControl::default()),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: super::Code::Invalid,
                field: "component binary",
                ..
            }
        })
    ));
    Ok(())
}

#[test]
fn admission_requires_analysis_contract() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        cache_entries: Some(1),
        memory_bytes: Some(256 * 1024 * 1024),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
    for source in [
        "(component)",
        "(component (import \"wasi:filesystem/types@0.2.0\" (instance)))",
        "(component (component (component)))",
    ] {
        let bytes = wat::parse_str(source)?;
        assert!(runtime.admit(&bytes, &control).is_err(), "{source}");
    }
    let bytes = wat::parse_str(
        "(component (core module $large (memory 4097)) (core instance (instantiate $large)))",
    )?;
    assert!(matches!(
        runtime.admit(&bytes, &control),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: super::Code::Limit,
                ..
            }
        })
    ));
    assert!(runtime.admit(b"not a component", &control).is_err());
    assert!(runtime
        .admit(&wat::parse_str("(module)")?, &control)
        .is_err());
    assert!(runtime
        .cache
        .lock()
        .map_err(|_| "component cache lock")?
        .available(0));
    Ok(())
}

#[test]
fn sdk_components_pass_admission() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let components: [(&str, &[u8]); 5] = [
        (
            "discovery",
            araphor_analysis_builtins::components::DISCOVERY,
        ),
        ("process", araphor_analysis_builtins::components::PROCESS),
        (
            "credentials",
            araphor_analysis_builtins::components::CREDENTIALS,
        ),
        (
            "kubernetes",
            araphor_analysis_builtins::components::KUBERNETES,
        ),
        (
            "detector-example",
            araphor_analysis_builtins::components::DETECTOR,
        ),
    ];
    for (name, bytes) in components {
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(45))?;
        let result = runtime.admit(bytes, &control);
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    Ok(())
}

#[test]
fn admission_bounds_compile_work() -> TestResult {
    let control = AnalysisReadControl::default();
    let bytes = wat::parse_str("(component)")?;
    let quota = WasmLimits {
        source_bytes: Some(bytes.len()),
        ..Default::default()
    };
    CompileBudget::check(&bytes, &control, &quota)?;
    assert!(matches!(
        CompileBudget::check(
            &bytes,
            &control,
            &WasmLimits {
                source_bytes: Some(bytes.len() - 1),
                ..quota
            }
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: super::Code::Limit,
                field: "component source bytes",
                ..
            }
        })
    ));
    let quota = WasmLimits {
        function_operators: Some(32_768),
        compile_instances: Some(16),
        ..Default::default()
    };
    let body = "nop ".repeat(65_536);
    let bytes = wat::parse_str(format!("(component (core module (func {body})))"))?;
    assert!(CompileBudget::check(&bytes, &control, &quota).is_err());
    let bytes = wat::parse_str("(component (core module (func (local i32))))")?;
    CompileBudget::check(&bytes, &control, &quota)?;
    let instances = "(core instance (instantiate $empty))".repeat(17);
    let bytes = wat::parse_str(format!("(component (core module $empty) {instances})"))?;
    assert!(matches!(
        CompileBudget::check(&bytes, &control, &quota),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: super::Code::Limit,
                ..
            }
        })
    ));
    let bytes = wat::parse_str("(component (core module (func (local i32))))")?;
    control.cancel()?;
    assert!(matches!(
        CompileBudget::check(&bytes, &control, &quota),
        Err(crate::Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    Ok(())
}

#[test]
fn evaluation_capacity_recovers() -> TestResult {
    use std::future::Future;
    use std::task::{Context, Poll};

    let runtime = WasmExecution::new(WasmLimits {
        evaluations: Some(4),
        ..Default::default()
    })?;
    let permits = (0..4)
        .map(|_| runtime.try_acquire_evaluation())
        .collect::<crate::Result<Vec<_>>>()?;
    assert!(matches!(
        runtime.try_acquire_evaluation(),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    let wait = runtime.wait_capacity("component evaluations", 1);
    tokio::pin!(wait);
    assert!(wait.as_mut().poll(&mut context).is_pending());
    drop(permits);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
    let _permit = runtime.try_acquire_evaluation()?;
    Ok(())
}

#[test]
fn wait_checks_resource() -> TestResult {
    use std::future::Future;
    use std::task::{Context, Poll};

    let runtime = WasmExecution::new(WasmLimits {
        evaluations: Some(4),
        ..Default::default()
    })?;
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    let permits = (0..4)
        .map(|_| runtime.try_acquire_evaluation())
        .collect::<crate::Result<Vec<_>>>()?;
    let wait = runtime.wait_capacity("component evaluations", 1);
    tokio::pin!(wait);
    assert!(wait.as_mut().poll(&mut context).is_pending());
    runtime.capacity.send_replace(());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    drop(permits);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));

    let compiler = runtime
        .compiler
        .lock()
        .map_err(|_| "compiler fixture lock")?;
    let wait = runtime.wait_capacity("component compiler", 1);
    tokio::pin!(wait);
    assert!(wait.as_mut().poll(&mut context).is_pending());
    runtime.capacity.send_replace(());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    drop(compiler);
    runtime.capacity.send_replace(());
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
    Ok(())
}
