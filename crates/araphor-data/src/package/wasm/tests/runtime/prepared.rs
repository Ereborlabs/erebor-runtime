use std::sync::atomic::Ordering;

use super::*;

#[test]
fn prepared_handle_keeps_binding() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let foreign = WasmExecution::new(WasmLimits {
        fuel: Some(100_000_000),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    let input = evaluation(&package, "echo", 42)?;
    let prepared = runtime.prepare(COMPONENT, &control)?;
    assert!(matches!(
        foreign.evaluate_prepared(
            &package,
            &input,
            prepared,
            sdk::wire::Evaluation::encode(&package, &input)?,
            &control,
        ),
        Err(Error::Package {
            code: Code::Unsupported,
            field: "component engine",
            ..
        })
    ));
    assert_eq!(foreign.running.load(Ordering::Acquire), 0);

    let prepared = runtime.prepare(COMPONENT, &control)?;
    runtime
        .cache
        .lock()
        .map_err(|_| "fixture cache lock")?
        .clear();
    let _compiler = runtime
        .compiler
        .lock()
        .map_err(|_| "fixture compiler lock")?;
    assert!(matches!(
        runtime.admit(COMPONENT, &control),
        Err(Error::AnalysisBusy {
            resource: "component compiler",
            ..
        })
    ));
    let output = runtime.evaluate_prepared(
        &package,
        &input,
        prepared,
        sdk::wire::Evaluation::encode(&package, &input)?,
        &control,
    )?;
    assert_eq!(value(&output)?, 42);
    assert_eq!(runtime.running.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn retained_trap_keeps_code() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    let prepared = runtime.prepare(COMPONENT, &control)?;
    let retained = Arc::downgrade(&prepared.0);
    drop(prepared);
    let input = evaluation(&package, "trap", 0)?;
    let error = runtime
        .evaluate(&package, &input, COMPONENT, &control)
        .err()
        .ok_or("guest trap absent")?;
    let Error::PackageWasm { code, source, .. } = &error else {
        return Err("guest trap variant changed".into());
    };
    assert_eq!(*code, Code::Incomplete);
    assert!(source.to_string().contains("wasm backtrace:\n    0:"));
    let mut cause: &dyn std::error::Error = source.as_ref();
    while let Some(next) = cause.source() {
        cause = next;
    }
    assert_eq!(
        cause.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::UnreachableCodeReached)
    );
    runtime
        .cache
        .lock()
        .map_err(|_| "fixture cache lock")?
        .clear();
    assert!(
        retained.upgrade().is_some(),
        "retained trap released its compiled code charge"
    );
    drop(error);
    assert!(retained.upgrade().is_none());
    Ok(())
}
