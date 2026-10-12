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
