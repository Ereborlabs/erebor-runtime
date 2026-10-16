use super::*;

#[test]
fn default_quotas_execute_component() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    assert_eq!(runtime.limits, WasmLimits::default());
    let store = wasmtime::Store::new(&runtime.engine, ());
    assert!(store.get_fuel().is_err());
    let package = package();
    let limits = package.exports[0].limits;
    assert_eq!(WasmExecution::limits(limits, &runtime.limits), limits);
    assert_eq!(limits.max_bytes, 64 * 1024 * 1024);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let output = runtime.evaluate(
        &package,
        &evaluation(&package, "echo", 42)?,
        COMPONENT,
        &control,
    )?;
    assert_eq!(value(&output)?, 42);
    Ok(())
}

#[test]
fn explicit_fuel_exhausts_component() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        fuel: Some(100_000_000),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    let input = evaluation(&package, "echo", 9)?;
    assert_eq!(
        value(&runtime.evaluate(&package, &input, COMPONENT, &control)?)?,
        9
    );
    let error = runtime.evaluate(
        &package,
        &evaluation(&package, "loop", 0)?,
        COMPONENT,
        &control,
    );
    let Err(Error::PackageWasm {
        code: Code::Limit,
        source,
        ..
    }) = &error
    else {
        return Err(format!("{error:?}").into());
    };
    let mut cause: &dyn std::error::Error = source.as_ref();
    while let Some(next) = cause.source() {
        cause = next;
    }
    assert_eq!(
        cause.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::OutOfFuel),
        "{error:?}"
    );
    assert_eq!(
        value(&runtime.evaluate(&package, &input, COMPONENT, &control)?)?,
        9
    );
    Ok(())
}

#[test]
fn explicit_timeout_interrupts_component() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        timeout: Some(Duration::from_secs(1)),
        ..WasmLimits::default()
    })?;
    runtime.admit(
        COMPONENT,
        &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
    )?;
    let package = package();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let result = runtime.evaluate(
        &package,
        &evaluation(&package, "loop", 0)?,
        COMPONENT,
        &control,
    );
    assert!(
        matches!(
            result,
            Err(Error::Data {
                source: araphor_data::Error::AnalysisReadDeadline { .. }
            })
        ),
        "{result:?}"
    );
    control.check()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let output = runtime.evaluate(
        &package,
        &evaluation(&package, "echo", 42)?,
        COMPONENT,
        &control,
    )?;
    assert_eq!(value(&output)?, 42);
    Ok(())
}

#[test]
fn fixture_modes_keep_quotas() -> TestResult {
    let unlimited = WasmExecution::fixture_code(WasmLimits::default())?;
    let quota = WasmLimits {
        fuel: Some(100_000_000),
        host_calls: Some(4096),
        ..WasmLimits::default()
    };
    let limited = WasmExecution::fixture_code(quota)?;
    assert_eq!(limited.limits, quota);
    assert!(!Arc::ptr_eq(&unlimited.epoch, &limited.epoch));
    let configured = WasmLimits {
        fuel: Some(1),
        memory_bytes: Some(1),
        data_bytes: Some(1024),
        timeout: Some(Duration::from_millis(10)),
        allocation_bytes: Some(1024),
        host_calls: Some(1),
    };
    let strict = WasmExecution::fixture_code(configured)?;
    assert_eq!(strict.limits, configured);
    assert!(Arc::ptr_eq(&strict.epoch, &limited.epoch));
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    assert!(matches!(
        strict.admit(COMPONENT, &control),
        Err(Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Limit,
                ..
            }
        })
    ));
    let package = package();
    let input = evaluation(&package, "echo", 9)?;
    for runtime in [&unlimited, &limited] {
        assert_eq!(
            value(&runtime.evaluate(&package, &input, COMPONENT, &control)?)?,
            9
        );
    }
    Ok(())
}
