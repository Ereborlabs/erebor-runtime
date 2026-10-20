use super::*;

#[tokio::test]
async fn preparation_precedes_guest_timeout() -> TestResult {
    use sha2::Digest as _;

    let runtime = crate::Runtime::new(crate::Limits {
        wasm: WasmLimits {
            timeout: Some(Duration::from_nanos(1)),
            evaluations: Some(1),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let wasm = runtime.wasm()?;
    let digest = sha2::Sha256::digest(COMPONENT).into();
    assert!(wasm.cached(&digest)?.is_none());
    let package = package();
    let image = bundle(&package);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let workers = crate::TaskTracker::new();
    let result = runtime
        .evaluate(
            Arc::clone(&image),
            image.root.clone(),
            evaluation(&package, "echo", 42)?,
            control.within(None)?,
            &workers,
        )
        .await;
    assert!(
        matches!(
            result,
            Err(Error::Data {
                source: araphor_data::Error::AnalysisReadDeadline { .. }
            })
        ),
        "{result:?}"
    );
    assert!(wasm.cached(&digest)?.is_some());
    assert_eq!(
        wasm.evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    control.check()?;
    workers.close();
    workers.wait().await;
    Ok(())
}

#[test]
fn prepared_handle_keeps_binding() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits {
        evaluations: Some(1),
        ..Default::default()
    })?;
    let foreign = WasmExecution::new(WasmLimits {
        fuel: Some(100_000_000),
        evaluations: Some(1),
        ..WasmLimits::default()
    })?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    let input = evaluation(&package, "echo", 42)?;
    let checked = package.check_evaluation(&input)?;
    let prepared = runtime.prepare(COMPONENT, &control)?;
    assert!(matches!(
        foreign.invoke(&prepared, checked.encode()?.into(), &control),
        Err(Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Unsupported,
                field: "component engine",
                ..
            }
        })
    ));
    assert_eq!(
        foreign
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    let cancelled = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    cancelled.cancel()?;
    assert!(matches!(
        foreign.invoke(&prepared, checked.encode()?.into(), &cancelled),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    assert_eq!(
        foreign
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    drop(prepared);

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
    let output = runtime.invoke(&prepared, checked.encode()?.into(), &control)?;
    let output = sdk::wire::Output::from(output).decode(&package, &input)?;
    assert_eq!(value(&output)?, 42);
    assert_eq!(
        runtime
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    Ok(())
}

#[test]
fn retained_trap_keeps_code() -> TestResult {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let package = package();
    let prepared = runtime.prepare(COMPONENT, &control)?;
    let retained = Arc::downgrade(&prepared.entry);
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
