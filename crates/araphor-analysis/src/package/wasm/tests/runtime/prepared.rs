use std::sync::atomic::Ordering;

use sha2::Digest as _;

use super::*;

#[test]
fn preparation_precedes_evaluation_deadline() -> TestResult {
    let fixture = crate::package::tests::Fixture::new()?;
    let query = crate::Engine::new(
        Arc::clone(&fixture.store),
        crate::Limits {
            evaluate_timeout: Duration::from_nanos(1),
            ..Default::default()
        },
    )?;
    let owner = crate::AnalysisPackageOwner::new(Arc::clone(&query), fixture.authority.clone())?;
    let package = package();
    let input = evaluation(&package, "echo", 42)?;
    let artifact = crate::package::PackageArtifactV1 {
        descriptor: package,
        implementations: vec![crate::package::PackageImplementationV1::Wasm {
            exports: vec!["evaluate".into()],
            artifact: COMPONENT.to_vec(),
        }],
        fixtures: Vec::new(),
    };
    let bundle = crate::package::installed::snapshot::InstalledBundle::new(
        &query,
        crate::package::PackageBundleV1 {
            schema_version: 1,
            root: crate::package::PackageRefV1 {
                package_id: artifact.descriptor.id.clone(),
                revision: artifact.descriptor.revision.clone(),
            },
            artifacts: vec![artifact],
        },
        query.memory(),
    )?;
    let artifact = &bundle.value.artifacts[0];
    let index = bundle.export_index(
        &artifact.descriptor.id,
        &artifact.descriptor.revision,
        &input.export,
    )?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let digest = sha2::Sha256::digest(COMPONENT).into();
    assert!(owner.wasm.cached(&digest)?.is_none());
    assert!(matches!(
        owner.evaluate_artifact(
            [1; 16],
            bundle,
            index,
            input,
            None,
            &query.memory().scope(),
            &control
        ),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadDeadline { .. }
        })
    ));
    assert!(owner.wasm.cached(&digest)?.is_some());
    control.check()?;
    query.reserve_evaluation([1; 16])?;
    query
        .memory()
        .reserve_input(query.limits().input_capacity)?;
    query
        .memory()
        .reserve_output(query.limits().output_capacity)?;
    Ok(())
}

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
    assert_eq!(foreign.running.load(Ordering::Acquire), 0);
    let cancelled = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    cancelled.cancel()?;
    assert!(matches!(
        foreign.invoke(&prepared, checked.encode()?.into(), &cancelled),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    assert_eq!(foreign.running.load(Ordering::Acquire), 0);
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
    assert_eq!(runtime.running.load(Ordering::Acquire), 0);
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
