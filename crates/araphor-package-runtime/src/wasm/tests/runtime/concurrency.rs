use std::future::Future as _;
use std::task::Context;

use araphor_analysis_builtins::discovery::Discovery;

use super::*;

fn input(package: &sdk::Package, id: &str) -> sdk::Evaluation {
    let model = &package.exports[2];
    sdk::Evaluation {
        export: model.name.clone(),
        inputs: model
            .inputs
            .iter()
            .map(|port| sdk::Input {
                data: sdk::Dataset {
                    name: port.port.name.clone(),
                    batches: Vec::new(),
                },
                revision: sdk::Revision {
                    owner: "overlap-fixture".into(),
                    id: id.into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        checkpoint: None,
        parameters: None,
        context: sdk::EvaluationContext {
            id: id.into(),
            time_utc_ns: 123,
            seed: Some(7),
            limits: model.limits,
        },
    }
}

#[tokio::test]
async fn guests_overlap_with_independent_lifetimes() -> TestResult {
    let runtime = crate::Runtime::new(crate::Limits {
        wasm: WasmLimits {
            evaluations: Some(2),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let wasm = runtime.wasm()?;
    let package = Discovery::package();
    let image = Arc::new(PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: package.id.clone(),
            revision: package.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor: package.clone(),
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["groups".into()],
                artifact: araphor_analysis_builtins::components::DISCOVERY.to_vec(),
            }],
            fixtures: Vec::new(),
        }],
    });
    let first_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let second_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    wasm.admit(
        araphor_analysis_builtins::components::DISCOVERY,
        &first_control,
    )?;
    let workers = crate::TaskTracker::new();
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    let (entered, entering) = std::sync::mpsc::channel();
    let (first_release, released) = std::sync::mpsc::channel();
    wasm.guest_entry(entered, Some(released))?;
    let first = runtime.evaluate(
        Arc::clone(&image),
        image.root.clone(),
        input(&package, "first"),
        first_control.within(None)?,
        &workers,
    );
    tokio::pin!(first);
    assert!(first.as_mut().poll(&mut context).is_pending());
    tokio::task::spawn_blocking(move || entering.recv_timeout(Duration::from_secs(10))).await??;

    let (entered, entering) = std::sync::mpsc::channel();
    let (second_release, released) = std::sync::mpsc::channel();
    wasm.guest_entry(entered, Some(released))?;
    let second = runtime.evaluate(
        Arc::clone(&image),
        image.root.clone(),
        input(&package, "second"),
        second_control.within(None)?,
        &workers,
    );
    tokio::pin!(second);
    assert!(second.as_mut().poll(&mut context).is_pending());
    tokio::task::spawn_blocking(move || entering.recv_timeout(Duration::from_secs(10))).await??;
    let slots = wasm
        .evaluations
        .as_ref()
        .ok_or("configured evaluation slots")?;
    assert_eq!(slots.available_permits(), 0);

    first_release.send(())?;
    let first = first.await?;
    assert!(second.as_mut().poll(&mut context).is_pending());
    assert_eq!(slots.available_permits(), 1);
    second_control.check()?;
    second_release.send(())?;
    let second = second.await?;
    assert_eq!(slots.available_permits(), 2);
    for ((evaluation, output), id) in [(first, "first"), (second, "second")] {
        assert_eq!(evaluation.context.id, id);
        assert!(evaluation
            .inputs
            .iter()
            .all(|input| input.revision.id == id));
        assert_eq!(output.datasets.len(), 1);
        assert_eq!(output.datasets[0].name, "groups");
        assert!(output.datasets[0]
            .batches
            .iter()
            .all(|batch| batch.num_rows() == 0));
        assert!(output.checkpoint.is_none());
        assert!(output.evidence.is_empty());
        assert!(output.reasons.is_empty());
    }
    first_control.check()?;
    workers.close();
    workers.wait().await;
    Ok(())
}
