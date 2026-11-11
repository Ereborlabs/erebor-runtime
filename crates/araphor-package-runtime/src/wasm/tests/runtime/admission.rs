use super::*;

#[tokio::test]
async fn host_requires_graph_capability() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Service(AtomicUsize);
    impl Service {
        fn called<T>(&self) -> sdk::Result<T> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(sdk::Error::contract(
                sdk::ErrorCode::Failed,
                "unexpected host callback",
            ))
        }
    }
    impl sdk::InvocationHost for Service {
        fn read(&self, _: &str, _: &sdk::Dataset) -> sdk::Result<sdk::Input> {
            self.called()
        }
        fn stage(&self, _: &sdk::Dataset) -> sdk::Result<()> {
            self.called()
        }
    }
    impl sdk::InvocationService for Service {
        fn argument_schema(&self, _: &str) -> sdk::Result<sdk::Schema> {
            self.called()
        }
        fn command_schema(&self, _: &str) -> sdk::Result<sdk::Schema> {
            self.called()
        }
        fn reserve_transfer(&self) -> sdk::Result<sdk::Transfer> {
            self.called()
        }
    }

    let runtime = crate::Runtime::new(crate::Limits::default())?;
    let package = package();
    let image = bundle(&package)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let prepared = runtime.prepare(
        image.clone(),
        image.bundle().root.clone(),
        "evaluate".into(),
        &control,
    )?;
    let wasm = runtime.wasm()?;
    let (entered, entering) = std::sync::mpsc::channel();
    wasm.guest_entry(entered, None)?;
    let service = Arc::new(Service(AtomicUsize::new(0)));
    let workers = crate::TaskTracker::new();
    let error = runtime
        .evaluate_reserved(
            image.clone(),
            image.bundle().root.clone(),
            evaluation(&package, "echo", 42)?,
            control.within(None)?,
            &workers,
            None,
            prepared,
            None,
            Some(service.clone()),
            (),
        )
        .await
        .err()
        .ok_or("undeclared Graph host accepted")?;
    assert!(matches!(
        error,
        Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                field: "Graph capability",
                ..
            }
        }
    ));
    assert_eq!(service.0.load(Ordering::SeqCst), 0);
    assert!(wasm
        .entered
        .lock()
        .map_err(|_| "guest gate lock")?
        .is_some());
    assert!(matches!(
        entering.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(workers.is_empty());
    let (_, output) = runtime
        .evaluate(
            image.clone(),
            image.bundle().root.clone(),
            evaluation(&package, "echo", 42)?,
            control,
            &workers,
        )
        .await?;
    assert_eq!(value(&output)?, 42);
    assert!(wasm
        .entered
        .lock()
        .map_err(|_| "guest gate lock")?
        .is_none());
    workers.close();
    workers.wait().await;
    Ok(())
}

struct Lease {
    slots: Arc<tokio::sync::Semaphore>,
    observed: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.observed.store(
            self.slots.available_permits(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

#[tokio::test]
async fn owned_admission_binds_runtime() -> TestResult {
    let quota = crate::Limits {
        wasm: WasmLimits {
            evaluations: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    let first = crate::Runtime::new(quota)?;
    let second = crate::Runtime::new(quota)?;
    let package = package();
    let image = bundle(&package)?;
    let control = AnalysisReadControl::default();
    let prepared = first
        .prepare(
            Arc::clone(&image),
            image.bundle().root.clone(),
            "evaluate".into(),
            &control,
        )?
        .ok_or("prepared component")?;
    let other = second
        .prepare(
            Arc::clone(&image),
            image.bundle().root.clone(),
            "evaluate".into(),
            &control,
        )?
        .ok_or("second prepared component")?;
    let held = prepared.acquire_evaluation(&control).await?;
    let workers = crate::TaskTracker::new();
    let finite = first.evaluate(
        Arc::clone(&image),
        image.bundle().root.clone(),
        evaluation(&package, "echo", 9)?,
        control.within(None)?,
        &workers,
    );
    let error = tokio::time::timeout(Duration::from_secs(30), finite)
        .await?
        .err()
        .ok_or("finite admission waited or exceeded the bound")?;
    assert!(matches!(
        error,
        Error::AnalysisBusy {
            resource: "component evaluations",
            ..
        }
    ));
    let wrong = other.acquire_evaluation(&control).await?;
    let error = first
        .evaluate_reserved(
            Arc::clone(&image),
            image.bundle().root.clone(),
            evaluation(&package, "echo", 9)?,
            control.within(None)?,
            &workers,
            None,
            Some(prepared.clone()),
            wrong,
            None,
            (),
        )
        .await
        .err()
        .ok_or("foreign admission accepted")?;
    assert!(matches!(
        error,
        Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Invalid,
                field: "component evaluation admission",
                ..
            }
        }
    ));
    assert_eq!(
        first
            .wasm()?
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(0)
    );
    assert_eq!(
        second
            .wasm()?
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    let admitted = {
        let waiting = prepared.acquire_evaluation(&control);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        drop(held);
        waiting.await?
    };
    assert_eq!(
        first
            .wasm()?
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(0)
    );
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    let lease = Lease {
        slots: Arc::clone(
            first
                .wasm()?
                .evaluations
                .as_ref()
                .ok_or("evaluation slots")?,
        ),
        observed: Arc::clone(&observed),
    };
    let (_, output) = first
        .evaluate_reserved(
            Arc::clone(&image),
            image.bundle().root.clone(),
            evaluation(&package, "echo", 9)?,
            control.within(None)?,
            &workers,
            None,
            Some(prepared.clone()),
            admitted,
            None,
            lease,
        )
        .await?;
    assert_eq!(value(&output)?, 9);
    assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        first
            .wasm()?
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    workers.close();
    workers.wait().await;
    let admitted = prepared.acquire_evaluation(&control).await?;
    let error = first
        .evaluate_reserved(
            Arc::clone(&image),
            image.bundle().root.clone(),
            evaluation(&package, "echo", 9)?,
            control.within(None)?,
            &workers,
            None,
            Some(prepared),
            admitted,
            None,
            (),
        )
        .await
        .err()
        .ok_or("closed worker scope accepted an owned permit")?;
    assert!(matches!(
        error,
        Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Incomplete,
                field: "runtime scope is closed",
                ..
            }
        }
    ));
    assert_eq!(
        first
            .wasm()?
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn admission_cancellation_and_zero() -> TestResult {
    let disabled = WasmExecution::new(WasmLimits::default())?;
    assert!(disabled.evaluations.is_none());
    assert!(disabled
        .acquire_evaluation(&AnalysisReadControl::default())
        .await?
        .is_none());
    let largest = WasmExecution::new(WasmLimits {
        evaluations: Some(tokio::sync::Semaphore::MAX_PERMITS),
        ..Default::default()
    })?;
    assert_eq!(
        largest
            .evaluations
            .as_ref()
            .map(|capacity| capacity.available_permits()),
        Some(tokio::sync::Semaphore::MAX_PERMITS)
    );
    let invalid = WasmLimits {
        evaluations: Some(tokio::sync::Semaphore::MAX_PERMITS + 1),
        ..Default::default()
    };
    for rejected in [
        WasmExecution::new(invalid),
        WasmExecution::fixture_code(invalid),
    ] {
        assert!(matches!(
            rejected,
            Err(Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Invalid,
                    field: "component evaluations",
                    ..
                }
            })
        ));
    }
    for maximum in [0, 1] {
        let runtime = crate::Runtime::new(crate::Limits {
            wasm: WasmLimits {
                evaluations: Some(maximum),
                ..Default::default()
            },
            ..Default::default()
        })?;
        let package = package();
        let image = bundle(&package)?;
        let control = AnalysisReadControl::default();
        let prepared = runtime
            .prepare(
                Arc::clone(&image),
                image.bundle().root.clone(),
                "evaluate".into(),
                &control,
            )?
            .ok_or("prepared component")?;
        if maximum == 0 {
            assert!(matches!(
                prepared.acquire_evaluation(&control).await,
                Err(Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Limit,
                        field: "component evaluations",
                        ..
                    }
                })
            ));
        } else {
            let held = prepared.acquire_evaluation(&control).await?;
            let cancelled = AnalysisReadControl::default();
            let waiting = prepared.acquire_evaluation(&cancelled);
            tokio::pin!(waiting);
            assert!(futures_util::poll!(&mut waiting).is_pending());
            cancelled.cancel()?;
            assert!(matches!(
                waiting.await,
                Err(Error::Data {
                    source: araphor_data::Error::AnalysisReadCancelled { .. }
                })
            ));
            assert_eq!(
                runtime
                    .wasm()?
                    .evaluations
                    .as_ref()
                    .map(|capacity| capacity.available_permits()),
                Some(0)
            );
            drop(held);
            let admitted = prepared.acquire_evaluation(&control).await?;
            assert_eq!(
                runtime
                    .wasm()?
                    .evaluations
                    .as_ref()
                    .map(|capacity| capacity.available_permits()),
                Some(0)
            );
            drop(admitted);
        }
        assert_eq!(
            runtime
                .wasm()?
                .evaluations
                .as_ref()
                .map(|capacity| capacity.available_permits()),
            Some(maximum)
        );
    }
    Ok(())
}
