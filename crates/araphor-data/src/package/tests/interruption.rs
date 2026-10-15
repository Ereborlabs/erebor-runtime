use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use super::{bundle, run, Fixture, TestResult};
use crate::analysis::PackageKeyV1;
use crate::package::{AnalysisPackageOwner, PackageBundleV1, PackageErrorCodeV1, PackageRequestV1};
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, ContextSensitivityV1,
};

#[tokio::test(flavor = "current_thread")]
async fn package_supervisor_stop_during_admission() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .install(bundle("1", "SELECT 1::UBIGINT AS count"), None)
        .await?;
    let before = fixture.activation("test.model")?;
    let results = fixture.store.package_results(&before.key)?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (held, admission) = mpsc::channel();
    let (release, resumed) = mpsc::channel();
    let mut entered = Some(entered);
    *fixture
        .authority
        .before_admit
        .lock()
        .map_err(|_| "fixture admission observer")? = Some(Box::new(move || {
        if let Some(entered) = entered.take() {
            let _sent = entered.send(());
        }
        let _held = held.send(());
        resumed.recv().map_err(|_| {
            crate::package::PackageErrorCodeV1::Incomplete.error("fixture admission release")
        })?;
        Ok(())
    }));
    let (checked, observed) = mpsc::channel();
    let controller = std::thread::spawn(move || {
        let responsive_before_release = admission.recv_timeout(Duration::from_secs(5)).is_ok()
            && observed.recv_timeout(Duration::from_secs(5)).is_ok();
        let _released = release.send(());
        responsive_before_release
    });
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let mut worker = Box::pin(fixture.owner.clone().serve(receiver));
    tokio::select! {
        entered = ready => { entered?; }
        result = &mut worker => {
            result?;
            return Err("supervisor stopped before admission".into());
        }
    }
    stop.send(true)?;
    let completion = std::future::poll_fn(|context| {
        std::task::Poll::Ready(std::future::Future::poll(worker.as_mut(), context))
    })
    .await;
    let shutdown_pending = completion.is_pending();
    let retained_permit = fixture.owner.operations.available_permits() == 3;
    let _acknowledged = checked.send(());
    let responsive_before_release = tokio::task::spawn_blocking(move || {
        controller
            .join()
            .map_err(|_| "admission controller panicked")
    })
    .await??;
    match completion {
        std::task::Poll::Ready(result) => result?,
        std::task::Poll::Pending => {
            tokio::time::timeout(Duration::from_secs(5), worker).await??;
        }
    }
    assert!(responsive_before_release);
    assert!(shutdown_pending);
    assert!(retained_permit);
    assert_eq!(fixture.owner.operations.available_permits(), 4);
    let after = fixture
        .store
        .package_activation(&before.key)?
        .ok_or("activation absent")?;
    assert_eq!(after, before);
    assert_eq!(fixture.store.package_results(&before.key)?, results);
    Ok(())
}

#[tokio::test]
async fn package_cancelled_failure_preserves_state() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .install(bundle("1", "SELECT 1::UBIGINT AS count"), None)
        .await?;
    let before = fixture.activation("test.model")?;
    let results = fixture.store.package_results(&before.key)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    control.cancel()?;
    let error = crate::package::PackageErrorCodeV1::Incomplete.error("fixture failure");
    assert!(matches!(
        fixture.owner.failed(&before, &error, &control),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(
        fixture.store.package_activation(&before.key)?,
        Some(before.clone())
    );
    assert_eq!(fixture.store.package_results(&before.key)?, results);
    Ok(())
}

#[tokio::test]
async fn package_running_stop() -> TestResult {
    for revoke in [false, true] {
        let mut fixture = Fixture::new()?;
        let package = source_bundle(&fixture)?;
        fixture.install(package.clone(), None).await?;
        let before = fixture.activation("test.model")?;
        let (entered, ready) = mpsc::channel();
        let (release, resumed) = mpsc::channel();
        fixture.owner.query.set_scan_gate(entered, resumed)?;
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
        let owner = fixture.owner.clone();
        let grant = fixture.grant.clone();
        let stage = control.clone();
        let task = tokio::spawn(async move { owner.execute(grant, run("stopped"), stage).await });
        let ready = tokio::task::spawn_blocking(move || -> TestResult<_> {
            ready.recv_timeout(Duration::from_secs(5))?;
            Ok(ready)
        })
        .await??;
        if revoke {
            fixture.authority.set_revision(0);
        } else {
            control.cancel()?;
        }
        if revoke {
            assert!(tokio::time::timeout(Duration::from_secs(5), task)
                .await??
                .is_err());
            release.send(())?;
        } else {
            release.send(())?;
            assert!(tokio::time::timeout(Duration::from_secs(5), task)
                .await??
                .is_err());
        }
        tokio::task::spawn_blocking(move || ready.recv_timeout(Duration::from_secs(5))).await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.owner.operations.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let after = fixture
            .store
            .package_activation(&before.key)?
            .ok_or("activation absent")?;
        assert_eq!(after.checkpoint_revision, before.checkpoint_revision);
        assert_eq!(after.result_id, before.result_id);
        assert_eq!(fixture.store.package_results(&before.key)?.len(), 1);
        if revoke {
            fixture.renew();
            fixture.install(package, None).await?;
        }
        assert!(fixture.execute(run("resumed")).await.is_ok());
    }
    Ok(())
}

#[tokio::test]
async fn package_busy_preserves_result() -> TestResult {
    let fixture = Fixture::new()?;
    let package = source_bundle(&fixture)?;
    fixture.install(package.clone(), None).await?;
    let before = fixture.activation("test.model")?;
    let (entered, ready) = mpsc::channel();
    let (release, resumed) = mpsc::channel();
    fixture.owner.query.set_scan_gate(entered, resumed)?;
    let owner = fixture.owner.clone();
    let grant = fixture.grant.clone();
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let stage = control.clone();
    let task = tokio::spawn(async move { owner.execute(grant, run("held"), stage).await });
    let ready = tokio::task::spawn_blocking(move || -> TestResult<_> {
        ready.recv_timeout(Duration::from_secs(5))?;
        Ok(ready)
    })
    .await??;
    let checks = (|| -> TestResult {
        assert!(matches!(
            fixture
                .owner
                .inspect(&fixture.grant, "test", "test.model", None, &control),
            Err(crate::Error::AnalysisBusy { .. })
        ));
        assert!(matches!(
            fixture.owner.evaluate_active(
                &before,
                "automatic",
                true,
                &crate::package::PackageBundleRef::new(&package)?,
                &control
            ),
            Err(crate::Error::AnalysisBusy { .. })
        ));
        assert_eq!(
            fixture.store.package_activation(&before.key)?.as_ref(),
            Some(&before)
        );
        let result = fixture.result(before.result_id.as_deref().ok_or("result absent")?)?;
        assert!(!result.stale);
        Ok(())
    })();
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    ready.recv_timeout(Duration::from_secs(5))?;
    checks?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let status = fixture
        .owner
        .inspect(&fixture.grant, "test", "test.model", None, &control)?;
    assert!(status.exports[0].results.iter().any(|result| !result.stale));
    Ok(())
}

fn source_bundle(fixture: &Fixture) -> TestResult<PackageBundleV1> {
    fixture.store.commit_context(&AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "fixture".into(),
            entity_key: b"event".to_vec(),
            lifetime_key: b"lifetime".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"value".to_vec(),
    })?;
    let mut package = bundle("1", "SELECT count FROM source");
    let artifact = &mut package.artifacts[0];
    let mut input = artifact.descriptor.exports[0].outputs[0].clone();
    input.name = "source".into();
    artifact.descriptor.exports[0].inputs.push(input.into());
    artifact.descriptor.exports[0].inputs[0].source = araphor_analysis_sdk::InputSource::Query(
        "SELECT owner_revision AS count FROM context_versions".into(),
    );
    Ok(package)
}

pub(super) async fn running_guest(
    fixture: Fixture,
    package: PackageBundleV1,
    cause: &str,
) -> TestResult {
    let key = PackageKeyV1 {
        tenant_id: [1; 16],
        scope_id: "test".into(),
        package_id: "runtime-fixture".into(),
        export: "evaluate".into(),
    };
    let owner = fixture.owner.clone();
    let mut grant = fixture.grant.clone();
    if cause == "expiry" {
        grant.expires_utc_ns = Some(AnalysisPackageOwner::now() + 5_000_000_000);
    }
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let stage = control.clone();
    let task = tokio::spawn(async move {
        owner
            .execute(
                grant,
                PackageRequestV1::Install {
                    scope_id: "test".into(),
                    bundle: package,
                    parameters: Some(super::wasm::parameters("cancel")),
                },
                stage,
            )
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fixture.store.package_activation(&key)?.is_some() {
            break;
        }
        if task.is_finished() {
            return Err(format!("{cause}: guest activation absent: {:?}", task.await?).into());
        }
        if Instant::now() >= deadline {
            control.cancel()?;
            let result = tokio::time::timeout(Duration::from_secs(5), task).await;
            return Err(format!("{cause}: guest activation deadline: {result:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    match cause {
        "cancel" => control.cancel()?,
        "revoke" => fixture.authority.set_revision(0),
        _ => (),
    }
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .map_err(|error| format!("{cause}: guest task: {error}"))??;
    match cause {
        "cancel" => assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadCancelled { .. })
        )),
        "revoke" => assert!(matches!(
            result,
            Err(crate::Error::Package {
                code: PackageErrorCodeV1::Denied,
                ..
            })
        )),
        _ => assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadDeadline { .. })
                | Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    field: "package grant",
                    ..
                })
        )),
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.owner.operations.available_permits() != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| {
        format!(
            "{cause}: guest permits ({} available): {error}",
            fixture.owner.operations.available_permits()
        )
    })?;
    assert!(fixture.store.package_results(&key)?.is_empty());
    let active = fixture
        .store
        .package_activation(&key)?
        .ok_or("guest activation absent")?;
    assert!(active.result_id.is_none());
    assert_eq!(active.checkpoint_revision, 0);
    Ok(())
}
