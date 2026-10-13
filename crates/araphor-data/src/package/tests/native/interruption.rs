use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::{analysis::PackageKeyV1, AnalysisReadControl};

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_cancellation_revocation_and_expiry() -> TestResult {
    for cause in ["cancel", "revoke", "expiry"] {
        let fixture = Fixture::new()?;
        let package = native(component("1"))?;
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
                        parameters: Some(parameters("cancel")),
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
                return Err(format!("{cause}: native activation absent: {:?}", task.await?).into());
            }
            if Instant::now() >= deadline {
                control.cancel()?;
                let result = tokio::time::timeout(Duration::from_secs(5), task).await;
                return Err(format!("{cause}: native activation deadline: {result:?}").into());
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
            .map_err(|error| format!("{cause}: native task: {error}"))??;
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
                "{cause}: native permits ({} available): {error}",
                fixture.owner.operations.available_permits()
            )
        })?;
        assert!(fixture.store.package_results(&key)?.is_empty());
        let active = fixture
            .store
            .package_activation(&key)?
            .ok_or("native activation absent")?;
        assert!(active.result_id.is_none());
        assert_eq!(active.checkpoint_revision, 0);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_expired_grant_denies_admission() -> TestResult {
    let fixture = Fixture::new()?;
    let package = native(component("1"))?;
    let mut grant = fixture.grant.clone();
    grant.expires_utc_ns = Some(AnalysisPackageOwner::now().saturating_sub(1));
    let denied = fixture
        .owner
        .execute(
            grant,
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: package,
                parameters: Some(parameters("echo")),
            },
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
        )
        .await;
    assert!(matches!(
        denied,
        Err(crate::Error::Package {
            code: PackageErrorCodeV1::Denied,
            field: "package grant",
            ..
        })
    ));
    assert!(fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?
        .is_empty());
    assert_eq!(fixture.owner.operations.available_permits(), 4);
    Ok(())
}
