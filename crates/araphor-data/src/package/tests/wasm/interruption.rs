use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::*;
use crate::{analysis::PackageKeyV1, AnalysisReadControl};

#[tokio::test]
async fn wasm_running_stop_releases_capacity() -> TestResult {
    for revoke in [false, true] {
        let fixture = Fixture::new()?;
        let package = component("1");
        fixture.owner.admit_artifact(
            &package.artifacts[0],
            &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
        )?;
        let key = PackageKeyV1 {
            tenant_id: [1; 16],
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
            export: "evaluate".into(),
        };
        let owner = fixture.owner.clone();
        let grant = fixture.grant.clone();
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
            if task.is_finished() || Instant::now() >= deadline {
                return Err("guest activation absent".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if revoke {
            fixture.authority.set_revision(0);
        } else {
            control.cancel()?;
        }
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        if revoke {
            assert!(matches!(
                result,
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    ..
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(crate::Error::AnalysisReadCancelled { .. })
            ));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.owner.operations.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(fixture.store.package_results(&key)?.is_empty());
    }
    Ok(())
}
