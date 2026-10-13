use std::sync::{mpsc, Arc};
use std::time::Duration;

use super::{bundle, run, Fixture, TestResult};
use crate::package::{PackageBundleV1, PackageImplementationV1};
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, ContextSensitivityV1,
};

#[tokio::test]
async fn package_running_stop() -> TestResult {
    for revoke in [false, true] {
        let mut fixture = Fixture::new()?;
        let package = source_bundle(&fixture)?;
        fixture.install(package.clone(), None).await?;
        let before = fixture
            .owner
            .activations([1; 16], "test", "test.model")?
            .pop()
            .ok_or("activation absent")?;
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
    fixture.install(source_bundle(&fixture)?, None).await?;
    let before = fixture
        .owner
        .activations([1; 16], "test", "test.model")?
        .pop()
        .ok_or("activation absent")?;
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
            fixture
                .owner
                .evaluate_active(&before, "automatic", true, &control),
            Err(crate::Error::AnalysisBusy { .. })
        ));
        assert_eq!(
            fixture.store.package_activation(&before.key)?.as_ref(),
            Some(&before)
        );
        let result = fixture
            .store
            .package_result([1; 16], before.result_id.as_deref().ok_or("result absent")?)?
            .ok_or("stored result absent")?;
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
    artifact.descriptor.exports[0].inputs.push(input);
    let PackageImplementationV1::Sql { inputs, .. } = &mut artifact.implementations[0] else {
        return Err("SQL fixture absent".into());
    };
    inputs.insert(
        "source".into(),
        "SELECT owner_revision AS count FROM context_versions".into(),
    );
    Ok(package)
}
