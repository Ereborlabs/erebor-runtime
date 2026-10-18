use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::PackageImplementationV1;

#[tokio::test]
async fn root_group_reuses_bundle() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count");
    let artifact = &mut package.artifacts[0];
    let mut second = artifact.descriptor.exports[0].clone();
    second.name = "second".into();
    artifact.descriptor.exports.push(second);
    let mut implementation = artifact.implementations[0].clone();
    let PackageImplementationV1::Sql { export, .. } = &mut implementation else {
        return Err("SQL implementation".into());
    };
    *export = "second".into();
    artifact.implementations.push(implementation);
    fixture.install(package.clone(), None).await?;
    let before = fixture.store.package_activation_page(None)?;
    let store = fixture.store.clone();
    *fixture
        .authority
        .before_admit
        .lock()
        .map_err(|_| "admission observer")? = Some(Box::new(move || {
        store
            .fault_write(
                "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
                &[],
            )
            .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("fixture artifact mutation"))
    }));
    let mut admissions = fixture.authority.admissions.subscribe();
    let expected = *admissions.borrow() + 2;
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let worker = fixture.owner.clone().serve(receiver);
    tokio::pin!(worker);
    loop {
        tokio::select! {
            result = &mut worker => { result?; return Err("supervisor ended before both exports were admitted".into()); }
            changed = admissions.changed() => { changed?; if *admissions.borrow_and_update() >= expected { break; } }
        }
    }
    stop.send_replace(true);
    worker.await?;
    assert_eq!(fixture.store.package_activation_page(None)?, before);
    assert!(fixture
        .owner
        .load_bundle([1; 16], &package.root, None)
        .is_err());
    Ok(())
}

#[tokio::test]
async fn idle_reconcile_checks_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let package = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count");
    fixture.install(package, None).await?;
    let before = fixture.store.package_activation_page(None)?;
    let mut admissions = fixture.authority.admissions.subscribe();
    let expected = *admissions.borrow() + 1;
    let mut lifecycle = fixture.store.subscribe_activations();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let worker = fixture.owner.clone().serve(receiver);
    tokio::pin!(worker);
    loop {
        tokio::select! {
            result = &mut worker => { result?; return Err("supervisor ended before idle admission".into()); }
            changed = admissions.changed() => { changed?; if *admissions.borrow_and_update() >= expected { break; } }
        }
    }
    fixture
        .store
        .fault_write(
            "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
            &[],
        )
        .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("fixture artifact mutation"))?;
    assert_eq!(fixture.store.package_activation_page(None)?, before);
    fixture.authority.set_revision(0);
    loop {
        tokio::select! {
            result = &mut worker => { result?; return Err("supervisor ended before revocation".into()); }
            changed = lifecycle.changed() => {
                changed?;
                if !fixture.store.package_activation_page(None)?[0].active { break; }
            }
        }
    }
    stop.send_replace(true);
    worker.await?;
    assert!(!fixture.store.package_activation_page(None)?[0].active);
    Ok(())
}

#[tokio::test]
async fn expiry_keeps_service() -> TestResult {
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::package::owner::InstalledContext;
    use crate::package::AnalysisPackageOwner;
    use araphor_analysis_sdk as sdk;

    let fixture = Fixture::new()?;
    fixture
        .install(bundle("1", "SELECT 3::BIGINT UNSIGNED AS count"), None)
        .await?;
    let mut healthy = bundle("1", "SELECT count FROM source");
    healthy.root.package_id = "zz.healthy".into();
    let artifact = &mut healthy.artifacts[0];
    artifact.descriptor.id = "zz.healthy".into();
    let mut port = artifact.descriptor.exports[0].outputs[0].clone();
    port.name = "source".into();
    artifact.descriptor.exports[0].inputs.push(sdk::InputPort {
        port,
        source: sdk::InputSource::Query(
            "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM context_versions".into(),
        ),
    });
    fixture.install(healthy, None).await?;
    let expired = fixture.activation("test.model")?;
    let healthy = fixture.activation("zz.healthy")?;
    let results = fixture.store.package_results(&expired.key)?;
    let mut context: InstalledContext = AnalysisPackageOwner::decode(&expired.metadata)?;
    let expiry = AnalysisPackageOwner::now() + 2_000_000_000;
    context.grant.expires_utc_ns = Some(expiry);
    let expired = fixture.store.renew_package(
        &expired,
        &AnalysisPackageOwner::encode(&context)?,
        &context.grant.principal,
        || Ok(()),
    )?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let mut entered = Some(entered);
    let (release, resumed) = mpsc::channel();
    let mut release = Some(release);
    *fixture
        .authority
        .before_admit
        .lock()
        .map_err(|_| "admission observer")? = Some(Box::new(move || {
        if let Some(entered) = entered.take() {
            let _sent = entered.send(());
        }
        resumed
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| crate::PackageErrorCodeV1::Incomplete.error("expiry admission release"))?;
        Ok(())
    }));
    let mut lifecycle = fixture.store.subscribe_activations();
    let mut revisions = fixture.store.subscribe_revision();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let worker = fixture.owner.clone().serve(receiver);
    tokio::pin!(worker);
    let mut ended = false;
    let progress = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = &mut worker => { ended = true; result?; return Err("serve stopped before expiry admission".into()); }
            result = ready => { result?; }
        }
        tokio::time::sleep(Duration::from_nanos(expiry.saturating_sub(AnalysisPackageOwner::now()))).await;
        release.take().ok_or("admission release")?.send(())?;
        loop {
            if !fixture.store.package_activation(&expired.key)?.ok_or("expired activation")?.active {
                break;
            }
            tokio::select! {
                result = &mut worker => { ended = true; result?; return Err("serve stopped at grant expiry".into()); }
                changed = lifecycle.changed() => { changed?; }
            }
        }
        let suspended = fixture.store.package_activation(&expired.key)?.ok_or("suspended activation")?;
        assert_eq!(suspended.checkpoint_revision, expired.checkpoint_revision);
        assert_eq!(suspended.result_id, expired.result_id);
        assert_eq!(fixture.store.package_results(&expired.key)?.len(), results.len());
        assert!(fixture.store.package_activation(&healthy.key)?.ok_or("healthy activation")?.active);
        fixture.store.commit_context(&crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16], owner_id: "expiry-fixture".into(), entity_key: b"context".to_vec(),
                lifetime_key: b"lifetime".to_vec(), owner_revision: 1,
            },
            valid_from_utc_ns: None, valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant, body: b"value".to_vec(),
        })?;
        loop {
            let current = fixture.store.package_activation(&healthy.key)?.ok_or("continued activation")?;
            if current.checkpoint_revision > healthy.checkpoint_revision {
                let output = fixture.output("zz.healthy", "count", current.result_id.as_deref().ok_or("continued result")?)?;
                assert_eq!(AnalysisPackageOwner::output_rows(&output)?["rows"], serde_json::json!([{"count": 1}]));
                break;
            }
            tokio::select! {
                result = &mut worker => { ended = true; result?; return Err("serve stopped before healthy commit".into()); }
                changed = revisions.changed() => { changed?; }
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await;
    if let Some(release) = release.take() {
        let _released = release.send(());
    }
    stop.send_replace(true);
    if !ended {
        tokio::time::timeout(Duration::from_secs(30), &mut worker).await??;
    }
    progress??;
    Ok(())
}
