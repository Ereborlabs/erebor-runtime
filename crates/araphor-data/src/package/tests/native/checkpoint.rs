use super::super::wasm::checkpoint::{bundle, run};
use super::*;

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_checkpoint_retry_and_restart() -> TestResult {
    let fixture = Fixture::new_limits(crate::QueryLimits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        extract_timeout: std::time::Duration::from_secs(30),
        evaluate_timeout: std::time::Duration::from_secs(30),
        ..Default::default()
    })?;
    let package = native(bundle()?)?;
    let installed = fixture.install(package.clone(), None).await?;
    let initial = &installed.exports[0].results[0];
    assert_eq!(initial.target, "native");
    let PackageImplementationV1::Native {
        artifact,
        qualification,
        ..
    } = &package.artifacts[0].implementations[0]
    else {
        return Err("native artifact absent".into());
    };
    let identity = initial
        .artifact
        .as_ref()
        .ok_or("native artifact receipt absent")?;
    assert_eq!(
        identity.digest,
        crate::package::native::Qualification::digest(artifact)
    );
    assert_eq!(
        identity.closure_digest.as_ref(),
        Some(
            &qualification
                .as_ref()
                .ok_or("qualification absent")?
                .closure_digest(artifact)?
        )
    );
    assert_eq!(
        identity.platform.as_deref(),
        Some(env!("ARAPHOR_NATIVE_TARGET"))
    );
    let first = fixture.execute(run("first")).await?;
    let receipt = first.exports[0].results[0].clone();
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        &receipt.result_id,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value":6}])
    );
    let checkpoint = output.checkpoint.ok_or("native checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(
        PackageOutputV1 {
            datasets: checkpoint.datasets,
            ..Default::default()
        }
        .json_rows()?["state"],
        serde_json::json!([{"value":6}])
    );
    let retained = fixture
        .store
        .package_result([1; 16], &receipt.result_id)?
        .ok_or("retained result absent")?;
    let retry = fixture.execute(run("first")).await?;
    assert_eq!(retry.exports[0].results[0].result_id, receipt.result_id);
    assert_eq!(
        retry.exports[0].results[0].commit_revision,
        receipt.commit_revision
    );
    let fixture = fixture.reopen()?;
    let retry = fixture.execute(run("first")).await?;
    assert_eq!(retry.exports[0].results[0].result_id, receipt.result_id);
    let second = fixture.execute(run("second")).await?;
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        &second.exports[0].results[0].result_id,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value":9}])
    );
    let checkpoint = output.checkpoint.ok_or("restarted checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(
        PackageOutputV1 {
            datasets: checkpoint.datasets,
            ..Default::default()
        }
        .json_rows()?["state"],
        serde_json::json!([{"value":9}])
    );
    let original = fixture
        .store
        .package_result([1; 16], &receipt.result_id)?
        .ok_or("original result absent")?;
    assert_eq!(original.datasets, retained.datasets);
    assert_eq!(original.checkpoint, retained.checkpoint);
    assert_eq!(original.commit_revision, retained.commit_revision);
    assert_eq!(original.metadata, retained.metadata);
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_overflow_keeps_checkpoint() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle()?;
    package.artifacts[0].descriptor.exports[0].inputs[0].source =
        araphor_analysis_sdk::InputSource::Query(
            "SELECT 18446744073709551615::UBIGINT AS value".into(),
        );
    let installed = fixture.install(native(package)?, None).await?;
    assert_eq!(installed.exports[0].results[0].target, "native");
    let before = fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?
        .pop()
        .ok_or("activation absent")?;
    let receipt = before.result_id.as_ref().ok_or("committed result absent")?;
    let stored = fixture
        .store
        .package_result([1; 16], receipt)?
        .ok_or("retained output absent")?;
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        receipt,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value":u64::MAX}])
    );
    let checkpoint = output.checkpoint.ok_or("committed checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(
        PackageOutputV1 {
            datasets: checkpoint.datasets,
            ..Default::default()
        }
        .json_rows()?["state"],
        serde_json::json!([{"value":u64::MAX}])
    );
    assert!(matches!(
        fixture.execute(run("overflow")).await,
        Err(crate::Error::PackageNative {
            code: PackageErrorCodeV1::Limit,
            ..
        })
    ));
    let after = fixture
        .store
        .package_activation(&before.key)?
        .ok_or("activation absent")?;
    assert_eq!(after.result_id, before.result_id);
    assert_eq!(after.checkpoint_revision, before.checkpoint_revision);
    let original = fixture
        .store
        .package_result([1; 16], receipt)?
        .ok_or("original output absent")?;
    assert_eq!(original.datasets, stored.datasets);
    assert_eq!(original.checkpoint, stored.checkpoint);
    assert_eq!(fixture.store.package_results(&before.key)?.len(), 1);
    assert_eq!(fixture.owner.operations.available_permits(), 4);
    Ok(())
}
