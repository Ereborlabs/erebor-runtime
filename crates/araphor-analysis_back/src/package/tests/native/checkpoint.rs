use super::super::wasm::checkpoint::{bundle, run};
use super::*;
use araphor_analysis_sdk as sdk;

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_checkpoint_retry_and_restart() -> TestResult {
    let fixture = Fixture::new_limits(crate::Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        extract_timeout: Some(std::time::Duration::from_secs(30)),
        evaluate_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    })?;
    super::super::wasm::checkpoint::replay(fixture, native(bundle()?)?, "native").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_overflow_keeps_checkpoint() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle()?;
    package.artifacts[0].descriptor.exports[0].inputs[0].source =
        araphor_analysis_sdk::InputSource::Query(
            "SELECT 18446744073709551615::BIGINT UNSIGNED AS value".into(),
        );
    let installed = fixture.install(native(package)?, None).await?;
    assert_eq!(installed.exports[0].results[0].target, "native");
    let before = fixture.activation("runtime-fixture")?;
    let receipt = before.result_id.as_ref().ok_or("committed result absent")?;
    let stored = fixture.result(receipt)?;
    let output = fixture.output("runtime-fixture", "accumulate", receipt)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["data"],
        serde_json::json!([{"value":u64::MAX}])
    );
    let checkpoint = output.checkpoint.ok_or("committed checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&sdk::wire::Output {
            datasets: checkpoint.datasets,
            ..Default::default()
        })?["state"],
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
    let original = fixture.result(receipt)?;
    assert_eq!(original.commit.datasets, stored.commit.datasets);
    assert_eq!(original.commit.checkpoint, stored.commit.checkpoint);
    assert_eq!(fixture.store.package_results(&before.key)?.len(), 1);
    assert_eq!(fixture.owner.operations.available_permits(), 4);
    Ok(())
}
