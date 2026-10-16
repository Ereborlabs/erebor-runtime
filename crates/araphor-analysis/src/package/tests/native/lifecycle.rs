use super::*;

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_declared_type_lifecycle() -> TestResult {
    let fixture = Fixture::new()?;
    let package = native(component("1"))?;
    let installed = fixture
        .install(package.clone(), Some(parameters("echo")))
        .await?;
    assert!(matches!(
        installed.exports[0].readiness,
        PackageReadinessV1::Ready
    ));
    assert_eq!(installed.exports[0].results[0].target, "native");
    let first = fixture.execute(evaluate("first")).await?;
    let receipt = first.exports[0].results[0].clone();
    let output = fixture.output("runtime-fixture", "evaluate", &receipt.result_id)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["data"],
        serde_json::json!([{"value":7}])
    );
    let retry = fixture.execute(evaluate("first")).await?;
    assert_eq!(retry.exports[0].results[0].result_id, receipt.result_id);
    assert_eq!(
        retry.exports[0].results[0].commit_revision,
        receipt.commit_revision
    );
    let original = fixture
        .store
        .package_revision([1; 16], "runtime-fixture", "1")?;
    fixture.install(package, Some(parameters("echo"))).await?;
    assert_eq!(
        fixture
            .store
            .package_revision([1; 16], "runtime-fixture", "1")?,
        original
    );
    let updated = fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: component("2"),
        })
        .await?;
    assert_eq!(updated.exports[0].revision, "2");
    assert_eq!(updated.exports[0].results[0].target, "wasm");
    assert!(matches!(
        fixture.execute(evaluate("first")).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: PackageErrorCodeV1::Conflict,
                ..
            }
        })
    ));
    let fixture = fixture.reopen()?;
    let reopened = fixture.execute(evaluate("second")).await?;
    assert_eq!(reopened.exports[0].results[0].target, "wasm");
    let rolled = fixture
        .execute(PackageRequestV1::Rollback {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
            revision: "1".into(),
        })
        .await?;
    assert_eq!(rolled.exports[0].revision, "1");
    assert_eq!(rolled.exports[0].results[0].target, "native");
    let original = fixture.execute(evaluate("first")).await?;
    assert_eq!(original.exports[0].results[0].result_id, receipt.result_id);
    fixture
        .execute(PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
        })
        .await?;
    assert!(fixture.execute(evaluate("removed")).await.is_err());
    let historical = fixture.output("runtime-fixture", "evaluate", &receipt.result_id)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&historical)?["data"],
        serde_json::json!([{"value":7}])
    );
    assert_eq!(fixture.owner.operations.available_permits(), 4);
    Ok(())
}
