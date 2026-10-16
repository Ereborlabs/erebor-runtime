use super::*;
use araphor_analysis_sdk as sdk;

#[tokio::test]
async fn wasm_installed_lifecycle() -> TestResult {
    let fixture = Fixture::new()?;
    let installed = fixture
        .install(component("1"), Some(parameters("echo")))
        .await?;
    assert!(matches!(
        installed.exports[0].readiness,
        PackageReadinessV1::Ready
    ));
    assert_eq!(installed.exports[0].results[0].target, "wasm");
    let first = fixture.execute(evaluate("first")).await?;
    let retry = fixture.execute(evaluate("first")).await?;
    assert_eq!(
        first.exports[0].results[0].result_id,
        retry.exports[0].results[0].result_id
    );
    assert_eq!(
        first.exports[0].results[0].commit_revision,
        retry.exports[0].results[0].commit_revision
    );
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured = observed.clone();
    let store = fixture.store.clone();
    *fixture
        .authority
        .after_commit
        .lock()
        .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture commit observer"))? =
        Some(Box::new(move || {
            let mut captured = captured
                .lock()
                .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture commit observation"))?;
            if captured.is_some() {
                return Ok(());
            }
            let key = crate::analysis::PackageKeyV1 {
                tenant_id: [1; 16],
                scope_id: "test".into(),
                package_id: "runtime-fixture".into(),
                export: "evaluate".into(),
            };
            let active = store
                .package_activation(&key)?
                .ok_or_else(|| PackageErrorCodeV1::Missing.error("fixture activation"))?;
            if active.revision == "2" {
                *captured = Some(
                    store
                        .package_result(
                            key.tenant_id,
                            active.result_id.as_deref().ok_or_else(|| {
                                PackageErrorCodeV1::Missing.error("upgrade result")
                            })?,
                        )?
                        .ok_or_else(|| PackageErrorCodeV1::Missing.error("upgrade receipt"))?,
                );
            }
            Ok(())
        }));
    let upgraded = fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: component("2"),
        })
        .await?;
    drop(
        fixture
            .authority
            .after_commit
            .lock()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture commit observer"))?
            .take(),
    );
    assert_eq!(upgraded.exports[0].revision, "2");
    let committed = observed
        .lock()
        .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture commit observation"))?
        .take()
        .ok_or("upgrade commit observation absent")?;
    assert_eq!(committed.commit.activation.revision, "2");
    let receipt = AnalysisPackageOwner::receipt(&committed)?;
    assert_eq!(receipt.target, "wasm");
    assert!(!receipt.stale);
    let returned = upgraded.exports[0]
        .results
        .iter()
        .find(|result| result.result_id == receipt.result_id)
        .cloned()
        .ok_or("returned upgrade receipt absent")?;
    if returned.stale {
        let saved: crate::package::evaluation::ResultContext =
            AnalysisPackageOwner::decode(&committed.commit.metadata)?;
        assert!(AnalysisPackageOwner::clock_changed(
            true,
            saved.context.time_utc_ns,
            AnalysisPackageOwner::now(),
        ));
    }
    assert_receipt(&returned, &receipt)?;
    let output: sdk::wire::Output = AnalysisPackageOwner::decode(&committed.commit.datasets)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["data"],
        serde_json::json!([{"value":7}])
    );
    let fixture = fixture.reopen()?;
    let reopened = fixture.execute(evaluate("second")).await?;
    assert_eq!(reopened.exports[0].revision, "2");
    let rolled = fixture
        .execute(PackageRequestV1::Rollback {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
            revision: "1".into(),
        })
        .await?;
    assert_eq!(rolled.exports[0].revision, "1");
    assert!(fixture.execute(evaluate("first")).await.is_ok());
    fixture
        .execute(PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
        })
        .await?;
    assert!(fixture.execute(evaluate("removed")).await.is_err());
    Ok(())
}
