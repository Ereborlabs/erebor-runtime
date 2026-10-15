use std::sync::Arc;
use std::time::Duration;

use super::{bundle, run, Fixture, TestResult};
use crate::package::{PackageErrorCodeV1 as Code, PackageRequestV1 as Request};
use crate::{AnalysisReadControl, AnalysisSelectionV1};

#[tokio::test]
async fn package_historical_scope() -> TestResult {
    let mut fixture = Fixture::new()?;
    let installed = fixture
        .install(bundle("1", "SELECT 3::UBIGINT AS count"), None)
        .await?;
    let receipt = installed.exports[0].results[0].clone();
    fixture
        .execute(Request::Remove {
            scope_id: "test".into(),
            package_id: "test.model".into(),
        })
        .await?;
    fixture.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut narrow = bundle("2", "SELECT 3::UBIGINT AS count");
    narrow.artifacts[0].implementations = vec![crate::package::PackageImplementationV1::Native {
        export: "count".into(),
        artifact: vec![0, 97, 115, 109],
        qualification: None,
    }];
    let response = fixture.install(narrow, None).await?;
    assert!(response.exports[0].results.is_empty());
    let result = fixture.output("test.model", "count", &receipt.result_id);
    assert!(matches!(
        result,
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(matches!(
        fixture
            .execute(Request::Query {
                scope_id: "test".into(),
                package_id: "test.model".into(),
                export: "count".into(),
                result_id: Some(receipt.result_id.clone()),
                sql: "SELECT * FROM rows".into(),
            })
            .await,
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let response = fixture
        .execute(Request::Query {
            scope_id: "test".into(),
            package_id: "test.model".into(),
            export: "count".into(),
            result_id: Some(receipt.result_id.clone()),
            sql: "SELECT * FROM rows".into(),
        })
        .await?;
    assert_eq!(response.exports[0].results[0].result_id, receipt.result_id);
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&response.output.ok_or("query output")?)?["query"],
        serde_json::json!([{"count":3}])
    );
    Ok(())
}

#[tokio::test]
async fn package_retry_revision() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .install(bundle("1", "SELECT 3::UBIGINT AS count"), None)
        .await?;
    let first = fixture.execute(run("same")).await?;
    let repeated = fixture.execute(run("same")).await?;
    assert_eq!(
        first.exports[0].results[0].result_id,
        repeated.exports[0].results[0].result_id
    );
    assert_eq!(
        first.exports[0].results[0].commit_revision,
        repeated.exports[0].results[0].commit_revision
    );
    fixture
        .execute(Request::Update {
            scope_id: "test".into(),
            bundle: bundle("2", "SELECT 4::UBIGINT AS count"),
        })
        .await?;
    assert!(matches!(
        fixture.execute(run("same")).await,
        Err(crate::Error::Package {
            code: Code::Conflict,
            ..
        })
    ));
    let response = fixture
        .execute(Request::Query {
            scope_id: "test".into(),
            package_id: "test.model".into(),
            export: "count".into(),
            result_id: Some(first.exports[0].results[0].result_id.clone()),
            sql: "SELECT * FROM rows".into(),
        })
        .await?;
    assert_eq!(response.exports[0].revision, "1");
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&response.output.ok_or("query output")?)?["query"],
        serde_json::json!([{"count":3}])
    );
    Ok(())
}

#[tokio::test]
async fn package_cancel_capacity() -> TestResult {
    let fixture = Fixture::new()?;
    let mut expiring = fixture.grant.clone();
    expiring.expires_utc_ns = Some(crate::AnalysisPackageOwner::now() + 1_000_000_000);
    let bounded = crate::AnalysisPackageOwner::grant_control(
        &expiring,
        Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
    )?;
    assert!(bounded.remaining()? <= Duration::from_secs(1));
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(10))?);
    control.cancel()?;
    assert!(fixture
        .owner
        .execute(
            fixture.grant.clone(),
            Request::Install {
                scope_id: "test".into(),
                bundle: bundle("1", "SELECT 1::UBIGINT AS count"),
                parameters: None,
            },
            control
        )
        .await
        .is_err());
    assert!(fixture
        .owner
        .activations([1; 16], "test", "test.model")?
        .is_empty());
    let permits = (0..4)
        .map(|_| fixture.owner.operation())
        .collect::<crate::Result<Vec<_>>>()?;
    assert!(matches!(
        fixture.owner.operation(),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    drop(permits);
    fixture
        .install(bundle("1", "SELECT 1::UBIGINT AS count"), None)
        .await?;
    fixture.authority.set_revision(0);
    assert!(fixture.execute(run("revoked")).await.is_err());
    fixture.owner.reconcile().await?;
    let suspended = fixture.owner.activations([1; 16], "test", "test.model")?;
    assert_eq!(suspended.len(), 1);
    assert!(!suspended[0].active);
    Ok(())
}
