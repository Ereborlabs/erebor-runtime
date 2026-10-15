use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::AnalysisReadControl;

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_cancellation_revocation_and_expiry() -> TestResult {
    for cause in ["cancel", "revoke", "expiry"] {
        super::super::interruption::running_guest(Fixture::new()?, native(component("1"))?, cause)
            .await?;
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
