use araphor_data::{AnalysisSelectionV1, ManagedRequest};
use araphor_discovery_definition::ImagePin;

use super::*;

#[tokio::test]
async fn removal_rpc_keeps_history() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let image = bundle();
    let pin = ImagePin {
        image: image.root.clone(),
        digest: image.digest()?,
    };
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: pin.digest.clone(),
        }])?;
    fixture
        .package(
            PackageRequestV1::InstallImage {
                bundle: image.clone(),
            },
            true,
        )
        .await?;
    let instance = fixture
        .retained_instance(
            "removed-counts",
            r#"SELECT * FROM "api.fixture"."1".count()"#,
        )
        .await?;
    let control = AnalysisReadControl::default();
    let receipt = instance
        .run(
            ManagedRequest {
                id: "original".into(),
                time_utc_ns: ClientGrpcOwner::now()?,
                seed: None,
                rebuild: false,
                witness_expiry: u64::MAX,
                frontier: None,
            },
            &control,
        )
        .await?;
    let result = receipt
        .results
        .values()
        .next()
        .ok_or("original result")?
        .result_id
        .clone();
    let data = fixture.service.data()?;
    let before = data.store.meta()?.commit_revision;
    let request = PackageRequestV1::RemoveInstance {
        instance_id: "removed-counts".into(),
        expected_lifecycle: instance.admitted().lifecycle,
    };
    assert_eq!(
        fixture
            .package(request.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert_eq!(
        fixture
            .package(request.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(data.store.meta()?.commit_revision, before);
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    fixture.service.auth.replace_package_trust(Vec::new())?;
    let PackageResponseV1::Instance(removed) = fixture.package(request.clone(), true).await? else {
        return Err("removed instance variant".into());
    };
    assert!(removed.removed);
    assert!(!removed.running);
    assert_eq!(removed.progress, receipt.commit_revision);
    assert!(removed.lifecycle > instance.admitted().lifecycle);
    assert_eq!(
        fixture
            .package(request, true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::AlreadyExists)
    );
    let PackageResponseV1::History(history) = fixture
        .package(
            PackageRequestV1::InspectInstanceHistory {
                instance_id: "removed-counts".into(),
            },
            false,
        )
        .await?
    else {
        return Err("removed history variant".into());
    };
    assert_eq!(history, vec![receipt]);
    let PackageResponseV1::Result(retained) = fixture
        .package(
            PackageRequestV1::ReadInstanceResult {
                instance_id: "removed-counts".into(),
                result_id: result,
            },
            false,
        )
        .await?
    else {
        return Err("removed result variant".into());
    };
    assert!(!retained.current);
    let PackageResponseV1::Uninstalled(actual) = fixture
        .package(
            PackageRequestV1::UninstallImage { image: pin.clone() },
            true,
        )
        .await?
    else {
        return Err("uninstalled image variant".into());
    };
    assert_eq!(actual, pin);
    assert!(data
        .store
        .package_image([1; 16], "api.fixture", Some("1"), &control)?
        .is_none());
    assert!(data
        .store
        .retained_package_image([1; 16], &pin, &control)?
        .is_some());
    let removed_revision = data.store.meta()?.commit_revision;
    assert!(
        matches!(fixture.package(PackageRequestV1::UninstallImage { image: pin.clone() }, true).await?, PackageResponseV1::Uninstalled(actual) if actual == pin)
    );
    assert_eq!(data.store.meta()?.commit_revision, removed_revision);
    let recreate = PackageRequestV1::RecreateInstance {
        instance_id: "removed-counts".into(),
        expected_lifecycle: removed.lifecycle,
        definition_name: instance.admitted().spec.definition.definition.name.clone(),
        definition_revision: instance.admitted().spec.definition.digest()?,
    };
    assert!(fixture.package(recreate.clone(), true).await.is_err());
    assert_eq!(data.store.meta()?.commit_revision, removed_revision);
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: pin.digest.clone(),
        }])?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: image }, true)
        .await?;
    let PackageResponseV1::Instance(recreated) = fixture.package(recreate, true).await? else {
        return Err("recreated instance variant".into());
    };
    assert!(!recreated.removed);
    assert!(!recreated.running);
    assert_eq!(recreated.progress, 0);
    assert!(recreated.generation > removed.lifecycle);
    assert_eq!(
        data.store
            .managed_history(
                &AnalysisSelectionV1::tenant([1; 16]),
                "removed-counts",
                &control
            )?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn uninstall_rpc_checks_pin() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    let image = bundle();
    let pin = ImagePin {
        image: image.root.clone(),
        digest: image.digest()?,
    };
    fixture
        .service
        .auth
        .replace_package_trust(vec![crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: pin.digest.clone(),
        }])?;
    fixture
        .package(PackageRequestV1::InstallImage { bundle: image }, true)
        .await?;
    let store = &fixture.service.data()?.store;
    let before = store.meta()?.commit_revision;
    assert_eq!(
        fixture
            .package(
                PackageRequestV1::UninstallImage { image: pin.clone() },
                false
            )
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    let mut forged = pin.clone();
    forged.digest = format!("sha256:{}", "f".repeat(64));
    assert_eq!(
        fixture
            .package(PackageRequestV1::UninstallImage { image: forged }, true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::AlreadyExists)
    );
    assert_eq!(store.meta()?.commit_revision, before);
    fixture.service.auth.replace_package_trust(Vec::new())?;
    assert!(
        matches!(fixture.package(PackageRequestV1::UninstallImage { image: pin.clone() }, true).await?, PackageResponseV1::Uninstalled(actual) if actual == pin)
    );
    let revision = store.meta()?.commit_revision;
    assert!(revision > before);
    assert!(store
        .package_image(
            [1; 16],
            "api.fixture",
            Some("1"),
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(
        matches!(fixture.package(PackageRequestV1::UninstallImage { image: pin.clone() }, true).await?, PackageResponseV1::Uninstalled(actual) if actual == pin)
    );
    assert_eq!(store.meta()?.commit_revision, revision);
    Ok(())
}
