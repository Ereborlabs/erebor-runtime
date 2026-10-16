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
    fixture.owner.reconcile().await?;
    assert_eq!(fixture.store.package_activation_page(None)?, before);
    assert!(fixture.owner.load_bundle([1; 16], &package.root).is_err());
    Ok(())
}

#[tokio::test]
async fn idle_reconcile_checks_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let package = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count");
    fixture.install(package, None).await?;
    let before = fixture.store.package_activation_page(None)?;
    fixture
        .store
        .fault_write(
            "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
            &[],
        )
        .map_err(|_| crate::PackageErrorCodeV1::Invalid.error("fixture artifact mutation"))?;
    let (_stop, mut receiver) = tokio::sync::watch::channel(false);
    let (complete, deadline) = fixture
        .owner
        .reconcile_until(&mut receiver, false, false)
        .await?;
    assert!(complete);
    assert_eq!(deadline, u64::MAX);
    assert_eq!(fixture.store.package_activation_page(None)?, before);
    fixture.authority.set_revision(0);
    assert!(
        fixture
            .owner
            .reconcile_until(&mut receiver, false, false)
            .await?
            .0
    );
    assert!(!fixture.store.package_activation_page(None)?[0].active);
    Ok(())
}
