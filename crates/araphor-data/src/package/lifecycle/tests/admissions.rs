use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{AnalysisPackageOwner, PackageImplementationV1, PackageRequestV1};
use crate::AnalysisReadControl;

#[tokio::test]
async fn failed_upgrade_preserves_state() -> TestResult {
    let fixture = Fixture::new()?;
    let original = fixture
        .install(bundle("1", "SELECT 3::UBIGINT AS count"), None)
        .await?;
    let before = fixture.store.package_activation_page(None)?.remove(0);
    assert!(fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: bundle("2", "SELECT CAST('bad' AS UBIGINT) AS count"),
        })
        .await
        .is_err());
    assert!(fixture
        .store
        .package_revision([1; 16], "test.model", "2")?
        .is_none());
    let fixture = fixture.reopen()?;
    assert!(fixture
        .store
        .package_revision([1; 16], "test.model", "2")?
        .is_none());
    let after = fixture.store.package_activation_page(None)?.remove(0);
    assert_eq!(before, after);
    let response = fixture.owner.inspect(
        &fixture.grant,
        "test",
        "test.model",
        None,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(response.exports[0].revision, "1");
    assert_eq!(
        response.exports[0].results[0].result_id,
        original.exports[0].results[0].result_id
    );
    assert!(!response.exports[0].results[0].stale);
    Ok(())
}

#[tokio::test]
async fn startup_releases_unreferenced_admissions() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .install(bundle("1", "SELECT 1::UBIGINT AS count"), None)
        .await?;
    fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: bundle("2", "SELECT 2::UBIGINT AS count"),
        })
        .await?;
    let mut inactive = bundle("1", "SELECT 0::UBIGINT AS count");
    inactive.root.package_id = "test.inactive".into();
    inactive.artifacts[0].descriptor.id = inactive.root.package_id.clone();
    inactive.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "count".into(),
        artifact: vec![0],
    }];
    fixture.install(inactive, None).await?;
    let revisions = fixture.store.package_revisions([1; 16])?;
    let activations = fixture.store.package_activation_page(None)?;

    let mut records = super::shared_bundle("orphan.root")
        .artifacts
        .iter()
        .map(|artifact| AnalysisPackageOwner::revision(&fixture.grant, artifact))
        .collect::<crate::Result<Vec<_>>>()?;
    for index in 0..33 {
        let mut artifact = bundle("1", "SELECT 0::UBIGINT AS count")
            .artifacts
            .remove(0);
        artifact.descriptor.id = format!("orphan.{index:02}");
        records.push(AnalysisPackageOwner::revision(&fixture.grant, &artifact)?);
    }
    fixture.store.install_package(&records, || Ok(()))?;
    assert_eq!(
        fixture.store.package_revisions([1; 16])?.len(),
        revisions.len() + records.len()
    );
    let fixture = fixture.reopen()?;
    assert_eq!(fixture.store.package_revisions([1; 16])?, revisions);
    assert_eq!(fixture.store.package_activation_page(None)?, activations);
    let revision = *fixture.store.subscribe_revision().borrow();
    fixture.store.collect_package_admissions()?;
    assert_eq!(*fixture.store.subscribe_revision().borrow(), revision);
    Ok(())
}
