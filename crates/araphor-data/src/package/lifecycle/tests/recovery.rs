use araphor_analysis_sdk as sdk;

use crate::package::tests::{bundle, run, Fixture, TestResult};
use crate::package::{PackageImplementationV1, PackageReadinessV1};

#[tokio::test]
async fn suspended_package_renewal_restart() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::UBIGINT AS count");
    let artifact = &mut package.artifacts[0];
    artifact.descriptor.exports[0].checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new(
            "state",
            sdk::Schema::new(vec![sdk::Field::new("runs", sdk::DataType::UInt64, false)]),
        )],
    });
    if let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] {
        program.checkpoint.insert(
            "state".into(),
            "SELECT CAST(COALESCE(MAX(runs),0)+1 AS UBIGINT) AS runs FROM prior_state".into(),
        );
    }
    let installed = fixture.install(package.clone(), None).await?;
    let original = &installed.exports[0].results[0];
    let historical = fixture.result(&original.result_id)?;
    assert!(!historical.checkpoint.is_empty());

    fixture.authority.set_revision(0);
    fixture.owner.reconcile().await?;
    let suspended = fixture.store.package_activation_page(None)?.remove(0);
    assert!(!suspended.active);
    assert!(fixture.execute(run("suspended")).await.is_err());

    fixture.renew();
    let resumed = fixture.install(package, None).await?;
    let export = &resumed.exports[0];
    assert!(export.active);
    assert!(matches!(export.readiness, PackageReadinessV1::Ready));
    assert!(export.activation_revision > suspended.generation);
    assert_ne!(export.results[0].result_id, original.result_id);
    let current = fixture.store.package_activation_page(None)?.remove(0);
    assert!(current.checkpoint_revision > suspended.checkpoint_revision);
    let output = fixture.output(
        "test.model",
        "count",
        current.result_id.as_deref().ok_or("new result is absent")?,
    )?;
    let checkpoint = output.checkpoint.ok_or("new checkpoint is absent")?;
    let state = crate::AnalysisPackageOwner::output_rows(&sdk::wire::Output {
        datasets: checkpoint.datasets,
        ..Default::default()
    })?;
    assert_eq!(state["state"], serde_json::json!([{"runs":1}]));
    let later = fixture.execute(run("resumed")).await?;
    assert_ne!(
        later.exports[0].results[0].result_id,
        export.results[0].result_id
    );
    let retained = fixture.result(&original.result_id)?;
    assert_eq!(retained.checkpoint, historical.checkpoint);
    assert_eq!(retained.datasets, historical.datasets);
    Ok(())
}
