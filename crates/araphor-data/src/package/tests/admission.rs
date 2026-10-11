use araphor_analysis_sdk as sdk;

use super::{bundle, Fixture, TestResult};
use crate::package::{PackageArtifactV1, PackageBundleV1, PackageRefV1};

mod cycles;

fn bind(artifact: &mut PackageArtifactV1, input: &str, source: &PackageRefV1) {
    let mut port = artifact.descriptor.exports[0].outputs[0].clone();
    port.name = input.into();
    artifact.descriptor.exports[0].inputs.push(port);
    artifact.descriptor.dependencies.push(sdk::Dependency {
        model: "count".into(),
        input: input.into(),
        package: source.package_id.clone(),
        revision: source.revision.clone(),
        export: "count".into(),
        output: "rows".into(),
    });
}

fn chain() -> PackageBundleV1 {
    let mut package = bundle("1", "SELECT count FROM source");
    let mut upstream = bundle("1", "SELECT 3::UBIGINT AS count")
        .artifacts
        .remove(0);
    upstream.descriptor.id = "test.upstream".into();
    bind(&mut package.artifacts[0], "source", &upstream.reference());
    package.artifacts.push(upstream);
    package
}

#[tokio::test]
async fn admission_rejects_invalid_closures() -> TestResult {
    let fixture = Fixture::new()?;
    let valid = chain();
    valid.validate()?;
    let mut cycle = valid.clone();
    bind(&mut cycle.artifacts[1], "cycle", &cycle.root);
    let mut schema = valid.clone();
    schema.artifacts[1].descriptor.exports[0].outputs[0].schema =
        sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt32, false)]);
    let mut revisions = valid;
    let mut newer = revisions.artifacts[1].clone();
    newer.descriptor.revision = "2".into();
    bind(&mut revisions.artifacts[0], "newer", &newer.reference());
    revisions.artifacts.push(newer);
    for package in [cycle, schema, revisions] {
        assert!(fixture.install(package, None).await.is_err());
        assert!(fixture
            .store
            .package_revision([1; 16], "test.model", "1")?
            .is_none());
        assert!(fixture
            .store
            .package_revision([1; 16], "test.upstream", "1")?
            .is_none());
        assert!(fixture
            .store
            .package_revision([1; 16], "test.upstream", "2")?
            .is_none());
        assert!(fixture.store.package_activation_page(None)?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn admission_rejects_domain_execution() -> TestResult {
    let fixture = Fixture::new()?;
    for (index, kind) in [
        sdk::OutputKind::Discovery,
        sdk::OutputKind::Subjects,
        sdk::OutputKind::Relationships,
        sdk::OutputKind::Findings,
        sdk::OutputKind::PolicyCandidates,
    ]
    .into_iter()
    .enumerate()
    {
        let mut package = bundle("1", "SELECT 1::UBIGINT AS count");
        package.root.package_id = format!("test.domain{index}");
        package.artifacts[0].descriptor.id = package.root.package_id.clone();
        package.artifacts[0].descriptor.exports[0].outputs[0].kind = kind;
        let response = fixture.install(package, None).await?;
        assert!(matches!(&response.exports[0].readiness,
            crate::package::PackageReadinessV1::Unsupported { target } if target == "domain output adapter"));
        assert!(response.exports[0].results.is_empty());
    }
    let active = fixture.store.package_activation_page(None)?;
    assert_eq!(active.len(), 5);
    assert!(active
        .iter()
        .all(|activation| !activation.active && activation.result_id.is_none()));
    Ok(())
}
