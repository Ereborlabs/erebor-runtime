use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{
    PackageArtifactV1, PackageErrorCodeV1, PackageImplementationV1, PackageRefV1,
};
use crate::SqlModelV1;

fn derived(artifact: &mut PackageArtifactV1, source: &PackageRefV1) {
    let mut model = artifact.descriptor.exports[0].clone();
    model.name = "derived".into();
    let mut input = model.outputs[0].clone();
    input.name = "source".into();
    model.inputs.push(sdk::InputPort {
        port: input,
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: source.package_id.clone(),
            revision: source.revision.clone(),
            export: "count".into(),
            output: "rows".into(),
        })),
    });
    artifact.descriptor.exports.push(model);
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "derived".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT CAST(count + 1 AS UBIGINT) AS count FROM source".into(),
            )]),
            ..Default::default()
        },
    });
}

#[tokio::test]
async fn admission_rejects_artifact_cycles() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::UBIGINT AS count");
    let mut upstream = bundle("1", "SELECT 2::UBIGINT AS count")
        .artifacts
        .remove(0);
    upstream.descriptor.id = "test.upstream".into();
    derived(&mut package.artifacts[0], &upstream.reference());
    derived(&mut upstream, &package.root);
    package.artifacts.push(upstream);
    for artifact in &package.artifacts {
        artifact.descriptor.validate()?;
    }
    assert_eq!(package.order()?.len(), 3);
    assert!(matches!(
        fixture.install(package, None).await,
        Err(crate::Error::Package {
            code: PackageErrorCodeV1::Invalid,
            field: "artifact dependency cycle",
            ..
        })
    ));
    assert!(fixture.store.package_revisions([1; 16])?.is_empty());
    assert!(fixture.store.package_activation_page(None)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn admission_preserves_internal_composition() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::UBIGINT AS count");
    derived(&mut package.artifacts[0], &package.root);
    let response = fixture.install(package, None).await?;
    let export = response
        .exports
        .iter()
        .find(|export| export.descriptor.name == "derived")
        .ok_or("derived export is absent")?;
    let output = crate::AnalysisPackageOwner::output_rows(&fixture.output(
        "test.model",
        "derived",
        &export.results[0].result_id,
    )?)?;
    assert_eq!(output["rows"], serde_json::json!([{"count": 4}]));
    Ok(())
}
