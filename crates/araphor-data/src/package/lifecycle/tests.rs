use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageImplementationV1, PackageReadinessV1, PackageRequestV1};
use crate::SqlModelV1;

mod admissions;
mod recovery;

#[test]
fn graph_accepts_output_sources() {
    let mut artifact = super::AnalysisPackageOwner::required_bundles()
        .remove(1)
        .artifacts
        .remove(0);
    let model = &mut artifact.descriptor.exports[0];
    let export = model.name.clone();
    model.inputs[0].source = sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
        package: "test.upstream".into(),
        revision: "1".into(),
        export: "source".into(),
        output: "rows".into(),
    }));
    assert!(matches!(
        super::AnalysisPackageOwner::readiness(&artifact, &export),
        PackageReadinessV1::Ready
    ));
    artifact.descriptor.exports[0].inputs[0].port.name = "other".into();
    assert!(matches!(
        super::AnalysisPackageOwner::readiness(&artifact, &export),
        PackageReadinessV1::Unsupported { .. }
    ));
}

#[tokio::test]
async fn admitted_inspection_tracks_replacement() -> TestResult {
    let fixture = Fixture::new()?;
    let original = bundle("1", "SELECT 3::UBIGINT AS count");
    fixture.install(original.clone(), None).await?;
    let control = crate::AnalysisReadControl::default();
    let response = fixture.owner.inspect(
        &fixture.grant,
        "test",
        "test.model",
        Some(&original),
        &control,
    )?;
    assert_eq!(response.exports[0].revision, "1");
    assert_eq!(response.exports[0].results.len(), 1);
    let replacement = bundle("2", "SELECT 4::UBIGINT AS count");
    fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: replacement.clone(),
        })
        .await?;
    for admitted in [&original, &replacement] {
        let response = fixture.owner.inspect(
            &fixture.grant,
            "test",
            "test.model",
            Some(admitted),
            &control,
        )?;
        assert_eq!(response.exports[0].revision, "2");
        assert!(!response.exports[0].results.is_empty());
        assert!(fixture
            .owner
            .inspect(
                &fixture.grant,
                "other",
                "test.model",
                Some(admitted),
                &control,
            )?
            .exports
            .is_empty());
    }
    let mut denied = fixture.grant.clone();
    denied.revision += 1;
    assert!(matches!(
        fixture
            .owner
            .inspect(&denied, "test", "test.model", Some(&replacement), &control,),
        Err(crate::Error::Package {
            code: crate::package::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn parameters_checked_before_installation() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::UBIGINT AS count");
    let artifact = &mut package.artifacts[0];
    let mut second = artifact.descriptor.exports[0].clone();
    second.name = "threshold".into();
    second.parameters = sdk::Schema::new(vec![sdk::Field::new(
        "minimum",
        sdk::DataType::UInt64,
        false,
    )]);
    artifact.descriptor.exports.push(second);
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "threshold".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT minimum AS count FROM parameters".into(),
            )]),
            ..Default::default()
        },
    });
    for parameters in [
        None,
        Some(serde_json::json!({"test.model":{"threshold":{"minimum":"bad"}}})),
        Some(serde_json::json!({"test.model":{"unknown":{}}})),
        Some(serde_json::json!({"missing":{"threshold":{"minimum":3}}})),
    ] {
        assert!(fixture.install(package.clone(), parameters).await.is_err());
        assert!(fixture
            .store
            .package_revision([1; 16], "test.model", "1")?
            .is_none());
        assert!(fixture.store.package_activation_page(None)?.is_empty());
    }
    let response = fixture
        .install(
            package,
            Some(serde_json::json!({
                "test.model":{"threshold":{"minimum":3}}
            })),
        )
        .await?;
    assert_eq!(response.exports.len(), 2);
    assert!(response
        .exports
        .iter()
        .all(|export| export.active && matches!(export.readiness, PackageReadinessV1::Ready)));
    Ok(())
}

#[tokio::test]
async fn renewal_preserves_failed_readiness() -> TestResult {
    let mut fixture = Fixture::new()?;
    let package = bundle("1", "SELECT CAST('bad' AS UBIGINT) AS count");
    assert!(fixture.install(package.clone(), None).await.is_err());
    let before = fixture.store.package_activation_page(None)?.remove(0);
    let before_context: super::InstalledContext =
        super::AnalysisPackageOwner::decode(&before.metadata)?;
    assert!(matches!(
        before_context.readiness,
        PackageReadinessV1::Failed { .. }
    ));
    fixture.renew();
    let response = fixture.install(package, None).await?;
    assert!(matches!(
        response.exports[0].readiness,
        PackageReadinessV1::Failed { .. }
    ));
    assert!(response.exports[0].results.is_empty());
    let after = fixture.store.package_activation_page(None)?.remove(0);
    let after_context: super::InstalledContext =
        super::AnalysisPackageOwner::decode(&after.metadata)?;
    assert_eq!(after_context.grant, fixture.grant);
    assert_eq!(
        after_context.status_checkpoint,
        before_context.status_checkpoint
    );
    assert_eq!(after.checkpoint_revision, before.checkpoint_revision);
    Ok(())
}

#[tokio::test]
async fn missing_dependency_target_status() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT count FROM source");
    let mut upstream = bundle("1", "SELECT 3::UBIGINT AS count")
        .artifacts
        .remove(0);
    upstream.descriptor.id = "test.upstream".into();
    upstream.implementations = vec![PackageImplementationV1::Native {
        export: "count".into(),
        artifact: vec![0, 97, 115, 109],
        qualification: None,
    }];
    let root = &mut package.artifacts[0];
    let mut input = root.descriptor.exports[0].outputs[0].clone();
    input.name = "source".into();
    root.descriptor.exports[0].inputs.push(input.into());
    root.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "test.upstream".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        }));
    let explicit = crate::PackageBundleV1 {
        schema_version: 1,
        root: upstream.reference(),
        artifacts: vec![upstream.clone()],
    };
    let first = fixture.install(explicit.clone(), None).await?;
    let retry = fixture.install(explicit, None).await?;
    assert_eq!(
        first.exports[0].activation_revision,
        retry.exports[0].activation_revision
    );
    package.artifacts.push(upstream);
    let response = fixture.install(package, None).await?;
    assert!(response.exports[0].active);
    assert!(matches!(
        response.exports[0].readiness,
        PackageReadinessV1::MissingInput { .. }
    ));
    assert!(response.exports[0].results.is_empty());
    let upstream = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: "test.upstream".into(),
        })
        .await?;
    assert!(!upstream.exports[0].active);
    assert_eq!(
        upstream.exports[0].activation_revision,
        first.exports[0].activation_revision
    );
    assert!(matches!(
        upstream.exports[0].readiness,
        PackageReadinessV1::Unsupported { .. }
    ));
    assert!(upstream.exports[0].results.is_empty());
    fixture
        .execute(PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: "test.model".into(),
        })
        .await?;
    let retained = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: "test.upstream".into(),
        })
        .await?;
    assert_eq!(retained.exports.len(), 1);
    assert!(matches!(
        retained.exports[0].readiness,
        PackageReadinessV1::Unsupported { .. }
    ));
    Ok(())
}

fn shared_bundle(name: &str) -> crate::PackageBundleV1 {
    let mut package = bundle(
        "1",
        "SELECT source.count + parameters.offset AS count FROM source JOIN parameters ON source.__row_index = parameters.__row_index",
    );
    package.root.package_id = name.into();
    let root = &mut package.artifacts[0];
    root.descriptor.id = name.into();
    let mut input = root.descriptor.exports[0].outputs[0].clone();
    input.name = "source".into();
    root.descriptor.exports[0].inputs.push(input.into());
    root.descriptor.exports[0].parameters = sdk::Schema::new(vec![sdk::Field::new(
        "offset",
        sdk::DataType::UInt64,
        false,
    )]);
    root.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "test.shared".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        }));
    let mut upstream = bundle("1", "SELECT minimum AS count FROM parameters")
        .artifacts
        .remove(0);
    upstream.descriptor.id = "test.shared".into();
    upstream.descriptor.exports[0].parameters = sdk::Schema::new(vec![sdk::Field::new(
        "minimum",
        sdk::DataType::UInt64,
        false,
    )]);
    package.artifacts.push(upstream);
    package
}

#[tokio::test]
async fn shared_dependency_parameter_comparison() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .install(
            shared_bundle("test.first"),
            Some(serde_json::json!({
                "test.first":{"count":{"offset":1}}, "test.shared":{"count":{"minimum":3}}
            })),
        )
        .await?;
    let second = shared_bundle("test.second");
    let response = fixture
        .install(
            second.clone(),
            Some(serde_json::json!({
                "test.second":{"count":{"offset":2}}, "test.shared":{"count":{"minimum":3}}
            })),
        )
        .await?;
    let output = crate::AnalysisPackageOwner::output_rows(&fixture.output(
        "test.second",
        "count",
        &response.exports[0].results[0].result_id,
    )?)?;
    assert_eq!(output["rows"], serde_json::json!([{"count":5}]));
    let evaluated = fixture
        .execute(PackageRequestV1::Run {
            scope_id: "test".into(),
            package_id: "test.second".into(),
            export: None,
            evaluation_id: "shared-root".into(),
            parameters: None,
        })
        .await?;
    let output = fixture.output(
        "test.second",
        "count",
        &evaluated.exports[0].results[0].result_id,
    )?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["rows"],
        serde_json::json!([{"count":5}])
    );
    let shared = fixture
        .store
        .package_activation_page(None)?
        .into_iter()
        .find(|active| active.key.package_id == "test.shared")
        .ok_or("shared activation")?;
    let context: super::InstalledContext = super::AnalysisPackageOwner::decode(&shared.metadata)?;
    assert_eq!(context.root.package_id, "test.first");
    assert!(fixture
        .install(
            second,
            Some(serde_json::json!({
                "test.second":{"count":{"offset":2}}, "test.shared":{"count":{"minimum":4}}
            }))
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn oversized_parameters_preserve_store() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT 3::UBIGINT AS count");
    package.artifacts[0].descriptor.exports[0].parameters =
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Utf8, false)]);
    let parameters = serde_json::json!({"test.model":{"count":{
        "value":"x".repeat(crate::analysis::MAX_PACKAGE_METADATA_BYTES)
    }}});
    assert!(fixture.install(package, Some(parameters)).await.is_err());
    assert!(fixture
        .store
        .package_revision([1; 16], "test.model", "1")?
        .is_none());
    assert!(fixture.store.package_activation_page(None)?.is_empty());
    Ok(())
}
