use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::{Fixture, TestResult};
use crate::package::*;

pub(super) mod checkpoint;
mod flow;
mod interruption;
mod lifecycle;
mod metadata;

#[test]
fn oversized_input_precedes_compilation() -> TestResult {
    let fixture = Fixture::new()?;
    let query = crate::Engine::new(
        fixture.store.clone(),
        crate::Limits {
            input_bytes: 1024,
            ..Default::default()
        },
    )?;
    let owner = std::sync::Arc::new(AnalysisPackageOwner::new(query, fixture.authority.clone())?);
    let mut package = component("1");
    let artifact = &mut package.artifacts[0];
    let PackageImplementationV1::Wasm {
        artifact: bytes, ..
    } = &mut artifact.implementations[0]
    else {
        return Err("Wasm fixture absent".into());
    };
    *bytes = b"invalid component".to_vec();
    let model = &artifact.descriptor.exports[0];
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: Vec::new(),
        checkpoint: None,
        parameters: araphor_data::decode_parameters(
            &model.parameters,
            Some(&serde_json::json!({"mode": "x".repeat(4096), "amount": 7})),
        )?,
        context: sdk::EvaluationContext {
            id: "memory".into(),
            time_utc_ns: 0,
            seed: None,
            limits: model.limits,
        },
    };
    let bundle = crate::package::installed::snapshot::InstalledBundle::new(
        &owner.query,
        package,
        owner.query.memory(),
    )?;
    let index = bundle.export_index("runtime-fixture", "1", &evaluation.export)?;
    let control = crate::AnalysisReadControl::default();
    assert!(matches!(
        owner.evaluate_artifact(
            [1; 16],
            bundle,
            index,
            evaluation.clone(),
            None,
            &owner.query.memory().scope(),
            &control
        ),
        Err(crate::Error::ModelLimit {
            resource: "analysis input memory",
            ..
        })
    ));
    let installed = InstalledAnalysis::new(owner, "test")?;
    assert!(matches!(
        installed.evaluate([1; 16], "runtime-fixture", &evaluation, &control),
        Err(crate::Error::ModelLimit {
            resource: "analysis input memory",
            ..
        })
    ));
    Ok(())
}

pub(super) fn component(revision: &str) -> PackageBundleV1 {
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let descriptor = sdk::Package::new("runtime-fixture", revision, vec![model]);
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: revision.into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["evaluate".into()],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            }],
            fixtures: Vec::new(),
        }],
    }
}

pub(super) fn parameters(mode: &str) -> serde_json::Value {
    serde_json::json!({"runtime-fixture": {"evaluate": {"mode": mode, "amount": 7}}})
}

pub(super) fn evaluate(id: &str) -> PackageRequestV1 {
    PackageRequestV1::Run {
        scope_id: "test".into(),
        package_id: "runtime-fixture".into(),
        export: Some("evaluate".into()),
        evaluation_id: id.into(),
        parameters: None,
    }
}

fn assert_receipt(actual: &PackageReceiptV1, expected: &PackageReceiptV1) -> TestResult {
    let mut actual = actual.clone();
    // Clock refresh can change the stale flag of a retained result.
    actual.stale = expected.stale;
    assert_eq!(
        serde_json::to_value(actual)?,
        serde_json::to_value(expected)?
    );
    Ok(())
}

#[tokio::test]
async fn wasm_failure_retains_state() -> TestResult {
    for (mode, code) in [
        ("trap", PackageErrorCodeV1::Incomplete),
        ("hostcalls", PackageErrorCodeV1::Limit),
        ("limit", PackageErrorCodeV1::Limit),
        ("invalid-evidence", PackageErrorCodeV1::Invalid),
    ] {
        let fixture = Fixture::new_backend_limits(
            crate::Limits {
                extract_timeout: std::time::Duration::from_secs(30),
                evaluate_timeout: std::time::Duration::from_secs(30),
                ..Default::default()
            },
            crate::AnalysisLimits {
                wasm: crate::WasmLimits {
                    fuel: Some(100_000_000),
                    memory_bytes: Some(256 * 1024 * 1024),
                    data_bytes: Some(32 * 1024 * 1024),
                    timeout: Some(std::time::Duration::from_secs(5)),
                    allocation_bytes: Some(32 * 1024 * 1024),
                    host_calls: Some(4096),
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        let package = component("1");
        assert!(fixture
            .install(package, Some(parameters(mode)))
            .await
            .is_err());
        let inspected = fixture
            .execute(PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: "runtime-fixture".into(),
            })
            .await?;
        assert!(inspected.exports[0].results.is_empty());
        assert!(
            matches!(inspected.exports[0].readiness, PackageReadinessV1::Failed { code: failed, .. } if failed == code)
        );
        let fixture = fixture.reopen()?;
        assert!(fixture.execute(evaluate("retry-trap")).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn ambiguous_type_rejects_activation() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = component("1");
    package.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Sql {
            export: "evaluate".into(),
            program: crate::SqlModelV1 {
                outputs: BTreeMap::from([(
                    "data".into(),
                    "SELECT 7::BIGINT UNSIGNED AS value".into(),
                )]),
                ..Default::default()
            },
        });
    assert!(matches!(
        fixture.install(package, Some(parameters("echo"))).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: PackageErrorCodeV1::Invalid,
                field: "plugin execution type",
                ..
            }
        })
    ));
    assert!(fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?
        .is_empty());
    assert!(fixture
        .store
        .package_revision([1; 16], "runtime-fixture", "1")?
        .is_none());
    Ok(())
}
