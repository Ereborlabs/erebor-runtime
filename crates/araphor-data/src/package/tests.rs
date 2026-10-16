use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::*;

pub(super) type TestResult<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) fn bundle(revision: &str, sql: &str) -> PackageBundleV1 {
    let mut descriptor = sdk::Package::new(
        "test.model",
        revision,
        vec![sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
            )],
        )],
    );
    descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: revision.into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), sql.into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

#[test]
fn parameter_contract_without_engine() -> TestResult {
    let schema = sdk::Schema::new(vec![
        sdk::Field::new("count", sdk::DataType::UInt64, false),
        sdk::Field::new("ratio", sdk::DataType::Float32, true),
    ]);
    let value = serde_json::json!({"count": u64::MAX, "ratio": 1.5});
    let batch = decode_parameters(&schema, Some(&value))?.ok_or("parameters absent")?;
    assert_eq!(batch.num_rows(), 1);
    assert_eq!(batch.schema().as_ref(), &schema);
    for invalid in [
        serde_json::json!({"count": -1}),
        serde_json::json!({"count": "1"}),
        serde_json::json!({"count": null}),
        serde_json::json!({"count": 1, "extra": true}),
        serde_json::json!({"count": 1, "ratio": 1e100}),
    ] {
        assert!(
            decode_parameters(&schema, Some(&invalid)).is_err(),
            "{invalid}"
        );
    }
    assert!(decode_parameters(&schema, None).is_err());
    assert!(decode_parameters(&sdk::Schema::empty(), None)?.is_none());
    Ok(())
}

#[test]
fn selections_reject_foreign_keys() -> TestResult {
    let mut selection = crate::AnalysisSelectionV1::tenant([1; 16]);
    selection.select_profiles(crate::Selection::Exact(vec!["profile".into()]))?;
    let before = selection.clone();
    assert!(selection
        .select_profiles(crate::Selection::Exact(vec![
            "profile".into(),
            "profile".into()
        ]))
        .is_err());
    assert_eq!(selection, before);
    let foreign = crate::AnalysisContextKeyV1 {
        tenant_id: [2; 16],
        owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
        entity_key: vec![1],
        lifetime_key: vec![1],
        owner_revision: 1,
    };
    assert!(selection
        .select_notifications(crate::Selection::Exact(vec![foreign]))
        .is_err());
    assert_eq!(selection, before);
    assert!(selection.select_targets(false, true).is_err());
    assert_eq!(selection, before);
    Ok(())
}
