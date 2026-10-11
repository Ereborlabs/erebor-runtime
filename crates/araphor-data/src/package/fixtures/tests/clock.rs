use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::UInt64Array;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageFixtureV1, PackageOutputV1, PackageRequestV1};

#[tokio::test]
async fn fixture_replays_saved_context() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT CASE WHEN CURRENT_TIMESTAMP = TIMESTAMP '2000-01-01 00:00:00' THEN 1::UBIGINT ELSE 0::UBIGINT END AS count");
    let artifact = &mut package.artifacts[0];
    let model = &artifact.descriptor.exports[0];
    for (name, now, expected) in [
        ("matching", 946684800000000000, 1),
        ("later", 946684801000000000, 0),
    ] {
        let output = sdk::Output {
            datasets: vec![sdk::Dataset {
                name: "rows".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(model.outputs[0].schema.clone()),
                    vec![Arc::new(UInt64Array::from(vec![expected]))],
                )?],
            }],
            ..Default::default()
        };
        let saved = PackageFixtureV1 {
            name: name.into(),
            export: "count".into(),
            time_utc_ns: now,
            seed: Some(u64::MAX),
            inputs: Vec::new(),
            parameters: None,
            checkpoint: None,
            expected: PackageOutputV1::encode(&output, model)?,
        };
        let mut json = serde_json::to_value(&saved)?;
        let restored: PackageFixtureV1 = serde_json::from_value(json.clone())?;
        let context = restored.evaluation_context(model);
        assert_eq!(context.time_utc_ns, now);
        assert_eq!(context.seed, Some(u64::MAX));
        assert_eq!(context.limits, model.limits);
        json.as_object_mut()
            .ok_or("fixture object")?
            .remove("time_utc_ns");
        json.as_object_mut().ok_or("fixture object")?.remove("seed");
        let defaults: PackageFixtureV1 = serde_json::from_value(json)?;
        assert_eq!(defaults.evaluation_context(model).time_utc_ns, 0);
        assert_eq!(defaults.evaluation_context(model).seed, None);
        artifact.fixtures.push(restored);
    }
    fixture.install(package, None).await?;
    for _ in 0..2 {
        let response = fixture
            .execute(PackageRequestV1::Test {
                scope_id: "test".into(),
                package_id: "test.model".into(),
                fixture: None,
            })
            .await?;
        assert_eq!(response.tests.len(), 2);
        assert!(response.tests.iter().all(|result| result.passed));
    }
    Ok(())
}
