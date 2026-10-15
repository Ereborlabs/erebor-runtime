use super::*;
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};

fn chain(revision: &str, empty: bool) -> TestResult<PackageBundleV1> {
    let mut package = component(revision);
    let artifact = &mut package.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.name = "count-input".into();
    model.inputs = vec![sdk::Port::new("input", model.outputs[0].schema.clone()).into()];
    model.inputs[0].source = sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
        package: "sql-source".into(),
        revision: revision.into(),
        export: "count".into(),
        output: "rows".into(),
    }));
    let PackageImplementationV1::Wasm { exports, .. } = &mut artifact.implementations[0] else {
        return Err("Wasm fixture absent".into());
    };
    *exports = vec!["count-input".into()];
    let mut upstream = crate::package::tests::bundle(
        revision,
        if empty {
            "SELECT value FROM source WHERE false"
        } else {
            "SELECT value FROM source"
        },
    )
    .artifacts
    .remove(0);
    upstream.descriptor.id = "sql-source".into();
    upstream.descriptor.exports[0].outputs[0].schema = model.outputs[0].schema.clone();
    upstream.descriptor.exports[0].inputs =
        vec![sdk::Port::new("source", model.outputs[0].schema.clone()).into()];
    upstream.descriptor.exports[0].inputs[0].source = sdk::InputSource::Query("SELECT max(owner_revision)::UBIGINT AS value FROM context_versions WHERE owner_id = 'fixture'".into());
    package.artifacts.push(upstream);
    Ok(package)
}

fn context(revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "fixture".into(),
            entity_key: b"event".to_vec(),
            lifetime_key: b"lifetime".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"value".to_vec(),
    }
}

fn run(id: &str) -> PackageRequestV1 {
    PackageRequestV1::Run {
        scope_id: "test".into(),
        package_id: "runtime-fixture".into(),
        export: Some("count-input".into()),
        evaluation_id: id.into(),
        parameters: None,
    }
}

fn assert_value(fixture: &Fixture, response: &PackageResponseV1, expected: u64) -> TestResult {
    let receipt = &response.exports[0].results[0];
    let rows = crate::AnalysisPackageOwner::output_rows(&fixture.output(
        "runtime-fixture",
        "count-input",
        &receipt.result_id,
    )?)?;
    assert_eq!(rows["data"], serde_json::json!([{"value": expected}]));
    assert_eq!(receipt.target, "wasm");
    Ok(())
}

#[tokio::test]
async fn wasm_dependency_replacements() -> TestResult {
    let fixture = Fixture::new_limits(crate::QueryLimits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        extract_timeout: std::time::Duration::from_secs(30),
        evaluate_timeout: std::time::Duration::from_secs(30),
        ..Default::default()
    })?;
    fixture.store.commit_context(&context(1))?;
    let first = fixture
        .install(
            chain("1", false)?,
            Some(serde_json::json!({
                "runtime-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
            })),
        )
        .await?;
    assert_value(&fixture, &first, 1)?;
    let old = first.exports[0].results[0].result_id.clone();
    fixture.store.commit_context(&context(2))?;
    let stale = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: "runtime-fixture".into(),
        })
        .await?;
    assert!(stale.exports[0]
        .results
        .iter()
        .any(|receipt| receipt.result_id == old && receipt.stale));
    let corrected = fixture.execute(run("corrected")).await?;
    assert_value(&fixture, &corrected, 2)?;
    let retry = fixture.execute(run("corrected")).await?;
    assert_eq!(
        retry.exports[0].results[0].result_id,
        corrected.exports[0].results[0].result_id
    );
    let empty = fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: chain("2", true)?,
        })
        .await?;
    assert_value(&fixture, &empty, 0)?;
    let fixture = fixture.reopen()?;
    assert_value(&fixture, &fixture.execute(run("empty-reopened")).await?, 0)?;
    assert!(matches!(
        fixture.execute(run("corrected")).await,
        Err(crate::Error::Package {
            code: PackageErrorCodeV1::Conflict,
            ..
        })
    ));
    Ok(())
}
