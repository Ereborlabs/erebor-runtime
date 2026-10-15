use super::*;

pub(in crate::package::tests) fn bundle() -> TestResult<PackageBundleV1> {
    let mut package = component("1");
    let artifact = &mut package.artifacts[0];
    let schema = artifact.descriptor.exports[0].outputs[0].schema.clone();
    let mut model = sdk::Model::new(
        "accumulate",
        vec![sdk::Port::new("input", schema.clone())],
        vec![sdk::Port::new("data", schema.clone())],
    );
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", schema)],
    });
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0].source = sdk::InputSource::Query("SELECT 3::UBIGINT AS value".into());
    artifact.descriptor.exports = vec![model];
    let PackageImplementationV1::Wasm { exports, .. } = &mut artifact.implementations[0] else {
        return Err("Wasm fixture absent".into());
    };
    *exports = vec!["accumulate".into()];
    Ok(package)
}

pub(in crate::package::tests) fn run(id: &str) -> PackageRequestV1 {
    PackageRequestV1::Run {
        scope_id: "test".into(),
        package_id: "runtime-fixture".into(),
        export: Some("accumulate".into()),
        evaluation_id: id.into(),
        parameters: None,
    }
}

fn assert_state(fixture: &Fixture, response: &PackageResponseV1, value: u64) -> TestResult {
    let receipt = &response.exports[0].results[0];
    assert_eq!(receipt.target, "wasm");
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        &receipt.result_id,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value":value}])
    );
    let checkpoint = output.checkpoint.ok_or("checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    let state = PackageOutputV1 {
        datasets: checkpoint.datasets,
        ..Default::default()
    };
    assert_eq!(
        state.json_rows()?["state"],
        serde_json::json!([{"value":value}])
    );
    let active = fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?;
    assert_eq!(active[0].checkpoint_revision, receipt.commit_revision);
    Ok(())
}

#[tokio::test]
async fn wasm_checkpoint_retry_reopens() -> TestResult {
    let fixture = Fixture::new()?;
    let installed = fixture.install(bundle()?, None).await?;
    assert_state(&fixture, &installed, 3)?;
    let first = fixture.execute(run("first")).await?;
    assert_state(&fixture, &first, 6)?;
    let receipt = first.exports[0].results[0].clone();
    let retained = fixture
        .store
        .package_result([1; 16], &receipt.result_id)?
        .ok_or("retained result absent")?;
    let repeated = fixture.execute(run("first")).await?;
    assert_receipt(&repeated.exports[0].results[0], &receipt)?;
    assert_state(&fixture, &repeated, 6)?;
    let fixture = fixture.reopen()?;
    let repeated = fixture.execute(run("first")).await?;
    assert_receipt(&repeated.exports[0].results[0], &receipt)?;
    assert_state(&fixture, &repeated, 6)?;
    let second = fixture.execute(run("second")).await?;
    assert_state(&fixture, &second, 9)?;
    assert_ne!(second.exports[0].results[0].result_id, receipt.result_id);
    let original = fixture
        .store
        .package_result([1; 16], &receipt.result_id)?
        .ok_or("original result absent")?;
    assert_eq!(original.datasets, retained.datasets);
    assert_eq!(original.checkpoint, retained.checkpoint);
    assert_eq!(original.commit_revision, retained.commit_revision);
    let old = fixture.execute(run("first")).await?;
    assert_receipt(&old.exports[0].results[0], &receipt)?;
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        &receipt.result_id,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value":6}])
    );
    let active = fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?;
    assert_eq!(
        active[0].checkpoint_revision,
        second.exports[0].results[0].commit_revision
    );
    let repeated = fixture.execute(run("second")).await?;
    assert_receipt(
        &repeated.exports[0].results[0],
        &second.exports[0].results[0],
    )?;
    assert_state(&fixture, &repeated, 9)?;
    Ok(())
}
