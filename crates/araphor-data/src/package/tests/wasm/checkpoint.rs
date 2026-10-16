use super::*;
use araphor_analysis_sdk as sdk;

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
    model.inputs[0].source = sdk::InputSource::Query("SELECT 3::BIGINT UNSIGNED AS value".into());
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

fn assert_state(
    fixture: &Fixture,
    response: &PackageResponseV1,
    target: &str,
    value: u64,
) -> TestResult {
    assert_output(fixture, response, target, value)?;
    let receipt = &response.exports[0].results[0];
    let active = fixture
        .owner
        .activations([1; 16], "test", "runtime-fixture")?;
    assert_eq!(active[0].checkpoint_revision, receipt.commit_revision);
    Ok(())
}

pub(in crate::package::tests) fn assert_output(
    fixture: &Fixture,
    response: &PackageResponseV1,
    target: &str,
    value: u64,
) -> TestResult {
    let receipt = &response.exports[0].results[0];
    assert_eq!(receipt.target, target);
    if target == "native" {
        assert!(receipt.artifact.is_some());
    }
    let output = fixture.output("runtime-fixture", "accumulate", &receipt.result_id)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["data"],
        serde_json::json!([{"value":value}])
    );
    let checkpoint = output.checkpoint.ok_or("checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    let state = sdk::wire::Output {
        datasets: checkpoint.datasets,
        ..Default::default()
    };
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&state)?["state"],
        serde_json::json!([{"value":value}])
    );
    Ok(())
}

#[tokio::test]
async fn wasm_checkpoint_retry_reopens() -> TestResult {
    replay(Fixture::new()?, bundle()?, "wasm").await
}

pub(in crate::package::tests) async fn replay(
    fixture: Fixture,
    package: PackageBundleV1,
    target: &str,
) -> TestResult {
    let installed = fixture.install(package.clone(), None).await?;
    if let PackageImplementationV1::Native {
        artifact,
        qualification,
        ..
    } = &package.artifacts[0].implementations[0]
    {
        let identity = installed.exports[0].results[0]
            .artifact
            .as_ref()
            .ok_or("native artifact receipt absent")?;
        assert_eq!(
            identity.digest,
            crate::package::native::Qualification::digest(artifact)
        );
        assert_eq!(
            identity.closure_digest.as_ref(),
            Some(
                &qualification
                    .as_ref()
                    .ok_or("qualification absent")?
                    .closure_digest(artifact)?
            )
        );
        assert_eq!(
            identity.platform.as_deref(),
            Some(env!("ARAPHOR_NATIVE_TARGET"))
        );
    }
    assert_state(&fixture, &installed, target, 3)?;
    let first = fixture.execute(run("first")).await?;
    assert_state(&fixture, &first, target, 6)?;
    let receipt = first.exports[0].results[0].clone();
    let retained = fixture.result(&receipt.result_id)?;
    let repeated = fixture.execute(run("first")).await?;
    assert_receipt(&repeated.exports[0].results[0], &receipt)?;
    assert_state(&fixture, &repeated, target, 6)?;
    let fixture = fixture.reopen()?;
    let repeated = fixture.execute(run("first")).await?;
    assert_receipt(&repeated.exports[0].results[0], &receipt)?;
    assert_state(&fixture, &repeated, target, 6)?;
    let second = fixture.execute(run("second")).await?;
    assert_state(&fixture, &second, target, 9)?;
    assert_ne!(second.exports[0].results[0].result_id, receipt.result_id);
    let original = fixture.result(&receipt.result_id)?;
    assert_eq!(original.commit.datasets, retained.commit.datasets);
    assert_eq!(original.commit.checkpoint, retained.commit.checkpoint);
    assert_eq!(original.commit_revision, retained.commit_revision);
    assert_eq!(original.commit.metadata, retained.commit.metadata);
    let old = fixture.execute(run("first")).await?;
    assert_receipt(&old.exports[0].results[0], &receipt)?;
    let output = fixture.output("runtime-fixture", "accumulate", &receipt.result_id)?;
    assert_eq!(
        crate::AnalysisPackageOwner::output_rows(&output)?["data"],
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
    assert_state(&fixture, &repeated, target, 9)?;
    Ok(())
}
