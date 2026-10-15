use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::package::{
    InstalledAnalysis, PackageArtifactV1, PackageBundleV1, PackageGrantV1, PackageImplementationV1,
    PackageRefV1, PackageRequestV1,
};

fn bundle(inputs: &[sdk::Input]) -> TestResult<PackageBundleV1> {
    let ports = inputs
        .iter()
        .map(|input| {
            let batch = input.data.batches.first().ok_or("input batch absent")?;
            Ok(sdk::Port::new(
                &input.data.name,
                batch.schema().as_ref().clone(),
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut outputs = ports.clone();
    outputs.push(sdk::Port::new(
        "metadata",
        sdk::Schema::new(vec![
            sdk::Field::new("dataset", sdk::DataType::Utf8, false),
            sdk::Field::new("revision", sdk::DataType::Utf8, false),
            sdk::Field::new("coverage", sdk::DataType::Utf8, false),
        ]),
    ));
    let descriptor = sdk::Package::new(
        "runtime-fixture",
        "1",
        vec![sdk::Model::new("echo-inputs", ports, outputs)],
    );
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["echo-inputs".into()],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            }],
            fixtures: Vec::new(),
        }],
    })
}

fn assert_inputs(
    execution: &InstalledAnalysis,
    tenant: [u8; 16],
    inputs: &GraphAnalysisInputsV1,
    id: &str,
) -> TestResult {
    let evaluation = sdk::Evaluation {
        export: "echo-inputs".into(),
        inputs: inputs.inputs().to_vec(),
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: id.into(),
            time_utc_ns: 10,
            seed: None,
            limits: sdk::Limits::default(),
        },
    };
    let evaluated = execution.evaluate(tenant, "runtime-fixture", &evaluation, &control()?)?;
    evaluated
        .descriptor
        .validate_output(&evaluated.evaluation, &evaluated.output)?;
    assert_eq!(evaluated.revision, "1");
    assert_eq!(evaluated.output.datasets.len(), inputs.inputs().len() + 1);
    let metadata = evaluated
        .output
        .datasets
        .iter()
        .find(|dataset| dataset.name == "metadata")
        .ok_or("metadata dataset absent")?;
    let rows = metadata.batches.first().ok_or("metadata batch absent")?;
    assert_eq!(rows.num_rows(), inputs.inputs().len());
    for (index, input) in inputs.inputs().iter().enumerate() {
        let output = evaluated
            .output
            .datasets
            .iter()
            .find(|dataset| dataset.name == input.data.name)
            .ok_or("returned dataset absent")?;
        assert_eq!(output.batches, input.data.batches);
        assert_eq!(
            column::<StringArray>(rows, "dataset")?.value(index),
            input.data.name
        );
        assert_eq!(
            serde_json::from_str::<sdk::Revision>(
                column::<StringArray>(rows, "revision")?.value(index)
            )?,
            input.revision
        );
        assert_eq!(
            serde_json::from_str::<sdk::Coverage>(
                column::<StringArray>(rows, "coverage")?.value(index)
            )?,
            input.coverage
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_graph_component_inputs() -> TestResult {
    let fixture = NativeFixture::new(true)?;
    let tenant = fixture.selection.tenant_id;
    let execution = InstalledAnalysis::testing(Some(fixture.stored.store.clone()), tenant)?;
    let owner = fixture.owner(QueryLimits::default())?;
    let inputs = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    execution
        .testing_owner()
        .execute(
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(tenant),
                expires_utc_ns: None,
                authorization_id: None,
            },
            PackageRequestV1::Install {
                scope_id: crate::AnalysisPackageOwner::DOMAIN_SCOPE.into(),
                bundle: bundle(inputs.inputs())?,
                parameters: None,
            },
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(60))?),
        )
        .await?;
    let execution = execution.snapshot(tenant)?;
    assert_inputs(&execution, tenant, &inputs, "native")?;
    assert_eq!(inputs.inputs()[0].data.batches[0].num_rows(), 2);
    assert_eq!(inputs.inputs()[1].data.batches[0].num_rows(), 1);
    assert!(inputs.traversal.hop_boundary);
    assert_eq!(
        inputs.inputs()[0].coverage.state,
        sdk::CoverageState::Unknown
    );
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &fixture.request, &control()?),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    let revision = inputs.inputs()[0].revision.clone();
    drop(inputs);
    let replacement = fixture.replace_empty()?;
    let inputs = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    assert_inputs(&execution, tenant, &inputs, "empty")?;
    assert_eq!(inputs.traversal.result_ids, vec![replacement]);
    assert_ne!(inputs.inputs()[0].revision, revision);
    assert_eq!(inputs.inputs()[0].data.batches[0].num_rows(), 0);
    assert_eq!(inputs.inputs()[1].data.batches[0].num_rows(), 0);
    let manifest = &inputs.inputs()[2].data.batches[0];
    assert_eq!(manifest.num_rows(), 1);
    assert_eq!(
        column::<UInt64Array>(manifest, "subject_count")?.value(0),
        0
    );
    assert_eq!(
        column::<UInt64Array>(manifest, "relationship_count")?.value(0),
        0
    );
    assert_eq!(
        column::<StringArray>(manifest, "previous_result_id")?.value(0),
        fixture.stored.request.result_id
    );
    assert_eq!(
        serde_json::from_slice::<crate::EvidenceIntakeIdentityV1>(
            column::<BinaryArray>(manifest, "source_key")?.value(0)
        )?,
        fixture.stored.snapshot.scope.identity
    );
    Ok(())
}
