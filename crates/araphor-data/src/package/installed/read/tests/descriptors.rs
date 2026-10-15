use super::*;

fn mixed_bundle() -> TestResult<PackageBundleV1> {
    let mut selected = component();
    let mut source = selected.artifacts.remove(1);
    let mut auxiliary = source.descriptor.exports.remove(0);
    auxiliary.name = "aux".into();
    let mut implementation = source.implementations.remove(0);
    let PackageImplementationV1::Sql { export, .. } = &mut implementation else {
        return Err("SQL auxiliary absent".into());
    };
    *export = auxiliary.name.clone();
    let artifact = &mut selected.artifacts[0];
    artifact.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            export: auxiliary.name.clone(),
            output: "rows".into(),
        }));
    artifact.descriptor.exports.push(auxiliary);
    artifact.implementations.push(implementation);
    selected.validate()?;
    Ok(selected)
}

fn assert_output(result: &crate::InstalledEvaluation) -> TestResult {
    result
        .descriptor
        .validate_output(&result.evaluation, &result.output)?;
    assert_eq!(result.output.datasets.len(), 1);
    let data = &result.output.datasets[0];
    assert_eq!(data.name, "data");
    assert_eq!(data.batches.len(), 1);
    let values = data.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("component value absent")?;
    assert_eq!(values.values().as_ref(), &[7]);
    assert!(result.output.evidence.is_empty());
    assert!(result.output.reasons.is_empty());
    assert!(result.output.checkpoint.is_none());
    Ok(())
}

#[test]
fn selected_descriptor_keeps_auxiliary() -> TestResult {
    let fixture = Fixture::new()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let selected = mixed_bundle()?;
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: Some(serde_json::json!({
                "runtime-fixture": {"count-input": {"mode": "sum-input", "amount": 0}}
            })),
        },
        &control,
    )?;
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let evaluation = evaluation(&selected)?;
    let direct = execution.evaluate([1; 16], &selected.root.package_id, &evaluation, &control)?;
    assert_eq!(direct.descriptor, selected.artifacts[0].descriptor);
    assert_output(&direct)?;

    let snapshot = execution.snapshot([1; 16])?;
    let descriptors = snapshot.descriptors([1; 16])?;
    assert_eq!(descriptors.len(), 1);
    let descriptor = &descriptors[0];
    descriptor.validate()?;
    assert_eq!(descriptor, &selected.artifacts[0].descriptor);
    assert_eq!(
        snapshot
            .prepared_models(descriptor)
            .map(|model| model.name.as_str())
            .collect::<Vec<_>>(),
        ["count-input"]
    );
    let references = snapshot.refs()?;
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].package_id, descriptor.id);
    assert_eq!(references[0].revision, descriptor.revision);
    assert_eq!(references[0].export, "count-input");
    assert!(matches!(
        snapshot.evaluate([1; 16], &descriptor.id, &evaluation, &control),
        Err(crate::Error::AnalysisBusy {
            resource: "query output capacity",
            ..
        })
    ));
    let revision = direct.revision.clone();
    let context = direct.evaluation.context.clone();
    let parameters = direct.evaluation.parameters.clone();
    let batches = direct.output.datasets[0].batches.clone();
    drop(direct);
    let result = snapshot.evaluate([1; 16], &descriptor.id, &evaluation, &control)?;
    assert_eq!(&result.descriptor, descriptor);
    assert_eq!(result.revision, revision);
    assert_eq!(result.evaluation.context, context);
    assert_eq!(result.evaluation.parameters, parameters);
    assert_eq!(result.output.datasets[0].batches, batches);
    assert_output(&result)?;
    Ok(())
}
