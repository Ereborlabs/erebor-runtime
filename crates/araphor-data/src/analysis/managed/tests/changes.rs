use super::*;

#[test]
fn change_base_requires_reference() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let requested = request("change-basis");
    let attempt = store.register_managed_attempt(&captured, &requested, || Ok(()))?;
    let evaluations = (10..12)
        .map(|call| fixture.evaluation(&requested, call, Some(&captured)))
        .collect::<TestResult<Vec<_>>>()?;
    let outputs = [fixture.output(1)?, fixture.output(1)?];
    let receipt = fixture.publish_checked(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    let reference = &receipt.results[&10];
    let mut lease = store.reader()?;
    let reader = lease.get_mut()?;
    let (mut record, _) = AnalysisStore::managed_meta_from(reader, [1; 16], &reference.result_id)?;
    let mut model = fixture.model.clone();
    model
        .inputs
        .push(sdk::Port::new("before", model.inputs[0].port.schema.clone()).into());
    model
        .inputs
        .push(sdk::ChangeInputs::reset_port("reset").into());
    model
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .resume_input_changes = true;
    model.change_inputs = Some(sdk::ChangeInputs {
        reset: "reset".into(),
        ports: vec![sdk::ChangeInput {
            affected: "affected".into(),
            before: "before".into(),
            after: "source".into(),
            current: None,
        }],
    });
    record.changes = Some(super::super::model::RecordChanges { base: None });
    let declaration = &fixture.instance.spec.manifest.calls[&10];
    AnalysisStore::check_change_record(reader, [1; 16], &record, declaration, &model, &attempt.0)?;
    for base in [
        reference.clone(),
        crate::analysis::PackageResultRefV1 {
            result_id: "missing-result".into(),
            commit_revision: reference.commit_revision,
        },
        crate::analysis::PackageResultRefV1 {
            result_id: reference.result_id.clone(),
            commit_revision: reference.commit_revision + 1,
        },
        receipt.results[&11].clone(),
    ] {
        record.changes.as_mut().ok_or("changes")?.base = Some(base);
        let error = AnalysisStore::check_change_record(
            reader,
            [1; 16],
            &record,
            declaration,
            &model,
            &attempt.0,
        )
        .err()
        .ok_or("unbound change base accepted")?;
        assert!(
            error.to_string().contains("managed historical base"),
            "{error:?}"
        );
    }
    Ok(())
}
