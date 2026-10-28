use super::*;

#[test]
fn previous_outputs_follow_checkpoint() -> TestResult {
    let mut package = FilesCount::package();
    package.exports[0].checkpoint = Some(CheckpointSpec {
        version: 1,
        resume_input_changes: true,
        datasets: vec![Port::new("state", Schema::empty())],
    });
    let mut evaluation = FilesCount::fixture()?.evaluation;
    package.validate_evaluation(&evaluation)?;
    let previous = FilesCount::evaluate(&evaluation)?.datasets;
    evaluation.previous_outputs = previous.clone();
    assert!(package.validate_evaluation(&evaluation).is_err());
    evaluation.checkpoint = Some(Checkpoint {
        version: 1,
        datasets: vec![Dataset {
            name: "state".into(),
            batches: Vec::new(),
        }],
    });
    package.validate_evaluation(&evaluation)?;
    let mut declaration = serde_json::to_value(
        package.exports[0]
            .checkpoint
            .as_ref()
            .ok_or("checkpoint model")?,
    )?;
    declaration
        .as_object_mut()
        .ok_or("checkpoint declaration")?
        .remove("resume_input_changes");
    let ordinary = serde_json::from_value::<CheckpointSpec>(declaration)?;
    assert!(!ordinary.resume_input_changes);
    package.exports[0].checkpoint = Some(ordinary);
    assert!(package.validate_evaluation(&evaluation).is_err());
    evaluation.previous_outputs.clear();
    package.validate_evaluation(&evaluation)?;
    package.exports[0]
        .checkpoint
        .as_mut()
        .ok_or("checkpoint model")?
        .resume_input_changes = true;
    assert_eq!(
        package
            .validate_evaluation(&evaluation)
            .err()
            .ok_or("missing prior accepted")?
            .code(),
        ErrorCode::Incomplete
    );
    for invalid in 0..4 {
        evaluation.previous_outputs = previous.clone();
        match invalid {
            0 => evaluation.previous_outputs[0].name = "unknown".into(),
            1 => evaluation.previous_outputs.push(previous[0].clone()),
            2 => {
                evaluation.previous_outputs[0].batches =
                    vec![RecordBatch::new_empty(Arc::new(Schema::empty()))]
            }
            _ => evaluation.previous_outputs.push(Dataset {
                name: "extra".into(),
                batches: Vec::new(),
            }),
        }
        assert!(package.validate_evaluation(&evaluation).is_err());
    }
    evaluation.previous_outputs = vec![Dataset {
        name: previous[0].name.clone(),
        batches: vec![RecordBatch::new_empty(Arc::new(
            package.exports[0].outputs[0].schema.clone(),
        ))],
    }];
    package.validate_evaluation(&evaluation)?;
    let wire = package.check_evaluation(&evaluation)?.encode()?;
    assert_eq!(wire.decode(&package)?.previous_outputs[0].rows(), 0);
    Ok(())
}

#[test]
fn previous_state_cannot_cite() -> TestResult {
    let mut package = FilesCount::package();
    package.exports[0].checkpoint = Some(CheckpointSpec {
        version: 1,
        resume_input_changes: true,
        datasets: vec![Port::new("state", Schema::empty())],
    });
    let mut evaluation = FilesCount::fixture()?.evaluation;
    let mut output = FilesCount::evaluate(&evaluation)?;
    evaluation.checkpoint = Some(Checkpoint {
        version: 1,
        datasets: vec![Dataset {
            name: "state".into(),
            batches: Vec::new(),
        }],
    });
    evaluation.previous_outputs = output.datasets.clone();
    output.checkpoint = evaluation.checkpoint.clone();
    package.validate_output(&evaluation, &output)?;
    let encoded = package.check_evaluation(&evaluation)?.encode()?;
    let decoded = encoded.decode(&package)?;
    assert_eq!(
        encoded.previous_outputs.len(),
        evaluation.previous_outputs.len()
    );
    assert_eq!(
        decoded.previous_outputs[0].name,
        evaluation.previous_outputs[0].name
    );
    assert_eq!(
        decoded.previous_outputs[0].batches,
        evaluation.previous_outputs[0].batches
    );
    let mut invalid_wire = encoded;
    invalid_wire.previous_outputs.clear();
    assert!(invalid_wire.decode(&package).is_err());
    for value in [&evaluation, &decoded] {
        output.evidence[0].input.dataset = value.previous_outputs[0].name.clone();
        assert_eq!(
            package
                .validate_output(value, &output)
                .err()
                .ok_or("prior state cited as evidence")?
                .code(),
            ErrorCode::Invalid
        );
    }
    drop(evaluation);
    assert_eq!(decoded.previous_outputs[0].rows(), 1);
    Ok(())
}
