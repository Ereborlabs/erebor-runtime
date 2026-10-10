use super::*;

#[test]
fn output_evidence_is_exact() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let mut output = FilesCount::evaluate(&fixture.evaluation)?;
    output.evidence.clear();
    assert_eq!(
        package
            .validate_output(&fixture.evaluation, &output)
            .err()
            .ok_or("missing evidence accepted")?
            .code(),
        ErrorCode::Incomplete
    );
    for (dataset, row) in [("events", 3), ("wrong", 0)] {
        output.evidence = vec![EvidenceLink {
            input: RowRef {
                dataset: dataset.into(),
                row,
            },
            output: RowRef {
                dataset: "counts".into(),
                row: 0,
            },
        }];
        assert_eq!(
            package
                .validate_output(&fixture.evaluation, &output)
                .err()
                .ok_or("orphan evidence accepted")?
                .code(),
            ErrorCode::Invalid
        );
    }
    Ok(())
}

#[test]
fn checkpoint_version_and_schema() -> TestResult {
    let mut package = FilesCount::package();
    package.exports[0].checkpoint = Some(CheckpointSpec {
        version: 2,
        datasets: vec![Port::new("state", Schema::empty())],
    });
    let mut fixture = FilesCount::fixture()?;
    let state = Checkpoint {
        version: 2,
        datasets: vec![Dataset {
            name: "state".into(),
            batches: vec![],
        }],
    };
    let mut output = FilesCount::evaluate(&fixture.evaluation)?;
    output.checkpoint = Some(state.clone());
    package.validate_output(&fixture.evaluation, &output)?;
    fixture.evaluation.checkpoint = Some(state);
    package.validate_evaluation(&fixture.evaluation)?;
    fixture
        .evaluation
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .version = 1;
    assert_eq!(
        package
            .validate_evaluation(&fixture.evaluation)
            .err()
            .ok_or("wrong version accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    let checkpoint = fixture.evaluation.checkpoint.as_mut().ok_or("checkpoint")?;
    checkpoint.version = 2;
    checkpoint.datasets[0].batches = vec![fixture.evaluation.inputs[0].data.batches[0].clone()];
    assert_eq!(
        package
            .validate_evaluation(&fixture.evaluation)
            .err()
            .ok_or("wrong checkpoint schema accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    fixture.evaluation.checkpoint = None;
    output.checkpoint = None;
    assert!(package
        .validate_output(&fixture.evaluation, &output)
        .is_err());
    Ok(())
}

#[test]
fn reason_namespace_and_details() -> TestResult {
    let mut package = FilesCount::package();
    let details = Schema::new(vec![Field::new("count", DataType::UInt64, false)]);
    package.exports[0].reasons.push(Reason {
        code: "files.REPEATED".into(),
        details: details.clone(),
    });
    let fixture = FilesCount::fixture()?;
    let mut output = FilesCount::evaluate(&fixture.evaluation)?;
    output.reasons.push(ReasonValue {
        output: RowRef {
            dataset: "counts".into(),
            row: 0,
        },
        code: "files.REPEATED".into(),
        details: RecordBatch::try_new(
            Arc::new(details),
            vec![Arc::new(UInt64Array::from(vec![3]))],
        )?,
    });
    package.validate_output(&fixture.evaluation, &output)?;
    output.reasons[0].code = "other.REPEATED".into();
    assert!(package
        .validate_output(&fixture.evaluation, &output)
        .is_err());
    package.exports[0].reasons[0].code = "other.REPEATED".into();
    assert!(package.validate().is_err());
    Ok(())
}

#[test]
fn limits_reject_complete_result() -> TestResult {
    let package = FilesCount::package();
    let mut fixture = FilesCount::fixture()?;
    for limits in [
        Limits {
            max_rows: 2,
            ..Limits::default()
        },
        Limits {
            max_bytes: 1,
            ..Limits::default()
        },
    ] {
        fixture.evaluation.context.limits = limits;
        assert_eq!(
            package
                .validate_evaluation(&fixture.evaluation)
                .err()
                .ok_or("limit accepted")?
                .code(),
            ErrorCode::Limit
        );
    }
    fixture.evaluation.context.limits = Limits {
        max_batches: 1,
        ..Limits::default()
    };
    let duplicate = fixture.evaluation.inputs[0].data.batches[0].clone();
    fixture.evaluation.inputs[0].data.batches.push(duplicate);
    assert_eq!(
        package
            .validate_evaluation(&fixture.evaluation)
            .err()
            .ok_or("batch limit accepted")?
            .code(),
        ErrorCode::Limit
    );
    fixture.evaluation.inputs[0].data.batches.pop();
    fixture.evaluation.context.limits = Limits {
        max_rows: 1_000_001,
        ..Limits::default()
    };
    assert!(package.validate_evaluation(&fixture.evaluation).is_err());
    Ok(())
}

#[test]
fn failure_returns_no_report() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    for code in [
        ErrorCode::Unauthorized,
        ErrorCode::Incomplete,
        ErrorCode::Failed,
    ] {
        assert_eq!(
            package
                .test(&fixture, |_| Err(Error::contract(code, "fixture")))
                .err()
                .ok_or("failure produced report")?
                .code(),
            code
        );
    }
    Ok(())
}

#[test]
fn rejects_descriptor_duplicates() -> TestResult {
    let mut package = FilesCount::package();
    let duplicate = package.exports[0].inputs[0].clone();
    package.exports[0].inputs.push(duplicate);
    assert!(package.validate().is_err());
    let mut package = FilesCount::package();
    package.exports[0].parameters = Schema::new(vec![Field::new(
        "time",
        DataType::Timestamp(TimeUnit::Microsecond, None),
        false,
    )]);
    assert_eq!(
        package
            .validate()
            .err()
            .ok_or("ambiguous timestamp accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    Ok(())
}
