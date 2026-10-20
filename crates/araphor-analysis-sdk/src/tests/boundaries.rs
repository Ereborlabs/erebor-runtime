use super::*;

#[test]
fn checked_output_keeps_contract() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let checked = package.check_evaluation(&fixture.evaluation)?;
    assert!(std::ptr::eq(checked.package(), &package));
    assert!(std::ptr::eq(checked.evaluation(), &fixture.evaluation));
    assert!(std::ptr::eq(checked.model(), &package.exports[0]));
    let mut output = FilesCount::evaluate(checked.evaluation())?;
    checked.validate_output(&output)?;
    let mut encoded = crate::wire::Output::encode(&package, &fixture.evaluation, &output)?;
    encoded.evidence.clear();
    assert!(matches!(
        encoded.decode_bounded(&package, &fixture.evaluation, Limits::default()),
        Err(Error::Contract { code: ErrorCode::Incomplete, field, .. })
            if field == "required output evidence"
    ));
    output.evidence.clear();
    assert!(
        matches!(checked.validate_output(&output), Err(Error::Contract {
        code: ErrorCode::Incomplete, field, ..
    }) if field == "required output evidence")
    );
    let mut invalid = fixture.evaluation.clone();
    invalid.inputs.clear();
    assert!(
        matches!(package.check_evaluation(&invalid), Err(Error::Contract {
        code: ErrorCode::Incomplete, field, ..
    }) if field == "missing dataset")
    );
    Ok(())
}

#[test]
fn dataset_checks_shape_and_limits() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let port = &package.exports[0].inputs[0].port;
    let mut data = fixture.evaluation.inputs[0].data.clone();
    let limits = package.exports[0].limits;
    data.validate(port, limits)?;
    data.name = "other".into();
    assert_eq!(
        data.validate(port, limits).map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
    data.name = port.name.clone();
    let mut wrong = port.clone();
    wrong.schema = Schema::empty();
    assert_eq!(
        data.validate(&wrong, limits).map_err(|error| error.code()),
        Err(ErrorCode::Incompatible)
    );
    data.batches.push(data.batches[0].clone());
    for limits in [
        Limits {
            max_rows: 5,
            ..limits
        },
        Limits {
            max_bytes: 1,
            ..limits
        },
        Limits {
            max_batches: 1,
            ..limits
        },
    ] {
        assert_eq!(
            data.validate(port, limits).map_err(|error| error.code()),
            Err(ErrorCode::Limit)
        );
    }
    data.batches.clear();
    data.validate(port, limits)?;
    assert_eq!(
        data.validate(
            port,
            Limits {
                max_rows: 0,
                ..limits
            }
        )
        .map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
    wrong.name = port.name.clone();
    wrong.schema = Schema::new(vec![Field::new("day", DataType::Date32, false)]);
    assert_eq!(
        data.validate(&wrong, limits).map_err(|error| error.code()),
        Err(ErrorCode::Incompatible)
    );
    wrong.name = "invalid name".into();
    data.name = wrong.name.clone();
    wrong.schema = Schema::empty();
    assert_eq!(
        data.validate(&wrong, limits).map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
    Ok(())
}

#[test]
fn dataset_collection_keeps_bounds() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let port = package.exports[0].inputs[0].port.clone();
    let data = fixture.evaluation.inputs[0].data.clone();
    let mut other = data.clone();
    other.name = "other".into();
    let ports = [
        port,
        Port::new(&other.name, data.batches[0].schema().as_ref().clone()),
    ];
    let bytes = data.batches[0].get_array_memory_size() as u64
        + data.name.len().max(other.name.len()) as u64;
    let datasets = [data, other];
    for limits in [
        Limits {
            max_rows: 5,
            ..Limits::default()
        },
        Limits {
            max_batches: 1,
            ..Limits::default()
        },
        Limits {
            max_bytes: bytes,
            ..Limits::default()
        },
    ] {
        for (data, port) in datasets.iter().zip(&ports) {
            data.validate(port, limits)?;
        }
        assert_eq!(
            Dataset::validate_all(&datasets, &ports, limits).map_err(|error| error.code()),
            Err(ErrorCode::Limit)
        );
    }
    Ok(())
}

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
    let mut package = FilesCount::package();
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
    package.exports[0].limits.max_rows = 1_000_000;
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

#[test]
fn limits_default_disabled() -> TestResult {
    let limits = Limits::default();
    assert_eq!(limits.max_batches, u32::MAX);
    assert_eq!(limits.max_rows, u64::MAX);
    assert_eq!(limits.max_bytes, u64::MAX);
    assert_eq!(limits.max_checkpoint_bytes, u64::MAX);
    let restored: Limits = serde_json::from_slice(&serde_json::to_vec(&limits)?)?;
    assert_eq!(restored, limits);
    Ok(())
}
