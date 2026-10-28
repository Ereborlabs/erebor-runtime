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
        encoded.decode_bounded(&package, &fixture.evaluation, encoded.allocated_bytes() + output.allocated_bytes()),
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
fn dataset_checks_shape() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let port = &package.exports[0].inputs[0].port;
    let mut data = fixture.evaluation.inputs[0].data.clone();
    data.validate(port)?;
    data.name = "other".into();
    assert_eq!(
        data.validate(port).map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
    data.name = port.name.clone();
    let mut wrong = port.clone();
    wrong.schema = Schema::empty();
    assert_eq!(
        data.validate(&wrong).map_err(|error| error.code()),
        Err(ErrorCode::Incompatible)
    );
    data.batches.push(data.batches[0].clone());
    data.validate(port)?;
    data.batches.clear();
    data.validate(port)?;
    wrong.name = port.name.clone();
    wrong.schema = Schema::new(vec![Field::new("day", DataType::Date32, false)]);
    assert_eq!(
        data.validate(&wrong).map_err(|error| error.code()),
        Err(ErrorCode::Incompatible)
    );
    wrong.name = "invalid name".into();
    data.name = wrong.name.clone();
    wrong.schema = Schema::empty();
    assert_eq!(
        data.validate(&wrong).map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
    Ok(())
}

#[test]
fn dataset_collection_checks_names() -> TestResult {
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
    let datasets = [data, other];
    for (data, port) in datasets.iter().zip(&ports) {
        data.validate(port)?;
    }
    Dataset::validate_all(&datasets, &ports)?;
    assert_eq!(
        Dataset::validate_all(&datasets[..1], &ports).map_err(|error| error.code()),
        Err(ErrorCode::Incomplete)
    );
    assert_eq!(
        Dataset::validate_all(&[datasets[0].clone(), datasets[0].clone()], &ports)
            .map_err(|error| error.code()),
        Err(ErrorCode::Invalid)
    );
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
        resume_input_changes: false,
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
fn metadata_omits_package_quotas() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let mut model = serde_json::to_value(&package.exports[0])?;
    let mut context = serde_json::to_value(&fixture.evaluation.context)?;
    assert!(model.get("limits").is_none());
    assert!(context.get("limits").is_none());
    assert_eq!(context.as_object().ok_or("context object")?.len(), 3);
    model["limits"] = serde_json::json!({"max_rows": 1});
    context["limits"] = serde_json::json!({"max_rows": 1});
    assert!(serde_json::from_value::<Model>(model).is_err());
    assert!(serde_json::from_value::<EvaluationContext>(context).is_err());
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
fn descriptor_has_no_caps() -> TestResult {
    let mut package = Package::new(
        "files",
        "r".repeat(4097),
        (0..65)
            .map(|index| {
                Model::new(
                    format!("export_{index}"),
                    Vec::new(),
                    vec![Port::new("result", Schema::empty())],
                )
            })
            .collect(),
    );
    let model = &mut package.exports[0];
    model.name = "x".repeat(257);
    model.inputs = (0..65)
        .map(|index| Port::new(format!("input_{index}"), Schema::empty()).into())
        .collect();
    model.outputs = (0..65)
        .map(|index| Port::new(format!("output_{index}"), Schema::empty()))
        .collect();
    model.reasons = (0..129)
        .map(|index| Reason {
            code: format!("files.reason_{index}"),
            details: Schema::empty(),
        })
        .collect();
    let mut nested = DataType::UInt64;
    for _ in 0..17 {
        nested = DataType::List(Arc::new(Field::new("item", nested, false)));
    }
    let mut fields = (0..1025)
        .map(|index| Field::new(format!("field_{index}"), DataType::UInt64, false))
        .collect::<Vec<_>>();
    fields.push(Field::new("nested", nested, false));
    fields.push(Field::new(
        "binary",
        DataType::FixedSizeBinary(65537),
        false,
    ));
    fields.push(Field::new(
        "list",
        DataType::FixedSizeList(Arc::new(Field::new("item", DataType::UInt64, false)), 65537),
        false,
    ));
    model.parameters = Schema::new(fields);
    package.validate()?;
    let mut fixture = FilesCount::fixture()?;
    fixture.evaluation.context.id = "x".repeat(4097);
    fixture.evaluation.inputs[0].revision.window = Some(SourceWindow {
        source: vec![1; 4097],
        start_utc_ns: 0,
        end_utc_ns: 1,
    });
    fixture.evaluation.inputs[0].coverage.limits =
        (0..129).map(|index| format!("gap_{index}")).collect();
    FilesCount::package().validate_evaluation(&fixture.evaluation)?;
    Ok(())
}
