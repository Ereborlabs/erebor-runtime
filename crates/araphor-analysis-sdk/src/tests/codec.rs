use super::*;

#[test]
fn wire_contract_boundaries() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let output = FilesCount::evaluate(&fixture.evaluation)?;
    let input = package.check_evaluation(&fixture.evaluation)?.encode()?;
    let encoded = wire::Output::encode(&package, &fixture.evaluation, &output)?;
    assert_eq!(
        serde_json::from_slice::<wire::Output>(&serde_json::to_vec(&encoded)?)?,
        encoded
    );
    assert_eq!(
        serde_json::from_slice::<Vec<wire::Input>>(&serde_json::to_vec(&input.inputs)?)?,
        input.inputs
    );
    let mut metadata = serde_json::to_value(&encoded)?;
    metadata["datasets"][0]["ipc"] = serde_json::json!([]);
    assert!(serde_json::from_value::<wire::Output>(metadata).is_err());
    let mut evaluation = fixture.evaluation.clone();
    evaluation.export = "missing".into();
    evaluation.context.limits.max_bytes = 0;
    let mut header = input.clone();
    header.export_name = evaluation.export.clone();
    header.context.limits = evaluation.context.limits;
    let headers = [
        (
            package.check_evaluation(&evaluation).map(|_| ()),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            package.validate_evaluation(&evaluation),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            package
                .check_evaluation(&evaluation)
                .and_then(|checked| checked.encode())
                .map(|_| ()),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            wire::Output::encode(&package, &evaluation, &output).map(|_| ()),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            header.decode(&package).map(|_| ()),
            ErrorCode::Invalid,
            "limits",
        ),
        (
            encoded.decode(&package, &evaluation).map(|_| ()),
            ErrorCode::Invalid,
            "limits",
        ),
    ];
    let mut invalid = package.clone();
    invalid.contract_version += 1;
    let versions = [
        invalid.check_evaluation(&evaluation).map(|_| ()),
        invalid.validate_evaluation(&evaluation),
        invalid
            .check_evaluation(&evaluation)
            .and_then(|checked| checked.encode())
            .map(|_| ()),
        wire::Output::encode(&invalid, &evaluation, &output).map(|_| ()),
        header.decode(&invalid).map(|_| ()),
        encoded.decode(&invalid, &evaluation).map(|_| ()),
    ]
    .map(|result| (result, ErrorCode::Incompatible, "contract version"));
    evaluation = fixture.evaluation.clone();
    evaluation.inputs.clear();
    let mut missing = input.clone();
    missing.inputs.clear();
    let mut malformed = encoded.clone();
    malformed.datasets[0].arrow_ipc = vec![0];
    let mut uncited = encoded.clone();
    uncited.evidence.clear();
    let inputs = [
        (
            malformed.decode(&package, &evaluation).map(|_| ()),
            ErrorCode::Invalid,
            "arrow framing",
        ),
        (
            encoded.decode(&package, &evaluation).map(|_| ()),
            ErrorCode::Incomplete,
            "missing dataset",
        ),
        (
            wire::Output::encode(&package, &evaluation, &output).map(|_| ()),
            ErrorCode::Incomplete,
            "missing dataset",
        ),
        (
            missing.decode(&package).map(|_| ()),
            ErrorCode::Incomplete,
            "missing dataset",
        ),
        (
            uncited.decode(&package, &fixture.evaluation).map(|_| ()),
            ErrorCode::Incomplete,
            "required output evidence",
        ),
    ];
    let mut changed_input = package.clone();
    changed_input.exports[0].inputs[0].port.schema = Schema::new(vec![
        Field::new("subject", DataType::UInt64, false),
        Field::new("event_id", DataType::UInt64, false),
    ]);
    let mut changed_output = package.clone();
    changed_output.exports[0].outputs[0].schema = Schema::new(vec![
        Field::new("subject", DataType::Utf8, false),
        Field::new("count", DataType::Boolean, false),
    ]);
    changed_input.validate()?;
    changed_output.validate()?;
    let schemas = [
        input.decode(&changed_input).map(|_| ()),
        encoded
            .decode(&changed_output, &fixture.evaluation)
            .map(|_| ()),
    ]
    .map(|result| (result, ErrorCode::Invalid, "dataset schema"));
    for (result, expected, expected_field) in headers
        .into_iter()
        .chain(versions)
        .chain(inputs)
        .chain(schemas)
    {
        let Error::Contract { code, field, .. } =
            result.err().ok_or("invalid contract accepted")?
        else {
            return Err("contract error absent".into());
        };
        assert_eq!(code, expected);
        assert_eq!(field, expected_field);
    }
    let decoded = encoded.decode(&package, &fixture.evaluation)?;
    assert_eq!(decoded.evidence, output.evidence);
    assert_eq!(decoded.datasets[0].batches, output.datasets[0].batches);
    Ok(())
}
