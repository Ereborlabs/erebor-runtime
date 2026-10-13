use super::*;

#[test]
fn wire_validation_keeps_precedence() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let output = FilesCount::evaluate(&fixture.evaluation)?;
    let mut input = wire::Evaluation::encode(&package, &fixture.evaluation)?;
    let encoded = wire::Output::encode(&package, &fixture.evaluation, &output)?;
    let mut evaluation = fixture.evaluation;
    evaluation.export = "missing".into();
    evaluation.context.limits.max_bytes = 0;
    input.export_name = evaluation.export.clone();
    input.context.limits = evaluation.context.limits;
    for (result, expected, expected_field) in [
        (
            package.validate_evaluation(&evaluation),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            wire::Evaluation::encode(&package, &evaluation).map(|_| ()),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            wire::Output::encode(&package, &evaluation, &output).map(|_| ()),
            ErrorCode::Incompatible,
            "export",
        ),
        (
            input.decode(&package).map(|_| ()),
            ErrorCode::Invalid,
            "limits",
        ),
        (
            encoded.decode(&package, &evaluation).map(|_| ()),
            ErrorCode::Invalid,
            "limits",
        ),
    ] {
        let Error::Contract { code, field, .. } = result.err().ok_or("invalid header accepted")?
        else {
            return Err("contract error absent".into());
        };
        assert_eq!(code, expected);
        assert_eq!(field, expected_field);
    }
    let mut invalid = package;
    invalid.contract_version += 1;
    for result in [
        invalid.validate_evaluation(&evaluation),
        wire::Evaluation::encode(&invalid, &evaluation).map(|_| ()),
        wire::Output::encode(&invalid, &evaluation, &output).map(|_| ()),
        input.decode(&invalid).map(|_| ()),
        encoded.decode(&invalid, &evaluation).map(|_| ()),
    ] {
        let Error::Contract { code, field, .. } = result.err().ok_or("invalid package accepted")?
        else {
            return Err("contract error absent".into());
        };
        assert_eq!(code, ErrorCode::Incompatible);
        assert_eq!(field, "contract version");
    }
    Ok(())
}

#[test]
fn wire_checks_decoded_inputs() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let output = FilesCount::evaluate(&fixture.evaluation)?;
    let mut input = wire::Evaluation::encode(&package, &fixture.evaluation)?;
    let encoded = wire::Output::encode(&package, &fixture.evaluation, &output)?;
    let mut evaluation = fixture.evaluation.clone();
    evaluation.inputs.clear();
    input.inputs.clear();
    let mut malformed = encoded.clone();
    malformed.datasets[0].arrow_ipc = vec![0];
    let mut uncited = encoded.clone();
    uncited.evidence.clear();
    for (result, expected, expected_field) in [
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
            input.decode(&package).map(|_| ()),
            ErrorCode::Incomplete,
            "missing dataset",
        ),
        (
            uncited.decode(&package, &fixture.evaluation).map(|_| ()),
            ErrorCode::Incomplete,
            "required output evidence",
        ),
    ] {
        let Error::Contract { code, field, .. } = result.err().ok_or("invalid wire accepted")?
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

#[test]
fn wire_rejects_changed_packages() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let output = FilesCount::evaluate(&fixture.evaluation)?;
    let input = wire::Evaluation::encode(&package, &fixture.evaluation)?;
    let encoded = wire::Output::encode(&package, &fixture.evaluation, &output)?;
    let mut changed_input = package.clone();
    changed_input.exports[0].inputs[0].schema = Schema::new(vec![
        Field::new("subject", DataType::UInt64, false),
        Field::new("event_id", DataType::UInt64, false),
    ]);
    let mut changed_output = package;
    changed_output.exports[0].outputs[0].schema = Schema::new(vec![
        Field::new("subject", DataType::Utf8, false),
        Field::new("count", DataType::Boolean, false),
    ]);
    changed_input.validate()?;
    changed_output.validate()?;
    for result in [
        input.decode(&changed_input).map(|_| ()),
        encoded
            .decode(&changed_output, &fixture.evaluation)
            .map(|_| ()),
    ] {
        let Error::Contract { code, field, .. } = result.err().ok_or("changed schema accepted")?
        else {
            return Err("contract error absent".into());
        };
        assert_eq!(code, ErrorCode::Invalid);
        assert_eq!(field, "dataset schema");
    }
    Ok(())
}
