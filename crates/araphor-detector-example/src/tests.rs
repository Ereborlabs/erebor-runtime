use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn threshold_retains_evidence_and_state() -> TestResult {
    let package = BurstDetector::package();
    let model = &package.exports[0];
    let first = Observation {
        lifetime: vec![1],
        task: 7,
        process: Some([2; 16]),
        execution: vec![3],
        object: vec![4],
        role: None,
        state: None,
        exact_identity: true,
        policy_conflict: false,
        complete: true,
        network: false,
        denied: false,
        admitted: true,
        operation: Operation::Read,
        physical: Physical::Unknown,
        boottime: 10,
    };
    let mut separate = first.clone();
    separate.lifetime = vec![9];
    let inputs = vec![
        Rows::encode(&model.inputs[0].port, &[first.clone(), separate, first])?,
        Rows::encode::<Fact>(&model.inputs[1].port, &[])?,
        Rows::encode(&model.inputs[2].port, &[Manifest { window_ns: 100 }])?,
    ];
    let mut evaluation = sdk::Evaluation {
        previous_outputs: Vec::new(),
        export: "detect".into(),
        inputs: inputs
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        parameters: Some(sdk::RecordBatch::try_new(
            Arc::new(model.parameters.clone()),
            vec![Arc::new(UInt64Array::from(vec![2]))],
        )?),
        context: sdk::EvaluationContext {
            id: "example".into(),
            time_utc_ns: 10,
            seed: Some(3),
        },
        checkpoint: None,
    };
    let output = BurstDetector::evaluate(&evaluation)?;
    let checked = package.check_evaluation(&evaluation)?;
    let supplied = <BurstDetector as sdk::Guest>::compute(&checked)?;
    checked.validate_output(&supplied)?;
    assert_eq!(supplied.evidence, output.evidence);
    for (actual, expected) in supplied.datasets.iter().zip(&output.datasets) {
        assert_eq!(actual.batches, expected.batches);
    }
    let mut other = package.clone();
    other.revision = "other".into();
    let other = other.check_evaluation(&evaluation)?;
    assert!(matches!(<BurstDetector as sdk::Guest>::compute(&other),
        Err(sdk::Error::Contract { code: sdk::ErrorCode::Incompatible, field, .. }) if field == "detector package"));
    let findings: Vec<Finding> = Rows::decode(&model.outputs[2], &output.datasets[2])?;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence, vec![0, 2]);
    assert!(!findings[0].confirmed);
    assert_eq!(output.evidence.len(), 2);
    assert_eq!(output.reasons[0].code, "example-burst.THRESHOLD");
    assert_eq!(
        output.reasons[0]
            .details
            .column(1)
            .as_primitive::<UInt64Type>()
            .value(0),
        2
    );
    let encoded = sdk::wire::Output::encode(&package, &evaluation, &output)?;
    let decoded = encoded.decode(&package, &evaluation)?;
    evaluation.checkpoint = decoded.checkpoint;
    assert_eq!(
        BurstDetector::evaluate(&evaluation)?.evidence,
        output.evidence
    );
    evaluation.parameters = Some(sdk::RecordBatch::try_new(
        Arc::new(model.parameters.clone()),
        vec![Arc::new(UInt64Array::from(vec![1]))],
    )?);
    assert_eq!(
        BurstDetector::evaluate(&evaluation)
            .err()
            .ok_or("invalid threshold accepted")?
            .code(),
        sdk::ErrorCode::Invalid
    );
    Ok(())
}
