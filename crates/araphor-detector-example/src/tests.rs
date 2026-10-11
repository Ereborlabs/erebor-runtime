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
        Rows::encode(
            &model.inputs[0],
            &[first.clone(), separate, first],
            model.limits,
        )?,
        Rows::encode::<Fact>(&model.inputs[1], &[], model.limits)?,
        Rows::encode(
            &model.inputs[2],
            &[Manifest {
                window_ns: 100,
                window_records: 3,
            }],
            model.limits,
        )?,
    ];
    let mut evaluation = sdk::Evaluation {
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
            limits: model.limits,
        },
        checkpoint: None,
    };
    let output = BurstDetector::evaluate(&evaluation)?;
    let findings: Vec<Finding> =
        Rows::decode(&model.outputs[2], &output.datasets[2], model.limits)?;
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
