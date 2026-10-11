use super::*;

pub(super) fn record() -> Observation {
    Observation {
        lifetime: vec![2],
        task: 3,
        process: Some([4; 16]),
        execution: vec![5; 16],
        object: vec![6; 16],
        role: Some(1),
        state: Some(1),
        exact_identity: true,
        policy_conflict: false,
        complete: true,
        network: false,
        denied: true,
        admitted: false,
        operation: Operation::Read,
        physical: Physical::Prevented,
        boottime: 10,
    }
}

pub(super) fn fact(record: u64, value: FactValue) -> Fact {
    Fact {
        identity: record,
        record,
        value,
    }
}

pub(super) fn fixture(
    detector: Detector,
    records: &[Observation],
    facts: &[Fact],
) -> sdk::Result<sdk::Fixture> {
    let package = detector.descriptor();
    let model = &package.exports[0];
    let datasets = vec![
        Rows::encode(&model.inputs[0], records, model.limits)?,
        Rows::encode(&model.inputs[1], facts, model.limits)?,
        Rows::encode(
            &model.inputs[2],
            &[Manifest {
                window_ns: 100,
                window_records: 256,
            }],
            model.limits,
        )?,
    ];
    Ok(sdk::Fixture {
        implementation: "shared-rust".into(),
        revision: "graph-v1".into(),
        evaluation: sdk::Evaluation {
            export: "detect".into(),
            inputs: datasets
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
            parameters: None,
            context: sdk::EvaluationContext {
                id: "evaluation".into(),
                time_utc_ns: 1,
                seed: None,
                limits: model.limits,
            },
            checkpoint: None,
        },
    })
}

pub(super) fn findings(
    detector: Detector,
    fixture: &sdk::Fixture,
) -> sdk::Result<(Vec<Finding>, sdk::Output)> {
    let package = detector.descriptor();
    let report = package.test(fixture, |evaluation| detector.evaluate(evaluation))?;
    let rows = Rows::decode(
        &package.exports[0].outputs[2],
        &report.output.datasets[2],
        fixture.evaluation.context.limits,
    )?;
    Ok((rows, report.output))
}
