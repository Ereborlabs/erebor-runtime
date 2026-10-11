use super::*;

fn evaluation(model: &sdk::Model, values: Vec<Vec<u64>>) -> sdk::Result<sdk::Evaluation> {
    let batch = |values| {
        sdk::RecordBatch::try_new(
            Arc::new(model.inputs[0].schema.clone()),
            vec![Arc::new(UInt64Array::from(values))],
        )
    };
    Ok(sdk::Evaluation {
        export: model.name.clone(),
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: values.into_iter().map(batch).collect::<Result<_, _>>()?,
            },
            revision: sdk::Revision {
                owner: "sql".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: if model.parameters.fields().is_empty() {
            None
        } else {
            Some(sdk::RecordBatch::try_new(
                Arc::new(model.parameters.clone()),
                vec![
                    Arc::new(StringArray::from(vec!["sum-input"])),
                    Arc::new(UInt64Array::from(vec![0])),
                ],
            )?)
        },
        context: sdk::EvaluationContext {
            id: "sum".into(),
            time_utc_ns: 1,
            seed: None,
            limits: model.limits,
        },
        checkpoint: None,
    })
}

fn run(package: &sdk::Package, evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
    let input = sdk::wire::Evaluation::encode(package, evaluation)?;
    RuntimeFixture::execute(input)?.decode(package, evaluation)
}

#[test]
fn sum_keeps_all_input_batches() -> sdk::Result<()> {
    let package = RuntimeFixture::package();
    let evaluation = evaluation(&package.exports[1], vec![vec![2, 3], vec![], vec![5]])?;
    let output = run(&package, &evaluation)?;
    assert_eq!(
        output.datasets[0].batches[0]
            .column(0)
            .as_primitive::<UInt64Type>()
            .value(0),
        10
    );
    Ok(())
}

#[test]
fn accumulate_receives_previous_versioned_state() -> Result<(), Box<dyn std::error::Error>> {
    let package = RuntimeFixture::package();
    let mut evaluation = evaluation(&package.exports[2], vec![vec![2, 3]])?;
    let initial = run(&package, &evaluation)?;
    evaluation.checkpoint = initial.checkpoint;
    let next = run(&package, &evaluation)?;
    for data in next
        .datasets
        .iter()
        .chain(&next.checkpoint.as_ref().ok_or("checkpoint")?.datasets)
    {
        assert_eq!(
            data.batches[0]
                .column(0)
                .as_primitive::<UInt64Type>()
                .value(0),
            10
        );
    }
    assert_eq!(next.checkpoint.as_ref().ok_or("checkpoint")?.version, 1);
    evaluation.checkpoint.as_mut().ok_or("checkpoint")?.version = 2;
    assert_eq!(
        sdk::wire::Evaluation::encode(&package, &evaluation)
            .err()
            .ok_or("checkpoint version accepted")?
            .code(),
        sdk::ErrorCode::Incompatible
    );
    Ok(())
}

#[test]
fn echo_keeps_context_rows_revision_and_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let port = builtin::Discovery::port::<builtin::ContextSelection>("context");
    let package = sdk::Package::new(
        "context-fixture",
        "1",
        vec![sdk::Model::new(
            "echo-inputs",
            vec![port.clone()],
            vec![port.clone(), RuntimeFixture::metadata_port()],
        )],
    );
    let row = builtin::ContextSelection {
        selector_version: 1,
        from_utc_ns: 1000,
        cutoff_utc_ns: 1999,
        host_packet: "{\"omissions\":{\"EVIDENCE_OUTSIDE_WINDOW_OR_UNDATED\":1}}".into(),
    };
    let evaluation = sdk::Evaluation {
        export: "echo-inputs".into(),
        inputs: vec![sdk::Input {
            data: Rows::encode(&port, std::slice::from_ref(&row), sdk::Limits::default())?,
            revision: sdk::Revision {
                owner: "discovery-context-v1".into(),
                id: "cutoff-1999".into(),
                window: Some(sdk::SourceWindow {
                    source: b"qualified-subject".to_vec(),
                    start_utc_ns: 1000,
                    end_utc_ns: 1999,
                }),
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["EVIDENCE_OUTSIDE_WINDOW_OR_UNDATED".into()],
            },
        }],
        parameters: None,
        context: sdk::EvaluationContext {
            id: "context-echo".into(),
            time_utc_ns: 3000,
            seed: None,
            limits: sdk::Limits::default(),
        },
        checkpoint: None,
    };
    let output = run(&package, &evaluation)?;
    let rows: Vec<builtin::ContextSelection> =
        Rows::decode(&port, &output.datasets[0], sdk::Limits::default())?;
    assert_eq!(serde_json::to_value(&rows[0])?, serde_json::to_value(row)?);
    let metadata = &output.datasets[1].batches[0];
    let revision: sdk::Revision =
        serde_json::from_str(metadata.column(1).as_string::<i32>().value(0))?;
    let coverage: sdk::Coverage =
        serde_json::from_str(metadata.column(2).as_string::<i32>().value(0))?;
    assert_eq!(revision, evaluation.inputs[0].revision);
    assert_eq!(coverage, evaluation.inputs[0].coverage);
    Ok(())
}
