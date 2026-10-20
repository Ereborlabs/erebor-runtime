use super::*;

#[tokio::test]
async fn fixtures_compare_complete_return() -> TestResult {
    let mut model = sdk::Model::new(
        "evaluate",
        vec![sdk::Port::new("input", Fixture::schema())],
        vec![
            sdk::Port::new("data", Fixture::schema()),
            sdk::Port::new("clock", Fixture::schema()),
        ],
    );
    model.parameters = sdk::Schema::new(vec![sdk::Field::new(
        "increment",
        sdk::DataType::UInt64,
        false,
    )]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", Fixture::schema())],
    });
    model.reasons.push(sdk::Reason {
        code: "runtime-fixture.note".into(),
        details: Fixture::schema(),
    });
    let parameters = serde_json::json!({"increment":2});
    let mut evaluation = Fixture::evaluation(&model);
    evaluation.context.time_utc_ns = 2_000;
    evaluation.inputs.push(sdk::Input {
        data: Fixture::data("input", &[3, 7])?,
        revision: sdk::Revision {
            owner: "saved".into(),
            id: "1".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    });
    evaluation.parameters = araphor_data::decode_parameters(&model.parameters, Some(&parameters))?;
    let mut expected = sdk::Output {
        datasets: vec![
            Fixture::data("data", &[5, 9])?,
            Fixture::data("clock", &[2_000])?,
        ],
        evidence: (0..2)
            .map(|row| sdk::EvidenceLink {
                output: sdk::RowRef {
                    dataset: "data".into(),
                    row,
                },
                input: sdk::RowRef {
                    dataset: "input".into(),
                    row,
                },
            })
            .collect(),
        reasons: vec![sdk::ReasonValue {
            output: sdk::RowRef {
                dataset: "data".into(),
                row: 0,
            },
            code: "runtime-fixture.note".into(),
            details: Fixture::data("details", &[5])?.batches.remove(0),
        }],
        checkpoint: Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![Fixture::data("state", &[5, 9])?],
        }),
    };
    let mut bundle = Fixture::bundle("sql", model, SqlModelV1 {
        outputs: BTreeMap::from([
            ("data".into(), "SELECT input.value + parameters.increment AS value FROM input CROSS JOIN parameters ORDER BY input.__row_index".into()),
            ("clock".into(), "SELECT CAST(arrow_cast(CURRENT_TIMESTAMP, 'Int64') AS BIGINT UNSIGNED) AS value".into()),
        ]),
        checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM output_data ORDER BY __row_index".into())]),
        evidence: Some("SELECT 'data' AS output_dataset, __row_index AS output_row, 'input' AS input_dataset, __row_index AS input_row FROM input".into()),
        reasons: vec![araphor_package::SqlReasonV1 { output: "data".into(), code: "runtime-fixture.note".into(), sql: "SELECT __row_index AS output_row, value FROM output_data WHERE __row_index = 0".into() }],
    })?;
    Fixture::save(
        &mut bundle,
        &evaluation,
        &expected,
        Some(parameters.clone()),
    )?;
    evaluation.context.id = "different-reason".into();
    expected.reasons[0].details = Fixture::data("details", &[6])?.batches.remove(0);
    Fixture::save(&mut bundle, &evaluation, &expected, Some(parameters))?;
    let fixture = Fixture::new(&bundle)?;
    assert_eq!(
        fixture.run(&bundle).await?,
        vec![
            FixtureResult {
                fixture: "case".into(),
                passed: true
            },
            FixtureResult {
                fixture: "different-reason".into(),
                passed: false
            }
        ]
    );
    Ok(())
}
