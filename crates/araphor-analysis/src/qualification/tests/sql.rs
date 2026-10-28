use super::*;

#[tokio::test]
async fn fixtures_use_previous_outputs() -> TestResult {
    let mut model = sdk::Model::new(
        "evaluate",
        vec![sdk::Port::new("input", Fixture::schema())],
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    model.checkpoint = Some(sdk::CheckpointSpec {
        resume_input_changes: true,
        version: 1,
        datasets: vec![sdk::Port::new("state", Fixture::schema())],
    });
    let mut evaluation = Fixture::evaluation(&model);
    evaluation.inputs.push(sdk::Input {
        data: Fixture::data("input", &[3])?,
        revision: sdk::Revision {
            owner: "saved-source".into(),
            id: "current".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    });
    evaluation.checkpoint = Some(sdk::Checkpoint {
        version: 1,
        datasets: vec![Fixture::data("state", &[100])?],
    });
    let expected = sdk::Output {
        datasets: vec![Fixture::data("data", &[5])?],
        checkpoint: Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![Fixture::data("state", &[5])?],
        }),
        ..Default::default()
    };
    let mut bundle = Fixture::bundle(
        "sql",
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "data".into(),
                "SELECT CAST((SELECT SUM(value) FROM input) + \
                    (SELECT SUM(value) FROM previous_data) AS BIGINT UNSIGNED) AS value"
                    .into(),
            )]),
            checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM output_data".into())]),
            ..Default::default()
        },
    )?;
    for (name, value) in [("matching", 2), ("different", 4)] {
        evaluation.context.id = name.into();
        evaluation.previous_outputs = vec![Fixture::data("data", &[value])?];
        Fixture::save(&mut bundle, &evaluation, &expected, None)?;
        let saved = bundle.artifacts[0].fixtures.last().ok_or("saved fixture")?;
        let data = saved.previous_outputs[0].decode(&Fixture::schema())?;
        assert_eq!(data.batches, evaluation.previous_outputs[0].batches);
    }
    let fixture = Fixture::new(&bundle)?;
    let before = fixture.owner.query.store().meta()?;
    assert_eq!(
        fixture.run(&bundle).await?,
        vec![
            FixtureResult {
                fixture: "matching".into(),
                passed: true,
            },
            FixtureResult {
                fixture: "different".into(),
                passed: false,
            },
        ]
    );
    assert_eq!(fixture.owner.query.store().meta()?, before);
    Ok(())
}

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
        resume_input_changes: false,
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

#[tokio::test]
async fn fixtures_repeat_saved_clock() -> TestResult {
    let model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    let mut bundle = Fixture::bundle(
        "sql",
        model.clone(),
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "data".into(),
                "SELECT CAST(CASE WHEN CURRENT_TIMESTAMP = TIMESTAMP '2000-01-01 00:00:00' THEN 1 ELSE 0 END AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    )?;
    for (name, now, value) in [
        ("matching", 946684800000000000, 1),
        ("later", 946684801000000000, 0),
        ("before-epoch", -1, 0),
    ] {
        let mut evaluation = Fixture::evaluation(&model);
        evaluation.context.id = name.into();
        evaluation.context.time_utc_ns = now;
        Fixture::save(
            &mut bundle,
            &evaluation,
            &sdk::Output {
                datasets: vec![Fixture::data("data", &[value])?],
                ..Default::default()
            },
            None,
        )?;
    }
    let fixture = Fixture::new(&bundle)?;
    for _ in 0..2 {
        let results = fixture.run(&bundle).await?;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| result.passed));
    }
    Ok(())
}

#[tokio::test]
async fn fixtures_keep_signed_clock() -> TestResult {
    use sdk::arrow_array::Int64Array;
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Int64, false)]);
    let model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", schema.clone())],
    );
    let mut bundle = Fixture::bundle(
        "sql",
        model.clone(),
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "data".into(),
                "SELECT arrow_cast(CURRENT_TIMESTAMP, 'Int64') AS value".into(),
            )]),
            ..Default::default()
        },
    )?;
    for now in [i64::MIN, -1000, -1, 0, i64::MAX] {
        let mut evaluation = Fixture::evaluation(&model);
        evaluation.context.id = format!("clock-{now}");
        evaluation.context.time_utc_ns = now;
        let data = sdk::Dataset {
            name: "data".into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(schema.clone()),
                vec![Arc::new(Int64Array::from(vec![now]))],
            )?],
        };
        Fixture::save(
            &mut bundle,
            &evaluation,
            &sdk::Output {
                datasets: vec![data],
                ..Default::default()
            },
            None,
        )?;
    }
    let fixture = Fixture::new(&bundle)?;
    let before = fixture.owner.query.store().meta()?;
    let results = fixture.run(&bundle).await?;
    assert_eq!(results.len(), 5);
    assert!(results.iter().all(|result| result.passed));
    assert_eq!(fixture.owner.query.store().meta()?, before);
    Ok(())
}
