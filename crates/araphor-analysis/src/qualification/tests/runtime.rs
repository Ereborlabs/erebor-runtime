use super::*;

#[tokio::test]
async fn input_precedes_compilation() -> TestResult {
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let parameters = serde_json::json!({"mode": "x".repeat(4096), "amount": 7});
    let mut evaluation = Fixture::evaluation(&model);
    evaluation.parameters = araphor_data::decode_parameters(&model.parameters, Some(&parameters))?;
    let expected = sdk::Output {
        datasets: vec![Fixture::data("data", &[7])?],
        ..Default::default()
    };
    let mut bundle = Fixture::bundle("wasm", model, SqlModelV1::default())?;
    Fixture::save(&mut bundle, &evaluation, &expected, Some(parameters))?;
    let PackageImplementationV1::Wasm { artifact, .. } =
        &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("Wasm fixture absent".into());
    };
    *artifact = b"invalid component".to_vec();
    let fixture = Fixture::limits(
        &bundle,
        araphor_query::execution::Limits {
            input_bytes: 1024,
            ..Default::default()
        },
    )?;
    let before = fixture.owner.query.store().meta()?.commit_revision;
    let error = fixture
        .run(&bundle)
        .await
        .err()
        .ok_or("invalid input executed")?;
    assert!(matches!(
        error,
        crate::Error::Query { source }
            if araphor_query::Failure::from(&source)
                == araphor_query::Failure::InputTooLarge
    ));
    assert_eq!(fixture.owner.query.store().meta()?.commit_revision, before);
    Ok(())
}

#[tokio::test]
async fn fixtures_execute_sql_wasm() -> TestResult {
    for target in ["sql", "wasm"] {
        accumulate(target).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_fixture_accumulates() -> TestResult {
    accumulate("native").await
}

#[tokio::test]
async fn fixtures_keep_clock_seed() -> TestResult {
    clock_seed("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_fixture_clock_seed() -> TestResult {
    clock_seed("native").await
}

async fn accumulate(target: &str) -> TestResult {
    let mut model = sdk::Model::new(
        "accumulate",
        vec![sdk::Port::new("input", Fixture::schema())],
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", Fixture::schema())],
    });
    let mut evaluation = Fixture::evaluation(&model);
    let mut data = Fixture::data("input", &[3])?;
    data.batches.extend(Fixture::data("input", &[7])?.batches);
    evaluation.inputs.push(sdk::Input {
        data,
        revision: sdk::Revision {
            owner: "saved-source".into(),
            id: "immutable-cut".into(),
            window: Some(sdk::SourceWindow {
                source: vec![5],
                start_utc_ns: 0,
                end_utc_ns: 2_000,
            }),
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Gapped,
            limits: vec!["SAVED_GAP".into()],
        },
    });
    evaluation.checkpoint = Some(sdk::Checkpoint {
        version: 1,
        datasets: vec![Fixture::data("state", &[100])?],
    });
    let expected = sdk::Output {
        datasets: vec![Fixture::data("data", &[110])?],
        checkpoint: Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![Fixture::data("state", &[110])?],
        }),
        ..Default::default()
    };
    let sql = SqlModelV1 {
        outputs: BTreeMap::from([("data".into(), "SELECT CAST((SELECT SUM(value) FROM input) + (SELECT SUM(value) FROM prior_state) AS BIGINT UNSIGNED) AS value".into())]),
        checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM output_data".into())]),
        ..Default::default()
    };
    let mut bundle = Fixture::bundle(target, model, sql)?;
    Fixture::save(&mut bundle, &evaluation, &expected, None)?;
    let fixture = Fixture::new(&bundle)?;
    let revision = fixture.owner.query.store().meta()?.commit_revision;
    assert_eq!(
        fixture.run(&bundle).await?,
        vec![FixtureResult {
            fixture: "case".into(),
            passed: true
        }],
        "{target}"
    );
    assert_eq!(
        fixture.owner.query.store().meta()?.commit_revision,
        revision,
        "{target}"
    );
    Ok(())
}

async fn clock_seed(target: &str) -> TestResult {
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let mut bundle = Fixture::bundle(target, model.clone(), SqlModelV1::default())?;
    for (mode, time, value) in [
        ("clock", 0, 0),
        ("clock", 2_000, 2_000),
        ("seed", 0, u64::MAX),
    ] {
        let mut evaluation = Fixture::evaluation(&model);
        evaluation.context.id = format!("{mode}-{time}");
        evaluation.context.time_utc_ns = time;
        let parameters = serde_json::json!({"mode":mode,"amount":0});
        evaluation.parameters =
            araphor_data::decode_parameters(&model.parameters, Some(&parameters))?;
        let expected = sdk::Output {
            datasets: vec![Fixture::data("data", &[value])?],
            ..Default::default()
        };
        Fixture::save(&mut bundle, &evaluation, &expected, Some(parameters))?;
    }
    let fixture = Fixture::new(&bundle)?;
    assert!(
        fixture
            .run(&bundle)
            .await?
            .iter()
            .all(|result| result.passed),
        "{target}"
    );
    Ok(())
}

#[tokio::test]
async fn fixtures_keep_input_provenance() -> TestResult {
    let target = "wasm";
    {
        let port = sdk::Port::new("input", Fixture::schema());
        let metadata = sdk::Port::new(
            "metadata",
            sdk::Schema::new(vec![
                sdk::Field::new("dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("revision", sdk::DataType::Utf8, false),
                sdk::Field::new("coverage", sdk::DataType::Utf8, false),
            ]),
        );
        let model = sdk::Model::new(
            "echo-inputs",
            vec![port.clone()],
            vec![port, metadata.clone()],
        );
        let mut evaluation = Fixture::evaluation(&model);
        evaluation.inputs.push(sdk::Input {
            data: Fixture::data("input", &[3, 7])?,
            revision: sdk::Revision {
                owner: "retained-source".into(),
                id: "saved-revision".into(),
                window: Some(sdk::SourceWindow {
                    source: vec![7],
                    start_utc_ns: 1,
                    end_utc_ns: 5,
                }),
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["SAVED_GAP".into()],
            },
        });
        let input = &evaluation.inputs[0];
        let expected = sdk::Output {
            datasets: vec![
                input.data.clone(),
                sdk::Dataset {
                    name: "metadata".into(),
                    batches: vec![sdk::RecordBatch::try_new(
                        Arc::new(metadata.schema),
                        vec![
                            Arc::new(StringArray::from(vec!["input"])),
                            Arc::new(StringArray::from(vec![serde_json::to_string(
                                &input.revision,
                            )?])),
                            Arc::new(StringArray::from(vec![serde_json::to_string(
                                &input.coverage,
                            )?])),
                        ],
                    )?],
                },
            ],
            ..Default::default()
        };
        let mut bundle = Fixture::bundle(target, model, SqlModelV1::default())?;
        Fixture::save(&mut bundle, &evaluation, &expected, None)?;
        let fixture = Fixture::new(&bundle)?;
        assert!(
            fixture
                .run(&bundle)
                .await?
                .iter()
                .all(|result| result.passed),
            "{target}"
        );
    }
    Ok(())
}
