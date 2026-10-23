use std::sync::mpsc;

use sdk::arrow_array::StringArray;

use super::*;

#[tokio::test]
async fn supplied_sql_keeps_shapes() -> TestResult {
    let mut image = Fixture::bundle();
    image.artifacts[0].descriptor.exports = vec![sdk::Model::new(
        "count",
        vec![sdk::Port::new("source", Fixture::schema("value"))],
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    )];
    image.artifacts[0].implementations = vec![PackageImplementationV1::Sql {
        export: "count".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(COALESCE(SUM(value), 0) AS BIGINT UNSIGNED) AS value FROM source"
                    .into(),
            )]),
            ..Default::default()
        },
    }];
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let before = fixture.engine.store().meta()?;
    for (index, (chunks, expected)) in [
        (vec![vec![2, 3], vec![5]], 10),
        (vec![vec![11]], 11),
        (Vec::new(), 0),
        (vec![Vec::new()], 0),
    ]
    .into_iter()
    .enumerate()
    {
        let schema = Arc::new(Fixture::schema("value"));
        let batches = chunks
            .iter()
            .map(|rows| {
                sdk::RecordBatch::try_new(
                    Arc::clone(&schema),
                    vec![Arc::new(UInt64Array::from(rows.clone()))],
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let control = AnalysisReadControl::default();
        let mut session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
        session.register("supplied_rows", schema, &batches)?;
        let prepared = session.prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM supplied_rows))"#,
        )).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.package(), &image.root);
        assert_eq!(call.export(), "count");
        assert_eq!(call.output(), "result");
        assert_eq!(call.descriptor(), &image.artifacts[0].descriptor);
        let id = call.id();
        let input = sdk::Input {
            data: sdk::Dataset {
                name: "source".into(),
                batches,
            },
            revision: sdk::Revision {
                owner: "external-local".into(),
                id: format!("chunks-{index}"),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        };
        let mut request = invocation(&format!("supplied-shape-{index}"));
        request.inputs.insert(id, vec![input.clone()]);
        let output = session.execute_definition(&prepared, request).await?;
        assert_eq!(values(&output.batches)?, [expected]);
        assert_eq!(output.calls.len(), 1);
        let returned = output.calls.get(&id).ok_or("supplied SQL return")?;
        assert!(returned.belongs_to(call));
        assert_eq!(values(&returned.output().datasets[0].batches)?, [expected]);
        assert_eq!(returned.output().datasets[0].name, "result");
        assert_eq!(returned.evaluation().inputs.len(), 1);
        let captured = &returned.evaluation().inputs[0];
        assert_eq!(captured.data.name, input.data.name);
        assert_eq!(values(&captured.data.batches)?, chunks.concat());
        assert_eq!(captured.revision, input.revision);
        assert_eq!(captured.coverage, input.coverage);
        assert!(output.snapshot.witnesses.is_empty());
        assert!(output.snapshot.page.extraction.sources.is_empty());
        assert_eq!(fixture.engine.store().meta()?, before);
    }
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn supplied_inputs_reject_shape() -> TestResult {
    let image = component("wasm", "count-input")?;

    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let control = AnalysisReadControl::default();
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let schema = Arc::new(Fixture::schema("value"));
    let batch = sdk::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(UInt64Array::from(vec![7]))],
    )?;
    session.register("supplied_rows", schema, std::slice::from_ref(&batch))?;
    let prepared = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
            input => (SELECT value FROM supplied_rows), mode => 'sum-input', amount => 0)"#,
        ))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    let id = calls[0].id();
    let input = sdk::Input {
        data: sdk::Dataset {
            name: "input".into(),
            batches: vec![batch],
        },
        revision: sdk::Revision {
            owner: "external-local".into(),
            id: "provided".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    };
    let mut wrong = input.clone();
    wrong.data.batches = vec![sdk::RecordBatch::try_new(
        Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::Utf8,
            false,
        )])),
        vec![Arc::new(StringArray::from(vec!["seven"]))],
    )?];
    let mut extra = input.clone();
    extra.data.name = "undeclared".into();
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let before = fixture.engine.store().meta()?;
    let held = fixture.engine.memory().input_reserved();
    for (index, supplied) in [vec![wrong], Vec::new(), vec![input.clone(), extra]]
        .into_iter()
        .enumerate()
    {
        let mut request = invocation(&format!("bad-supplied-{index}"));
        request.inputs.insert(id, supplied);
        let error = session
            .execute_definition(&prepared, request)
            .await
            .err()
            .ok_or("malformed supplied SDK input accepted")?;
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::InvalidQuery,
            "{error:?}"
        );
        assert!(matches!(
            observed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(fixture.engine.store().meta()?, before);
        assert_eq!(fixture.engine.memory().input_reserved(), held);
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        drop(
            fixture.engine.memory().reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .ok_or("output capacity")?,
            )?,
        );
    }
    let mut request = invocation("valid-supplied");
    request.inputs.insert(id, vec![input.clone()]);
    let output = session.execute_definition(&prepared, request).await?;
    assert_eq!(values(&output.batches)?, [7]);
    assert_eq!(output.calls.len(), 1);
    let returned = output.calls.get(&id).ok_or("valid supplied return")?;
    assert!(returned.belongs_to(&calls[0]));
    assert_eq!(returned.evaluation().inputs[0].data.name, input.data.name);
    assert_eq!(
        returned.evaluation().inputs[0].data.batches,
        input.data.batches
    );
    assert_eq!(returned.evaluation().inputs[0].revision, input.revision);
    assert_eq!(returned.evaluation().inputs[0].coverage, input.coverage);
    // The runtime takes this sender when evaluation starts.
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert!(output.snapshot.witnesses.is_empty());
    assert!(output.snapshot.page.extraction.sources.is_empty());
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((output, prepared, calls, session, input));
    capacity_released(&fixture)?;
    Ok(())
}
