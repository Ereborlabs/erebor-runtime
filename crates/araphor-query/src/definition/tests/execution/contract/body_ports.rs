use super::*;

fn body_image(source: &str, elided: bool) -> PackageBundleV1 {
    let mut inner = sdk::Model::new(
        "inner",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    inner.input_mode = sdk::InputMode::Resolved;
    inner.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("selected", Fixture::schema("value")),
        source: sdk::InputSource::Table(sdk::TableRef::Named("selected".into())),
    }];
    let mut image = bundle(
        inner,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM selected".into())]),
            ..Default::default()
        },
    );
    let mut outer = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    outer.input_mode = sdk::InputMode::Resolved;
    outer.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("root_rows", Fixture::schema("value")),
        source: sdk::InputSource::Query(source.into()),
    }];
    image.artifacts[0].descriptor.exports.push(outer);
    image.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    format!(
                        r#"SELECT value FROM "fixture"."r1"."inner"(selected => ({}))"#,
                        if elided {
                            "WITH unused AS (SELECT value FROM root_rows) SELECT CAST(7 AS BIGINT UNSIGNED) AS value"
                        } else {
                            "SELECT value FROM root_rows WHERE value = 1"
                        }
                    ),
                )]),
                ..Default::default()
            },
        });
    for model in &mut image.artifacts[0].descriptor.exports {
        model.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: false,
            version: 1,
            datasets: vec![sdk::Port::new("state", Fixture::schema("value"))],
        });
    }
    for implementation in &mut image.artifacts[0].implementations {
        let PackageImplementationV1::Sql { program, .. } = implementation else {
            unreachable!("SQL body fixture")
        };
        program
            .checkpoint
            .insert("state".into(), "SELECT value FROM output_result".into());
    }
    image
}

fn body_states(output: &DefinitionOutput, expected: u64) -> TestResult {
    assert_eq!(values(&output.batches)?, [expected]);
    assert_eq!(output.calls.len(), 2);
    for call in output.calls.values() {
        assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
        assert_eq!(call.evaluation().context.seed, Some(7));
        let state = call.output().checkpoint.as_ref().ok_or("body state")?;
        assert_eq!(state.version, 1);
        assert_eq!(state.datasets.len(), 1);
        assert_eq!(state.datasets[0].name, "state");
        assert_eq!(values(&state.datasets[0].batches)?, [expected]);
    }
    Ok(())
}

#[tokio::test]
async fn body_port_metadata() -> TestResult {
    let image = body_image("SELECT value FROM local_rows", false);
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let control = AnalysisReadControl::default();
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let schema = Arc::new(Fixture::schema("value"));
    let rows = sdk::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(UInt64Array::from(vec![1, 2]))],
    )?;
    session.register("local_rows", schema, &[rows])?;
    let prepared = session
        .prepare_definition(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    let inner = calls
        .iter()
        .find(|call| call.export() == "inner")
        .ok_or("inner body")?;
    let outer = calls
        .iter()
        .find(|call| call.export() == "count")
        .ok_or("outer body")?;
    let (inner_id, outer_id) = (inner.id(), outer.id());
    assert_ne!(inner_id, outer_id);
    assert!(PackageCall::any(&outer.children[1], &mut |call| Ok(call
        .id()
        == inner_id))?);
    drop(calls);
    let meta = fixture.engine.store().meta()?;
    let initial = session
        .execute_definition(&prepared, invocation("body-initial"))
        .await?;
    body_states(&initial, 1)?;
    let mut supplied = initial.calls[&outer_id].evaluation().inputs.clone();
    assert_eq!(supplied.len(), 1);
    assert_eq!(supplied[0].data.name, "root_rows");
    assert_eq!(values(&supplied[0].data.batches)?, [1, 2]);
    supplied[0].coverage = sdk::Coverage {
        state: sdk::CoverageState::Gapped,
        limits: vec!["LOCAL_METADATA".into()],
    };
    drop(initial);
    let mut previous = None;
    for id in ["first", "second"] {
        supplied[0].revision = sdk::Revision {
            owner: "external-local".into(),
            id: id.into(),
            window: Some(sdk::SourceWindow {
                source: vec![9],
                start_utc_ns: 1,
                end_utc_ns: 2,
            }),
        };
        let mut request = invocation("body-supplied");
        request.inputs.insert(outer_id, supplied.clone());
        let output = session.execute_definition(&prepared, request).await?;
        body_states(&output, 1)?;
        let parent = &output.calls[&outer_id].evaluation().inputs[0];
        assert_eq!(parent.data.name, supplied[0].data.name);
        assert_eq!(parent.data.batches, supplied[0].data.batches);
        assert_eq!(parent.revision, supplied[0].revision);
        assert_eq!(parent.coverage, supplied[0].coverage);
        let child = &output.calls[&inner_id].evaluation().inputs[0];
        assert_eq!(child.data.name, "selected");
        assert_eq!(values(&child.data.batches)?, [1]);
        assert_eq!(child.coverage, supplied[0].coverage);
        assert_eq!(child.revision.owner, "araphor-query.Inputs");
        if let Some(previous) = previous {
            assert_ne!(child.revision, previous);
        }
        previous = Some(child.revision.clone());
        assert!(output.snapshot.witnesses.is_empty());
        assert!(output.snapshot.page.extraction.sources.is_empty());
        assert_eq!(fixture.engine.store().meta()?, meta);
    }
    drop(supplied);
    drop(prepared);
    drop(session);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn body_elided_metadata() -> TestResult {
    for elided in [false, true] {
        let image = body_image("SELECT source_cursor AS value FROM events", elided);
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        fixture.event(1)?;
        fixture.event(2)?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 2);
        let inner = calls
            .iter()
            .find(|call| call.export() == "inner")
            .ok_or("inner body")?;
        let outer = calls
            .iter()
            .find(|call| call.export() == "count")
            .ok_or("outer body")?;
        let (inner_id, outer_id) = (inner.id(), outer.id());
        assert!(PackageCall::any(&outer.children[1], &mut |call| Ok(call
            .id()
            == inner_id))?);
        drop(calls);
        let mut previous = None;
        for cursor in [2, 3] {
            if cursor == 3 {
                fixture.event(3)?;
            }
            let meta = fixture.engine.store().meta()?;
            let output = fixture
                .execute(&prepared, invocation("body-capture"))
                .await?;
            let expected = if elided { 7 } else { 1 };
            body_states(&output, expected)?;
            let parent = &output.calls[&outer_id].evaluation().inputs[0];
            assert_eq!(parent.data.name, "root_rows");
            assert_eq!(
                values(&parent.data.batches)?,
                (1..=cursor).collect::<Vec<_>>()
            );
            let child = &output.calls[&inner_id].evaluation().inputs[0];
            assert_eq!(child.data.name, "selected");
            assert_eq!(values(&child.data.batches)?, [expected]);
            assert_eq!(child.coverage, parent.coverage);
            assert!(!child
                .coverage
                .limits
                .iter()
                .any(|limit| limit == "NO_SOURCE_COVERAGE"));
            if let Some(previous) = previous {
                assert_ne!(child.revision, previous);
            }
            previous = Some(child.revision.clone());
            assert_eq!(output.snapshot.page.extraction.sources.len(), 1);
            assert_eq!(
                output.snapshot.page.extraction.sources[0]
                    .receipt
                    .contiguous_cursor,
                cursor
            );
            assert_eq!(
                output
                    .snapshot
                    .witnesses
                    .iter()
                    .map(|w| w.cursor)
                    .collect::<Vec<_>>(),
                (1..=cursor).collect::<Vec<_>>()
            );
            assert_eq!(fixture.engine.store().meta()?, meta);
        }
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}
