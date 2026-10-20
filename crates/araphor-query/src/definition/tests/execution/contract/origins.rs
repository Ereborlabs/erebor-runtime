use std::hash::{Hash as _, Hasher as _};

use super::*;

fn nested_image(supplied: bool, source: &str) -> PackageBundleV1 {
    let mut inner = sdk::Model::new(
        "inner",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    inner.input_mode = sdk::InputMode::Resolved;
    inner.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("base", Fixture::schema("source_cursor")),
            source: sdk::InputSource::Table(sdk::TableRef::Named(source.into())),
        },
        sdk::InputPort {
            port: sdk::Port::new("derived", Fixture::schema("value")),
            source: sdk::InputSource::Query("SELECT source_cursor AS value FROM base".into()),
        },
    ];
    let mut image = bundle(
        inner,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM derived".into())]),
            ..Default::default()
        },
    );
    let mut outer = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    outer.input_mode = sdk::InputMode::Resolved;
    let arguments = if supplied {
        "base => (SELECT source_cursor FROM root_rows)"
    } else {
        ""
    };
    outer.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("guarded", Fixture::schema("value")),
        source: sdk::InputSource::Query(format!(
            r#"WITH unused AS (SELECT * FROM "fixture"."r1"."inner"({arguments}))
            SELECT CAST(7 AS BIGINT UNSIGNED) AS value"#,
        )),
    }];
    if supplied {
        outer.inputs.push(sdk::InputPort {
            port: sdk::Port::new("root_rows", Fixture::schema("source_cursor")),
            source: sdk::InputSource::Table(sdk::TableRef::Named(source.into())),
        });
    }
    image.artifacts[0].descriptor.exports.push(outer);
    image.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), "SELECT value FROM guarded".into())]),
                ..Default::default()
            },
        });
    image
}

async fn nested_origins(supplied: bool) -> TestResult {
    let image = nested_image(supplied, "events");
    let fixture = Fixture::installed(&image)?;
    fixture.event(1)?;
    let definition = Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#);
    let prepared = fixture.prepare(&definition).await?;
    assert!(prepared.sources().contains_key("events"));
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].export(), "count");
    drop(calls);
    let meta = fixture.engine.store().meta()?;
    let first = fixture
        .execute(&prepared, invocation("nested-first"))
        .await?;
    assert_eq!(values(&first.batches)?, [7]);
    assert_eq!(first.calls.len(), 1);
    let first_call = first.calls.values().next().ok_or("first call")?;
    assert_eq!(
        first_call.evaluation().inputs.len(),
        if supplied { 2 } else { 1 }
    );
    assert_eq!(first_call.evaluation().inputs[0].data.name, "guarded");
    assert_eq!(
        values(&first_call.evaluation().inputs[0].data.batches)?,
        [7]
    );
    if supplied {
        assert_eq!(first_call.evaluation().inputs[1].data.name, "root_rows");
        assert_eq!(
            values(&first_call.evaluation().inputs[1].data.batches)?,
            [1]
        );
    }
    assert_eq!(
        first
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(
        first.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    let hash = |prepared: &PreparedDefinition| {
        let mut hash = std::hash::DefaultHasher::new();
        prepared.plan.hash(&mut hash);
        hash.finish()
    };
    let plan_hash = hash(&prepared);
    let display = prepared.plan.display_indent().to_string();
    let resolved = prepared.resolved().clone();
    let sources = prepared.sources().clone();
    let fresh = fixture.prepare(&definition).await?;
    assert_eq!(fresh.resolved(), &resolved);
    assert_eq!(fresh.sources(), &sources);
    assert_eq!(fresh.plan.display_indent().to_string(), display);
    assert_eq!(hash(&fresh), plan_hash);
    let fresh_output = fixture.execute(&fresh, invocation("nested-fresh")).await?;
    assert_eq!(fresh_output.calls.len(), 1);
    let fresh_call = fresh_output.calls.values().next().ok_or("fresh call")?;
    assert_eq!(
        first_call.evaluation().inputs.len(),
        fresh_call.evaluation().inputs.len()
    );
    for (first, fresh) in first_call
        .evaluation()
        .inputs
        .iter()
        .zip(&fresh_call.evaluation().inputs)
    {
        assert_eq!(first.data.name, fresh.data.name);
        assert_eq!(first.data.batches, fresh.data.batches);
        assert_eq!(first.revision, fresh.revision);
        assert_eq!(first.coverage, fresh.coverage);
    }
    assert_eq!(fixture.engine.store().meta()?, meta);
    fixture.event(2)?;
    let meta = fixture.engine.store().meta()?;
    let second = fixture
        .execute(&prepared, invocation("nested-second"))
        .await?;
    assert_eq!(values(&second.batches)?, [7]);
    assert_eq!(second.calls.len(), 1);
    let second_call = second.calls.values().next().ok_or("second call")?;
    assert_ne!(
        first_call.evaluation().inputs[0].revision,
        second_call.evaluation().inputs[0].revision
    );
    if supplied {
        assert_ne!(
            first_call.evaluation().inputs[1].revision,
            second_call.evaluation().inputs[1].revision
        );
        assert_eq!(
            values(&second_call.evaluation().inputs[1].data.batches)?,
            [1, 2]
        );
    }
    assert_eq!(
        second
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        second.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    assert_eq!(fixture.engine.store().meta()?, meta);
    let revisions = second_call
        .evaluation()
        .inputs
        .iter()
        .map(|input| input.revision.clone())
        .collect::<Vec<_>>();
    drop(first);
    drop(fresh_output);
    drop(second);
    drop(prepared);
    drop(fresh);
    let Fixture { engine, _directory } = fixture;
    drop(engine);
    let fixture = Fixture {
        engine: Engine::new(
            Arc::new(AnalysisStore::open(_directory.path().join("data"))?),
            Limits::default(),
        )?,
        _directory,
    };
    let restored = fixture.prepare(&definition).await?;
    assert_eq!(restored.resolved(), &resolved);
    assert_eq!(restored.sources(), &sources);
    assert_eq!(restored.plan.display_indent().to_string(), display);
    assert_eq!(hash(&restored), plan_hash);
    let restored_output = fixture
        .execute(&restored, invocation("nested-restored"))
        .await?;
    assert_eq!(values(&restored_output.batches)?, [7]);
    assert_eq!(restored_output.calls.len(), 1);
    let restored_call = restored_output
        .calls
        .values()
        .next()
        .ok_or("restored call")?;
    assert_eq!(
        restored_call
            .evaluation()
            .inputs
            .iter()
            .map(|input| input.revision.clone())
            .collect::<Vec<_>>(),
        revisions
    );
    assert_eq!(fixture.engine.store().meta()?, meta);
    Ok(())
}

#[tokio::test]
async fn nested_unused_ports() -> TestResult {
    nested_origins(false).await
}

#[tokio::test]
async fn nested_caller_origins() -> TestResult {
    nested_origins(true).await
}

#[tokio::test]
async fn nested_local_metadata() -> TestResult {
    for retained in [false, true] {
        let mut image = nested_image(false, "local_rows");
        if retained {
            let outer = image.artifacts[0]
                .descriptor
                .exports
                .iter_mut()
                .find(|model| model.name == "count")
                .ok_or("local outer")?;
            outer.inputs[0].source =
                sdk::InputSource::Query(r#"SELECT * FROM "fixture"."r1"."inner"()"#.into());
        }
        let expected = if retained { 1 } else { 7 };
        let fixture = Fixture::installed(&image)?;
        let control = AnalysisReadControl::default();
        let mut session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
        let rows = sdk::RecordBatch::try_new(
            Arc::new(Fixture::schema("source_cursor")),
            vec![Arc::new(UInt64Array::from(vec![1]))],
        )?;
        session.register("local_rows", rows.schema(), &[rows])?;
        let prepared = session
            .prepare_definition(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        assert!(prepared.sources().is_empty());
        let meta = fixture.engine.store().meta()?;
        let first = session
            .execute_definition(&prepared, invocation("local-default"))
            .await?;
        assert_eq!(values(&first.batches)?, [expected]);
        assert_eq!(first.calls.len(), if retained { 2 } else { 1 });
        assert!(first.snapshot.witnesses.is_empty());
        assert!(first.snapshot.page.extraction.sources.is_empty());
        let (&id, first_call) = first
            .calls
            .iter()
            .find(|(_, call)| call.evaluation().export == "count")
            .ok_or("local call")?;
        let mut supplied = first_call.evaluation().inputs.clone();
        assert_eq!(supplied.len(), 1);
        supplied[0].revision = sdk::Revision {
            owner: "external-local".into(),
            id: "supplied-local".into(),
            window: None,
        };
        supplied[0].coverage = sdk::Coverage {
            state: sdk::CoverageState::Gapped,
            limits: vec!["LOCAL_METADATA".into()],
        };
        let mut request = invocation("local-supplied");
        request.inputs.insert(id, supplied.clone());
        let returned = session.execute_definition(&prepared, request).await?;
        assert_eq!(values(&returned.batches)?, [expected]);
        assert_eq!(returned.calls.len(), if retained { 2 } else { 1 });
        assert!(returned.snapshot.witnesses.is_empty());
        assert!(returned.snapshot.page.extraction.sources.is_empty());
        let actual = &returned.calls[&id].evaluation().inputs;
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].data.name, supplied[0].data.name);
        assert_eq!(actual[0].data.batches, supplied[0].data.batches);
        assert_eq!(actual[0].revision, supplied[0].revision);
        assert_eq!(actual[0].coverage, supplied[0].coverage);
        assert_eq!(fixture.engine.store().meta()?, meta);
    }
    Ok(())
}

async fn retained_origins(elided: bool) -> TestResult {
    let mut image = nested_image(true, "events");
    let supplied = if elided {
        "WITH unused AS (SELECT source_cursor FROM root_rows) SELECT CAST(7 AS BIGINT UNSIGNED) AS source_cursor"
    } else {
        "SELECT source_cursor FROM root_rows WHERE source_cursor = 1"
    };
    let outer = image.artifacts[0]
        .descriptor
        .exports
        .iter_mut()
        .find(|model| model.name == "count")
        .ok_or("outer descriptor")?;
    outer.inputs[0].source = sdk::InputSource::Query(format!(
        r#"SELECT * FROM "fixture"."r1"."inner"(base => ({supplied}))"#,
    ));
    for model in &mut image.artifacts[0].descriptor.exports {
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", Fixture::schema("value"))],
        });
    }
    for implementation in &mut image.artifacts[0].implementations {
        let PackageImplementationV1::Sql { program, .. } = implementation else {
            return Err("SQL origin fixture".into());
        };
        program
            .checkpoint
            .insert("state".into(), "SELECT value FROM output_result".into());
    }
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
        .ok_or("inner plan")?;
    let outer = calls
        .iter()
        .find(|call| call.export() == "count")
        .ok_or("outer plan")?;
    assert_ne!(inner.id(), outer.id());
    assert!(PackageCall::any(outer.inputs()[0], &mut |call| Ok(call
        .id()
        == inner.id()))?);
    let inner_id = inner.id();
    let outer_id = outer.id();
    drop(calls);
    let expected = if elided { 7 } else { 1 };
    let meta = fixture.engine.store().meta()?;
    let first = fixture
        .execute(&prepared, invocation("retained-first"))
        .await?;
    assert_eq!(values(&first.batches)?, [expected]);
    assert_eq!(first.calls.len(), 2);
    let inner = &first.calls[&inner_id];
    let outer = &first.calls[&outer_id];
    assert_eq!(inner.evaluation().inputs.len(), 2);
    assert_eq!(outer.evaluation().inputs.len(), 2);
    assert_eq!(inner.evaluation().inputs[0].data.name, "base");
    assert_eq!(inner.evaluation().inputs[1].data.name, "derived");
    assert_eq!(outer.evaluation().inputs[0].data.name, "guarded");
    assert_eq!(outer.evaluation().inputs[1].data.name, "root_rows");
    for input in &inner.evaluation().inputs {
        assert_eq!(values(&input.data.batches)?, [expected]);
        assert!(!input
            .coverage
            .limits
            .iter()
            .any(|limit| limit == "NO_SOURCE_COVERAGE"));
        assert_eq!(input.coverage, outer.evaluation().inputs[1].coverage);
    }
    assert_eq!(
        values(&outer.evaluation().inputs[0].data.batches)?,
        [expected]
    );
    assert_eq!(values(&outer.evaluation().inputs[1].data.batches)?, [1, 2]);
    for call in [inner, outer] {
        assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
        let checkpoint = call.output().checkpoint.as_ref().ok_or("nested state")?;
        assert_eq!(checkpoint.version, 1);
        assert_eq!(checkpoint.datasets.len(), 1);
        assert_eq!(checkpoint.datasets[0].name, "state");
        assert_eq!(values(&checkpoint.datasets[0].batches)?, [expected]);
    }
    assert_eq!(
        first
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        first.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    assert_eq!(fixture.engine.store().meta()?, meta);
    fixture.event(3)?;
    let meta = fixture.engine.store().meta()?;
    let second = fixture
        .execute(&prepared, invocation("retained-second"))
        .await?;
    assert_eq!(values(&second.batches)?, [expected]);
    assert_eq!(second.calls.len(), 2);
    let changed = &second.calls[&inner_id];
    for (before, after) in inner
        .evaluation()
        .inputs
        .iter()
        .zip(&changed.evaluation().inputs)
    {
        assert_eq!(values(&after.data.batches)?, [expected]);
        assert_ne!(before.revision, after.revision);
    }
    assert_ne!(
        outer.evaluation().inputs[0].revision,
        second.calls[&outer_id].evaluation().inputs[0].revision
    );
    assert_eq!(
        values(&second.calls[&outer_id].evaluation().inputs[1].data.batches)?,
        [1, 2, 3]
    );
    for call in second.calls.values() {
        let checkpoint = call
            .output()
            .checkpoint
            .as_ref()
            .ok_or("changed nested state")?;
        assert_eq!(checkpoint.version, 1);
        assert_eq!(values(&checkpoint.datasets[0].batches)?, [expected]);
    }
    assert_eq!(
        second
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        second.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        3
    );
    assert_eq!(fixture.engine.store().meta()?, meta);
    drop(first);
    drop(second);
    drop(prepared);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn retained_caller_rows() -> TestResult {
    retained_origins(false).await
}

#[tokio::test]
async fn retained_caller_elision() -> TestResult {
    retained_origins(true).await
}
