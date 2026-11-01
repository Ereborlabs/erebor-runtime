use futures_util::StreamExt as _;

use super::*;

impl Fixture {
    pub(in crate::instance) async fn replay_result(
        &self,
        instance: &araphor_data::ManagedInstance,
        result: &str,
        control: &AnalysisReadControl,
    ) -> TestResult<araphor_query::definition::DefinitionOutput> {
        Ok(Instance::replay_result(
            Arc::clone(&self.query),
            self.authority.clone(),
            None,
            instance.grant.clone(),
            &instance.spec.id,
            result,
            control,
        )
        .await?)
    }
}

fn image(target: &str) -> TestResult<PackageBundleV1> {
    let mut image = bundle(target)?;
    let artifact = &mut image.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.name = "changes".into();
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, true)]);
    model.inputs = vec![
        sdk::Port::new("input", schema.clone()).into(),
        sdk::Port::new("removed", schema.clone()).into(),
        sdk::ChangeInputs::reset_port("reset").into(),
        sdk::InputPort {
            port: sdk::Port::new("affected", schema),
            source: sdk::InputSource::Query(
                "SELECT value FROM inserted.input UNION SELECT value FROM removed.input".into(),
            ),
        },
    ];
    model.input_mode = sdk::InputMode::Resolved;
    model.change_inputs = Some(sdk::ChangeInputs {
        reset: "reset".into(),
        ports: vec![sdk::ChangeInput {
            affected: "affected".into(),
            before: "removed".into(),
            after: "input".into(),
        }],
    });
    model
        .checkpoint
        .as_mut()
        .ok_or("checkpoint declaration")?
        .resume_input_changes = true;
    model.outputs[0].evidence_required = false;
    model.reasons.clear();
    match &mut artifact.implementations[0] {
        PackageImplementationV1::Sql { export, program } => {
            *export = "changes".into();
            *program =
        SqlModelV1 {
            outputs: BTreeMap::from([("data".into(), "SELECT CAST(COALESCE((SELECT SUM(value) FROM prior_state), 0) + (SELECT COUNT(*) FROM input) - (SELECT COUNT(*) FROM removed) AS BIGINT UNSIGNED) AS value".into())]),
            checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM output_data".into())]),
            ..Default::default()
        };
        }
        PackageImplementationV1::Wasm { exports, .. } => *exports = vec!["changes".into()],
        PackageImplementationV1::Native {
            export,
            artifact,
            qualification,
        } => {
            *export = "changes".into();
            *qualification = Some(araphor_package::Qualification::inspect(
                artifact,
                vec!["changes".into()],
                std::env::var("ARAPHOR_NATIVE_TARGET")?,
            )?);
        }
        _ => return Err("change fixture target".into()),
    }
    Ok(image)
}

fn sql(value: &str) -> String {
    format!(
        r#"SELECT * FROM "runtime-fixture"."1".changes(input => (
        SELECT {value} AS value FROM context_versions
        WHERE owner_revision = (SELECT MAX(owner_revision) FROM context_versions)
        UNION ALL SELECT {value} AS value FROM context_versions
        WHERE owner_revision = (SELECT MAX(owner_revision) FROM context_versions) AND owner_revision % 2 = 0))"#
    )
}

fn lookup_image() -> TestResult<PackageBundleV1> {
    let mut image = image("sql")?;
    let artifact = &mut image.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.checkpoint = None;
    model.inputs.push(sdk::InputPort {
        port: model.inputs[0].port.clone(),
        source: sdk::InputSource::Lookup("SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM input
            UNION ALL SELECT CAST(MAX(owner_revision) AS BIGINT UNSIGNED) AS value FROM context_versions".into()),
    });
    model.inputs[4].port.name = "support".into();
    let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] else {
        return Err("lookup SQL fixture".into());
    };
    *program = SqlModelV1 {
        outputs: BTreeMap::from([(
            "data".into(),
            "SELECT CAST(COALESCE(SUM(value), 0) AS BIGINT UNSIGNED) AS value FROM support".into(),
        )]),
        ..Default::default()
    };
    Ok(image)
}

#[tokio::test]
async fn lookup_preserves_sql_order() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let control = AnalysisReadControl::default();
    let mut image = lookup_image()?;
    image.artifacts[0].descriptor.exports[0].inputs[4].source = sdk::InputSource::Lookup(
        "SELECT value FROM (VALUES (CAST(3 AS BIGINT UNSIGNED)), (CAST(NULL AS BIGINT UNSIGNED)), (CAST(1 AS BIGINT UNSIGNED)), (CAST(2 AS BIGINT UNSIGNED))) values(value) ORDER BY value DESC NULLS FIRST".into(),
    );
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture
        .admit("ordered-lookup", &sql("CAST(7 AS BIGINT UNSIGNED)"))
        .await?;
    let receipt = instance.run(request("ordered-lookup"), &control).await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("ordered lookup result")?;
    let saved_replay = fixture
        .replay_result(instance.admitted(), &reference.result_id, &control)
        .await?;
    let saved = saved_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    let mut actual = Vec::new();
    for batch in &saved.input("support")?.data.batches {
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("lookup value type")?;
        actual.extend(values.iter());
    }
    assert_eq!(actual, [None, Some(3), Some(2), Some(1)]);
    let replay = Instance::replay_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        fixture.grant.clone(),
        "ordered-lookup",
        &reference.result_id,
        &control,
    )
    .await?;
    let call = replay
        .calls
        .values()
        .next()
        .ok_or("ordered lookup replay")?;
    assert_eq!(
        call.evaluation().input("support")?.data.batches,
        saved.input("support")?.data.batches
    );
    Ok(())
}

#[tokio::test]
async fn source_lookup_keeps_evidence() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = lookup_image()?;
    image.artifacts[0].descriptor.exports[0].inputs[4].source = sdk::InputSource::Lookup(
        "SELECT c.owner_revision AS value FROM input i JOIN context_versions c ON c.owner_revision = i.value - 1".into(),
    );
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture.admit("indexed-support", r#"SELECT * FROM "runtime-fixture"."1".changes(input => (SELECT owner_revision AS value FROM context_versions))"#).await?;
    let lifecycle = fixture.start(&instance)?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    for revision in 1..=3 {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("indexed support receipt")??;
        let result = receipt
            .results
            .values()
            .next()
            .ok_or("indexed support result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &result.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert_eq!(
            values(&evaluation.input("input")?.data.batches)?,
            [revision]
        );
        assert_eq!(
            values(&evaluation.input("support")?.data.batches)?,
            if revision == 1 {
                vec![]
            } else {
                vec![revision - 1]
            }
        );
        let (_, contexts) = fixture
            .query
            .store()
            .package_evidence([1; 16], std::slice::from_ref(&result.result_id))?;
        let actual = contexts
            .iter()
            .map(|reference| reference.key.owner_revision)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            if revision == 1 {
                vec![1]
            } else {
                vec![revision - 1, revision]
            }
        );
    }
    stream.cancel_and_join(&control).await?;
    fixture.context(4)?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("restored support receipt")??;
    let result = receipt
        .results
        .values()
        .next()
        .ok_or("restored support result")?;
    let evaluation_replay = fixture
        .replay_result(instance.admitted(), &result.result_id, &control)
        .await?;
    let evaluation = evaluation_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    assert_eq!(values(&evaluation.input("input")?.data.batches)?, [4]);
    assert_eq!(values(&evaluation.input("support")?.data.batches)?, [3]);
    stream.cancel_and_join(&control).await?;
    Ok(())
}

#[tokio::test]
async fn lookup_rejects_early_dependencies() -> TestResult {
    for sql in [
        "SELECT value FROM removed",
        "SELECT CAST(reset AS BIGINT UNSIGNED) AS value FROM reset",
        "SELECT value FROM support",
    ] {
        let fixture = Fixture::new(Default::default())?;
        let mut image = lookup_image()?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        let mut port = model.inputs[0].port.clone();
        port.name = "early".into();
        model.inputs.push(sdk::InputPort {
            port,
            source: sdk::InputSource::Query(sql.into()),
        });
        fixture.install(&image)?;
        let error = fixture
            .admit("early", &self::sql("CAST(7 AS BIGINT UNSIGNED)"))
            .await
            .err()
            .ok_or("early lookup admission")?;
        assert!(
            format!("{error:?}").contains("lookup input phase"),
            "{error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn lookup_rejects_early_base() -> TestResult {
    for sql in [
        "SELECT value FROM removed",
        "SELECT CAST(reset AS BIGINT UNSIGNED) AS value FROM reset",
        "SELECT value FROM support",
    ] {
        let fixture = Fixture::new(Default::default())?;
        let mut image = lookup_image()?;
        image.artifacts[0].descriptor.exports[0].inputs[0].source =
            sdk::InputSource::Query(sql.into());
        fixture.install(&image)?;
        let error = fixture
            .admit(
                "early-base",
                r#"SELECT * FROM "runtime-fixture"."1".changes()"#,
            )
            .await
            .err()
            .ok_or("early base admission")?;
        assert!(
            format!("{error:?}").contains("lookup input phase"),
            "{error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn named_inputs_keep_phase() -> TestResult {
    for name in ["removed", "support"] {
        for target in ["input", "early"] {
            let fixture = Fixture::new(Default::default())?;
            let mut image = lookup_image()?;
            let model = &mut image.artifacts[0].descriptor.exports[0];
            let schema = Arc::new(model.inputs[0].port.schema.clone());
            let source = sdk::InputSource::Table(sdk::TableRef::Named(name.into()));
            if target == "input" {
                model.inputs[0].source = source;
            } else {
                let mut port = model.inputs[0].port.clone();
                port.name = target.into();
                model.inputs.push(sdk::InputPort { port, source });
            }
            fixture.install(&image)?;
            let batch = sdk::RecordBatch::try_new(
                Arc::clone(&schema),
                vec![Arc::new(UInt64Array::from(vec![7]))],
            )?;
            let table: Arc<dyn datafusion::catalog::TableProvider> = Arc::new(
                datafusion::datasource::MemTable::try_new(schema, vec![vec![batch]])?,
            );
            let control = AnalysisReadControl::default();
            let mut session =
                fixture
                    .query
                    .session(fixture.grant.selection.clone(), &control, 10)?;
            session.register_table(name, Arc::clone(&table))?;
            session.register_table("input", table)?;
            let prepared = session
                .prepare_definition(&Fixture::definition(&format!("SELECT value FROM {name}")))
                .await?;
            let output = session
                .execute_definition(&prepared, araphor_query::definition::Invocation::default())
                .await?;
            assert_eq!(values(&output.batches)?, [7]);
            drop(output);
            let error = session
                .prepare_definition(&Fixture::definition(
                    r#"SELECT * FROM "runtime-fixture"."1".changes()"#,
                ))
                .await
                .err()
                .ok_or("Named input crossed the change phase")?;
            assert!(
                format!("{error:?}").contains("lookup input phase"),
                "{name}/{target}: {error:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn lookup_keeps_historical_provenance() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = lookup_image()?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    for (name, source) in [
        (
            "copy",
            sdk::InputSource::Query("SELECT value FROM input".into()),
        ),
        (
            "copy_removed",
            sdk::InputSource::Table(sdk::TableRef::Named("copy_removed".into())),
        ),
        (
            "affected_support",
            sdk::InputSource::Query(
                r#"SELECT value FROM "inserted.copy" UNION SELECT value FROM "removed.copy""#
                    .into(),
            ),
        ),
        (
            "old_input",
            sdk::InputSource::Lookup("SELECT value FROM removed".into()),
        ),
        (
            "old_copy",
            sdk::InputSource::Lookup("SELECT value FROM copy_removed".into()),
        ),
    ] {
        let mut port = model.inputs[0].port.clone();
        port.name = name.into();
        model.inputs.push(sdk::InputPort { port, source });
    }
    model
        .change_inputs
        .as_mut()
        .ok_or("change declaration")?
        .ports
        .push(sdk::ChangeInput {
            affected: "affected_support".into(),
            before: "copy_removed".into(),
            after: "copy".into(),
        });
    fixture.install(&image)?;
    fixture.context(2)?;
    let instance = fixture
        .admit("history", &sql("CAST(NULL AS BIGINT UNSIGNED)"))
        .await?;
    let lifecycle = fixture.start(&instance)?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("first historical lookup")??;
    fixture.context(3)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("second historical lookup")??;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("historical lookup result")?;
    let evaluation_replay = fixture
        .replay_result(instance.admitted(), &reference.result_id, &control)
        .await?;
    let evaluation = evaluation_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    let before = evaluation.input("removed")?;
    let copy = evaluation.input("copy_removed")?;
    let first = evaluation.input("old_input")?;
    let second = evaluation.input("old_copy")?;
    assert_eq!(first.data.batches, second.data.batches);
    assert_eq!(first.data.rows(), 1);
    assert_ne!(before.revision, copy.revision);
    assert_ne!(first.revision, second.revision);
    assert_eq!(first.coverage, before.coverage);
    assert_eq!(second.coverage, copy.coverage);
    stream.cancel_and_join(&control).await?;
    Ok(())
}

#[tokio::test]
async fn stateless_lookup_uses_changes() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = lookup_image()?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let definition = sql("CAST(NULL AS BIGINT UNSIGNED)");
    assert!(fixture
        .admit(
            "override",
            &definition.replace("input => (", "support => (")
        )
        .await
        .is_err());
    let instance = fixture.admit("lookup", &definition).await?;
    let control = Arc::new(AnalysisReadControl::default());
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    for (revision, added, removed, total) in
        [(1, 1, 0, 2), (2, 1, 0, 3), (4, 0, 0, 4), (5, 0, 1, 5)]
    {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("lookup receipt")??;
        assert_eq!(fixture.selected("lookup", &receipt.attempt).await?, [total]);
        let reference = receipt.results.values().next().ok_or("lookup result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &reference.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert!(evaluation.checkpoint.is_none());
        assert!(evaluation.previous_outputs.is_empty());
        assert_eq!(
            image.artifacts[0].descriptor.exports[0]
                .change_inputs
                .as_ref()
                .ok_or("change declaration")?
                .is_reset(evaluation)?,
            revision == 1
        );
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), removed);
        assert_eq!(
            values(&evaluation.input("support")?.data.batches)?,
            [added, revision]
        );
        let replay = Instance::replay_result(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            None,
            fixture.grant.clone(),
            "lookup",
            &reference.result_id,
            &control,
        )
        .await?;
        assert_eq!(values(&replay.batches)?, [total]);
        let actual = replay
            .calls
            .values()
            .next()
            .ok_or("lookup replay")?
            .evaluation();
        for (actual, expected) in actual.inputs.iter().zip(&evaluation.inputs) {
            assert_eq!(actual.data.batches, expected.data.batches);
            assert_eq!(actual.revision, expected.revision);
            assert_eq!(actual.coverage, expected.coverage);
        }
    }
    stream.cancel_and_join(&control).await?;
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let fixture = Fixture {
        query: Engine::new(
            Arc::new(AnalysisStore::open(directory.path().join("data"))?),
            Default::default(),
        )?,
        directory,
        authority,
        grant,
    };
    fixture.context(6)?;
    let control = Arc::new(AnalysisReadControl::default());
    let instance = Instance::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "lookup".into(),
        definition,
        &control,
    )
    .await?;
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("reopened lookup receipt")??;
    assert_eq!(fixture.selected("lookup", &receipt.attempt).await?, [7]);
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("reopened lookup result")?;
    let evaluation_replay = fixture
        .replay_result(instance.admitted(), &reference.result_id, &control)
        .await?;
    let evaluation = evaluation_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    assert!(!image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("change declaration")?
        .is_reset(evaluation)?);
    assert!(evaluation.checkpoint.is_none());
    assert_eq!(evaluation.input("input")?.data.rows(), 1);
    stream.cancel_and_join(&control).await?;
    Ok(())
}

#[tokio::test]
async fn subscription_consumes_query_changes() -> TestResult {
    subscription_changes("sql").await
}

#[tokio::test]
async fn subscription_reads_source_changes() -> TestResult {
    source_changes("sql").await
}

#[tokio::test]
async fn wasm_reads_source_changes() -> TestResult {
    source_changes("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_reads_source_changes() -> TestResult {
    source_changes("native").await
}

#[tokio::test]
async fn ordered_input_keeps_ctes() -> TestResult {
    for (outer, query, expected) in [
        ("SELECT owner_revision AS value, owner_id AS owner FROM context_versions", "SELECT value, owner FROM picked ORDER BY value DESC", Some(vec![3, 2, 1])),
        ("SELECT owner_revision AS value, owner_id AS owner FROM context_versions", "WITH selected AS (SELECT * FROM picked WHERE value >= 2) SELECT value, owner FROM selected ORDER BY value DESC", Some(vec![3, 2])),
        ("SELECT owner_revision AS value, owner_id AS owner FROM context_versions WHERE owner_revision = 1", "WITH picked AS (SELECT owner_revision AS value, owner_id AS owner FROM context_versions WHERE owner_revision >= 2) SELECT value, owner FROM picked ORDER BY value DESC", None),
        ("SELECT owner_revision AS value, owner_id AS owner FROM context_versions", "SELECT value, owner FROM picked ORDER BY value DESC NULLS LAST LIMIT 2", Some(vec![3, 2])),
    ] {
        let fixture = Fixture::new(Default::default())?;
        let mut image = image("sql")?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        let schema = sdk::Schema::new(vec![model.inputs[0].port.schema.fields()[0].clone(), Arc::new(sdk::Field::new("owner", sdk::DataType::Utf8, true))]);
        model.inputs[0].port.schema = schema.clone();
        model.inputs[1].port.schema = schema;
        fixture.install(&image)?;
        for revision in 1..=3 { fixture.context(revision)?; }
        let sql = format!(r#"WITH picked AS ({outer}) SELECT * FROM "runtime-fixture"."1".changes(input => ({query}))"#);
        let Some(expected) = expected else {
            let native = datafusion::prelude::SessionContext::new();
            native.register_table("context_versions", Arc::new(datafusion::datasource::empty::EmptyTable::new(Arc::clone(&AnalysisStore::table_schemas()["context_versions"]))))?;
            let plain = format!("WITH picked AS ({outer}) SELECT * FROM ({query}) nested");
            let diagnostic = "WITH query name \"picked\" specified more than once";
            let native = native.sql(&plain).await.err().ok_or("native CTE shadowing was accepted")?;
            assert!(native.to_string().contains(diagnostic));
            let actual = fixture.admit("ordered-cte", &sql).await.err().ok_or("package CTE shadowing was accepted")?;
            let mut source = Some(actual.as_ref() as &dyn std::error::Error);
            let mut matched = false;
            while let Some(error) = source {
                matched |= error.to_string().contains(diagnostic);
                source = error.source();
            }
            assert!(matched, "{actual:?}");
            continue;
        };
        let instance = fixture.admit("ordered-cte", &sql).await?;
        let control = AnalysisReadControl::default();
        let receipt = instance.run(request("ordered-cte"), &control).await?;
        let reference = receipt.results.values().next().ok_or("ordered CTE result")?;
        let evaluation_replay = fixture.replay_result(instance.admitted(), &reference.result_id, &control).await?;
        let evaluation = evaluation_replay.calls.values().next().ok_or("replayed call")?.evaluation();
        let mut ordered = Vec::new();
        for batch in &evaluation.input("input")?.data.batches {
            assert_eq!(batch.num_columns(), 2);
            let column = batch.column(0).as_any().downcast_ref::<UInt64Array>().ok_or("ordered CTE values")?;
            ordered.extend_from_slice(column.values());
        }
        assert_eq!(ordered, expected);
    }
    Ok(())
}

async fn source_changes(target: &str) -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&image(target)?)?;
    fixture.context(1)?;
    let instance = fixture.admit("source-changes", r#"SELECT * FROM "runtime-fixture"."1".changes(input => (SELECT owner_revision AS value FROM context_versions ORDER BY owner_revision DESC))"#).await?;
    let lifecycle = fixture.start(&instance)?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    for revision in 1..=3 {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("source change receipt")??;
        assert_eq!(
            fixture.selected("source-changes", &receipt.attempt).await?,
            [revision]
        );
        let result = receipt
            .results
            .values()
            .next()
            .ok_or("source change result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &result.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert_eq!(
            values(&evaluation.input("input")?.data.batches)?,
            [revision]
        );
        assert_eq!(
            values(&evaluation.input("affected")?.data.batches)?,
            [revision]
        );
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert!(futures_util::poll!(stream.next()).is_pending());
    }
    stream.cancel_and_join(&control).await?;
    let control = Arc::new(AnalysisReadControl::default());
    fixture.context(4)?;
    fixture.context(5)?;
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("restored source receipt")??;
    assert_eq!(
        fixture.selected("source-changes", &receipt.attempt).await?,
        [5]
    );
    let result = receipt
        .results
        .values()
        .next()
        .ok_or("restored source result")?;
    let evaluation_replay = fixture
        .replay_result(instance.admitted(), &result.result_id, &control)
        .await?;
    let evaluation = evaluation_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    let mut ordered = Vec::new();
    for batch in &evaluation.input("input")?.data.batches {
        let column = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("ordered source values")?;
        ordered.extend_from_slice(column.values());
    }
    assert_eq!(ordered, [5, 4]);
    assert_eq!(evaluation.input("removed")?.data.rows(), 0);
    stream.cancel_and_join(&control).await?;
    Ok(())
}

#[tokio::test]
async fn wasm_consumes_query_changes() -> TestResult {
    subscription_changes("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_consumes_query_changes() -> TestResult {
    subscription_changes("native").await
}

async fn subscription_changes(target: &str) -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = image(target)?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture
        .admit("changes", &sql("CAST(NULL AS BIGINT UNSIGNED)"))
        .await?;
    let retained = fixture.query.memory().input_reserved();
    let lifecycle = fixture.start(&instance)?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    let mut saved = Vec::new();
    for (revision, total, added, removed) in
        [(1, 1, 1, 0), (2, 2, 1, 0), (3, 1, 0, 1), (4, 2, 1, 0)]
    {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("change receipt")??;
        assert_eq!(
            fixture.selected("changes", &receipt.attempt).await?,
            [total]
        );
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("change call result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &reference.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        let contract = image.artifacts[0].descriptor.exports[0]
            .change_inputs
            .as_ref()
            .ok_or("change contract")?;
        let stored = fixture.query.store().managed_result(
            instance.admitted(),
            &reference.result_id,
            u64::try_from(evaluation.context.time_utc_ns)?,
            &control,
        )?;
        let context = call_context(&stored)?;
        assert_eq!(
            evaluation
                .inputs
                .iter()
                .map(|input| &input.revision)
                .collect::<Vec<_>>(),
            context.inputs.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            evaluation
                .inputs
                .iter()
                .map(|input| &input.coverage)
                .collect::<Vec<_>>(),
            context.input_coverage.iter().collect::<Vec<_>>()
        );
        assert_eq!(contract.is_reset(evaluation)?, revision == 1);
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), removed);
        let replay = Instance::replay_result(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            None,
            fixture.grant.clone(),
            "changes",
            &reference.result_id,
            &control,
        )
        .await?;
        assert_eq!(values(&replay.batches)?, [total]);
        let replayed = replay
            .calls
            .values()
            .next()
            .ok_or("replayed change")?
            .evaluation();
        for (actual, expected) in replayed.inputs.iter().zip(&evaluation.inputs) {
            assert_eq!(actual.data.batches, expected.data.batches);
            assert_eq!(actual.revision, expected.revision);
            assert_eq!(actual.coverage, expected.coverage);
        }
        saved.push(reference.clone());
        assert!(futures_util::poll!(stream.next()).is_pending());
    }
    stream.cancel_and_join(&control).await?;
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let control = Arc::new(AnalysisReadControl::default());
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Default::default(),
    )?;
    let instance = Instance::admit(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "changes".into(),
        definition,
        &control,
    )
    .await?;
    let fixture = Fixture {
        directory,
        query,
        authority,
        grant,
    };
    fixture.context(5)?;
    let mut stream = instance.subscribe(Arc::clone(&control), u64::MAX, lifecycle)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("reopened change receipt")??;
    assert_eq!(fixture.selected("changes", &receipt.attempt).await?, [1]);
    let reference = receipt.results.values().next().ok_or("reopened call")?;
    let evaluation_replay = fixture
        .replay_result(instance.admitted(), &reference.result_id, &control)
        .await?;
    let evaluation = evaluation_replay
        .calls
        .values()
        .next()
        .ok_or("replayed call")?
        .evaluation();
    assert!(!image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("change contract")?
        .is_reset(evaluation)?);
    assert_eq!(evaluation.input("input")?.data.rows(), 0);
    assert_eq!(evaluation.input("removed")?.data.rows(), 1);
    let old = instance.replay(&saved[1].result_id, &control).await?;
    assert_eq!(values(&old.batches)?, [2]);
    stream.cancel_and_join(&control).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_changes_keep_bases() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&image("sql")?)?;
    fixture.context(1)?;
    let control = AnalysisReadControl::default();
    let left = fixture
        .admit("left-changes", &sql("CAST(1 AS BIGINT UNSIGNED)"))
        .await?;
    let right = fixture
        .admit("right-changes", &sql("CAST(2 AS BIGINT UNSIGNED)"))
        .await?;
    let (left_first, right_first) = tokio::join!(
        left.run(request("left-first"), &control),
        right.run(request("right-first"), &control)
    );
    left_first?;
    right_first?;
    fixture.context(2)?;
    let (left_second, right_second) = tokio::join!(
        left.run(request("left-second"), &control),
        right.run(request("right-second"), &control)
    );
    for (instance, receipt, value) in [(left, left_second?, 1), (right, right_second?, 2)] {
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("concurrent change result")?;
        let evaluation_replay = fixture
            .replay_result(
                instance.admitted(),
                &reference.result_id,
                &AnalysisReadControl::default(),
            )
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert_eq!(values(&evaluation.input("input")?.data.batches)?, [value]);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(
            fixture
                .selected(&instance.admitted().spec.id, &receipt.attempt)
                .await?,
            [2]
        );
    }
    Ok(())
}

#[tokio::test]
async fn skipped_calls_reset_basis() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = image("sql")?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "conditional-changes",
            r#"SELECT * FROM "runtime-fixture"."1".changes(input => (
                SELECT owner_revision AS value FROM context_versions ORDER BY owner_revision))
                WHERE CURRENT_TIMESTAMP <> TIMESTAMP '1970-01-01 00:00:02'
                UNION ALL
                SELECT * FROM "runtime-fixture"."1".changes(input => (
                SELECT owner_revision + CAST(10 AS BIGINT UNSIGNED) AS value
                FROM context_versions ORDER BY owner_revision))"#,
        )
        .await?;
    let control = AnalysisReadControl::default();
    let mut receipts = Vec::new();
    for revision in 1..=2 {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let mut input = request(&format!("conditional-{revision}"));
        input.time_utc_ns = revision * 1_000_000_000;
        input.seed = Some(100 + revision);
        let receipt = instance.run(input, &control).await?;
        assert_eq!(receipt.results.len(), if revision == 2 { 1 } else { 2 });
        receipts.push(receipt);
    }
    let resume = fixture
        .query
        .store()
        .managed_resume([1; 16], "conditional-changes", &control)?;
    let mut saved = Vec::new();
    for reference in receipts.iter().flat_map(|receipt| receipt.results.values()) {
        saved.push(fixture.query.store().managed_result(
            instance.admitted(),
            &reference.result_id,
            2_000_000_000,
            &control,
        )?);
    }
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let fixture = Fixture {
        query: Engine::new(
            Arc::new(AnalysisStore::open(directory.path().join("data"))?),
            Default::default(),
        )?,
        directory,
        authority,
        grant,
    };
    let instance = Instance::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "conditional-changes".into(),
        definition,
        &control,
    )
    .await?;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_resume([1; 16], "conditional-changes", &control)?,
        resume
    );
    for expected in &saved {
        let actual = fixture.query.store().managed_result(
            instance.admitted(),
            &expected.result.result_id,
            2_000_000_000,
            &control,
        )?;
        assert_eq!(actual.result, expected.result);
        assert_eq!(actual.receipt, expected.receipt);
        assert_eq!(actual.source, expected.source);
        assert_eq!(actual.prior, expected.prior);
        assert_eq!(call_context(&actual)?, call_context(expected)?);
    }
    fixture.context(3)?;
    let mut input = request("conditional-3");
    input.time_utc_ns = 3_000_000_000;
    input.seed = Some(103);
    let receipt = instance.run(input, &control).await?;
    assert_eq!(receipt.results.len(), 2);
    receipts.push(receipt);
    let first = receipts.first().ok_or("first conditional receipt")?;
    let second = receipts.get(1).ok_or("second conditional receipt")?;
    let third = receipts.get(2).ok_or("third conditional receipt")?;
    let (&sibling, second_ref) = second.results.iter().next().ok_or("active sibling")?;
    let (&skipped, first_ref) = first
        .results
        .iter()
        .find(|(call, _)| **call != sibling)
        .ok_or("skipped call")?;
    let contract = image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("conditional change contract")?;
    for (call, expected, reset, base) in [
        (skipped, vec![1, 2, 3], true, None),
        (sibling, vec![13], false, Some(second_ref)),
    ] {
        let reference = third.results.get(&call).ok_or("resumed call reference")?;
        let replay = fixture
            .replay_result(instance.admitted(), &reference.result_id, &control)
            .await?;
        let result = replay.calls.get(&call).ok_or("resumed call")?;
        let evaluation = result.evaluation();
        assert_eq!(contract.is_reset(evaluation)?, reset);
        assert_eq!(values(&evaluation.input("input")?.data.batches)?, expected);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(evaluation.checkpoint.is_none(), reset);
        assert_eq!(evaluation.previous_outputs.is_empty(), reset);
        assert_eq!(
            result.changes().ok_or("resumed change base")?.base.as_ref(),
            base
        );
        assert_eq!(values(&replay.batches)?, [3]);
        assert_eq!(evaluation.context.id, "conditional-3");
        assert_eq!(evaluation.context.time_utc_ns, 3_000_000_000);
        assert_eq!(evaluation.context.seed, Some(103));
    }
    let old = fixture
        .replay_result(instance.admitted(), &first_ref.result_id, &control)
        .await?;
    assert_eq!(values(&old.batches)?, [1]);
    let evaluation = old
        .calls
        .get(&skipped)
        .ok_or("old conditional call")?
        .evaluation();
    assert_eq!(evaluation.context.id, "conditional-1");
    assert_eq!(evaluation.context.time_utc_ns, 1_000_000_000);
    assert_eq!(evaluation.context.seed, Some(101));
    Ok(())
}

#[tokio::test]
async fn parameters_reset_all_inputs() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = image("sql")?;
    image.artifacts[0].descriptor.exports[0].parameters = sdk::Schema::new(vec![sdk::Field::new(
        "marker",
        sdk::DataType::UInt64,
        false,
    )]);
    fixture.install(&image)?;
    fixture.context(1)?;
    let mut query = sql("CAST(NULL AS BIGINT UNSIGNED)");
    assert_eq!(query.pop(), Some(')'));
    query.push_str(", marker => CASE WHEN (SELECT MAX(owner_revision) FROM context_versions) < 3 THEN CAST(0 AS BIGINT UNSIGNED) ELSE CAST(1 AS BIGINT UNSIGNED) END)");
    let instance = fixture.admit("parameter-changes", &query).await?;
    let control = AnalysisReadControl::default();
    let contract = image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("change contract")?;
    for (revision, reset, total, added, marker) in
        [(1, true, 1, 1, 0), (2, false, 2, 1, 0), (3, true, 1, 1, 1)]
    {
        if revision != 1 {
            fixture.context(revision)?;
        }
        let receipt = instance
            .run(request(&format!("parameters-{revision}")), &control)
            .await?;
        assert_eq!(
            fixture
                .selected("parameter-changes", &receipt.attempt)
                .await?,
            [total]
        );
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("parameter change result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &reference.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert_eq!(contract.is_reset(evaluation)?, reset);
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(
            values(std::slice::from_ref(
                evaluation.parameters.as_ref().ok_or("parameters")?
            ))?,
            [marker]
        );
        assert_eq!(evaluation.checkpoint.is_none(), reset);
        assert_eq!(evaluation.previous_outputs.is_empty(), reset);
        let replay = instance.replay(&reference.result_id, &control).await?;
        assert_eq!(values(&replay.batches)?, [total]);
    }
    Ok(())
}

#[tokio::test]
async fn support_change_resets_inputs() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = image("sql")?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model
        .inputs
        .push(sdk::Port::new("support", model.inputs[0].port.schema.clone()).into());
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture.admit("support-changes", r#"SELECT * FROM "runtime-fixture"."1".changes(
        input => (SELECT CAST(NULL AS BIGINT UNSIGNED) AS value UNION ALL SELECT CAST(NULL AS BIGINT UNSIGNED) AS value),
        support => (SELECT MAX(owner_revision) AS value FROM context_versions))"#).await?;
    let control = AnalysisReadControl::default();
    let contract = image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("change contract")?;
    let mut last = None;
    for (step, reset, added) in [(1, true, 2), (2, false, 0), (3, true, 2)] {
        if step == 3 {
            fixture.context(2)?;
        }
        let receipt = instance
            .run(request(&format!("support-{step}")), &control)
            .await?;
        let reference = receipt.results.values().next().ok_or("support result")?;
        let evaluation_replay = fixture
            .replay_result(instance.admitted(), &reference.result_id, &control)
            .await?;
        let evaluation = evaluation_replay
            .calls
            .values()
            .next()
            .ok_or("replayed call")?
            .evaluation();
        assert_eq!(contract.is_reset(evaluation)?, reset);
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(evaluation.checkpoint.is_none(), reset);
        assert_eq!(evaluation.previous_outputs.is_empty(), reset);
        assert_eq!(
            fixture
                .selected("support-changes", &receipt.attempt)
                .await?,
            [2]
        );
        let replay = instance.replay(&reference.result_id, &control).await?;
        assert_eq!(values(&replay.batches)?, [2]);
        let replayed = replay
            .calls
            .values()
            .next()
            .ok_or("support replay")?
            .evaluation();
        for (actual, expected) in replayed.inputs.iter().zip(&evaluation.inputs) {
            assert_eq!(actual.data.batches, expected.data.batches);
            assert_eq!(actual.revision, expected.revision);
            assert_eq!(actual.coverage, expected.coverage);
        }
        last = Some(receipt);
    }
    let last = last.ok_or("support receipt")?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "support-changes", &control)?
        .ok_or("support instance")?;
    let session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 10)?;
    let capture = session
        .capture_managed(
            &instance.prepared,
            araphor_query::definition::Invocation::default(),
            araphor_data::ManagedRead {
                source: None,
                execution: None,
                instance: current,
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
        )
        .await?;
    let prior = capture
        .snapshot()
        .managed()
        .and_then(|managed| managed.prior(*last.results.keys().next()?))
        .and_then(|prior| prior.retained.as_ref())
        .ok_or("saved reset call")?;
    assert!(prior
        .changes
        .as_ref()
        .ok_or("saved change base")?
        .base
        .is_none());
    assert_eq!(prior.evaluation.input("input")?.data.rows(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captures_keep_distinct_positions() -> TestResult {
    use araphor_data::ManagedRead;
    use araphor_query::definition::Invocation;

    let fixture = Fixture::new(Default::default())?;
    fixture.install(&image("sql")?)?;
    fixture.context(1)?;
    let instance = fixture
        .admit("change-positions", &sql("CAST(1 AS BIGINT UNSIGNED)"))
        .await?;
    let control = AnalysisReadControl::default();
    instance.run(request("initial"), &control).await?;
    fixture.context(2)?;
    instance.run(request("second"), &control).await?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "change-positions", &control)?
        .ok_or("current instance")?;
    let session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 10)?;
    let read = || ManagedRead {
        source: None,
        execution: None,
        instance: current.clone(),
        expected: None,
        rebuild: false,
        follow: false,
        completed: None,
    };
    let invocation = |id: &str| Invocation {
        id: id.into(),
        ..Default::default()
    };
    let first = session
        .capture_managed(&instance.prepared, invocation("captured-a"), read())
        .await?;
    let retry = session
        .capture_managed(&instance.prepared, invocation("captured-a"), read())
        .await?
        .execute()
        .await?;
    let changed = session
        .capture_managed(&instance.prepared, invocation("captured-b"), read())
        .await?
        .execute()
        .await?;
    let retry_input = retry
        .calls
        .values()
        .next()
        .ok_or("retry call")?
        .evaluation()
        .input("input")?;
    let changed_input = changed
        .calls
        .values()
        .next()
        .ok_or("changed call")?
        .evaluation()
        .input("input")?;
    assert_ne!(retry_input.revision, changed_input.revision);
    fixture.context(3)?;
    let later = session
        .capture_managed(&instance.prepared, invocation("captured-a"), read())
        .await?;
    let (first, later) = tokio::join!(first.execute(), later.execute());
    let first = first?;
    let later = later?;
    assert_eq!(values(&first.batches)?, [2]);
    assert_eq!(values(&later.batches)?, [1]);
    let first = first
        .calls
        .values()
        .next()
        .ok_or("first captured call")?
        .evaluation();
    let later = later
        .calls
        .values()
        .next()
        .ok_or("later captured call")?
        .evaluation();
    assert_eq!(first.input("input")?.revision, retry_input.revision);
    assert_ne!(
        first.input("input")?.revision,
        later.input("input")?.revision
    );
    assert_eq!(first.input("removed")?.data.rows(), 0);
    assert_eq!(later.input("removed")?.data.rows(), 1);
    Ok(())
}
