use futures_util::StreamExt as _;

use super::*;

fn image(target: &str) -> TestResult<PackageBundleV1> {
    let mut image = bundle(target)?;
    let artifact = &mut image.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.name = "changes".into();
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, true)]);
    model.inputs = vec![
        sdk::Port::new("input", schema.clone()).into(),
        sdk::Port::new("removed", schema).into(),
        sdk::ChangeInputs::reset_port("reset").into(),
    ];
    model.change_inputs = Some(sdk::ChangeInputs {
        reset: "reset".into(),
        ports: vec![sdk::ChangeInput {
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

#[tokio::test]
async fn subscription_consumes_query_changes() -> TestResult {
    subscription_changes("sql").await
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
        assert_eq!(fixture.selected("changes", &receipt.attempt)?, [total]);
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("change call result")?;
        let evaluation = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &control,
        )?;
        let contract = image.artifacts[0].descriptor.exports[0]
            .change_inputs
            .as_ref()
            .ok_or("change contract")?;
        assert_eq!(contract.is_reset(&evaluation)?, revision == 1);
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), removed);
        let replay = Instance::replay_result(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
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
    assert_eq!(fixture.selected("changes", &receipt.attempt)?, [1]);
    let reference = receipt.results.values().next().ok_or("reopened call")?;
    let evaluation = fixture.query.store().managed_evaluation(
        instance.admitted(),
        &reference.result_id,
        &control,
    )?;
    assert!(!image.artifacts[0].descriptor.exports[0]
        .change_inputs
        .as_ref()
        .ok_or("change contract")?
        .is_reset(&evaluation)?);
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
        let evaluation = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(values(&evaluation.input("input")?.data.batches)?, [value]);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(
            fixture.selected(&instance.admitted().spec.id, &receipt.attempt)?,
            [2]
        );
    }
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
            fixture.selected("parameter-changes", &receipt.attempt)?,
            [total]
        );
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("parameter change result")?;
        let evaluation = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &control,
        )?;
        assert_eq!(contract.is_reset(&evaluation)?, reset);
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
        let evaluation = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &control,
        )?;
        assert_eq!(contract.is_reset(&evaluation)?, reset);
        assert_eq!(evaluation.input("input")?.data.rows(), added);
        assert_eq!(evaluation.input("removed")?.data.rows(), 0);
        assert_eq!(evaluation.checkpoint.is_none(), reset);
        assert_eq!(evaluation.previous_outputs.is_empty(), reset);
        assert_eq!(fixture.selected("support-changes", &receipt.attempt)?, [2]);
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
        .and_then(|prior| prior.changes.as_ref())
        .ok_or("saved reset target")?;
    assert!(prior.base.is_none());
    assert_eq!(
        prior
            .targets
            .iter()
            .find(|input| input.data.name == "input")
            .ok_or("saved input")?
            .data
            .rows(),
        2
    );
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
