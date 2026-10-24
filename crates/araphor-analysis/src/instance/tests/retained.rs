mod expiry;
mod guards;
mod origins;
mod projections;
mod revisions;

use super::*;

use araphor_data::analysis::PackageResultRefV1;
use araphor_query::definition::Invocation;
use araphor_query::Failure;

fn consumer(revision: &str) -> TestResult<PackageBundleV1> {
    let mut image = bundle("sql")?;
    let artifact = &mut image.artifacts[0];
    artifact.descriptor.id = "retained-consumer".into();
    artifact.descriptor.revision = revision.into();
    let model = &mut artifact.descriptor.exports[0];
    model.name = "echo".into();
    model.inputs = ["left_input", "right_input"]
        .into_iter()
        .map(|name| sdk::InputPort {
            port: sdk::Port::new(name, model.outputs[0].schema.clone()),
            source: sdk::InputSource::Table(sdk::TableRef::Named(name.into())),
        })
        .collect();
    model.checkpoint = None;
    model.reasons.clear();
    artifact.implementations = vec![PackageImplementationV1::Sql {
        export: "echo".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([("data".into(), "SELECT value FROM left_input".into())]),
            evidence: Some("SELECT 'data' AS output_dataset, __row_index AS output_row, 'left_input' AS input_dataset, __row_index AS input_row FROM left_input".into()),
            ..Default::default()
        },
    }];
    image.root = artifact.reference();
    Ok(image)
}

fn sql(revision: &str) -> String {
    format!(
        r#"SELECT * FROM "retained-consumer"."{revision}".echo(left_input => (SELECT value FROM saved), right_input => (SELECT value FROM again))"#
    )
}

async fn producer(fixture: &Fixture) -> TestResult<(Arc<Instance>, PackageResultRefV1)> {
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("retained-source", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("source"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("source call receipt")?
        .clone();
    Ok((instance, reference))
}

fn invocation() -> Invocation {
    Invocation {
        id: "retained".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn retained_alias_keeps_identity() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&consumer("1")?)?;
    let (source, reference) = producer(&fixture).await?;
    let original = fixture.query.store().managed_result(
        source.admitted(),
        &reference.result_id,
        30,
        &AnalysisReadControl::default(),
    )?;
    let coverage = original.context.coverage.clone();
    drop(original);
    let baseline = fixture.query.memory().input_reserved();
    let before = fixture.query.store().meta()?;
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    for name in ["saved", "again"] {
        session
            .register_retained(name, "retained-source", reference.clone(), "data")
            .await?;
    }
    let prepared = session
        .prepare_definition(&Fixture::definition(&sql("1")))
        .await?;
    assert!(prepared
        .images()
        .all(|(image, _)| image.root.package_id == "retained-consumer"));
    let captured = session.capture_definition(&prepared, invocation()).await?;
    assert_eq!(
        captured.snapshot().results().collect::<Vec<_>>(),
        [&reference]
    );
    assert!(captured.snapshot().witnesses.is_empty());
    drop(prepared);
    let output = captured.execute().await?;
    assert_eq!(values(&output.batches)?, [7]);
    assert_eq!(output.calls.len(), 1);
    let evaluation = output
        .calls
        .values()
        .next()
        .ok_or("consumer call")?
        .evaluation();
    assert_eq!(evaluation.export, "echo");
    assert_eq!(
        evaluation
            .inputs
            .iter()
            .map(|input| input.data.name.as_str())
            .collect::<Vec<_>>(),
        ["left_input", "right_input"]
    );
    for input in &evaluation.inputs {
        assert_eq!(values(&input.data.batches)?, [7]);
        assert_eq!(
            input.revision,
            sdk::Revision {
                owner: "runtime-fixture.accumulate".into(),
                id: format!("{}:{}", reference.result_id, reference.commit_revision),
                window: None,
            }
        );
        assert_eq!(input.coverage, coverage);
    }
    let buffer = |slot: usize| {
        evaluation.inputs[slot].data.batches[0]
            .column(0)
            .to_data()
            .buffers()[0]
            .as_ptr()
    };
    assert_eq!(buffer(0), buffer(1));
    let alias = evaluation.inputs[0].data.batches[0].clone();
    assert_eq!(fixture.query.store().meta()?, before);
    drop(output);
    drop(session);
    assert!(fixture.query.memory().input_reserved() > baseline);
    assert_eq!(values(std::slice::from_ref(&alias))?, [7]);
    drop(alias);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn retained_alias_fences_head() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (source, reference) = producer(&fixture).await?;
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    session
        .register_retained("saved", "retained-source", reference.clone(), "data")
        .await?;
    let definition = Fixture::definition("SELECT value FROM saved");
    let first = session.prepare_definition(&definition).await?;
    let output = session.execute_definition(&first, invocation()).await?;
    assert_eq!(values(&output.batches)?, [7]);
    assert!(output.calls.is_empty());
    drop(output);
    let mut changed = request("replacement");
    changed.rebuild = true;
    let receipt = source.run(changed, &control).await?;
    let next = receipt
        .results
        .values()
        .next()
        .ok_or("replacement receipt")?
        .clone();
    assert_ne!(next, reference);
    session
        .register_retained("saved", "retained-source", next.clone(), "data")
        .await?;
    let held = fixture.query.memory().input_reserved();
    let before = fixture.query.store().meta()?;
    let error = session
        .capture_definition(&first, invocation())
        .await
        .err()
        .ok_or("stale pin captured")?;
    assert_eq!(Failure::from(&error), Failure::StorageUnavailable);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    let second = session.prepare_definition(&definition).await?;
    let output = session.execute_definition(&second, invocation()).await?;
    assert_eq!(values(&output.batches)?, [7]);
    assert_eq!(output.snapshot.results().collect::<Vec<_>>(), [&next]);
    assert!(output.calls.is_empty());
    drop(output);
    let mut changed = first.clone();
    changed.plan = second.plan.clone();
    let error = session
        .capture_definition(&changed, invocation())
        .await
        .err()
        .ok_or("unadmitted retained provider captured")?;
    assert_eq!(Failure::from(&error), Failure::InvalidQuery);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn retained_alias_checks_scope() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&consumer("1")?)?;
    let (_, reference) = producer(&fixture).await?;
    let control = AnalysisReadControl::default();
    let mut denied =
        fixture
            .query
            .session(AnalysisSelectionV1::new([1; 16], Vec::new()), &control, 30)?;
    let before = fixture.query.store().meta()?;
    let error = denied
        .register_retained("saved", "retained-source", reference.clone(), "data")
        .await
        .err()
        .ok_or("narrow source scope admitted")?;
    assert_eq!(Failure::from(&error), Failure::Denied);
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    for name in ["saved", "again"] {
        session
            .register_retained(name, "retained-source", reference.clone(), "data")
            .await?;
    }
    let prepared = session
        .prepare_definition(&Fixture::definition(&sql("1")))
        .await?;
    let output = session.execute_definition(&prepared, invocation()).await?;
    let (&call, result) = output.calls.first_key_value().ok_or("consumer call")?;
    let mut supplied = invocation();
    supplied
        .inputs
        .insert(call, result.evaluation().inputs.clone());
    let error = session
        .capture_definition(&prepared, supplied)
        .await
        .err()
        .ok_or("supplied retained provenance accepted")?;
    assert_eq!(Failure::from(&error), Failure::InvalidQuery);
    let derived = session
        .prepare_definition(&Fixture::definition(&sql("1").replace(
            "SELECT value FROM saved",
            "SELECT value FROM saved WHERE value = 7",
        )))
        .await?;
    let derived = session.execute_definition(&derived, invocation()).await?;
    let derived = derived
        .calls
        .values()
        .next()
        .ok_or("derived input")?
        .evaluation();
    assert_eq!(values(&derived.inputs[0].data.batches)?, [7]);
    assert_ne!(
        derived.inputs[0].revision,
        result.evaluation().inputs[0].revision
    );
    assert_eq!(
        derived.inputs[1].revision,
        result.evaluation().inputs[1].revision
    );
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn retained_alias_counts_inputs() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&consumer("1")?)?;
    let rows = (0..256)
        .map(|value| format!("({value})"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = fixture
        .admit(
            "retained-source",
            &format!(
                r#"SELECT * FROM "retained-consumer"."1".echo(
                    left_input => (SELECT CAST(value AS BIGINT UNSIGNED) AS value FROM (VALUES {rows}) AS supplied(value)),
                    right_input => (SELECT CAST(0 AS BIGINT UNSIGNED) AS value))"#,
            ),
        )
        .await?;
    let receipt = source
        .run(request("source"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("source call receipt")?
        .clone();
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    for name in ["saved", "again"] {
        session
            .register_retained(name, "retained-source", reference.clone(), "data")
            .await?;
    }
    let first = session
        .prepare_definition(&Fixture::definition(&sql("1")))
        .await?;
    let before = fixture.query.store().meta()?;
    let output = session.execute_definition(&first, invocation()).await?;
    let evaluation = output
        .calls
        .values()
        .next()
        .ok_or("consumer call")?
        .evaluation();
    assert_eq!(evaluation.inputs.len(), 2);
    let sizes = evaluation
        .inputs
        .iter()
        .map(|input| {
            input
                .data
                .batches
                .iter()
                .map(sdk::RecordBatch::get_array_memory_size)
                .sum::<usize>()
        })
        .collect::<Vec<_>>();
    assert_eq!(sizes[0], sizes[1]);
    assert_eq!(
        values(&evaluation.inputs[0].data.batches)?,
        (0..256).collect::<Vec<_>>()
    );
    assert_eq!(
        evaluation.inputs[0].data.batches.len(),
        evaluation.inputs[1].data.batches.len()
    );
    for (left, right) in evaluation.inputs[0]
        .data
        .batches
        .iter()
        .zip(&evaluation.inputs[1].data.batches)
    {
        assert_eq!(
            left.column(0).to_data().buffers()[0].as_ptr(),
            right.column(0).to_data().buffers()[0].as_ptr()
        );
    }
    assert_eq!(fixture.query.store().meta()?, before);
    drop(output);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    let healthy = session
        .prepare_definition(&Fixture::definition(
            "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
        ))
        .await?;
    assert_eq!(
        values(
            &session
                .execute_definition(&healthy, invocation())
                .await?
                .batches
        )?,
        [1]
    );
    Ok(())
}

#[tokio::test]
async fn retained_alias_rejects_managed() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (source, reference) = producer(&fixture).await?;
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    session
        .register_retained("saved", "retained-source", reference, "data")
        .await?;
    let prepared = session
        .prepare_definition(&Fixture::definition("SELECT value FROM saved"))
        .await?;
    let before = fixture.query.store().meta()?;
    let error = session
        .capture_managed(
            &prepared,
            invocation(),
            araphor_data::ManagedRead {
                expected: None,
                instance: source.admitted().clone(),
                rebuild: false,
                completed: None,
            },
        )
        .await
        .err()
        .ok_or("unrecorded managed alias accepted")?;
    assert_eq!(Failure::from(&error), Failure::Unsupported);
    assert_eq!(fixture.query.store().meta()?, before);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
