use super::*;
use araphor_query::definition::DefinitionOutput;

async fn read_pair(
    fixture: &Fixture,
    left: &PackageResultRefV1,
    right: &PackageResultRefV1,
    reverse: bool,
    sql: &str,
) -> TestResult<DefinitionOutput> {
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    let bindings = [
        ("saved", "retained-source", left),
        ("again", "retained-second", right),
    ];
    for slot in if reverse { [1, 0] } else { [0, 1] } {
        let (alias, instance, reference) = bindings[slot];
        session
            .register_retained(alias, instance, reference.clone(), "data")
            .await?;
    }
    let sql = format!(
        r#"SELECT * FROM "retained-consumer"."1".echo(left_input => ({sql}), right_input => (SELECT value FROM saved))"#
    );
    let before = fixture.query.store().meta()?;
    let prepared = session
        .prepare_definition(&Fixture::definition(&sql))
        .await?;
    let output = session.execute_definition(&prepared, invocation()).await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        output
            .snapshot
            .results()
            .map(|result| (result.result_id.as_str(), result.commit_revision))
            .collect::<BTreeSet<_>>(),
        [
            (left.result_id.as_str(), left.commit_revision),
            (right.result_id.as_str(), right.commit_revision)
        ]
        .into_iter()
        .collect(),
    );
    Ok(output)
}

fn revision(output: &DefinitionOutput) -> TestResult<&sdk::Revision> {
    Ok(&output
        .calls
        .values()
        .next()
        .ok_or("consumer call")?
        .evaluation()
        .input("left_input")?
        .revision)
}

#[tokio::test]
async fn retained_revisions_ignore_slots() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        output_capacity: Some(64 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&consumer("1")?)?;
    let (source, first) = producer(&fixture).await?;
    let second = fixture.admit("retained-second", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(9 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = second
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    let other = receipt
        .results
        .values()
        .next()
        .ok_or("second receipt")?
        .clone();
    assert_eq!(fixture.selected("retained-source", "source")?, [7]);
    assert_eq!(fixture.selected("retained-second", "second")?, [9]);
    let baseline = fixture.query.memory().input_reserved();
    let sql = "SELECT saved.value + again.value AS value FROM saved CROSS JOIN again";
    let forward = read_pair(&fixture, &first, &other, false, sql).await?;
    let reverse = read_pair(&fixture, &first, &other, true, sql).await?;
    for output in [&forward, &reverse] {
        assert_eq!(values(&output.batches)?, [16]);
        let evaluation = output
            .calls
            .values()
            .next()
            .ok_or("consumer call")?
            .evaluation();
        assert_eq!(values(&evaluation.input("left_input")?.data.batches)?, [16]);
        assert_eq!(values(&evaluation.input("right_input")?.data.batches)?, [7]);
        assert_ne!(
            revision(output)?,
            &evaluation.input("right_input")?.revision
        );
        assert_eq!(
            evaluation.input("right_input")?.revision.id,
            format!("{}:{}", first.result_id, first.commit_revision)
        );
    }
    assert_eq!(
        revision(&forward)?,
        revision(&reverse)?,
        "registration slots must not change a derived input revision"
    );
    let original = revision(&forward)?.clone();
    drop((forward, reverse));
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop(fixture.query.reserve_evaluation([1; 16])?);

    let transformed = read_pair(&fixture, &first, &other, false, "SELECT saved.value + again.value + CAST(1 AS BIGINT UNSIGNED) AS value FROM saved CROSS JOIN again").await?;
    assert_eq!(values(&transformed.batches)?, [17]);
    assert_ne!(revision(&transformed)?, &original);
    drop(transformed);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);

    let mut rebuild = request("same-value");
    rebuild.rebuild = true;
    let receipt = source.run(rebuild, &AnalysisReadControl::default()).await?;
    let replacement = receipt
        .results
        .values()
        .next()
        .ok_or("same-value receipt")?
        .clone();
    assert_ne!(replacement, first);
    assert_eq!(fixture.selected("retained-source", "same-value")?, [7]);
    let changed = read_pair(&fixture, &replacement, &other, false, sql).await?;
    assert_eq!(values(&changed.batches)?, [16]);
    assert_ne!(
        revision(&changed)?,
        &original,
        "equal rows must retain the changed source pin"
    );
    let repinned = revision(&changed)?.clone();
    drop(changed);

    let receipt = second
        .run(request("changed-value"), &AnalysisReadControl::default())
        .await?;
    let next = receipt
        .results
        .values()
        .next()
        .ok_or("changed-value receipt")?
        .clone();
    assert_eq!(fixture.selected("retained-second", "changed-value")?, [18]);
    let changed = read_pair(&fixture, &replacement, &next, true, sql).await?;
    assert_eq!(values(&changed.batches)?, [25]);
    assert_ne!(revision(&changed)?, &repinned);
    drop(changed);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
