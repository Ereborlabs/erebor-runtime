use super::*;
use araphor_query::definition::DefinitionOutput;

async fn read_scope(
    fixture: &Fixture,
    saved: &PackageResultRefV1,
    again: Option<&PackageResultRefV1>,
    sql: &str,
) -> TestResult<DefinitionOutput> {
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 30)?;
    session
        .register_retained("saved", "retained-source", saved.clone(), "data")
        .await?;
    if let Some(reference) = again {
        session
            .register_retained("again", "retained-other", reference.clone(), "data")
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
    assert_eq!(values(&output.batches)?, [7]);
    let evaluation = output
        .calls
        .values()
        .next()
        .ok_or("consumer call")?
        .evaluation();
    for input in &evaluation.inputs {
        assert_eq!(values(&input.data.batches)?, [7]);
    }
    assert_eq!(fixture.query.store().meta()?, before);
    let expected = std::iter::once(saved)
        .chain(again)
        .map(|reference| (reference.result_id.as_str(), reference.commit_revision))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        output
            .snapshot
            .results()
            .map(|reference| (reference.result_id.as_str(), reference.commit_revision))
            .collect::<BTreeSet<_>>(),
        expected
    );
    Ok(output)
}

fn input(output: &DefinitionOutput, name: &str) -> TestResult<sdk::Revision> {
    Ok(output
        .calls
        .values()
        .next()
        .ok_or("consumer call")?
        .evaluation()
        .input(name)?
        .revision
        .clone())
}

#[tokio::test]
async fn retained_origins_require_identity() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    const OUTPUT: usize = 64 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(OUTPUT),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&consumer("1", 1024 * 1024)?)?;
    let (source, saved) = producer(&fixture).await?;
    let other = fixture.admit("retained-other", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(9 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = other
        .run(request("other"), &AnalysisReadControl::default())
        .await?;
    let again = receipt
        .results
        .values()
        .next()
        .ok_or("other source receipt")?
        .clone();
    fixture.context(1)?;
    let baseline = fixture.query.memory().input_reserved();

    let direct = read_scope(&fixture, &saved, None, "SELECT value FROM saved").await?;
    let original = input(&direct, "left_input")?;
    assert_eq!(original.owner, "runtime-fixture.accumulate");
    assert_eq!(
        original.id,
        format!("{}:{}", saved.result_id, saved.commit_revision)
    );
    assert_eq!(input(&direct, "right_input")?, original);
    assert!(!direct
        .snapshot
        .contexts()
        .any(|context| context.key.owner_id == "instance-context"));
    drop(direct);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);

    let sql = "WITH unused AS (SELECT * FROM context_versions) SELECT value FROM saved";
    let declared = read_scope(&fixture, &saved, None, sql).await?;
    assert!(declared.snapshot.contexts().any(
        |context| context.key.owner_id == "instance-context" && context.key.owner_revision == 1
    ));
    let first = input(&declared, "left_input")?;
    assert_ne!(
        first, original,
        "an elided context declaration must derive the input revision"
    );
    assert_eq!(input(&declared, "right_input")?, original);
    drop(declared);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    fixture.context(2)?;
    let changed = read_scope(&fixture, &saved, None, sql).await?;
    assert!(changed.snapshot.contexts().any(
        |context| context.key.owner_id == "instance-context" && context.key.owner_revision == 2
    ));
    assert_ne!(
        input(&changed, "left_input")?,
        first,
        "changed declared context must change revision with unchanged selected rows"
    );
    assert_eq!(input(&changed, "right_input")?, original);
    drop(changed);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);

    let sql = "WITH unused AS (SELECT value FROM again) SELECT value FROM saved";
    let declared = read_scope(&fixture, &saved, Some(&again), sql).await?;
    let first = input(&declared, "left_input")?;
    assert_ne!(
        first, original,
        "an elided second alias must remain part of input provenance"
    );
    assert_eq!(input(&declared, "right_input")?, original);
    drop(declared);
    let receipt = other
        .run(request("changed"), &AnalysisReadControl::default())
        .await?;
    let next = receipt
        .results
        .values()
        .next()
        .ok_or("changed source receipt")?
        .clone();
    assert_ne!(next, again);
    assert_eq!(fixture.selected("retained-other", "changed")?, [18]);
    let changed = read_scope(&fixture, &saved, Some(&next), sql).await?;
    assert_ne!(
        input(&changed, "left_input")?,
        first,
        "changed elided alias pin must change revision with unchanged selected rows"
    );
    assert_eq!(input(&changed, "right_input")?, original);
    drop(changed);
    let direct = read_scope(&fixture, &saved, None, "SELECT value FROM saved").await?;
    assert_eq!(input(&direct, "left_input")?, original);
    drop(direct);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop((source, other));
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
