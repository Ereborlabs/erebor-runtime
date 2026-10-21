use super::*;

fn wide_source() -> TestResult<PackageBundleV1> {
    let mut image = bundle("sql")?;
    image.artifacts[0].descriptor.exports[0].outputs[0].schema = sdk::Schema::new(vec![
        sdk::Field::new("value", sdk::DataType::UInt64, false),
        sdk::Field::new("second", sdk::DataType::UInt64, false),
    ]);
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL source implementation".into());
    };
    program.outputs.insert(
        "data".into(),
        "SELECT value, CAST(8 AS BIGINT UNSIGNED) AS second FROM input".into(),
    );
    Ok(image)
}

fn projected_consumer(revision: &str, fields: &[&str]) -> TestResult<PackageBundleV1> {
    let mut image = consumer(revision, 1024 * 1024)?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    let schema = sdk::Schema::new(
        fields
            .iter()
            .map(|name| sdk::Field::new(*name, sdk::DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    for input in &mut model.inputs {
        input.port.schema = schema.clone();
    }
    model.inputs[0].source = sdk::InputSource::Table(sdk::TableRef::Named("saved".into()));
    Ok(image)
}

#[tokio::test]
async fn retained_projection_derives_revision() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(2 * 1024 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&wide_source()?)?;
    let source = fixture.admit("retained-wide", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = source
        .run(request("wide"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("wide source receipt")?
        .clone();
    assert_eq!(fixture.selected("retained-wide", "wide")?, [7]);
    let original = sdk::Revision {
        owner: "runtime-fixture.accumulate".into(),
        id: format!("{}:{}", reference.result_id, reference.commit_revision),
        window: None,
    };
    let cases: [(&str, &[&str], bool); 3] = [
        ("narrow", &["value"], false),
        ("reordered", &["second", "value"], false),
        ("identity", &["value", "second"], true),
    ];
    for (revision, fields, identity) in cases {
        fixture.install(&projected_consumer(revision, fields)?)?;
        let baseline = fixture.query.memory().input_reserved();
        let before = fixture.query.store().meta()?;
        let control = AnalysisReadControl::default();
        let mut session = fixture
            .query
            .session(fixture.grant.selection.clone(), &control, 30)?;
        session
            .register_retained("saved", "retained-wide", reference.clone(), "data")
            .await?;
        let sql = format!(
            r#"SELECT * FROM "retained-consumer"."{revision}".echo(right_input => (SELECT {} FROM saved))"#,
            fields.join(", ")
        );
        let prepared = session
            .prepare_definition(&Fixture::definition(&sql))
            .await?;
        let output = session.execute_definition(&prepared, invocation()).await?;
        assert_eq!(values(&output.batches)?, [7]);
        assert_eq!(output.snapshot.results().collect::<Vec<_>>(), [&reference]);
        assert_eq!(output.calls.len(), 1);
        let evaluation = output
            .calls
            .values()
            .next()
            .ok_or("projected consumer call")?
            .evaluation();
        let left = evaluation.input("left_input")?;
        let right = evaluation.input("right_input")?;
        for input in [left, right] {
            let schema = input
                .data
                .batches
                .first()
                .ok_or("projected input batch")?
                .schema();
            assert_eq!(
                schema
                    .fields()
                    .iter()
                    .map(|field| field.name().as_str())
                    .collect::<Vec<_>>(),
                fields
            );
            assert_eq!(
                values(&input.data.batches)?,
                if fields[0] == "value" { [7] } else { [8] }
            );
            assert_eq!(
                input.revision == original,
                identity,
                "only the full identity projection can preserve the original revision: {revision}"
            );
        }
        assert_eq!(
            left.revision, right.revision,
            "equivalent native projections must have the same revision"
        );
        assert_eq!(fixture.query.store().meta()?, before);
        drop(output);
        drop(prepared);
        drop(session);
        assert_eq!(fixture.query.memory().input_reserved(), baseline);
        drop(fixture.query.reserve_evaluation([1; 16])?);
    }
    Ok(())
}
