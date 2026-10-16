use super::*;

#[test]
fn model_clock_dependencies() -> TestResult {
    let mut model = sdk::Model::new("count", Vec::new(), vec![port("rows", "count")]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![port("state", "count")],
    });
    model.reasons.push(sdk::Reason {
        code: "expired".into(),
        details: sdk::Schema::empty(),
    });
    let program = SqlModelV1 {
        outputs: BTreeMap::from([(
            "rows".into(),
            "SELECT length('CURRENT_TIMESTAMP') AS count".into(),
        )]),
        checkpoint: BTreeMap::from([("state".into(), "SELECT count FROM output_rows".into())]),
        ..Default::default()
    };
    assert!(!program.uses_clock(&model)?);
    for location in 0..4 {
        let mut clocked = program.clone();
        let sql = "SELECT CURRENT_TIMESTAMP AS count".to_owned();
        match location {
            0 => {
                clocked.outputs.insert("rows".into(), sql);
            }
            1 => {
                clocked.checkpoint.insert("state".into(), sql);
            }
            2 => {
                clocked.evidence = Some(sql);
            }
            _ => clocked.reasons.push(SqlReasonV1 {
                output: "rows".into(),
                code: "expired".into(),
                sql,
            }),
        }
        assert!(clocked.uses_clock(&model)?);
    }
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: port("source", "count"),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        })),
    });
    for (sql, expected) in [
        (
            "SELECT count + length('CURRENT_TIMESTAMP') AS count FROM source",
            false,
        ),
        (
            "SELECT CASE WHEN CURRENT_TIMESTAMP IS NULL THEN 0 ELSE count END AS count FROM source",
            true,
        ),
    ] {
        let mut sourced = model.clone();
        sourced.inputs.push(sdk::InputPort {
            port: port("selected", "count"),
            source: sdk::InputSource::Query(sql.into()),
        });
        assert_eq!(QueryOwner::inputs_use_clock(&sourced)?, expected);
        assert!(!program.uses_clock(&sourced)?);
    }
    for source in [
        sdk::InputSource::Table(sdk::TableRef::Named("notifications".into())),
        sdk::InputSource::Query(
            "SELECT notification_revision FROM notifications WHERE overdue".into(),
        ),
        sdk::InputSource::Query(
            "WITH unused AS (SELECT notification_revision FROM notifications) SELECT 1::BIGINT UNSIGNED AS notification_revision".into(),
        ),
    ] {
        let mut sourced = model.clone();
        sourced.inputs.push(sdk::InputPort {
            port: port("notices", "notification_revision"),
            source,
        });
        assert!(QueryOwner::inputs_use_clock(&sourced)?);
        assert!(!program.uses_clock(&sourced)?);
    }
    Ok(())
}

#[test]
fn model_output_deadline() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits {
        evaluate_timeout: Duration::from_millis(100),
        ..Default::default()
    })?;
    let rows = port("rows", "count");
    let model = sdk::Model::new("count", Vec::new(), vec![rows.clone()]);
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        parameters: None,
        inputs: Vec::new(),
        context: sdk::EvaluationContext {
            id: "deadline".into(),
            time_utc_ns: 100,
            seed: None,
            limits: model.limits,
        },
        checkpoint: None,
    };
    let package = sdk::Package::new("deadline", "1", vec![model]);
    let output = sdk::Output {
        datasets: vec![sdk::Dataset {
            name: rows.name.clone(),
            batches: vec![batch(&rows, vec![1])?],
        }],
        ..Default::default()
    };
    let bytes = output.allocated_bytes();
    let caller = control()?;
    let result = owner.evaluate_model_reserved(
        &package,
        &evaluation,
        &caller,
        |capacity| owner.budget.model([1; 16], capacity),
        |model, local, _, _| {
            assert!(std::ptr::eq(model, &package.exports[0]));
            std::thread::sleep(local.remaining()? + Duration::from_millis(1));
            Ok((output.clone(), bytes))
        },
    );
    assert!(matches!(
        result,
        Err(crate::Error::AnalysisReadDeadline { .. })
    ));
    caller.check()?;
    let result = owner.evaluate_model_reserved(
        &package,
        &evaluation,
        &caller,
        |capacity| owner.budget.model([1; 16], capacity),
        |_, _, _, _| Ok((output, bytes)),
    )?;
    assert_eq!(result.output.datasets[0].batches[0].num_rows(), 1);
    Ok(())
}
