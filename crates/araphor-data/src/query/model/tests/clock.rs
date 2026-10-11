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
    Ok(())
}
