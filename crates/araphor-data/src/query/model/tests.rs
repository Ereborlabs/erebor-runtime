use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::UInt64Array;

use super::*;
use crate::query::tests::QueryFixture;
use crate::{AnalysisSelectionV1, QueryLimits};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn port(name: &str, column: &str) -> sdk::Port {
    sdk::Port::new(
        name,
        sdk::Schema::new(vec![sdk::Field::new(column, sdk::DataType::UInt64, false)]),
    )
}

fn batch(port: &sdk::Port, rows: Vec<u64>) -> sdk::Result<sdk::RecordBatch> {
    Ok(sdk::RecordBatch::try_new(
        Arc::new(port.schema.clone()),
        vec![Arc::new(UInt64Array::from(rows))],
    )?)
}

fn control() -> crate::Result<AnalysisReadControl> {
    AnalysisReadControl::with_timeout(Duration::from_secs(30))
}

#[test]
fn sql_model_state_provenance() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits {
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let events = port("events", "id");
    let mut counts = port("counts", "count");
    counts.evidence_required = true;
    let mut model = sdk::Model::new("count", vec![events.clone()], vec![counts.clone()]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![port("state", "count")],
    });
    model.reasons.push(sdk::Reason {
        code: "denials.repeated".into(),
        details: counts.schema.clone(),
    });
    model.reasons.push(sdk::Reason {
        code: "denials.empty".into(),
        details: sdk::Schema::empty(),
    });
    let package = sdk::Package::new("denials", "1", vec![model.clone()]);
    let evaluation = sdk::Evaluation {
        export: "count".into(),
        parameters: None,
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "events".into(),
                batches: vec![batch(&events, vec![1, 2, 3])?],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        context: sdk::EvaluationContext {
            id: "run".into(),
            time_utc_ns: 100,
            seed: None,
            limits: model.limits,
        },
        checkpoint: Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![sdk::Dataset {
                name: "state".into(),
                batches: vec![batch(&port("state", "count"), vec![9])?],
            }],
        }),
    };
    let program = SqlModelV1 {
        outputs: BTreeMap::from([("counts".into(), "SELECT CAST(COUNT(*) AS UBIGINT) AS count FROM events".into())]),
        checkpoint: BTreeMap::from([("state".into(), "SELECT count FROM prior_state".into())]),
        evidence: Some("SELECT 'counts' AS output_dataset, CAST(0 AS UBIGINT) AS output_row, 'events' AS input_dataset, __row_index AS input_row FROM events".into()),
        reasons: vec![SqlReasonV1 { output: "counts".into(), code: "denials.repeated".into(), sql: "SELECT __row_index AS output_row, count FROM output_counts".into() }, SqlReasonV1 { output: "counts".into(), code: "denials.empty".into(), sql: "SELECT __row_index AS output_row FROM output_counts".into() }],
    };
    let result = owner.evaluate_model([1; 16], &package, &program, &evaluation, &control()?)?;
    assert_eq!(result.output.evidence.len(), 3);
    assert_eq!(result.output.reasons.len(), 2);
    assert_eq!(result.output.reasons[1].details.num_rows(), 1);
    assert_eq!(
        result.output.datasets[0].batches[0],
        batch(&counts, vec![3])?
    );
    assert_eq!(
        result
            .output
            .checkpoint
            .as_ref()
            .ok_or("checkpoint")?
            .datasets[0]
            .batches[0],
        batch(&port("state", "count"), vec![9])?
    );
    let mut bad = program.clone();
    bad.evidence = Some("SELECT 'counts' AS output_dataset, CAST(0 AS UBIGINT) AS output_row, 'events' AS input_dataset, CAST(99 AS UBIGINT) AS input_row".into());
    drop(result);
    let mut reused = program.clone();
    reused
        .checkpoint
        .insert("state".into(), "SELECT * FROM output_counts".into());
    let reused = owner.evaluate_model([1; 16], &package, &reused, &evaluation, &control()?)?;
    assert_eq!(
        reused
            .output
            .checkpoint
            .as_ref()
            .ok_or("checkpoint reuse")?
            .datasets[0]
            .batches[0],
        batch(&port("state", "count"), vec![3])?
    );
    drop(reused);
    assert!(owner
        .evaluate_model([1; 16], &package, &bad, &evaluation, &control()?)
        .is_err());
    for sql in [
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT * FROM events; DROP TABLE events",
        "SELECT * FROM absent",
    ] {
        bad.outputs.insert("counts".into(), sql.into());
        assert!(QueryOwner::admit_model(&model, &bad).is_err());
    }
    Ok(())
}

#[test]
fn sql_model_source_bounds() -> TestResult {
    let fixture = QueryFixture::new()?;
    for cursor in 1..=3 {
        fixture.event(cursor, cursor * 100, 7)?;
    }
    let owner = fixture.owner(QueryLimits {
        output_rows: 1,
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let selection =
        AnalysisSelectionV1::new(fixture.source.tenant_id, vec![fixture.source.clone()]);
    let port = port("events", "id");
    let sql = QuerySql::admit(
        "SELECT source_cursor AS id FROM events ORDER BY source_cursor",
        Vec::new(),
        false,
    )?;
    let first = owner.model_input(
        SqlModelInputRequestV1 {
            selection: selection.clone(),
            sql: sql.clone(),
            port: &port,
            limits: sdk::Limits::default(),
            now_ns: 1000,
        },
        &control()?,
    )?;
    assert_eq!(
        first
            .input
            .data
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        3
    );
    assert_eq!(first.witnesses.len(), 3);
    for relation in [
        "events",
        "source_receipts",
        "coverage",
        "expired_ranges",
        "recovery_gaps",
    ] {
        assert!(first
            .source_revisions
            .contains(&(relation.into(), first.meta.commit_revision)));
    }
    assert!(!first
        .source_revisions
        .iter()
        .any(|(name, _)| name == "analysis_results"));
    let second = owner.model_input(
        SqlModelInputRequestV1 {
            selection: selection.clone(),
            sql: sql.clone(),
            port: &port,
            limits: sdk::Limits::default(),
            now_ns: 2000,
        },
        &control()?,
    )?;
    assert_eq!(first.input.revision, second.input.revision);
    let result = owner.query_datasets(
        fixture.source.tenant_id,
        std::slice::from_ref(&first.input.data),
        "SELECT * FROM events WHERE id > 1 ORDER BY id",
        sdk::Limits::default(),
        &control()?,
    )?;
    assert_eq!(result.data.batches[0].num_columns(), 1);
    assert_eq!(result.data.batches[0].num_rows(), 2);
    drop(result);
    let mut corrected = selection;
    corrected.received_until = std::ops::Bound::Included(200);
    let third = owner.model_input(
        SqlModelInputRequestV1 {
            selection: corrected,
            sql,
            port: &port,
            limits: sdk::Limits::default(),
            now_ns: 2000,
        },
        &control()?,
    )?;
    assert_ne!(first.input.revision, third.input.revision);
    assert_eq!(third.input.data.batches[0].num_rows(), 2);
    assert_ne!(third.input.coverage.state, sdk::CoverageState::Complete);
    Ok(())
}

#[test]
fn sql_model_exact_parameters() -> TestResult {
    let schema = sdk::Schema::new(vec![
        sdk::Field::new("unsigned", sdk::DataType::UInt64, false),
        sdk::Field::new("signed", sdk::DataType::Int64, false),
    ]);
    let valid = serde_json::json!({"unsigned": u64::MAX, "signed": i64::MIN});
    let batch = QueryOwner::model_parameters(&schema, Some(&valid))?.ok_or("parameters")?;
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("uint")?
            .value(0),
        u64::MAX
    );
    for invalid in [
        serde_json::json!({"unsigned":1.5,"signed":0}),
        serde_json::json!({"unsigned":-1,"signed":0}),
        serde_json::json!({"unsigned":1,"signed":0,"unknown":1}),
        serde_json::json!({"unsigned":1}),
    ] {
        assert!(QueryOwner::model_parameters(&schema, Some(&invalid)).is_err());
    }
    Ok(())
}

mod clock;
mod types;
