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
    let mut supplied = package.clone();
    supplied.exports[0].input_mode = sdk::InputMode::Resolved;
    supplied.exports[0].inputs[0].source =
        sdk::InputSource::Query("SELECT missing FROM absent".into());
    assert!(AdmittedExport::admit(&supplied.exports[0], Some(&program)).is_err());
    let supplied = owner.evaluate_model([1; 16], &supplied, &program, &evaluation, &control()?)?;
    assert_eq!(
        supplied.output.datasets[0].batches[0],
        batch(&counts, vec![3])?
    );
    drop(supplied);
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
    let mut model = sdk::Model::new("source", Vec::new(), vec![port.clone()]);
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: port.clone(),
        source: sdk::InputSource::Query(
            "SELECT source_cursor AS id FROM events ORDER BY source_cursor".into(),
        ),
    });
    let revision = fixture.store.meta()?.commit_revision;
    let read = |selection: AnalysisSelectionV1, now| -> crate::Result<ModelInputs> {
        let active = crate::analysis::PackageActivationV1 {
            key: crate::analysis::PackageKeyV1 {
                tenant_id: selection.tenant_id,
                scope_id: "scope".into(),
                package_id: "fixture".into(),
                export: model.name.clone(),
            },
            revision: "1".into(),
            generation: 0,
            checkpoint_revision: 0,
            result_id: None,
            grant_id: "fixture".into(),
            metadata: Vec::new(),
            active: true,
        };
        let grant = crate::package::PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection,
            expires_utc_ns: None,
            authorization_id: None,
        };
        let (operation, inputs) = owner.model_operation(grant.selection.tenant_id).inputs(
            ModelInputRequest {
                activation: &active,
                model: &model,
                grant: &grant,
                now,
            },
            &control()?,
            || Ok(()),
        )?;
        assert!(matches!(
            owner.budget.component(grant.selection.tenant_id, 0, 0),
            Err(crate::Error::AnalysisBusy {
                resource: "query evaluation capacity",
                ..
            })
        ));
        operation.release_inputs()?;
        assert!(owner.input_charge() > 0);
        drop(owner.budget.component(grant.selection.tenant_id, 0, 0)?);
        Ok(inputs)
    };
    let first = read(selection.clone(), 1_000)?;
    assert_eq!(
        first.inputs[0]
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
            .contains(&(relation.into(), revision)));
    }
    assert!(!first
        .source_revisions
        .iter()
        .any(|(name, _)| name == "analysis_results"));
    let second = read(selection.clone(), 2_000)?;
    assert_eq!(first.inputs[0].revision, second.inputs[0].revision);
    let result = owner.query_datasets(
        fixture.source.tenant_id,
        std::slice::from_ref(&first.inputs[0].data),
        "SELECT * FROM events WHERE id > 1 ORDER BY id",
        sdk::Limits::default(),
        &control()?,
    )?;
    assert_eq!(result.data.batches[0].num_columns(), 1);
    assert_eq!(result.data.batches[0].num_rows(), 2);
    drop(result);
    let mut corrected = selection;
    corrected.received_until = std::ops::Bound::Included(200);
    let third = read(corrected, 2_000)?;
    assert_ne!(first.inputs[0].revision, third.inputs[0].revision);
    assert_eq!(third.inputs[0].data.batches[0].num_rows(), 2);
    assert_ne!(third.inputs[0].coverage.state, sdk::CoverageState::Complete);
    let alias = first.inputs[0].data.batches[0].column(0).slice(0, 1);
    drop((first, second, third));
    assert!(owner.input_charge() > 0);
    assert_eq!(
        alias
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("model input index")?
            .value(0),
        1
    );
    drop(owner.budget.component(fixture.source.tenant_id, 0, 0)?);
    drop(alias);
    assert_eq!(owner.input_charge(), 0);
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

#[test]
fn admitted_program_order() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits {
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let mut model = sdk::Model::new(
        "ordered",
        Vec::new(),
        vec![port("ZRows", "count"), port("ARows", "count")],
    );
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![port("ZState", "count"), port("AState", "count")],
    });
    model.reasons = ["ordered.z", "ordered.a"]
        .map(|code| sdk::Reason {
            code: code.into(),
            details: port("details", "count").schema,
        })
        .into();
    let mut program = SqlModelV1 {
        outputs: BTreeMap::from([
            ("ARows".into(), "SELECT 9::UBIGINT AS count".into()),
            ("ZRows".into(), "SELECT 7::UBIGINT AS count".into()),
        ]),
        checkpoint: BTreeMap::from([
            ("AState".into(), "SELECT count FROM output_ARows".into()),
            ("ZState".into(), "SELECT count FROM output_ZRows".into()),
        ]),
        reasons: vec![
            SqlReasonV1 {
                output: "ARows".into(),
                code: "ordered.a".into(),
                sql: "SELECT __row_index AS output_row, count FROM output_ARows".into(),
            },
            SqlReasonV1 {
                output: "ZRows".into(),
                code: "ordered.z".into(),
                sql: "SELECT __row_index AS output_row, count FROM output_ZRows".into(),
            },
        ],
        ..Default::default()
    };
    for (output, code) in [("missing", "ordered.a"), ("ARows", "missing")] {
        let mut invalid = program.clone();
        invalid.reasons[0].output = output.into();
        invalid.reasons[0].code = code.into();
        assert!(QueryOwner::admit_model(&model, &invalid).is_err());
    }
    let mut admitted = AdmittedExport::admit(&model, Some(&program))?;
    let before = admitted.allocated_bytes();
    let growth = {
        let plan = admitted.model.as_mut().ok_or("admitted model")?;
        assert_eq!(plan.outputs[0].original(), program.outputs["ZRows"]);
        assert_eq!(plan.outputs[1].original(), program.outputs["ARows"]);
        assert_eq!(plan.checkpoint[0].original(), program.checkpoint["ZState"]);
        assert_eq!(plan.checkpoint[1].original(), program.checkpoint["AState"]);
        assert_eq!((plan.reasons[0].0, plan.reasons[0].1), (1, 1));
        assert_eq!((plan.reasons[1].0, plan.reasons[1].1), (0, 0));
        let mut growth = 0;
        for statements in [&mut plan.outputs, &mut plan.checkpoint] {
            let capacity = statements.capacity();
            statements.reserve_exact(8);
            growth += (statements.capacity() - capacity) * std::mem::size_of::<QuerySql>();
        }
        let capacity = plan.reasons.capacity();
        plan.reasons.reserve_exact(8);
        growth +=
            (plan.reasons.capacity() - capacity) * std::mem::size_of::<(usize, usize, QuerySql)>();
        growth
    };
    assert_eq!(admitted.allocated_bytes(), before + growth);
    program.outputs.clear();
    program.checkpoint.clear();
    program.reasons.clear();
    let package = sdk::Package::new("ordered", "1", vec![model.clone()]);
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: Vec::new(),
        parameters: None,
        context: sdk::EvaluationContext {
            id: "ordered".into(),
            time_utc_ns: 100,
            seed: None,
            limits: model.limits,
        },
        checkpoint: None,
    };
    let output = owner.model_operation([1; 16]).evaluate_admitted(
        &package,
        &admitted,
        &evaluation,
        &control()?,
    )?;
    for (index, expected) in [7, 9].into_iter().enumerate() {
        let data = &output.output.datasets[index];
        assert_eq!(data.name, model.outputs[index].name);
        assert_eq!(
            data.batches,
            vec![batch(&model.outputs[index], vec![expected])?]
        );
    }
    let checkpoint = output.output.checkpoint.as_ref().ok_or("checkpoint")?;
    for (index, expected) in [7, 9].into_iter().enumerate() {
        let port = &model.checkpoint.as_ref().ok_or("checkpoint spec")?.datasets[index];
        assert_eq!(checkpoint.datasets[index].name, port.name);
        assert_eq!(
            checkpoint.datasets[index].batches,
            vec![batch(port, vec![expected])?]
        );
    }
    assert_eq!(output.output.reasons.len(), 2);
    for (reason, (dataset, code, value)) in output
        .output
        .reasons
        .iter()
        .zip([("ARows", "ordered.a", 9), ("ZRows", "ordered.z", 7)])
    {
        assert_eq!(
            reason.output,
            sdk::RowRef {
                dataset: dataset.into(),
                row: 0
            }
        );
        assert_eq!(reason.code, code);
        assert_eq!(
            reason.details,
            batch(&port("details", "count"), vec![value])?
        );
    }
    drop(output);
    for (output, reason) in [(usize::MAX, 1), (1, usize::MAX)] {
        let plan = admitted.model.as_mut().ok_or("admitted model")?;
        (plan.reasons[0].0, plan.reasons[0].1) = (output, reason);
        assert!(matches!(
            owner.model_operation([1; 16]).evaluate_admitted(
                &package,
                &admitted,
                &evaluation,
                &control()?
            ),
            Err(crate::Error::QueryInvalid {
                field: "model reason declaration",
                ..
            })
        ));
        assert_eq!(owner.input_charge(), 0);
    }
    let plan = admitted.model.as_mut().ok_or("admitted model")?;
    (plan.reasons[0].0, plan.reasons[0].1) = (1, 1);
    plan.outputs.pop();
    assert!(matches!(
        owner.model_operation([1; 16]).evaluate_admitted(
            &package,
            &admitted,
            &evaluation,
            &control()?
        ),
        Err(crate::Error::QueryInvalid {
            field: "model admitted output",
            ..
        })
    ));
    assert_eq!(owner.input_charge(), 0);
    Ok(())
}

mod clock;
mod types;
