use super::*;
use araphor_data::AnalysisSelectionV1;
use sdk::arrow_array::{Array as _, UInt64Array};

use crate::definition::{CallResult, DefinitionOutput, Invocation};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::DataFusionError;
use datafusion::logical_expr::{
    col, create_udf, Extension, LogicalPlanBuilder, Partitioning, Volatility,
};
use futures_util::TryStreamExt as _;
use prost::Message as _;

const NOW: u64 = 1_700_000_000_123_456_789;

#[tokio::test]
async fn registered_arrow_package_inputs() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let mut session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    let schema = Arc::new(Fixture::schema("value"));
    let batches = [7, 11]
        .into_iter()
        .map(|value| {
            sdk::RecordBatch::try_new(
                Arc::clone(&schema),
                vec![Arc::new(UInt64Array::from(vec![value]))],
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    session.register("fixture_input", schema, &batches)?;
    let prepared = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(
                source => (SELECT * FROM fixture_input), increment => 2)"#,
        ))
        .await?;
    assert!(prepared.sources().is_empty());
    let result = session
        .execute_definition(&prepared, invocation("fixture-input"))
        .await?;
    assert_eq!(values(&result.batches)?, [9, 13]);
    assert_eq!(result.calls.len(), 1);
    assert_eq!(
        values(
            &result
                .calls
                .values()
                .next()
                .ok_or("call absent")?
                .evaluation()
                .inputs[0]
                .data
                .batches
        )?,
        [7, 11]
    );
    Ok(())
}

#[tokio::test]
async fn registered_scalar_parameter_admission() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let mut session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    for (table, field, value) in [
        ("fixture_input", "value", 7),
        ("__fixture_parameters", "increment", 2),
    ] {
        let schema = Arc::new(Fixture::schema(field));
        let batch = sdk::RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(UInt64Array::from(vec![value]))],
        )?;
        session.register(table, schema, &[batch])?;
    }
    let prepared = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(
                source => (SELECT value FROM fixture_input),
                increment => (SELECT increment FROM __fixture_parameters))"#,
        ))
        .await?;
    let output = session
        .execute_definition(&prepared, invocation("fixture-parameter"))
        .await?;
    assert_eq!(values(&output.batches)?, [9]);
    assert_eq!(output.calls.len(), 1);
    let call = output.calls.values().next().ok_or("call absent")?;
    assert_eq!(
        values(std::slice::from_ref(
            call.evaluation().parameters.as_ref().ok_or("parameters")?
        ))?,
        [2]
    );
    let state = call.output().checkpoint.as_ref().ok_or("checkpoint")?;
    assert_eq!(values(&state.datasets[0].batches)?, [9]);
    assert_eq!(call.output().evidence.len(), 1);
    assert_eq!(call.output().reasons[0].code, "fixture.note");
    assert_eq!(
        values(std::slice::from_ref(&call.output().reasons[0].details))?,
        [9]
    );
    Ok(())
}

#[tokio::test]
async fn registered_sources_cannot_shadow() -> TestResult {
    let fixture = Fixture::new()?;
    let mut session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    session.register("events", Arc::new(Fixture::schema("value")), &[])?;
    assert!(matches!(
        session
            .prepare_definition(&Fixture::sql("SELECT * FROM events"))
            .await,
        Err(crate::Error::Invalid {
            field: "definition source binding",
            ..
        })
    ));
    Ok(())
}

pub(super) fn invocation(id: &str) -> Invocation {
    Invocation {
        id: id.into(),
        seed: Some(7),
        time_utc_ns: None,
        checkpoints: BTreeMap::new(),
        inputs: BTreeMap::new(),
    }
}

fn values(batches: &[sdk::RecordBatch]) -> TestResult<Vec<u64>> {
    batches
        .iter()
        .map(|batch| {
            let values = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 output required")?;
            assert_eq!(values.null_count(), 0);
            Ok(values.values().to_vec())
        })
        .collect::<TestResult<Vec<_>>>()
        .map(|chunks| chunks.into_iter().flatten().collect())
}

fn dataset<'a>(call: &'a CallResult, name: &str) -> TestResult<&'a sdk::Dataset> {
    call.output()
        .datasets
        .iter()
        .find(|data| data.name == name)
        .ok_or_else(|| format!("output dataset absent: {name}").into())
}

fn checkpoint(total: u64) -> TestResult<sdk::Checkpoint> {
    Ok(sdk::Checkpoint {
        version: 1,
        datasets: vec![sdk::Dataset {
            name: "state".into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(Fixture::schema("value")),
                vec![Arc::new(UInt64Array::from(vec![total]))],
            )?],
        }],
    })
}

impl Fixture {
    pub(super) async fn execute(
        &self,
        prepared: &PreparedDefinition,
        invocation: Invocation,
    ) -> crate::Result<DefinitionOutput> {
        self.engine
            .session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                NOW,
            )?
            .execute_definition(prepared, invocation)
            .await
    }

    pub(super) fn event(&self, cursor: u64) -> TestResult {
        let payload = araphor_data::EvidenceRecord {
            operation: 7,
            ..Default::default()
        }
        .encode_to_vec();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        self.engine.store().accept_validated_batch(
            araphor_data::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "call-input".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: NOW - 1_000_000 + cursor,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    pub(super) fn context(&self, revision: u64) -> TestResult {
        self.engine
            .store()
            .commit_context(&araphor_data::AnalysisContextVersionV1 {
                key: araphor_data::AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "call-context".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![1],
                    owner_revision: revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                body: vec![1],
            })?;
        Ok(())
    }
}

fn gate_input(
    prepared: &mut PreparedDefinition,
    id: u64,
    entered: tokio::sync::oneshot::Sender<()>,
    released: std::sync::mpsc::Receiver<()>,
) -> TestResult {
    let entered = std::sync::Mutex::new(Some(entered));
    let released = std::sync::Mutex::new(released);
    let gate = create_udf(
        "call_input_gate",
        vec![sdk::DataType::UInt64],
        sdk::DataType::UInt64,
        Volatility::Volatile,
        Arc::new(move |arguments| {
            let entered = entered
                .lock()
                .map_err(|_| DataFusionError::Execution("test call gate lock".into()))?
                .take();
            if let Some(entered) = entered {
                let _sent = entered.send(());
                released
                    .lock()
                    .map_err(|_| DataFusionError::Execution("test call release lock".into()))?
                    .recv()
                    .map_err(|_| DataFusionError::Execution("test call gate release".into()))?;
            }
            arguments
                .first()
                .cloned()
                .ok_or_else(|| DataFusionError::Execution("test call gate input".into()))
        }),
    );
    prepared.plan = prepared
        .plan
        .clone()
        .transform_up(|plan| {
            if let LogicalPlan::Extension(extension) = &plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    if call.id() != id {
                        return Ok(Transformed::no(plan));
                    }
                    let mut children = call.children.clone();
                    children[0] = LogicalPlanBuilder::from(children[0].clone())
                        .project(vec![gate.call(vec![col("value")]).alias("value")])?
                        .build()?;
                    let mut call = call.with_exprs_and_inputs(Vec::new(), children)?;
                    call.admitted = call.children.clone().into();
                    return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                        node: Arc::new(call),
                    })));
                }
            }
            Ok(Transformed::no(plan))
        })?
        .data;
    Ok(())
}

#[tokio::test]
async fn physical_sql_return_retains_contract() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0]
        .outputs
        .push(sdk::Port::new("copy", Fixture::schema("value")));
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert(
        "copy".into(),
        "SELECT source.value + parameters.increment + CAST(1 AS BIGINT UNSIGNED) AS value \
            FROM source CROSS JOIN parameters"
            .into(),
    );
    let fixture = Fixture::installed(&bundle)?;
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count('result', source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
    );
    let prepared = fixture.prepare(&definition).await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let before = fixture.engine.store().meta()?;
    let output = fixture.execute(&prepared, invocation("complete")).await?;
    assert_eq!(values(&output.batches)?, [9]);
    assert_eq!(output.calls.len(), 1);
    let call = Arc::clone(output.calls.get(&id).ok_or("call result absent")?);
    assert_eq!(values(&dataset(&call, "result")?.batches)?, [9]);
    assert_eq!(values(&dataset(&call, "copy")?.batches)?, [10]);
    let state = call
        .output()
        .checkpoint
        .as_ref()
        .ok_or("checkpoint absent")?;
    assert_eq!(state.version, 2);
    assert_eq!(state.datasets[0].name, "state");
    assert_eq!(values(&state.datasets[0].batches)?, [9]);
    assert_eq!(call.output().evidence.len(), 1);
    assert_eq!(call.output().evidence[0].input.dataset, "source");
    assert_eq!(call.output().evidence[0].input.row, 0);
    assert_eq!(call.output().evidence[0].output.dataset, "result");
    assert_eq!(call.output().evidence[0].output.row, 0);
    assert_eq!(call.output().reasons.len(), 1);
    assert_eq!(call.output().reasons[0].code, "fixture.note");
    assert_eq!(values(&[call.output().reasons[0].details.clone()])?, [9]);
    assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
    assert_eq!(call.evaluation().context.seed, Some(7));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(fixture
        .engine
        .store()
        .active_managed(&araphor_data::AnalysisReadControl::default())?
        .1
        .is_empty());
    drop(output);
    drop(prepared);
    drop(fixture);
    assert_eq!(values(&dataset(&call, "copy")?.batches)?, [10]);
    assert_eq!(
        values(
            &call
                .output()
                .checkpoint
                .as_ref()
                .ok_or("checkpoint absent")?
                .datasets[0]
                .batches
        )?,
        [9]
    );
    Ok(())
}

async fn accumulation(target: &str) -> TestResult {
    let fixture = Fixture::installed(&component(target, "accumulate")?)?;
    assert_eq!(fixture.engine.limits(), &Limits::default());
    let before = fixture.engine.store().meta()?;
    for (source, total, repartition) in [
        (
            "SELECT value FROM (VALUES (CAST(2 AS BIGINT UNSIGNED)), \
                (CAST(3 AS BIGINT UNSIGNED)), (CAST(5 AS BIGINT UNSIGNED))) AS supplied(value)"
                .to_owned(),
            10,
            false,
        ),
        (
            "SELECT CAST(2 AS BIGINT UNSIGNED) AS value UNION ALL \
                SELECT CAST(3 AS BIGINT UNSIGNED) AS value UNION ALL \
                SELECT CAST(5 AS BIGINT UNSIGNED) AS value"
                .to_owned(),
            10,
            true,
        ),
        (
            format!(
                "SELECT value FROM (VALUES {}) AS supplied(value)",
                vec!["(CAST(1 AS BIGINT UNSIGNED))"; 201].join(", ")
            ),
            201,
            false,
        ),
        (
            "SELECT CAST(1 AS BIGINT UNSIGNED) AS value WHERE FALSE".to_owned(),
            0,
            true,
        ),
    ] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => ({source}))"#
        ));
        let mut prepared = fixture.prepare(&definition).await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        if repartition {
            prepared.plan = prepared
                .plan
                .transform_up(|plan| {
                    if let LogicalPlan::Extension(extension) = &plan {
                        if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                            let mut children = call.children.clone();
                            children[0] = LogicalPlanBuilder::from(children[0].clone())
                                .repartition(Partitioning::RoundRobinBatch(3))?
                                .build()?;
                            let mut call = call.with_exprs_and_inputs(Vec::new(), children)?;
                            call.admitted = call.children.clone().into();
                            return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                                node: Arc::new(call),
                            })));
                        }
                    }
                    Ok(Transformed::no(plan))
                })?
                .data;
        }
        let mut invocation = invocation("state");
        invocation.checkpoints.insert(id, checkpoint(100)?);
        for _ in 0..2 {
            let output = fixture.execute(&prepared, invocation.clone()).await?;
            assert_eq!(values(&output.batches)?, [100 + total], "{target}");
            assert_eq!(output.calls.len(), 1, "{target}");
            let call = output.calls.get(&id).ok_or("call result absent")?;
            assert_eq!(values(&dataset(call, "data")?.batches)?, [100 + total]);
            assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
            let state = call
                .output()
                .checkpoint
                .as_ref()
                .ok_or("checkpoint absent")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0].batches)?, [100 + total]);
            assert_eq!(fixture.engine.store().meta()?, before);
            assert!(fixture
                .engine
                .store()
                .active_managed(&araphor_data::AnalysisReadControl::default())?
                .1
                .is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn physical_sql_wasm_complete_relation() -> TestResult {
    for target in ["sql", "wasm"] {
        accumulation(target).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn physical_native_complete_relation() -> TestResult {
    accumulation("native").await
}

#[tokio::test]
async fn physical_nested_calls_share_permit() -> TestResult {
    let fixture = Fixture::limits(Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    fixture.install(&component("wasm", "count-input")?)?;
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(source => (
            SELECT value FROM "runtime-fixture"."1"."count-input"(
                input => (SELECT value FROM (VALUES (CAST(7 AS BIGINT UNSIGNED)),
                    (CAST(11 AS BIGINT UNSIGNED))) AS supplied(value)),
                mode => 'sum-input', amount => 0)), increment => 2)"#,
    );
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(prepared.resolved().images.len(), 2);
    let before = fixture.engine.store().meta()?;
    let output = fixture.execute(&prepared, invocation("nested")).await?;
    assert_eq!(values(&output.batches)?, [20]);
    assert_eq!(output.calls.len(), 2);
    for call in output.calls.values() {
        assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
        assert_eq!(call.evaluation().context.seed, Some(7));
    }
    let guest = output
        .calls
        .values()
        .find(|call| call.evaluation().export == "count-input")
        .ok_or("guest call absent")?;
    let sql = output
        .calls
        .values()
        .find(|call| call.evaluation().export == "count")
        .ok_or("SQL call absent")?;
    assert_eq!(values(&dataset(guest, "data")?.batches)?, [18]);
    assert_eq!(values(&sql.evaluation().inputs[0].data.batches)?, [18]);
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn physical_calls_keep_state_identity() -> TestResult {
    let fixture = Fixture::installed(&component("sql", "accumulate")?)?;
    let source = "SELECT CAST(2 AS BIGINT UNSIGNED) AS value";
    let prepared = fixture
        .prepare(&Fixture::sql(format!(
            r#"SELECT left_call.value AS first, right_call.value AS second
            FROM "runtime-fixture"."1".accumulate(input => ({source})) AS left_call
            CROSS JOIN "runtime-fixture"."1".accumulate(input => ({source})) AS right_call"#
        )))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].id(), calls[1].id());
    let mut request = invocation("independent");
    request.checkpoints.insert(calls[0].id(), checkpoint(10)?);
    request.checkpoints.insert(calls[1].id(), checkpoint(20)?);
    let output = fixture.execute(&prepared, request).await?;
    assert_eq!(output.calls.len(), 2);
    let mut totals = output
        .calls
        .values()
        .map(|call| values(&dataset(call, "data")?.batches))
        .collect::<TestResult<Vec<_>>>()?;
    totals.sort();
    assert_eq!(totals, [vec![12], vec![22]]);

    let prepared = fixture
        .prepare(&Fixture::sql(format!(
            r#"WITH shared AS (
                SELECT * FROM "runtime-fixture"."1".accumulate(input => ({source})))
            SELECT left_call.value + right_call.value AS value FROM shared AS left_call
            CROSS JOIN shared AS right_call"#
        )))
        .await?;
    let ids = Fixture::calls(&prepared.plan)?
        .into_iter()
        .map(|call| call.id())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 1);
    let id = *ids.first().ok_or("call ID absent")?;
    let mut request = invocation("shared");
    request.checkpoints.insert(id, checkpoint(10)?);
    let output = fixture.execute(&prepared, request).await?;
    assert_eq!(values(&output.batches)?, [24]);
    assert_eq!(output.calls.len(), 1);
    assert_eq!(values(&dataset(&output.calls[&id], "data")?.batches)?, [12]);
    Ok(())
}

#[tokio::test]
async fn physical_checkpoint_preflight() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let fixture = Fixture::installed(&component("sql", "accumulate")?)?;
    fixture.event(1)?;
    let prepared = fixture.prepare(&Fixture::sql(
        r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT source_cursor AS value FROM events))"#,
    )).await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let control = AnalysisReadControl::default();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&reads);
    control.on_read_step(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let mut request = invocation("stale-state");
    request.checkpoints.insert(
        id.checked_add(1).ok_or("call ID overflow")?,
        checkpoint(10)?,
    );
    let error = session
        .execute_definition(&prepared, request)
        .await
        .err()
        .ok_or("unknown checkpoint call succeeded")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Invalid,
                field: "invocation checkpoint call",
                ..
            }
        }
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    control.check()?;
    let mut request = invocation("known-state");
    request.checkpoints.insert(id, checkpoint(10)?);
    for _ in 0..2 {
        let output = session
            .execute_definition(&prepared, request.clone())
            .await?;
        assert_eq!(values(&output.batches)?, [11]);
        assert_eq!(
            values(
                &output.calls[&id]
                    .evaluation()
                    .checkpoint
                    .as_ref()
                    .ok_or("prior checkpoint absent")?
                    .datasets[0]
                    .batches
            )?,
            [10]
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0].checkpoint = None;
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.checkpoint.clear();
    fixture.install(&bundle)?;
    let stateless = fixture.prepare(&Fixture::definition()).await?;
    let observed = Arc::clone(&reads);
    control.on_read_step(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    let mut request = invocation("stateless-state");
    request
        .checkpoints
        .insert(Fixture::calls(&stateless.plan)?[0].id(), checkpoint(10)?);
    let error = session
        .execute_definition(&stateless, request)
        .await
        .err()
        .ok_or("stateless checkpoint succeeded")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    control.check()?;
    Ok(())
}

#[tokio::test]
async fn physical_definition_denies_other_tenant() -> TestResult {
    let fixture = Fixture::installed(&component("sql", "accumulate")?)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(
                input => (SELECT CAST(2 AS BIGINT UNSIGNED) AS value))"#,
        ))
        .await?;
    let before = fixture.engine.store().meta()?;
    let session = fixture.engine.session(
        AnalysisSelectionV1::tenant([2; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    let error = session
        .execute_definition(&prepared, invocation("other-tenant"))
        .await
        .err()
        .ok_or("other tenant definition succeeded")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    let (snapshot, stream) = session
        .stream(
            &prepared.plan,
            prepared.sources(),
            crate::execution::Read::Snapshot,
        )
        .await?;
    let source = stream
        .try_collect::<Vec<_>>()
        .await
        .err()
        .ok_or("other tenant physical call succeeded")?;
    assert_eq!(
        crate::Failure::from(&crate::Error::Sql { source }),
        crate::Failure::Denied
    );
    drop(snapshot);
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(fixture.engine.reserve_evaluation([2; 16])?);
    Ok(())
}

fn capacity_limits() -> Limits {
    Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        input_bytes: 4 * 1024 * 1024,
        input_capacity: Some(4 * 1024 * 1024),
        output_capacity: Some(1024 * 1024),
        ..Default::default()
    }
}

fn capacity_released(fixture: &Fixture) -> TestResult {
    let limits = fixture.engine.limits();
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(limits.input_capacity.ok_or("input capacity absent")?)?,
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(limits.output_capacity.ok_or("output capacity absent")?)?,
    );
    Ok(())
}

#[tokio::test]
async fn physical_sql_failure_keeps_data() -> TestResult {
    for cause in ["evidence", "reason", "execution"] {
        let fixture = Fixture::limits(capacity_limits())?;
        let mut bundle = Fixture::bundle();
        let PackageImplementationV1::Sql { program, .. } =
            &mut bundle.artifacts[0].implementations[0]
        else {
            return Err("SQL required".into());
        };
        match cause {
            "evidence" => program.evidence = Some("SELECT 'result' AS output_dataset, CAST(999 AS BIGINT UNSIGNED) AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source".into()),
            "reason" => program.reasons[0].sql = "SELECT CAST(999 AS BIGINT UNSIGNED) AS output_row, value FROM output_result".into(),
            _ => { program.outputs.insert("result".into(), "SELECT CAST('invalid:' || CAST(value AS VARCHAR) AS BIGINT UNSIGNED) AS value FROM source".into()); },
        }
        fixture.install(&bundle)?;
        let definition = Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(
                source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
        );
        let prepared = fixture.prepare(&definition).await?;
        let before = fixture.engine.store().meta()?;
        assert!(
            fixture.execute(&prepared, invocation(cause)).await.is_err(),
            "{cause}"
        );
        assert_eq!(fixture.engine.store().meta()?, before);
        assert!(fixture
            .engine
            .store()
            .active_managed(&araphor_data::AnalysisReadControl::default())?
            .1
            .is_empty());
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn physical_failure_keeps_session() -> TestResult {
    for cause in ["execution", "contract", "input"] {
        let fixture = Fixture::limits(capacity_limits())?;
        let mut bundle = Fixture::bundle();
        let PackageImplementationV1::Sql { program, .. } =
            &mut bundle.artifacts[0].implementations[0]
        else {
            return Err("SQL required".into());
        };
        if cause == "execution" {
            program.outputs.insert("result".into(), "SELECT CAST(CASE WHEN value = 0 THEN 'invalid' ELSE CAST(value AS VARCHAR) END AS BIGINT UNSIGNED) AS value FROM source".into());
        } else if cause == "contract" {
            program.evidence = Some("SELECT 'result' AS output_dataset, CAST(CASE WHEN value = 0 THEN 999 ELSE 0 END AS BIGINT UNSIGNED) AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source".into());
        }
        if cause == "input" {
            bundle.artifacts[0].descriptor.exports[0]
                .inputs
                .push(sdk::Port::new("additional", Fixture::schema("value")).into());
        }
        fixture.install(&bundle)?;
        let definition = |value| {
            let additional = if cause == "input" {
                format!(
                    ", additional => (SELECT CAST({} AS BIGINT UNSIGNED) AS value)",
                    if value == 0 { "NULL" } else { "7" }
                )
            } else {
                String::new()
            };
            Fixture::sql(format!(
                r#"SELECT * FROM "fixture"."r1".count(source => (
                SELECT CAST({value} AS BIGINT UNSIGNED) AS value){additional}, increment => 2)"#
            ))
        };
        let bad = fixture.prepare(&definition(0)).await?;
        let good = fixture.prepare(&definition(7)).await?;
        let control = AnalysisReadControl::default();
        let session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
        let error = session
            .execute_definition(&bad, invocation("failed"))
            .await
            .err()
            .ok_or("invalid native input returned output")?;
        if cause == "input" {
            let mut source: &(dyn std::error::Error + 'static) = &error;
            loop {
                if matches!(
                    source.downcast_ref::<sdk::Error>(),
                    Some(sdk::Error::Batch {
                        source: sdk::arrow_schema::ArrowError::InvalidArgumentError(message),
                        ..
                    }) if message == "Column 'value' is declared as non-nullable but contains null values"
                ) {
                    break;
                }
                source = source.source().ok_or("missing native null-input error")?;
            }
        }
        control.check()?;
        let output = session
            .execute_definition(&good, invocation("reused"))
            .await?;
        assert_eq!(
            values(&output.batches)?,
            [if cause == "execution" { 7 } else { 9 }]
        );
        assert_eq!(output.calls.len(), 1);
        control.check()?;
        drop(output);
        drop((bad, good));
        capacity_released(&fixture)?;
    }
    Ok(())
}

async fn guest_failures(target: &str) -> TestResult {
    let bundle = component(target, "evaluate")?;

    let fixture = Fixture::image_limits(
        capacity_limits(),
        &bundle,
        &Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'trap', amount => 7)"#,
        ),
    )
    .await?;
    for mode in ["trap", "invalid-name", "invalid-evidence"] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => '{mode}', amount => 7)"#
        ));
        let prepared = fixture.prepare(&definition).await?;
        let before = fixture.engine.store().meta()?;
        assert!(
            fixture.execute(&prepared, invocation(mode)).await.is_err(),
            "{target}/{mode}"
        );
        assert_eq!(fixture.engine.store().meta()?, before);
        assert!(fixture
            .engine
            .store()
            .active_managed(&araphor_data::AnalysisReadControl::default())?
            .1
            .is_empty());
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn physical_wasm_failures_release() -> TestResult {
    guest_failures("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn physical_native_failures_release() -> TestResult {
    guest_failures("native").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn physical_call_cancellation_joins() -> TestResult {
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&Fixture::bundle())?;
    fixture.event(1)?;
    let mut prepared = fixture.prepare(&Fixture::definition()).await?;
    let control = AnalysisReadControl::default();
    let (entered, entering) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let id = Fixture::calls(&prepared.plan)?[0].id();
    gate_input(&mut prepared, id, entered, released)?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let worker = tokio::spawn(async move {
        session
            .execute_definition(&prepared, invocation("cancelled"))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), entering).await??;
    control.cancel()?;
    release.send(())?;
    let error = tokio::time::timeout(std::time::Duration::from_secs(30), worker)
        .await??
        .err()
        .ok_or("cancelled package execution succeeded")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(fixture
        .engine
        .store()
        .active_managed(&araphor_data::AnalysisReadControl::default())?
        .1
        .is_empty());
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn physical_calls_keep_capture_and_clock() -> TestResult {
    let fixture = Fixture::new()?;
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model
        .inputs
        .push(sdk::Port::new("context", Fixture::schema("value")).into());
    for name in ["clock", "context"] {
        model
            .outputs
            .push(sdk::Port::new(name, Fixture::schema("value")));
    }
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert(
        "clock".into(),
        "SELECT CAST(arrow_cast(CURRENT_TIMESTAMP, 'Int64') AS BIGINT UNSIGNED) AS value".into(),
    );
    program
        .outputs
        .insert("context".into(), "SELECT value FROM context".into());
    fixture.install(&bundle)?;
    fixture.install(&component("wasm", "evaluate")?)?;
    fixture.event(1)?;
    fixture.context(1)?;
    let definition = Fixture::sql(
        r#"SELECT sql_call.value AS result, guest_call.value AS clock
        FROM "fixture"."r1".count('result',
            source => (SELECT source_cursor AS value FROM events),
            context => (SELECT owner_revision AS value FROM context_versions ORDER BY owner_revision DESC LIMIT 1),
            increment => 2) AS sql_call
        CROSS JOIN "runtime-fixture"."1".evaluate(mode => 'clock', amount => 0) AS guest_call"#,
    );
    let mut prepared = fixture.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    let sql = calls
        .iter()
        .find(|call| call.export() == "count")
        .ok_or("SQL call absent")?
        .id();
    let (entered, entering) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    gate_input(&mut prepared, sql, entered, released)?;
    let prepared = Arc::new(prepared);
    let session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    let running = Arc::clone(&prepared);
    let worker = tokio::spawn(async move {
        session
            .execute_definition(&running, invocation("captured"))
            .await
    });
    let changed = async {
        tokio::time::timeout(std::time::Duration::from_secs(30), entering).await??;
        fixture.event(2)?;
        fixture.context(2)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let _released = release.send(());
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), worker).await???;
    changed?;
    assert_eq!(values(&output.batches)?, [3]);
    let call = output.calls.get(&sql).ok_or("SQL result absent")?;
    assert_eq!(values(&dataset(call, "context")?.batches)?, [1]);
    assert_eq!(values(&dataset(call, "clock")?.batches)?, [NOW]);
    assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
    let guest = output
        .calls
        .values()
        .find(|call| call.evaluation().export == "evaluate")
        .ok_or("guest result absent")?;
    assert_eq!(values(&dataset(guest, "data")?.batches)?, [NOW]);
    assert_eq!(
        output.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    let revision = output.snapshot.page.extraction.meta.commit_revision;
    let later = fixture.execute(&prepared, invocation("later")).await?;
    let mut later_values = values(&later.batches)?;
    later_values.sort_unstable();
    assert_eq!(later_values, [3, 4]);
    let later_call = later.calls.get(&sql).ok_or("later call absent")?;
    assert_eq!(values(&dataset(later_call, "context")?.batches)?, [2]);
    let mut links = later_call
        .output()
        .evidence
        .iter()
        .map(|link| {
            assert_eq!(link.output.dataset, "result");
            assert_eq!(link.input.dataset, "source");
            (link.output.row, link.input.row)
        })
        .collect::<Vec<_>>();
    links.sort_unstable();
    assert_eq!(links, [(0, 0), (1, 1)]);
    let results = values(&dataset(later_call, "result")?.batches)?;
    let mut reason_rows = Vec::new();
    for reason in &later_call.output().reasons {
        assert_eq!(reason.output.dataset, "result");
        assert_eq!(reason.code, "fixture.note");
        assert_eq!(
            values(std::slice::from_ref(&reason.details))?,
            [results[reason.output.row as usize]]
        );
        reason_rows.push(reason.output.row);
    }
    reason_rows.sort_unstable();
    assert_eq!(reason_rows, [0, 1]);
    assert!(later.snapshot.page.extraction.meta.commit_revision > revision);
    Ok(())
}

#[tokio::test]
async fn physical_input_keeps_declared_sources() -> TestResult {
    for source in [
        "WITH unused AS (SELECT * FROM events) SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
        "SELECT source_cursor AS value FROM events LIMIT 0",
    ] {
        let fixture = Fixture::installed(&Fixture::bundle())?;
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count(source => ({source}), increment => 2)"#,
        ));
        let prepared = fixture.prepare(&definition).await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        let first = fixture.execute(&prepared, invocation("before")).await?;
        fixture.event(1)?;
        let second = fixture.execute(&prepared, invocation("after")).await?;
        let old = &first
            .calls
            .get(&id)
            .ok_or("first call absent")?
            .evaluation()
            .inputs[0];
        let new = &second
            .calls
            .get(&id)
            .ok_or("second call absent")?
            .evaluation()
            .inputs[0];
        assert_eq!(values(&old.data.batches)?, values(&new.data.batches)?);
        assert_ne!(old.revision.id, new.revision.id, "{source}");
        assert_eq!(second.snapshot.page.extraction.sources.len(), 1);
        assert_eq!(
            second.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn physical_tight_output_capacity() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::limits(Limits {
        output_capacity: Some(capacity),
        output_bytes: capacity,
        input_capacity: Some(capacity),
        input_bytes: capacity,
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    for finite in [false, true] {
        let prepared = fixture
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count(
            source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
            ))
            .await?;
        let batches = if finite {
            let output = fixture
                .execute(&prepared, invocation("tight-output"))
                .await?;
            assert_eq!(output.calls.len(), 1);
            output.batches
        } else {
            let session = fixture.engine.session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                NOW,
            )?;
            let (_snapshot, stream) = session
                .stream(
                    &prepared.plan,
                    prepared.sources(),
                    crate::execution::Read::Snapshot,
                )
                .await?;
            stream.try_collect::<Vec<_>>().await?
        };
        assert_eq!(values(&batches)?, [9], "finite={finite}");
        let alias = Arc::clone(batches[0].column(0));
        let retained = alias.get_buffer_memory_size();
        assert!(retained > 0 && retained < capacity);
        assert!(fixture.engine.memory().reserve_output(capacity).is_err());
        drop(batches);
        assert_eq!(
            alias
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 alias required")?
                .value(0),
            9
        );
        let remaining = fixture
            .engine
            .memory()
            .reserve_output(capacity - retained)?;
        assert!(fixture.engine.memory().reserve_output(1).is_err());
        drop(remaining);
        drop(alias);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

pub(super) fn component(target: &str, export: &str) -> TestResult<PackageBundleV1> {
    let mut model = sdk::Model::new(
        export,
        if export == "evaluate" {
            Vec::new()
        } else {
            vec![sdk::Port::new("input", Fixture::schema("value"))]
        },
        vec![sdk::Port::new("data", Fixture::schema("value"))],
    );
    if export == "accumulate" {
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", Fixture::schema("value"))],
        });
    } else {
        model.parameters = sdk::Schema::new(vec![
            sdk::Field::new("mode", sdk::DataType::Utf8, false),
            sdk::Field::new("amount", sdk::DataType::UInt64, false),
        ]);
    }
    let implementation = match target {
        "sql" => PackageImplementationV1::Sql {
            export: export.into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "data".into(),
                    "SELECT CAST(COALESCE((SELECT SUM(value) FROM input), 0) + \
                        COALESCE((SELECT SUM(value) FROM prior_state), 0) \
                        AS BIGINT UNSIGNED) AS value"
                        .into(),
                )]),
                checkpoint: BTreeMap::from([(
                    "state".into(),
                    "SELECT value FROM output_data".into(),
                )]),
                ..Default::default()
            },
        },
        "wasm" => PackageImplementationV1::Wasm {
            exports: vec![export.into()],
            artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
        },
        "native" => {
            let directory = std::path::PathBuf::from(
                std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
            );
            let artifact = std::fs::read(
                directory.join(format!("runtime.{}", std::env::consts::DLL_EXTENSION)),
            )?;
            let qualification = araphor_package::Qualification::inspect(
                &artifact,
                vec![export.into()],
                std::env::var("ARAPHOR_NATIVE_TARGET")?,
            )?;
            PackageImplementationV1::Native {
                export: export.into(),
                artifact,
                qualification: Some(qualification),
            }
        }
        _ => return Err("unknown component target".into()),
    };
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: "runtime-fixture".into(),
            revision: "1".into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
            implementations: vec![implementation],
            fixtures: Vec::new(),
        }],
    })
}

#[tokio::test]
async fn sql_body_scope() -> TestResult {
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0].source =
        sdk::InputSource::Query("SELECT source_cursor AS value FROM events".into());
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.checkpoint.insert(
        "state".into(),
        "SELECT value AS total FROM output_result UNION ALL SELECT total FROM prior_state ORDER BY total".into(),
    );
    let fixture = Fixture::installed(&bundle)?;
    fixture.event(1)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#,
        ))
        .await?;
    assert!(prepared.sources().contains_key("events"));
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let mut invocation = invocation("declared-body");
    invocation.checkpoints.insert(
        id,
        sdk::Checkpoint {
            version: 2,
            datasets: vec![sdk::Dataset {
                name: "state".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(Fixture::schema("total")),
                    vec![Arc::new(UInt64Array::from(vec![5]))],
                )?],
            }],
        },
    );
    let output = fixture.execute(&prepared, invocation).await?;
    assert_eq!(values(&output.batches)?, [3]);
    let returned = output.calls.get(&id).ok_or("call return")?;
    let checkpoint = returned.output().checkpoint.as_ref().ok_or("checkpoint")?;
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [3, 5]);
    assert_eq!(returned.output().evidence.len(), 1);
    assert_eq!(returned.output().reasons[0].code, "fixture.note");
    assert_eq!(
        values(std::slice::from_ref(&returned.output().reasons[0].details))?,
        [3]
    );

    for table in ["events", "caller_rows"] {
        let column = if table == "events" {
            "source_cursor"
        } else {
            "value"
        };
        for body in ["output", "checkpoint", "evidence", "reason"] {
            let mut bundle = Fixture::bundle();
            let PackageImplementationV1::Sql { program, .. } =
                &mut bundle.artifacts[0].implementations[0]
            else {
                return Err("SQL fixture absent".into());
            };
            match body {
                "output" => {
                    program.outputs.insert(
                        "result".into(),
                        format!("SELECT {column} AS value FROM {table}"),
                    );
                }
                "checkpoint" => {
                    program.checkpoint.insert(
                        "state".into(),
                        format!("SELECT {column} AS total FROM {table}"),
                    );
                }
                "evidence" => {
                    program.evidence = Some(format!(
                        "SELECT 'result' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'source' AS input_dataset, {column} AS input_row FROM {table}",
                    ));
                }
                _ => {
                    program.reasons[0].sql =
                        format!("SELECT {column} AS output_row, {column} AS value FROM {table}");
                }
            }
            let fixture = Fixture::installed(&bundle)?;
            let mut session = fixture.engine.session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                NOW,
            )?;
            let schema = Arc::new(Fixture::schema("value"));
            let batch = sdk::RecordBatch::try_new(
                Arc::clone(&schema),
                vec![Arc::new(UInt64Array::from(vec![11]))],
            )?;
            session.register("caller_rows", schema, &[batch])?;
            let error = session
                .prepare_definition(&Fixture::definition())
                .await
                .err()
                .ok_or("SQL body read an undeclared table")?;
            assert!(
                snafu::ChainCompat::new(&error).any(|cause| matches!(
                    cause.downcast_ref::<DataFusionError>(),
                    Some(DataFusionError::Plan(message))
                        if message.contains(table) && message.contains("not found")
                )),
                "{body}/{table}: {error:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn sql_struct_join_inputs() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0].inputs[0]
        .port
        .schema = sdk::Schema::new(vec![
        sdk::Field::new(
            "attributes",
            sdk::DataType::Struct(
                vec![
                    sdk::Field::new("uid", sdk::DataType::Utf8, false),
                    sdk::Field::new("tag", sdk::DataType::Utf8, false),
                ]
                .into(),
            ),
            false,
        ),
        sdk::Field::new("value", sdk::DataType::UInt64, false),
    ]);
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.outputs.insert("result".into(), "SELECT r.value FROM source r JOIN (SELECT attributes['uid'] AS uid FROM source) f ON f.uid = r.attributes['uid'] WHERE r.attributes['tag'] IN (SELECT attributes['tag'] FROM source)".into());
    let fixture = Fixture::installed(&bundle)?;
    fixture.event(1)?;
    let prepared = fixture.prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count(source => (SELECT named_struct('uid', 'u1', 'tag', 't1') AS attributes, source_cursor AS value FROM events), increment => 2)"#)).await?;
    let output = fixture
        .execute(&prepared, invocation("struct-joins"))
        .await?;
    assert_eq!(values(&output.batches)?, [1]);
    let returned = output.calls.values().next().ok_or("call return")?;
    let checkpoint = returned.output().checkpoint.as_ref().ok_or("checkpoint")?;
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [1]);
    assert_eq!(returned.output().evidence.len(), 1);
    assert_eq!(returned.output().reasons[0].code, "fixture.note");
    assert_eq!(
        values(std::slice::from_ref(&returned.output().reasons[0].details))?,
        [1]
    );
    Ok(())
}

impl Fixture {
    async fn assembled_input(
        &self,
        batch: &sdk::RecordBatch,
        prior: &sdk::Checkpoint,
    ) -> crate::Result<DefinitionOutput> {
        let mut session = self.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        session.register("total_input", batch.schema(), std::slice::from_ref(batch))?;
        let prepared = session.prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM total_input), increment => 2)"#,
        )).await?;
        let calls =
            Fixture::calls(&prepared.plan).map_err(|source| crate::Error::Sql { source })?;
        let mut request = invocation("total-input");
        request.checkpoints.insert(calls[0].id(), prior.clone());
        session.execute_definition(&prepared, request).await
    }
}

#[tokio::test]
async fn combined_input_respects_limit() -> TestResult {
    let batch = sdk::RecordBatch::try_new(
        Arc::new(Fixture::schema("value")),
        vec![Arc::new(UInt64Array::from((0..4096).collect::<Vec<u64>>()))],
    )?;
    let prior = sdk::Checkpoint {
        version: 2,
        datasets: vec![sdk::Dataset {
            name: "state".into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(Fixture::schema("total")),
                vec![Arc::new(UInt64Array::from((0..4096).collect::<Vec<u64>>()))],
            )?],
        }],
    };
    let fixture = Fixture::installed(&Fixture::bundle())?;
    assert_eq!(fixture.engine.limits().input_capacity, None);
    let result = fixture.assembled_input(&batch, &prior).await?;
    let evaluation = result
        .calls
        .values()
        .next()
        .ok_or("call absent")?
        .evaluation();
    let total = evaluation.allocated_bytes();
    assert!(evaluation.inputs[0].data.allocated_bytes() < total - 1);
    assert!(prior.datasets[0].allocated_bytes() < total - 1);
    assert!(
        evaluation
            .parameters
            .as_ref()
            .ok_or("parameters absent")?
            .get_array_memory_size()
            < total - 1
    );
    drop(result);
    for (input_bytes, accepted) in [(total - 1, false), (total, true)] {
        let fixture = Fixture::limits(Limits {
            input_bytes,
            input_capacity: None,
            ..Limits::default()
        })?;
        fixture.install(&Fixture::bundle())?;
        let before = fixture.engine.store().meta()?;
        let result = fixture.assembled_input(&batch, &prior).await;
        if accepted {
            let output = result?;
            assert_eq!(
                output
                    .calls
                    .values()
                    .next()
                    .ok_or("call absent")?
                    .evaluation()
                    .allocated_bytes(),
                total
            );
        } else {
            let error = result.err().ok_or("combined input limit was ignored")?;
            assert_eq!(crate::Failure::from(&error), crate::Failure::InputTooLarge);
            assert!(
                matches!(&error, crate::Error::Sql { source }
                    if matches!(source.find_root(), DataFusionError::ResourcesExhausted(resource)
                        if resource == "package input bytes")),
                "{error:?}"
            );
        }
        assert_eq!(fixture.engine.store().meta()?, before);
    }
    Ok(())
}

mod contract;
mod descriptors;
mod reusing;
mod supplied;

#[tokio::test]
async fn native_caps_keep_targets() -> TestResult {
    let mut limits = capacity_limits();
    limits.package.native.memory_bytes = Some(1024);
    let runtime = araphor_package_runtime::Runtime::new(limits.package)?;
    let fixture = Fixture::limits(limits)?;
    for (target, revision) in [("sql", "1"), ("wasm", "2")] {
        let mut bundle = component(target, "accumulate")?;
        bundle.root.revision = revision.into();
        bundle.artifacts[0].descriptor.revision = revision.into();
        fixture.install(&bundle)?;
        let prepared = fixture.prepare(&Fixture::sql(format!(
            r#"SELECT * FROM "runtime-fixture"."{revision}".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#
        ))).await?;
        let before = fixture.engine.store().meta()?;
        let output = fixture.execute(&prepared, invocation(target)).await?;
        assert_eq!(values(&output.batches)?, [7]);
        assert_eq!(output.calls.len(), 1);
        assert_eq!(fixture.engine.store().meta()?, before);
        drop((output, prepared));
        capacity_released(&fixture)?;
    }
    let mut bundle = component("wasm", "accumulate")?;
    bundle.root.revision = "3".into();
    bundle.artifacts[0].descriptor.revision = "3".into();
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "accumulate".into(),
        artifact: b"invalid".to_vec(),
        qualification: Some(araphor_package::Qualification {
            exports: vec!["accumulate".into()],
            target: "foreign-target".into(),
            cpu_features: Vec::new(),
            contract_version: sdk::CONTRACT_VERSION,
            system_libraries: Vec::new(),
            dependencies: Vec::new(),
        }),
    }];
    fixture.install(&bundle)?;
    let before = fixture.engine.store().meta()?;
    let error = fixture.prepare(&Fixture::sql(
        r#"SELECT * FROM "runtime-fixture"."3".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#
    )).await.err().ok_or("capped Native call admitted")?;
    let bundle = Arc::new(bundle);
    let control = AnalysisReadControl::default();
    let workers = araphor_package_runtime::TaskTracker::new();
    let prepared = runtime
        .prepare(
            Arc::clone(&bundle),
            bundle.root.clone(),
            "accumulate".into(),
            &control,
        )
        .err()
        .ok_or("capped Native preparation succeeded")?;
    let evaluation = sdk::Evaluation {
        export: "accumulate".into(),
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "caps".into(),
            time_utc_ns: 0,
            seed: None,
        },
    };
    let called = runtime
        .evaluate(
            Arc::clone(&bundle),
            bundle.root.clone(),
            evaluation,
            control.within(None)?,
            &workers,
        )
        .await
        .err()
        .ok_or("capped Native execution succeeded")?;
    let wrap = |source| crate::Error::Sql {
        source: DataFusionError::External(Box::new(source)),
    };
    for error in [error, wrap(prepared), wrap(called)] {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut exact = false;
        while let Some(current) = source {
            if matches!(
                current.downcast_ref::<araphor_package_runtime::Error>(),
                Some(araphor_package_runtime::Error::Data {
                    source: araphor_data::Error::Package {
                        code: araphor_data::PackageErrorCodeV1::Unsupported,
                        field: "in-process native resource limits",
                        ..
                    }
                })
            ) {
                exact = true;
                break;
            }
            source = current.source();
        }
        assert!(exact, "Native cap error was replaced: {error:?}");
    }
    assert!(workers.is_empty());
    control.cancel()?;
    assert!(matches!(
        runtime.prepare(
            Arc::clone(&bundle),
            bundle.root.clone(),
            "accumulate".into(),
            &control
        ),
        Err(araphor_package_runtime::Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(fixture
        .engine
        .store()
        .active_managed(&araphor_data::AnalysisReadControl::default())?
        .1
        .is_empty());
    capacity_released(&fixture)?;
    Ok(())
}
