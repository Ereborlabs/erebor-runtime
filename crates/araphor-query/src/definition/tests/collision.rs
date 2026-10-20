use super::*;
use crate::definition::Invocation;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::logical_expr::{col, lit, Extension, LogicalPlanBuilder};
use sdk::arrow_array::UInt64Array;

fn combined(left: LogicalPlan, right: LogicalPlan) -> datafusion::common::Result<LogicalPlan> {
    LogicalPlanBuilder::from(left)
        .alias("first_call")?
        .cross_join(
            LogicalPlanBuilder::from(right)
                .alias("second_call")?
                .build()?,
        )?
        .build()
}

#[tokio::test]
async fn foreign_admission_cannot_share() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let mut replacement = Fixture::bundle();
    replacement.root.revision = "r2".into();
    replacement.artifacts[0].descriptor.revision = "r2".into();
    fixture.install(&replacement)?;
    let source = |revision: &str, value: u64, increment: u64| {
        Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."{revision}".count(source => (
            SELECT CAST({value} AS BIGINT UNSIGNED) AS value), increment => {increment})"#,
        ))
    };
    for (revision, value, increment) in [("r1", 7, 2), ("r1", 7, 3), ("r1", 11, 2), ("r2", 7, 2)] {
        let mut first = fixture.prepare(&source("r1", 7, 2)).await?;
        let second = fixture.prepare(&source(revision, value, increment)).await?;
        assert_eq!(
            Fixture::calls(&first.plan)?[0].id(),
            Fixture::calls(&second.plan)?[0].id()
        );
        first.plan = combined(first.plan, second.plan)?;
        let error = fixture
            .execute(&first, Invocation::default())
            .await
            .err()
            .ok_or("foreign admission reused a package call")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
        assert!(format!("{error:?}").contains("package call identity collision"));
    }
    let valid = fixture.prepare(&source("r1", 7, 2)).await?;
    let output = fixture.execute(&valid, Invocation::default()).await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(
        output.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("UInt64 output")?
            .value(0),
        9
    );
    let readmitted = fixture.prepare(&source("r1", 7, 2)).await?;
    let call = Fixture::calls(&readmitted.plan)?.remove(0);
    assert!(!output.calls[&call.id()].belongs_to(&call));
    let digest = |plan: &LogicalPlan| {
        use std::hash::{Hash as _, Hasher as _};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        plan.hash(&mut hash);
        hash.finish()
    };
    assert_eq!(digest(&valid.plan), digest(&readmitted.plan));
    Ok(())
}

#[tokio::test]
async fn same_admission_shares_outputs() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0]
        .outputs
        .push(sdk::Port::new("copy", Fixture::schema("value")));
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL implementation".into());
    };
    program.outputs.insert("copy".into(), "SELECT source.value + parameters.increment + CAST(1 AS BIGINT UNSIGNED) AS value FROM source CROSS JOIN parameters".into());
    let fixture = Fixture::installed(&bundle)?;
    let mut prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count('result', source => (
            SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
        ))
        .await?;
    let copied = prepared
        .plan
        .clone()
        .transform_up(|plan| {
            if let LogicalPlan::Extension(extension) = &plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    let mut call = call.clone();
                    call.output = "copy".into();
                    return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                        node: Arc::new(call),
                    })));
                }
            }
            Ok(Transformed::no(plan))
        })?
        .data;
    prepared.plan = combined(prepared.plan, copied)?;
    let output = fixture.execute(&prepared, Invocation::default()).await?;
    assert_eq!(output.calls.len(), 1);
    let batch = &output.batches[0];
    for (column, expected) in [(0, 9), (1, 10)] {
        assert_eq!(
            batch
                .column(column)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 output")?
                .value(0),
            expected
        );
    }
    assert_eq!(
        output
            .calls
            .values()
            .next()
            .ok_or("call")?
            .output()
            .datasets
            .len(),
        2
    );
    Ok(())
}

async fn changed_child_rejected(slot: usize) -> TestResult {
    use araphor_data::AnalysisSelectionV1;
    use std::sync::atomic::{AtomicBool, Ordering};

    for entry in 0..4 {
        let fixture = Fixture::installed(&Fixture::bundle())?;
        fixture.event(1)?;
        let mut prepared = fixture.prepare(&Fixture::definition()).await?;
        let original = prepared.plan.clone();
        let changed = original
            .clone()
            .transform_up(|plan| {
                if let LogicalPlan::Extension(extension) = &plan {
                    if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                        let mut children = call.inputs().into_iter().cloned().collect::<Vec<_>>();
                        children[slot] = LogicalPlanBuilder::from(children[slot].clone())
                            .project(vec![(col("value") + lit(10u64)).alias("value")])?
                            .build()?;
                        let changed = call.with_exprs_and_inputs(Vec::new(), children)?;
                        assert_eq!(changed.id(), call.id());
                        return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                            node: Arc::new(changed),
                        })));
                    }
                }
                Ok(Transformed::no(plan))
            })?
            .data;
        prepared.plan = combined(original.clone(), changed)?;
        if entry == 1 {
            use datafusion::datasource::{provider_as_source, view::ViewTable};
            use datafusion::logical_expr::TableScan;

            prepared.plan = LogicalPlanBuilder::from(prepared.plan)
                .project(vec![
                    col("first_call.value").alias("first_value"),
                    col("second_call.value").alias("second_value"),
                ])?
                .build()?;
            prepared.plan = LogicalPlan::TableScan(TableScan::try_new(
                "altered_view",
                provider_as_source(Arc::new(ViewTable::new(prepared.plan, None))),
                None,
                Vec::new(),
                None,
            )?);
        }
        let captured = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&captured);
        let control = AnalysisReadControl::default();
        control.on_read_step(move || {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })?;
        let session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &control,
            1_700_000_000_123_456_789,
        )?;
        let error = match entry {
            0 => session
                .execute_definition(&prepared, Invocation::default())
                .await
                .err(),
            1 => session
                .stream(
                    &prepared.plan,
                    &prepared.sources,
                    crate::execution::Read::Snapshot,
                )
                .await
                .err(),
            2 => session
                .stream_local(
                    &prepared.plan,
                    Arc::new(fixture.engine.reserve_evaluation([1; 16])?),
                )
                .await
                .err(),
            _ => crate::follow::Subscription::new(
                session.clone(),
                Arc::new(prepared.plan.clone()),
                prepared.sources.clone(),
                b"altered call",
                None,
                Arc::new(crate::follow::SystemClock::default()),
                false,
            )
            .err(),
        }
        .ok_or("changed call was accepted")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
        assert!(format!("{error:?}").contains("package call admission"));
        assert!(!captured.load(Ordering::SeqCst));
        control.check()?;
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        prepared.plan = LogicalPlanBuilder::from(original)
            .alias("admitted_alias")?
            .build()?;
        let output = session
            .execute_definition(&prepared, Invocation::default())
            .await?;
        assert!(captured.load(Ordering::SeqCst));
        assert_eq!(output.calls.len(), 1);
        assert_eq!(
            output.batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 output")?
                .value(0),
            3
        );
    }
    Ok(())
}

#[tokio::test]
async fn changed_inputs_require_readmission() -> TestResult {
    changed_child_rejected(0).await
}

#[tokio::test]
async fn changed_body_requires_readmission() -> TestResult {
    changed_child_rejected(2).await
}

#[tokio::test]
async fn replaced_provider_requires_readmission() -> TestResult {
    use araphor_data::AnalysisSelectionV1;
    use datafusion::datasource::{provider_as_source, MemTable, ViewTable};
    use datafusion::logical_expr::TableScan;
    use std::sync::atomic::{AtomicBool, Ordering};

    for nested in [false, true] {
        for entry in 0..4 {
            let fixture = Fixture::installed(&Fixture::bundle())?;
            fixture.event(1)?;
            let mut prepared = fixture.prepare(&Fixture::definition()).await?;
            let original = prepared.plan.clone();
            let mut replaced = false;
            prepared.plan = original
                .clone()
                .transform_up(|plan| {
                    if let LogicalPlan::Extension(extension) = &plan {
                        if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                            let mut children =
                                call.inputs().into_iter().cloned().collect::<Vec<_>>();
                            let admitted = children[0].clone();
                            children[0] = admitted
                                .clone()
                                .transform_up_with_subqueries(|plan| {
                                    if !replaced {
                                        if let LogicalPlan::TableScan(mut scan) = plan {
                                            let schema = scan.source.schema();
                                            let batch =
                                                sdk::RecordBatch::new_empty(Arc::clone(&schema));
                                            scan.source = provider_as_source(Arc::new(
                                                MemTable::try_new(schema, vec![vec![batch]])?,
                                            ));
                                            replaced = true;
                                            return Ok(Transformed::yes(LogicalPlan::TableScan(
                                                scan,
                                            )));
                                        }
                                    }
                                    Ok(Transformed::no(plan))
                                })?
                                .data;
                            assert_eq!(children[0], admitted);
                            let changed = call.with_exprs_and_inputs(Vec::new(), children)?;
                            return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                                node: Arc::new(changed),
                            })));
                        }
                    }
                    Ok(Transformed::no(plan))
                })?
                .data;
            assert!(replaced);
            if nested {
                prepared.plan = LogicalPlan::TableScan(TableScan::try_new(
                    "provider_view",
                    provider_as_source(Arc::new(ViewTable::new(prepared.plan, None))),
                    None,
                    Vec::new(),
                    None,
                )?);
            }
            let captured = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&captured);
            let control = AnalysisReadControl::default();
            control.on_read_step(move || {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            })?;
            let session = fixture.engine.session(
                AnalysisSelectionV1::tenant([1; 16]),
                &control,
                1_700_000_000_123_456_789,
            )?;
            let error = match entry {
                0 => session
                    .execute_definition(&prepared, Invocation::default())
                    .await
                    .err(),
                1 => session
                    .stream(
                        &prepared.plan,
                        &prepared.sources,
                        crate::execution::Read::Snapshot,
                    )
                    .await
                    .err(),
                2 => session
                    .stream_local(
                        &prepared.plan,
                        Arc::new(fixture.engine.reserve_evaluation([1; 16])?),
                    )
                    .await
                    .err(),
                _ => crate::follow::Subscription::new(
                    session.clone(),
                    Arc::new(prepared.plan.clone()),
                    prepared.sources.clone(),
                    b"provider replacement",
                    None,
                    Arc::new(crate::follow::SystemClock::default()),
                    false,
                )
                .err(),
            }
            .ok_or("replaced provider was accepted")?;
            assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
            assert!(
                format!("{error:?}").contains("package call admission"),
                "entry={entry} nested={nested}: {error:?}"
            );
            assert!(!captured.load(Ordering::SeqCst));
            control.check()?;
            drop(fixture.engine.reserve_evaluation([1; 16])?);
            prepared.plan = LogicalPlanBuilder::from(original)
                .alias("admitted_alias")?
                .build()?;
            let output = session
                .execute_definition(&prepared, Invocation::default())
                .await?;
            assert!(captured.load(Ordering::SeqCst));
            assert_eq!(output.calls.len(), 1);
            assert_eq!(
                output.batches[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("UInt64 output")?
                    .value(0),
                3
            );
        }
    }
    Ok(())
}
