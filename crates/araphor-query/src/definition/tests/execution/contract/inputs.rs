use datafusion::common::ScalarValue;

use super::*;

fn column_values(batches: &[sdk::RecordBatch], column: usize) -> TestResult<Vec<ScalarValue>> {
    Ok(batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows())
                .map(move |row| ScalarValue::try_from_array(batch.column(column), row))
        })
        .collect::<datafusion::common::Result<Vec<_>>>()?)
}

#[tokio::test]
async fn durable_input_indices() -> TestResult {
    let mut limits = capacity_limits();
    limits.global_evaluations = Some(2);
    let fixture = Fixture::limits(limits)?;
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new(
                "indexed",
                sdk::Schema::new(vec![
                    sdk::Field::new("value", sdk::DataType::UInt64, false),
                    sdk::Field::new("row_index", sdk::DataType::UInt64, false),
                ]),
            ),
            source: sdk::InputSource::Query("SELECT source_cursor AS value, __row_index AS row_index FROM chosen ORDER BY __row_index".into()),
        },
        sdk::InputPort {
            port: sdk::Port::new("chosen", Fixture::schema("source_cursor")),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ];
    fixture.install(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM indexed".into())]),
            ..Default::default()
        },
    ))?;
    for cursor in 1..=3 {
        fixture.event(cursor)?;
    }
    let source = araphor_data::EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "call-input".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    fixture.engine.store().accept_validated_batch(
        araphor_data::EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..source.clone()
        },
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: NOW - 1_000_000 + 4,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let foreign = fixture.engine.reserve_evaluation([9; 16])?;
    let output = fixture
        .execute(&prepared, invocation("durable-indices"))
        .await?;
    assert_eq!(values(&output.batches)?, [1, 2, 3]);
    assert_eq!(output.calls.len(), 1);
    let call = output.calls.values().next().ok_or("call absent")?;
    assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
    let inputs = &call.evaluation().inputs;
    assert_eq!(
        inputs
            .iter()
            .map(|input| input.data.name.as_str())
            .collect::<Vec<_>>(),
        ["indexed", "chosen"]
    );
    assert_eq!(values(&inputs[0].data.batches)?, [1, 2, 3]);
    assert_eq!(
        column_values(&inputs[0].data.batches, 1)?,
        (0..3)
            .map(|index| ScalarValue::UInt64(Some(index)))
            .collect::<Vec<_>>()
    );
    assert_eq!(values(&inputs[1].data.batches)?, [1, 2, 3]);
    assert_eq!(output.snapshot.page.extraction.sources.len(), 1);
    assert_eq!(output.snapshot.witnesses.len(), 3);
    assert!(output
        .snapshot
        .witnesses
        .iter()
        .all(|witness| witness.identity == source));
    assert_eq!(
        output.snapshot.page.extraction.meta,
        fixture.engine.store().meta()?
    );
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop((output, prepared, foreign));
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn input_receipts_stay_scoped() -> TestResult {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = [
        (
            "contexts",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        ),
        (
            "activity",
            "SELECT source_cursor AS value FROM events ORDER BY source_cursor",
        ),
    ]
    .map(|(name, sql)| sdk::InputPort {
        port: sdk::Port::new(name, Fixture::schema("value")),
        source: sdk::InputSource::Query(sql.into()),
    })
    .into();
    let fixture = Fixture::installed(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM activity".into())]),
            ..Default::default()
        },
    ))?;
    fixture.event(1)?;
    fixture.context(1)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let first = fixture
        .execute(&prepared, invocation("scope-first"))
        .await?;
    let call = first.calls.values().next().ok_or("first call")?;
    let inputs = &call.evaluation().inputs;
    assert_eq!(values(&inputs[0].data.batches)?, [1]);
    assert!(inputs[0]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    assert!(!inputs[1]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    let context_revision = inputs[0].revision.clone();
    let context_coverage = inputs[0].coverage.clone();
    drop(first);
    fixture.event(2)?;
    let second = fixture
        .execute(&prepared, invocation("scope-second"))
        .await?;
    let call = second.calls.values().next().ok_or("second call")?;
    let inputs = &call.evaluation().inputs;
    assert_eq!(inputs[0].revision, context_revision);
    assert_eq!(inputs[0].coverage, context_coverage);
    assert_eq!(values(&inputs[1].data.batches)?, [1, 2]);
    let activity_revision = inputs[1].revision.clone();
    let activity_coverage = inputs[1].coverage.clone();
    drop(second);
    fixture.context(2)?;
    let third = fixture
        .execute(&prepared, invocation("scope-third"))
        .await?;
    let call = third.calls.values().next().ok_or("third call")?;
    let inputs = &call.evaluation().inputs;
    assert_eq!(values(&inputs[0].data.batches)?, [2]);
    assert_ne!(inputs[0].revision, context_revision);
    assert_eq!(inputs[1].revision, activity_revision);
    assert_eq!(inputs[1].coverage, activity_coverage);
    assert_eq!(third.snapshot.contexts().count(), 2);
    Ok(())
}

#[tokio::test]
async fn input_clocks_share_time() -> TestResult {
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
        false,
    )]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = [("first", "CURRENT_TIMESTAMP"), ("second", "now()")]
        .map(|(name, expression)| sdk::InputPort {
            port: sdk::Port::new(name, schema.clone()),
            source: sdk::InputSource::Query(format!("SELECT {expression} AS value")),
        })
        .into();
    let fixture = Fixture::installed(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM \"first\"".into())]),
            ..Default::default()
        },
    ))?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    assert_eq!(crate::follow::Window::clocks(&prepared.plan)?, 2);
    assert!(prepared.sources().is_empty());
    let output = fixture
        .execute(&prepared, invocation("input-clocks"))
        .await?;
    let call = output.calls.values().next().ok_or("call absent")?;
    assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
    assert_eq!(call.evaluation().inputs.len(), 2);
    let expected = [ScalarValue::TimestampNanosecond(
        Some(NOW as i64),
        Some("UTC".into()),
    )];
    for input in &call.evaluation().inputs {
        assert_eq!(column_values(&input.data.batches, 0)?, expected);
    }
    assert_eq!(column_values(&output.batches, 0)?, expected);
    assert!(output.snapshot.page.extraction.sources.is_empty());
    assert!(output.snapshot.witnesses.is_empty());
    Ok(())
}

#[tokio::test]
async fn catalog_input_contract() -> TestResult {
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "ordinal",
        sdk::DataType::UInt32,
        false,
    )]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("columns", schema.clone()),
        source: sdk::InputSource::Query("SELECT ordinal FROM catalog LIMIT 100".into()),
    }];
    model.limits.max_rows = 100;
    model.limits.max_batches = 1;
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(count(*) AS BIGINT UNSIGNED) AS value FROM \"columns\"".into(),
            )]),
            ..Default::default()
        },
    ))?;
    fixture.event(1)?;
    let definition = Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#);
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(
        prepared
            .sources()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["catalog"]
    );
    let output = fixture
        .execute(&prepared, invocation("catalog-first"))
        .await?;
    assert_eq!(values(&output.batches)?, [100]);
    let call = output.calls.values().next().ok_or("call absent")?;
    assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
    assert_eq!(call.evaluation().inputs.len(), 1);
    let input = &call.evaluation().inputs[0];
    assert_eq!(input.data.name, "columns");
    assert_eq!(input.data.batches.len(), 1);
    assert_eq!(input.data.batches[0].num_rows(), 100);
    assert_eq!(input.data.batches[0].schema().as_ref(), &schema);
    let expected = crate::sources::SourceSnapshot::schemas()
        .values()
        .flat_map(|schema| 0..schema.fields().len())
        .take(100)
        .map(|ordinal| ScalarValue::UInt32(Some(ordinal as u32)))
        .collect::<Vec<_>>();
    assert_eq!(column_values(&input.data.batches, 0)?, expected);
    assert_eq!(input.revision.owner, "araphor-query.Inputs");
    assert!(!input.revision.id.is_empty());
    assert!(input.revision.window.is_none());
    assert!(input
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    let revision = input.revision.clone();
    assert_eq!(
        output.snapshot.page.extraction.meta,
        fixture.engine.store().meta()?
    );
    assert!(output.snapshot.page.extraction.sources.is_empty());
    assert!(output.snapshot.witnesses.is_empty());
    assert_eq!(output.snapshot.contexts().count(), 0);
    assert_eq!(output.snapshot.results().count(), 0);
    let read_revision = output.snapshot.page.extraction.meta.commit_revision;
    let borrowed = Arc::clone(input.data.batches[0].column(0));
    drop((output, prepared));
    let limits = fixture.engine.limits();
    assert!(fixture
        .engine
        .memory()
        .reserve_input(limits.input_capacity.ok_or("input capacity")?)
        .is_err());
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(limits.output_capacity.ok_or("output capacity")?)?,
    );
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0)?,
        ScalarValue::UInt32(Some(0))
    );
    drop(borrowed);
    capacity_released(&fixture)?;
    fixture.event(2)?;
    let prepared = fixture.prepare(&definition).await?;
    let output = fixture
        .execute(&prepared, invocation("catalog-second"))
        .await?;
    let call = output.calls.values().next().ok_or("later call")?;
    let input = &call.evaluation().inputs[0];
    assert_eq!(input.revision, revision);
    assert_eq!(input.data.batches.len(), 1);
    assert_eq!(input.data.batches[0].num_rows(), 100);
    assert!(output.snapshot.page.extraction.meta.commit_revision > read_revision);
    assert!(output.snapshot.witnesses.is_empty());
    drop((output, prepared));
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn generated_input_scope() -> TestResult {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Int64, false)]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("generated", schema),
        source: sdk::InputSource::Query(
            "SELECT * FROM generate_series(1, 3) AS generated(value)".into(),
        ),
    }];
    let fixture = Fixture::installed(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM generated".into())]),
            ..Default::default()
        },
    ))?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    assert!(prepared.sources().is_empty());
    let output = fixture.execute(&prepared, invocation("generated")).await?;
    let call = output.calls.values().next().ok_or("call absent")?;
    let expected = (1..=3)
        .map(|value| ScalarValue::Int64(Some(value)))
        .collect::<Vec<_>>();
    assert_eq!(
        column_values(&call.evaluation().inputs[0].data.batches, 0)?,
        expected
    );
    assert_eq!(column_values(&output.batches, 0)?, expected);
    assert!(output.snapshot.page.extraction.sources.is_empty());
    assert!(output.snapshot.selection.sources.is_empty());
    assert!(output.snapshot.witnesses.is_empty());
    Ok(())
}

#[tokio::test]
async fn captured_trace_revocation() -> TestResult {
    use araphor_data::{
        Selection, TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1,
    };

    let fixture = Fixture::limits(capacity_limits())?;
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema("value")),
        source: sdk::InputSource::Query("SELECT sequence AS value FROM trace_output".into()),
    }];
    fixture.install(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
            ..Default::default()
        },
    ))?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "input-trace".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    fixture.engine.store().accept_trace(&TraceIntentV1 {
        tenant_id: identity.tenant_id,
        request_id: identity.request_id,
        source,
        bindings: vec![TraceBindingV1 {
            identity: identity.clone(),
            binding_id: [6; 16],
            namespace_uid: "input-namespace".into(),
        }],
        authority: b"accepted".to_vec(),
        accepted_unix_ns: NOW - 3_000_000_000,
        deadline_unix_ns: NOW + 60_000_000_000,
        host_sensitive: false,
    })?;
    fixture.engine.store().append_trace(
        &identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"trace-input".to_vec(),
            }],
            terminal: None,
        },
        NOW - 2_000_000_000,
    )?;
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.traces = Selection::Exact(vec![identity.clone()]);
    let parent = AnalysisReadControl::default();
    let session = fixture.engine.session(selection, &parent, NOW)?;
    let prepared = session
        .prepare_definition(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let first = session
        .execute_definition(&prepared, invocation("trace-readable"))
        .await?;
    assert_eq!(values(&first.batches)?, [1]);
    let call = first.calls.values().next().ok_or("trace call")?;
    assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [1]);
    assert_eq!(
        first.snapshot.page.extraction.trace_reads(),
        &[identity.request_id]
    );
    fixture.engine.check_read(&first.snapshot).await?;
    let captured = session
        .capture_definition(&prepared, invocation("trace-revoked"))
        .await?;
    assert_eq!(
        captured.snapshot().page.extraction.meta,
        first.snapshot.page.extraction.meta
    );
    assert_eq!(
        captured.snapshot().page.extraction.trace_reads(),
        &[identity.request_id]
    );
    let (mut state, _) = fixture
        .engine
        .store()
        .trace_intent(identity.tenant_id, identity.request_id)?
        .ok_or("trace intent")?;
    state.cancel_requested = true;
    state.read_revoked = true;
    fixture.engine.store().update_trace(&state)?;
    let before = fixture.engine.store().meta()?;
    let error = fixture
        .engine
        .check_read(&first.snapshot)
        .await
        .err()
        .ok_or("revoked receipt accepted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    let error = captured
        .execute()
        .await
        .err()
        .ok_or("revoked captured result returned")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    assert_eq!(fixture.engine.store().meta()?, before);
    parent.check()?;
    drop((first, prepared, session));
    capacity_released(&fixture)?;
    Ok(())
}
