use std::sync::mpsc;

use sdk::arrow_array::{ArrayRef, FixedSizeListArray, NullArray, StringViewArray, StructArray};

use super::*;

fn evaluation(
    image: &PackageBundleV1,
    batch: &sdk::RecordBatch,
    id: &str,
) -> TestResult<sdk::Evaluation> {
    let model = &image.artifacts[0].descriptor.exports[0];
    Ok(sdk::Evaluation {
        export: model.name.clone(),
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![batch.clone()],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: Some(sdk::SourceWindow {
                    source: vec![1],
                    start_utc_ns: 0,
                    end_utc_ns: 1,
                }),
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: araphor_data::decode_parameters(
            &model.parameters,
            (!model.parameters.fields().is_empty())
                .then(|| serde_json::json!({"mode": "cancel", "amount": 7}))
                .as_ref(),
        )?,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: id.into(),
            time_utc_ns: NOW as i64,
            seed: Some(7),
        },
    })
}

#[tokio::test]
async fn guest_nested_encoding_preflight() -> TestResult {
    let capacity = 64 * 1024 * 1024;
    for (fixed_list, minimum) in [(false, 125_000), (true, 1024 * 1024)] {
        let rows = if fixed_list { 128 * 65_536 } else { 1_000_000 };
        let records = StructArray::try_new(
            vec![sdk::Field::new("missing", sdk::DataType::Null, true)].into(),
            vec![Arc::new(NullArray::new(rows))],
            None,
        )?;
        let array: ArrayRef = if fixed_list {
            let field = Arc::new(sdk::Field::new("item", records.data_type().clone(), false));
            Arc::new(FixedSizeListArray::try_new(
                field,
                65_536,
                Arc::new(records),
                None,
            )?)
        } else {
            Arc::new(records)
        };
        let schema = sdk::Schema::new(vec![sdk::Field::new(
            "value",
            array.data_type().clone(),
            false,
        )]);
        let batch = sdk::RecordBatch::try_new(Arc::new(schema.clone()), vec![array])?;
        let mut image = component("wasm", "count-input")?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        model.inputs[0].port.schema = schema;

        let evaluation = evaluation(&image, &batch, "nested-encoding")?;
        assert!(evaluation.allocated_bytes() < 32 * 1024);
        let scratch = evaluation.encoding_scratch_bytes()?;
        assert!(scratch >= minimum);
        let wire = image.artifacts[0]
            .descriptor
            .check_evaluation(&evaluation)?
            .encode()?;
        assert!(wire.inputs[0].data.arrow_ipc.len() >= minimum);
        let decoded = wire.decode(&image.artifacts[0].descriptor)?;
        assert_eq!(
            decoded.inputs[0].data.batches,
            evaluation.inputs[0].data.batches
        );
        assert_eq!(decoded.inputs[0].revision, evaluation.inputs[0].revision);
        assert_eq!(decoded.inputs[0].coverage, evaluation.inputs[0].coverage);
        assert_eq!(decoded.context, evaluation.context);
        drop((wire, decoded));
        let fixture = Fixture::limits(Limits {
            input_bytes: capacity,
            input_capacity: Some(capacity),
            evaluate_timeout: Some(std::time::Duration::from_secs(10)),
            output_bytes: 16 * 1024 * 1024,
            output_capacity: Some(16 * 1024 * 1024),
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })?;
        fixture.install(&image)?;
        let mut session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        session.register("nested_input", batch.schema(), std::slice::from_ref(&batch))?;
        let prepared = session.prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."count-input"(input => (SELECT value FROM nested_input), mode => 'cancel', amount => 7)"#,
        )).await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        let available = fixture.engine.memory().prepare_input(capacity)?;
        let pressure_bytes = available
            .size()
            .checked_sub(scratch * 2)
            .ok_or("nested fixture capacity")?;
        drop(available);
        let pressure = fixture.engine.memory().reserve_input(pressure_bytes)?;
        let (entry, observed) = mpsc::channel();
        fixture.engine.guest_entry(entry, None)?;
        let mut request = invocation("nested-encoding");
        request.inputs.insert(id, evaluation.inputs.clone());
        let before = fixture.engine.store().meta()?;
        let error = session
            .execute_definition(&prepared, request)
            .await
            .err()
            .ok_or("nested exchange scratch was not reserved")?;
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::Busy,
            "{error:?}"
        );
        assert!(
            format!("{error:?}").contains("araphor input"),
            "fixed_list={fixed_list}: {error:?}"
        );
        assert!(matches!(
            observed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(fixture.engine.store().meta()?, before);
        drop((session, prepared, pressure, evaluation, batch));
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn guest_schema_and_wire_preflight() -> TestResult {
    for empty in [true, false] {
        let capacity = 4 * 1024 * 1024;
        let metadata = if empty { 100 * 1024 } else { 4 * 1024 };
        let schema = Fixture::schema("value").with_metadata(std::collections::HashMap::from([(
            "metadata".into(),
            "x".repeat(metadata),
        )]));
        let batch = sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(if empty {
                Vec::new()
            } else {
                vec![7]
            }))],
        )?;
        let mut image = component("wasm", "count-input")?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        model.inputs[0].port.schema = schema.clone();

        let evaluation = evaluation(&image, &batch, "schema-encoding")?;
        let descriptor = &image.artifacts[0].descriptor;
        let checked = descriptor.check_evaluation(&evaluation)?;
        let wire = checked.encode()?;
        let decoded = wire.decode(descriptor)?;
        assert_eq!(decoded.inputs[0].data.batches.len(), 1);
        assert_eq!(
            decoded.inputs[0].data.batches[0].num_rows(),
            usize::from(!empty)
        );
        assert_eq!(decoded.inputs[0].data.batches[0].schema().as_ref(), &schema);
        assert_eq!(
            decoded.inputs[0].data.batches,
            evaluation.inputs[0].data.batches
        );
        let fixture = Fixture::limits(Limits {
            input_bytes: capacity,
            input_capacity: Some(capacity),
            evaluate_timeout: Some(std::time::Duration::from_secs(10)),
            output_bytes: capacity,
            output_capacity: Some(capacity),
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })?;
        fixture.install(&image)?;
        let mut session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        session.register("schema_input", batch.schema(), std::slice::from_ref(&batch))?;
        let prepared = session.prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."count-input"(input => (SELECT value FROM schema_input), mode => 'cancel', amount => 7)"#,
        )).await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        let available = fixture.engine.memory().prepare_input(capacity)?;
        let bytes = available
            .size()
            .checked_sub(descriptor.allocated_bytes())
            .ok_or("schema fixture capacity")?;
        drop(available);
        let pressure = fixture.engine.memory().reserve_input(bytes)?;
        let (entry, observed) = mpsc::channel();
        fixture.engine.guest_entry(entry, None)?;
        let mut request = invocation("schema-encoding");
        request.inputs.insert(id, evaluation.inputs.clone());
        let before = fixture.engine.store().meta()?;
        let error = session
            .execute_definition(&prepared, request)
            .await
            .err()
            .ok_or("schema exchange exceeded its reservation")?;
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::Busy,
            "{error:?}"
        );
        assert!(format!("{error:?}").contains("araphor input"), "{error:?}");
        assert!(matches!(
            observed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(fixture.engine.store().meta()?, before);
        drop((session, prepared, pressure, evaluation, batch));
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn guest_checkpoint_exchange_capacity() -> TestResult {
    let capacity = 512 * 1024;
    let image = component("wasm", "accumulate")?;

    let definition = Fixture::sql(
        r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#,
    );
    let fixture = Fixture::image_limits(
        Limits {
            input_bytes: capacity,
            input_capacity: Some(capacity),
            output_bytes: 1024 * 1024,
            output_capacity: Some(1024 * 1024),
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        },
        &image,
        &definition,
    )
    .await?;
    let prepared = fixture.prepare(&definition).await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let before = fixture.engine.store().meta()?;
    let first = fixture
        .execute(&prepared, invocation("checkpoint-base"))
        .await?;
    let mut evaluation = first
        .calls
        .get(&id)
        .ok_or("initial checkpoint call")?
        .evaluation()
        .clone();
    let retained = evaluation.allocated_bytes();
    let scratch = evaluation.encoding_scratch_bytes()?;
    evaluation.checkpoint = Some(sdk::Checkpoint {
        version: 1,
        datasets: Vec::new(),
    });
    assert_eq!(evaluation.allocated_bytes(), retained);
    assert_eq!(evaluation.encoding_scratch_bytes()?, scratch);
    let state = sdk::RecordBatch::try_new(
        Arc::new(Fixture::schema("value")),
        vec![Arc::new(UInt64Array::from(vec![1; 8192]))],
    )?;
    let checkpoint = sdk::Checkpoint {
        version: 1,
        datasets: vec![sdk::Dataset {
            name: "state".into(),
            batches: vec![state],
        }],
    };
    evaluation.checkpoint = Some(checkpoint.clone());
    image.artifacts[0]
        .descriptor
        .validate_evaluation(&evaluation)?;
    assert!(evaluation.allocated_bytes() > retained + 64 * 1024);
    assert!(evaluation.encoding_scratch_bytes()? > scratch);
    let checkpoint_bytes = checkpoint.datasets[0].allocated_bytes();
    drop(first);
    let available = fixture.engine.memory().prepare_input(capacity)?;
    let bytes = available
        .size()
        .checked_sub(checkpoint_bytes + 32 * 1024)
        .ok_or("checkpoint fixture capacity")?;
    drop(available);
    let pressure = fixture.engine.memory().reserve_input(bytes)?;
    let baseline = fixture
        .execute(&prepared, invocation("checkpoint-base"))
        .await?;
    assert_eq!(values(&baseline.batches)?, [7]);
    drop(baseline);
    let mut request = invocation("checkpoint-state");
    request.checkpoints.insert(id, checkpoint.clone());
    let error = fixture
        .execute(&prepared, request)
        .await
        .err()
        .ok_or("checkpoint exchange scratch was not reserved")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::Busy,
        "{error:?}"
    );
    assert!(format!("{error:?}").contains("araphor input"), "{error:?}");
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((pressure, evaluation, checkpoint, prepared));
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn sql_normalization_preflight() -> TestResult {
    let capacity = 64 * 1024;
    for fixed_binary in [true, false] {
        let value = vec![7; 1024];
        let array: ArrayRef = if fixed_binary {
            let mut values = vec![None; 200];
            values[0] = Some(value.as_slice());
            Arc::new(BinaryArray::from(values))
        } else {
            let (views, buffers, _) = StringViewArray::from(vec!["x".repeat(1024)]).into_parts();
            Arc::new(StringViewArray::new(
                vec![views[0]; 200].into(),
                buffers,
                None,
            ))
        };
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            array.data_type().clone(),
            fixed_binary,
        )]));
        let expected = sdk::Schema::new(vec![sdk::Field::new(
            "value",
            if fixed_binary {
                sdk::DataType::FixedSizeBinary(1024)
            } else {
                sdk::DataType::Utf8
            },
            fixed_binary,
        )]);
        let batch = sdk::RecordBatch::try_new(Arc::clone(&schema), vec![array])?;
        assert!(batch.get_array_memory_size() < capacity);
        assert!(sdk::Dataset::conversion_bytes(&batch, &expected)? > capacity);
        let valid = sdk::Dataset::normalize_batch(batch.clone(), Arc::new(expected.clone()))?;
        assert_eq!(valid.num_rows(), 200);
        assert!(valid.get_array_memory_size() > capacity);
        drop(valid);
        let model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", expected)],
        );

        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    if fixed_binary {
                        "SELECT X'7878' AS value".into()
                    } else {
                        "SELECT 'value' AS value".into()
                    },
                )]),
                ..Default::default()
            },
        );
        let fixture = Fixture::limits(Limits {
            output_bytes: capacity,
            output_capacity: Some(capacity),
            ..capacity_limits()
        })?;
        fixture.install(&image)?;
        let mut prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let gate = Arc::new(ConversionGate {
            schema,
            batch: Some(batch),
            first: Arc::new(AtomicUsize::new(0)),
            later: Arc::new(AtomicUsize::new(0)),
            later_entered: Arc::new(Notify::new()),
            released: Arc::new(Notify::new()),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let partition: Arc<dyn PartitionStream> = gate.clone();
        let provider: Arc<dyn TableProvider> = Arc::new(StreamingTable::try_new(
            Arc::clone(&gate.schema),
            vec![partition],
        )?);
        child(
            &mut prepared,
            0,
            LogicalPlanBuilder::scan(
                "pressure_gate",
                datafusion::datasource::provider_as_source(provider),
                None,
            )?
            .build()?,
        )?;
        let before = fixture.engine.store().meta()?;
        let error = {
            let execution = fixture.execute(&prepared, invocation("normalization-pressure"));
            tokio::pin!(execution);
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::select! {
                    result = &mut execution => result,
                    _ = gate.later_entered.notified() => {
                        gate.released.notify_one();
                        execution.await
                    }
                }
            })
            .await?;
            result
                .err()
                .ok_or("normalization allocation exceeded capacity")?
        };
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::ResultTooLarge,
            "fixed_binary={fixed_binary}: {error:?}"
        );
        assert!(format!("{error:?}").contains("output"), "{error:?}");
        assert_eq!(gate.first.load(Ordering::SeqCst), 1);
        assert_eq!(gate.later.load(Ordering::SeqCst), 0);
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert_eq!(fixture.engine.store().meta()?, before);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}
