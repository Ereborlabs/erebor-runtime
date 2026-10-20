use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use datafusion::catalog::streaming::StreamingTable;
use datafusion::catalog::TableProvider;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::PartitionStream;
use datafusion::physical_plan::SendableRecordBatchStream;
use sdk::arrow_array::{BinaryArray, FixedSizeBinaryArray, StringArray, TimestampNanosecondArray};
use tokio::sync::Notify;

use super::*;

fn bundle(model: sdk::Model, program: SqlModelV1) -> PackageBundleV1 {
    let mut image = Fixture::bundle();
    image.artifacts[0].implementations = vec![PackageImplementationV1::Sql {
        export: model.name.clone(),
        program,
    }];
    image.artifacts[0].descriptor.exports = vec![model];
    image
}

fn child(prepared: &mut PreparedDefinition, slot: usize, replacement: LogicalPlan) -> TestResult {
    assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
    prepared.plan = prepared
        .plan
        .clone()
        .transform_up(|plan| {
            let LogicalPlan::Extension(extension) = &plan else {
                return Ok(Transformed::no(plan));
            };
            let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() else {
                return Ok(Transformed::no(plan));
            };
            let mut children = call.children.clone();
            children[slot] = replacement.clone();
            let mut call = call.with_exprs_and_inputs(Vec::new(), children)?;
            call.admitted = call.children.clone().into();
            Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                node: Arc::new(call),
            })))
        })?
        .data;
    Ok(())
}

#[tokio::test]
async fn sql_zero_column_reason() -> TestResult {
    let mut image = Fixture::bundle();
    image.artifacts[0].descriptor.exports[0]
        .reasons
        .push(sdk::Reason {
            code: "fixture.empty".into(),
            details: sdk::Schema::empty(),
        });
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture".into());
    };
    program.reasons.push(SqlReasonV1 {
        output: "result".into(),
        code: "fixture.empty".into(),
        sql: "SELECT __row_index AS output_row FROM output_result".into(),
    });
    let fixture = Fixture::installed(&image)?;
    let prepared = fixture.prepare(&Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
    )).await?;
    let output = fixture
        .execute(&prepared, invocation("empty-reason"))
        .await?;
    let call = output.calls.values().next().ok_or("call absent")?;
    assert_eq!(values(&output.batches)?, [9]);
    assert_eq!(call.output().evidence.len(), 1);
    assert_eq!(
        call.output()
            .checkpoint
            .as_ref()
            .ok_or("checkpoint")?
            .version,
        2
    );
    assert_eq!(call.output().reasons.len(), 2);
    assert_eq!(
        call.output()
            .reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect::<Vec<_>>(),
        ["fixture.note", "fixture.empty"]
    );
    let reason = call
        .output()
        .reasons
        .iter()
        .find(|reason| reason.code == "fixture.empty")
        .ok_or("empty reason")?;
    assert_eq!(reason.output.dataset, "result");
    assert_eq!(reason.output.row, 0);
    assert_eq!(reason.details.num_columns(), 0);
    assert_eq!(reason.details.num_rows(), 1);
    let packet = sdk::wire::Output::encode(
        &image.artifacts[0].descriptor,
        call.evaluation(),
        call.output(),
    )?;
    let decoded = packet.decode(&image.artifacts[0].descriptor, call.evaluation())?;
    let reason = decoded
        .reasons
        .iter()
        .find(|reason| reason.code == "fixture.empty")
        .ok_or("decoded empty reason")?;
    assert_eq!(reason.details.num_columns(), 0);
    assert_eq!(reason.details.num_rows(), 1);
    Ok(())
}

#[tokio::test]
async fn sql_preserves_admitted_order() -> TestResult {
    let port = |name| sdk::Port::new(name, Fixture::schema("value"));
    let mut model = sdk::Model::new("count", Vec::new(), vec![port("ZRows"), port("ARows")]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![port("ZState"), port("AState")],
    });
    model.reasons = ["fixture.z", "fixture.a"]
        .map(|code| sdk::Reason {
            code: code.into(),
            details: Fixture::schema("value"),
        })
        .into();
    let image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([
                (
                    "ARows".into(),
                    "SELECT CAST(9 AS BIGINT UNSIGNED) AS value".into(),
                ),
                (
                    "ZRows".into(),
                    "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                ),
            ]),
            checkpoint: BTreeMap::from([
                ("AState".into(), "SELECT value FROM \"output_ARows\"".into()),
                ("ZState".into(), "SELECT value FROM \"output_ZRows\"".into()),
            ]),
            reasons: vec![
                SqlReasonV1 {
                    output: "ARows".into(),
                    code: "fixture.a".into(),
                    sql: "SELECT __row_index AS output_row, value FROM \"output_ARows\"".into(),
                },
                SqlReasonV1 {
                    output: "ZRows".into(),
                    code: "fixture.z".into(),
                    sql: "SELECT __row_index AS output_row, value FROM \"output_ZRows\"".into(),
                },
            ],
            ..Default::default()
        },
    );
    for (output, code, field) in [
        ("missing", "fixture.a", "package reason output"),
        ("ARows", "missing", "package reason code"),
    ] {
        let mut invalid = image.clone();
        let PackageImplementationV1::Sql { program, .. } =
            &mut invalid.artifacts[0].implementations[0]
        else {
            return Err("SQL fixture".into());
        };
        program.reasons[0].output = output.into();
        program.reasons[0].code = code.into();
        let invalid = Fixture::installed(&invalid)?;
        let error = invalid
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count('ZRows')"#,
            ))
            .await
            .err()
            .ok_or("undeclared reason was admitted")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut rejected = false;
        while let Some(error) = source {
            rejected |= matches!(
                error.downcast_ref::<crate::Error>(),
                Some(crate::Error::Invalid { field: actual, .. }) if *actual == field
            );
            source = error.source();
        }
        assert!(rejected, "{error:?}");
    }
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count('ZRows')"#,
        ))
        .await?;
    let result = fixture
        .execute(&prepared, invocation("admitted-order"))
        .await?;
    let call = result.calls.values().next().ok_or("call absent")?;
    assert_eq!(values(&result.batches)?, [7]);
    let output = call.output();
    assert_eq!(output.datasets.len(), 2);
    for (data, (name, expected)) in output.datasets.iter().zip([("ZRows", 7), ("ARows", 9)]) {
        assert_eq!(data.name, name);
        assert_eq!(values(&data.batches)?, [expected]);
    }
    let checkpoint = output.checkpoint.as_ref().ok_or("checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(checkpoint.datasets.len(), 2);
    for (data, (name, expected)) in checkpoint
        .datasets
        .iter()
        .zip([("ZState", 7), ("AState", 9)])
    {
        assert_eq!(data.name, name);
        assert_eq!(values(&data.batches)?, [expected]);
    }
    assert_eq!(output.reasons.len(), 2);
    for (reason, (name, code, expected)) in output
        .reasons
        .iter()
        .zip([("ARows", "fixture.a", 9), ("ZRows", "fixture.z", 7)])
    {
        assert_eq!(reason.output.dataset, name);
        assert_eq!(reason.output.row, 0);
        assert_eq!(reason.code, code);
        assert_eq!(values(std::slice::from_ref(&reason.details))?, [expected]);
    }
    drop(result);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn sql_preserves_portable_precision() -> TestResult {
    let schema = sdk::Schema::new(vec![
        sdk::Field::new("value", sdk::DataType::UInt64, false),
        sdk::Field::new(
            "time",
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        sdk::Field::new("bytes", sdk::DataType::FixedSizeBinary(2), false),
    ]);
    let batch = sdk::RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(UInt64Array::from(vec![u64::MAX])),
            Arc::new(TimestampNanosecondArray::from(vec![-1]).with_timezone("UTC")),
            Arc::new(FixedSizeBinaryArray::try_from_iter(
                [[0_u8, 255]].into_iter(),
            )?),
        ],
    )?;
    for (sql, accepted) in [
        ("SELECT value, time, bytes FROM source", true),
        (
            "SELECT CAST(value AS BIGINT) AS value, time, bytes FROM source",
            false,
        ),
    ] {
        let output_schema = sdk::Schema::new(vec![
            sdk::Field::new(
                "value",
                if accepted {
                    sdk::DataType::UInt64
                } else {
                    sdk::DataType::Int64
                },
                false,
            ),
            schema.field(1).clone(),
            schema.field(2).clone(),
        ]);
        let model = sdk::Model::new(
            "count",
            vec![sdk::Port::new("source", schema.clone())],
            vec![sdk::Port::new("result", output_schema)],
        );
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), sql.into())]),
                ..Default::default()
            },
        );
        let fixture = Fixture::installed(&image)?;
        let mut session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        session.register(
            "precise_input",
            batch.schema(),
            std::slice::from_ref(&batch),
        )?;
        let prepared = session
            .prepare_definition(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count(source => (SELECT * FROM precise_input))"#,
            ))
            .await?;
        let result = session
            .execute_definition(&prepared, invocation("portable"))
            .await;
        if accepted {
            let output = result?;
            assert_eq!(output.batches, vec![batch.clone()]);
            let call = output.calls.values().next().ok_or("call absent")?;
            assert_eq!(
                call.evaluation().inputs[0].data.batches,
                vec![batch.clone()]
            );
            assert_eq!(call.output().datasets[0].batches, vec![batch.clone()]);
        } else {
            let error = result.err().ok_or("u64MAX signed cast was accepted")?;
            assert!(format!("{error:?}").contains("Cast"), "{error:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn sql_empty_output_metadata() -> TestResult {
    let schema = sdk::Schema::new_with_metadata(
        vec![sdk::Field::new("value", sdk::DataType::Utf8, false)],
        std::collections::HashMap::from([("contract".into(), "empty-output".into())]),
    );
    let model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    let image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT 'value' AS value WHERE false".into(),
            )]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let output = fixture
        .execute(&prepared, invocation("empty-output"))
        .await?;
    let call = output.calls.values().next().ok_or("call absent")?;
    let batch = &call.output().datasets[0].batches[0];
    assert_eq!(batch.num_rows(), 0);
    assert_eq!(batch.schema().as_ref(), &schema);
    assert!(batch.column(0).as_any().is::<StringArray>());
    let capacity = fixture
        .engine
        .limits()
        .output_capacity
        .ok_or("output capacity")?;
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    drop(output);
    capacity_released(&fixture)?;
    Ok(())
}

#[derive(Debug)]
struct ConversionGate {
    schema: Arc<sdk::Schema>,
    batch: Option<sdk::RecordBatch>,
    first: Arc<AtomicUsize>,
    later: Arc<AtomicUsize>,
    later_entered: Arc<Notify>,
    released: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct Producer(Arc<AtomicBool>);
impl Drop for Producer {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl PartitionStream for ConversionGate {
    fn schema(&self) -> &Arc<sdk::Schema> {
        &self.schema
    }

    fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
        let first = self.batch.clone().map_or_else(
            || {
                sdk::RecordBatch::try_new(
                    Arc::clone(&self.schema),
                    vec![Arc::new(BinaryArray::from_iter_values(
                        std::iter::repeat_n([7_u8], context.session_config().batch_size()),
                    ))],
                )
                .map_err(DataFusionError::from)
            },
            Ok,
        );
        let producer = Producer(Arc::clone(&self.dropped));
        let first_count = Arc::clone(&self.first);
        let later_count = Arc::clone(&self.later);
        let later_entered = Arc::clone(&self.later_entered);
        let released = Arc::clone(&self.released);
        let stream =
            futures_util::stream::unfold((Some(first), producer), move |(first, producer)| {
                let first_count = Arc::clone(&first_count);
                let later_count = Arc::clone(&later_count);
                let later_entered = Arc::clone(&later_entered);
                let released = Arc::clone(&released);
                async move {
                    let batch = match first {
                        Some(batch) => {
                            first_count.fetch_add(1, Ordering::SeqCst);
                            batch
                        }
                        None => {
                            later_count.fetch_add(1, Ordering::SeqCst);
                            later_entered.notify_one();
                            released.notified().await;
                            Err(DataFusionError::Execution("later native failure".into()))
                        }
                    };
                    Some((batch, (None, producer)))
                }
            });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sql_conversion_drops_producer() -> TestResult {
    let model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new(
            "result",
            sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::FixedSizeBinary(2),
                false,
            )]),
        )],
    );
    let image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT X'7878' AS value".into())]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let mut prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let gate = Arc::new(ConversionGate {
        batch: None,
        schema: Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::Binary,
            false,
        )])),
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
            "conversion_gate",
            datafusion::datasource::provider_as_source(provider),
            None,
        )?
        .build()?,
    )?;
    let execution = fixture.execute(&prepared, invocation("conversion-stop"));
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
    let error = result.err().ok_or("invalid fixed width accepted")?;
    let mut source: &(dyn std::error::Error + 'static) = &error;
    loop {
        if matches!(
            source.downcast_ref::<sdk::Error>(),
            Some(sdk::Error::Batch { .. })
        ) {
            break;
        }
        source = source
            .source()
            .ok_or("native conversion error lost its SDK Batch cause")?;
    }
    assert_eq!(gate.first.load(Ordering::SeqCst), 1);
    assert_eq!(gate.later.load(Ordering::SeqCst), 0);
    assert!(gate.dropped.load(Ordering::SeqCst));
    capacity_released(&fixture)?;
    Ok(())
}

mod pressure;

#[tokio::test]
async fn sql_limit_precedes_references() -> TestResult {
    let schema = Fixture::schema("value");
    let model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![
            sdk::Port::new("first", schema.clone()),
            sdk::Port::new("second", schema),
        ],
    );
    let image = bundle(model, SqlModelV1 {
        outputs: BTreeMap::from([("first".into(), "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into()), ("second".into(), "SELECT CAST(2 AS BIGINT UNSIGNED) AS value".into())]),
        evidence: Some("SELECT 'first' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'unused' AS input_dataset, CAST(0 AS BIGINT UNSIGNED) AS input_row".into()),
        ..Default::default()
    });
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let mut prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count('first')"#,
        ))
        .await?;
    let polls = Arc::new(AtomicUsize::new(0));
    let marked = Arc::clone(&polls);
    let marker = create_udf(
        "reference_marker",
        vec![sdk::DataType::UInt64],
        sdk::DataType::UInt64,
        Volatility::Volatile,
        Arc::new(move |arguments| {
            marked.fetch_add(1, Ordering::SeqCst);
            arguments
                .first()
                .cloned()
                .ok_or_else(|| DataFusionError::Execution("reference marker argument".into()))
        }),
    );
    let calls = Fixture::calls(&prepared.plan)?;
    let evidence = LogicalPlanBuilder::from(calls[0].children[2].clone())
        .project(vec![
            col("output_dataset"),
            marker.call(vec![col("output_row")]).alias("output_row"),
            col("input_dataset"),
            col("input_row"),
        ])?
        .build()?;
    child(&mut prepared, 2, evidence)?;
    let mut request = invocation("rows-before-evidence");
    request.limits.max_rows = 1;
    let before = fixture.engine.store().meta()?;
    let error = fixture
        .execute(&prepared, request)
        .await
        .err()
        .ok_or("aggregate row limit ignored")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::ResultTooLarge);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.store().meta()?, before);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn sql_indexes_local_relations() -> TestResult {
    let mut image = Fixture::bundle();
    image.artifacts[0].descriptor.exports[0].outputs[0].schema = sdk::Schema::new(
        ["value", "source_row", "parameter_row", "prior_row"]
            .into_iter()
            .map(|name| sdk::Field::new(name, sdk::DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture".into());
    };
    program.outputs.insert(
        "result".into(),
        r#"SELECT source.value + parameters.increment + prior_state.total AS value,
                  source.__row_index AS source_row,
                  parameters.__row_index AS parameter_row,
                  prior_state.__row_index AS prior_row
           FROM source CROSS JOIN parameters
           JOIN prior_state ON source.__row_index = prior_state.__row_index
           ORDER BY source_row"#
            .into(),
    );
    let fixture = Fixture::installed(&image)?;
    let before = fixture.engine.store().meta()?;
    let prepared = fixture.prepare(&Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM (VALUES (CAST(7 AS BIGINT UNSIGNED)), (CAST(11 AS BIGINT UNSIGNED))) AS supplied(value) ORDER BY value), increment => 2)"#,
    )).await?;
    let call = Fixture::calls(&prepared.plan)?
        .into_iter()
        .next()
        .ok_or("call absent")?;
    let mut request = invocation("local-indexes");
    request.checkpoints.insert(
        call.id(),
        sdk::Checkpoint {
            version: 2,
            datasets: vec![sdk::Dataset {
                name: "state".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(Fixture::schema("total")),
                    vec![Arc::new(UInt64Array::from(vec![3, 5]))],
                )?],
            }],
        },
    );
    let output = fixture.execute(&prepared, request).await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(values(&output.batches)?, [12, 18]);
    for (column, expected) in [(1, vec![0, 1]), (2, vec![0, 0]), (3, vec![0, 1])] {
        let actual = output
            .batches
            .iter()
            .map(|batch| {
                let rows = batch
                    .column(column)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("UInt64 index required")?;
                assert_eq!(rows.null_count(), 0);
                Ok(rows.values().to_vec())
            })
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(actual.into_iter().flatten().collect::<Vec<_>>(), expected);
    }
    let returned = output.calls.get(&call.id()).ok_or("call return")?;
    assert_eq!(
        returned.evaluation().inputs[0].data.batches[0]
            .schema()
            .as_ref(),
        &Fixture::schema("value")
    );
    let parameters = returned
        .evaluation()
        .parameters
        .as_ref()
        .ok_or("parameters")?;
    assert_eq!(parameters.schema().as_ref(), &Fixture::schema("increment"));
    assert_eq!(values(std::slice::from_ref(parameters))?, [2]);
    let prior = returned.evaluation().checkpoint.as_ref().ok_or("prior")?;
    assert_eq!(prior.version, 2);
    assert_eq!(
        prior.datasets[0].batches[0].schema().as_ref(),
        &Fixture::schema("total")
    );
    assert_eq!(values(&prior.datasets[0].batches)?, [3, 5]);
    let state = returned.output().checkpoint.as_ref().ok_or("checkpoint")?;
    assert_eq!(state.version, 2);
    assert_eq!(values(&state.datasets[0].batches)?, [12, 18]);
    assert_eq!(returned.output().evidence.len(), 2);
    for (row, evidence) in returned.output().evidence.iter().enumerate() {
        assert_eq!(evidence.input.dataset, "source");
        assert_eq!(evidence.input.row, row as u64);
        assert_eq!(evidence.output.dataset, "result");
        assert_eq!(evidence.output.row, row as u64);
    }
    assert_eq!(returned.output().reasons.len(), 2);
    for (row, reason) in returned.output().reasons.iter().enumerate() {
        assert_eq!(reason.code, "fixture.note");
        assert_eq!(reason.output.row, row as u64);
        assert_eq!(
            values(std::slice::from_ref(&reason.details))?,
            [if row == 0 { 12 } else { 18 }]
        );
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn native_ports_shadow_sources() -> TestResult {
    for supplied in [false, true] {
        let column = if supplied { "value" } else { "ordinal" };
        let input = sdk::Schema::new(vec![sdk::Field::new(
            column,
            if supplied {
                sdk::DataType::UInt64
            } else {
                sdk::DataType::UInt32
            },
            false,
        )]);
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![
            sdk::InputPort {
                port: sdk::Port::new("selected", sdk::Schema::new(vec![
                    sdk::Field::new("value", sdk::DataType::UInt64, false),
                    sdk::Field::new("row_index", sdk::DataType::UInt64, false),
                ])),
                source: sdk::InputSource::Query(format!(
                    "SELECT CAST({column} AS BIGINT UNSIGNED) AS value, __row_index AS row_index FROM events ORDER BY __row_index LIMIT 2"
                )),
            },
            sdk::InputPort {
                port: sdk::Port::new("events", input),
                source: sdk::InputSource::Table(sdk::TableRef::Named(
                    if supplied { "events" } else { "catalog" }.into(),
                )),
            },
        ];
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT value FROM selected ORDER BY row_index".into(),
                )]),
                ..Default::default()
            },
        );
        let fixture = Fixture::installed(&image)?;
        fixture.event(1)?;
        let sql = if supplied {
            r#"SELECT * FROM "fixture"."r1".count(events => (SELECT value FROM (VALUES (CAST(7 AS BIGINT UNSIGNED)), (CAST(11 AS BIGINT UNSIGNED))) AS supplied(value) ORDER BY value))"#
        } else {
            r#"SELECT * FROM "fixture"."r1".count()"#
        };
        let prepared = fixture.prepare(&Fixture::sql(sql)).await?;
        let output = fixture
            .execute(&prepared, invocation("port-shadow"))
            .await?;
        let expected = if supplied { vec![7, 11] } else { vec![0, 1] };
        assert_eq!(values(&output.batches)?, expected);
        assert_eq!(output.calls.len(), 1);
        let call = output.calls.values().next().ok_or("call absent")?;
        assert_eq!(
            call.evaluation()
                .inputs
                .iter()
                .map(|input| input.data.name.as_str())
                .collect::<Vec<_>>(),
            ["selected", "events"]
        );
        let selected = &call.evaluation().inputs[0];
        assert_eq!(values(&selected.data.batches)?, expected);
        let indices = selected
            .data
            .batches
            .iter()
            .map(|batch| batch.project(&[1]))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(values(&indices)?, [0, 1]);
        assert!(selected
            .coverage
            .limits
            .iter()
            .any(|limit| limit == "NO_SOURCE_COVERAGE"));
        assert!(output.snapshot.page.extraction.sources.is_empty());
        assert!(output.snapshot.witnesses.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn native_self_sources_remain() -> TestResult {
    for query in [false, true] {
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![
            sdk::InputPort {
                port: sdk::Port::new("selected", Fixture::schema("value")),
                source: sdk::InputSource::Query("SELECT source_cursor AS value FROM events".into()),
            },
            sdk::InputPort {
                port: sdk::Port::new("events", Fixture::schema("source_cursor")),
                source: if query {
                    sdk::InputSource::Query("SELECT source_cursor FROM events".into())
                } else {
                    sdk::InputSource::Table(sdk::TableRef::Named("events".into()))
                },
            },
        ];
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), "SELECT value FROM selected".into())]),
                ..Default::default()
            },
        );
        let fixture = Fixture::installed(&image)?;
        fixture.event(1)?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let output = fixture
            .execute(&prepared, invocation("self-source"))
            .await?;
        assert_eq!(values(&output.batches)?, [1]);
        assert_eq!(output.calls.len(), 1);
        let call = output.calls.values().next().ok_or("call absent")?;
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [1]);
        assert_eq!(values(&call.evaluation().inputs[1].data.batches)?, [1]);
        assert_eq!(output.snapshot.page.extraction.sources.len(), 1);
        assert_eq!(
            output.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            1
        );
        assert_eq!(output.snapshot.witnesses.len(), 1);
    }
    Ok(())
}
