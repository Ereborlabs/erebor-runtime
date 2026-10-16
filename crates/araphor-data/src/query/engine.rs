use std::future::Future;
use std::path::Path;
use std::sync::{mpsc, Arc, LazyLock, Mutex};

use datafusion::common::{config::Dialect, ScalarValue};
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::GreedyMemoryPool;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::{SessionState, SessionStateBuilder, SessionStateDefaults};
use datafusion::logical_expr::ScalarUDF;
use datafusion::prelude::SessionConfig;
use duckdb::types::{TimeUnit, Value};
use snafu::ResultExt as _;
use tokio::runtime::{Builder, Handle, Runtime};

use crate::{AnalysisReadControl, Result};

const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const RUNTIME_PATH: &str = "<query-runtime>";
static FUNCTIONS: LazyLock<Vec<Arc<ScalarUDF>>> = LazyLock::new(|| {
    let mut functions = scalar::HugeInt::functions();
    functions.push(Arc::new(ScalarUDF::from(
        super::time_bucket::TimeBucket::new(),
    )));
    functions
});

mod batches;
mod scalar;

#[derive(Default)]
pub(super) struct QueryEngine {
    runtime: Mutex<Option<Runtime>>,
    #[cfg(test)]
    pub(super) input_refs:
        Mutex<Vec<std::sync::Weak<dyn araphor_analysis_sdk::arrow_array::Array>>>,
    #[cfg(test)]
    pub(super) input_leases: Mutex<Vec<std::sync::Weak<dyn std::any::Any + Send + Sync>>>,
    #[cfg(test)]
    pub(super) scan_gate: Mutex<Option<super::owner_tests::ScanGate>>,
    #[cfg(test)]
    pub(super) native_failed: std::sync::atomic::AtomicBool,
}

impl QueryEngine {
    /// The future must own its source data and all resource guards.
    pub(super) fn run<T, F>(&self, control: &AnalysisReadControl, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
    {
        let stage = control.within(control.remaining()?)?;
        let handle = {
            let mut runtime = self.runtime.lock().map_err(|_| {
                crate::AnalysisStateSnafu {
                    path: RUNTIME_PATH,
                    reason: "the query runtime lock is poisoned",
                }
                .build()
            })?;
            if runtime.is_none() {
                *runtime = Some(
                    Builder::new_multi_thread()
                        .worker_threads(1)
                        .thread_name("araphor-query")
                        .enable_time()
                        .build()
                        .context(crate::IoSnafu {
                            path: Path::new(RUNTIME_PATH),
                        })?,
                );
            }
            runtime
                .as_ref()
                .map(|runtime| runtime.handle().clone())
                .ok_or_else(|| {
                    crate::AnalysisStateSnafu {
                        path: RUNTIME_PATH,
                        reason: "the query runtime is absent after initialization",
                    }
                    .build()
                })?
        };
        if Handle::try_current().is_ok_and(|current| current.id() == handle.id()) {
            return crate::AnalysisStateSnafu {
                path: RUNTIME_PATH,
                reason: "the query runtime cannot wait for its own task",
            }
            .fail();
        }

        let (sender, receiver) = mpsc::sync_channel(1);
        let task = handle.spawn(async move { stage.query_async(operation).await });
        let _completion = handle.spawn(async move {
            let result = task
                .await
                .context(crate::QueryExecutionSnafu)
                .and_then(std::convert::identity);
            let _sent = sender.send(result);
        });
        let result = receiver
            .recv()
            .map_err(std::io::Error::other)
            .context(crate::IoSnafu {
                path: Path::new(RUNTIME_PATH),
            })?;
        control.check()?;
        result
    }

    pub(super) fn state() -> Result<SessionState> {
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_pool(Arc::new(GreedyMemoryPool::new(MEMORY_LIMIT)))
            .with_disk_manager_builder(
                DiskManagerBuilder::default().with_mode(DiskManagerMode::Disabled),
            )
            .build_arc()
            .context(crate::QueryEngineSnafu {
                operation: "configure query resources",
            })?;
        let mut config = SessionConfig::new()
            .with_target_partitions(1)
            .with_create_default_catalog_and_schema(false)
            .with_information_schema(false);
        let options = config.options_mut();
        options.execution.planning_concurrency = 1;
        options.optimizer.prefer_existing_union = true;
        options.sql_parser.dialect = Dialect::DuckDB;
        options.sql_parser.map_string_types_to_utf8view = false;
        options.sql_parser.parse_float_as_decimal = true;
        options.sql_parser.default_null_ordering = "nulls_last".to_owned();

        let mut functions = SessionStateDefaults::default_scalar_functions();
        functions.extend(FUNCTIONS.iter().cloned());
        Ok(SessionStateBuilder::new()
            .with_config(config)
            .with_runtime_env(runtime)
            .with_expr_planners(SessionStateDefaults::default_expr_planners())
            .with_scalar_functions(functions)
            .with_aggregate_functions(SessionStateDefaults::default_aggregate_functions())
            .with_window_functions(SessionStateDefaults::default_window_functions())
            .build())
    }

    /// SQL admission checks the parameter count and total byte limit.
    pub(super) fn parameters(values: &[Value]) -> Result<Vec<ScalarValue>> {
        values
            .iter()
            .map(|value| {
                Ok(match value {
                    Value::Null => ScalarValue::Null,
                    Value::Boolean(value) => ScalarValue::Boolean(Some(*value)),
                    Value::TinyInt(value) => ScalarValue::Int8(Some(*value)),
                    Value::SmallInt(value) => ScalarValue::Int16(Some(*value)),
                    Value::Int(value) => ScalarValue::Int32(Some(*value)),
                    Value::BigInt(value) => ScalarValue::Int64(Some(*value)),
                    Value::UTinyInt(value) => ScalarValue::UInt8(Some(*value)),
                    Value::USmallInt(value) => ScalarValue::UInt16(Some(*value)),
                    Value::UInt(value) => ScalarValue::UInt32(Some(*value)),
                    Value::UBigInt(value) => ScalarValue::UInt64(Some(*value)),
                    Value::Float(value) if value.is_finite() => ScalarValue::Float32(Some(*value)),
                    Value::Double(value) if value.is_finite() => ScalarValue::Float64(Some(*value)),
                    Value::Text(value) => ScalarValue::Utf8(Some(value.clone())),
                    Value::Blob(value) => ScalarValue::Binary(Some(value.clone())),
                    Value::Timestamp(unit, value) => {
                        let micros = match unit {
                            TimeUnit::Second => value.checked_mul(1_000_000),
                            TimeUnit::Millisecond => value.checked_mul(1_000),
                            TimeUnit::Microsecond => Some(*value),
                            TimeUnit::Nanosecond => Some(value / 1_000),
                        }
                        .ok_or_else(|| {
                            crate::QueryInvalidSnafu {
                                field: "SQL timestamp parameter",
                            }
                            .build()
                        })?;
                        ScalarValue::TimestampMicrosecond(Some(micros), None)
                    }
                    _ => {
                        return crate::QueryInvalidSnafu {
                            field: "SQL parameter type",
                        }
                        .fail();
                    }
                })
            })
            .collect()
    }
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        let runtime = self
            .runtime
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(runtime) = runtime {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use datafusion::arrow::array::Int64Array;
    use datafusion::execution::memory_pool::MemoryConsumer;
    use datafusion::prelude::SessionContext;
    use snafu::IntoError as _;

    use super::*;

    fn execute(engine: &QueryEngine) -> Result<()> {
        engine.run(
            &AnalysisReadControl::with_timeout(Duration::from_secs(5))?,
            async {
                use datafusion::physical_expr::Partitioning;
                use datafusion::physical_plan::{collect, repartition::RepartitionExec};

                let mut state = QueryEngine::state()?;
                state.config_mut().options_mut().execution.batch_size = 1;
                let context = SessionContext::new_with_state(state);
                let schema = Arc::new(araphor_analysis_sdk::Schema::new(vec![
                    araphor_analysis_sdk::Field::new(
                        "value",
                        araphor_analysis_sdk::DataType::Int64,
                        false,
                    ),
                ]));
                let batch = araphor_analysis_sdk::RecordBatch::try_new(
                    schema.clone(),
                    vec![Arc::new(Int64Array::from(vec![7]))],
                )
                .map_err(araphor_analysis_sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
                let bytes = batch.get_array_memory_size();
                let pointer = batch.column(0).to_data().buffers()[0].as_ptr() as usize;
                let budget = super::super::budget::QueryBudget::new(super::super::QueryLimits {
                    input_bytes: bytes,
                    input_capacity: bytes,
                    ..Default::default()
                });
                let lease = budget.model([1; 16], 0)?;
                let batch = lease.retain_batch(&batch)?;
                let input = context
                    .read_table(Arc::new(
                        datafusion::datasource::MemTable::try_new(schema, vec![vec![batch; 513]])
                            .context(crate::QueryEngineSnafu {
                            operation: "create test input",
                        })?,
                    ))
                    .context(crate::QueryEngineSnafu {
                        operation: "plan test input",
                    })?
                    .create_physical_plan()
                    .await
                    .context(crate::QueryEngineSnafu {
                        operation: "plan test execution",
                    })?;
                let plan = Arc::new(
                    RepartitionExec::try_new(input, Partitioning::RoundRobinBatch(2)).context(
                        crate::QueryEngineSnafu {
                            operation: "partition test execution",
                        },
                    )?,
                );
                let batches =
                    collect(plan, context.task_ctx())
                        .await
                        .context(crate::QueryEngineSnafu {
                            operation: "collect test query",
                        })?;
                assert_eq!(
                    batches
                        .iter()
                        .map(araphor_analysis_sdk::RecordBatch::num_rows)
                        .sum::<usize>(),
                    513
                );
                for batch in &batches {
                    assert_eq!(
                        batch.column(0).to_data().buffers()[0].as_ptr() as usize,
                        pointer
                    );
                    let values = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<Int64Array>()
                        .ok_or_else(|| {
                            crate::QueryInvalidSnafu {
                                field: "test result type",
                            }
                            .build()
                        })?;
                    assert!(values.values().iter().all(|value| *value == 7));
                }
                drop(context);
                drop(lease);
                assert!(budget.retained_input(1).is_err());
                drop(batches);
                drop(budget.retained_input(bytes)?);
                Ok(())
            },
        )
    }

    #[test]
    fn works_without_host_runtime() -> Result<()> {
        let engine = QueryEngine::default();
        execute(&engine)?;
        execute(&engine)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn works_in_current_thread_runtime() -> Result<()> {
        execute(&QueryEngine::default())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn works_in_multi_thread_runtime() -> Result<()> {
        execute(&QueryEngine::default())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn works_in_blocking_task() -> Result<()> {
        tokio::task::spawn_blocking(|| execute(&QueryEngine::default()))
            .await
            .context(crate::QueryExecutionSnafu)?
    }

    #[test]
    fn state_limits_resources_and_has_no_external_table_factories() -> Result<()> {
        let first = QueryEngine::state()?;
        let second = QueryEngine::state()?;
        let options = first.config().options();
        assert_eq!(options.execution.target_partitions, 1);
        assert_eq!(options.execution.planning_concurrency, 1);
        assert!(options.optimizer.prefer_existing_union);
        assert!(!options.catalog.information_schema);
        assert!(!options.catalog.create_default_catalog_and_schema);
        assert!(first.catalog_list().catalog_names().is_empty());
        assert!(!options.sql_parser.map_string_types_to_utf8view);
        assert!(options.sql_parser.parse_float_as_decimal);
        assert_eq!(options.sql_parser.default_null_ordering, "nulls_last");
        assert!(first.table_factories().is_empty());
        assert!(first.table_functions().is_empty());
        assert!(first.scalar_functions().contains_key("time_bucket"));
        assert!(!first.runtime_env().disk_manager.tmp_files_enabled());
        assert!(!Arc::ptr_eq(first.runtime_env(), second.runtime_env()));
        let reservation =
            MemoryConsumer::new("test limit").register(&first.runtime_env().memory_pool);
        assert!(reservation.try_grow(MEMORY_LIMIT + 1).is_err());
        Ok(())
    }

    #[test]
    fn cancellation_wakes_pending_operation() -> Result<()> {
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(5))?);
        let cancel = Arc::clone(&control);
        let result = QueryEngine::default().run(&control, async move {
            let _cancel = tokio::spawn(async move {
                tokio::task::yield_now().await;
                cancel.cancel()
            });
            std::future::pending::<Result<()>>().await
        });
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        Ok(())
    }

    #[test]
    fn deadline_wakes_pending_operation() -> Result<()> {
        let result = QueryEngine::default().run(
            &AnalysisReadControl::with_timeout(Duration::from_millis(20))?,
            std::future::pending::<Result<()>>(),
        );
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadDeadline { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_recursive_runtime_wait() -> Result<()> {
        let engine = Arc::new(QueryEngine::default());
        let nested = Arc::clone(&engine);
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
        let nested_control = control.within(Duration::from_secs(5))?;
        engine.run(&control, async move {
            let result = nested.run(&nested_control, async { Ok(()) });
            assert!(matches!(result, Err(crate::Error::AnalysisState { .. })));
            Ok(())
        })
    }

    #[test]
    #[allow(clippy::panic)]
    fn task_panic_preserves_execution_error() -> Result<()> {
        let result = QueryEngine::default().run(
            &AnalysisReadControl::with_timeout(Duration::from_secs(5))?,
            async {
                panic!("test query task panic");
                #[allow(unreachable_code)]
                Ok::<(), crate::Error>(())
            },
        );
        assert!(matches!(result, Err(crate::Error::QueryExecution { .. })));
        Ok(())
    }

    #[test]
    fn engine_errors_preserve_limit_category() {
        use erebor_runtime_error::{ErrorExt as _, StatusCode};
        let source = datafusion::common::DataFusionError::ResourcesExhausted("test pool".into());
        let error = crate::QueryEngineSnafu {
            operation: "test query pool",
        }
        .into_error(source);
        assert_eq!(error.status_code(), StatusCode::InvalidArguments);
        assert_eq!(
            crate::QueryErrorCode::from(&error),
            crate::QueryErrorCode::ResultTooLarge
        );
        let source = datafusion::common::DataFusionError::Execution("test execution".into());
        let error = crate::QueryEngineSnafu {
            operation: "test query execution",
        }
        .into_error(source);
        assert_eq!(error.status_code(), StatusCode::External);
        assert_eq!(
            crate::QueryErrorCode::from(&error),
            crate::QueryErrorCode::EvaluationFailed
        );
    }

    #[test]
    fn parameters_preserve_types_and_reject_unadmitted_values() -> Result<()> {
        let values = QueryEngine::parameters(&[
            Value::Null,
            Value::TinyInt(-3),
            Value::UBigInt(u64::MAX),
            Value::Timestamp(TimeUnit::Nanosecond, -1),
            Value::Text("text".into()),
            Value::Blob(vec![0, 255]),
        ])?;
        assert_eq!(
            values,
            vec![
                ScalarValue::Null,
                ScalarValue::Int8(Some(-3)),
                ScalarValue::UInt64(Some(u64::MAX)),
                ScalarValue::TimestampMicrosecond(Some(0), None),
                ScalarValue::Utf8(Some("text".into())),
                ScalarValue::Binary(Some(vec![0, 255])),
            ]
        );
        for value in [Value::Double(f64::NAN), Value::HugeInt(1), Value::Date32(0)] {
            assert!(matches!(
                QueryEngine::parameters(&[value]),
                Err(crate::Error::QueryInvalid { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn repeated_multi_batch_scans() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_analysis_sdk as sdk;
        use datafusion::arrow::array::UInt64Array;
        use datafusion::datasource::MemTable;
        use std::collections::BTreeMap;

        let capacity = 2048;
        let count = capacity * 2 + 3;
        let schema = Arc::new(sdk::Schema::new(vec![
            sdk::Field::new("id", sdk::DataType::UInt64, false),
            sdk::Field::new("value", sdk::DataType::UInt64, true),
        ]));
        let budget = super::super::budget::QueryBudget::new(super::super::QueryLimits::default());
        let lease = budget.model([1; 16], 0)?;
        let mut batches = Vec::new();
        for start in (0..count).step_by(capacity) {
            let end = count.min(start + capacity);
            let batch = sdk::RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(UInt64Array::from_iter_values(start as u64..end as u64)),
                    Arc::new(UInt64Array::from_iter(
                        (start..end).map(|id| (id >= capacity).then_some(id as u64)),
                    )),
                ],
            )?;
            batches.push(lease.retain_batch(&batch)?);
        }
        assert_eq!(batches.len(), 3);
        let weak = Arc::downgrade(batches[0].column(0));
        let tables = BTreeMap::from([(
            "data".into(),
            Arc::new(MemTable::try_new(schema.clone(), vec![batches])?),
        )]);
        let relations = BTreeMap::from([("data".into(), schema)]);
        let engine = QueryEngine::default();
        let mut state = QueryEngine::state()?;
        state.config_mut().options_mut().execution.batch_size = capacity;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let run = |query: &crate::QuerySql| {
            engine.query(
                &state,
                &query.bind_complete(0)?,
                &tables,
                sdk::Limits::default(),
                &control,
                &lease,
            )
        };
        let ordered = crate::QuerySql::admit_relations(
            "SELECT id, value FROM data ORDER BY id",
            relations.clone(),
        )?;
        let rows = || -> std::result::Result<Vec<_>, Box<dyn std::error::Error>> {
            let mut rows = Vec::new();
            for batch in run(&ordered)? {
                let ids = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("scan ID type")?;
                let values = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("scan value type")?;
                rows.extend(ids.iter().zip(values.iter()));
            }
            Ok(rows)
        };
        let expected = (0..count)
            .map(|id| (Some(id as u64), (id >= capacity).then_some(id as u64)))
            .collect::<Vec<_>>();
        for _ in 0..2 {
            assert_eq!(rows()?, expected);
        }
        for (sql, expected) in [
            (
                "SELECT COUNT(value) FROM data",
                vec![Some((count - capacity) as i64)],
            ),
            (
                "SELECT COUNT(*) FROM data a JOIN data b ON a.id = b.id",
                vec![Some(count as i64)],
            ),
            (
                "SELECT COUNT(*) FROM (SELECT id FROM data UNION ALL SELECT id FROM data) repeated",
                vec![Some((count * 2) as i64)],
            ),
            (
                "SELECT 1::BIGINT AS id UNION ALL SELECT 2::BIGINT AS id",
                vec![Some(1), Some(2)],
            ),
        ] {
            let query = crate::QuerySql::admit_relations(sql, relations.clone())?;
            let mut actual = Vec::new();
            for batch in run(&query)? {
                let counts = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or("scan count type")?;
                actual.extend(counts.iter());
            }
            assert_eq!(actual, expected, "{sql}");
        }
        for sql in [
            "SELECT absent FROM data",
            "SELECT CAST('invalid' AS INTEGER) FROM data",
        ] {
            let result = crate::QuerySql::admit_relations(sql, relations.clone())
                .and_then(|query| run(&query));
            assert!(result.is_err(), "{sql}");
            assert!(weak.upgrade().is_some());
            assert_eq!(rows()?, expected);
        }
        drop(tables);
        assert!(weak.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn unsigned_filter_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_analysis_sdk as sdk;
        use datafusion::arrow::array::UInt64Array;
        use datafusion::datasource::MemTable;
        use std::collections::BTreeMap;

        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::UInt64,
            true,
        )]));
        let batch = sdk::RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(UInt64Array::from(vec![
                None,
                Some(0),
                Some(u64::MAX),
            ]))],
        )?;
        let tables = BTreeMap::from([(
            "data".into(),
            Arc::new(MemTable::try_new(schema.clone(), vec![vec![batch]])?),
        )]);
        let budget = super::super::budget::QueryBudget::new(super::super::QueryLimits::default());
        let lease = budget.model([1; 16], 0)?;
        let engine = QueryEngine::default();
        let state = QueryEngine::state()?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
        for (predicate, expected) in [
            ("value >= 0", vec![Some(0), Some(u64::MAX)]),
            ("value > 0", vec![Some(u64::MAX)]),
            ("value IS NULL", vec![None]),
        ] {
            let sql = crate::QuerySql::admit_relations(
                &format!("SELECT value FROM data WHERE {predicate} ORDER BY value"),
                BTreeMap::from([("data".into(), schema.clone())]),
            )?;
            let batches = engine.query(
                &state,
                &sql.bind_complete(0)?,
                &tables,
                sdk::Limits::default(),
                &control,
                &lease,
            )?;
            let actual = batches
                .iter()
                .map(|batch| {
                    batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<UInt64Array>()
                        .map(|array| array.iter().collect::<Vec<_>>())
                        .ok_or("unsigned result type")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            assert_eq!(actual.concat(), expected, "{predicate}");
        }
        Ok(())
    }
}
