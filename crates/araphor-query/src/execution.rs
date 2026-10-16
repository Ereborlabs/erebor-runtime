use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, StorePositionV1,
};
use async_trait::async_trait;
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::memory::{
    MemoryCatalogProvider, MemoryCatalogProviderList, MemorySchemaProvider,
};
use datafusion::catalog::{
    CatalogProvider, CatalogProviderList, SchemaProvider, Session as NativeSession, TableProvider,
};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::MemTable;
use datafusion::execution::config::SessionConfig;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::{GreedyMemoryPool, MemoryReservation};
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::SessionState;
use datafusion::logical_expr::execution_props::ExecutionProps;
use datafusion::logical_expr::{Expr, LogicalPlan, TableType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{execute_stream, ExecutionPlan, SendableRecordBatchStream};
use futures_util::TryStreamExt;
use snafu::ResultExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::memory::Memory;
use crate::sources::{ArrowSnapshot, SourceSnapshot};
use crate::{BusySnafu, InvalidSnafu, Result, SqlSnafu};

mod admission;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub scan_bytes: usize,
    pub input_bytes: usize,
    pub output_rows: usize,
    pub output_bytes: usize,
    pub extract_timeout: Duration,
    pub evaluate_timeout: Duration,
    pub global_evaluations: usize,
    pub tenant_evaluations: usize,
    pub global_streams: usize,
    pub tenant_streams: usize,
    pub input_capacity: usize,
    pub output_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_bytes: 256 * 1024 * 1024,
            input_bytes: 64 * 1024 * 1024,
            output_rows: 200,
            output_bytes: 1024 * 1024,
            extract_timeout: Duration::from_secs(1),
            evaluate_timeout: Duration::from_secs(1),
            global_evaluations: 2,
            tenant_evaluations: 1,
            global_streams: 16,
            tenant_streams: 4,
            input_capacity: 128 * 1024 * 1024,
            output_capacity: 16 * 1024 * 1024,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        if self.scan_bytes == 0
            || self.input_bytes == 0
            || self.output_bytes == 0
            || self.output_rows == 0
            || self.extract_timeout.is_zero()
            || self.evaluate_timeout.is_zero()
            || self.global_evaluations == 0
            || self.tenant_evaluations == 0
            || self.tenant_evaluations > self.global_evaluations
            || self.global_streams == 0
            || self.tenant_streams == 0
            || self.tenant_streams > self.global_streams
            || self.input_capacity < self.input_bytes
            || self.output_capacity < self.output_bytes
        {
            return InvalidSnafu {
                field: "execution limits",
            }
            .fail();
        }
        Ok(())
    }
}

struct TenantCapacity {
    evaluations: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}

pub struct Permit {
    _tenant: Arc<TenantCapacity>,
    _global: OwnedSemaphorePermit,
    _local: OwnedSemaphorePermit,
}

pub(crate) struct PendingRead {
    pub(crate) control: Arc<AnalysisReadControl>,
    pub(crate) active: bool,
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        if self.active {
            let _cancelled = self.control.cancel();
        }
    }
}

pub struct Engine {
    store: Arc<AnalysisStore>,
    state: SessionState,
    memory: Arc<Memory>,
    limits: Limits,
    evaluations: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    tenants: Mutex<BTreeMap<[u8; 16], Weak<TenantCapacity>>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Engine {
    pub fn new(store: Arc<AnalysisStore>, limits: Limits) -> Result<Arc<Self>> {
        limits.validate()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("araphor-query")
            .enable_all()
            .build()
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::IoError(source),
            })?;
        let native = RuntimeEnvBuilder::new()
            .with_memory_pool(Arc::new(GreedyMemoryPool::new(64 * 1024 * 1024)))
            .with_disk_manager_builder(
                DiskManagerBuilder::default().with_mode(DiskManagerMode::Disabled),
            )
            .build_arc()
            .context(SqlSnafu)?;
        let mut config = SessionConfig::new()
            .with_target_partitions(1)
            .with_batch_size(200);
        config.options_mut().execution.planning_concurrency = 1;
        let state = SessionStateBuilder::new()
            .with_default_features()
            .with_config(config)
            .with_runtime_env(native)
            .with_query_planner(Arc::new(crate::planner::subscription::SubscriptionPlanner))
            .build();
        let scalar = state
            .scalar_functions()
            .values()
            .filter(|function| {
                matches!(
                    function.name(),
                    "abs"
                        | "coalesce"
                        | "current_timestamp"
                        | "date_bin"
                        | "character_length"
                        | "lower"
                        | "now"
                        | "nullif"
                        | "upper"
                )
            })
            .cloned()
            .collect();
        let aggregate = state
            .aggregate_functions()
            .values()
            .filter(|function| matches!(function.name(), "avg" | "count" | "max" | "min" | "sum"))
            .cloned()
            .collect();
        let window = state
            .window_functions()
            .values()
            .filter(|function| {
                matches!(
                    function.name(),
                    "dense_rank" | "lag" | "lead" | "rank" | "row_number"
                )
            })
            .cloned()
            .collect();
        let state = SessionStateBuilder::new_from_existing(state)
            .with_table_functions(std::collections::HashMap::new())
            .with_scalar_functions(scalar)
            .with_aggregate_functions(aggregate)
            .with_window_functions(window)
            .build();
        Ok(Arc::new(Self {
            store,
            state,
            memory: Memory::new(limits.input_capacity, limits.output_capacity),
            evaluations: Arc::new(Semaphore::new(limits.global_evaluations)),
            streams: Arc::new(Semaphore::new(limits.global_streams)),
            tenants: Mutex::default(),
            limits,
            runtime: Some(runtime),
        }))
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn memory(&self) -> &Arc<Memory> {
        &self.memory
    }

    pub fn store(&self) -> &Arc<AnalysisStore> {
        &self.store
    }

    pub(crate) async fn metadata(
        self: &Arc<Self>,
        selection: AnalysisSelectionV1,
        sources: &BTreeSet<String>,
        control: &AnalysisReadControl,
        now: u64,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(control.within(self.limits.extract_timeout)?);
        control.check()?;
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let capture = SourceSnapshot::new(
            Arc::clone(&self.store),
            selection,
            AnalysisExtractLimits {
                scan_bytes: self.limits.scan_bytes,
                input_bytes: self.limits.input_bytes,
                ..Default::default()
            },
            control.within(control.remaining()?)?,
            self.limits.extract_timeout,
            now,
            Arc::clone(&self.memory),
        );
        let sources = sources.clone();
        let result = control
            .query_async(async move {
                tokio::task::spawn_blocking(move || capture.capture_metadata(&sources))
                    .await
                    .map_err(|source| crate::Error::Sql {
                        source: DataFusionError::External(Box::new(source)),
                    })?
                    .context(SqlSnafu)
            })
            .await;
        pending.active = result.is_err();
        result
    }

    pub async fn check_read(self: &Arc<Self>, snapshot: &Arc<ArrowSnapshot>) -> Result<()> {
        if snapshot.page.extraction.trace_reads().is_empty() {
            return Ok(());
        }
        let control = Arc::new(AnalysisReadControl::with_timeout(
            self.limits.extract_timeout,
        )?);
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let permit = self.store.reserve_trace_read()?;
        let engine = Arc::clone(self);
        let snapshot = Arc::clone(snapshot);
        let stage = Arc::clone(&control);
        let result = control
            .query_async(async move {
                tokio::task::spawn_blocking(move || {
                    engine.store.check_trace_reads(
                        snapshot.selection.tenant_id,
                        snapshot.page.extraction.trace_reads(),
                        &stage,
                        permit,
                    )
                })
                .await
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?
                .map_err(crate::Error::from)
            })
            .await;
        pending.active = result.is_err();
        result
    }

    pub fn catalog(&self, schemas: BTreeMap<String, SchemaRef>) -> Result<SessionState> {
        let mut tables = SourceSnapshot::providers();
        for (name, schema) in schemas {
            tables.insert(name.clone(), Arc::new(LocalTable { name, schema }));
        }
        let schema = Arc::new(MemorySchemaProvider::new());
        for (name, table) in tables {
            schema.register_table(name, table).context(SqlSnafu)?;
        }
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog
            .register_schema(&self.state.config_options().catalog.default_schema, schema)
            .context(SqlSnafu)?;
        let catalogs = Arc::new(MemoryCatalogProviderList::new());
        catalogs.register_catalog(
            self.state.config_options().catalog.default_catalog.clone(),
            catalog,
        );
        Ok(SessionStateBuilder::new_from_existing(self.state.clone())
            .with_catalog_list(catalogs)
            .build())
    }

    pub fn plan(
        &self,
        state: &SessionState,
        statement: datafusion::sql::parser::Statement,
        parameters: Vec<datafusion::common::ScalarValue>,
    ) -> Result<LogicalPlan> {
        let state = state.clone();
        self.wait(async move {
            crate::planner::Planner::new(&state)
                .build(statement, parameters)
                .await
        })
    }

    pub fn session(
        self: &Arc<Self>,
        selection: AnalysisSelectionV1,
        control: &AnalysisReadControl,
        now: u64,
    ) -> Result<Session> {
        if !selection.valid() {
            return InvalidSnafu {
                field: "source selection",
            }
            .fail();
        }
        Ok(Session {
            engine: Arc::clone(self),
            selection,
            control: Arc::new(control.within(control.remaining()?)?),
            now,
            tables: BTreeMap::new(),
            output_rows: self.limits.output_rows,
            output_bytes: self.limits.output_bytes,
        })
    }

    pub fn reserve_stream(&self, tenant: [u8; 16]) -> Result<Permit> {
        self.reserve(tenant, true)
    }

    pub fn reserve_evaluation(&self, tenant: [u8; 16]) -> Result<Permit> {
        self.reserve(tenant, false)
    }

    fn tenant(&self, tenant: [u8; 16]) -> Result<Arc<TenantCapacity>> {
        let mut tenants = self.tenants.lock().map_err(|_| {
            BusySnafu {
                resource: "tenant registry",
            }
            .build()
        })?;
        tenants.retain(|_, capacity| capacity.strong_count() > 0);
        Ok(tenants
            .get(&tenant)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let capacity = Arc::new(TenantCapacity {
                    evaluations: Arc::new(Semaphore::new(self.limits.tenant_evaluations)),
                    streams: Arc::new(Semaphore::new(self.limits.tenant_streams)),
                });
                tenants.insert(tenant, Arc::downgrade(&capacity));
                capacity
            }))
    }

    pub(crate) async fn acquire_evaluation(&self, tenant: [u8; 16]) -> Result<Permit> {
        let tenant = self.tenant(tenant)?;
        let error = |_| {
            BusySnafu {
                resource: "evaluation",
            }
            .build()
        };
        let local = Arc::clone(&tenant.evaluations)
            .acquire_owned()
            .await
            .map_err(error)?;
        let global = Arc::clone(&self.evaluations)
            .acquire_owned()
            .await
            .map_err(error)?;
        Ok(Permit {
            _tenant: tenant,
            _global: global,
            _local: local,
        })
    }

    fn reserve(&self, tenant: [u8; 16], stream: bool) -> Result<Permit> {
        let tenant = self.tenant(tenant)?;
        let (global, local) = if stream {
            (&self.streams, &tenant.streams)
        } else {
            (&self.evaluations, &tenant.evaluations)
        };
        let error = |_| {
            BusySnafu {
                resource: if stream { "stream" } else { "evaluation" },
            }
            .build()
        };
        let global = Arc::clone(global).try_acquire_owned().map_err(error)?;
        let local = Arc::clone(local).try_acquire_owned().map_err(error)?;
        Ok(Permit {
            _tenant: tenant,
            _global: global,
            _local: local,
        })
    }

    fn wait<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        let handle = self
            .runtime
            .as_ref()
            .ok_or_else(|| {
                BusySnafu {
                    resource: "execution runtime",
                }
                .build()
            })?
            .handle();
        if tokio::runtime::Handle::try_current().is_ok_and(|current| current.id() == handle.id()) {
            return InvalidSnafu {
                field: "synchronous runtime reentry",
            }
            .fail();
        }
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        handle.spawn(async move {
            let _sent = send.send(future.await);
        });
        receive.recv().map_err(|_| {
            BusySnafu {
                resource: "execution runtime",
            }
            .build()
        })?
    }
}

type LocalTables = BTreeMap<String, (Arc<MemTable>, usize)>;

#[derive(Clone, Copy, Debug)]
pub enum Read {
    Snapshot,
    Page(Option<StorePositionV1>),
}

#[derive(Clone)]
pub struct Session {
    engine: Arc<Engine>,
    selection: AnalysisSelectionV1,
    control: Arc<AnalysisReadControl>,
    now: u64,
    tables: LocalTables,
    output_rows: usize,
    output_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum Retention {
    Input,
    Output,
}

impl Session {
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.control = Arc::new(self.control.within(timeout)?);
        Ok(())
    }

    pub fn set_output(&mut self, rows: usize, bytes: usize) -> Result<()> {
        if rows == 0 || bytes == 0 {
            return InvalidSnafu {
                field: "output limits",
            }
            .fail();
        }
        self.output_rows = rows;
        self.output_bytes = bytes;
        Ok(())
    }

    pub fn register(
        &mut self,
        name: &str,
        schema: SchemaRef,
        batches: &[RecordBatch],
    ) -> Result<()> {
        self.control.check()?;
        let bytes = batches
            .iter()
            .map(RecordBatch::get_array_memory_size)
            .sum::<usize>();
        let held = self
            .tables
            .iter()
            .filter(|(key, _)| key.as_str() != name)
            .fold(bytes, |total, (_, (_, bytes))| total.saturating_add(*bytes));
        if held > self.engine.limits.input_bytes {
            return Err(crate::Error::Sql {
                source: DataFusionError::ResourcesExhausted("local input bytes".into()),
            });
        }
        let table = MemTable::try_new(schema, vec![batches.to_vec()]).context(SqlSnafu)?;
        let mut reservation = self.engine.memory.reserve_input(bytes).context(SqlSnafu)?;
        for batch in batches {
            self.engine
                .memory
                .retain_input(batch, &mut reservation)
                .context(SqlSnafu)?;
        }
        self.tables
            .insert(name.to_owned(), (Arc::new(table), bytes));
        Ok(())
    }

    pub fn execute(
        &self,
        plan: Arc<LogicalPlan>,
        sources: &BTreeSet<String>,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        self.collect(plan, sources, Retention::Output)
    }

    pub fn execute_input(
        &self,
        plan: Arc<LogicalPlan>,
        sources: &BTreeSet<String>,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        self.collect(plan, sources, Retention::Input)
    }

    /// Execute an admitted local plan. Durable source tables have no binding.
    pub fn execute_local(&self, plan: Arc<LogicalPlan>) -> Result<Vec<RecordBatch>> {
        let engine = Arc::clone(&self.engine);
        let session = self.clone();
        engine.wait(async move {
            session.control.check()?;
            let permit = Arc::new(
                session
                    .engine
                    .reserve_evaluation(session.selection.tenant_id)?,
            );
            let reservation = session
                .engine
                .memory
                .prepare_output(session.output_bytes)
                .context(SqlSnafu)?;
            let state = session.state()?;
            let physical = session.physical(&plan, &state).await?;
            let control = Arc::new(
                session
                    .control
                    .within(session.engine.limits.evaluate_timeout)?,
            );
            let stream = execute_stream(physical, state.task_ctx()).context(SqlSnafu)?;
            session
                .bounded(
                    stream,
                    permit,
                    control,
                    reservation,
                    Retention::Output,
                    None,
                )
                .try_collect()
                .await
                .context(SqlSnafu)
        })
    }

    fn collect(
        &self,
        plan: Arc<LogicalPlan>,
        sources: &BTreeSet<String>,
        retention: Retention,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        let engine = Arc::clone(&self.engine);
        let session = self.clone();
        let sources = sources.clone();
        engine.wait(async move {
            let (snapshot, stream) = session
                .emit(&plan, &sources, Read::Snapshot, retention)
                .await?;
            let batches = stream.try_collect().await.context(SqlSnafu)?;
            Ok((snapshot, batches))
        })
    }

    pub async fn stream(
        &self,
        plan: &LogicalPlan,
        sources: &BTreeSet<String>,
        read: Read,
    ) -> Result<(Arc<ArrowSnapshot>, SendableRecordBatchStream)> {
        self.emit(plan, sources, read, Retention::Output).await
    }

    async fn emit(
        &self,
        plan: &LogicalPlan,
        sources: &BTreeSet<String>,
        read: Read,
        retention: Retention,
    ) -> Result<(Arc<ArrowSnapshot>, SendableRecordBatchStream)> {
        let permit = Arc::new(self.engine.reserve_evaluation(self.selection.tenant_id)?);
        let (captured, stream, permit, control, reservation) =
            self.start(plan, sources, read, retention, permit).await?;
        let stream = self.bounded(
            stream,
            permit,
            control,
            reservation,
            retention,
            Some(Arc::clone(&captured)),
        );
        Ok((captured, stream))
    }

    fn bounded(
        &self,
        stream: SendableRecordBatchStream,
        permit: Arc<Permit>,
        control: Arc<AnalysisReadControl>,
        reservation: MemoryReservation,
        retention: Retention,
        receipt: Option<Arc<ArrowSnapshot>>,
    ) -> SendableRecordBatchStream {
        let schema = stream.schema();
        let memory = Arc::clone(&self.engine.memory);
        let engine = Arc::clone(&self.engine);
        let (rows, bytes) = (self.output_rows, self.output_bytes);
        let stream = futures_util::stream::try_unfold(
            (stream, reservation, 0usize, 0usize, permit),
            move |(mut stream, mut reservation, count, size, permit)| {
                let memory = Arc::clone(&memory);
                let engine = Arc::clone(&engine);
                let receipt = receipt.clone();
                let control = Arc::clone(&control);
                async move {
                    let batch = control
                        .query_async(async { stream.try_next().await.context(SqlSnafu) })
                        .await
                        .map_err(|source| DataFusionError::External(Box::new(source)))?;
                    let Some(batch) = batch else {
                        return Ok(None);
                    };
                    if let Some(receipt) = &receipt {
                        control
                            .query_async(engine.check_read(receipt))
                            .await
                            .map_err(|source| DataFusionError::External(Box::new(source)))?;
                    }
                    let count = count.saturating_add(batch.num_rows());
                    let size = size.saturating_add(batch.get_array_memory_size());
                    if count > rows || size > bytes {
                        return Err(DataFusionError::ResourcesExhausted("query output".into()));
                    }
                    match retention {
                        Retention::Input => memory.retain_input(&batch, &mut reservation)?,
                        Retention::Output => memory.retain_output(&batch, &mut reservation)?,
                    }
                    Ok(Some((batch, (stream, reservation, count, size, permit))))
                }
            },
        );
        Box::pin(RecordBatchStreamAdapter::new(schema, stream))
    }

    fn state(&self) -> Result<SessionState> {
        let mut state = self.engine.state.clone();
        state
            .config_mut()
            .set_extension(Arc::new(self.tables.clone()));
        let clock = chrono::DateTime::from_timestamp(
            (self.now / 1_000_000_000) as i64,
            (self.now % 1_000_000_000) as u32,
        )
        .ok_or_else(|| {
            InvalidSnafu {
                field: "execution time",
            }
            .build()
        })?;
        *state.execution_props_mut() = ExecutionProps::new().with_query_execution_start_time(clock);
        Ok(state)
    }

    async fn physical(
        &self,
        plan: &LogicalPlan,
        state: &SessionState,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let planning = self.control.within(self.engine.limits.evaluate_timeout)?;
        planning
            .query_async(async { state.create_physical_plan(plan).await.context(SqlSnafu) })
            .await
    }

    pub(crate) async fn subscribe(
        &self,
        plan: &LogicalPlan,
        sources: &BTreeSet<String>,
    ) -> Result<Option<crate::stream::OutputStream>> {
        let snapshot = SourceSnapshot::new(
            Arc::clone(self.engine.store()),
            self.selection.clone(),
            AnalysisExtractLimits {
                scan_bytes: self.engine.limits.scan_bytes,
                input_bytes: self.engine.limits.input_bytes,
                ..Default::default()
            },
            self.control.within(self.control.remaining()?)?,
            self.engine.limits.extract_timeout,
            self.now,
            Arc::clone(self.engine.memory()),
        );
        let mut state = self.state()?;
        state.config_mut().set_extension(snapshot);
        state
            .config_mut()
            .set_extension(Arc::new(crate::stream::Run {
                engine: Arc::clone(&self.engine),
                selection: self.selection.clone(),
                sources: sources.clone(),
                control: Arc::clone(&self.control),
                now: self.now,
            }));
        let logical = match crate::planner::subscription::Subscribe::plan(plan.clone()) {
            Ok(plan) => plan,
            Err(DataFusionError::NotImplemented(_)) => return Ok(None),
            Err(source) => return Err(crate::Error::Sql { source }),
        };
        let physical = self.physical(&logical, &state).await?;
        let subscription = physical
            .as_any()
            .downcast_ref::<crate::stream::physical::SubscribeExec>()
            .ok_or_else(|| crate::Error::Sql {
                source: DataFusionError::Internal("subscription physical root changed".into()),
            })?;
        match subscription.execute_committed(0, state.task_ctx()) {
            Ok(stream) => Ok(Some(stream)),
            Err(crate::Error::Sql {
                source: DataFusionError::NotImplemented(_),
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn start(
        &self,
        plan: &LogicalPlan,
        sources: &BTreeSet<String>,
        read: Read,
        retention: Retention,
        permit: Arc<Permit>,
    ) -> Result<(
        Arc<ArrowSnapshot>,
        SendableRecordBatchStream,
        Arc<Permit>,
        Arc<AnalysisReadControl>,
        MemoryReservation,
    )> {
        self.control.check()?;
        let reservation = match retention {
            Retention::Input => None,
            Retention::Output => Some(
                self.engine
                    .memory
                    .prepare_output(self.output_bytes)
                    .context(SqlSnafu)?,
            ),
        };
        let snapshot = SourceSnapshot::new(
            Arc::clone(&self.engine.store),
            self.selection.clone(),
            AnalysisExtractLimits {
                scan_bytes: self.engine.limits.scan_bytes,
                input_bytes: self.engine.limits.input_bytes,
                ..Default::default()
            },
            self.control.within(self.control.remaining()?)?,
            self.engine.limits.extract_timeout,
            self.now,
            Arc::clone(&self.engine.memory),
        );
        let mut state = self.state()?;
        state.config_mut().set_extension(Arc::clone(&snapshot));
        let physical = self.physical(plan, &state).await?;
        let sources = sources.clone();
        let capture = Arc::clone(&snapshot);
        let capture_permit = Arc::clone(&permit);
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let captured = control
            .query_async(async move {
                tokio::task::spawn_blocking(move || {
                    let _permit = capture_permit;
                    match read {
                        Read::Snapshot => capture.capture(&sources),
                        Read::Page(after) => capture.capture_positions(&sources, after),
                    }
                })
                .await
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?
                .context(SqlSnafu)
            })
            .await?;
        pending.active = false;
        let control = Arc::new(self.control.within(self.engine.limits.evaluate_timeout)?);
        let reservation = match reservation {
            Some(reservation) => reservation,
            None => self
                .engine
                .memory
                .reserve_input(self.output_bytes)
                .context(SqlSnafu)?,
        };
        let stream = execute_stream(physical, state.task_ctx()).context(SqlSnafu)?;
        Ok((captured, stream, permit, control, reservation))
    }
}

#[derive(Debug)]
struct LocalTable {
    name: String,
    schema: SchemaRef,
}

#[async_trait]
impl TableProvider for LocalTable {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        session: &dyn NativeSession,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        let tables = session
            .config()
            .get_extension::<LocalTables>()
            .ok_or_else(|| DataFusionError::Execution("local input tables are absent".into()))?;
        let (table, _) = tables
            .get(&self.name)
            .ok_or_else(|| DataFusionError::Execution("local input table is absent".into()))?;
        if table.schema() != self.schema {
            return datafusion::common::exec_err!("local input schema changed");
        }
        table.scan(session, projection, filters, limit).await
    }
}

#[cfg(test)]
mod tests;
