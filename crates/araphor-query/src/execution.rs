use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRequests, StorePositionV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::memory::{
    MemoryCatalogProvider, MemoryCatalogProviderList, MemorySchemaProvider,
};
use datafusion::catalog::{CatalogProvider, CatalogProviderList, SchemaProvider, TableProvider};
use datafusion::common::tree_node::Transformed;
use datafusion::common::DataFusionError;
use datafusion::datasource::{provider_as_source, source_as_provider, MemTable};
use datafusion::execution::config::SessionConfig;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::{SessionState, TaskContext};
use datafusion::logical_expr::execution_props::ExecutionProps;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, ExecutionPlan, RecordBatchStream, SendableRecordBatchStream,
};
use futures_util::{StreamExt as _, TryStreamExt};
use snafu::ResultExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::memory::Memory;
use crate::sources::{ArrowSnapshot, ReadMode, SourceSnapshot};
use crate::{BusySnafu, InvalidSnafu, Result, SqlSnafu};

mod admission;
mod tables;

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
    pub execution_capacity: Option<usize>,
    pub parser: crate::parser::Parser,
    pub parameter_count: Option<usize>,
    pub parameter_bytes: Option<usize>,
    pub projection_columns: Option<usize>,
    pub window_bound: Option<usize>,
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
            execution_capacity: None,
            parser: crate::parser::Parser::default(),
            parameter_count: None,
            parameter_bytes: None,
            projection_columns: None,
            window_bound: None,
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
            || self.execution_capacity == Some(0)
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
    limits: Arc<Limits>,
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
        let limits = Arc::new(limits);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("araphor-query")
            .enable_all()
            .build()
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::IoError(source),
            })?;
        let mut native = RuntimeEnvBuilder::new().with_disk_manager_builder(
            DiskManagerBuilder::default().with_mode(DiskManagerMode::Disabled),
        );
        if let Some(bytes) = limits.execution_capacity {
            native = native.with_memory_limit(bytes, 1.0);
        }
        let native = native.build_arc().context(SqlSnafu)?;
        let mut config = SessionConfig::new()
            .with_target_partitions(1)
            .with_batch_size(200);
        config.options_mut().execution.planning_concurrency = 1;
        config.set_extension(Arc::clone(&limits));
        let mut optimizers = PhysicalOptimizer::new().rules;
        optimizers.insert(
            optimizers.len() - 1,
            Arc::new(crate::planner::subscription::PageLineage),
        );
        let state = SessionStateBuilder::new()
            .with_default_features()
            .with_physical_optimizer_rules(optimizers)
            .with_config(config)
            .with_runtime_env(native)
            .with_query_planner(Arc::new(crate::planner::subscription::SubscriptionPlanner))
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
        sources: &AnalysisTableRequests,
        control: &AnalysisReadControl,
        now: u64,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(control.within(self.limits.extract_timeout)?);
        control.check()?;
        let capture = SourceSnapshot::new(
            Arc::clone(&self.store),
            selection,
            None,
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
        Self::blocking(control, move || {
            capture.capture_metadata(&sources).context(SqlSnafu)
        })
        .await
    }

    pub async fn check_read(self: &Arc<Self>, snapshot: &Arc<ArrowSnapshot>) -> Result<()> {
        if snapshot.page.extraction.trace_reads().is_empty() {
            return Ok(());
        }
        let control = Arc::new(AnalysisReadControl::with_timeout(
            self.limits.extract_timeout,
        )?);
        let permit = self.store.reserve_trace_read()?;
        let engine = Arc::clone(self);
        let snapshot = Arc::clone(snapshot);
        let stage = Arc::clone(&control);
        Self::blocking(control, move || {
            engine
                .store
                .check_trace_reads(
                    snapshot.selection.tenant_id,
                    snapshot.page.extraction.trace_reads(),
                    &stage,
                    permit,
                )
                .map_err(crate::Error::from)
        })
        .await
    }

    pub(crate) async fn blocking<T: Send + 'static>(
        control: Arc<AnalysisReadControl>,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let mut worker = tokio::task::spawn_blocking(operation);
        let result = control
            .query_async(async {
                let result = (&mut worker).await;
                pending.active = false;
                result.map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?
            })
            .await;
        if pending.active {
            let _result = worker.await;
            pending.active = false;
        }
        result
    }

    pub fn catalog(
        &self,
        tables: BTreeMap<String, Arc<dyn TableProvider>>,
    ) -> Result<SessionState> {
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
        let mut state = self.state.clone();
        state.register_catalog_list(catalogs);
        Ok(state)
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
        self.session_on(selection, control, now, Arc::clone(&self.memory))
    }

    pub fn session_on(
        self: &Arc<Self>,
        selection: AnalysisSelectionV1,
        control: &AnalysisReadControl,
        now: u64,
        memory: Arc<Memory>,
    ) -> Result<Session> {
        if !selection.valid() {
            return InvalidSnafu {
                field: "source selection",
            }
            .fail();
        }
        if !self.memory.same_family(&memory) {
            return InvalidSnafu {
                field: "session memory owner",
            }
            .fail();
        }
        Ok(Session {
            engine: Arc::clone(self),
            memory,
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

    pub async fn acquire_evaluation(&self, tenant: [u8; 16]) -> Result<Permit> {
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

    pub fn wait<T: Send + 'static>(
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

#[derive(Clone, Copy, Debug)]
pub enum Read {
    Snapshot,
    Page(Option<StorePositionV1>),
}

#[derive(Clone)]
pub struct Session {
    engine: Arc<Engine>,
    memory: Arc<Memory>,
    selection: AnalysisSelectionV1,
    control: Arc<AnalysisReadControl>,
    now: u64,
    tables: BTreeMap<String, (Arc<MemTable>, usize)>,
    output_rows: usize,
    output_bytes: usize,
}

impl Session {
    pub fn memory(&self) -> &Arc<Memory> {
        &self.memory
    }

    pub(crate) fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    pub(crate) fn selection(&self) -> &AnalysisSelectionV1 {
        &self.selection
    }

    pub(crate) fn control(&self) -> &Arc<AnalysisReadControl> {
        &self.control
    }

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
        let reservation = self.memory.reserve_input(0).context(SqlSnafu)?;
        for batch in batches {
            self.memory
                .retain_input(batch, &reservation)
                .context(SqlSnafu)?;
        }
        self.tables
            .insert(name.to_owned(), (Arc::new(table), bytes));
        Ok(())
    }

    pub fn execute(
        &self,
        plan: Arc<LogicalPlan>,
        sources: &AnalysisTableRequests,
    ) -> Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        let engine = Arc::clone(&self.engine);
        let session = self.clone();
        let sources = sources.clone();
        engine.wait(async move {
            let (snapshot, stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
            let batches = stream.try_collect().await.context(SqlSnafu)?;
            Ok((snapshot, batches))
        })
    }

    pub async fn stream_local(
        &self,
        plan: &LogicalPlan,
        permit: Arc<Permit>,
    ) -> Result<SendableRecordBatchStream> {
        self.control.check()?;
        if !Arc::ptr_eq(permit._global.semaphore(), &self.engine.evaluations)
            || !Arc::ptr_eq(
                permit._local.semaphore(),
                &self.engine.tenant(self.selection.tenant_id)?.evaluations,
            )
        {
            return InvalidSnafu {
                field: "evaluation permit",
            }
            .fail();
        }
        let reservation = Arc::new(
            self.memory
                .prepare_output(self.output_bytes)
                .context(SqlSnafu)?,
        );
        let unspent = Arc::downgrade(&reservation);
        let state = self.state()?;
        let physical = self.physical(plan, &state).await?;
        let control = Arc::new(self.control.within(self.engine.limits.evaluate_timeout)?);
        let stream = execute_stream(physical, state.task_ctx()).context(SqlSnafu)?;
        let schema = stream.schema();
        let stream = self
            .bounded(stream, permit, control, reservation, None)
            .map(move |item| {
                if let Some(reservation) = unspent.upgrade() {
                    reservation.free();
                }
                item
            });
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }

    pub async fn stream(
        &self,
        plan: &LogicalPlan,
        sources: &AnalysisTableRequests,
        read: Read,
    ) -> Result<(Arc<ArrowSnapshot>, SendableRecordBatchStream)> {
        let permit = Arc::new(self.engine.reserve_evaluation(self.selection.tenant_id)?);
        let (captured, stream, permit, control, reservation) =
            self.start(plan, sources, read, permit).await?;
        let stream = Box::pin(self.bounded(
            stream,
            permit,
            control,
            reservation,
            Some(Arc::clone(&captured)),
        ));
        Ok((captured, stream))
    }

    pub(crate) fn bounded<'a, R>(
        &self,
        stream: SendableRecordBatchStream,
        permit: Arc<Permit>,
        control: Arc<AnalysisReadControl>,
        reservation: R,
        receipt: Option<Arc<ArrowSnapshot>>,
    ) -> impl RecordBatchStream + Send + 'a
    where
        R: Borrow<MemoryReservation> + Send + 'a,
    {
        let schema = stream.schema();
        let memory = Arc::clone(&self.memory);
        let engine = Arc::clone(&self.engine);
        let (rows, bytes) = (self.output_rows, self.output_bytes);
        let stream = futures_util::stream::try_unfold(
            (stream, reservation, 0usize, 0usize, permit),
            move |(mut stream, reservation, count, size, permit)| {
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
                    memory.retain_output(&batch, reservation.borrow())?;
                    Ok(Some((batch, (stream, reservation, count, size, permit))))
                }
            },
        );
        RecordBatchStreamAdapter::new(schema, stream)
    }

    pub(crate) fn state(&self) -> Result<SessionState> {
        let mut state = self.engine.state.clone();
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

    pub(crate) async fn physical(
        &self,
        plan: &LogicalPlan,
        state: &SessionState,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let planning = self.control.within(self.engine.limits.evaluate_timeout)?;
        planning
            .query_async(async {
                let plan = plan
                    .clone()
                    .transform_up_with_subqueries(|plan| {
                        let LogicalPlan::TableScan(mut scan) = plan else {
                            return Ok(Transformed::no(plan));
                        };
                        let declared = source_as_provider(&scan.source)?;
                        if !declared.as_any().is::<MemTable>() {
                            return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
                        }
                        let (table, _) =
                            self.tables.get(scan.table_name.table()).ok_or_else(|| {
                                DataFusionError::Execution("local input table is absent".into())
                            })?;
                        if table.schema() != declared.schema() {
                            return datafusion::common::exec_err!("local input schema changed");
                        }
                        let table: Arc<dyn TableProvider> = table.clone();
                        scan.source = provider_as_source(table);
                        Ok(Transformed::yes(LogicalPlan::TableScan(scan)))
                    })
                    .context(SqlSnafu)?
                    .data;
                state.create_physical_plan(&plan).await.context(SqlSnafu)
            })
            .await
    }

    pub(crate) async fn start(
        &self,
        plan: &LogicalPlan,
        sources: &AnalysisTableRequests,
        read: Read,
        permit: Arc<Permit>,
    ) -> Result<(
        Arc<ArrowSnapshot>,
        SendableRecordBatchStream,
        Arc<Permit>,
        Arc<AnalysisReadControl>,
        MemoryReservation,
    )> {
        self.control.check()?;
        let state = self.state()?;
        let physical = self.physical(plan, &state).await?;
        self.start_physical(physical, state.task_ctx(), sources, read, permit)
            .await
    }

    pub(crate) async fn start_physical(
        &self,
        physical: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
        sources: &AnalysisTableRequests,
        read: Read,
        permit: Arc<Permit>,
    ) -> Result<(
        Arc<ArrowSnapshot>,
        SendableRecordBatchStream,
        Arc<Permit>,
        Arc<AnalysisReadControl>,
        MemoryReservation,
    )> {
        self.control.check()?;
        let reservation = self
            .memory
            .prepare_output(self.output_bytes)
            .context(SqlSnafu)?;
        let snapshot = SourceSnapshot::new(
            Arc::clone(&self.engine.store),
            self.selection.clone(),
            None,
            AnalysisExtractLimits {
                scan_bytes: self.engine.limits.scan_bytes,
                input_bytes: self.engine.limits.input_bytes,
                ..Default::default()
            },
            self.control.within(self.control.remaining()?)?,
            self.engine.limits.extract_timeout,
            self.now,
            Arc::clone(&self.memory),
        );
        let mut config = context.session_config().clone();
        config.set_extension(Arc::clone(&snapshot));
        let context = Arc::new(TaskContext::new(
            context.task_id(),
            context.session_id(),
            config,
            context.scalar_functions().clone(),
            context.aggregate_functions().clone(),
            context.window_functions().clone(),
            context.runtime_env(),
        ));
        let mode = match read {
            Read::Snapshot => ReadMode::Snapshot,
            Read::Page(after) => ReadMode::Page(after),
        };
        let mut requests = sources.clone();
        let received = SourceSnapshot::requests(&mut requests, std::slice::from_ref(&physical))
            .context(SqlSnafu)?;
        let captured = self
            .capture(snapshot, requests, received, mode, Arc::clone(&permit))
            .await?;
        let control = Arc::new(self.control.within(self.engine.limits.evaluate_timeout)?);
        let stream = execute_stream(physical, context).context(SqlSnafu)?;
        Ok((captured, stream, permit, control, reservation))
    }

    pub(crate) async fn capture(
        &self,
        snapshot: Arc<SourceSnapshot>,
        requests: AnalysisTableRequests,
        received: Option<Interval>,
        mode: ReadMode,
        permit: Arc<Permit>,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        Engine::blocking(control, move || {
            let _permit = permit;
            snapshot
                .capture(&requests, received, mode)
                .context(SqlSnafu)
        })
        .await
    }
}

#[cfg(test)]
mod tests;
