use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRequests, StorePositionV1,
};
use datafusion::arrow::array::{Array as _, RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::memory::{
    MemoryCatalogProvider, MemoryCatalogProviderList, MemorySchemaProvider,
};
use datafusion::catalog::{CatalogProvider, CatalogProviderList, SchemaProvider, TableProvider};
use datafusion::common::tree_node::TreeNode;
use datafusion::common::DataFusionError;
use datafusion::datasource::MemTable;
use datafusion::execution::config::SessionConfig;
use datafusion::execution::context::SessionContext;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::{SessionState, TaskContext};
use datafusion::logical_expr::execution_props::ExecutionProps;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::logical_expr::{LogicalPlan, TableType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, ExecutionPlan, RecordBatchStream, SendableRecordBatchStream,
};
use datafusion::sql::parser::{DFParserBuilder, Statement};
use datafusion::sql::planner::object_name_to_table_reference;
use datafusion::sql::sqlparser::ast::Statement as SqlStatement;
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
    pub extract_keys: Option<usize>,
    pub extract_timeout: Option<Duration>,
    pub evaluate_timeout: Option<Duration>,
    pub global_evaluations: Option<usize>,
    pub tenant_evaluations: Option<usize>,
    pub global_streams: Option<usize>,
    pub tenant_streams: Option<usize>,
    pub input_capacity: Option<usize>,
    pub output_capacity: Option<usize>,
    pub execution_capacity: Option<usize>,
    pub parser: crate::parser::Parser,
    pub parameter_count: Option<usize>,
    pub parameter_bytes: Option<usize>,
    pub projection_columns: Option<usize>,
    pub window_bound: Option<usize>,
    pub package: araphor_package_runtime::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_bytes: usize::MAX,
            input_bytes: usize::MAX,
            output_rows: usize::MAX,
            output_bytes: usize::MAX,
            extract_keys: None,
            extract_timeout: None,
            evaluate_timeout: None,
            global_evaluations: None,
            tenant_evaluations: None,
            global_streams: None,
            tenant_streams: None,
            input_capacity: None,
            output_capacity: None,
            execution_capacity: None,
            parser: crate::parser::Parser::default(),
            parameter_count: None,
            parameter_bytes: None,
            projection_columns: None,
            window_bound: None,
            package: araphor_package_runtime::Limits::default(),
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        if self.scan_bytes == 0
            || self.input_bytes == 0
            || self.output_bytes == 0
            || self.output_rows == 0
            || self.extract_timeout == Some(Duration::ZERO)
            || self.evaluate_timeout == Some(Duration::ZERO)
            || self
                .global_evaluations
                .is_some_and(|count| count == 0 || count > Semaphore::MAX_PERMITS)
            || self
                .tenant_evaluations
                .is_some_and(|count| count == 0 || count > Semaphore::MAX_PERMITS)
            || self
                .tenant_evaluations
                .zip(self.global_evaluations)
                .is_some_and(|(tenant, global)| tenant > global)
            || self
                .global_streams
                .is_some_and(|count| count > Semaphore::MAX_PERMITS)
            || self
                .tenant_streams
                .is_some_and(|count| count > Semaphore::MAX_PERMITS)
            || self
                .tenant_streams
                .zip(self.global_streams)
                .is_some_and(|(tenant, global)| tenant > global)
            || self.input_capacity.is_some_and(|capacity| {
                capacity == 0 || (self.input_bytes != usize::MAX && capacity < self.input_bytes)
            })
            || self.output_capacity.is_some_and(|capacity| {
                capacity == 0 || (self.output_bytes != usize::MAX && capacity < self.output_bytes)
            })
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
    evaluations: Option<Arc<Semaphore>>,
    streams: Option<Arc<Semaphore>>,
}

pub struct Permit {
    evaluation: bool,
    _tenant: Arc<TenantCapacity>,
    _global: Option<OwnedSemaphorePermit>,
    _local: Option<OwnedSemaphorePermit>,
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
    default_views: BTreeMap<String, Arc<dyn TableProvider>>,
    memory: Arc<Memory>,
    limits: Arc<Limits>,
    package_runtime: Arc<araphor_package_runtime::Runtime>,
    evaluations: Option<Arc<Semaphore>>,
    streams: Option<Arc<Semaphore>>,
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
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn guest_entry(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Result<()> {
        self.package_runtime
            .guest_entry(entered, release)
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::External(Box::new(source)),
            })
    }

    #[cfg(test)]
    pub(crate) fn guest_cached(&self, bytes: &[u8]) -> Result<bool> {
        self.package_runtime
            .guest_cached(bytes)
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::External(Box::new(source)),
            })
    }

    #[cfg(test)]
    pub(crate) fn preparation_entry(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<()> {
        self.package_runtime
            .preparation_entry(entered, release)
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::External(Box::new(source)),
            })
    }

    pub fn new(store: Arc<AnalysisStore>, limits: Limits) -> Result<Arc<Self>> {
        limits.validate()?;
        let package_runtime =
            araphor_package_runtime::Runtime::new(limits.package).map_err(|error| {
                crate::Error::Sql {
                    source: DataFusionError::External(Box::new(error)),
                }
            })?;
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
        // shortcut: DataFusion 53.1 corrupts join schemas in leaf pushdown; enable after the native fix is available.
        config
            .options_mut()
            .optimizer
            .enable_leaf_expression_pushdown = false;
        config.set_extension(Arc::clone(&limits));
        config.set_extension(Arc::clone(&package_runtime));
        let state = SessionStateBuilder::new()
            .with_default_features()
            .with_config(config)
            .with_runtime_env(native)
            .with_query_planner(Arc::new(crate::planner::subscription::SubscriptionPlanner))
            .build();
        Ok(Arc::new(Self {
            store,
            state,
            default_views: BTreeMap::new(),
            memory: Memory::new(limits.input_capacity, limits.output_capacity),
            evaluations: limits
                .global_evaluations
                .map(|count| Arc::new(Semaphore::new(count))),
            streams: limits
                .global_streams
                .map(|count| Arc::new(Semaphore::new(count))),
            tenants: Mutex::default(),
            limits,
            package_runtime,
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

    pub fn register_views(&mut self, sql: &str) -> Result<()> {
        let statements = DFParserBuilder::new(sql)
            .with_recursion_limit(usize::MAX)
            .build()
            .and_then(|mut parser| parser.parse_statements())
            .context(SqlSnafu)?;
        if statements.iter().any(|statement| {
            !matches!(statement, Statement::Statement(statement)
                if matches!(statement.as_ref(), SqlStatement::CreateSchema { .. } | SqlStatement::CreateView(_)))
        }) {
            return InvalidSnafu {
                field: "view registration statement",
            }
            .fail();
        }
        let context = SessionContext::new_with_state(self.catalog(SourceSnapshot::providers())?);
        let (state, views) = self.wait(async move {
            for statement in statements {
                if let Statement::Statement(statement) = &statement {
                    if let SqlStatement::CreateView(view) = statement.as_ref() {
                        let state = context.state();
                        let name = object_name_to_table_reference(
                            view.name.clone(),
                            state.config_options().sql_parser.enable_ident_normalization,
                        )
                        .context(SqlSnafu)?;
                        let config = &state.config_options().catalog;
                        if let Some(catalog) =
                            context.catalog(name.catalog().unwrap_or(&config.default_catalog))
                        {
                            let schema = name.schema().unwrap_or(&config.default_schema);
                            if catalog.schema(schema).is_none() {
                                catalog
                                    .register_schema(schema, Arc::new(MemorySchemaProvider::new()))
                                    .context(SqlSnafu)?;
                            }
                        }
                    }
                }
                let plan = context
                    .state()
                    .statement_to_plan(statement)
                    .await
                    .context(SqlSnafu)?;
                let _frame = context.execute_logical_plan(plan).await.context(SqlSnafu)?;
            }
            let state = context.state();
            let config = &state.config_options().catalog;
            let mut views = BTreeMap::new();
            if let Some(schema) = context
                .catalog(&config.default_catalog)
                .and_then(|catalog| catalog.schema(&config.default_schema))
            {
                for name in schema.table_names() {
                    if let Some(table) = schema.table(&name).await.context(SqlSnafu)? {
                        if table.table_type() == TableType::View {
                            views.insert(name, table);
                        }
                    }
                }
            }
            Ok((state, views))
        })?;
        self.state = state;
        self.default_views = views;
        Ok(())
    }

    pub async fn check_read(self: &Arc<Self>, snapshot: &Arc<ArrowSnapshot>) -> Result<()> {
        self.check_read_scoped(snapshot, ()).await
    }

    async fn check_read_scoped(
        self: &Arc<Self>,
        snapshot: &Arc<ArrowSnapshot>,
        scope: impl Send + 'static,
    ) -> Result<()> {
        if snapshot.page.extraction.trace_reads().is_empty() {
            return Ok(());
        }
        let control = Arc::new(AnalysisReadControl::default().within(self.limits.extract_timeout)?);
        let permit = self.store.reserve_trace_read()?;
        let engine = Arc::clone(self);
        let snapshot = Arc::clone(snapshot);
        let stage = Arc::clone(&control);
        Self::blocking(control, scope, move || {
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

    pub async fn blocking<T: Send + 'static>(
        control: Arc<AnalysisReadControl>,
        lease: impl Send + 'static,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut worker = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            drop(send.send(operation()));
        });
        let result = control
            .query_async(async {
                let result = (&mut worker).await;
                pending.active = false;
                result.map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?;
                receive.await.map_err(|source| crate::Error::Sql {
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
        let mut bindings = self.default_views.clone();
        bindings.extend(tables);
        for (name, table) in bindings {
            schema.register_table(name, table).context(SqlSnafu)?;
        }
        let catalog = Arc::new(MemoryCatalogProvider::new());
        let config = &self.state.config_options().catalog;
        catalog
            .register_schema(&config.default_schema, schema)
            .context(SqlSnafu)?;
        let catalogs = Arc::new(MemoryCatalogProviderList::new());
        for name in self.state.catalog_list().catalog_names() {
            let Some(existing) = self.state.catalog_list().catalog(&name) else {
                continue;
            };
            if name == config.default_catalog {
                for name in existing.schema_names() {
                    if name != config.default_schema {
                        if let Some(schema) = existing.schema(&name) {
                            catalog.register_schema(&name, schema).context(SqlSnafu)?;
                        }
                    }
                }
            } else {
                catalogs.register_catalog(name, existing);
            }
        }
        catalogs.register_catalog(config.default_catalog.clone(), catalog);
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
            tables: Arc::default(),
            calls: None,
            managed: None,
            workers: None,
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
                    evaluations: self
                        .limits
                        .tenant_evaluations
                        .map(|count| Arc::new(Semaphore::new(count))),
                    streams: self
                        .limits
                        .tenant_streams
                        .map(|count| Arc::new(Semaphore::new(count))),
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
        let local = match &tenant.evaluations {
            Some(semaphore) => Some(Arc::clone(semaphore).acquire_owned().await.map_err(error)?),
            None => None,
        };
        let global = match &self.evaluations {
            Some(semaphore) => Some(Arc::clone(semaphore).acquire_owned().await.map_err(error)?),
            None => None,
        };
        Ok(Permit {
            evaluation: true,
            _tenant: tenant,
            _global: global,
            _local: local,
        })
    }

    fn reserve(&self, tenant: [u8; 16], stream: bool) -> Result<Permit> {
        let tenant = self.tenant(tenant)?;
        let (global, local) = if stream {
            (self.streams.as_ref(), tenant.streams.as_ref())
        } else {
            (self.evaluations.as_ref(), tenant.evaluations.as_ref())
        };
        let error = |_| {
            BusySnafu {
                resource: if stream { "stream" } else { "evaluation" },
            }
            .build()
        };
        let global = global
            .map(|semaphore| Arc::clone(semaphore).try_acquire_owned())
            .transpose()
            .map_err(error)?;
        let local = local
            .map(|semaphore| Arc::clone(semaphore).try_acquire_owned())
            .transpose()
            .map_err(error)?;
        Ok(Permit {
            evaluation: !stream,
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

pub(crate) type LocalTables = BTreeMap<String, (Arc<MemTable>, usize)>;

#[derive(Clone)]
pub struct Session {
    engine: Arc<Engine>,
    memory: Arc<Memory>,
    selection: AnalysisSelectionV1,
    pub(crate) control: Arc<AnalysisReadControl>,
    now: u64,
    pub(crate) tables: Arc<LocalTables>,
    pub(crate) calls: Option<Arc<crate::definition::CallContext>>,
    pub(crate) managed: Option<araphor_data::ManagedRead>,
    pub(crate) workers: Option<araphor_package_runtime::TaskTracker>,
    output_rows: usize,
    output_bytes: usize,
}

pub(crate) struct CapturedPhysical {
    physical: Arc<dyn ExecutionPlan>,
    context: TaskContext,
    pub(crate) snapshot: Arc<ArrowSnapshot>,
    pub(crate) permit: Arc<Permit>,
    control: Arc<AnalysisReadControl>,
    timeout: Option<Duration>,
    reservation: MemoryReservation,
}

pub(crate) struct PhysicalStream {
    pub(crate) snapshot: Arc<ArrowSnapshot>,
    pub(crate) stream: SendableRecordBatchStream,
    pub(crate) permit: Arc<Permit>,
    pub(crate) control: Arc<AnalysisReadControl>,
    pub(crate) reservation: MemoryReservation,
}

impl CapturedPhysical {
    pub(crate) fn start(self) -> Result<PhysicalStream> {
        let control = Arc::new(self.control.within(self.timeout)?);
        let mut config = self.context.session_config().clone();
        config.set_extension(Arc::clone(&control));
        let context = Arc::new(self.context.with_session_config(config));
        let stream = execute_stream(self.physical, context).context(SqlSnafu)?;
        Ok(PhysicalStream {
            snapshot: self.snapshot,
            stream,
            permit: self.permit,
            control,
            reservation: self.reservation,
        })
    }
}

impl Session {
    pub(crate) async fn metadata(
        &self,
        sources: &AnalysisTableRequests,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        control.check()?;
        let capture = SourceSnapshot::new(
            Arc::clone(self.engine.store()),
            self.selection.clone(),
            None,
            AnalysisExtractLimits {
                scan_bytes: self.engine.limits.scan_bytes,
                input_bytes: self.engine.limits.input_bytes,
                keys: self.engine.limits.extract_keys,
                ..Default::default()
            },
            control.within(control.remaining()?)?,
            self.engine.limits.extract_timeout,
            self.now,
            Arc::clone(&self.memory),
            self.managed.clone(),
        );
        let sources = sources.clone();
        let scope = self.token()?;
        Engine::blocking(control, scope, move || {
            capture.capture_metadata(&sources).context(SqlSnafu)
        })
        .await
    }

    pub(crate) fn at(&self, selection: AnalysisSelectionV1, now: u64) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
            memory: Arc::clone(&self.memory),
            selection,
            control: Arc::clone(&self.control),
            now,
            tables: Arc::clone(&self.tables),
            calls: None,
            managed: None,
            workers: self.workers.clone(),
            output_rows: self.output_rows,
            output_bytes: self.output_bytes,
        }
    }

    pub(crate) fn token(
        &self,
    ) -> Result<(
        Option<araphor_package_runtime::TaskTrackerToken>,
        Option<araphor_package_runtime::TaskTrackerToken>,
    )> {
        if let Some(calls) = &self.calls {
            let (token, scope) = calls.token().context(SqlSnafu)?;
            Ok((Some(token), scope))
        } else {
            let token = self
                .workers
                .as_ref()
                .map(araphor_package_runtime::TaskTracker::token);
            if self
                .workers
                .as_ref()
                .is_some_and(araphor_package_runtime::TaskTracker::is_closed)
            {
                return InvalidSnafu {
                    field: "execution scope",
                }
                .fail();
            }
            Ok((token, None))
        }
    }

    pub(crate) async fn check_read(&self, snapshot: &Arc<ArrowSnapshot>) -> Result<()> {
        self.engine.check_read_scoped(snapshot, self.token()?).await
    }

    pub(crate) fn output(&self) -> (usize, usize) {
        (self.output_rows, self.output_bytes)
    }

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
        Arc::make_mut(&mut self.tables).insert(name.to_owned(), (Arc::new(table), bytes));
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
        crate::definition::PackageCall::check_admission(plan).context(SqlSnafu)?;
        let tenant = self.engine.tenant(self.selection.tenant_id)?;
        if !permit.evaluation || !Arc::ptr_eq(&permit._tenant, &tenant) {
            return InvalidSnafu {
                field: "evaluation permit",
            }
            .fail();
        }
        let mut state = self.state()?;
        state.config_mut().set_extension(Arc::clone(&permit));
        state.config_mut().set_extension(
            self.calls
                .clone()
                .unwrap_or_else(|| self.call_context(crate::definition::Invocation::default())),
        );
        let physical = self.physical(plan, &state).await?;
        let reservation = Arc::new(self.output_reservation(&physical)?);
        let unspent = Arc::downgrade(&reservation);
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
        crate::definition::PackageCall::check_admission(plan).context(SqlSnafu)?;
        let permit = Arc::new(self.engine.reserve_evaluation(self.selection.tenant_id)?);
        let PhysicalStream {
            snapshot: captured,
            stream,
            permit,
            control,
            reservation,
        } = self
            .capture_plan(plan, sources, read, permit)
            .await?
            .start()?;
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
        let session = self.clone();
        let (rows, bytes) = (self.output_rows, self.output_bytes);
        let stream = futures_util::stream::try_unfold(
            (stream, reservation, 0usize, 0usize, permit),
            move |(mut stream, reservation, count, size, permit)| {
                let memory = Arc::clone(&memory);
                let session = session.clone();
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
                            .query_async(session.check_read(receipt))
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

    fn output_reservation(&self, physical: &Arc<dyn ExecutionPlan>) -> Result<MemoryReservation> {
        if physical
            .as_any()
            .is::<datafusion::datasource::sink::DataSinkExec>()
        {
            // Native DML returns one UInt64 count after the sink commits.
            let count = UInt64Array::from(vec![0]);
            if self.output_rows < 1 || count.get_array_memory_size() > self.output_bytes {
                return Err(crate::Error::Sql {
                    source: DataFusionError::ResourcesExhausted("query output".into()),
                });
            }
            return self
                .memory
                .reserve_output(count.get_buffer_memory_size())
                .context(SqlSnafu);
        }
        let package = physical
            .exists(|node| {
                Ok(node
                    .as_any()
                    .is::<crate::definition::physical::PackageExec>())
            })
            .context(SqlSnafu)?;
        self.memory
            .prepare_output(if package { 0 } else { self.output_bytes })
            .context(SqlSnafu)
    }

    pub(crate) fn call_context(
        &self,
        invocation: crate::definition::Invocation,
    ) -> Arc<crate::definition::CallContext> {
        crate::definition::CallContext::new(
            Arc::clone(&self.engine.package_runtime),
            invocation,
            Arc::clone(&self.memory),
            Arc::clone(&self.control),
            self.now,
            self.workers.clone(),
        )
    }

    pub(crate) fn state(&self) -> Result<SessionState> {
        let mut state = self.engine.state.clone();
        state.config_mut().set_extension(Arc::clone(&self.tables));
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
        let package = crate::definition::PackageCall::contains(plan).context(SqlSnafu)?;
        let mut state = state.clone();
        state.config_mut().set_extension(Arc::clone(&self.control));
        if package {
            let calls = self
                .calls
                .clone()
                .or_else(|| {
                    state
                        .config()
                        .get_extension::<crate::definition::CallContext>()
                })
                .unwrap_or_else(|| self.call_context(crate::definition::Invocation::default()));
            state.config_mut().set_extension(calls);
        }
        let control = if package {
            Arc::clone(&self.control)
        } else {
            Arc::new(self.control.within(self.engine.limits.evaluate_timeout)?)
        };
        let plan = plan.clone();
        let planning = state.clone();
        let plan = Engine::blocking(Arc::clone(&control), self.token()?, move || {
            planning.optimize(&plan).context(SqlSnafu)
        })
        .await?;
        control
            .query_async(async {
                state
                    .query_planner()
                    .create_physical_plan(&plan, &state)
                    .await
                    .context(SqlSnafu)
            })
            .await
    }

    pub(crate) async fn capture_plan(
        &self,
        plan: &LogicalPlan,
        sources: &AnalysisTableRequests,
        read: Read,
        permit: Arc<Permit>,
    ) -> Result<CapturedPhysical> {
        self.control.check()?;
        let mut state = self.state()?;
        state.config_mut().set_extension(Arc::clone(&permit));
        let physical = self.physical(plan, &state).await?;
        self.capture_physical(physical, state.task_ctx(), sources, read, permit)
            .await
    }

    pub(crate) async fn start_physical(
        &self,
        physical: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
        sources: &AnalysisTableRequests,
        read: Read,
        permit: Arc<Permit>,
    ) -> Result<PhysicalStream> {
        self.capture_physical(physical, context, sources, read, permit)
            .await?
            .start()
    }

    pub(crate) async fn capture_physical(
        &self,
        physical: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
        sources: &AnalysisTableRequests,
        read: Read,
        permit: Arc<Permit>,
    ) -> Result<CapturedPhysical> {
        self.control.check()?;
        let reservation = self.output_reservation(&physical)?;
        let snapshot = SourceSnapshot::new(
            Arc::clone(&self.engine.store),
            self.selection.clone(),
            None,
            AnalysisExtractLimits {
                scan_bytes: self.engine.limits.scan_bytes,
                input_bytes: self.engine.limits.input_bytes,
                keys: self.engine.limits.extract_keys,
                ..Default::default()
            },
            self.control.within(self.control.remaining()?)?,
            self.engine.limits.extract_timeout,
            self.now,
            Arc::clone(&self.memory),
            self.managed.clone(),
        );
        let mut config = context.session_config().clone();
        config.set_extension(Arc::clone(&permit));
        config.set_extension(Arc::clone(&snapshot));
        config.set_extension(
            self.calls
                .clone()
                .unwrap_or_else(|| self.call_context(crate::definition::Invocation::default())),
        );
        let context = TaskContext::new(
            context.task_id(),
            context.session_id(),
            config,
            context.scalar_functions().clone(),
            context.aggregate_functions().clone(),
            context.window_functions().clone(),
            context.runtime_env(),
        );
        let mode = match read {
            Read::Snapshot => ReadMode::Snapshot,
            Read::Page(after) => ReadMode::Page(after),
        };
        let mut requests = sources.clone();
        let bounds = SourceSnapshot::requests(&mut requests, std::slice::from_ref(&physical))
            .context(SqlSnafu)?;
        let captured = self
            .capture(snapshot, requests, bounds, mode, Arc::clone(&permit))
            .await?;
        Ok(CapturedPhysical {
            physical,
            context,
            snapshot: captured,
            permit,
            control: Arc::clone(&self.control),
            timeout: self.engine.limits.evaluate_timeout,
            reservation,
        })
    }

    pub(crate) async fn capture(
        &self,
        snapshot: Arc<SourceSnapshot>,
        requests: AnalysisTableRequests,
        bounds: BTreeMap<&'static str, Interval>,
        mode: ReadMode,
        permit: Arc<Permit>,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        let scope = self.token()?;
        Engine::blocking(control, scope, move || {
            let _permit = permit;
            snapshot.capture(&requests, bounds, mode).context(SqlSnafu)
        })
        .await
    }
}

#[cfg(test)]
mod tests;
