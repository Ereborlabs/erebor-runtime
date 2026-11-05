use std::any::Any;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRequests, ManagedSourceRef, StorePositionV1,
};
use datafusion::arrow::array::{Array as _, RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::memory::{
    MemoryCatalogProvider, MemoryCatalogProviderList, MemorySchemaProvider,
};
use datafusion::catalog::{CatalogProvider, CatalogProviderList, SchemaProvider, TableProvider};
use datafusion::common::runtime::{
    set_join_set_tracer, JoinSetTracer, JoinSetTracerError, SpawnedTask,
};
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
use datafusion::logical_expr::{LogicalPlan, TableType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, ExecutionPlan, RecordBatchStream, SendableRecordBatchStream,
};
use datafusion::sql::parser::{DFParserBuilder, Statement};
use datafusion::sql::planner::object_name_to_table_reference;
use datafusion::sql::sqlparser::ast::Statement as SqlStatement;
use erebor_telemetry::tracing::{instrument::WithSubscriber as _, Instrument as _};
use futures_util::future::{BoxFuture, FutureExt as _};
use futures_util::{StreamExt as _, TryStreamExt};
use snafu::ResultExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::memory::Memory;
use crate::sources::{ArrowSnapshot, ReadMode, ScanBounds, SourceSnapshot};
use crate::{BusySnafu, InvalidSnafu, Result, SqlSnafu};

mod admission;
mod coverage;
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

struct TaskTracer;

impl JoinSetTracer for TaskTracer {
    fn trace_future(
        &self,
        future: BoxFuture<'static, Box<dyn Any + Send>>,
    ) -> BoxFuture<'static, Box<dyn Any + Send>> {
        future.in_current_span().with_current_subscriber().boxed()
    }

    fn trace_block(
        &self,
        operation: Box<dyn FnOnce() -> Box<dyn Any + Send> + Send>,
    ) -> Box<dyn FnOnce() -> Box<dyn Any + Send> + Send> {
        let dispatch = erebor_telemetry::tracing::dispatcher::get_default(Clone::clone);
        let span = erebor_telemetry::tracing::Span::current();
        Box::new(move || {
            erebor_telemetry::tracing::dispatcher::with_default(&dispatch, || {
                span.in_scope(operation)
            })
        })
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
    #[cfg(test)]
    pub(crate) fn add_physical_optimizer_rule(
        &mut self,
        rule: Arc<dyn datafusion::physical_optimizer::PhysicalOptimizerRule + Send + Sync>,
    ) {
        let mut rules = self.state.physical_optimizers().to_vec();
        rules.push(rule);
        self.state = SessionStateBuilder::new_from_existing(self.state.clone())
            .with_physical_optimizer_rules(rules)
            .build();
    }

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

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn guest_cached(
        &self,
        image: &str,
        package: &araphor_package::PackageRefV1,
        export: &str,
    ) -> Result<bool> {
        self.package_runtime
            .guest_cached(image, package, export)
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::External(Box::new(source)),
            })
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn preparation_entry(
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

    pub async fn wait_package_capacity(&self, resource: &str, requested: usize) -> Result<()> {
        self.package_runtime
            .wait_capacity(resource, requested)
            .await
            .map_err(|source| crate::Error::Sql {
                source: DataFusionError::External(Box::new(source)),
            })
    }

    pub fn new(store: Arc<AnalysisStore>, limits: Limits) -> Result<Arc<Self>> {
        limits.validate()?;
        match set_join_set_tracer(&TaskTracer) {
            Ok(()) | Err(JoinSetTracerError::AlreadySet) => {}
        }
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
        // Keep scalar SQL inside the package input scope.
        config
            .options_mut()
            .optimizer
            .enable_physical_uncorrelated_scalar_subquery = false;
        // shortcut: Keep leaf pushdown disabled until native join schema checks pass.
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
        let mut rules = state.physical_optimizers().to_vec();
        let distribution = rules
            .iter()
            .position(|rule| rule.name() == "EnsureRequirements")
            .ok_or_else(|| crate::Error::Sql {
                source: DataFusionError::Internal("the native distribution rule is absent".into()),
            })?;
        rules.insert(distribution, Arc::new(crate::sources::SourceJoin));
        rules.push(Arc::new(crate::sources::SourceLookup));
        let mut functions = state
            .scalar_functions()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        functions.push(Arc::new(coverage::CoverageProof::function()));
        let state = SessionStateBuilder::new_from_existing(state)
            .with_scalar_functions(functions)
            .with_physical_optimizer_rules(rules)
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
                let plan = crate::planner::Planner::new(&context.state())
                    .statement(statement)
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
        let pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let (send, receive) = tokio::sync::oneshot::channel();
        let dispatch = erebor_telemetry::tracing::dispatcher::get_default(Clone::clone);
        let span = erebor_telemetry::tracing::Span::current();
        let worker = tokio::task::spawn_blocking(move || {
            erebor_telemetry::tracing::dispatcher::with_default(&dispatch, || {
                span.in_scope(|| {
                    let _lease = lease;
                    drop(send.send(operation()));
                })
            })
        });
        Self::join_worker(control, pending, worker, receive).await
    }

    pub(crate) async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        control: Arc<AnalysisReadControl>,
        lease: impl Send + 'static,
        operation: impl Future<Output = Result<T>> + Send + 'static,
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
        let mut pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
        let engine = Arc::clone(self);
        let worker = {
            let _entered = handle.enter();
            SpawnedTask::spawn(
                async move {
                    let _engine = engine;
                    let _lease = lease;
                    operation.await
                }
                .in_current_span()
                .with_current_subscriber(),
            )
        };
        let result = worker.await;
        pending.active = false;
        result.map_err(|source| crate::Error::Sql {
            source: DataFusionError::External(Box::new(source)),
        })?
    }

    async fn plan_physical(
        self: &Arc<Self>,
        state: SessionState,
        plan: LogicalPlan,
        control: Arc<AnalysisReadControl>,
        lease: impl Send + 'static,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let pending = PendingRead {
            control: Arc::clone(&control),
            active: true,
        };
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
        let (send, receive) = tokio::sync::oneshot::channel();
        let engine = Arc::clone(self);
        let stage = Arc::clone(&control);
        let worker = handle.spawn(
            async move {
                let _engine = engine;
                let _lease = lease;
                let result = stage
                    .query_async(async move {
                        state
                            .query_planner()
                            .create_physical_plan(&plan, &state)
                            .await
                            .context(SqlSnafu)
                    })
                    .await;
                drop(send.send(result));
            }
            .in_current_span()
            .with_current_subscriber(),
        );
        Self::join_worker(control, pending, worker, receive).await
    }

    async fn join_worker<T: Send + 'static>(
        control: Arc<AnalysisReadControl>,
        mut pending: PendingRead,
        mut worker: tokio::task::JoinHandle<()>,
        receive: tokio::sync::oneshot::Receiver<Result<T>>,
    ) -> Result<T> {
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
            if matches!(
                control.check(),
                Err(araphor_data::Error::AnalysisReadCancelled { .. })
            ) {
                let _cancelled = control.cancel();
            }
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
            reference: None,
            replay_frontier: None,
            nested_permit: None,
            definition: None,
            source_index: None,
            workers: None,
            context_init: None,
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
        handle.spawn(
            async move {
                let _sent = send.send(future.await);
            }
            .in_current_span()
            .with_current_subscriber(),
        );
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
    Changes(StorePositionV1),
    Page(Option<StorePositionV1>),
}

#[derive(Clone)]
pub(crate) enum TableBinding {
    Rows { table: Arc<MemTable>, bytes: usize },
    Provider(Arc<dyn TableProvider>),
}

pub(crate) type LocalTables = BTreeMap<String, TableBinding>;

type ContextInit = dyn Fn(&mut SessionConfig) + Send + Sync;
type ReplayFrontier = (u64, Option<(u64, Arc<crate::definition::CallResult>)>);

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
    pub(crate) reference: Option<Arc<araphor_data::ManagedAttempt>>,
    pub(crate) replay_frontier: Option<ReplayFrontier>,
    pub(crate) nested_permit: Option<Arc<Permit>>,
    pub(crate) definition: Option<Arc<crate::definition::PreparedDefinition>>,
    pub(crate) source_index: Option<Arc<crate::sources::SourceIndex>>,
    pub(crate) workers: Option<araphor_package_runtime::TaskTracker>,
    context_init: Option<Arc<ContextInit>>,
    output_rows: usize,
    output_bytes: usize,
}

pub(crate) struct CapturedPhysical {
    physical: Arc<dyn ExecutionPlan>,
    pub(crate) context: TaskContext,
    pub(crate) snapshot: Arc<ArrowSnapshot>,
    pub(crate) recovery: Option<crate::stream::recovery::SourceRecovery>,
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
    pub(crate) fn reserve_complete(&self) -> Result<()> {
        if self
            .physical
            .is::<datafusion::datasource::sink::DataSinkExec>()
        {
            self.reservation
                .try_grow(crate::stream::Output::count_bytes())
                .map_err(|source| crate::Error::Capacity {
                    resource: "shared output",
                    source,
                })?;
        }
        Ok(())
    }

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
    pub fn operation_at(
        &self,
        selection: AnalysisSelectionV1,
        control: &AnalysisReadControl,
        now: u64,
    ) -> Result<Self> {
        let mut session =
            self.engine
                .session_on(selection, control, now, self.engine.memory().scope())?;
        session.tables = Arc::clone(&self.tables);
        session.context_init = self.context_init.clone();
        session.output_rows = self.output_rows;
        session.output_bytes = self.output_bytes;
        Ok(session)
    }

    pub(crate) fn evaluation_permit(&self) -> Result<Arc<Permit>> {
        if let Some(permit) = &self.nested_permit {
            let tenant = self.engine.tenant(self.selection.tenant_id)?;
            if !permit.evaluation || !Arc::ptr_eq(&permit._tenant, &tenant) {
                return InvalidSnafu {
                    field: "nested evaluation permit",
                }
                .fail();
            }
            return Ok(Arc::clone(permit));
        }
        Ok(Arc::new(
            self.engine.reserve_evaluation(self.selection.tenant_id)?,
        ))
    }

    pub fn operation(&self, control: &AnalysisReadControl, now: u64) -> Result<Self> {
        let mut session = self.at(self.selection.clone(), now);
        session.control = Arc::new(control.within(None)?);
        Ok(session)
    }

    pub fn set_context_init(
        &mut self,
        initializer: impl Fn(&mut SessionConfig) + Send + Sync + 'static,
    ) {
        self.context_init = Some(Arc::new(initializer));
    }

    pub(crate) fn initialize_context(&self, config: &mut SessionConfig) {
        if let Some(initializer) = &self.context_init {
            initializer(config);
        }
    }

    pub(crate) async fn metadata(
        &self,
        sources: &AnalysisTableRequests,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        control.check()?;
        let capture = SourceSnapshot::new(
            Arc::clone(self.engine.store()),
            self.selection.clone(),
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
        let sources = sources.keys().map(|name| (name.clone(), None)).collect();
        let scope = self.token()?;
        Engine::blocking(control, scope, move || {
            capture
                .capture(&sources, ScanBounds::default(), ReadMode::Metadata)
                .context(SqlSnafu)
        })
        .await
    }

    pub(crate) async fn subscription_metadata(
        &self,
        sources: &AnalysisTableRequests,
        now: u64,
        window: Option<&crate::follow::Window>,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        control.check()?;
        let capture = crate::sources::MetadataRead::new(
            self,
            sources,
            now,
            window,
            control.within(control.remaining()?)?,
        )
        .context(SqlSnafu)?;
        let scope = self.token()?;
        Engine::blocking(control, scope, move || capture.capture().context(SqlSnafu)).await
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
            reference: self.reference.clone(),
            replay_frontier: self.replay_frontier.clone(),
            nested_permit: self.nested_permit.clone(),
            definition: self.definition.clone(),
            source_index: None,
            workers: self.workers.clone(),
            context_init: self.context_init.clone(),
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

    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    pub fn selection(&self) -> &AnalysisSelectionV1 {
        &self.selection
    }

    pub fn control(&self) -> &Arc<AnalysisReadControl> {
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
            .fold(bytes, |total, (_, table)| match table {
                TableBinding::Rows { bytes, .. } => total.saturating_add(*bytes),
                TableBinding::Provider(_) => total,
            });
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
        Arc::make_mut(&mut self.tables).insert(
            name.to_owned(),
            TableBinding::Rows {
                table: Arc::new(table),
                bytes,
            },
        );
        Ok(())
    }

    pub fn register_table(&mut self, name: &str, provider: Arc<dyn TableProvider>) -> Result<()> {
        self.control.check()?;
        let provider = crate::definition::PackageCall::defer_view(provider).context(SqlSnafu)?;
        Arc::make_mut(&mut self.tables).insert(name.to_owned(), TableBinding::Provider(provider));
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
                        .query_async(async {
                            std::future::poll_fn(|context| {
                                crate::parser::Parser::stack(|| stream.poll_next_unpin(context))
                            })
                            .await
                            .transpose()
                            .context(SqlSnafu)
                        })
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
        if physical.is::<datafusion::datasource::sink::DataSinkExec>() {
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
        let mut package = false;
        crate::sources::PortExec::apply(physical, &mut |node| {
            if node.is::<crate::definition::physical::PackageExec>() {
                package = true;
                return Ok(datafusion::common::tree_node::TreeNodeRecursion::Stop);
            }
            Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
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
        let clock = match self
            .calls
            .as_ref()
            .and_then(|calls| calls.invocation().time_utc_ns)
        {
            Some(now) => chrono::DateTime::from_timestamp_nanos(now),
            None => chrono::DateTime::from_timestamp(
                (self.now / 1_000_000_000) as i64,
                (self.now % 1_000_000_000) as u32,
            )
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "execution time",
                }
                .build()
            })?,
        };
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
        let mut planning = state.clone();
        let calls = self.calls.clone();
        let plan = Engine::blocking(Arc::clone(&control), self.token()?, move || {
            crate::parser::Parser::stack(|| match &calls {
                Some(calls) if calls.has_windows() => {
                    let plan = planning.analyzer().execute_and_check(
                        plan,
                        planning.config_options(),
                        |_, _| {},
                    )?;
                    let plan = calls.bind_window_clocks(plan, &planning)?;
                    if let Some(clock) = calls.window_clock(crate::follow::WindowSource::Query)? {
                        planning.execution_props_mut().query_execution_start_time =
                            Some(chrono::DateTime::from_timestamp_nanos(clock));
                    }
                    planning.optimizer().optimize(plan, &planning, |_, _| {})
                }
                _ => planning.optimize(&plan),
            })
            .context(SqlSnafu)
        })
        .await?;
        self.engine
            .plan_physical(
                {
                    if let Some(clock) = self
                        .calls
                        .as_ref()
                        .map(|calls| calls.window_clock(crate::follow::WindowSource::Query))
                        .transpose()
                        .context(SqlSnafu)?
                        .flatten()
                    {
                        state.execution_props_mut().query_execution_start_time =
                            Some(chrono::DateTime::from_timestamp_nanos(clock));
                    }
                    state
                },
                plan,
                control,
                self.token()?,
            )
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
        let mut hydration = self.clone();
        hydration.nested_permit = Some(Arc::clone(&permit));
        if hydration.definition.is_none() {
            hydration.definition = context
                .session_config()
                .get_extension::<crate::stream::Run>()
                .and_then(|run| {
                    run.managed
                        .as_ref()
                        .map(|(definition, _)| Arc::new(definition.clone()))
                });
        }
        let mut requests = sources.clone();
        let run = context
            .session_config()
            .get_extension::<crate::stream::Run>();
        let mut bounds = SourceSnapshot::requests(
            &mut requests,
            std::slice::from_ref(&physical),
            run.as_deref(),
            self.calls.as_deref(),
        )
        .context(SqlSnafu)?;
        if let Some(calls) = &self.calls {
            for (source, _, _, clock) in &mut bounds.windows {
                *clock = calls.window_clock(*source).context(SqlSnafu)?;
            }
        }
        let mut managed = self.managed.clone();
        let mut read = read;
        let source_index = if let Some(index) = &self.source_index {
            Some(Arc::clone(index))
        } else if (managed.is_some() || self.reference.is_some())
            && crate::sources::SourceLookup::required(&physical, self.calls.as_deref())
                .context(SqlSnafu)?
        {
            Some(
                crate::sources::SourceIndex::new(
                    crate::sources::SourceLookup::keys(&physical, self.calls.as_deref())
                        .context(SqlSnafu)?,
                    Arc::clone(&self.memory),
                )
                .context(SqlSnafu)?,
            )
        } else {
            None
        };
        SourceSnapshot::project_requests(&mut requests, &mut bounds, source_index.is_some())
            .context(SqlSnafu)?;
        if let Some(index) = &source_index {
            let head = index.reference().context(SqlSnafu)?;
            let parent = if let Some(reference) = &self.reference {
                let store = Arc::clone(&self.engine.store);
                let reference = reference.clone();
                let control = Arc::new(self.control.operation()?);
                Engine::blocking(Arc::clone(&control), self.token()?, move || {
                    store
                        .managed_parent(&reference, &control)
                        .map_err(Into::into)
                })
                .await?
            } else {
                let managed = managed.as_ref().ok_or_else(|| {
                    araphor_data::PackageErrorCodeV1::Invalid.error("managed source owner")
                })?;
                if head.is_none() && !managed.rebuild {
                    let store = Arc::clone(&self.engine.store);
                    let instance = managed.instance.clone();
                    let control = Arc::new(self.control.operation()?);
                    Engine::blocking(Arc::clone(&control), self.token()?, move || {
                        Ok(store
                            .managed_resume(instance.spec.tenant, &instance.spec.id, &control)?
                            .source)
                    })
                    .await?
                } else {
                    head.clone()
                }
            };
            if head.is_some() && head != parent {
                return Err(araphor_data::PackageErrorCodeV1::Conflict
                    .error("replay source parent")
                    .into());
            }
            if let Some(parent) = parent.as_ref().filter(|_| head.is_none()) {
                let owner = self
                    .reference
                    .as_ref()
                    .map(|reference| reference.instance())
                    .or_else(|| managed.as_ref().map(|managed| &managed.instance))
                    .ok_or_else(|| {
                        araphor_data::PackageErrorCodeV1::Missing.error("source parent owner")
                    })?
                    .clone();
                let parent = parent.clone();
                let requests = requests.clone();
                let ranges = bounds.events.clone();
                let owners = bounds.context_owners.clone();
                let index = Arc::clone(index);
                let store = Arc::clone(&self.engine.store);
                let control = Arc::new(self.control.operation()?);
                let memory = Arc::clone(&self.memory);
                let limits = AnalysisExtractLimits {
                    scan_bytes: self.engine.limits.scan_bytes,
                    input_bytes: self.engine.limits.input_bytes,
                    keys: self.engine.limits.extract_keys,
                    ..Default::default()
                };
                Engine::blocking(Arc::clone(&control), self.token()?, move || {
                    let restored = (|| {
                        let (head, call, _) = store.managed_reference(
                            &owner,
                            &parent.result.result_id,
                            0,
                            &control,
                        )?;
                        if call.is_some()
                            || head
                                .receipt()
                                .is_none_or(|receipt| receipt.selected != parent.result)
                            || head.captured_revision() != parent.position.commit_revision
                            || parent.position.ordinal != u32::MAX
                        {
                            return Err(araphor_data::PackageErrorCodeV1::Invalid
                                .error("source parent reference")
                                .into());
                        }
                        let mut retained = BTreeMap::new();
                        let metadata = memory.reserve_input(0).context(SqlSnafu)?;
                        let receipt = head.receipt().ok_or_else(|| {
                            araphor_data::PackageErrorCodeV1::Missing.error("source parent receipt")
                        })?;
                        for call in head.instance().spec.manifest.calls.keys() {
                            control.check()?;
                            let Some(expected) = receipt
                                .results
                                .get(call)
                                .or_else(|| head.prior_result(*call))
                            else {
                                continue;
                            };
                            let (reference, actual, _) = store.managed_reference(
                                &owner,
                                &expected.result_id,
                                0,
                                &control,
                            )?;
                            let saved = reference.receipt().filter(|receipt| {
                                receipt.commit_revision == expected.commit_revision
                                    && receipt.results.get(call) == Some(expected)
                            });
                            let saved = saved.ok_or_else(|| {
                                araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source retained call")
                            })?;
                            if actual != Some(*call)
                                || saved.selected.commit_revision > parent.result.commit_revision
                            {
                                return Err(araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source retained call")
                                    .into());
                            }
                            let point = ManagedSourceRef {
                                result: saved.selected.clone(),
                                position: araphor_data::StorePositionV1 {
                                    commit_revision: reference.captured_revision(),
                                    ordinal: u32::MAX,
                                },
                            };
                            if let Some(previous) = retained.get(&point.result.commit_revision) {
                                if previous != &point {
                                    return Err(araphor_data::PackageErrorCodeV1::Conflict
                                        .error("source retained point")
                                        .into());
                                }
                            } else {
                                metadata
                                    .try_grow(
                                        std::mem::size_of::<(u64, ManagedSourceRef)>()
                                            .saturating_add(point.result.result_id.capacity()),
                                    )
                                    .context(SqlSnafu)?;
                                retained.insert(point.result.commit_revision, point);
                            }
                        }
                        let mut chain = Vec::new();
                        let mut point = parent.clone();
                        let mut reference = head;
                        let mut call = call;
                        loop {
                            control.check()?;
                            if call.is_some()
                                || reference
                                    .receipt()
                                    .is_none_or(|receipt| receipt.selected != point.result)
                                || reference.captured_revision() != point.position.commit_revision
                                || point.position.ordinal != u32::MAX
                            {
                                return Err(araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source replay point")
                                    .into());
                            }
                            if let Some(expected) = retained.remove(&point.result.commit_revision) {
                                if expected != point {
                                    return Err(araphor_data::PackageErrorCodeV1::Conflict
                                        .error("source replay point")
                                        .into());
                                }
                            }
                            if chain.len() == chain.capacity() {
                                let capacity = chain.capacity();
                                chain.try_reserve_exact(1).map_err(|_| {
                                    araphor_data::PackageErrorCodeV1::Limit
                                        .error("source replay references")
                                })?;
                                metadata
                                    .try_grow(
                                        chain
                                            .capacity()
                                            .saturating_sub(capacity)
                                            .saturating_mul(std::mem::size_of_val(&point)),
                                    )
                                    .context(SqlSnafu)?;
                            }
                            metadata
                                .try_grow(point.result.result_id.capacity())
                                .context(SqlSnafu)?;
                            chain.push(point.clone());
                            if retained.is_empty() {
                                break;
                            }
                            let previous =
                                store.managed_parent(&reference, &control)?.ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Missing
                                        .error("source retained history")
                                })?;
                            if previous.result.commit_revision >= point.result.commit_revision {
                                return Err(araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source replay order")
                                    .into());
                            }
                            point = previous;
                            let (next, actual, _) = store.managed_reference(
                                &owner,
                                &point.result.result_id,
                                0,
                                &control,
                            )?;
                            reference = next;
                            call = actual;
                        }
                        for point in chain.into_iter().rev() {
                            control.check()?;
                            let (reference, call, _) = store.managed_reference(
                                &owner,
                                &point.result.result_id,
                                0,
                                &control,
                            )?;
                            let receipt = reference
                                .receipt()
                                .filter(|receipt| receipt.selected == point.result)
                                .ok_or_else(|| {
                                    araphor_data::PackageErrorCodeV1::Conflict
                                        .error("source replay receipt")
                                })?;
                            if call.is_some()
                                || reference.captured_revision() != point.position.commit_revision
                            {
                                return Err(araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source replay point")
                                    .into());
                            }
                            let restored = index.reference().context(SqlSnafu)?;
                            let mode = if let Some(restored) = restored {
                                if store.managed_parent(&reference, &control)?.as_ref()
                                    != Some(&restored)
                                {
                                    return Err(araphor_data::PackageErrorCodeV1::Conflict
                                        .error("source replay parent")
                                        .into());
                                }
                                araphor_data::AnalysisReadModeV1::Changes(restored.position)
                            } else {
                                araphor_data::AnalysisReadModeV1::Complete
                            };
                            let selection = reference
                                .instance()
                                .spec
                                .destination
                                .selection(&reference.instance().grant.selection)?;
                            let selection = selection.project(&requests)?;
                            let decode =
                                memory.prepare_input(limits.input_bytes).context(SqlSnafu)?;
                            let bound = if memory.input_capacity().is_some()
                                || limits.input_bytes != usize::MAX
                            {
                                decode.size()
                            } else {
                                usize::MAX
                            };
                            let page = store.read_managed_reference(
                                &selection,
                                &reference,
                                araphor_data::AnalysisTableRead {
                                    requests: &requests,
                                    event_ranges: ranges.as_deref(),
                                    mode,
                                    now: reference.request().time_utc_ns,
                                },
                                AnalysisExtractLimits {
                                    input_bytes: bound,
                                    ..limits
                                },
                                &control,
                                owners.as_ref(),
                            )?;
                            let frame = page.state.source().cloned().ok_or_else(|| {
                                araphor_data::PackageErrorCodeV1::Missing
                                    .error("source parent frame")
                            })?;
                            if frame.position() != point.position {
                                return Err(araphor_data::PackageErrorCodeV1::Conflict
                                    .error("source parent position")
                                    .into());
                            }
                            for batch in frame.datasets().iter().flat_map(|data| &data.batches) {
                                memory.retain_input(batch, &decode).context(SqlSnafu)?;
                            }
                            index.restore(frame, receipt, &control).context(SqlSnafu)?;
                        }
                        Ok(())
                    })();
                    if restored.is_err() {
                        index.discard_restore().context(SqlSnafu)?;
                    }
                    restored
                })
                .await?;
            }
            read = parent
                .as_ref()
                .map_or(Read::Snapshot, |parent| Read::Changes(parent.position));
            if let Some(managed) = &mut managed {
                managed.source = Some(parent.map_or(
                    araphor_data::ManagedSourceRead::Initial,
                    araphor_data::ManagedSourceRead::Changes,
                ));
            }
        }
        let snapshot = SourceSnapshot::new(
            Arc::clone(&self.engine.store),
            self.selection.clone(),
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
            managed,
        );
        if let Some(reference) = &self.reference {
            snapshot
                .bind_reference(reference.clone())
                .context(SqlSnafu)?;
        }
        if let Some(index) = &source_index {
            snapshot.bind_index(Arc::clone(index)).context(SqlSnafu)?;
        }
        let mut config = context.session_config().clone();
        config.set_extension(Arc::clone(&permit));
        config.set_extension(Arc::clone(&snapshot));
        let mut replay = hydration.at(hydration.selection.clone(), hydration.now);
        replay.reference = None;
        config.set_extension(Arc::new(replay));
        config.set_extension(
            self.calls
                .clone()
                .unwrap_or_else(|| self.call_context(crate::definition::Invocation::default())),
        );
        self.initialize_context(&mut config);
        let context = TaskContext::new(
            context.task_id(),
            context.session_id(),
            config,
            context.scalar_functions().clone(),
            context.higher_order_functions().clone(),
            context.aggregate_functions().clone(),
            context.window_functions().clone(),
            context.runtime_env(),
        );
        let mode = if self.reference.is_some()
            && source_index.is_none()
            && !requests.values().any(Option::is_some)
        {
            ReadMode::Metadata
        } else {
            match read {
                Read::Snapshot => ReadMode::Snapshot,
                Read::Changes(after) => ReadMode::Changes(after),
                Read::Page(after) => ReadMode::Page(after),
            }
        };
        let mut recovery = run
            .filter(|run| run.follow && run.managed.is_some())
            .map(|run| {
                crate::stream::recovery::SourceRecovery::new(run, self, self.now, requests.clone())
            });
        self.capture(
            Arc::clone(&snapshot),
            requests,
            bounds,
            mode,
            Arc::clone(&permit),
        )
        .await
        .map_err(|error| match recovery.take() {
            Some(recovery) => recovery.failed(error),
            None => error,
        })?;
        hydration.hydrate_source(&snapshot, &physical).await?;
        let captured = snapshot.snapshot().context(SqlSnafu)?;
        Ok(CapturedPhysical {
            physical,
            context,
            snapshot: captured,
            recovery,
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
        bounds: ScanBounds,
        mode: ReadMode,
        permit: Arc<Permit>,
    ) -> Result<()> {
        let control = Arc::new(self.control.within(self.engine.limits.extract_timeout)?);
        let scope = self.token()?;
        Engine::blocking(control, scope, move || {
            let _permit = permit;
            drop(
                snapshot
                    .capture(&requests, bounds, mode)
                    .context(SqlSnafu)?,
            );
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests;
