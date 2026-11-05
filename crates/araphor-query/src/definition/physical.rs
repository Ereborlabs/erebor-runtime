use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use araphor_analysis_sdk as sdk;
use araphor_data::AnalysisReadControl;
use araphor_discovery_definition::ImagePin;
use araphor_package::ModelRef;
use araphor_package_runtime::{Prepared, Runtime, TaskTracker, TaskTrackerToken};
use datafusion::common::tree_node::{Transformed, TreeNodeRecursion};
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::{SessionState, TaskContext};
use datafusion::logical_expr::LogicalPlan;
use datafusion::optimizer::simplify_expressions::SimplifyExpressions;
use datafusion::optimizer::OptimizerRule;
use datafusion::physical_expr::{EquivalenceProperties, OrderingRequirements, PhysicalExpr};
use datafusion::physical_optimizer::output_requirements::OutputRequirements;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, ChildrenPropertiesMode, DisplayAs, DisplayFormatType, Distribution,
    ExecutionPlan, InputDistributionRequirements, Partitioning, PlanProperties,
    ReplaceChildrenOptions, SendableRecordBatchStream,
};
use erebor_telemetry::tracing::{instrument::WithSubscriber as _, Instrument as _};
use futures_util::future::{BoxFuture, FutureExt, Shared, WeakShared};
use futures_util::{stream, StreamExt, TryStreamExt};

use super::PackageCall;
use crate::memory::Memory;
use crate::sources::SourceSnapshot;

mod changes;
pub(crate) mod graph;
mod guest;
mod sql;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct Invocation {
    pub id: String,
    pub seed: Option<u64>,
    pub time_utc_ns: Option<i64>,
    pub inputs: BTreeMap<u64, Vec<sdk::Input>>,
    pub checkpoints: BTreeMap<u64, sdk::Checkpoint>,
    pub previous_outputs: BTreeMap<u64, Vec<sdk::Dataset>>,
}

impl Default for Invocation {
    fn default() -> Self {
        Self {
            id: "package-call".into(),
            seed: None,
            time_utc_ns: None,
            inputs: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            previous_outputs: BTreeMap::new(),
        }
    }
}

pub struct CallResult {
    evaluation: sdk::Evaluation,
    output: sdk::Output,
    origin: Origin,
    retained: Option<araphor_data::analysis::PackageResultRefV1>,
    changes: Option<araphor_data::ManagedChanges>,
    graph: Option<Arc<araphor_data::ManagedGraphJournal>>,
    _input: Arc<MemoryReservation>,
    _output: Arc<MemoryReservation>,
    _metadata: Option<MemoryReservation>,
}

#[derive(Clone, Debug)]
pub struct ExecutionReceipt {
    snapshot: Arc<crate::sources::ArrowSnapshot>,
    calls: BTreeMap<u64, Arc<CallResult>>,
    completed_windows: Vec<crate::follow::WindowRange>,
}

impl ExecutionReceipt {
    pub fn from_context(context: &TaskContext) -> Result<Self> {
        let calls = context
            .session_config()
            .get_extension::<CallContext>()
            .ok_or_else(|| internal("package execution context is absent"))?;
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("package source snapshot is absent"))?;
        context
            .session_config()
            .get_extension::<AnalysisReadControl>()
            .ok_or_else(|| internal("package execution control is absent"))?
            .check()
            .map_err(external)?;
        let snapshot = source.snapshot()?;
        Ok(Self {
            completed_windows: calls.completed_windows(&snapshot)?,
            snapshot,
            calls: calls.results()?,
        })
    }

    pub fn snapshot(&self) -> &crate::sources::ArrowSnapshot {
        &self.snapshot
    }

    pub fn completed_windows(&self) -> &[crate::follow::WindowRange] {
        &self.completed_windows
    }

    pub fn calls(&self) -> &BTreeMap<u64, Arc<CallResult>> {
        &self.calls
    }

    pub fn prepare_ack(&self, context: &TaskContext) -> Result<()> {
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("the publication source is absent"))?;
        if !Arc::ptr_eq(&self.snapshot, &source.snapshot()?) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("publication receipt"),
            ));
        }
        if let Some(view) = source.source_view()? {
            view.prepare_calls(self.calls.keys().copied())?;
        }
        Ok(())
    }

    pub fn acknowledge(
        &self,
        context: &TaskContext,
        revision: u64,
        completed: bool,
        receipt: Option<&araphor_data::ManagedReceipt>,
    ) -> Result<()> {
        let current = Self::from_context(context)?;
        if !Arc::ptr_eq(&self.snapshot, &current.snapshot) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("publication receipt"),
            ));
        }
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("the publication source is absent"))?;
        if let Some(view) = source.source_view()? {
            let proof = view
                .frame()
                .proof()
                .filter(|proof| proof.commit_revision == revision)
                .ok_or_else(|| internal("the source publication acknowledgement differs"))?;
            let receipt = receipt
                .filter(|receipt| {
                    receipt.commit_revision == revision
                        && &receipt.selected == proof.as_ref()
                        && receipt.results.keys().eq(self.calls.keys())
                })
                .ok_or_else(|| internal("the source call acknowledgement differs"))?;
            view.commit(receipt)?;
        }
        if completed {
            context
                .session_config()
                .get_extension::<CallContext>()
                .ok_or_else(|| internal("package execution context is absent"))?
                .publication
                .fetch_max(revision, Ordering::AcqRel);
        }
        Ok(())
    }

    pub async fn blocking<T: Send + 'static>(
        self,
        context: &TaskContext,
        lease: impl Send + 'static,
        operation: impl FnOnce(&AnalysisReadControl) -> crate::Result<T> + Send + 'static,
    ) -> Result<T> {
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("package source snapshot is absent"))?;
        if !Arc::ptr_eq(&self.snapshot, &source.snapshot()?) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("package execution receipt"),
            ));
        }
        source
            .blocking(context, (self, lease), move |_, control| operation(control))
            .await
    }
}

#[derive(Clone)]
struct Origin {
    admission: Arc<()>,
    tenant: [u8; 16],
    image: ImagePin,
    model: ModelRef,
    call: u64,
}

impl Origin {
    fn new(call: &PackageCall) -> Self {
        Self {
            admission: Arc::clone(&call.admission),
            tenant: call.tenant,
            image: call.pin.clone(),
            model: ModelRef {
                package: call.package.clone(),
                export: call.export.clone(),
            },
            call: call.id,
        }
    }

    fn matches(&self, call: &PackageCall) -> bool {
        Arc::ptr_eq(&self.admission, &call.admission) && self.same_call(call)
    }

    fn same_call(&self, call: &PackageCall) -> bool {
        self.tenant == call.tenant
            && self.image == call.pin
            && self.model.package == call.package
            && self.model.export == call.export
            && self.call == call.id
    }
}

impl PackageCall {
    pub fn same_call(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.admission, &other.admission)
            && self.tenant == other.tenant
            && self.pin == other.pin
            && self.package == other.package
            && self.export == other.export
            && self.id == other.id
    }
}

impl CallResult {
    pub fn evaluation(&self) -> &sdk::Evaluation {
        &self.evaluation
    }

    pub fn output(&self) -> &sdk::Output {
        &self.output
    }

    pub fn belongs_to(&self, call: &PackageCall) -> bool {
        self.origin.matches(call)
    }

    pub fn retained(&self) -> Option<&araphor_data::analysis::PackageResultRefV1> {
        self.retained.as_ref()
    }

    pub fn changes(&self) -> Option<&araphor_data::ManagedChanges> {
        self.changes.as_ref()
    }

    pub fn graph(&self) -> Option<&Arc<araphor_data::ManagedGraphJournal>> {
        self.graph.as_ref()
    }
}

impl fmt::Debug for CallResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallResult")
            .field("export", &self.evaluation.export)
            .field("outputs", &self.output.datasets.len())
            .finish_non_exhaustive()
    }
}

type Outcome = std::result::Result<Arc<CallResult>, Arc<DataFusionError>>;
type CallFuture = BoxFuture<'static, Outcome>;
type SharedCall = Shared<CallFuture>;

enum CallState {
    Running(Origin, WeakShared<CallFuture>),
    Complete(Origin, Outcome),
}

pub(crate) struct CallContext {
    runtime: Arc<Runtime>,
    invocation: Invocation,
    memory: Arc<Memory>,
    control: Arc<AnalysisReadControl>,
    now: u64,
    workers: TaskTracker,
    calls: Mutex<BTreeMap<u64, CallState>>,
    graphs: Mutex<BTreeMap<u64, Arc<graph::GraphService>>>,
    publication: AtomicU64,
    pub(crate) completion: Vec<crate::follow::WindowRange>,
    windows: Vec<crate::follow::WindowRange>,
    _windows: Option<MemoryReservation>,
    scope: Option<TaskTracker>,
}

impl fmt::Debug for CallContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallContext")
            .field("id", &self.invocation.id)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl CallContext {
    pub(crate) fn cached(&self, call: &PackageCall) -> Result<bool> {
        let calls = self
            .calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?;
        match calls.get(&call.id) {
            Some(CallState::Complete(origin, result)) => {
                if !origin.matches(call) {
                    return Err(internal("cached package origin differs"));
                }
                let result = result
                    .as_ref()
                    .map_err(|error| DataFusionError::Shared(Arc::clone(error)))?;
                if !result.belongs_to(call) {
                    return Err(internal("cached package result differs"));
                }
                Ok(true)
            }
            Some(CallState::Running(origin, _)) => {
                if !origin.matches(call) {
                    return Err(internal("running package origin differs"));
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }

    pub(crate) fn seed(
        &self,
        call: &PackageCall,
        result: Arc<CallResult>,
        reference: &araphor_data::analysis::PackageResultRefV1,
    ) -> Result<()> {
        self.control.check().map_err(external)?;
        if !result.origin.same_call(call)
            || result.evaluation.export != call.export
            || reference.result_id.is_empty()
            || reference.commit_revision == 0
            || result
                .retained
                .as_ref()
                .is_some_and(|prior| prior != reference)
        {
            return Err(internal("retained package identity differs"));
        }
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?;
        if self.workers.is_closed() {
            return Err(internal("package execution is closed"));
        }
        if let Some(prior) = calls.get(&call.id) {
            return match prior {
                CallState::Complete(origin, Ok(result))
                    if origin.matches(call)
                        && result.belongs_to(call)
                        && result.retained.as_ref() == Some(reference) =>
                {
                    Ok(())
                }
                _ => Err(internal("retained package cache conflicts")),
            };
        }
        let origin = &result.origin;
        let heaps = [
            origin.image.image.package_id.capacity(),
            origin.image.image.revision.capacity(),
            origin.image.digest.capacity(),
            origin.model.package.package_id.capacity(),
            origin.model.package.revision.capacity(),
            origin.model.export.capacity(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(limit)?;
        let bytes = result
            .evaluation
            .metadata_bytes()
            .checked_add(result.output.metadata_bytes())
            .and_then(|bytes| {
                bytes.checked_add(
                    result
                        .changes
                        .as_ref()
                        .map_or(0, araphor_data::ManagedChanges::metadata_bytes),
                )
            })
            .and_then(|bytes| {
                heaps
                    .checked_mul(2)
                    .and_then(|heaps| bytes.checked_add(heaps))
            })
            .and_then(|bytes| bytes.checked_add(reference.result_id.capacity()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CallResult>()))
            .ok_or_else(limit)?;
        let metadata = self.memory.reserve_input(bytes)?;
        let mut origin = result.origin.clone();
        origin.admission = Arc::clone(&call.admission);
        let result = Arc::new(CallResult {
            evaluation: result.evaluation.clone(),
            output: result.output.clone(),
            origin,
            retained: Some(reference.clone()),
            changes: result.changes.clone(),
            graph: None,
            _input: Arc::clone(&result._input),
            _output: Arc::clone(&result._output),
            _metadata: Some(metadata),
        });
        calls.insert(call.id, CallState::Complete(Origin::new(call), Ok(result)));
        Ok(())
    }

    pub(crate) fn invocation(&self) -> &Invocation {
        &self.invocation
    }

    pub fn new(
        runtime: Arc<Runtime>,
        invocation: Invocation,
        memory: Arc<Memory>,
        control: Arc<AnalysisReadControl>,
        now: u64,
        scope: Option<TaskTracker>,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            invocation,
            memory,
            control,
            now,
            workers: TaskTracker::new(),
            calls: Mutex::default(),
            graphs: Mutex::default(),
            publication: AtomicU64::new(0),
            completion: Vec::new(),
            windows: Vec::new(),
            _windows: None,
            scope,
        })
    }

    pub(crate) fn set_windows(
        &mut self,
        windows: Vec<crate::follow::WindowRange>,
    ) -> crate::Result<()> {
        if !windows.is_empty() {
            let bytes = windows
                .capacity()
                .checked_mul(std::mem::size_of::<crate::follow::WindowRange>())
                .ok_or_else(|| {
                    araphor_data::PackageErrorCodeV1::Limit.error("window scope memory")
                })?;
            self._windows = Some(
                self.memory
                    .reserve_input(bytes)
                    .map_err(|source| crate::Error::Sql { source })?,
            );
            self.windows = windows;
        }
        Ok(())
    }

    pub(crate) fn window_clock(&self, source: crate::follow::WindowSource) -> Result<Option<i64>> {
        let Some(window) = self.windows.iter().find(|window| window.source == source) else {
            return Ok(None);
        };
        if i128::from(window.start_utc_ns) <= i128::from(self.now)
            && i128::from(self.now) < i128::from(window.end_utc_ns)
        {
            return Ok(None);
        }
        window
            .end_utc_ns
            .checked_sub(1)
            .map(Some)
            .ok_or_else(|| internal("window statement time"))
    }

    pub(crate) fn has_windows(&self) -> bool {
        !self.windows.is_empty()
    }

    pub(crate) fn bind_window_clocks(
        &self,
        plan: LogicalPlan,
        state: &SessionState,
    ) -> Result<LogicalPlan> {
        let simplify = SimplifyExpressions::new();
        plan.transform_up_with_subqueries(|plan| {
            let LogicalPlan::Extension(extension) = &plan else {
                return Ok(Transformed::no(plan));
            };
            let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() else {
                return Ok(Transformed::no(plan));
            };
            let mut call = call.clone();
            for (slot, child) in call.children.iter_mut().enumerate() {
                let mut scoped = state.clone();
                let clock = if call.input_scope.window(slot).is_some() {
                    self.window_clock(crate::follow::WindowSource::Input {
                        call: call.id,
                        slot,
                    })?
                } else {
                    None
                };
                if let Some(clock) = clock {
                    scoped.execution_props_mut().query_execution_start_time =
                        Some(chrono::DateTime::from_timestamp_nanos(clock));
                }
                *child = child
                    .clone()
                    .transform_down_up_with_subqueries(
                        |plan| {
                            if let LogicalPlan::TableScan(scan) = &plan {
                                if let Ok(provider) =
                                    datafusion::datasource::source_as_provider(&scan.source)
                                {
                                    if let Some(source) =
                                        provider.downcast_ref::<crate::sources::SourcePort>()
                                    {
                                        return source
                                            .clocked(&scoped)
                                            .scan_plan(scan.clone())
                                            .map(Transformed::yes);
                                    }
                                }
                            }
                            let nested = matches!(&plan, LogicalPlan::Extension(extension)
                                if extension.node.as_any().is::<PackageCall>());
                            Ok(Transformed::new(
                                plan,
                                false,
                                if nested {
                                    TreeNodeRecursion::Jump
                                } else {
                                    TreeNodeRecursion::Continue
                                },
                            ))
                        },
                        |plan| simplify.rewrite(plan, &scoped),
                    )?
                    .data;
            }
            Ok(Transformed::yes(LogicalPlan::Extension(
                datafusion::logical_expr::Extension {
                    node: Arc::new(call),
                },
            )))
        })
        .map(|plan| plan.data)
    }

    pub(crate) fn token(&self) -> Result<(TaskTrackerToken, Option<TaskTrackerToken>)> {
        let _calls = self
            .calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?;
        if self.workers.is_closed() {
            return Err(internal("package execution is closed"));
        }
        let scope = self.scope.as_ref().map(TaskTracker::token);
        if self.scope.as_ref().is_some_and(TaskTracker::is_closed) {
            return Err(internal("package parent execution is closed"));
        }
        Ok((self.workers.token(), scope))
    }

    pub(crate) fn completed_windows(
        &self,
        snapshot: &crate::sources::ArrowSnapshot,
    ) -> Result<Vec<crate::follow::WindowRange>> {
        let Some(first) = self.completion.first() else {
            return Ok(Vec::new());
        };
        if self.completion.iter().any(|requested| {
            requested.end_utc_ns != first.end_utc_ns
                || !snapshot
                    .windows
                    .iter()
                    .any(|captured| requested.same_interval(captured))
        }) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("window completion capture"),
            ));
        }
        let mut completed = self.completion.clone();
        for captured in snapshot
            .windows
            .iter()
            .filter(|captured| captured.active && captured.end_utc_ns == first.end_utc_ns)
        {
            if !completed
                .iter()
                .any(|requested| requested.same_interval(captured))
            {
                completed.push(*captured);
            }
        }
        completed.sort_by_key(|window| window.source);
        Ok(completed)
    }

    pub(crate) fn published_revision(&self) -> u64 {
        self.publication.load(Ordering::Acquire)
    }

    pub fn results(&self) -> Result<BTreeMap<u64, Arc<CallResult>>> {
        self.calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?
            .iter()
            .map(|(id, call)| {
                let CallState::Complete(_, result) = call else {
                    return Err(internal("package call has not completed"));
                };
                result
                    .clone()
                    .map(|result| (*id, result))
                    .map_err(DataFusionError::Shared)
            })
            .collect()
    }

    pub async fn finish(&self) {
        let mut pending: stream::FuturesUnordered<_> = {
            let calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.workers.close();
            calls
                .values()
                .filter_map(|call| match call {
                    CallState::Running(_, future) => future.upgrade(),
                    CallState::Complete(_, _) => None,
                })
                .collect()
        };
        // A native join can retain a pending call after its stream is dropped.
        while pending.next().await.is_some() {}
        self.workers.wait().await;
    }

    fn call(self: &Arc<Self>, plan: PackageExec, context: Arc<TaskContext>) -> Result<SharedCall> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?;
        let id = plan.call.id;
        if self.workers.is_closed() {
            return Err(internal("package execution is closed"));
        }
        if let Some(call) = calls.get(&id) {
            let (CallState::Running(previous, _) | CallState::Complete(previous, _)) = call;
            if !previous.matches(&plan.call) {
                return Err(external(
                    araphor_data::PackageErrorCodeV1::Invalid
                        .error("package call identity collision"),
                ));
            }
            return match call {
                CallState::Running(_, call) => call
                    .upgrade()
                    .ok_or_else(|| internal("package call was abandoned")),
                CallState::Complete(_, result) => {
                    let result = result.clone();
                    Ok(async move { result }.boxed().shared())
                }
            };
        }
        let scope = self.scope.as_ref().map(TaskTracker::token);
        if self.scope.as_ref().is_some_and(TaskTracker::is_closed) {
            return Err(internal("package parent execution is closed"));
        }
        let token = self.workers.token();
        let owner = Arc::clone(self);
        let origin = Origin::new(&plan.call);
        let running = origin.clone();
        let future = async move {
            let _token = token;
            let _scope = scope;
            let result = plan
                .evaluate(Arc::clone(&owner), context)
                .await
                .map(Arc::new)
                .map_err(Arc::new);
            if let Ok(mut calls) = owner.calls.lock() {
                calls.insert(id, CallState::Complete(origin, result.clone()));
            }
            result
        }
        .in_current_span()
        .with_current_subscriber()
        .boxed()
        .shared();
        calls.insert(
            id,
            CallState::Running(
                running,
                future
                    .downgrade()
                    .ok_or_else(|| internal("package call future is absent"))?,
            ),
        );
        Ok(future)
    }
}

#[derive(Clone)]
pub(crate) struct PackageExec {
    prepared: Option<Prepared>,
    children: Vec<Arc<dyn ExecutionPlan>>,
    ordering: Vec<Option<OrderingRequirements>>,
    properties: Arc<PlanProperties>,
    call: PackageCall,
    before: BTreeSet<usize>,
}

impl fmt::Debug for PackageExec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageExec")
            .field("id", &self.call.id)
            .field("export", &self.call.export)
            .finish_non_exhaustive()
    }
}

impl PackageExec {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn before_inputs(&self) -> &BTreeSet<usize> {
        &self.before
    }

    pub(super) fn before_plan(&self, slot: usize) -> Result<Option<Arc<dyn ExecutionPlan>>> {
        self.before
            .contains(&slot)
            .then(|| {
                datafusion::physical_plan::execution_plan::reset_plan_states(Arc::clone(
                    &self.children[slot],
                ))
            })
            .transpose()
    }

    pub(crate) fn before_reusable(
        admitted: &LogicalPlan,
        logical: &LogicalPlan,
        physical: &Arc<dyn ExecutionPlan>,
        state: &SessionState,
    ) -> Result<bool> {
        let config = &state.config_options().optimizer;
        if config.enable_dynamic_filter_pushdown
            || config.enable_join_dynamic_filter_pushdown
            || config.enable_topk_dynamic_filter_pushdown
            || config.enable_aggregate_dynamic_filter_pushdown
            || physical.schema().as_ref() != logical.schema().as_arrow()
            || crate::follow::Windows::programs(std::slice::from_ref(logical))
                .map_err(external)?
                .runtime()
        {
            return Ok(false);
        }
        for plan in [admitted, logical] {
            if PackageCall::contains(plan)?
                || crate::follow::Window::clocks(plan).map_err(external)? != 0
                || !crate::stream::physical::SubscribeExec::reusable(plan, &mut BTreeSet::new())?
                || crate::planner::SourceDemand::collect(plan, false)?
                    .iter()
                    .any(|origin| matches!(origin, crate::sources::SourceOrigin::Local(_)))
            {
                return Ok(false);
            }
        }
        let mut scalar = false;
        crate::sources::PortExec::apply(physical, &mut |node| {
            scalar |= node.is::<datafusion::physical_plan::scalar_subquery::ScalarSubqueryExec>();
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(!scalar)
    }

    pub(crate) fn logical_call(&self) -> &PackageCall {
        &self.call
    }

    pub(crate) fn has_changes(&self) -> bool {
        self.call.changes.is_some()
    }

    pub(crate) fn call_id(&self) -> u64 {
        self.call.id
    }

    pub(crate) fn event_inputs(
        &self,
        moving: bool,
    ) -> Result<Vec<(bool, Option<crate::follow::Window>)>> {
        self.call
            .admitted
            .iter()
            .enumerate()
            .map(|(slot, plan)| {
                Ok((
                    self.call.input_scope.uses_events(slot),
                    if moving {
                        self.call
                            .input_scope
                            .window(slot)
                            .map_or_else(
                                || crate::follow::Window::infer(plan).map(|(window, _)| window),
                                Ok,
                            )
                            .map_err(external)?
                    } else {
                        None
                    },
                ))
            })
            .collect()
    }

    pub(crate) async fn new(
        call: &PackageCall,
        children: &[Arc<dyn ExecutionPlan>],
        logical: &[&LogicalPlan],
        state: &SessionState,
    ) -> Result<Self> {
        if children.len() != call.children.len() || logical.len() != children.len() {
            return Err(internal("package physical inputs changed"));
        }
        let mut before = BTreeSet::new();
        for pair in call.changes.iter().flat_map(|changes| &changes.ports) {
            let slot = pair.before;
            let admitted = call
                .admitted
                .get(slot)
                .ok_or_else(|| internal("admitted Before input is absent"))?;
            let input = logical
                .get(slot)
                .ok_or_else(|| internal("logical Before input is absent"))?;
            let child = children
                .get(slot)
                .ok_or_else(|| internal("physical Before input is absent"))?;
            if Self::before_reusable(admitted, input, child, state)? {
                before.insert(slot);
            }
        }
        let prepared = match (
            state.config().get_extension::<Runtime>(),
            state.config().get_extension::<AnalysisReadControl>(),
        ) {
            (Some(runtime), Some(control)) if call.sql.is_none() => {
                let calls = state
                    .config()
                    .get_extension::<CallContext>()
                    .ok_or_else(|| internal("package preparation context is absent"))?;
                let permit = state
                    .config()
                    .get_extension::<crate::execution::Permit>()
                    .ok_or_else(|| internal("package preparation permit is absent"))?;
                let worker = calls.token()?;
                let control = Arc::new(control.within(None).map_err(external)?);
                let stage = Arc::clone(&control);
                let bundle = Arc::clone(&call.bundle);
                let image = Arc::clone(&call._image);
                let package = call.package.clone();
                let export = call.export.clone();
                crate::execution::Engine::blocking(control, worker, move || {
                    let _permit = permit;
                    runtime
                        .prepare(bundle, package, export, &stage)
                        .map(|prepared| (prepared, image))
                        .map_err(|source| crate::Error::Sql {
                            source: external(source),
                        })
                })
                .await
                .map_err(external)?
            }
            _ => (None, Arc::clone(&call._image)),
        };
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(Arc::clone(call.schema.inner())),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Final,
            Boundedness::Bounded,
        ));
        Ok(Self {
            call: call.clone(),
            ordering: children
                .iter()
                .map(|child| {
                    child
                        .properties()
                        .output_ordering()
                        .cloned()
                        .map(OrderingRequirements::from)
                })
                .collect(),
            children: children
                .iter()
                .map(|child| {
                    OutputRequirements::new_add_mode()
                        .optimize(Arc::clone(child), state.config_options())
                })
                .collect::<Result<_>>()?,
            prepared: prepared.0,
            properties,
            before,
        })
    }

    async fn evaluate(
        &self,
        owner: Arc<CallContext>,
        context: Arc<TaskContext>,
    ) -> Result<CallResult> {
        owner.control.check().map_err(external)?;
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("package source snapshot is absent"))?;
        let snapshot = source.snapshot()?;
        if snapshot.selection.tenant_id != self.call.tenant {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Denied.error("package call tenant"),
            ));
        }
        let model = self
            .call
            .model()
            .ok_or_else(|| internal("package export is absent"))?;
        let input = Arc::new(owner.memory.reserve_input(0)?);
        let mut inputs = Vec::with_capacity(model.inputs.len());
        for (slot, port) in model.inputs.iter().enumerate() {
            if self.call.changes.is_some() {
                continue;
            }
            inputs.push(
                self.read_input((slot, slot), port, &owner, &context, &input, &source)
                    .await?,
            );
        }
        let parameters = if model.parameters.fields().is_empty() {
            None
        } else {
            let batches = self
                .collect(
                    model.inputs.len(),
                    &model.parameters,
                    &owner,
                    &context,
                    &input,
                    true,
                )
                .await?;
            Some(Self::parameters(batches)?)
        };
        let (checkpoint, previous_outputs) = match snapshot.managed() {
            Some(managed) => {
                let declaration = managed
                    .instance()
                    .spec
                    .manifest
                    .calls
                    .get(&self.call.id)
                    .ok_or_else(|| {
                        external(
                            araphor_data::PackageErrorCodeV1::Invalid.error("managed package call"),
                        )
                    })?;
                if declaration.image != self.call.pin
                    || declaration.package != self.call.package
                    || declaration.export != self.call.export
                    || declaration.arguments.as_slice() != self.call.arguments()
                {
                    return Err(external(
                        araphor_data::PackageErrorCodeV1::Invalid
                            .error("managed package declaration"),
                    ));
                }
                let view = source.source_view()?;
                managed
                    .prior(self.call.id)
                    .map(|prior| {
                        let reset = model.change_inputs.is_some()
                            && match &view {
                                Some(view) => !view.has_call(self.call.id, prior)?,
                                None => true,
                            };
                        prior
                            .state(
                                model,
                                &inputs,
                                parameters.as_ref(),
                                managed.rebuild() || reset,
                            )
                            .map_err(external)
                    })
                    .transpose()?
                    .unwrap_or_default()
            }
            None => (
                owner.invocation.checkpoints.get(&self.call.id).cloned(),
                owner
                    .invocation
                    .previous_outputs
                    .get(&self.call.id)
                    .cloned()
                    .unwrap_or_default(),
            ),
        };
        let mut evaluation = sdk::Evaluation {
            export: self.call.export.clone(),
            inputs,
            parameters,
            context: sdk::EvaluationContext {
                id: owner.invocation.id.clone(),
                time_utc_ns: match owner.invocation.time_utc_ns {
                    Some(now) => now,
                    None => i64::try_from(owner.now)
                        .map_err(|_| internal("package evaluation time is out of range"))?,
                },
                seed: owner.invocation.seed,
            },
            checkpoint,
            previous_outputs,
        };
        let changes = self
            .change_inputs(
                &mut evaluation,
                snapshot
                    .managed()
                    .and_then(|managed| managed.prior(self.call.id)),
                &owner,
                &context,
                &input,
            )
            .await?;
        if let Some(supplied) = owner.invocation.inputs.get(&self.call.id) {
            self.call
                .input_scope
                .supplied_inputs(&mut evaluation.inputs, supplied)
                .map_err(external)?;
        }
        let reason = "source evidence retention expired";
        if evaluation
            .inputs
            .iter()
            .any(|input| input.coverage.limits.iter().any(|limit| limit == reason))
        {
            let expired = sdk::Coverage {
                state: sdk::CoverageState::Unknown,
                limits: vec![reason.into()],
            };
            for input in &mut evaluation.inputs {
                input.coverage =
                    crate::inputs::Inputs::coverage([&input.coverage, &expired].into_iter());
            }
        }
        let configured = context
            .session_config()
            .get_extension::<crate::execution::Limits>()
            .ok_or_else(|| internal("package execution limits are absent"))?;
        if evaluation.allocated_bytes() > configured.input_bytes {
            return Err(DataFusionError::ResourcesExhausted(
                "package input bytes".into(),
            ));
        }
        for batch in evaluation.batches() {
            owner.memory.retain_input(batch, &input)?;
        }
        input.try_resize(
            evaluation.metadata_bytes().saturating_add(
                changes
                    .as_ref()
                    .map_or(0, araphor_data::ManagedChanges::metadata_bytes),
            ),
        )?;
        let started = Instant::now();
        owner.bind_graph(self, &source, &context).await?;
        let (_admission, output, output_memory) = if self.call.sql.is_some() {
            let output_memory = Arc::new(owner.memory.reserve_output(0)?);
            let output = self
                .sql(&evaluation, &owner, &context, &source, &output_memory)
                .await?;
            let checked = self
                .call
                .descriptor()
                .check_evaluation(&evaluation)
                .map_err(external)?;
            checked.validate_output(&output).map_err(external)?;
            (None, output, output_memory)
        } else {
            let (admission, effective, output, memory) = self
                .guest(evaluation, &owner, Arc::clone(&input), &context)
                .await?;
            evaluation = effective;
            (admission, output, memory)
        };
        owner.control.check().map_err(external)?;
        for batch in output.batches() {
            owner.memory.retain_output(batch, &output_memory)?;
        }
        output_memory.try_resize(output.metadata_bytes())?;
        let graph = match owner.bind_graph(self, &source, &context).await? {
            Some(host) => Some(host.freeze(&source, &context).await?),
            None => None,
        };

        let rows = |name: &str| {
            evaluation
                .inputs
                .iter()
                .find(|input| input.data.name == name)
                .map_or(0, |input| input.data.rows())
        };
        let changed = model
            .change_inputs
            .as_ref()
            .into_iter()
            .flat_map(|contract| &contract.ports)
            .fold((0u64, 0u64, 0u64), |counts, port| {
                (
                    counts.0.saturating_add(rows(&port.affected)),
                    counts.1.saturating_add(rows(&port.before)),
                    counts.2.saturating_add(rows(&port.after)),
                )
            });
        erebor_telemetry::debug!(
            stage = "package",
            instance_id = %snapshot.managed().map_or("", |managed| managed.instance().spec.id.as_str()),
            cut_revision = snapshot.page.extraction.meta.commit_revision,
            call_id = self.call.id,
            package_id = %self.call.package.package_id,
            affected_rows = changed.0,
            before_rows = changed.1,
            after_rows = changed.2,
            rows = evaluation.inputs.iter().fold(0u64, |rows, input| rows.saturating_add(input.data.rows())),
            output_rows = output.datasets.iter().fold(0u64, |rows, data| rows.saturating_add(data.rows())),
            elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "Package execution completed"
        );
        Ok(CallResult {
            evaluation,
            output,
            origin: Origin::new(&self.call),
            retained: None,
            changes,
            graph,
            _input: input,
            _output: output_memory,
            _metadata: None,
        })
    }

    async fn read_input(
        &self,
        (slot, child): (usize, usize),
        port: &sdk::InputPort,
        owner: &CallContext,
        context: &Arc<TaskContext>,
        input: &MemoryReservation,
        source: &SourceSnapshot,
    ) -> Result<sdk::Input> {
        let data = sdk::Dataset {
            name: port.port.name.clone(),
            batches: self
                .collect(child, &port.port.schema, owner, context, input, true)
                .await?,
        };
        let mut completed = Vec::new();
        self.call.children[child].apply_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    if let Some(result) = owner.completed(call.id)? {
                        completed.push(result);
                    }
                    return Ok(TreeNodeRecursion::Jump);
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let inherited = completed
            .iter()
            .flat_map(|result| result.evaluation.inputs.iter())
            .collect::<Vec<_>>();
        self.call
            .input_scope
            .input_for(
                data,
                source,
                (self.call.id, slot, child, &owner.invocation.id),
                &self.children[child],
                &inherited,
                owner,
            )
            .map_err(external)
    }

    pub(crate) fn parameters(batches: Vec<sdk::RecordBatch>) -> Result<sdk::RecordBatch> {
        let invalid = || external(sdk::Error::contract(sdk::ErrorCode::Invalid, "parameters"));
        let mut batches = batches.into_iter().filter(|batch| batch.num_rows() != 0);
        let batch = batches
            .next()
            .filter(|batch| batch.num_rows() == 1)
            .ok_or_else(invalid)?;
        if batches.next().is_some() {
            return Err(invalid());
        }
        Ok(batch)
    }

    #[allow(clippy::too_many_arguments)]
    async fn collect(
        &self,
        slot: usize,
        schema: &sdk::Schema,
        owner: &CallContext,
        context: &Arc<TaskContext>,
        memory: &MemoryReservation,
        input: bool,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let plan = self
            .children
            .get(slot)
            .ok_or_else(|| internal("package physical child is absent"))?;
        let batches = Self::collect_plan(plan, schema, owner, context, memory, input).await?;
        if input {
            let source = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .ok_or_else(|| internal("package source snapshot is absent"))?;
            source.attribute_input(self.call.id, plan, owner)?;
        }
        Ok(batches)
    }

    pub(crate) async fn collect_plan(
        plan: &Arc<dyn ExecutionPlan>,
        schema: &sdk::Schema,
        owner: &CallContext,
        context: &Arc<TaskContext>,
        memory: &MemoryReservation,
        input: bool,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let mut stream = execute_stream(Arc::clone(plan), Arc::clone(context))?;
        let exceeded = || {
            if input {
                external(sdk::Error::contract(sdk::ErrorCode::Limit, "package input"))
            } else {
                limit()
            }
        };
        let schema = Arc::new(schema.clone());
        let mut batches = Vec::new();
        while let Some(batch) = owner
            .control
            .query_async(async {
                stream
                    .try_next()
                    .await
                    .map_err(|source| crate::Error::Sql { source })
            })
            .await
            .map_err(external)?
        {
            let conversion = sdk::Dataset::conversion_bytes(&batch, &schema).map_err(external)?;
            let metadata = memory
                .size()
                .checked_add(std::mem::size_of::<sdk::RecordBatch>())
                .and_then(|bytes| {
                    batch
                        .num_columns()
                        .checked_mul(std::mem::size_of::<sdk::arrow_array::ArrayRef>())
                        .and_then(|headers| bytes.checked_add(headers))
                })
                .ok_or_else(exceeded)?;
            memory.try_resize(metadata.checked_add(conversion).ok_or_else(exceeded)?)?;
            let batch =
                sdk::Dataset::normalize_batch(batch, Arc::clone(&schema)).map_err(external)?;
            if input {
                owner.memory.retain_input(&batch, memory)?;
            } else {
                owner.memory.retain_output(&batch, memory)?;
            }
            memory.try_resize(metadata)?;
            batches.push(batch);
        }
        if batches.is_empty() {
            let batch = sdk::RecordBatch::new_empty(schema);
            batches.push(batch);
        }
        Ok(batches)
    }
}

impl CallContext {
    fn completed(&self, id: u64) -> Result<Option<Arc<CallResult>>> {
        match self
            .calls
            .lock()
            .map_err(|_| internal("package result lock is poisoned"))?
            .get(&id)
        {
            Some(CallState::Complete(_, result)) => {
                result.clone().map(Some).map_err(DataFusionError::Shared)
            }
            _ => Ok(None),
        }
    }
}

fn external(error: impl std::error::Error + Send + Sync + 'static) -> DataFusionError {
    DataFusionError::External(Box::new(error))
}
fn internal(message: &str) -> DataFusionError {
    DataFusionError::Internal(message.into())
}
fn limit() -> DataFusionError {
    DataFusionError::ResourcesExhausted("package allocation size overflow".into())
}

impl DisplayAs for PackageExec {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "PackageExec: id={} {}/{}",
            self.call.id, self.call.export, self.call.output
        )
    }
}

impl ExecutionPlan for PackageExec {
    fn name(&self) -> &str {
        "PackageExec"
    }
    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }
    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        self.children.iter().collect()
    }
    fn input_distribution_requirements(&self) -> InputDistributionRequirements {
        InputDistributionRequirements::new(vec![Distribution::SinglePartition; self.children.len()])
    }
    fn required_input_ordering(&self) -> Vec<Option<OrderingRequirements>> {
        self.ordering.clone()
    }
    fn apply_expressions(
        &self,
        _f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        Ok(TreeNodeRecursion::Continue)
    }
    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        self.replace_children(
            children,
            ReplaceChildrenOptions::new(ChildrenPropertiesMode::Recompute),
        )
    }
    fn replace_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
        _options: ReplaceChildrenOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if children.len() != self.children.len() {
            return Err(internal("package physical child count changed"));
        }
        Ok(Arc::new(Self {
            children,
            ..self.as_ref().clone()
        }))
    }
    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(internal("PackageExec has one output partition"));
        }
        let owner = context
            .session_config()
            .get_extension::<CallContext>()
            .ok_or_else(|| internal("package execution context is absent"))?;
        let plan = self.clone();
        let name = self.call.output.clone();
        let schema = self.schema();
        let batches = stream::once(async move {
            let result = owner
                .call(plan, context)?
                .await
                .map_err(DataFusionError::Shared)?;
            let output = result
                .output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| internal("package named output is absent"))?;
            Ok::<_, DataFusionError>(stream::iter(output.batches.clone().into_iter().map(
                move |batch| {
                    let _result = &result;
                    Ok(batch)
                },
            )))
        })
        .try_flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, batches)))
    }
}
