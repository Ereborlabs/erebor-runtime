use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning,
    PlanProperties, SendableRecordBatchStream,
};
use futures_util::future::{BoxFuture, FutureExt, Shared, WeakShared};
use futures_util::{stream, StreamExt, TryStreamExt};

use super::PackageCall;
use crate::memory::Memory;
use crate::sources::SourceSnapshot;

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
    _input: Arc<MemoryReservation>,
    _output: Arc<MemoryReservation>,
}

pub struct CallReuse {
    allows: Arc<dyn Fn(&PackageCall) -> bool + Send + Sync>,
}

impl CallReuse {
    pub fn new(allows: impl Fn(&PackageCall) -> bool + Send + Sync + 'static) -> Self {
        Self {
            allows: Arc::new(allows),
        }
    }
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

    pub fn acknowledge(&self, context: &TaskContext, revision: u64) -> Result<()> {
        let current = Self::from_context(context)?;
        if !Arc::ptr_eq(&self.snapshot, &current.snapshot) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("publication receipt"),
            ));
        }
        context
            .session_config()
            .get_extension::<CallContext>()
            .ok_or_else(|| internal("package execution context is absent"))?
            .publication
            .fetch_max(revision, Ordering::AcqRel);
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
        Arc::ptr_eq(&self.admission, &call.admission)
            && self.tenant == call.tenant
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
    properties: Arc<PlanProperties>,
    call: PackageCall,
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
                            .map_or_else(|| crate::follow::Window::infer(plan), Ok)
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
            children: children.to_vec(),
            prepared: prepared.0,
            properties,
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
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == self.call.export)
            .ok_or_else(|| internal("package export is absent"))?;
        let input = Arc::new(owner.memory.reserve_input(0)?);
        let mut inputs = Vec::with_capacity(model.inputs.len());
        for (slot, port) in model.inputs.iter().enumerate() {
            let data = sdk::Dataset {
                name: port.port.name.clone(),
                batches: self
                    .collect(slot, &port.port.schema, &owner, &context, &input, true)
                    .await?,
            };
            let mut completed = Vec::new();
            self.call.children[slot].apply_with_subqueries(|plan| {
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
            inputs.push(
                self.call
                    .input_scope
                    .input_for(
                        data,
                        &source,
                        (self.call.id, slot),
                        &self.children[slot],
                        &inherited,
                        &owner.memory,
                    )
                    .map_err(external)?,
            );
        }
        if let Some(supplied) = owner.invocation.inputs.get(&self.call.id) {
            self.call
                .input_scope
                .supplied_inputs(&mut inputs, supplied)
                .map_err(external)?;
        }
        let reason = "source evidence retention expired";
        if inputs
            .iter()
            .any(|input| input.coverage.limits.iter().any(|limit| limit == reason))
        {
            let expired = sdk::Coverage {
                state: sdk::CoverageState::Unknown,
                limits: vec![reason.into()],
            };
            for input in &mut inputs {
                input.coverage =
                    crate::inputs::Inputs::coverage([&input.coverage, &expired].into_iter());
            }
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
                managed
                    .prior(self.call.id)
                    .map(|prior| {
                        prior.state(model, &inputs, parameters.as_ref(), managed.rebuild())
                    })
                    .transpose()
                    .map_err(external)?
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
        let configured = context
            .session_config()
            .get_extension::<crate::execution::Limits>()
            .ok_or_else(|| internal("package execution limits are absent"))?;
        if evaluation.allocated_bytes() > configured.input_bytes {
            return Err(DataFusionError::ResourcesExhausted(
                "package input bytes".into(),
            ));
        }
        for batch in evaluation
            .checkpoint
            .iter()
            .flat_map(|checkpoint| &checkpoint.datasets)
            .chain(&evaluation.previous_outputs)
            .flat_map(|data| &data.batches)
        {
            owner.memory.retain_input(batch, &input)?;
        }
        input.try_resize(input_metadata(&evaluation))?;
        let retained = snapshot
            .managed()
            .filter(|_| self.call.sql.is_none())
            .and_then(|managed| managed.prior(self.call.id))
            .filter(|prior| prior.reusable)
            .filter(|prior| {
                prior
                    .retained
                    .as_ref()
                    .is_some_and(|saved| saved.matches(&evaluation))
            })
            .filter(|_| {
                context
                    .session_config()
                    .get_extension::<CallReuse>()
                    .is_some_and(|reuse| (reuse.allows)(&self.call))
            });
        let reference = retained.map(|prior| araphor_data::analysis::PackageResultRefV1 {
            result_id: prior.result.clone(),
            commit_revision: prior.revision,
        });
        // Keep admission until retained output replaces the exchange reservation.
        let (_admission, output, output_memory) = if let Some(prior) = retained {
            let checked = self
                .call
                .descriptor()
                .check_evaluation(&evaluation)
                .map_err(external)?;
            let output = prior
                .retained
                .as_ref()
                .ok_or_else(|| internal("retained call is absent"))?
                .output
                .clone();
            checked.validate_output(&output).map_err(external)?;
            (None, output, Arc::new(owner.memory.reserve_output(0)?))
        } else if self.call.sql.is_some() {
            let output_memory = Arc::new(owner.memory.reserve_output(0)?);
            let checked = self
                .call
                .descriptor()
                .check_evaluation(&evaluation)
                .map_err(external)?;
            let output = self
                .sql(&evaluation, &owner, &context, &source, &output_memory)
                .await?;
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
        for batch in output
            .datasets
            .iter()
            .chain(
                output
                    .checkpoint
                    .iter()
                    .flat_map(|checkpoint| &checkpoint.datasets),
            )
            .flat_map(|data| &data.batches)
            .chain(output.reasons.iter().map(|reason| &reason.details))
        {
            owner.memory.retain_output(batch, &output_memory)?;
        }
        output_memory.try_resize(output_metadata(&output))?;
        if let Some(reference) = &reference {
            output_memory.try_grow(reference.result_id.capacity())?;
        }
        Ok(CallResult {
            evaluation,
            output,
            origin: Origin::new(&self.call),
            retained: reference,
            _input: input,
            _output: output_memory,
        })
    }

    fn parameters(batches: Vec<sdk::RecordBatch>) -> Result<sdk::RecordBatch> {
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

fn input_metadata(evaluation: &sdk::Evaluation) -> usize {
    evaluation.allocated_bytes().saturating_sub(
        evaluation
            .inputs
            .iter()
            .flat_map(|input| &input.data.batches)
            .chain(evaluation.parameters.iter())
            .chain(
                evaluation
                    .previous_outputs
                    .iter()
                    .flat_map(|data| &data.batches),
            )
            .chain(
                evaluation
                    .checkpoint
                    .iter()
                    .flat_map(|checkpoint| &checkpoint.datasets)
                    .flat_map(|data| &data.batches),
            )
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>(),
    )
}

fn output_metadata(output: &sdk::Output) -> usize {
    output.allocated_bytes().saturating_sub(
        output
            .datasets
            .iter()
            .chain(
                output
                    .checkpoint
                    .iter()
                    .flat_map(|checkpoint| &checkpoint.datasets),
            )
            .flat_map(|data| &data.batches)
            .chain(output.reasons.iter().map(|reason| &reason.details))
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>(),
    )
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
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }
    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        self.children.iter().collect()
    }
    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition; self.children.len()]
    }
    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
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
