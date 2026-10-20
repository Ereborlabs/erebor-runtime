use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use araphor_data::AnalysisReadControl;
use araphor_discovery_definition::ImagePin;
use araphor_package::ModelRef;
use araphor_package_runtime::{Prepared, Runtime, TaskTracker, TaskTrackerToken};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::{SessionState, TaskContext};
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning,
    PlanProperties, SendableRecordBatchStream,
};
use futures_util::future::{BoxFuture, FutureExt, Shared, WeakShared};
use futures_util::{stream, TryStreamExt};

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
    pub inputs: BTreeMap<u64, Vec<sdk::Input>>,
    pub checkpoints: BTreeMap<u64, sdk::Checkpoint>,
    pub limits: sdk::Limits,
}

impl Default for Invocation {
    fn default() -> Self {
        Self {
            id: "package-call".into(),
            seed: None,
            inputs: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            limits: sdk::Limits::default(),
        }
    }
}

pub struct CallResult {
    evaluation: sdk::Evaluation,
    output: sdk::Output,
    origin: Origin,
    _input: Arc<MemoryReservation>,
    _output: Arc<MemoryReservation>,
}

#[derive(Clone, Debug)]
pub struct ExecutionReceipt {
    snapshot: Arc<crate::sources::ArrowSnapshot>,
    calls: BTreeMap<u64, Arc<CallResult>>,
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
        Ok(Self {
            snapshot: source.snapshot()?,
            calls: calls.results()?,
        })
    }

    pub fn snapshot(&self) -> &crate::sources::ArrowSnapshot {
        &self.snapshot
    }

    pub fn calls(&self) -> &BTreeMap<u64, Arc<CallResult>> {
        &self.calls
    }

    pub async fn blocking<T: Send + 'static>(
        self,
        context: &TaskContext,
        lease: impl Send + 'static,
        operation: impl FnOnce(&AnalysisReadControl) -> crate::Result<T> + Send + 'static,
    ) -> Result<T> {
        let calls = context
            .session_config()
            .get_extension::<CallContext>()
            .ok_or_else(|| internal("package execution context is absent"))?;
        let control = context
            .session_config()
            .get_extension::<AnalysisReadControl>()
            .ok_or_else(|| internal("package execution control is absent"))?;
        let permit = context
            .session_config()
            .get_extension::<crate::execution::Permit>()
            .ok_or_else(|| internal("package evaluation permit is absent"))?;
        control.check().map_err(external)?;
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("package source snapshot is absent"))?;
        if !Arc::ptr_eq(&self.snapshot, &source.snapshot()?) {
            return Err(external(
                araphor_data::PackageErrorCodeV1::Invalid.error("package execution receipt"),
            ));
        }
        let worker = calls.token()?;
        let stage = Arc::clone(&control);
        crate::execution::Engine::blocking(control, (worker, permit, self, lease), move || {
            operation(&stage)
        })
        .await
        .map_err(external)
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
            scope,
        })
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
        {
            let _calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.workers.close();
        }
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
    call: PackageCall,
    children: Vec<Arc<dyn ExecutionPlan>>,
    prepared: Option<Prepared>,
    properties: Arc<PlanProperties>,
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
                let package = call.package.clone();
                let export = call.export.clone();
                crate::execution::Engine::blocking(control, worker, move || {
                    let _permit = permit;
                    runtime
                        .prepare(bundle, package, export, &stage)
                        .map_err(|source| crate::Error::Sql {
                            source: external(source),
                        })
                })
                .await
                .map_err(external)?
            }
            _ => None,
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
            prepared,
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
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == self.call.export)
            .ok_or_else(|| internal("package export is absent"))?;
        let requested = owner.invocation.limits;
        let limits = sdk::Limits {
            max_batches: requested.max_batches.min(model.limits.max_batches),
            max_rows: requested.max_rows.min(model.limits.max_rows),
            max_bytes: requested.max_bytes.min(model.limits.max_bytes),
            max_checkpoint_bytes: requested
                .max_checkpoint_bytes
                .min(model.limits.max_checkpoint_bytes),
        };
        let input = Arc::new(owner.memory.reserve_input(0)?);
        let mut budget = Budget::new(limits);
        let mut inputs = Vec::with_capacity(model.inputs.len());
        for (slot, port) in model.inputs.iter().enumerate() {
            let data = sdk::Dataset {
                name: port.port.name.clone(),
                batches: self
                    .collect(
                        slot,
                        &port.port.schema,
                        &owner,
                        &context,
                        &input,
                        true,
                        &mut budget,
                    )
                    .await?,
            };
            let mut inherited = Vec::new();
            self.call.children[slot].apply_with_subqueries(|plan| {
                if let LogicalPlan::Extension(extension) = plan {
                    if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                        if let Some(result) = owner.completed(call.id)? {
                            inherited.extend(result.evaluation.inputs.iter().cloned());
                        }
                        return Ok(TreeNodeRecursion::Jump);
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
            inputs.push(
                self.call
                    .input_scope
                    .input_for(
                        data,
                        &snapshot,
                        slot,
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
                    &mut budget,
                )
                .await?;
            Some(Self::parameters(batches)?)
        };
        let checkpoint = match snapshot.managed() {
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
                        prior.checkpoint(model, &inputs, parameters.as_ref(), managed.rebuild())
                    })
                    .transpose()
                    .map_err(external)?
                    .flatten()
            }
            None => owner.invocation.checkpoints.get(&self.call.id).cloned(),
        };
        let mut evaluation = sdk::Evaluation {
            export: self.call.export.clone(),
            inputs,
            parameters,
            context: sdk::EvaluationContext {
                id: owner.invocation.id.clone(),
                time_utc_ns: i64::try_from(owner.now)
                    .map_err(|_| internal("package evaluation time is out of range"))?,
                seed: owner.invocation.seed,
                limits,
            },
            checkpoint,
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
            .flat_map(|data| &data.batches)
        {
            owner.memory.retain_input(batch, &input)?;
        }
        input.try_resize(input_metadata(&evaluation))?;
        let (output, output_memory) = if self.call.sql.is_some() {
            let output_memory = Arc::new(owner.memory.reserve_output(0)?);
            let checked = self
                .call
                .descriptor
                .check_evaluation(&evaluation)
                .map_err(external)?;
            let output = self
                .sql(&evaluation, &owner, &context, &source, &output_memory)
                .await?;
            checked.validate_output(&output).map_err(external)?;
            (output, output_memory)
        } else {
            let (effective, output, memory) = self
                .guest(
                    evaluation,
                    &owner,
                    Arc::clone(&input),
                    context
                        .session_config()
                        .get_extension::<crate::execution::Permit>()
                        .ok_or_else(|| internal("package evaluation permit is absent"))?,
                )
                .await?;
            evaluation = effective;
            (output, memory)
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
        Ok(CallResult {
            evaluation,
            output,
            origin: Origin::new(&self.call),
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
        budget: &mut Budget,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let plan = self
            .children
            .get(slot)
            .ok_or_else(|| internal("package physical child is absent"))?;
        let mut stream = execute_stream(Arc::clone(plan), Arc::clone(context))?;
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
                .ok_or_else(limit)?;
            memory.try_resize(metadata.checked_add(conversion).ok_or_else(limit)?)?;
            let batch =
                sdk::Dataset::normalize_batch(batch, Arc::clone(&schema)).map_err(external)?;
            budget.add(&batch)?;
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
            budget.add(&batch)?;
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

struct Budget {
    limits: sdk::Limits,
    rows: u64,
    bytes: u64,
    batches: u32,
    references: bool,
}

impl Budget {
    fn new(limits: sdk::Limits) -> Self {
        Self {
            limits,
            rows: 0,
            bytes: 0,
            batches: 0,
            references: false,
        }
    }
    fn references(limits: sdk::Limits) -> Self {
        Self {
            references: true,
            ..Self::new(limits)
        }
    }
    fn add(&mut self, batch: &sdk::RecordBatch) -> Result<()> {
        self.rows = self
            .rows
            .checked_add(batch.num_rows() as u64)
            .ok_or_else(limit)?;
        self.bytes = self
            .bytes
            .checked_add(batch.get_array_memory_size() as u64)
            .ok_or_else(limit)?;
        self.batches = self.batches.checked_add(1).ok_or_else(limit)?;
        if self.bytes > self.limits.max_bytes
            || (!self.references
                && (self.rows > self.limits.max_rows || self.batches > self.limits.max_batches))
        {
            return Err(limit());
        }
        Ok(())
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
    DataFusionError::ResourcesExhausted("package relation exceeds evaluation limits".into())
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
