use crate::storage::{AnalysisStore, ManagedGraphJournal, ManagedGraphTransaction};
use std::any::Any;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::ThreadId;

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisReadControl, ManagedAttempt};
use datafusion::arrow::compute::concat_batches;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::{memory_pool::MemoryReservation, TaskContext};

use super::{external, internal, CallContext, CallState, PackageExec};
use crate::{memory::Memory, sources::SourceSnapshot};

mod lookup;
pub(crate) use lookup::{GraphExec, GraphProvider};

pub(super) struct GraphService {
    store: Arc<AnalysisStore>,
    transaction: Arc<ManagedGraphTransaction>,
    pub(super) control: Arc<AnalysisReadControl>,
    memory: Arc<Memory>,
    limit: usize,
    active: Mutex<Weak<Loan>>,
    failure: Mutex<Option<sdk::Error>>,
    reads: Arc<tokio::sync::Mutex<()>>,
    inputs: AtomicBool,
}

struct Loan {
    thread: ThreadId,
    bounded: bool,
    state: Mutex<LoanState>,
}

struct LoanState {
    remaining: MemoryReservation,
    held: Vec<Arc<MemoryReservation>>,
}

impl Loan {
    fn allocate(&self, bytes: usize) -> araphor_data::Result<Arc<dyn Any + Send + Sync>> {
        if self.thread != std::thread::current().id() {
            return Err(araphor_data::PackageErrorCodeV1::Denied.error("Graph callback thread"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| araphor_data::PackageErrorCodeV1::Incomplete.error("Graph memory lock"))?;
        if self.bounded {
            if bytes > state.remaining.size() {
                return Err(araphor_data::PackageErrorCodeV1::Limit.error("Graph callback memory"));
            }
        } else {
            state.remaining.try_grow(bytes).map_err(|source| {
                araphor_data::Error::from(araphor_graph::Error::backend(crate::Error::Sql {
                    source,
                }))
            })?;
        }
        let lease = Arc::new(state.remaining.split(bytes));
        state.held.push(Arc::clone(&lease));
        Ok(lease)
    }

    fn retain(&self, memory: &Memory, batch: &sdk::RecordBatch) -> sdk::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| GraphService::invalid("Graph memory lock"))?;
        let reservation = state
            .held
            .iter()
            .max_by_key(|held| held.size())
            .map(Arc::as_ref)
            .unwrap_or(&state.remaining);
        memory
            .retain_input(batch, reservation)
            .map_err(GraphService::query_error)
    }
}

impl GraphService {
    fn capture<T>(&self, result: sdk::Result<T>) -> sdk::Result<T> {
        result.map_err(|error| {
            let portable = sdk::wire::EvaluationError::from(&error);
            let mut failure = self
                .failure
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if failure.is_none() {
                *failure = Some(error);
            }
            sdk::Error::from(portable)
        })
    }

    pub(super) fn failure(
        &self,
        error: &araphor_package_runtime::Error,
    ) -> Option<DataFusionError> {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(error) = cause {
            if let Some(sdk::Error::Contract { code, field, .. }) =
                error.downcast_ref::<sdk::Error>()
            {
                if field == "Graph host" {
                    let mut failure = self
                        .failure
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    return if failure.as_ref().is_some_and(|error| error.code() == *code) {
                        failure.take().map(external)
                    } else {
                        None
                    };
                }
            }
            cause = error.source();
        }
        None
    }

    pub(super) async fn bind(
        exec: &PackageExec,
        owner: &CallContext,
        source: &Arc<SourceSnapshot>,
        context: &TaskContext,
        control: Arc<AnalysisReadControl>,
    ) -> Result<Arc<Self>> {
        let attempt = source
            .attempt()
            .cloned()
            .ok_or_else(|| internal("Graph actual attempt is absent"))?;
        let predecessors = owner.graph_predecessors(exec.call.id, &attempt)?;
        let call = exec.call.clone();
        let memory = Arc::clone(&owner.memory);
        let limit = source.extraction_limits().input_bytes;
        source
            .blocking(context, (), move |source, stage| {
                let model = call
                    .descriptor()
                    .exports
                    .iter()
                    .find(|model| model.name == call.export)
                    .ok_or_else(|| {
                        araphor_data::PackageErrorCodeV1::Invalid.error("Graph actual model")
                    })?;
                let budget = memory.managed_budget(Arc::clone(&control), limit);
                Ok(Arc::new(Self {
                    store: Arc::clone(source.graph_store()),
                    transaction: ManagedGraphTransaction::new(
                        source.graph_store(),
                        attempt,
                        call.id,
                        model,
                        predecessors,
                        budget,
                        stage,
                    )?,
                    control,
                    memory,
                    limit,
                    active: Mutex::new(Weak::new()),
                    failure: Mutex::new(None),
                    reads: Arc::new(tokio::sync::Mutex::new(())),
                    inputs: AtomicBool::new(true),
                }))
            })
            .await
    }

    fn loan(&self) -> sdk::Result<Arc<Loan>> {
        self.control.check().map_err(Self::data_error)?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| Self::invalid("Graph transfer lock"))?;
        if active.upgrade().is_some() {
            return Err(Self::invalid("Graph transfer overlap"));
        }
        let reservation = self
            .memory
            .prepare_input(self.limit)
            .map_err(Self::query_error)?;
        let loan = Arc::new(Loan {
            thread: std::thread::current().id(),
            bounded: self.memory.input_capacity().is_some() || self.limit != usize::MAX,
            state: Mutex::new(LoanState {
                remaining: reservation,
                held: Vec::new(),
            }),
        });
        *active = Arc::downgrade(&loan);
        Ok(loan)
    }

    fn callback(&self) -> sdk::Result<Arc<Loan>> {
        let loan = self
            .active
            .lock()
            .map_err(|_| Self::invalid("Graph transfer lock"))?
            .upgrade();
        match loan {
            Some(loan) if loan.thread == std::thread::current().id() => Ok(loan),
            Some(_) => Err(Self::invalid("Graph callback overlap")),
            None => self.loan(),
        }
    }

    async fn owned(
        self: &Arc<Self>,
        relation: &str,
        source: &Arc<SourceSnapshot>,
        context: &TaskContext,
    ) -> Result<sdk::Input> {
        let guard = self.acquire().await;
        self.check_inputs()?;
        let host = Arc::clone(self);
        let relation = relation.to_owned();
        source
            .blocking(context, guard, move |_, control| {
                let _loan = host
                    .loan()
                    .map_err(|source| crate::Error::Contract { source })?;
                let arguments = sdk::Dataset {
                    name: relation,
                    batches: vec![sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()))],
                };
                host.read_inner("owned", &arguments, control)
                    .map_err(|source| crate::Error::Contract { source })
            })
            .await
    }

    pub(super) async fn freeze(
        self: &Arc<Self>,
        source: &Arc<SourceSnapshot>,
        context: &TaskContext,
    ) -> Result<Arc<ManagedGraphJournal>> {
        let guard = self.acquire().await;
        self.inputs.store(false, Ordering::Release);
        self.control.check().map_err(external)?;
        let host = Arc::clone(self);
        source
            .blocking(context, guard, move |_, control| {
                Ok(host.transaction.freeze(&host.store, control)?)
            })
            .await
    }

    async fn acquire(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.reads).lock_owned().await
    }

    pub(super) fn check_inputs(&self) -> Result<()> {
        self.control.check().map_err(external)?;
        if !self.inputs.load(Ordering::Acquire) {
            return Err(internal("Graph SQL input phase is closed"));
        }
        Ok(())
    }

    pub(super) async fn enter_guest(&self) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let guard = self.acquire().await;
        self.check_inputs()?;
        self.inputs.store(false, Ordering::Release);
        Ok(guard)
    }

    fn invalid(field: &str) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Unauthorized, field)
    }
    fn query_error(source: datafusion::common::DataFusionError) -> sdk::Error {
        sdk::Error::backend(crate::Error::Sql { source })
    }
    fn data_error(error: araphor_data::Error) -> sdk::Error {
        sdk::Error::backend(error)
    }
}

impl GraphService {
    fn read_inner(
        &self,
        operation: &str,
        arguments: &sdk::Dataset,
        control: &AnalysisReadControl,
    ) -> sdk::Result<sdk::Input> {
        (|| {
            let loan = self.callback()?;
            let schema = self.transaction.spec().argument_schema(operation)?;
            arguments.validate(&sdk::Port::new(&arguments.name, schema.clone()))?;
            let bytes = arguments.allocated_bytes().checked_mul(2).ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Limit, "Graph read arguments")
            })?;
            loan.allocate(bytes).map_err(Self::data_error)?;
            let batch = concat_batches(&Arc::new(schema), &arguments.batches)?;
            let input = self
                .transaction
                .read(
                    &self.store,
                    operation,
                    &arguments.name,
                    &batch,
                    |bytes| loan.allocate(bytes),
                    control,
                )
                .map_err(Self::data_error)?;
            for batch in &input.data.batches {
                loan.retain(&self.memory, batch)?;
            }
            let lease = loan
                .allocate(input.metadata_bytes())
                .map_err(Self::data_error)?;
            self.transaction.retain(lease).map_err(Self::data_error)?;
            Ok(input)
        })()
    }
}

impl sdk::InvocationHost for GraphService {
    fn read(&self, operation: &str, arguments: &sdk::Dataset) -> sdk::Result<sdk::Input> {
        self.capture(self.read_inner(operation, arguments, &self.control))
    }

    fn stage(&self, commands: &sdk::Dataset) -> sdk::Result<()> {
        self.capture((|| {
            let loan = self.callback()?;
            let schema = self.transaction.spec().command_schema(&commands.name)?;
            commands.validate(&sdk::Port::new(&commands.name, schema.clone()))?;
            let bytes = commands.allocated_bytes().checked_mul(2).ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Limit, "Graph command memory")
            })?;
            loan.allocate(bytes).map_err(Self::data_error)?;
            let batch = concat_batches(&Arc::new(schema), &commands.batches)?;
            let (retained, scratch) =
                araphor_graph::Journal::stage_budget(&batch).map_err(sdk::Error::backend)?;
            let lease = loan.allocate(retained).map_err(Self::data_error)?;
            loan.allocate(scratch).map_err(Self::data_error)?;
            loan.retain(&self.memory, &batch)?;
            self.transaction
                .stage(&self.store, &commands.name, batch, lease, &self.control)
                .map_err(Self::data_error)
        })())
    }
}

impl sdk::InvocationService for GraphService {
    fn argument_schema(&self, name: &str) -> sdk::Result<sdk::Schema> {
        self.capture(self.transaction.spec().argument_schema(name))
    }
    fn command_schema(&self, name: &str) -> sdk::Result<sdk::Schema> {
        self.capture(self.transaction.spec().command_schema(name))
    }
    fn reserve_transfer(&self) -> sdk::Result<sdk::Transfer> {
        self.capture((|| {
            let loan = self.loan()?;
            let bytes = loan.bounded.then(|| {
                loan.state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remaining
                    .size()
                    / 4
            });
            Ok(sdk::Transfer {
                bytes,
                lease: Box::new(loan),
            })
        })())
    }
}

impl CallContext {
    pub(super) fn graph(&self, call: u64) -> Result<Arc<GraphService>> {
        self.graphs
            .lock()
            .map_err(|_| internal("Graph invocation lock is poisoned"))?
            .get(&call)
            .cloned()
            .ok_or_else(|| internal("Graph predecessor inputs are incomplete"))
    }

    pub(super) async fn bind_graph(
        &self,
        exec: &PackageExec,
        source: &Arc<SourceSnapshot>,
        context: &TaskContext,
    ) -> Result<Option<Arc<GraphService>>> {
        if exec.call.model().is_none_or(|model| model.graph.is_none()) {
            return Ok(None);
        }
        if let Some(host) = self
            .graphs
            .lock()
            .map_err(|_| internal("Graph invocation lock is poisoned"))?
            .get(&exec.call.id)
            .cloned()
        {
            return Ok(Some(host));
        }
        let control = Arc::new(self.control.operation().map_err(external)?);
        let host = GraphService::bind(exec, self, source, context, control).await?;
        let mut graphs = self
            .graphs
            .lock()
            .map_err(|_| internal("Graph invocation lock is poisoned"))?;
        match graphs.entry(exec.call.id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&host));
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(internal("Graph invocation binding overlaps"));
            }
        }
        Ok(Some(host))
    }

    fn graph_predecessors(
        &self,
        call: u64,
        attempt: &ManagedAttempt,
    ) -> Result<Vec<Arc<ManagedGraphJournal>>> {
        let manifest = &attempt.instance().spec.manifest;
        let mut ancestors = BTreeSet::new();
        let mut pending = manifest.calls[&call]
            .dependencies
            .iter()
            .copied()
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if ancestors.insert(id) {
                pending.extend(&manifest.calls[&id].dependencies);
            }
        }
        let calls = self
            .calls
            .lock()
            .map_err(|_| internal("Graph predecessor lock is poisoned"))?;
        let mut journals = Vec::new();
        for id in manifest
            .order()
            .map_err(external)?
            .into_iter()
            .filter(|id| ancestors.contains(id))
        {
            if let Some(CallState::Complete(_, result)) = calls.get(&id) {
                let result = result
                    .as_ref()
                    .map_err(|error| DataFusionError::Shared(Arc::clone(error)))?;
                if let Some(journal) = &result.graph {
                    journals.push(Arc::clone(journal));
                }
            }
        }
        Ok(journals)
    }
}

impl PackageExec {
    pub(super) fn graph_inputs(&self) -> Result<BTreeSet<usize>> {
        let bindings = self
            .call
            .changes
            .as_ref()
            .map(|call| &call.lookups.bindings);
        let mut selected = BTreeSet::new();
        let mut dependencies = Vec::with_capacity(self.children.len());
        for (slot, child) in self.children.iter().enumerate() {
            let mut inputs = BTreeSet::new();
            crate::sources::PortExec::apply(child, &mut |node| {
                if let Some(graph) = node.downcast_ref::<GraphExec>() {
                    if graph.call_id() == self.call.id {
                        selected.insert(slot);
                    }
                }
                if let Some(source) = crate::sources::SourceData::from_plan(node.as_ref()) {
                    if let crate::sources::SourceOrigin::Port(id) = source.origin {
                        if let Some(input) = bindings.and_then(|bindings| {
                            bindings
                                .iter()
                                .find_map(|(bound, slot)| (*bound == id).then_some(slot))
                        }) {
                            inputs.insert(*input);
                        }
                    }
                }
                Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
            })?;
            dependencies.push(inputs);
        }
        loop {
            let count = selected.len();
            for (slot, inputs) in dependencies.iter().enumerate() {
                if inputs.iter().any(|input| selected.contains(input)) {
                    selected.insert(slot);
                }
            }
            if let Some(changes) = &self.call.changes {
                for pair in &changes.ports {
                    let slots = [
                        pair.before,
                        pair.after,
                        pair.affected,
                        pair.reset,
                        pair.reset_keys,
                    ];
                    if slots.iter().any(|slot| selected.contains(slot)) {
                        selected.extend(slots);
                    }
                }
            }
            if selected.len() == count {
                break;
            }
        }
        Ok(selected)
    }

    pub(super) fn check_graph_inputs(
        &self,
        slots: &BTreeSet<usize>,
        owner: &CallContext,
    ) -> Result<()> {
        for &slot in slots {
            crate::sources::PortExec::apply(&self.children[slot], &mut |node| {
                if let Some(call) = node.downcast_ref::<PackageExec>() {
                    if !owner.cached(&call.call)? {
                        return Err(internal(
                            "Graph input depends on an unresolved package call",
                        ));
                    }
                    return Ok(datafusion::common::tree_node::TreeNodeRecursion::Jump);
                }
                Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
            })?;
        }
        Ok(())
    }
}
