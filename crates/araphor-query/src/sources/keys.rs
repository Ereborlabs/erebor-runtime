use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use datafusion::arrow::array::{RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, Result};
use datafusion::datasource::source::DataSourceExec;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::joins::{HashExpr, SeededRandomState};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, PlanProperties, RecordBatchStream,
    SendableRecordBatchStream,
};
use futures_util::{Stream, StreamExt};
use tokio::sync::Notify;

use super::{SourceData, SourceImage, SourceKey, SourceSnapshot};

mod planner;
pub(crate) use planner::{SourceJoin, SourceLookup};

#[derive(Clone, Debug)]
pub(crate) struct KeyRead {
    pub(crate) slot: usize,
    pub(crate) key: SourceKey,
}

#[derive(Debug)]
pub(super) struct KeySlot {
    state: Mutex<KeyState>,
    ready: Notify,
}

#[derive(Debug)]
struct KeyState {
    hashes: Arc<BTreeSet<u64>>,
    finished: bool,
    failed: bool,
    memory: MemoryReservation,
}

#[derive(Debug)]
pub(crate) struct KeyBuildExec {
    input: Arc<dyn ExecutionPlan>,
    slot: usize,
    hash: Arc<HashExpr>,
}

struct KeyStream {
    input: SendableRecordBatchStream,
    slot: Arc<KeySlot>,
    hash: Arc<HashExpr>,
    ended: bool,
    control: araphor_data::AnalysisReadControl,
    scratch: MemoryReservation,
}

impl SourceSnapshot {
    pub(crate) fn bind_before_keys(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let view = self
            .source_view()?
            .ok_or_else(|| DataFusionError::Execution("the before source view is absent".into()))?;
        let cached = |node: &Arc<dyn ExecutionPlan>| match (
            node.as_any()
                .downcast_ref::<crate::definition::physical::PackageExec>(),
            calls,
        ) {
            (Some(package), Some(calls)) => calls.cached(package.logical_call()),
            _ => Ok(false),
        };
        SourceLookup::keys(&plan, calls)?;
        let mut seeds = BTreeMap::new();
        plan.apply(|node| {
            if cached(node)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                if source.origin.durable().is_some() && source.image != Some(SourceImage::Before) {
                    return Err(DataFusionError::Execution(
                        "the before source image differs".into(),
                    ));
                }
                if let Some(read) = &source.key {
                    if let Some(admitted) = view.before_key(&read.key) {
                        let hash = admitted.hash.seeds();
                        if seeds
                            .insert(read.slot, hash)
                            .is_some_and(|saved| saved != hash)
                        {
                            return Err(DataFusionError::Execution(
                                "the before source key bindings differ".into(),
                            ));
                        }
                    }
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let plan = plan
            .transform_down(|node| {
                if cached(&node)? {
                    return Ok(Transformed::new(node, false, TreeNodeRecursion::Jump));
                }
                if let Some(source) = SourceData::from_plan(node.as_ref()) {
                    if source.origin.durable().is_some() {
                        let mut source = source.clone();
                        source.image = Some(SourceImage::Before);
                        source.key = source.key.as_ref().and_then(|read| {
                            view.before_key(&read.key).map(|admitted| KeyRead {
                                slot: read.slot,
                                key: admitted.clone(),
                            })
                        });
                        return Ok(Transformed::yes(DataSourceExec::from_data_source(source)));
                    }
                }
                if let Some(build) = node.as_any().downcast_ref::<KeyBuildExec>() {
                    let Some(&(a, b, c, d)) = seeds.get(&build.slot) else {
                        return Ok(Transformed::yes(Arc::clone(&build.input)));
                    };
                    let hash = Arc::new(HashExpr::new(
                        build.hash.on_columns().to_vec(),
                        SeededRandomState::with_seeds(a, b, c, d),
                        build.hash.description().to_owned(),
                    ));
                    return Ok(Transformed::yes(Arc::new(KeyBuildExec::new(
                        Arc::clone(&build.input),
                        build.slot,
                        hash,
                    )?)));
                }
                Ok(Transformed::no(node))
            })?
            .data;
        SourceLookup::keys(&plan, calls)?;
        Ok(plan)
    }

    pub(super) fn key_slot(&self, id: usize) -> Result<Arc<KeySlot>> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| DataFusionError::Internal("the source key registry is poisoned".into()))?;
        if let Some(slot) = keys.get(&id) {
            return Ok(Arc::clone(slot));
        }
        let slot = Arc::new(KeySlot {
            state: Mutex::new(KeyState {
                hashes: Arc::default(),
                finished: false,
                failed: false,
                memory: self.memory.reserve_input(0)?,
            }),
            ready: Notify::new(),
        });
        keys.insert(id, Arc::clone(&slot));
        Ok(slot)
    }
}

impl KeySlot {
    fn add(&self, values: &UInt64Array) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DataFusionError::Internal("the source key state is poisoned".into()))?;
        if state.finished || state.failed {
            return Err(DataFusionError::Execution(
                "the native key build has ended".into(),
            ));
        }
        for value in values.values() {
            if !state.hashes.contains(value) {
                state.memory.try_grow(size_of::<u64>())?;
                Arc::make_mut(&mut state.hashes).insert(*value);
            }
        }
        Ok(())
    }

    fn finish(&self, failed: bool) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.failed |= failed;
        state.finished = true;
        drop(state);
        self.ready.notify_waiters();
    }

    pub(super) async fn hashes(&self) -> araphor_data::Result<Arc<BTreeSet<u64>>> {
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let state = self.state.lock().map_err(|_| {
                    araphor_data::PackageErrorCodeV1::Incomplete.error("native source key state")
                })?;
                if state.failed {
                    return Err(araphor_data::PackageErrorCodeV1::Incomplete
                        .error("native source key build"));
                }
                if state.finished {
                    return Ok(Arc::clone(&state.hashes));
                }
            }
            ready.await;
        }
    }
}

impl KeyBuildExec {
    pub(crate) fn new(
        input: Arc<dyn ExecutionPlan>,
        slot: usize,
        hash: Arc<HashExpr>,
    ) -> Result<Self> {
        if input.properties().output_partitioning().partition_count() != 1 {
            return Err(DataFusionError::Plan(
                "a native source key build requires one partition".into(),
            ));
        }
        Ok(Self { input, slot, hash })
    }
}

impl DisplayAs for KeyBuildExec {
    fn fmt_as(&self, _format: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "SourceKeys: slot={}, hash={}",
            self.slot, self.hash
        )
    }
}

impl ExecutionPlan for KeyBuildExec {
    fn name(&self) -> &'static str {
        "SourceKeys"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn properties(&self) -> &Arc<PlanProperties> {
        self.input.properties()
    }
    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }
    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let [input] = children.as_slice() else {
            return Err(DataFusionError::Internal(
                "the source key child count differs".into(),
            ));
        };
        Ok(Arc::new(Self::new(
            Arc::clone(input),
            self.slot,
            Arc::clone(&self.hash),
        )?))
    }
    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition]
    }
    fn maintains_input_order(&self) -> Vec<bool> {
        vec![true]
    }
    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Execution(
                "the source key partition differs".into(),
            ));
        }
        let snapshot = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| {
                DataFusionError::Execution("the source key snapshot is absent".into())
            })?;
        Ok(Box::pin(KeyStream {
            input: self.input.execute(partition, context)?,
            slot: snapshot.key_slot(self.slot)?,
            hash: Arc::clone(&self.hash),
            ended: false,
            control: snapshot
                .control
                .within(None)
                .map_err(SourceSnapshot::data_error)?,
            scratch: snapshot.memory.reserve_input(0)?,
        }))
    }
}

impl Stream for KeyStream {
    type Item = Result<RecordBatch>;
    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.get_mut();
        if let Err(error) = state.control.check().map_err(SourceSnapshot::data_error) {
            state.slot.finish(true);
            state.ended = true;
            return Poll::Ready(Some(Err(error)));
        }
        match state.input.poll_next_unpin(context) {
            Poll::Ready(Some(Ok(batch))) => {
                let result = state
                    .scratch
                    .try_resize(batch.num_rows().saturating_mul(size_of::<u64>()))
                    .and_then(|()| state.hash.evaluate(&batch))
                    .and_then(|value| value.into_array(batch.num_rows()))
                    .and_then(|values| {
                        let hashes =
                            values
                                .as_any()
                                .downcast_ref::<UInt64Array>()
                                .ok_or_else(|| {
                                    DataFusionError::Internal(
                                        "the native build hash type differs".into(),
                                    )
                                })?;
                        state.slot.add(hashes)
                    });
                state.scratch.shrink(state.scratch.size());
                match result {
                    Ok(()) => Poll::Ready(Some(Ok(batch))),
                    Err(error) => {
                        state.slot.finish(true);
                        state.ended = true;
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            Poll::Ready(Some(Err(error))) => {
                state.slot.finish(true);
                state.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                state.slot.finish(false);
                state.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl RecordBatchStream for KeyStream {
    fn schema(&self) -> SchemaRef {
        self.input.schema()
    }
}

impl Drop for KeyStream {
    fn drop(&mut self) {
        if !self.ended {
            self.slot.finish(true);
        }
    }
}
