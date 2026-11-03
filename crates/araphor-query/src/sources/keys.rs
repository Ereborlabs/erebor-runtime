use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::arrow::row::{RowConverter, Rows};
use datafusion::common::tree_node::{Transformed, TreeNodeRecursion};
use datafusion::common::{DataFusionError, Result};
use datafusion::datasource::source::DataSourceExec;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::{
    ChildrenPropertiesMode, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan,
    InputDistributionRequirements, PlanProperties, RecordBatchStream, ReplaceChildrenOptions,
    SendableRecordBatchStream,
};
use futures_util::{Stream, StreamExt};
use tokio::sync::Notify;

use super::{PortExec, SourceData, SourceImage, SourceKey, SourceSnapshot};

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
    keys: Arc<BTreeSet<Vec<u8>>>,
    finished: bool,
    failed: bool,
    memory: MemoryReservation,
}

#[derive(Debug)]
pub(crate) struct KeyBuildExec {
    input: Arc<dyn ExecutionPlan>,
    slot: usize,
    expressions: Arc<[Arc<dyn PhysicalExpr>]>,
    converter: Arc<RowConverter>,
    data_types: Arc<[DataType]>,
}

struct KeyStream {
    input: SendableRecordBatchStream,
    slot: Arc<KeySlot>,
    expressions: Arc<[Arc<dyn PhysicalExpr>]>,
    converter: Arc<RowConverter>,
    data_types: Arc<[DataType]>,
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
            node.downcast_ref::<crate::definition::physical::PackageExec>(),
            calls,
        ) {
            (Some(package), Some(calls)) => calls.cached(package.logical_call()),
            _ => Ok(false),
        };
        SourceLookup::keys(&plan, calls)?;
        let mut converters = BTreeMap::new();
        PortExec::apply(&plan, &mut |node| {
            if cached(node)? {
                return Ok(TreeNodeRecursion::Jump);
            }
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                if source
                    .origin
                    .durable()
                    .is_some_and(araphor_data::AnalysisTableRead::source_header)
                {
                    return Ok(TreeNodeRecursion::Continue);
                }
                if source.origin.durable().is_some() && source.image != Some(SourceImage::Before) {
                    return Err(DataFusionError::Execution(
                        "the before source image differs".into(),
                    ));
                }
                if let Some(read) = &source.key {
                    if let Some(admitted) = view.before_key(&read.key) {
                        if converters
                            .insert(
                                read.slot,
                                (
                                    Arc::clone(&admitted.converter),
                                    Arc::clone(&admitted.data_types),
                                ),
                            )
                            .is_some_and(|(converter, data_types)| {
                                !Arc::ptr_eq(&converter, &admitted.converter)
                                    || !Arc::ptr_eq(&data_types, &admitted.data_types)
                            })
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
        let plan = PortExec::transform_down(plan, &mut |node| {
            if cached(&node)? {
                return Ok(Transformed::new(node, false, TreeNodeRecursion::Jump));
            }
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                if source
                    .origin
                    .durable()
                    .is_some_and(araphor_data::AnalysisTableRead::source_header)
                {
                    return Ok(Transformed::no(node));
                }
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
            if let Some(build) = node.downcast_ref::<KeyBuildExec>() {
                let Some((converter, data_types)) = converters.get(&build.slot) else {
                    return Ok(Transformed::yes(Arc::clone(&build.input)));
                };
                return Ok(Transformed::yes(Arc::new(KeyBuildExec::new(
                    Arc::clone(&build.input),
                    build.slot,
                    Arc::clone(&build.expressions),
                    Arc::clone(converter),
                    Arc::clone(data_types),
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
                keys: Arc::default(),
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
    fn add(&self, values: &Rows) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DataFusionError::Internal("the source key state is poisoned".into()))?;
        if state.finished || state.failed {
            return Err(DataFusionError::Execution(
                "the native key build has ended".into(),
            ));
        }
        for value in values {
            if !state.keys.contains(value.data()) {
                state.memory.try_grow(
                    size_of::<Vec<u8>>()
                        .checked_add(value.data().len())
                        .ok_or_else(|| {
                            DataFusionError::ResourcesExhausted(
                                "the native key allocation overflowed".into(),
                            )
                        })?,
                )?;
                Arc::make_mut(&mut state.keys).insert(value.data().to_vec());
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

    pub(super) async fn values(&self) -> araphor_data::Result<Arc<BTreeSet<Vec<u8>>>> {
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
                    return Ok(Arc::clone(&state.keys));
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
        expressions: Arc<[Arc<dyn PhysicalExpr>]>,
        converter: Arc<RowConverter>,
        data_types: Arc<[DataType]>,
    ) -> Result<Self> {
        if input.properties().output_partitioning().partition_count() != 1 {
            return Err(DataFusionError::Plan(
                "a native source key build requires one partition".into(),
            ));
        }
        Ok(Self {
            input,
            slot,
            expressions,
            converter,
            data_types,
        })
    }
}

impl DisplayAs for KeyBuildExec {
    fn fmt_as(&self, _format: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "SourceKeys: slot={}, columns={:?}",
            self.slot, self.expressions
        )
    }
}

impl ExecutionPlan for KeyBuildExec {
    fn name(&self) -> &'static str {
        "SourceKeys"
    }
    fn properties(&self) -> &Arc<PlanProperties> {
        self.input.properties()
    }
    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }
    fn apply_expressions(
        &self,
        f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        datafusion::physical_plan::apply_expression_roots(self.expressions.iter(), f)
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
        let [input] = children.as_slice() else {
            return Err(DataFusionError::Internal(
                "the source key child count differs".into(),
            ));
        };
        Ok(Arc::new(Self::new(
            Arc::clone(input),
            self.slot,
            Arc::clone(&self.expressions),
            Arc::clone(&self.converter),
            Arc::clone(&self.data_types),
        )?))
    }
    fn input_distribution_requirements(&self) -> InputDistributionRequirements {
        InputDistributionRequirements::new(vec![Distribution::SinglePartition])
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
            expressions: Arc::clone(&self.expressions),
            converter: Arc::clone(&self.converter),
            data_types: Arc::clone(&self.data_types),
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
                let result = SourceKey::encode(
                    &state.expressions,
                    &state.converter,
                    &state.data_types,
                    &batch,
                )
                .and_then(|values| {
                    state.scratch.try_resize(values.size())?;
                    state.slot.add(&values)
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
