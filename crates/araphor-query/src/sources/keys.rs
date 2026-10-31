use std::any::Any;
use std::collections::BTreeSet;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use datafusion::arrow::array::{RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::joins::HashExpr;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, PlanProperties, RecordBatchStream,
    SendableRecordBatchStream,
};
use futures_util::{Stream, StreamExt};
use tokio::sync::Notify;

use super::{SourceKey, SourceSnapshot};

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
