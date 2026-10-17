use std::pin::Pin;
use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, StorePositionV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::execution::memory_pool::MemoryReservation;
use futures_core::Stream;

use crate::execution::{Engine, Permit};
use crate::sources::ArrowSnapshot;
use crate::Result;

pub(crate) mod physical;
#[cfg(test)]
mod tests;

pub(crate) struct Run {
    pub engine: Arc<Engine>,
    pub selection: AnalysisSelectionV1,
    pub sources: AnalysisTableRequests,
    pub control: Arc<AnalysisReadControl>,
    pub plan: Arc<datafusion::logical_expr::LogicalPlan>,
    pub clock: Arc<dyn crate::follow::Clock>,
    pub follow: bool,
    pub operation: crate::follow::Operation,
    pub window: Option<crate::follow::Window>,
    pub resume: Option<crate::follow::Cursor>,
}

pub(super) struct Change {
    pub before: Vec<RecordBatch>,
    pub after: Vec<RecordBatch>,
    pub position: StorePositionV1,
    pub snapshot: Arc<ArrowSnapshot>,
    pub control: Arc<AnalysisReadControl>,
    pub _permit: Option<Arc<Permit>>,
    pub _memory: MemoryReservation,
}

pub(crate) struct Output {
    pub snapshot: Arc<ArrowSnapshot>,
    pub batches: Option<Vec<RecordBatch>>,
    pub positions: Vec<StorePositionV1>,
    pub position: StorePositionV1,
    pub limited: bool,
    pub _memory: MemoryReservation,
    pub _permit: Option<Arc<Permit>>,
    pub _control: Arc<AnalysisReadControl>,
}

pub(crate) struct Event {
    pub output: Output,
    pub completed: bool,
    pub evaluated: u64,
    pub clock_changed: bool,
    pub exhausted: bool,
}

pub(crate) type OutputStream = Pin<Box<dyn Stream<Item = Result<Event>> + Send>>;
