use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, StorePositionV1};
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
    pub sources: BTreeSet<String>,
    pub control: Arc<AnalysisReadControl>,
    pub now: u64,
    pub after: Option<StorePositionV1>,
}

pub(super) enum Message {
    Begin(Arc<AnalysisReadControl>),
    Insert(RecordBatch),
    Delete(RecordBatch),
    Commit {
        position: StorePositionV1,
        snapshot: Arc<ArrowSnapshot>,
        _permit: Option<Arc<Permit>>,
    },
}

pub(super) type Input = Pin<Box<dyn Stream<Item = Result<Message>> + Send>>;

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

pub(crate) type OutputStream = Pin<Box<dyn Stream<Item = Result<Output>> + Send>>;
