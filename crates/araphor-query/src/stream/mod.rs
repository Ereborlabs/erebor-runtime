use std::pin::Pin;
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisTableRequests, StorePositionV1};
use datafusion::arrow::array::RecordBatch;
use datafusion::execution::memory_pool::MemoryReservation;
use futures_core::Stream;

use crate::execution::{Permit, Session};
use crate::sources::ArrowSnapshot;

pub(crate) mod physical;
pub(crate) mod progress;
#[cfg(test)]
mod tests;

pub(crate) struct Run {
    pub session: Arc<Session>,
    pub sources: AnalysisTableRequests,
    pub plan: Arc<datafusion::logical_expr::LogicalPlan>,
    pub clock: Arc<dyn crate::follow::Clock>,
    pub follow: bool,
    pub operation: crate::follow::Operation,
    pub window: Option<crate::follow::Window>,
    pub resume: Option<crate::follow::Cursor>,
    pub binding: [u8; 32],
    pub resume_expiry: Option<u64>,
    pub managed: Option<(
        crate::definition::PreparedDefinition,
        Arc<dyn crate::follow::ManagedPublication>,
    )>,
}

impl Run {
    pub(crate) fn sources(&self) -> &AnalysisTableRequests {
        self.managed
            .as_ref()
            .map_or(&self.sources, |(definition, _)| definition.sources())
    }

    pub(crate) async fn session(&self, now: u64, permit: &Arc<Permit>) -> crate::Result<Session> {
        let (invocation, managed) = match &self.managed {
            Some((definition, publication)) => {
                let publication = Arc::clone(publication);
                let control = Arc::clone(self.session.control());
                let worker = Arc::clone(&control);
                let lease = (self.session.token()?, Arc::clone(permit));
                let (invocation, managed) =
                    crate::execution::Engine::blocking(control, lease, move || {
                        publication.begin(&worker)
                    })
                    .await?;
                definition.check_invocation(
                    self.session.selection(),
                    &invocation,
                    Some(&managed),
                )?;
                (invocation, Some(managed))
            }
            None => (crate::definition::Invocation::default(), None),
        };
        let selection = self.window.map_or_else(
            || self.session.selection().clone(),
            |window| window.selection(self.session.selection(), now),
        );
        let mut session = self.session.at(selection, now);
        session.managed = managed;
        session.calls = Some(session.call_context(invocation));
        Ok(session)
    }
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
    pub calls: std::collections::BTreeMap<u64, Arc<crate::definition::CallResult>>,
    pub completed: bool,
    pub evaluated: u64,
    pub clock_changed: bool,
    pub exhausted: bool,
}

pub(crate) type StreamError = (crate::Error, Option<Arc<ArrowSnapshot>>);
pub(crate) type OutputStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Event, StreamError>> + Send>>;
