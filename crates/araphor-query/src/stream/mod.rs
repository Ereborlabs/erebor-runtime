use std::pin::Pin;
use std::sync::Arc;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStoreMetaV1,
    AnalysisTableRequests, StorePositionV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::execution::memory_pool::MemoryReservation;
use futures_core::Stream;
use snafu::ResultExt as _;

use crate::execution::{Permit, Session};
use crate::sources::{ArrowSnapshot, CapturedRequests};

pub(crate) mod physical;
pub(crate) mod progress;
pub(crate) mod recovery;
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
    pub resume_pending: bool,
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

    pub(crate) fn selection(&self, now: u64) -> crate::Result<araphor_data::AnalysisSelectionV1> {
        if let Some(window) = &self.window {
            if !crate::definition::PackageCall::contains(&self.plan).context(crate::SqlSnafu)? {
                return Ok(window.selection(self.session.selection(), now));
            }
        }
        Ok(self.session.selection().clone())
    }

    pub(crate) async fn dependencies(
        self: &Arc<Self>,
        session: &Session,
        selection: AnalysisSelectionV1,
        permit: Option<&Arc<Permit>>,
        requests: Option<&Arc<CapturedRequests>>,
    ) -> crate::Result<(AnalysisStoreMetaV1, u64)> {
        let requests = requests.cloned();
        loop {
            let stage = Arc::new(
                session
                    .control()
                    .within(session.engine().limits().extract_timeout)?,
            );
            let worker = Arc::clone(&stage);
            let store = Arc::clone(session.engine().store());
            let selection = selection.clone();
            let run = Arc::clone(self);
            let requests = requests.clone();
            let managed = session.managed.clone();
            let limits = AnalysisExtractLimits {
                scan_bytes: session.engine().limits().scan_bytes,
                input_bytes: session.engine().limits().input_bytes,
                keys: session.engine().limits().extract_keys,
                ..Default::default()
            };
            let scope = (session.token()?, permit.cloned());
            match crate::execution::Engine::blocking(stage, scope, move || {
                let tables = requests
                    .as_deref()
                    .map_or_else(|| run.sources(), CapturedRequests::tables);
                match &managed {
                    Some(managed) => store
                        .managed_dependency_revision(&selection, tables, managed, limits, &worker),
                    None => store.dependency_revision_for(&selection, tables, &worker),
                }
                .map_err(crate::Error::from)
            })
            .await
            {
                Err(crate::Error::Data {
                    source:
                        araphor_data::Error::AnalysisBusy {
                            resource: "reader", ..
                        },
                }) => {
                    session
                        .control()
                        .query_async(async {
                            session
                                .engine()
                                .store()
                                .wait_capacity()
                                .await
                                .map_err(crate::Error::from)
                        })
                        .await?;
                }
                result => return result,
            }
        }
    }

    pub(crate) async fn session(
        &self,
        now: u64,
        permit: &Arc<Permit>,
        mut completion: Vec<crate::follow::WindowRange>,
        mut windows: Vec<crate::follow::WindowRange>,
        resume: Option<&crate::follow::Cursor>,
    ) -> crate::Result<Session> {
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
                if managed.follow != self.follow {
                    return crate::InvalidSnafu {
                        field: "managed execution mode",
                    }
                    .fail();
                }
                definition.check_invocation(
                    self.session.selection(),
                    &invocation,
                    Some(&managed),
                )?;
                (invocation, Some(managed))
            }
            None => (crate::definition::Invocation::default(), None),
        };
        if let Some(cursor) =
            resume.filter(|_| managed.as_ref().is_none_or(|managed| !managed.rebuild))
        {
            // Managed frontiers precede publication. Query cursors follow publication.
            let offered = managed
                .as_ref()
                .is_some_and(|managed| managed.instance.progress <= cursor.read_revision());
            windows = cursor
                .windows
                .iter()
                .filter(|window| {
                    offered
                        || !cursor
                            .completed_windows
                            .iter()
                            .any(|closed| closed.same_interval(window))
                })
                .copied()
                .collect();
            completion = if offered {
                cursor.completed_windows.clone()
            } else {
                let end = windows
                    .iter()
                    .map(|window| window.end_utc_ns)
                    .filter(|end| i128::from(*end) <= i128::from(now))
                    .min();
                windows
                    .iter()
                    .filter(|window| Some(window.end_utc_ns) == end)
                    .copied()
                    .collect()
            };
        }
        let selection = self.selection(now)?;
        let mut session = self.session.at(selection, now);
        session.managed = managed;
        let mut calls = session.call_context(invocation);
        let context = Arc::get_mut(&mut calls).ok_or_else(|| {
            crate::InvalidSnafu {
                field: "new call context",
            }
            .build()
        })?;
        context.set_windows(windows)?;
        context.completion = completion;
        session.calls = Some(calls);
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
    pub revision: u64,
    pub evaluated: u64,
    pub clock_changed: bool,
    pub completed_windows: Vec<crate::follow::WindowRange>,
    pub exhausted: bool,
}

pub(crate) type StreamError = (crate::Error, Option<Arc<ArrowSnapshot>>);
pub(crate) type OutputStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Event, StreamError>> + Send>>;
