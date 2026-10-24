use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisStore, PackageErrorCodeV1};
use tokio::sync::watch;

use crate::follow::Clock;
use crate::Result;

#[derive(Clone)]
pub struct Progress {
    clock: Arc<dyn Clock>,
    changes: watch::Receiver<u64>,
    clock_changes: watch::Receiver<u64>,
    context: Option<watch::Receiver<u64>>,
    revision: u64,
    expiry: Option<u64>,
    fired: Option<u64>,
    elapsed: bool,
}

pub enum Wake {
    Source,
    Clock,
}

impl Progress {
    pub fn new(
        store: &AnalysisStore,
        clock: Arc<dyn Clock>,
        context: Option<watch::Receiver<u64>>,
    ) -> Self {
        Self {
            changes: store.subscribe_revision(),
            clock_changes: clock.changes(),
            context,
            clock,
            revision: 0,
            expiry: None,
            fired: None,
            elapsed: false,
        }
    }

    pub(crate) fn now(&self) -> Result<u64> {
        self.clock.now_ns()
    }

    pub(crate) fn observe(&mut self) {
        self.revision = *self.changes.borrow_and_update();
    }

    pub fn begin(&mut self) -> Result<u64> {
        self.observe();
        if let Some(context) = &mut self.context {
            context.borrow_and_update();
        }
        self.time()
    }

    pub(crate) fn time(&mut self) -> Result<u64> {
        self.clock_changes.borrow_and_update();
        self.now()
    }

    pub(crate) fn checked(&mut self, revision: u64) {
        self.revision = revision;
    }

    pub(crate) fn captured(&mut self, revision: u64, expiry: Option<u64>) {
        self.checked(revision);
        self.expiry = expiry;
        self.fired = None;
        self.elapsed = false;
    }

    pub(crate) fn deadline(&self) -> Option<u64> {
        self.expiry
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        self.expiry.is_some_and(|expiry| expiry <= now)
    }

    pub(crate) fn pending(&self) -> bool {
        self.changes.has_changed().unwrap_or(false)
            || *self.changes.borrow() > self.revision
            || self
                .context
                .as_ref()
                .is_some_and(|context| context.has_changed().unwrap_or(false))
    }

    pub(crate) fn clock_pending(&self) -> bool {
        self.clock_changes.has_changed().unwrap_or(false)
    }

    pub async fn next(
        &mut self,
        control: &AnalysisReadControl,
        deadline: Option<u64>,
    ) -> Result<Wake> {
        if self.clock_pending() {
            self.clock_changes.borrow_and_update();
            return Ok(Wake::Clock);
        }
        if self.pending() {
            self.observe();
            if let Some(context) = &mut self.context {
                context.borrow_and_update();
            }
            return Ok(Wake::Source);
        }
        let deadline = deadline
            .into_iter()
            .filter(|deadline| Some(*deadline) != self.fired)
            .chain(self.expiry.filter(|_| !self.elapsed))
            .min();
        let now = self.now()?;
        if deadline.is_some_and(|deadline| deadline <= now) {
            self.fired = deadline;
            self.elapsed |= self.expiry == deadline;
            return Ok(Wake::Clock);
        }
        tokio::select! {
            _ = control.cancelled() => {
                control.check()?;
                Ok(Wake::Source)
            }
            changed = self.changes.changed() => {
                changed.map_err(|_| PackageErrorCodeV1::Incomplete.error("source progress"))?;
                self.observe();
                Ok(Wake::Source)
            }
            changed = self.clock_changes.changed() => {
                changed.map_err(|_| PackageErrorCodeV1::Incomplete.error("clock progress"))?;
                self.clock_changes.borrow_and_update();
                Ok(Wake::Clock)
            }
            changed = async {
                match &mut self.context {
                    Some(context) => context.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                changed.map_err(|_| PackageErrorCodeV1::Incomplete.error("context progress"))?;
                Ok(Wake::Source)
            }
            _ = tokio::time::sleep(Duration::from_nanos(deadline.unwrap_or(now).saturating_sub(now))), if deadline.is_some() => {
                self.fired = deadline;
                self.elapsed |= self.expiry == deadline;
                Ok(Wake::Clock)
            }
        }
    }
}
