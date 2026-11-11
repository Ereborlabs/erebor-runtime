use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, InputSubscription, PackageErrorCodeV1, StorePositionV1};
use datafusion::physical_plan::ExecutionPlan;
use snafu::ResultExt as _;
use tokio::sync::watch;

use crate::follow::Clock;
use crate::Result;

#[derive(Clone)]
pub struct Progress {
    clock: Arc<dyn Clock>,
    run: Arc<super::Run>,
    changes: Option<InputSubscription>,
    controls: watch::Receiver<()>,
    observed: StorePositionV1,
    clock_changes: watch::Receiver<u64>,
    position: StorePositionV1,
    expiry: Option<u64>,
    fired: Option<u64>,
    elapsed: bool,
}

pub enum Wake {
    Source,
    Clock,
    Control,
}

impl Progress {
    pub(crate) fn new(run: Arc<super::Run>) -> Self {
        Self {
            clock: Arc::clone(&run.clock),
            clock_changes: run.clock.changes(),
            controls: run.session.engine().store().subscribe_control(),
            changes: run.session.input_changes.clone(),
            run,
            observed: StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            position: StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            expiry: None,
            fired: None,
            elapsed: false,
        }
    }

    pub(crate) async fn bind(
        &mut self,
        physical: &Arc<dyn ExecutionPlan>,
        binding: &crate::execution::Session,
    ) -> Result<()> {
        if self.changes.is_some() {
            self.observe();
            return Ok(());
        }
        let mut requests = self.run.sources().clone();
        let mut bounds = crate::sources::SourceSnapshot::requests(
            &mut requests,
            std::slice::from_ref(physical),
            Some(&self.run),
            None,
        )
        .context(crate::SqlSnafu)?;
        requests.retain(|_, columns| columns.is_some());

        let indexed = binding.managed.is_some()
            && crate::sources::SourceLookup::required(physical, None).context(crate::SqlSnafu)?;

        crate::sources::SourceSnapshot::project_requests(&mut requests, &mut bounds, indexed)
            .context(crate::SqlSnafu)?;
        let resume = self
            .run
            .resume
            .as_ref()
            .filter(|_| self.run.follow)
            .cloned();
        let selection = self.run.session.selection().clone();
        let subscribe = || {
            let session = Arc::new(binding.clone());

            let control = Arc::clone(session.control());
            let worker = Arc::clone(&control);
            let requests = requests.clone();
            let owners = bounds.input_owners.clone();
            let resume = resume.clone();
            let selection = selection.clone();
            async move {
                crate::execution::Engine::blocking(control, session.token()?, move || {
                    let budget = session
                        .memory()
                        .managed_budget(worker.as_ref(), session.engine().limits().input_bytes);

                    if let Some(instance) = session
                        .managed
                        .as_ref()
                        .filter(|managed| managed.follow)
                        .map(|managed| &managed.instance)
                        .or(session.consumer.as_ref())
                    {
                        return session
                            .engine()
                            .store()
                            .subscribe_managed_inputs(
                                instance,
                                &selection,
                                &requests,
                                owners.as_ref(),
                                &worker,
                                budget.as_ref(),
                            )
                            .map_err(crate::Error::from);
                    }
                    if let Some(cursor) = resume.as_ref().filter(|_| session.managed.is_none()) {
                        let store = session.engine().store();
                        cursor.check_store(&store.meta()?)?;
                        return store
                            .subscribe_inputs_since(
                                cursor.position(),
                                session.selection(),
                                &requests,
                                owners.as_ref(),
                                &worker,
                                budget.as_ref(),
                            )
                            .map_err(crate::Error::from);
                    }
                    session
                        .engine()
                        .store()
                        .subscribe_inputs(
                            session.selection(),
                            &requests,
                            owners.as_ref(),
                            &worker,
                            budget.as_ref(),
                        )
                        .map_err(crate::Error::from)
                })
                .await
            }
        };
        let subscription = subscribe().await?;
        self.changes = Some(subscription);
        self.observe();
        Ok(())
    }

    pub(crate) fn source_position(&self) -> StorePositionV1 {
        self.changes
            .as_ref()
            .map_or(self.position, InputSubscription::position)
    }

    pub(crate) fn can_resume(&self, position: StorePositionV1) -> bool {
        self.changes
            .as_ref()
            .is_none_or(|changes| changes.can_resume(position))
    }

    pub(crate) fn observed(&self) -> StorePositionV1 {
        self.observed
    }

    pub(crate) fn subscription(&self) -> Option<InputSubscription> {
        self.changes.clone()
    }

    pub(crate) fn meta(&self) -> Option<&araphor_data::AnalysisStoreMetaV1> {
        self.changes.as_ref().map(InputSubscription::meta)
    }

    pub(crate) fn now(&self) -> Result<u64> {
        self.clock.now_ns()
    }

    pub(crate) fn observe(&mut self) {
        if let Some(changes) = &mut self.changes {
            self.observed = changes.observe();
        }
    }

    pub fn begin(&mut self) -> Result<u64> {
        self.observe();
        self.time()
    }

    pub(crate) fn time(&mut self) -> Result<u64> {
        self.clock_changes.borrow_and_update();
        let now = self.now()?;
        if self.fired.is_some_and(|due| due > now) {
            self.fired = None;
        }
        if self.expiry.is_some_and(|due| due > now) {
            self.elapsed = false;
        }
        Ok(now)
    }

    pub(crate) fn captured(&mut self, position: StorePositionV1, expiry: Option<u64>) {
        self.position = position;
        self.expiry = expiry;
        self.fired = None;
        self.elapsed = false;
    }

    pub(crate) fn completed(&mut self, meta: &araphor_data::AnalysisStoreMetaV1, publication: u64) {
        if let Some(changes) = &mut self.changes {
            changes.observed_meta(meta, publication);
        }
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        self.expiry.is_some_and(|expiry| expiry <= now)
    }

    pub(crate) fn clock_pending(&self) -> bool {
        self.clock_changes.has_changed().unwrap_or(false)
    }

    pub async fn next(
        &mut self,
        control: &AnalysisReadControl,
        deadline: Option<u64>,
    ) -> Result<Wake> {
        self.next_after(control, self.position, deadline).await
    }

    pub(crate) async fn next_after(
        &mut self,
        control: &AnalysisReadControl,
        after: StorePositionV1,
        deadline: Option<u64>,
    ) -> Result<Wake> {
        if self.clock_pending() {
            self.clock_changes.borrow_and_update();
            return Ok(Wake::Clock);
        }
        if self.controls.has_changed().unwrap_or(false) {
            self.controls.borrow_and_update();
            return Ok(Wake::Control);
        }
        if self.source_position() > after {
            self.observe();
            return Ok(Wake::Source);
        }
        let deadline = deadline
            .into_iter()
            .filter(|deadline| Some(*deadline) != self.fired)
            .chain(self.expiry.filter(|_| !self.elapsed))
            .min();
        let remaining = if let Some(due) = deadline {
            let now = self.now()?;
            if due <= now {
                self.fired = deadline;
                self.elapsed |= self.expiry == deadline;
                return Ok(Wake::Clock);
            }
            Some(Duration::from_nanos(due - now))
        } else {
            None
        };
        tokio::select! {
            _ = control.cancelled() => {
                control.check()?;
                Ok(Wake::Control)
            }
            changed = async {
                let Some(changes) = &mut self.changes else { return std::future::pending().await; };
                loop {
                    let position = changes.changed().await?;
                    if position > after { return Ok::<_, crate::Error>(position); }
                }
            } => {
                self.observed = changed?;
                Ok(Wake::Source)
            }
            changed = self.clock_changes.changed() => {
                changed.map_err(|_| PackageErrorCodeV1::Incomplete.error("clock progress"))?;
                self.clock_changes.borrow_and_update();
                Ok(Wake::Clock)
            }
            changed = self.controls.changed() => {
                changed.map_err(|_| PackageErrorCodeV1::Incomplete.error("store control"))?;
                self.controls.borrow_and_update();
                Ok(Wake::Control)
            }
            _ = tokio::time::sleep(remaining.unwrap_or_default()), if remaining.is_some() => {
                self.fired = deadline;
                self.elapsed |= self.expiry == deadline;
                Ok(Wake::Clock)
            }
        }
    }
}
