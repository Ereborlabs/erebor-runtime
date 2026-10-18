use std::sync::Arc;

use araphor_data::{AnalysisSelectionV1, AnalysisStoreMetaV1, StorePositionV1};
use datafusion::common::DataFusionError;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::ExecutionPlan;
use snafu::ResultExt as _;

use super::{kernel::Kernel, Compiled, Mode, SubscribeExec};
use crate::execution::{Engine, Read};
use crate::follow::Operation;
use crate::sources::{ArrowSnapshot, Changes, JournalExec};
use crate::stream::progress::{Progress, Wake};
use crate::stream::{Event, Output, Run};
use crate::{Result, SqlSnafu};

pub(super) struct Runtime {
    run: Arc<Run>,
    input: Arc<dyn ExecutionPlan>,
    schema: datafusion::arrow::datatypes::SchemaRef,
    context: Arc<TaskContext>,
    maintained: Option<Maintained>,
    progress: Progress,
    snapshot: Option<Arc<ArrowSnapshot>>,
    revision: u64,
    position: Option<StorePositionV1>,
    content: Option<[u8; 32]>,
    evaluated: u64,
    exhausted: bool,
    ended: bool,
    initial: Option<(Arc<crate::execution::Permit>, u64)>,
}

struct Maintained {
    journal: Changes,
    kernel: Kernel,
    compiled: Arc<Compiled>,
}

impl Runtime {
    pub(super) fn new(
        physical: &SubscribeExec,
        context: Arc<TaskContext>,
        run: Arc<Run>,
        initial: Option<(Arc<crate::execution::Permit>, u64)>,
        progress: Progress,
    ) -> Result<Self> {
        let maintained = match &physical.mode {
            Mode::Count {
                journal: Some(journal),
                compiled: Some(compiled),
            } if run.follow
                && run.window.is_none()
                && !run.sources.contains_key("notifications")
                && run.sources.len() == 1
                && run.sources.contains_key("events") =>
            {
                let journal = journal
                    .as_any()
                    .downcast_ref::<JournalExec>()
                    .ok_or_else(Self::state_error)?
                    .open(Arc::clone(&context))?;
                let aggregate = compiled
                    .aggregate
                    .as_any()
                    .downcast_ref::<AggregateExec>()
                    .ok_or_else(Self::state_error)?;
                Some(Maintained {
                    journal,
                    kernel: Kernel::new(
                        aggregate,
                        Arc::clone(&compiled.source),
                        Arc::clone(&context),
                        Arc::clone(&run.session),
                    )?,
                    compiled: Arc::clone(compiled),
                })
            }
            _ => None,
        };
        Ok(Self {
            revision: run
                .resume
                .as_ref()
                .map_or(0, |cursor| cursor.read_revision()),
            position: run.resume.as_ref().map(|cursor| cursor.position()),
            run,
            input: Arc::clone(&physical.input),
            schema: physical.schema(),
            context,
            maintained,
            progress,
            snapshot: None,
            content: None,
            evaluated: 0,
            exhausted: true,
            ended: false,
            initial,
        })
    }

    pub(super) async fn next(&mut self) -> Result<Option<Event>> {
        if self.ended {
            return Ok(None);
        }
        if self.snapshot.is_none() {
            return self.evaluate(false).await.map(Some);
        }
        if !self.run.follow {
            self.ended = true;
            return Ok(None);
        }
        if self.run.operation == Operation::Append && !self.exhausted {
            return self.evaluate(false).await.map(Some);
        }
        {
            match self
                .run
                .session
                .control()
                .query_async(self.progress.next(self.run.session.control(), None))
                .await?
            {
                Wake::Source => {
                    if self.changed().await? {
                        return self.evaluate(false).await.map(Some);
                    }
                    return self.metadata_update(false).await.map(Some);
                }
                Wake::Clock => return self.metadata_update(true).await.map(Some),
            }
        }
    }

    async fn changed(&mut self) -> Result<bool> {
        self.progress.observe();
        let selection = self
            .snapshot
            .as_ref()
            .ok_or_else(Self::state_error)?
            .selection
            .clone();
        let (meta, revision) = self.dependencies(selection).await?;
        self.check_store(&meta)?;
        self.progress.checked(meta.commit_revision);
        Ok(revision > self.revision)
    }

    async fn dependencies(
        &self,
        selection: AnalysisSelectionV1,
    ) -> Result<(AnalysisStoreMetaV1, u64)> {
        loop {
            let stage = Arc::new(
                self.run
                    .session
                    .control()
                    .within(self.run.session.engine().limits().extract_timeout)?,
            );
            let worker = Arc::clone(&stage);
            let store = Arc::clone(self.run.session.engine().store());
            let selection = selection.clone();
            let relations: &'static [&'static str] =
                if self.run.sources.contains_key("discovery_state") {
                    &["processor_progress", "processor_gaps", "analysis_results"]
                } else {
                    &[]
                };
            match Engine::blocking(stage, move || {
                store
                    .dependency_revision_for(&selection, relations, &worker)
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
                    self.run
                        .session
                        .control()
                        .query_async(async {
                            self.run
                                .session
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

    async fn evaluate(&mut self, clock_changed: bool) -> Result<Event> {
        let (permit, now, reuse) = match self.initial.take() {
            Some((permit, now)) => (permit, now, true),
            None => {
                let permit = Arc::new(
                    self.run
                        .session
                        .control()
                        .query_async(
                            self.run
                                .session
                                .engine()
                                .acquire_evaluation(self.run.session.selection().tenant_id),
                        )
                        .await?,
                );
                (permit, self.progress.begin()?, false)
            }
        };
        let selection = self.run.window.map_or_else(
            || self.run.session.selection().clone(),
            |window| window.selection(self.run.session.selection(), now),
        );
        if self.snapshot.is_none() && self.run.resume.is_some() {
            let (meta, _) = self.dependencies(selection.clone()).await?;
            self.check_store(&meta)?;
        }
        let session = self.run.session.at(selection, now);
        let output = if self.run.operation == Operation::Append {
            let (snapshot, mut stream, permit, control, reservation) = session
                .start_physical(
                    Arc::clone(&self.input),
                    Arc::clone(&self.context),
                    &self.run.sources,
                    Read::Page(self.position),
                    permit,
                )
                .await?;
            self.check_store(&snapshot.page.extraction.meta)?;
            Output::page(
                &session,
                Arc::clone(&self.schema),
                &mut stream,
                control,
                reservation,
                snapshot,
                permit,
            )
            .await?
        } else if let Some(maintained) = &mut self.maintained {
            let change = maintained.journal.capture(permit, now).await?;
            let mut output = maintained.kernel.apply(change).await?;
            let batches = output.batches.take().ok_or_else(Self::state_error)?;
            output._control.check()?;
            let reservation = session
                .memory()
                .prepare_output(session.output().1)
                .context(SqlSnafu)?;
            let input = std::mem::replace(&mut output._memory, reservation);
            let stream = SubscribeExec::bind(
                &self.input,
                &maintained.compiled.aggregate,
                batches,
                Arc::clone(&self.context),
            )
            .context(SqlSnafu)?;
            let output = output
                .complete(&session, stream, Some(&mut self.content))
                .await?;
            drop(input);
            output
        } else {
            let (physical, context) = if reuse {
                (Arc::clone(&self.input), Arc::clone(&self.context))
            } else {
                let state = session.state()?;
                (
                    session.physical(&self.run.plan, &state).await?,
                    state.task_ctx(),
                )
            };
            let (snapshot, stream, permit, control, reservation) = session
                .start_physical(physical, context, &self.run.sources, Read::Snapshot, permit)
                .await?;
            self.check_store(&snapshot.page.extraction.meta)?;
            Output {
                snapshot,
                batches: None,
                positions: Vec::new(),
                position: StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                },
                limited: false,
                _memory: reservation,
                _permit: Some(permit),
                _control: control,
            }
            .complete(
                &session,
                stream,
                self.run.follow.then_some(&mut self.content),
            )
            .await?
        };
        self.check_store(&output.snapshot.page.extraction.meta)?;
        self.revision = output.snapshot.page.extraction.meta.commit_revision;
        self.position = Some(output.position);
        let expiry = self
            .run
            .window
            .and_then(|window| window.expiry(output.snapshot.received_min))
            .into_iter()
            .chain(output.snapshot.next_change)
            .min();
        self.progress.captured(self.revision, expiry);
        self.snapshot = Some(Arc::clone(&output.snapshot));
        self.evaluated = now;
        self.exhausted = self.run.operation == Operation::Replace
            || (output.snapshot.page.exhausted && !output.limited);
        Ok(Event {
            output,
            completed: true,
            evaluated: now,
            clock_changed,
            exhausted: self.exhausted,
        })
    }

    async fn metadata_update(&mut self, clock_changed: bool) -> Result<Event> {
        let clock_changed = clock_changed || self.progress.clock_pending();
        if (self.run.window.is_some() || self.run.sources.contains_key("notifications"))
            && clock_changed
        {
            return self.evaluate(true).await;
        }
        let now = self.progress.time()?;
        let selection = self.run.window.map_or_else(
            || self.run.session.selection().clone(),
            |window| window.selection(self.run.session.selection(), now),
        );
        let snapshot = self
            .run
            .session
            .at(selection, now)
            .metadata(&self.run.sources)
            .await?;
        self.check_store(&snapshot.page.extraction.meta)?;
        self.run
            .session
            .control()
            .query_async(self.run.session.engine().check_read(&snapshot))
            .await?;
        self.snapshot = Some(Arc::clone(&snapshot));
        Ok(Event {
            output: Output {
                snapshot,
                batches: None,
                positions: Vec::new(),
                position: self.position.ok_or_else(Self::state_error)?,
                limited: false,
                _memory: self
                    .run
                    .session
                    .memory()
                    .reserve_output(0)
                    .context(SqlSnafu)?,
                _permit: None,
                _control: Arc::clone(self.run.session.control()),
            },
            completed: false,
            evaluated: self.evaluated,
            clock_changed,
            exhausted: self.exhausted,
        })
    }

    fn check_store(&self, meta: &AnalysisStoreMetaV1) -> Result<()> {
        if let Some(cursor) = &self.run.resume {
            cursor.check_store(meta)?;
        }
        if let Some(snapshot) = &self.snapshot {
            ArrowSnapshot::check_store(&snapshot.page.extraction.meta, meta)?;
        }
        Ok(())
    }

    fn state_error() -> crate::Error {
        crate::Error::Sql {
            source: DataFusionError::Internal("subscription state is incomplete".into()),
        }
    }
}
