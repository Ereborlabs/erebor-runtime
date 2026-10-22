use std::sync::Arc;

use araphor_data::{AnalysisStoreMetaV1, StorePositionV1};
use datafusion::common::DataFusionError;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::ExecutionPlan;
use snafu::ResultExt as _;

use super::{kernel::Kernel, Compiled, Mode, SubscribeExec};
use crate::definition::CapturedExecution;
use crate::execution::{PendingRead, PhysicalStream, Read, Session};
use crate::follow::Operation;
use crate::sources::{ArrowSnapshot, Changes, JournalExec};
use crate::stream::progress::{Progress, Wake};
use crate::stream::{Event, Output, Run, StreamError};
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
    initial: Option<(Arc<crate::execution::Permit>, u64, Session)>,
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
        initial: Option<(Arc<crate::execution::Permit>, u64, Session)>,
        progress: Progress,
    ) -> Result<Self> {
        let maintained = match &physical.mode {
            Mode::Count {
                journal: Some(journal),
                compiled: Some(compiled),
            } if run.follow
                && run.window.is_none()
                && run.sources().len() == 1
                && run.sources().contains_key("events") =>
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

    pub(super) async fn next(&mut self) -> std::result::Result<Option<Event>, StreamError> {
        self.next_event()
            .await
            .map_err(|error| (error, self.snapshot.clone()))
    }

    async fn next_event(&mut self) -> Result<Option<Event>> {
        if self.ended {
            return Ok(None);
        }
        if self.snapshot.is_none() {
            if let Some(event) = self.evaluate(false).await? {
                return Ok(Some(event));
            }
        }
        if !self.run.follow {
            self.ended = true;
            return Ok(None);
        }
        if self.run.operation == Operation::Append && !self.exhausted {
            return self.evaluate(false).await;
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
                        return self.evaluate(false).await;
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
        let (meta, revision) = self
            .run
            .dependencies(&self.run.session, selection, None)
            .await?;
        self.check_store(&meta)?;
        self.progress.checked(meta.commit_revision);
        Ok(revision > self.revision)
    }

    async fn evaluate(&mut self, clock_changed: bool) -> Result<Option<Event>> {
        let (permit, now, initial) = match self.initial.take() {
            Some((permit, now, session)) => (permit, now, Some(session)),
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
                (permit, self.progress.begin()?, None)
            }
        };
        let selection = self.run.selection(now)?;
        if self.snapshot.is_none() && self.run.resume.is_some() && self.run.managed.is_none() {
            let (meta, _) = self
                .run
                .dependencies(&self.run.session, selection.clone(), Some(&permit))
                .await?;
            self.check_store(&meta)?;
        }
        let reuse = initial.is_some();
        let session = match initial {
            Some(session) => session,
            None => self.run.session(now, &permit).await?,
        };
        let calls = session.calls.clone().ok_or_else(Self::state_error)?;
        let execution = async {
            let output = if self.run.operation == Operation::Append {
                let PhysicalStream {
                    snapshot,
                    mut stream,
                    permit,
                    control,
                    reservation,
                } = session
                    .start_physical(
                        Arc::clone(&self.input),
                        Arc::clone(&self.context),
                        self.run.sources(),
                        Read::Page(self.position),
                        permit,
                    )
                    .await?;
                self.check_store(&snapshot.page.extraction.meta)?;
                self.snapshot = Some(Arc::clone(&snapshot));
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
                if let Some(previous) = &self.snapshot {
                    ArrowSnapshot::check_store(
                        &previous.page.extraction.meta,
                        &output.snapshot.page.extraction.meta,
                    )?;
                }
                self.snapshot = Some(Arc::clone(&output.snapshot));
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
                    let mut state = session.state()?;
                    state.config_mut().set_extension(Arc::clone(&permit));
                    state.config_mut().set_extension(Arc::clone(&self.run));
                    (
                        session.physical(&self.run.plan, &state).await?,
                        state.task_ctx(),
                    )
                };
                let pending = PendingRead {
                    control: Arc::clone(session.control()),
                    active: true,
                };
                let captured = session
                    .capture_physical(
                        physical,
                        context,
                        self.run.sources(),
                        Read::Snapshot,
                        permit,
                    )
                    .await?;
                captured.reserve_complete(self.run.follow)?;
                let captured = CapturedExecution::new(
                    captured,
                    session.clone(),
                    Arc::clone(&calls),
                    Arc::clone(self.run.session.control()),
                    pending,
                );
                if let Some((_, publication)) = &self.run.managed {
                    let snapshot = captured.snapshot();
                    self.check_store(&snapshot.page.extraction.meta)?;
                    let managed = snapshot.managed().ok_or_else(Self::state_error)?;
                    if let Some(cursor) =
                        self.run.resume.as_ref().filter(|_| self.snapshot.is_none())
                    {
                        if !managed.rebuild()
                            && managed.source_revision() <= cursor.read_revision()
                            && self.run.resume_expiry.is_none_or(|expiry| expiry > now)
                        {
                            let cursor = cursor.clone();
                            let (captured, mut pending) = captured.into_parts();
                            self.snapshot = Some(Arc::clone(&captured.snapshot));
                            self.revision = cursor.read_revision();
                            self.position = Some(cursor.position());
                            self.evaluated = cursor.evaluated();
                            self.exhausted = true;
                            self.progress.captured(
                                captured.snapshot.page.extraction.meta.commit_revision,
                                self.run.resume_expiry,
                            );
                            drop(captured);
                            pending.active = false;
                            return Ok(None);
                        }
                    }
                    let frontier = araphor_data::ManagedFrontier {
                        cursor: crate::follow::Cursor::new(
                            &snapshot.page.extraction.meta,
                            self.run.operation,
                            self.run.binding,
                            StorePositionV1 {
                                commit_revision: 0,
                                ordinal: 0,
                            },
                            now,
                        )
                        .encode()?,
                        next_change: snapshot.next_change,
                    };
                    let publication = Arc::clone(publication);
                    let invocation = calls.invocation().clone();
                    captured
                        .blocking(move |snapshot, control| {
                            publication.admit(snapshot, &invocation, &frontier, control)
                        })
                        .await?;
                }
                let (captured, mut pending) = captured.into_parts();
                let PhysicalStream {
                    snapshot,
                    stream,
                    permit,
                    control,
                    reservation,
                } = captured.start()?;
                self.check_store(&snapshot.page.extraction.meta)?;
                self.snapshot = Some(Arc::clone(&snapshot));
                let output = Output {
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
                .await?;
                pending.active = false;
                output
            };
            Ok::<_, crate::Error>(Some(output))
        };
        let result = execution.await;
        if result.is_err() {
            let _cancelled = session.control().cancel();
        }
        calls.finish().await;
        let Some(output) = result? else {
            return Ok(None);
        };
        self.check_store(&output.snapshot.page.extraction.meta)?;
        self.revision = output
            .snapshot
            .page
            .extraction
            .meta
            .commit_revision
            .max(calls.published_revision());
        self.position = Some(output.position);
        self.progress
            .captured(self.revision, output.snapshot.next_change);
        self.snapshot = Some(Arc::clone(&output.snapshot));
        self.evaluated = now;
        self.exhausted = self.run.operation == Operation::Replace
            || (output.snapshot.page.exhausted && !output.limited);
        Ok(Some(Event {
            output,
            calls: calls.results().context(SqlSnafu)?,
            completed: true,
            revision: self.revision,
            evaluated: now,
            clock_changed,
            exhausted: self.exhausted,
        }))
    }

    async fn metadata_update(&mut self, clock_changed: bool) -> Result<Event> {
        let clock_changed = clock_changed || self.progress.clock_pending();
        if clock_changed
            && (self.progress.deadline().is_some()
                || self
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.next_change.is_some())
                || crate::follow::Window::clocks(&self.run.plan)? != 0)
        {
            return self.evaluate(true).await?.ok_or_else(Self::state_error);
        }
        let now = self.progress.time()?;
        let selection = self.run.selection(now)?;
        let snapshot = self
            .run
            .session
            .at(selection, now)
            .metadata(self.run.sources())
            .await?;
        self.check_store(&snapshot.page.extraction.meta)?;
        self.run
            .session
            .control()
            .query_async(self.run.session.check_read(&snapshot))
            .await?;
        self.snapshot = Some(Arc::clone(&snapshot));
        Ok(Event {
            calls: Default::default(),
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
            revision: self.revision,
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
