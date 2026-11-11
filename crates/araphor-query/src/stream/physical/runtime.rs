use std::sync::Arc;

use araphor_data::{AnalysisStoreMetaV1, StorePositionV1};
use datafusion::common::DataFusionError;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::execution_plan::reset_plan_states;
use datafusion::physical_plan::ExecutionPlan;
use snafu::ResultExt as _;

use super::{kernel::Kernel, Compiled, Mode, SubscribeExec};
use crate::definition::CapturedExecution;
use crate::execution::{PendingRead, PhysicalStream, Read, Session};
use crate::follow::Operation;
use crate::sources::{ArrowSnapshot, Changes, SourceData};
use crate::stream::progress::{Progress, Wake};
use crate::stream::{Event, Output, Run, StreamError};
use crate::{Result, SqlSnafu};

pub(super) struct Runtime {
    run: Arc<Run>,
    input: Arc<dyn ExecutionPlan>,
    schema: datafusion::arrow::datatypes::SchemaRef,
    context: Arc<TaskContext>,
    reusable: bool,
    maintained: Option<Maintained>,
    progress: Progress,
    snapshot: Option<Arc<ArrowSnapshot>>,
    cut: Option<WindowCut>,
    advance_window: bool,
    revision: u64,
    captured: u64,
    position: Option<StorePositionV1>,
    evaluated: u64,
    exhausted: bool,
    ended: bool,
    initial: Option<(Arc<crate::execution::Permit>, u64, Session)>,
    source_index: Option<Arc<crate::sources::SourceIndex>>,
    append_read: Option<Arc<crate::sources::AppendRead>>,
}

struct WindowCut {
    snapshot: Arc<ArrowSnapshot>,
    _calls: Arc<crate::definition::CallContext>,
    closed: Vec<crate::follow::WindowRange>,
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
        reusable: bool,
    ) -> Result<Self> {
        let maintained = match &physical.mode {
            Mode::Replace {
                compiled: Some(compiled),
                ..
            } if run.follow
                && run.window.is_none()
                && run.sources().len() == 1
                && run.sources().contains_key("events") =>
            {
                let source = SourceData::from_plan(compiled.source.as_ref())
                    .ok_or_else(Self::state_error)?;
                let journal = Changes::new(source, Arc::clone(&context))?;
                let aggregate = compiled
                    .aggregate
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
        let revision = run
            .resume
            .as_ref()
            .map_or(0, |cursor| cursor.read_revision());
        let keys = crate::sources::SourceLookup::keys(&physical.input, None).context(SqlSnafu)?;
        let required = run.managed.is_some()
            && crate::sources::SourceLookup::required(&physical.input, None).context(SqlSnafu)?;
        if required && run.follow && !reusable {
            return Err(crate::Error::Sql {
                source: DataFusionError::NotImplemented(
                    "a retained source subscription requires a reusable native plan".into(),
                ),
            });
        }
        let continuing = initial
            .as_ref()
            .and_then(|(_, _, session)| session.managed.as_ref())
            .is_some_and(|managed| {
                !managed.rebuild
                    && managed
                        .expected
                        .as_ref()
                        .is_none_or(|expected| expected.generation == managed.instance.generation)
            });
        let source_index = required
            .then(
                || match run.session.source_index.as_ref().filter(|_| continuing) {
                    Some(index) => Ok(Arc::clone(index)),
                    None => {
                        crate::sources::SourceIndex::new(keys, Arc::clone(run.session.memory()))
                    }
                },
            )
            .transpose()
            .context(SqlSnafu)?;
        let append_read = (run.operation == Operation::Append)
            .then(|| crate::sources::AppendRead::new(run.session.memory()))
            .transpose()
            .context(SqlSnafu)?;
        Ok(Self {
            revision,
            captured: run.resume_revision(),
            position: run.resume.as_ref().map(|cursor| cursor.position()),
            run,
            input: Arc::clone(&physical.input),
            schema: physical.schema(),
            context,
            reusable,
            maintained,
            progress,
            snapshot: None,
            cut: None,
            advance_window: false,
            evaluated: 0,
            exhausted: true,
            ended: false,
            initial,
            source_index,
            append_read,
        })
    }

    pub(super) async fn next(mut self) -> std::result::Result<Option<(Event, Self)>, StreamError> {
        let session = Arc::clone(&self.run.session);
        let lease = session
            .workers
            .as_ref()
            .map(araphor_package_runtime::TaskTracker::token);
        if session
            .workers
            .as_ref()
            .is_some_and(araphor_package_runtime::TaskTracker::is_closed)
        {
            return Err((
                crate::InvalidSnafu {
                    field: "execution scope",
                }
                .build(),
                None,
            ));
        }
        let (state, result) = session
            .engine()
            .run(Arc::clone(session.control()), lease, async move {
                let result = self.next_event().await.map_err(|error| {
                    crate::stream::recovery::SourceRecovery::attach(
                        &error,
                        &self.progress,
                        self.source_index.as_ref(),
                    );
                    (error, self.snapshot.clone())
                });
                Ok((self, result))
            })
            .await
            .map_err(|error| (error, None))?;
        Ok(result?.map(|event| (event, state)))
    }

    async fn next_event(&mut self) -> Result<Option<Event>> {
        if self.ended {
            return Ok(None);
        }
        let binding = self
            .initial
            .as_ref()
            .map(|(_, _, session)| session)
            .unwrap_or(&self.run.session);
        self.progress.bind(&self.input, binding).await?;
        let mut resumed_clock = false;
        if self.snapshot.is_none() {
            let now = self.progress.now()?;
            if let Some(cursor) = self.run.resume.as_ref().filter(|cursor| {
                self.run.follow
                    && self.progress.can_resume(cursor.position())
                    && !self.run.resume_pending
                    && self
                        .initial
                        .as_ref()
                        .and_then(|(_, _, session)| session.managed.as_ref())
                        .is_none_or(|managed| !managed.rebuild)
                    && self.run.resume_expiry.is_none_or(|expiry| expiry > now)
            }) {
                if let Some(meta) = self.progress.meta() {
                    cursor.check_store(meta)?;
                }
                if self.progress.source_position() <= cursor.position() {
                    let cursor = cursor.clone();
                    self.progress
                        .captured(cursor.position(), self.run.resume_expiry);
                    self.evaluated = cursor.evaluated();
                    if let Some((permit, _, session)) = self.initial.take() {
                        if let Some(calls) = &session.calls {
                            calls.finish().await;
                        }
                        drop(session);
                        drop(permit);
                    }
                    match self
                        .run
                        .session
                        .control()
                        .query_async(self.progress.next(self.run.session.control(), None))
                        .await?
                    {
                        Wake::Source => {}
                        Wake::Control => return self.metadata_update(false).await.map(Some),
                        Wake::Clock => {
                            let now = self.progress.now()?;
                            if self.progress.expired(now)
                                || cursor.windows.iter().any(|window| {
                                    window.active
                                        && i128::from(window.end_utc_ns) <= i128::from(now)
                                        && !cursor
                                            .completed_windows
                                            .iter()
                                            .any(|closed| closed.same_interval(window))
                                })
                            {
                                resumed_clock = true;
                            } else {
                                let mut event = self.metadata_update(false).await?;
                                event.clock_changed = true;
                                return Ok(Some(event));
                            }
                        }
                    }
                }
            }
        }
        if self.advance_window {
            self.advance_window = false;
            if let Some(event) = self.complete_window().await? {
                return Ok(Some(event));
            }
            self.cut = None;
            return self.evaluate(true, Vec::new()).await;
        }
        if self.snapshot.is_none() {
            if let Some(event) = self.evaluate(resumed_clock, Vec::new()).await? {
                return Ok(Some(event));
            }
        }
        if !self.run.follow {
            self.ended = true;
            return Ok(None);
        }
        if !self.exhausted {
            return self.evaluate(false, Vec::new()).await;
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
                    if let Some(event) = self.complete_window().await? {
                        return Ok(Some(event));
                    }
                    return self.evaluate(false, Vec::new()).await;
                }
                Wake::Control => return self.metadata_update(false).await.map(Some),
                Wake::Clock => {
                    if let Some(event) = self.complete_window().await? {
                        return Ok(Some(event));
                    }
                    return self.metadata_update(true).await.map(Some);
                }
            }
        }
    }

    async fn evaluate(
        &mut self,
        clock_changed: bool,
        completion: Vec<crate::follow::WindowRange>,
    ) -> Result<Option<Event>> {
        let retained = self.cut.take();
        let windows = retained.as_ref().map_or_else(Vec::new, |cut| {
            cut.snapshot
                .windows
                .iter()
                .filter(|window| {
                    window.active && !cut.closed.iter().any(|closed| closed.same_interval(window))
                })
                .copied()
                .collect()
        });
        let retained = retained.map(|cut| cut.snapshot);
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
        let reuse = initial.is_some();
        let mut session = match initial {
            Some(session) => session,
            None => {
                self.run
                    .session(
                        now,
                        &permit,
                        completion,
                        windows,
                        self.run.resume.as_ref().filter(|_| self.snapshot.is_none()),
                    )
                    .await?
            }
        };

        {
            session.input_changes = self.progress.subscription();
        }
        session.source_index = self.source_index.clone();
        session.append_read = self.append_read.clone();
        let calls = session.calls.clone().ok_or_else(Self::state_error)?;
        let mut observed = None;
        let mut recovery = None;
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
                let output = output.complete(&session, stream).await?;
                drop(input);
                output
            } else {
                let (physical, context) = if reuse && !self.reusable {
                    (Arc::clone(&self.input), Arc::clone(&self.context))
                } else {
                    let mut state = session.state()?;
                    state.config_mut().set_extension(Arc::clone(&permit));
                    state.config_mut().set_extension(Arc::clone(&self.run));
                    let physical = if self.reusable {
                        match reset_plan_states(Arc::clone(&self.input)) {
                            Ok(physical) => physical,
                            Err(error) if self.source_index.is_some() => {
                                return Err(error).context(SqlSnafu)
                            }
                            Err(_) => session.physical(&self.run.plan, &state).await?,
                        }
                    } else {
                        session.physical(&self.run.plan, &state).await?
                    };
                    (physical, state.task_ctx())
                };
                let pending = PendingRead {
                    control: Arc::clone(session.control()),
                    active: true,
                };
                let mut captured = session
                    .capture_physical(
                        physical,
                        context,
                        self.run.sources(),
                        Read::Snapshot,
                        permit,
                    )
                    .await?;
                observed = captured
                    .context
                    .session_config()
                    .get_extension::<crate::sources::SourceSnapshot>();
                if self.run.follow || self.run.managed.is_none() {
                    captured.reserve_complete()?;
                }
                recovery = captured.recovery.take();
                let captured = CapturedExecution::new(
                    captured,
                    session.clone(),
                    Arc::clone(&calls),
                    Arc::clone(self.run.session.control()),
                    pending,
                );
                let position = StorePositionV1 {
                    commit_revision: captured.snapshot().page.extraction.meta.commit_revision,
                    ordinal: u32::MAX,
                };
                self.progress
                    .captured(position, captured.snapshot().next_change);
                if let Some((_, publication)) = &self.run.managed {
                    let snapshot = captured.snapshot();
                    self.check_store(&snapshot.page.extraction.meta)?;
                    let mut cursor = crate::follow::Cursor::new(
                        &snapshot.page.extraction.meta,
                        self.run.operation,
                        self.run.binding,
                        position,
                        now,
                    );
                    cursor.set_windows(
                        &snapshot.windows,
                        &calls.completed_windows(snapshot).context(SqlSnafu)?,
                    );
                    let frontier = araphor_data::ManagedFrontier {
                        cursor: cursor.encode()?,
                        next_change: snapshot.next_change,
                        pending: false,
                    };
                    let publication = Arc::clone(publication);
                    let invocation = calls.invocation().clone();
                    let admitted = captured
                        .blocking(move |snapshot, control| {
                            let attempt =
                                publication.admit(snapshot, &invocation, &frontier, control)?;
                            if let Some(attempt) = &attempt {
                                let request = attempt.request();
                                if request.id != invocation.id
                                    || request.seed != invocation.seed
                                    || request.frontier.as_ref() != Some(&frontier)
                                {
                                    return Err(araphor_data::PackageErrorCodeV1::Conflict
                                        .error("managed admission identity")
                                        .into());
                                }
                            }
                            Ok(attempt)
                        })
                        .await;
                    match admitted {
                        Ok(Some(attempt)) => captured.bind_attempt(attempt)?,
                        Ok(None) => {}
                        Err(error) => {
                            if self.run.follow
                                && matches!(
                                    &error,
                                    crate::Error::Data {
                                        source: araphor_data::Error::AnalysisConflict { .. }
                                            | araphor_data::Error::AnalysisSourceChanged { .. }
                                    }
                                )
                            {
                                if let Some(recovery) = recovery.take() {
                                    return Err(recovery.invalidated().failed(error));
                                }
                            }
                            return Err(error);
                        }
                    }
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
                    position,
                    limited: false,
                    _memory: reservation,
                    _permit: Some(permit),
                    _control: control,
                }
                .complete(&session, stream)
                .await?;
                pending.active = false;
                output
            };
            Ok::<_, crate::Error>(Some(output))
        };
        let result = execution.await.map_err(|error| match recovery {
            Some(recovery) => recovery.failed(error),
            None => error,
        });
        if result.is_err() {
            let _cancelled = session.control().cancel();
        }
        calls.finish().await;
        if let Some(source) = observed {
            source.report_work();
        }
        if let Ok(result) = &result {
            if let Some(snapshot) = result
                .as_ref()
                .map(|output| &output.snapshot)
                .or(self.snapshot.as_ref())
            {
                erebor_telemetry::debug!(
                    stage = "subscription_done",
                    instance_id = %snapshot.managed().map_or("", |capture| capture.instance().spec.id.as_str()),
                    cut_revision = snapshot.page.extraction.meta.commit_revision,
                    publication_revision = calls.published_revision(),
                    rows = result.as_ref().and_then(|output| output.batches.as_ref()).map_or(0u64, |batches| {
                        batches.iter().fold(0u64, |rows, batch| rows.saturating_add(batch.num_rows() as u64))
                    }),
                    "Native subscription execution completed"
                );
            }
        }
        let Some(output) = result? else {
            return Ok(None);
        };
        self.check_store(&output.snapshot.page.extraction.meta)?;
        let captured = output.snapshot.page.extraction.meta.commit_revision;
        self.progress.completed(
            &output.snapshot.page.extraction.meta,
            calls.published_revision(),
        );
        self.revision = captured.max(calls.published_revision());
        self.captured = captured;
        self.position = Some(output.position);
        self.progress
            .captured(output.position, output.snapshot.next_change);
        self.snapshot = Some(Arc::clone(&output.snapshot));
        self.evaluated = now;
        let completed = self.run.managed.is_none() || calls.published_revision() != 0;
        let consumed = match (
            &self.source_index,
            output
                .snapshot
                .managed()
                .and_then(|capture| capture.source()),
        ) {
            (Some(index), Some(frame)) => index.committed(frame).context(SqlSnafu)?,
            _ => false,
        };
        self.exhausted = (completed || consumed)
            && (self.run.operation == Operation::Replace
                || (output.snapshot.page.exhausted && !output.limited));
        let completed_windows = calls
            .completed_windows(&output.snapshot)
            .context(SqlSnafu)?;
        drop(retained);
        if self.run.follow && output.snapshot.windows.iter().any(|window| window.active) {
            self.cut = Some(WindowCut {
                snapshot: Arc::clone(&output.snapshot),
                _calls: Arc::clone(&calls),
                closed: completed_windows.clone(),
            });
        } else {
            self.cut = None;
        }
        self.advance_window = !completed_windows.is_empty();
        Ok(Some(Event {
            output,
            calls: calls.results().context(SqlSnafu)?,
            completed: true,
            revision: self.revision,
            evaluated: now,
            clock_changed,
            completed_windows,
            exhausted: self.exhausted,
        }))
    }

    async fn complete_window(&mut self) -> Result<Option<Event>> {
        let Some(cut) = &self.cut else {
            return Ok(None);
        };
        let now = self.progress.now()?;
        let end = cut
            .snapshot
            .windows
            .iter()
            .filter(|window| {
                window.active && !cut.closed.iter().any(|closed| closed.same_interval(window))
            })
            .map(|window| window.end_utc_ns)
            .filter(|end| i128::from(*end) <= i128::from(now))
            .min();
        let Some(end) = end else {
            return Ok(None);
        };
        let completed = cut
            .snapshot
            .windows
            .iter()
            .filter(|window| {
                window.active
                    && window.end_utc_ns == end
                    && !cut.closed.iter().any(|closed| closed.same_interval(window))
            })
            .copied()
            .collect::<Vec<_>>();
        self.evaluate(true, completed).await
    }

    async fn metadata_update(&mut self, clock_wake: bool) -> Result<Event> {
        let clock_changed = clock_wake || self.progress.clock_pending();
        let now = self.progress.time()?;
        if clock_changed
            && (self.progress.expired(now)
                || self
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.next_change.is_some_and(|due| due <= now)))
        {
            return self
                .evaluate(true, Vec::new())
                .await?
                .ok_or_else(Self::state_error);
        }
        let metadata = self
            .run
            .session
            .subscription_metadata(self.run.sources(), now, self.run.selection_window()?)
            .await?;
        self.check_store(&metadata.page.extraction.meta)?;
        let snapshot = if clock_wake {
            self.snapshot
                .as_ref()
                .filter(|snapshot| snapshot.next_change.is_some())
                .unwrap_or(&metadata)
        } else {
            &metadata
        };
        self.run
            .session
            .control()
            .query_async(self.run.session.check_read(snapshot))
            .await?;
        self.progress.completed(&metadata.page.extraction.meta, 0);
        Ok(Event {
            calls: Default::default(),
            output: Output {
                snapshot: Arc::clone(snapshot),
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
            completed_windows: Vec::new(),
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
