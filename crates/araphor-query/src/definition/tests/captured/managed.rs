use futures_util::StreamExt as _;

use super::*;
use crate::follow::{ManagedPublication, Operation, Subscription, SystemClock};
use araphor_data::{ManagedFrontier, ManagedRead};

mod snapshot;

impl ManagedPublication for Sink {
    fn begin(&self, control: &AnalysisReadControl) -> crate::Result<(Invocation, ManagedRead)> {
        self.state.begins.fetch_add(1, Ordering::SeqCst);
        self.state.admitted.store(false, Ordering::SeqCst);
        if let Some(gate) = &self.state.begin_gate {
            if let Some(entered) = gate.entered.lock().unwrap().take() {
                let _sent = entered.send(());
            }
            gate.release.lock().unwrap().recv().unwrap();
        }
        control.check()?;
        let instance = self
            .managed
            .clone()
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("test managed instance"))?;
        let completed = matches!(
            instance.spec.destination,
            araphor_data::ManagedDestination::Graph { .. }
        )
        .then_some(instance.progress);
        Ok((
            Invocation::default(),
            ManagedRead {
                execution: None,
                follow: !self.state.finite.load(Ordering::SeqCst),
                expected: None,
                instance,
                rebuild: self.state.rebuild.load(Ordering::SeqCst),
                completed,
            },
        ))
    }

    fn admit(
        &self,
        snapshot: &crate::sources::ArrowSnapshot,
        _: &Invocation,
        frontier: &ManagedFrontier,
        control: &AnalysisReadControl,
    ) -> crate::Result<()> {
        assert!(snapshot
            .managed()
            .is_some_and(|captured| captured.time_utc_ns() > 0));
        assert_eq!(
            snapshot.managed().map(|managed| managed.rebuild()),
            Some(self.state.rebuild.load(Ordering::SeqCst))
        );
        assert!(!frontier.pending);
        let cursor = crate::follow::Cursor::decode(&frontier.cursor)?;
        assert_eq!(
            cursor.read_revision(),
            snapshot.page.extraction.meta.commit_revision
        );
        *self.state.frontier.lock().unwrap() = Some(frontier.clone());
        assert!(!self.state.admitted.load(Ordering::SeqCst));
        assert_eq!(
            self.state.entries.load(Ordering::SeqCst),
            self.state.admissions.load(Ordering::SeqCst)
        );
        if let Some(gate) = &self.state.admission_gate {
            if let Some(entered) = gate.entered.lock().unwrap().take() {
                let _sent = entered.send(());
            }
            gate.release.lock().unwrap().recv().unwrap();
        }
        control.check()?;
        if let Some(error) = self.state.admission_error.lock().unwrap().take() {
            return Err(error);
        }
        self.state.admissions.fetch_add(1, Ordering::SeqCst);
        self.state.admitted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

async fn prepared(
    fixture: &Fixture,
    state: &Arc<SinkState>,
) -> TestResult<(PreparedDefinition, Arc<Sink>)> {
    let mut definition = fixture
        .prepare(&Fixture::sql("SELECT source_cursor AS value FROM events"))
        .await?;
    let input = Arc::clone(state);
    let gate = create_udf(
        "managed_input_gate",
        vec![sdk::DataType::UInt64],
        sdk::DataType::UInt64,
        Volatility::Volatile,
        Arc::new(move |arguments| {
            assert!(input.admitted.load(Ordering::SeqCst));
            input.input_evaluations.fetch_add(1, Ordering::SeqCst);
            arguments
                .first()
                .cloned()
                .ok_or_else(|| DataFusionError::Execution("test input absent".into()))
        }),
    );
    definition.plan = LogicalPlanBuilder::from(definition.plan)
        .project(vec![gate.call(vec![col("value")]).alias("value")])?
        .repartition(Partitioning::RoundRobinBatch(3))?
        .build()?;
    let instance = fixture.managed(&definition, AnalysisSelectionV1::tenant([1; 16]))?;
    let target = Arc::new(Sink {
        schema: Arc::clone(definition.plan.schema().inner()),
        calls: Vec::new(),
        state: Arc::clone(state),
        managed: Some(instance),
    });
    Ok((definition, target))
}

fn stream(
    fixture: &Fixture,
    definition: PreparedDefinition,
    target: Arc<Sink>,
    control: &AnalysisReadControl,
) -> crate::Result<Subscription> {
    Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), control, 0)?,
        definition,
        target,
        b"managed-test",
        None,
        Arc::new(SystemClock::default()),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_admits_each_input() -> TestResult {
    let fixture = fixture().await?;
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, held) = mpsc::channel();
    let state = Arc::new(SinkState {
        admission_gate: Some(WriterGate {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(held),
        }),
        ..Default::default()
    });
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut stream = stream(&fixture, definition, target, &control)?;
    let mut next = Box::pin(stream.next());
    tokio::select! {
        result = &mut next => return Err(format!("managed step ended before admission: {:?}", result).into()),
        entered = observed => entered?,
    }
    assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
    assert_eq!(state.entries.load(Ordering::SeqCst), 0);
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let first = next.await.ok_or("first managed update")??;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(
        first.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    assert_eq!(state.begins.load(Ordering::SeqCst), 1);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(state.partitions.load(Ordering::SeqCst), 3);
    let inputs = state.input_evaluations.load(Ordering::SeqCst);
    assert!(inputs > 0);
    drop(first);
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.event(2)?;
    release.send(())?;
    let second = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("second managed update")??;
    assert_eq!(
        second.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    assert_eq!(state.begins.load(Ordering::SeqCst), 2);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    assert!(state.input_evaluations.load(Ordering::SeqCst) > inputs);
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join().await?;
    assert!(second.snapshot.managed().is_some());
    drop(second);
    drop(state.receipt.lock().unwrap().take());
    released(&fixture)
}

#[tokio::test]
async fn replace_drains_pending_publications() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState {
        pending: 2,
        ..Default::default()
    });
    let (definition, target) = prepared(&fixture, &state).await?;
    let before = fixture.engine.store().meta()?;
    assert!(before.commit_revision > 0);
    let control = AnalysisReadControl::default();
    let mut subscription = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let mut inputs = 0;
    for step in 1..=3 {
        let update = tokio::time::timeout(Duration::from_secs(30), subscription.next())
            .await?
            .ok_or("pending managed update")??;
        assert_eq!(update.operation, Operation::Replace);
        assert_eq!(update.exhausted, step == 3);
        assert_eq!(update.snapshot.page.extraction.meta, before);
        assert_eq!(update.cursor.read_revision(), before.commit_revision);
        assert_eq!(
            update.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            1
        );
        assert_eq!(state.begins.load(Ordering::SeqCst), step);
        assert_eq!(state.admissions.load(Ordering::SeqCst), step);
        assert_eq!(state.entries.load(Ordering::SeqCst), step);
        assert_eq!(state.commits.load(Ordering::SeqCst), step);
        assert!(state.input_evaluations.load(Ordering::SeqCst) > inputs);
        inputs = state.input_evaluations.load(Ordering::SeqCst);
        drop(update);
        if step == 1 {
            let frontier = state
                .frontier
                .lock()
                .unwrap()
                .clone()
                .ok_or("pending frontier")?;
            assert!(frontier.pending);
            subscription.cancel_and_join().await?;
            subscription = Subscription::managed(
                fixture.engine.session(
                    AnalysisSelectionV1::tenant([1; 16]),
                    &AnalysisReadControl::default(),
                    0,
                )?,
                definition.clone(),
                Arc::clone(&target) as Arc<dyn ManagedPublication>,
                b"managed-test",
                Some(frontier),
                Arc::new(SystemClock::default()),
            )?;
        }
    }
    assert!(
        !state
            .frontier
            .lock()
            .unwrap()
            .as_ref()
            .ok_or("complete frontier")?
            .pending
    );
    assert!(futures_util::poll!(subscription.next()).is_pending());
    assert_eq!(state.begins.load(Ordering::SeqCst), 3);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 3);
    assert_eq!(state.entries.load(Ordering::SeqCst), 3);
    assert_eq!(state.commits.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.engine.store().meta()?, before);
    subscription.cancel_and_join().await?;
    drop(state.receipt.lock().unwrap().take());
    drop((definition, target));
    released(&fixture)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_cancel_joins_worker() -> TestResult {
    for begin in [true, false] {
        let fixture = fixture().await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, held) = mpsc::channel();
        let gate = WriterGate {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(held),
        };
        let mut state = SinkState::default();
        if begin {
            state.begin_gate = Some(gate);
        } else {
            state.admission_gate = Some(gate);
        }
        let state = Arc::new(state);
        let (definition, target) = prepared(&fixture, &state).await?;
        let control = AnalysisReadControl::default();
        let mut stream = stream(&fixture, definition, target, &control)?;
        let mut next = Box::pin(stream.next());
        tokio::select! {
            result = &mut next => return Err(format!("managed step ended before barrier: {:?}", result).into()),
            entered = observed => entered?,
        }
        control.cancel()?;
        assert!(next.as_mut().now_or_never().is_none());
        drop(next);
        let mut joined = Box::pin(stream.cancel_and_join());
        assert!(joined.as_mut().now_or_never().is_none());
        assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(30), joined).await??;
        assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
        released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn count_delivery_is_prepaid() -> TestResult {
    let required = 8 + crate::stream::Output::count_bytes(true)?;
    for capacity in [required - 1, required] {
        let fixture = Fixture::limits(Limits {
            output_capacity: Some(capacity),
            ..Default::default()
        })?;
        fixture.event(1)?;
        let state = Arc::new(SinkState::default());
        let (definition, target) = prepared(&fixture, &state).await?;
        let control = AnalysisReadControl::default();
        let mut stream = stream(&fixture, definition, target, &control)?;
        let result = stream.next().await.ok_or("managed count update")?;
        if capacity < required {
            assert!(result.is_err());
            assert_eq!(state.admissions.load(Ordering::SeqCst), 0);
            assert_eq!(state.entries.load(Ordering::SeqCst), 0);
            assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
        } else {
            let update = result?;
            assert_eq!(state.commits.load(Ordering::SeqCst), 1);
            assert_eq!(
                update.batches.as_ref().ok_or("native count absent")?.len(),
                1
            );
            drop(update);
        }
        stream.cancel_and_join().await?;
        drop(state.receipt.lock().unwrap().take());
        drop(fixture.engine.memory().reserve_output(capacity)?);
    }
    Ok(())
}

#[tokio::test]
async fn scope_check_precedes_capture() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let mut target = (*target).clone();
    target.managed.as_mut().unwrap().grant.selection =
        AnalysisSelectionV1::new([1; 16], Vec::new());
    let control = AnalysisReadControl::default();
    let mut stream = stream(&fixture, definition, Arc::new(target), &control)?;
    let error = stream
        .next()
        .await
        .ok_or("scope error absent")?
        .err()
        .ok_or("scope accepted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(state.entries.load(Ordering::SeqCst), 0);
    stream.cancel_and_join().await?;
    released(&fixture)
}

#[tokio::test]
async fn window_keeps_full_grant() -> TestResult {
    let fixture = fixture().await?;
    let definition = fixture.prepare(&Fixture::sql(
        "SELECT source_cursor AS value FROM events WHERE received_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds'",
    )).await?;
    let full = AnalysisSelectionV1::tenant([1; 16]);
    let instance = fixture.managed(&definition, full.clone())?;
    let state = Arc::new(SinkState::default());
    let target = Arc::new(Sink {
        schema: Arc::clone(definition.plan.schema().inner()),
        calls: Vec::new(),
        state: Arc::clone(&state),
        managed: Some(instance),
    });
    let control = AnalysisReadControl::default();
    let mut stream = Subscription::managed(
        fixture.engine.session(full.clone(), &control, 0)?,
        definition,
        target,
        b"managed-test",
        None,
        ResumeClock::new(NOW, None),
    )?;
    let update = stream.next().await.ok_or("window update")??;
    let received = NOW - 1_000_000 + 1;
    let expiry = received / 1000 * 1000 + 60_000_000_000;
    assert_eq!(update.snapshot.received_min, Some(received));
    assert_eq!(update.snapshot.next_change, Some(expiry));
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("window frontier")?;
    assert_eq!(frontier.next_change, Some(expiry));
    assert_eq!(frontier.cursor, update.cursor.encode()?);
    assert_eq!(
        update
            .snapshot
            .managed()
            .ok_or("window state")?
            .instance()
            .grant
            .selection,
        full
    );
    assert_ne!(update.snapshot.selection, full);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    stream.cancel_and_join().await?;
    drop(update);
    drop(state.receipt.lock().unwrap().take());
    released(&fixture)
}

#[tokio::test]
async fn capture_limits_precede_admission() -> TestResult {
    for configured in [true, false] {
        let mut limits = if configured {
            Limits {
                input_bytes: 1,
                ..Default::default()
            }
        } else {
            Limits {
                input_capacity: Some(1),
                ..Default::default()
            }
        };
        let mut fixture = Fixture::new()?;
        if !configured {
            let admitted = fixture
                .prepare(&Fixture::sql("SELECT source_cursor AS value FROM events"))
                .await?;
            let retained = fixture.engine.memory().input_reserved();
            assert!(retained > 0);
            limits.input_capacity = Some(retained.checked_add(1).ok_or("admission capacity")?);
            drop(admitted);
            assert_eq!(fixture.engine.memory().input_reserved(), 0);
        }
        fixture.engine = Engine::new(Arc::clone(fixture.engine.store()), limits)?;
        fixture.event(1)?;
        let state = Arc::new(SinkState::default());
        let (definition, target) = prepared(&fixture, &state).await?;
        let control = AnalysisReadControl::default();
        let mut stream = stream(&fixture, definition, target, &control)?;
        let error = stream
            .next()
            .await
            .ok_or("input quota failure")?
            .err()
            .ok_or("input quota accepted")?;
        assert!(matches!(
            crate::Failure::from(&error),
            crate::Failure::InputTooLarge | crate::Failure::Busy
        ));
        assert_eq!(state.admissions.load(Ordering::SeqCst), 0);
        assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
        stream.cancel_and_join().await?;
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        if !configured {
            let capacity = fixture.engine.limits().input_capacity.ok_or("input pool")?;
            drop(fixture.engine.memory().reserve_input(capacity)?);
        }
    }
    Ok(())
}

struct ResumeClock {
    now: u64,
    reads: AtomicUsize,
    idle: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl ResumeClock {
    fn new(now: u64, idle: Option<tokio::sync::oneshot::Sender<()>>) -> Arc<Self> {
        Arc::new(Self {
            now,
            reads: AtomicUsize::new(0),
            idle: Mutex::new(idle),
            changes: tokio::sync::watch::channel(0).0,
        })
    }
}

impl crate::follow::Clock for ResumeClock {
    fn now_ns(&self) -> crate::Result<u64> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            if let Some(idle) = self.idle.lock().unwrap().take() {
                let _sent = idle.send(());
            }
        }
        Ok(self.now)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_keeps_cut_idle() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let update = first.next().await.ok_or("initial managed update")??;
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("prospective frontier")?;
    assert_eq!(update.cursor.encode()?, frontier.cursor);
    let original_time = update.evaluated_utc_ns;
    drop(update);
    first.cancel_and_join().await?;
    drop(state.receipt.lock().unwrap().take());
    let retained = fixture.engine.memory().input_reserved();
    let capacity = fixture
        .engine
        .limits()
        .input_capacity
        .ok_or("input capacity")?;
    let pressure = fixture.engine.memory().reserve_input(capacity - retained)?;
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    let inputs = state.input_evaluations.load(Ordering::SeqCst);
    let (idle, observed) = tokio::sync::oneshot::channel();
    let clock = ResumeClock::new(original_time + 1, Some(idle));
    let control = AnalysisReadControl::default();
    let mut resumed = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier),
        clock,
    )?;
    let mut next = Box::pin(resumed.next());
    tokio::select! {
        update = &mut next => return Err(format!("unchanged resume executed: {update:?}").into()),
        observed = observed => observed?,
    }
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(state.input_evaluations.load(Ordering::SeqCst), inputs);
    assert_eq!(fixture.engine.memory().input_reserved(), capacity);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(pressure);
    fixture.event(2)?;
    let update = tokio::time::timeout(Duration::from_secs(30), next)
        .await?
        .ok_or("changed resumed update")??;
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    assert!(state.input_evaluations.load(Ordering::SeqCst) > inputs);
    assert_eq!(
        update.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    resumed.cancel_and_join().await?;
    drop(update);
    drop(state.receipt.lock().unwrap().take());
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_restart_cancellation_joins() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let update = first.next().await.ok_or("initial idle receipt")??;
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("idle frontier")?;
    let now = update.evaluated_utc_ns + 1;
    drop(update);
    first.cancel_and_join().await?;
    drop(state.receipt.lock().unwrap().take());
    let retained = fixture.engine.memory().input_reserved();
    let capacity = fixture
        .engine
        .limits()
        .input_capacity
        .ok_or("input capacity")?;
    let pressure = fixture.engine.memory().reserve_input(capacity - retained)?;
    let (idle, observed) = tokio::sync::oneshot::channel();
    let control = AnalysisReadControl::default();
    let mut resumed = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier),
        ResumeClock::new(now, Some(idle)),
    )?;
    let mut next = Box::pin(resumed.next());
    tokio::select! {
        update = &mut next => return Err(format!("idle restart executed: {update:?}").into()),
        observed = observed => observed?,
    }
    assert_eq!(fixture.engine.memory().input_reserved(), capacity);
    drop(next);
    tokio::time::timeout(Duration::from_secs(30), resumed.cancel_and_join()).await??;
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.engine.memory().input_reserved(),
        capacity - retained
    );
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(pressure);
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_keeps_source_notice() -> TestResult {
    let fixture = fixture().await?;
    let (release, held) = mpsc::channel();
    release.send(())?;
    let state = Arc::new(SinkState {
        begin_gate: Some(WriterGate {
            entered: Mutex::new(None),
            release: Mutex::new(held),
        }),
        ..Default::default()
    });
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let update = first.next().await.ok_or("initial source receipt")??;
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("source frontier")?;
    let now = update.evaluated_utc_ns + 1;
    drop(update);
    first.cancel_and_join().await?;
    let (entered, observed) = tokio::sync::oneshot::channel();
    *state
        .begin_gate
        .as_ref()
        .ok_or("begin gate")?
        .entered
        .lock()
        .unwrap() = Some(entered);
    let control = AnalysisReadControl::default();
    let mut resumed = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier),
        ResumeClock::new(now, None),
    )?;
    let mut next = Box::pin(resumed.next());
    tokio::select! {
        update = &mut next => return Err(format!("restart bypassed begin: {update:?}").into()),
        entered = observed => entered?,
    }
    fixture.event(2)?;
    release.send(())?;
    let update = tokio::time::timeout(Duration::from_secs(30), next)
        .await?
        .ok_or("source notice receipt")??;
    assert_eq!(state.begins.load(Ordering::SeqCst), 2);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    assert_eq!(
        update.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    resumed.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn rebuild_bypasses_idle_resume() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let initial = first.next().await.ok_or("initial rebuild receipt")??;
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("rebuild frontier")?;
    let now = initial.evaluated_utc_ns + 1;
    let revision = initial.cursor.read_revision();
    drop(initial);
    first.cancel_and_join().await?;
    let inputs = state.input_evaluations.load(Ordering::SeqCst);
    state.rebuild.store(true, Ordering::SeqCst);
    let control = AnalysisReadControl::default();
    let mut rebuilt = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier),
        ResumeClock::new(now, None),
    )?;
    let update = tokio::time::timeout(Duration::from_secs(30), rebuilt.next())
        .await?
        .ok_or("rebuilt update")??;
    assert_eq!(update.cursor.read_revision(), revision);
    assert_eq!(update.evaluated_utc_ns, now);
    assert_eq!(
        update.snapshot.managed().map(|managed| managed.rebuild()),
        Some(true)
    );
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    assert!(state.input_evaluations.load(Ordering::SeqCst) > inputs);
    assert_eq!(
        update.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    rebuilt.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn expired_resume_deadline_executes() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let update = first.next().await.ok_or("initial deadline update")??;
    let now = update.evaluated_utc_ns + 1;
    drop(update);
    first.cancel_and_join().await?;
    let mut frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("saved frontier")?;
    frontier.next_change = Some(now);
    let control = AnalysisReadControl::default();
    let mut resumed = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier),
        ResumeClock::new(now, None),
    )?;
    let update = tokio::time::timeout(Duration::from_secs(30), resumed.next())
        .await?
        .ok_or("expired frontier update")??;
    assert_eq!(update.evaluated_utc_ns, now);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    resumed.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn resumed_frontier_checks_binding() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (definition, target) = prepared(&fixture, &state).await?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    drop(first.next().await.ok_or("binding initial update")??);
    first.cancel_and_join().await?;
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("binding saved frontier")?;
    let control = AnalysisReadControl::default();
    let result = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"different-binding",
        Some(frontier),
        ResumeClock::new(123, None),
    );
    assert!(matches!(
        result,
        Err(crate::Error::Invalid {
            field: "cursor binding",
            ..
        })
    ));
    assert_eq!(state.begins.load(Ordering::SeqCst), 1);
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_offer_keeps_cut_idle() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let (mut definition, target) = prepared(&fixture, &state).await?;
    let failure = AtomicBool::new(true);
    let gate = create_udf(
        "failed_offer_input",
        vec![sdk::DataType::UInt64],
        sdk::DataType::UInt64,
        Volatility::Volatile,
        Arc::new(move |arguments| {
            if failure.swap(false, Ordering::SeqCst) {
                return Err(DataFusionError::Execution("known failed offer".into()));
            }
            arguments
                .first()
                .cloned()
                .ok_or_else(|| DataFusionError::Execution("failed offer input absent".into()))
        }),
    );
    definition.plan = LogicalPlanBuilder::from(definition.plan)
        .project(vec![gate.call(vec![col("value")]).alias("value")])?
        .build()?;
    let control = AnalysisReadControl::default();
    let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
    let error = tokio::time::timeout(Duration::from_secs(30), first.next())
        .await?
        .ok_or("failed offer result")?
        .err()
        .ok_or("failed offer published")?;
    assert!(format!("{error:?}").contains("known failed offer"));
    let frontier = state
        .frontier
        .lock()
        .unwrap()
        .clone()
        .ok_or("failed native frontier")?;
    first.cancel_and_join().await?;
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    let inputs = state.input_evaluations.load(Ordering::SeqCst);
    let now = crate::follow::Cursor::decode(&frontier.cursor)?.evaluated() + 1;
    let (idle, observed) = tokio::sync::oneshot::channel();
    let clock = ResumeClock::new(now, Some(idle));
    let control = AnalysisReadControl::default();
    let mut resumed = Subscription::managed(
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, 0)?,
        definition,
        target,
        b"managed-test",
        Some(frontier.clone()),
        clock,
    )?;
    let mut next = Box::pin(resumed.next());
    tokio::select! {
        update = &mut next => return Err(format!("unchanged failed cut executed: {update:?}").into()),
        observed = observed => observed?,
    }
    assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.input_evaluations.load(Ordering::SeqCst), inputs);
    assert_eq!(state.frontier.lock().unwrap().as_ref(), Some(&frontier));
    fixture.event(2)?;
    let update = tokio::time::timeout(Duration::from_secs(30), next)
        .await?
        .ok_or("changed failed cut update")??;
    assert_eq!(state.admissions.load(Ordering::SeqCst), 2);
    assert_eq!(state.entries.load(Ordering::SeqCst), 2);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert!(state.input_evaluations.load(Ordering::SeqCst) > inputs);
    assert_eq!(
        update.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    resumed.cancel_and_join().await?;
    drop(update);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_admission_keeps_capture_cut() -> TestResult {
    for (related, invalidated) in [(true, false), (false, false), (true, true), (false, true)] {
        let fixture = fixture().await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, held) = mpsc::channel();
        let state = Arc::new(SinkState {
            admission_gate: Some(WriterGate {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(held),
            }),
            admission_error: Mutex::new(Some(crate::Error::Data {
                source: if invalidated {
                    araphor_data::Error::AnalysisSourceChanged {
                        location: snafu::location!(),
                    }
                } else {
                    araphor_data::Error::AnalysisConflict {
                        location: snafu::location!(),
                    }
                },
            })),
            ..Default::default()
        });
        let (definition, target) = prepared(&fixture, &state).await?;
        let control = AnalysisReadControl::default();
        let mut first = stream(&fixture, definition.clone(), Arc::clone(&target), &control)?;
        let mut next = Box::pin(first.next());
        tokio::select! {
            result = &mut next => return Err(format!("stale admission ended before capture: {result:?}").into()),
            observed = observed => observed?,
        }
        let captured = state
            .frontier
            .lock()
            .unwrap()
            .clone()
            .ok_or("stale capture cut")?;
        let captured = crate::follow::Cursor::decode(&captured.cursor)?.read_revision();
        assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
        if related {
            fixture.event(2)?;
            fixture.context(1)?;
        } else {
            let mut foreign = fixture
                .engine
                .store()
                .source_page([1; 16], None)?
                .pop()
                .ok_or("captured source identity")?;
            let frame = fixture
                .engine
                .store()
                .read_page(&foreign, 1)?
                .records
                .remove(0)
                .framed_record;
            foreign.tenant_id = [2; 16];
            fixture.engine.store().accept_validated_batch(
                foreign,
                araphor_data::ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: NOW,
                    frame_ends: vec![frame.len()],
                    framed_records: frame.into(),
                },
            )?;
            let (_, revision) = fixture.engine.store().dependency_revision_for(
                &AnalysisSelectionV1::tenant([1; 16]),
                &[("events".to_owned(), None)].into_iter().collect(),
                &control,
            )?;
            assert!(revision <= captured);
        }
        assert!(fixture.engine.store().meta()?.commit_revision > captured);
        release.send(())?;
        let error = tokio::time::timeout(Duration::from_secs(30), next)
            .await?
            .ok_or("stale admission result")?
            .err()
            .ok_or("stale admission published")?;
        let mut source: &(dyn std::error::Error + 'static) = &error;
        loop {
            if matches!(
                (source.downcast_ref::<crate::Error>(), invalidated),
                (
                    Some(crate::Error::Data {
                        source: araphor_data::Error::AnalysisConflict { .. }
                    }),
                    false
                ) | (
                    Some(crate::Error::Data {
                        source: araphor_data::Error::AnalysisSourceChanged { .. }
                    }),
                    true
                )
            ) {
                break;
            }
            source = source.source().ok_or("stale source conflict lost")?;
        }
        assert_eq!(
            erebor_runtime_error::ErrorExt::status_code(&error),
            erebor_runtime_error::StatusCode::AlreadyExists,
        );
        first.cancel_and_join().await?;
        assert_eq!(state.admissions.load(Ordering::SeqCst), 0);
        assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        let recovery =
            crate::follow::SourceRecovery::take(&error).ok_or("stale admission recovery absent")?;
        assert!(crate::follow::SourceRecovery::take(&error).is_none());
        tokio::time::timeout(
            Duration::from_secs(30),
            recovery.changed(&AnalysisReadControl::default()),
        )
        .await??;
        let mut resumed = stream(
            &fixture,
            definition,
            target,
            &AnalysisReadControl::default(),
        )?;
        release.send(())?;
        let update = tokio::time::timeout(Duration::from_secs(30), resumed.next())
            .await?
            .ok_or("recovered admission update")??;
        assert_eq!(
            update.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            if related { 2 } else { 1 }
        );
        assert_eq!(state.admissions.load(Ordering::SeqCst), 1);
        assert_eq!(state.entries.load(Ordering::SeqCst), 1);
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        resumed.cancel_and_join().await?;
        drop(update);
        drop(state.receipt.lock().unwrap().take());
        released(&fixture)?;
    }
    Ok(())
}
