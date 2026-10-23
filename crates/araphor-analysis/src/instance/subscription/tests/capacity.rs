use super::*;
use std::sync::mpsc;

const INPUT: usize = 128 * 1024 * 1024;
const OUTPUT: usize = 8 * 1024 * 1024;

struct Cleanup {
    controls: Vec<Arc<AnalysisReadControl>>,
    release: Option<mpsc::Sender<()>>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for control in &self.controls {
            let _cancelled = control.cancel();
        }
        if let Some(release) = self.release.take() {
            let _released = release.send(());
        }
    }
}

async fn occupied_step(
    fixture: &Fixture,
    healthy: &Arc<Instance>,
    mut occupying: Subscription,
    mut waiting: Subscription,
    step: u64,
    cancel_waiter: bool,
) -> TestResult<Option<Subscription>> {
    let control = AnalysisReadControl::default();
    let occupying_control = Arc::clone(&occupying.control);
    let waiting_control = Arc::clone(&waiting.control);
    let state = Arc::clone(&waiting.state);
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture.query.guest_entry(entered, Some(released))?;
    let mut cleanup = Cleanup {
        controls: vec![Arc::clone(&occupying_control), Arc::clone(&waiting_control)],
        release: Some(release),
    };
    let occupied = tokio::spawn(async move {
        let result = occupying.next().await;
        (occupying, result)
    });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await??;
    let mut changes = fixture.query.store().subscribe_revision();
    changes.borrow_and_update();
    let mut offered = tokio::spawn(async move {
        let result = waiting.next().await;
        (waiting, result)
    });
    tokio::select! {
        result = &mut offered => return Err(format!("occupied slot did not retain the offer: {:?}", result.map(|(_, update)| update)).into()),
        changed = changes.changed() => changed?,
    }
    // The held guest uses one worker. This barrier runs after admission releases the other worker.
    Engine::blocking(Arc::new(AnalysisReadControl::default()), (), || Ok(())).await?;
    let attempt = state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("waiting original attempt")?;
    let original = attempt.request().clone();
    let before = attempt.instance().clone();
    assert!(original.frontier.is_some());
    assert!(!offered.is_finished());
    let saved = fixture
        .query
        .store()
        .managed_attempt([1; 16], "waiting-slot", &original.id, &control)?
        .ok_or("waiting durable attempt")?;
    assert_eq!(saved.request(), &original);
    assert!(saved.receipt().is_none());
    assert!(saved.terminal().is_none());
    let run = araphor_data::ManagedRequest {
        id: format!("healthy-{step}"),
        time_utc_ns: 10,
        seed: Some(7),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    };
    let healthy_run = healthy.run(run, &control);
    tokio::pin!(healthy_run);
    let receipt = tokio::select! {
        result = &mut offered => return Err(format!("occupied offer ended during healthy work: {:?}", result.map(|(_, update)| update)).into()),
        result = tokio::time::timeout(Duration::from_secs(30), &mut healthy_run) => {
            result.map_err(|error| format!("healthy SQL did not finish: {error}"))??
        },
    };
    assert_eq!(fixture.selected("healthy-slot", &receipt.attempt)?, [17]);
    assert!(!offered.is_finished());
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "waiting-slot", &control)?
        .ok_or("waiting instance")?;
    assert_eq!(current, before);
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt
            .as_ref()
            .ok_or("retained original claim")?
            .request(),
        &original
    );
    assert!(fixture
        .query
        .store()
        .managed_selected([1; 16], "waiting-slot", &original.id, &control)?
        .is_none());

    let waiting = if cancel_waiter {
        waiting_control.cancel()?;
        let (waiting, result) = tokio::time::timeout(Duration::from_secs(30), offered)
            .await
            .map_err(|error| format!("cancelled waiter did not join: {error}"))??;
        let error = result
            .ok_or("cancelled waiter ended")?
            .err()
            .ok_or("cancelled waiter published")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::Cancelled
        );
        let terminal = waiting
            .cancel_and_join(&control)
            .await?
            .ok_or("waiting cancellation terminal")?;
        assert_eq!(terminal.exit, ManagedExit::Cancelled);
        assert_eq!(terminal.attempt, original.id);
        assert_eq!(fixture.progress("waiting-slot")?, before.progress);
        assert!(!occupied.is_finished());
        None
    } else {
        Some(offered)
    };
    occupying_control.cancel()?;
    cleanup
        .release
        .take()
        .ok_or("occupying release")?
        .send(())?;
    let (occupying, result) = tokio::time::timeout(Duration::from_secs(30), occupied)
        .await
        .map_err(|error| format!("occupying guest did not join: {error}"))??;
    assert!(result.ok_or("occupying stream ended")?.is_err());
    let terminal = occupying
        .cancel_and_join(&control)
        .await?
        .ok_or("occupying terminal")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    let Some(waiting) = waiting else {
        return Ok(None);
    };
    let (waiting, result) = tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .map_err(|error| format!("released waiter did not finish: {error}"))??;
    let receipt = result.ok_or("released offer ended")??;
    assert_eq!(receipt.attempt, original.id);
    assert_eq!(receipt.frontier, original.frontier);
    assert_eq!(
        fixture.selected("waiting-slot", &receipt.attempt)?,
        [original.time_utc_ns]
    );
    assert_eq!(receipt.results.len(), 1);
    let retained = fixture
        .query
        .store()
        .managed_attempt([1; 16], "waiting-slot", &original.id, &control)?
        .ok_or("committed original attempt")?;
    assert_eq!(retained.request(), &original);
    assert_eq!(retained.receipt(), Some(&receipt));
    assert!(retained.terminal().is_none());
    cleanup.controls.pop();
    Ok(Some(waiting))
}

fn run_case(cancel_waiter: bool) -> TestResult {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()?
        .block_on(async {
            let mut limits = araphor_query::execution::Limits {
                input_capacity: Some(INPUT),
                output_capacity: Some(OUTPUT),
                output_bytes: 1024 * 1024,
                ..Default::default()
            };
            limits.package.wasm.evaluations = Some(1);
            let fixture = Fixture::new(limits)?;
            let query = Arc::clone(&fixture.query);
            {
                let (occupier, first) = fixture.terminal_stream("occupied-slot", "cancel").await?;
                let (_, stream) = fixture.terminal_stream("waiting-slot", "clock").await?;
                let mut waiting = Some(stream);
                let healthy = fixture
                    .admit(
                        "healthy-slot",
                        "SELECT CAST(17 AS BIGINT UNSIGNED) AS value",
                    )
                    .await?;
                let lifecycle = fixture
                    .query
                    .store()
                    .managed_instance([1; 16], "occupied-slot", &AnalysisReadControl::default())?
                    .ok_or("occupier lifecycle")?
                    .lifecycle;
                let mut occupying = Some(first);
                for step in 1..=if cancel_waiter { 1 } else { 2 } {
                    if step > 1 {
                        fixture.context(step)?;
                        occupying = Some(occupier.subscribe(
                            Arc::new(AnalysisReadControl::default()),
                            u64::MAX,
                            lifecycle,
                        )?);
                    }
                    waiting = occupied_step(
                        &fixture,
                        &healthy,
                        occupying.take().ok_or("occupying stream")?,
                        waiting.take().ok_or("waiting stream")?,
                        step,
                        cancel_waiter,
                    )
                    .await?;
                    if waiting.is_none() {
                        break;
                    }
                }
                if let Some(waiting) = waiting {
                    assert!(waiting
                        .cancel_and_join(&AnalysisReadControl::default())
                        .await?
                        .is_none());
                }
            }
            drop(fixture);
            drop(query.reserve_evaluation([1; 16])?);
            drop(query.memory().reserve_input(INPUT)?);
            drop(query.memory().reserve_output(OUTPUT)?);
            Ok(())
        })
}

#[test]
fn slot_wait_keeps_capture_and_progresses() -> TestResult {
    run_case(false)
}

#[test]
fn slot_wait_cancellation_joins() -> TestResult {
    run_case(true)
}
