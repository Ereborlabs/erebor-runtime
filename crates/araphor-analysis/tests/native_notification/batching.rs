use super::*;

struct BatchSink {
    sink: Sink,
    keys: Vec<NotificationKeyV1>,
    before: u64,
}

impl BatchSink {
    fn new(store: Arc<NativeStore>, states: &[NotificationObligationV1]) -> TestResult<Self> {
        Ok(Self {
            before: store.view()?.revision(),
            sink: Sink::new(store),
            keys: states.iter().map(|state| state.key).collect(),
        })
    }

    fn pending(&self, request: &NotificationDeliveryV1) -> TestResult {
        let offset = match request.kind {
            NotificationDeliveryKindV1::Finding => 1,
            NotificationDeliveryKindV1::FailureEscalation => 2,
            NotificationDeliveryKindV1::AcknowledgementEscalation => 3,
        };
        assert_eq!(self.sink.store.view()?.revision(), self.before + offset);
        for key in &self.keys {
            let state = Fixture::state(&self.sink.store, *key)?;
            let attempt = state
                .attempts
                .iter()
                .find(|attempt| attempt.kind == request.kind)
                .ok_or("batch pending attempt")?;
            assert!(attempt.result.is_none());
            if offset > 1 {
                assert!(state.attempts[0].result.is_some());
            }
        }
        Ok(())
    }
}

impl NotificationSink for BatchSink {
    fn deliver(&self, request: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        if let Err(error) = self.pending(request) {
            std::panic::resume_unwind(Box::new(error.to_string()));
        }
        self.sink.deliver(request)
    }
}

impl Fixture {
    fn subjects(router: &NotificationRouter) -> TestResult<Vec<NotificationObligationV1>> {
        (1..=3)
            .map(|id| {
                let mut concern = Self::concern();
                concern.concern_id = [id; 16];
                Ok(router.submit_concern(
                    &Self::grant(NotificationPrincipalV1::Agent),
                    "primary",
                    concern,
                    100,
                )?)
            })
            .collect()
    }
}

#[tokio::test]
async fn native_batch_delivery() -> TestResult {
    for (failure, now) in [(false, 100), (true, 100), (true, 200)] {
        let fixture = Fixture::new()?;
        let router = fixture.router()?;
        Fixture::configure(&router)?;
        let subjects = Fixture::subjects(&router)?;
        let (subscription, update) = fixture.update_at(now).await?;
        let sink = BatchSink::new(fixture.store.clone(), &subjects)?;
        sink.sink.fail.store(failure, Ordering::Release);
        let output = router.consume(&update, &sink)?;
        assert!(output.routed.is_empty());
        assert_eq!(output.delivered.len(), 3);
        let count = if now == 200 {
            3
        } else if failure {
            2
        } else {
            1
        };
        for (_, result) in output.delivered {
            assert_eq!(result.map_err(|error| error.to_string())?, count);
        }
        assert_eq!(
            fixture.store.view()?.revision(),
            sink.before + count as u64 + 1
        );
        assert_eq!(
            sink.sink.calls.lock().map_err(|_| "sink lock")?.len(),
            3 * count
        );
        let mut completed = Vec::new();
        for subject in &subjects {
            let state = Fixture::state(&fixture.store, subject.key)?;
            assert_eq!(state.attempts.len(), count);
            assert!(state
                .attempts
                .iter()
                .all(|attempt| attempt.result.is_some()));
            let historical = fixture
                .store
                .context_version(&Fixture::key(subject))?
                .ok_or("historical subject")?;
            assert_eq!(NotificationObligationV1::try_from(&historical)?, *subject);
            completed.push(state);
        }
        subscription.cancel_and_join().await?;
        drop((router, sink, update));
        let fixture = fixture.reopen()?;
        for state in completed {
            assert_eq!(Fixture::state(&fixture.store, state.key)?, state);
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_batch_conflict() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let subjects = Fixture::subjects(&router)?;
    let (subscription, update) = fixture.update().await?;
    let mut competing = subjects[1].clone();
    competing.revision += 1;
    competing.advisory = None;
    *fixture
        .authority
        .competing
        .lock()
        .map_err(|_| "authority lock")? = Some((
        AnalysisContextVersionV1 {
            key: Fixture::key(&competing),
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: competing.sensitivity,
            body: competing.encode()?,
        },
        subjects[1].revision,
    ));
    let sink = Sink::new(fixture.store.clone());
    let before = fixture.store.view()?.revision();
    assert!(router.consume(&update, &sink).is_err());
    assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
    assert_eq!(fixture.store.view()?.revision(), before + 1);
    for subject in &subjects {
        let expected = if subject.key == competing.key {
            &competing
        } else {
            subject
        };
        assert_eq!(Fixture::state(&fixture.store, subject.key)?, *expected);
        assert!(fixture
            .store
            .context_version(&AnalysisContextKeyV1 {
                owner_revision: expected.revision + 1,
                ..Fixture::key(expected)
            })?
            .is_none());
    }
    subscription.cancel_and_join().await?;
    drop((router, sink, update));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, competing.key)?, competing);
    Ok(())
}

#[tokio::test]
async fn native_batch_interruption() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let subjects = Fixture::subjects(&router)?;
    let (subscription, update) = fixture.update().await?;
    let sink = BatchSink::new(fixture.store.clone(), &subjects)?;
    sink.sink.interrupt.store(true, Ordering::Release);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        router.consume(&update, &sink)
    }));
    assert!(interrupted.is_err());
    let first = sink.sink.calls.lock().map_err(|_| "sink lock")?[0].clone();
    let pending = subjects
        .iter()
        .map(|subject| Fixture::state(&fixture.store, subject.key))
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(fixture.store.view()?.revision(), sink.before + 1);
    for state in &pending {
        assert_eq!(state.attempts.len(), 1);
        assert_eq!(state.attempts[0].number, 1);
        assert_eq!(state.attempts[0].context_revision, 1);
        assert!(state.attempts[0].result.is_none());
    }
    subscription.cancel_and_join().await?;
    drop((router, sink, update));
    let fixture = fixture.reopen()?;
    for state in pending {
        assert_eq!(Fixture::state(&fixture.store, state.key)?, state);
    }
    let router = fixture.router()?;
    let (subscription, update) = fixture.update().await?;
    let sink = Sink::new(fixture.store.clone());
    let before = fixture.store.view()?.revision();
    let output = router.consume(&update, &sink)?;
    assert_eq!(output.delivered.len(), 3);
    assert!(output
        .delivered
        .iter()
        .all(|(_, result)| result.as_ref().is_ok_and(|count| *count == 1)));
    assert_eq!(fixture.store.view()?.revision(), before + 1);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls.iter().find(|call| call.key == first.key),
        Some(&first)
    );
    assert!(calls.iter().all(|call| call.attempt == 1));
    drop(calls);
    subscription.cancel_and_join().await?;
    Ok(())
}
