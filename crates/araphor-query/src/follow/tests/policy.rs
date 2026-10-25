use super::*;

use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{mpsc, Mutex};

use datafusion::execution::memory_pool::MemoryReservation;
use tokio::sync::oneshot;

struct Cleanup {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    _memory: Arc<MemoryReservation>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(entered) = self
            .entered
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _sent = entered.send(());
        }
        let _released = self
            .release
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .recv_timeout(Duration::from_secs(8));
    }
}

fn fixture() -> Fixture {
    let fixture = Fixture::new(Limits {
        global_streams: Some(1),
        tenant_streams: Some(1),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 1);
    fixture
}

fn subscribe(fixture: &Fixture, parent: &AnalysisReadControl, follow: bool) -> Subscription {
    let (plan, sources) = fixture.plan("SELECT source_cursor FROM events", vec![]);
    Subscription::new(
        fixture
            .engine
            .session(fixture.selection(), &parent.operation().unwrap(), 0)
            .unwrap(),
        plan,
        sources,
        b"checked policy",
        None,
        TestClock::new(1),
        follow,
    )
    .unwrap()
}

fn released(fixture: &Fixture) {
    let memory = fixture.engine.memory();
    assert_eq!(memory.input_reserved(), 0);
    drop(
        memory
            .reserve_input(fixture.engine.limits().input_capacity.unwrap())
            .unwrap(),
    );
    drop(
        memory
            .reserve_output(fixture.engine.limits().output_capacity.unwrap())
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .reserve_stream(fixture.source.tenant_id)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
}

#[tokio::test]
async fn benign_notice_keeps_capture() {
    let fixture = fixture();
    let clock = TestClock::new(1);
    let mut stream = fixture.subscribe(
        "SELECT source_cursor FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut stream).await;
    assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(1))]);
    let cursor = first.cursor.clone();
    let revision = fixture.store.meta().unwrap();
    let checks = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&checks);
    let (entry, entered) = oneshot::channel();
    let entry = Mutex::new(Some(entry));
    let (changes, changed) = watch::channel(0);
    let mut stream = stream.until_checked(changed, move |control| {
        control.check()?;
        observed.fetch_add(1, Ordering::SeqCst);
        entry.lock().unwrap().take().unwrap().send(()).unwrap();
        Ok(())
    });
    assert_eq!(checks.load(Ordering::SeqCst), 0);
    {
        let waiting = stream.next();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        let reads = clock.reads.load(Ordering::SeqCst);
        changes.send_replace(1);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        tokio::time::timeout(Duration::from_secs(8), entered)
            .await
            .unwrap()
            .unwrap();
        assert!(futures_util::poll!(&mut waiting).is_pending());
        assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    }
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.meta().unwrap(), revision);
    assert_eq!(first.cursor, cursor);
    assert!(stream.session.control().check().is_ok());
    fixture.commit(&fixture.source, 2, 1, 2);
    let second = next(&mut stream).await;
    assert_eq!(values(&second, 0), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    drop((first, second));
    stream.cancel_and_join().await.unwrap();
    released(&fixture);
}

#[tokio::test]
async fn rejected_notice_stops_stream() {
    for closed in [false, true] {
        let fixture = fixture();
        let parent = AnalysisReadControl::default();
        let mut stream = subscribe(&fixture, &parent, true);
        drop(next(&mut stream).await);
        let checks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&checks);
        let (changes, changed) = watch::channel(0);
        let mut stream = stream.until_checked(changed, move |control| {
            control.check()?;
            observed.fetch_add(1, Ordering::SeqCst);
            Err(araphor_data::PackageErrorCodeV1::Denied
                .error("policy fixture rejected")
                .into())
        });
        if closed {
            drop(changes);
        } else {
            changes.send_replace(1);
        }
        let error = tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, crate::Error::AuthorityChanged { .. }));
        assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
        assert_eq!(checks.load(Ordering::SeqCst), usize::from(!closed));
        assert!(stream.next().await.is_none());
        assert!(parent.check().is_ok());
        stream.cancel_and_join().await.unwrap();
        released(&fixture);
    }
}

#[tokio::test]
async fn checker_end_keeps_cleanup() {
    for ending in ["eof", "cancel", "drop"] {
        let fixture = fixture();
        let parent = AnalysisReadControl::default();
        let mut stream = subscribe(&fixture, &parent, ending != "eof");
        drop(next(&mut stream).await);
        let (eof, ended) = oneshot::channel();
        if ending == "eof" {
            let inner =
                std::mem::replace(&mut stream.stream, Box::pin(futures_util::stream::empty()));
            stream.stream = futures_util::stream::unfold(
                (inner, Some(ended)),
                |(mut inner, ended)| async move {
                    match inner.next().await {
                        Some(item) => Some((item, (inner, ended))),
                        None => {
                            ended.unwrap().await.unwrap();
                            None
                        }
                    }
                },
            )
            .boxed();
        }
        let workers = stream.workers.clone();
        let control = Arc::clone(stream.session.control());
        let claim = Arc::new(fixture.engine.memory().reserve_input(1024).unwrap());
        let retained = Arc::downgrade(&claim);
        let (cleanup, cleaned) = oneshot::channel();
        let (release_cleanup, cleanup_release) = mpsc::channel();
        let cleanup = Cleanup {
            entered: Mutex::new(Some(cleanup)),
            release: Mutex::new(cleanup_release),
            _memory: claim,
        };
        let (entry, entered) = oneshot::channel();
        let entry = Mutex::new(Some(entry));
        let (release, body_release) = mpsc::channel();
        let body_release = Mutex::new(body_release);
        let (changes, changed) = watch::channel(0);
        let mut stream = stream.until_checked(changed, move |control| {
            let _cleanup = &cleanup;
            assert!(entry
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(control.within(None)?)
                .is_ok());
            body_release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(8))
                .unwrap();
            control.check()?;
            Ok(())
        });
        changes.send_replace(1);
        let child = {
            let waiting = stream.next();
            tokio::pin!(waiting);
            assert!(futures_util::poll!(&mut waiting).is_pending());
            tokio::time::timeout(Duration::from_secs(8), entered)
                .await
                .unwrap()
                .unwrap()
        };
        let complete: Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send>> =
            match ending {
                "eof" => {
                    eof.send(()).unwrap();
                    Box::pin(async move {
                        assert!(stream.next().await.is_none());
                        assert!(stream.session.control().check().is_ok());
                        Ok(())
                    })
                }
                "cancel" => Box::pin(stream.cancel_and_join()),
                "drop" => {
                    drop(stream);
                    workers.close();
                    Box::pin(async move {
                        workers.wait().await;
                        Ok(())
                    })
                }
                _ => unreachable!(),
            };
        tokio::pin!(complete);
        assert!(futures_util::poll!(&mut complete).is_pending(), "{ending}");
        assert!(child.check().is_err(), "{ending}");
        assert_eq!(control.check().is_ok(), ending == "eof");
        assert!(parent.check().is_ok(), "{ending}");
        assert!(retained.upgrade().is_some(), "{ending}");
        assert!(fixture.engine.memory().input_reserved() >= 1024, "{ending}");
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(8), cleaned)
            .await
            .unwrap()
            .unwrap();
        assert!(futures_util::poll!(&mut complete).is_pending(), "{ending}");
        assert!(retained.upgrade().is_some(), "{ending}");
        assert!(fixture.engine.memory().input_reserved() >= 1024, "{ending}");
        release_cleanup.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(8), complete)
            .await
            .unwrap()
            .unwrap();
        assert!(retained.upgrade().is_none(), "{ending}");
        assert!(parent.check().is_ok(), "{ending}");
        released(&fixture);
    }
}
