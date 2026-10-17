use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_data::AnalysisReadControl;
use tokio::sync::watch;

use super::{Fixture, Limits, TestClock};
use crate::follow::{Clock, Progress, Wake};

struct ContextClock {
    inner: Arc<TestClock>,
    notice: Mutex<Option<watch::Sender<u64>>>,
}

impl Clock for ContextClock {
    fn now_ns(&self) -> crate::Result<u64> {
        if let Some(context) = self.notice.lock().unwrap().take() {
            context.send_replace(1);
        }
        self.inner.now_ns()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes()
    }
}

async fn wake(
    progress: &mut Progress,
    control: &AnalysisReadControl,
    deadline: Option<u64>,
) -> Wake {
    tokio::time::timeout(
        Duration::from_secs(1),
        progress.next(control, deadline, None),
    )
    .await
    .expect("progress wait timed out")
    .expect("progress wait failed")
}

#[tokio::test]
async fn progress_context_wakes_idle() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let (context, receiver) = watch::channel(0);
    let mut progress = Progress::new(&fixture.store, clock, Some(receiver));
    let control = AnalysisReadControl::default();
    let revision = fixture.store.meta().unwrap().commit_revision;
    assert_eq!(progress.begin().unwrap(), 10);
    {
        let waiting = progress.next(&control, None, None);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        context.send_replace(1);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap(),
            Wake::Source
        ));
    }
    assert!(!progress.pending());
    assert_eq!(fixture.store.meta().unwrap().commit_revision, revision);
}

#[tokio::test]
async fn progress_keeps_context_during_capture() {
    let fixture = Fixture::new(Limits::default());
    let (context, receiver) = watch::channel(0);
    let clock = Arc::new(ContextClock {
        inner: TestClock::new(10),
        notice: Mutex::new(Some(context.clone())),
    });
    let mut progress = Progress::new(&fixture.store, clock, Some(receiver));
    let control = AnalysisReadControl::default();
    let revision = fixture.store.meta().unwrap().commit_revision;
    assert_eq!(progress.begin().unwrap(), 10);
    progress.captured(revision, None);
    assert!(progress.pending());
    assert!(matches!(
        wake(&mut progress, &control, None).await,
        Wake::Source
    ));
    assert!(!progress.pending());

    assert_eq!(progress.begin().unwrap(), 10);
    context.send_replace(2);
    progress.captured(revision, None);
    assert!(progress.pending());
    assert!(matches!(
        wake(&mut progress, &control, None).await,
        Wake::Source
    ));
    assert!(!progress.pending());
}

#[tokio::test]
async fn progress_preserves_concurrent_notices() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let (context, receiver) = watch::channel(0);
    let mut progress = Progress::new(&fixture.store, clock.clone(), Some(receiver));
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    fixture.commit(&fixture.source, 1, 1, 10);
    context.send_replace(1);
    clock.set(20);

    let first = wake(&mut progress, &control, None).await;
    let second = wake(&mut progress, &control, None).await;
    assert!(matches!(
        (first, second),
        (Wake::Clock, Wake::Source) | (Wake::Source, Wake::Clock)
    ));
    assert!(!progress.pending());
    assert!(!progress.clock_pending());
    {
        let waiting = progress.next(&control, None, None);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        context.send_replace(2);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap(),
            Wake::Source
        ));
    }
    assert!(!progress.pending());
}

#[tokio::test]
async fn progress_closed_context_is_explicit() {
    let fixture = Fixture::new(Limits::default());
    let (context, receiver) = watch::channel(0);
    let mut progress = Progress::new(&fixture.store, TestClock::new(10), Some(receiver));
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    drop(context);
    let error = tokio::time::timeout(Duration::from_secs(1), progress.next(&control, None, None))
        .await
        .unwrap()
        .err()
        .expect("closed context watch returned a wake");
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Incomplete,
                field: "context progress",
                ..
            }
        }
    ));
}

#[tokio::test]
async fn progress_without_context_waits_for_input() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let mut progress = Progress::new(&fixture.store, clock.clone(), None);
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    let waiting = progress.next(&control, None, None);
    tokio::pin!(waiting);
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    let reads = clock.reads.load(Ordering::SeqCst);
    clock.now.store(10_000_000_000, Ordering::SeqCst);
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    control.cancel().unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .err()
        .expect("cancelled progress returned a wake");
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        }
    ));
}

#[tokio::test]
async fn progress_context_keeps_deadline_consumed() {
    let fixture = Fixture::new(Limits::default());
    let (context, receiver) = watch::channel(0);
    let mut progress = Progress::new(&fixture.store, TestClock::new(10), Some(receiver));
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    progress.captured(fixture.store.meta().unwrap().commit_revision, Some(10));
    assert!(matches!(
        wake(&mut progress, &control, Some(10)).await,
        Wake::Clock
    ));
    context.send_replace(1);
    assert!(matches!(
        wake(&mut progress, &control, Some(10)).await,
        Wake::Source
    ));
    assert_eq!(progress.begin().unwrap(), 10);
    let waiting = progress.next(&control, Some(10), None);
    tokio::pin!(waiting);
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    context.send_replace(2);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap(),
        Wake::Source
    ));
}
