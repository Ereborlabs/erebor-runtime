use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisStore,
    ContextSensitivityV1, Selection,
};
use tokio::sync::watch;

use super::{Fixture, Limits, TestClock};
use crate::follow::{Clock, Progress, Wake};

struct ContextClock {
    inner: Arc<TestClock>,
    store: Arc<AnalysisStore>,
    notice: Mutex<Option<AnalysisContextVersionV1>>,
}

impl Clock for ContextClock {
    fn now_ns(&self) -> crate::Result<u64> {
        if let Some(context) = self.notice.lock().unwrap().take() {
            self.store.commit_context(&context).unwrap();
        }
        self.inner.now_ns()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes()
    }
}

fn context(revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "progress-test".into(),
            entity_key: b"input".to_vec(),
            lifetime_key: b"test".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"{}".to_vec(),
    }
}

async fn progress(fixture: &Fixture, clock: Arc<dyn Clock>) -> Progress {
    let (plan, sources) = fixture.plan("SELECT owner_id FROM context_versions", Vec::new());
    let mut selection = fixture.selection();
    selection.contexts = Selection::All;
    let session = Arc::new(
        fixture
            .engine
            .session(selection, &AnalysisReadControl::default(), 0)
            .unwrap(),
    );
    let physical = session
        .physical(&plan, &session.state().unwrap())
        .await
        .unwrap();
    let run = Arc::new(crate::stream::Run {
        session,
        sources,
        plan,
        clock,
        follow: true,
        operation: crate::follow::Operation::Replace,
        window: None,
        resume: None,
        binding: [0; 32],
        resume_expiry: None,
        resume_pending: false,
        managed: None,
    });
    let mut progress = Progress::new(run);
    progress.bind(&physical).await.unwrap();
    progress
}

async fn wake(
    progress: &mut Progress,
    control: &AnalysisReadControl,
    deadline: Option<u64>,
) -> Wake {
    tokio::time::timeout(Duration::from_secs(1), progress.next(control, deadline))
        .await
        .expect("progress wait timed out")
        .expect("progress wait failed")
}

#[tokio::test]
async fn progress_context_wakes_idle() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let mut progress = progress(&fixture, clock).await;
    let control = AnalysisReadControl::default();
    let revision = progress.source_position();
    assert_eq!(progress.begin().unwrap(), 10);
    {
        let waiting = progress.next(&control, None);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        fixture.store.commit_context(&context(1)).unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap(),
            Wake::Source
        ));
    }
    progress.captured(progress.source_position(), None);
    assert_eq!(progress.observed(), progress.source_position());
    assert!(fixture.store.meta().unwrap().commit_revision > revision.commit_revision);
}

#[tokio::test]
async fn progress_keeps_context_during_capture() {
    let fixture = Fixture::new(Limits::default());
    let clock = Arc::new(ContextClock {
        inner: TestClock::new(10),
        store: Arc::clone(&fixture.store),
        notice: Mutex::new(Some(context(1))),
    });
    let mut progress = progress(&fixture, clock).await;
    let control = AnalysisReadControl::default();
    let revision = progress.source_position();
    assert_eq!(progress.begin().unwrap(), 10);
    progress.captured(revision, None);
    assert!(progress.source_position() > revision);
    assert!(matches!(
        wake(&mut progress, &control, None).await,
        Wake::Source
    ));
    progress.captured(progress.source_position(), None);
    assert_eq!(progress.observed(), progress.source_position());

    assert_eq!(progress.begin().unwrap(), 10);
    fixture.store.commit_context(&context(2)).unwrap();
    progress.captured(revision, None);
    assert!(progress.source_position() > revision);
    assert!(matches!(
        wake(&mut progress, &control, None).await,
        Wake::Source
    ));
    progress.captured(progress.source_position(), None);
    assert_eq!(progress.observed(), progress.source_position());
}

#[tokio::test]
async fn progress_preserves_concurrent_notices() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let mut progress = progress(&fixture, clock.clone()).await;
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    fixture.commit(&fixture.source, 1, 1, 10);
    fixture.store.commit_context(&context(1)).unwrap();
    clock.set(20);

    let first = wake(&mut progress, &control, None).await;
    let second = wake(&mut progress, &control, None).await;
    assert!(matches!(
        (first, second),
        (Wake::Clock, Wake::Source) | (Wake::Source, Wake::Clock)
    ));
    progress.captured(progress.source_position(), None);
    assert_eq!(progress.observed(), progress.source_position());
    assert!(!progress.clock_pending());
    {
        let waiting = progress.next(&control, None);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        fixture.store.commit_context(&context(2)).unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap(),
            Wake::Source
        ));
    }
    progress.captured(progress.source_position(), None);
    assert_eq!(progress.observed(), progress.source_position());
}

#[tokio::test]
async fn progress_idle_waits_for_input() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(10);
    let mut progress = progress(&fixture, clock.clone()).await;
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    let waiting = progress.next(&control, None);
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
    let mut progress = progress(&fixture, TestClock::new(10)).await;
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    progress.captured(progress.source_position(), Some(10));
    assert!(matches!(
        wake(&mut progress, &control, Some(10)).await,
        Wake::Clock
    ));
    fixture.store.commit_context(&context(1)).unwrap();
    assert!(matches!(
        wake(&mut progress, &control, Some(10)).await,
        Wake::Source
    ));
    assert_eq!(progress.begin().unwrap(), 10);
    let after = progress.source_position();
    let waiting = progress.next_after(&control, after, Some(10));
    tokio::pin!(waiting);
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    fixture.store.commit_context(&context(2)).unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap(),
        Wake::Source
    ));
}

struct ClosedClock;

impl Clock for ClosedClock {
    fn now_ns(&self) -> crate::Result<u64> {
        Ok(10)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        watch::channel(0).1
    }
}

#[tokio::test]
async fn progress_clock_closure_fails() {
    let fixture = Fixture::new(Limits::default());
    let mut progress = progress(&fixture, Arc::new(ClosedClock)).await;
    let control = AnalysisReadControl::default();
    progress.begin().unwrap();
    progress.captured(progress.source_position(), Some(10_000_000_000));
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        progress.next(&control, Some(10_000_000_000)),
    )
    .await
    .unwrap()
    .err()
    .expect("closed required clock watch returned a wake");
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Incomplete,
                field: "clock progress",
                ..
            }
        }
    ));
    control.check().unwrap();
}
