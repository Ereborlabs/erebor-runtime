use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::{ControlStore, IntakeClock};
use araphor_data::{
    AnalysisCommitStage, AnalysisStore, RetentionLimitsV1, ValidatedEvidenceBatchV1,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct RetentionClock {
    started: tokio::time::Instant,
    reads: AtomicU64,
}

impl IntakeClock for RetentionClock {
    fn now(&self) -> SystemTime {
        self.reads.fetch_add(1, Ordering::Relaxed);
        UNIX_EPOCH + Duration::from_nanos(100) + self.started.elapsed()
    }
}

impl RetentionClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: tokio::time::Instant::now(),
            reads: AtomicU64::new(0),
        })
    }
}

async fn assert_idle(checks: &mut watch::Receiver<()>, clock: &RetentionClock) {
    let reads = clock.reads.load(Ordering::Relaxed);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), checks.changed())
            .await
            .is_err()
    );
    assert_eq!(clock.reads.load(Ordering::Relaxed), reads);
}

fn append(data: &AnalysisStore) -> araphor_data::Result<()> {
    data.accept_validated_batch(
        identity(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: vec![7].into(),
            frame_ends: vec![1],
        },
    )?;
    Ok(())
}

#[tokio::test]
async fn retention_disabled_stays_idle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let clock = RetentionClock::new();
    let owner = EvidenceIntakeOwner::new(
        ControlStore::open(directory.path().join("control"))?,
        data.clone(),
        clock.clone(),
    )?;
    let mut worker = tokio::spawn(async move { owner.run_retention().await });
    append(&data)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut worker)
            .await
            .is_err()
    );
    assert_eq!(clock.reads.load(Ordering::Relaxed), 0);
    assert_eq!(data.read_page(&identity(), 1)?.records.len(), 1);
    assert!(data.retention_healthy());
    worker.abort();
    assert!(worker.await.err().is_some_and(|error| error.is_cancelled()));
    Ok(())
}

#[tokio::test]
async fn retention_waits_for_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let data = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        RetentionLimitsV1 {
            raw_max_age_ns: Some(60_000_000_000),
            ..Default::default()
        },
        Default::default(),
    )?);
    append(&data)?;
    let clock = RetentionClock::new();
    let (send, mut checks) = watch::channel(());
    let mut owner = EvidenceIntakeOwner::new(
        ControlStore::open(directory.path().join("control"))?,
        data.clone(),
        clock.clone(),
    )?;
    owner.retention_checks = Some(send);
    let worker = tokio::spawn(async move { owner.run_retention().await });
    tokio::time::timeout(Duration::from_secs(5), checks.changed()).await??;
    assert_eq!(data.read_page(&identity(), 1)?.records.len(), 1);
    assert_idle(&mut checks, &clock).await;
    let mut changes = data.subscribe_revision();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), changes.changed()).await??;
    tokio::time::timeout(Duration::from_secs(5), checks.changed()).await??;
    assert!(matches!(
        data.read_page(&identity(), 1),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert!(data.retention_healthy());
    assert_idle(&mut checks, &clock).await;
    worker.abort();
    assert!(worker.await.err().is_some_and(|error| error.is_cancelled()));
    Ok(())
}

#[tokio::test]
async fn retention_waits_for_repair() -> TestResult {
    let directory = tempfile::tempdir()?;
    let data = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        RetentionLimitsV1 {
            raw_max_age_ns: Some(0),
            ..Default::default()
        },
        Default::default(),
    )?);
    append(&data)?;
    let before = data.meta()?;
    let reject = Arc::new(AtomicBool::new(true));
    let gate = reject.clone();
    data.set_commit_hook(AnalysisCommitStage::BeforeRetentionCommit, move || {
        if gate.load(Ordering::Acquire) {
            return Err(araphor_data::Error::StorageCapacity {
                resource: "retention repair fixture",
                location: snafu::Location::default(),
            });
        }
        Ok(())
    })?;
    let clock = RetentionClock::new();
    let (send, mut checks) = watch::channel(());
    let mut owner = EvidenceIntakeOwner::new(
        ControlStore::open(directory.path().join("control"))?,
        data.clone(),
        clock.clone(),
    )?;
    owner.retention_checks = Some(send);
    let worker = tokio::spawn(async move { owner.run_retention().await });
    tokio::time::timeout(Duration::from_secs(5), checks.changed()).await??;
    assert!(!data.retention_healthy());
    assert_eq!(data.meta()?, before);
    assert_idle(&mut checks, &clock).await;
    reject.store(false, Ordering::Release);
    data.recover()?;
    tokio::time::timeout(Duration::from_secs(5), checks.changed()).await??;
    assert!(data.retention_healthy());
    assert!(matches!(
        data.read_page(&identity(), 1),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
    assert_idle(&mut checks, &clock).await;
    worker.abort();
    assert!(worker.await.err().is_some_and(|error| error.is_cancelled()));
    Ok(())
}
