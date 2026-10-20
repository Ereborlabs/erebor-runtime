use super::*;
use araphor_data::AnalysisSelectionV1;
use futures_util::StreamExt as _;
use sdk::arrow_array::{Array as _, UInt64Array};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;

const NOW: u64 = 1_700_000_000_123_456_789;

struct Clock {
    time: AtomicU64,
    changes: watch::Sender<u64>,
}

impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            time: AtomicU64::new(NOW),
            changes: watch::channel(0).0,
        })
    }

    fn set(&self, time: u64) {
        self.time.store(time, Ordering::SeqCst);
        self.changes.send_replace(time);
    }
}

impl crate::follow::Clock for Clock {
    fn now_ns(&self) -> crate::Result<u64> {
        Ok(self.time.load(Ordering::SeqCst))
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

impl Fixture {
    fn follow(
        &self,
        prepared: &PreparedDefinition,
        clock: Arc<Clock>,
    ) -> crate::Result<crate::follow::Subscription> {
        crate::follow::Subscription::new(
            self.engine.session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                NOW,
            )?,
            Arc::new(prepared.plan.clone()),
            prepared.sources().clone(),
            prepared.resolved().sql.as_bytes(),
            None,
            clock,
            true,
        )
    }
}

async fn next(stream: &mut crate::follow::Subscription) -> TestResult<crate::follow::Update> {
    tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or_else(|| "subscription stopped".into())
        .and_then(|result| result.map_err(Into::into))
}

fn values(batches: &[sdk::RecordBatch]) -> TestResult<Vec<u64>> {
    batches
        .iter()
        .map(|batch| {
            let values = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 output required")?;
            assert_eq!(values.null_count(), 0);
            Ok(values.values().to_vec())
        })
        .collect::<TestResult<Vec<_>>>()
        .map(|chunks| chunks.into_iter().flatten().collect())
}

#[tokio::test]
async fn call_ids_survive_readmission() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let definition = Fixture::sql(
        r#"SELECT a.value, b.value AS other FROM
        "fixture"."r1".count(source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2) a
        CROSS JOIN "fixture"."r1".count(source => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value), increment => 3) b"#,
    );
    let ids = |prepared: &PreparedDefinition| -> TestResult<Vec<u64>> {
        Ok(Fixture::calls(&prepared.plan)?
            .iter()
            .map(PackageCall::id)
            .collect())
    };
    let first = fixture.prepare(&definition).await?;
    let _unrelated = fixture.prepare(&Fixture::definition()).await?;
    let second = fixture.prepare(&definition).await?;
    assert_eq!(ids(&first)?, ids(&second)?);
    assert_eq!(ids(&first)?.len(), 2);
    assert_ne!(ids(&first)?[0], ids(&first)?[1]);
    Ok(())
}

#[tokio::test]
async fn package_follow_retains_each_call() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    fixture.event(1)?;
    fixture.context(1)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(source => (
        SELECT source_cursor AS value FROM events
        WHERE EXISTS (SELECT 1 FROM context_versions)), increment => 2)"#,
        ))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let before = fixture.engine.store().meta()?;
    let mut stream = fixture.follow(&prepared, Clock::new())?;
    let first = next(&mut stream).await?;
    assert_eq!(
        values(first.batches.as_deref().ok_or("initial output absent")?)?,
        [3]
    );
    assert_eq!(first.calls.len(), 1);
    let old = &first.calls[&id];
    assert_eq!(old.output().evidence.len(), 1);
    assert_eq!(old.output().reasons.len(), 1);
    assert!(old.output().checkpoint.is_some());
    assert!(futures_util::poll!(stream.next()).is_pending());
    assert_eq!(fixture.engine.store().meta()?, before);
    fixture.context(2)?;
    let unchanged = next(&mut stream).await?;
    assert!(unchanged.batches.is_none());
    assert_eq!(unchanged.calls.len(), 1);
    assert!(!Arc::ptr_eq(old, &unchanged.calls[&id]));
    fixture.event(2)?;
    let changed = next(&mut stream).await?;
    let mut output = values(changed.batches.as_deref().ok_or("changed output absent")?)?;
    output.sort_unstable();
    assert_eq!(output, [3, 4]);
    assert_eq!(changed.calls[&id].output().evidence.len(), 2);
    assert_eq!(
        changed.calls[&id].evaluation().context.time_utc_ns,
        NOW as i64
    );
    assert!(!Arc::ptr_eq(old, &changed.calls[&id]));
    assert_eq!(values(&old.output().datasets[0].batches)?, [3]);
    stream.cancel()?;
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn package_window_expires_without_intake() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    fixture.event(1)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(source => (
        SELECT source_cursor AS value FROM events
        WHERE received_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds'), increment => 2)"#,
        ))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let clock = Clock::new();
    let mut stream = fixture.follow(&prepared, Arc::clone(&clock))?;
    let first = next(&mut stream).await?;
    assert_eq!(
        values(first.batches.as_deref().ok_or("initial output absent")?)?,
        [3]
    );
    let before = fixture.engine.store().meta()?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    clock.set(NOW + 61_000_000_000);
    let expired = next(&mut stream).await?;
    assert!(expired.clock_changed);
    assert_eq!(expired.calls.len(), 1);
    assert!(values(&expired.calls[&id].output().datasets[0].batches)?.is_empty());
    assert_eq!(
        expired.calls[&id].evaluation().context.time_utc_ns,
        (NOW + 61_000_000_000) as i64
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    Ok(())
}
