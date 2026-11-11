use super::*;
use araphor_query::follow::Cursor;

async fn ordinary(
    engine: &Arc<Engine>,
    resume: Option<Cursor>,
) -> araphor_query::Result<Subscription> {
    engine
        .subscribe(
            "SELECT source_cursor AS value FROM events",
            Vec::new(),
            AnalysisSelectionV1::tenant(TENANT),
            Arc::new(AnalysisReadControl::default()),
            b"ordinary-resume",
            resume,
            Arc::new(SystemClock::default()),
            true,
        )
        .await
}

fn span(store: &NativeStore, count: u64) -> TestResult {
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for cursor in 1..=count {
        bytes.extend(Vec::<u8>::try_from(&EvidenceRecord {
            task_cookie: cursor,
            observed_boottime_ns: cursor,
            ..Default::default()
        })?);
        ends.push(bytes.len());
    }
    store.accept_validated_batch(
        source(TENANT),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: count,
            intake_utc_ns: NOW + 1,
            frame_ends: ends,
            framed_records: bytes.into(),
        },
    )?;
    Ok(())
}

#[tokio::test]
async fn resume_replays_offline_input() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    let mut stream = ordinary(&engine, None).await?;
    let first = next(&mut stream).await?;
    assert_eq!(
        values(first.batches.as_ref().ok_or("initial rows")?)?,
        vec![1]
    );
    let cursor = first.cursor.clone();
    stream.cancel_and_join().await?;
    event(&store, TENANT, 2)?;
    let mut stream = ordinary(&engine, Some(cursor)).await?;
    let resumed = next(&mut stream).await?;
    assert_eq!(
        values(resumed.batches.as_ref().ok_or("resumed rows")?)?,
        vec![2]
    );
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn resume_keeps_partial_span() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(
        store.clone(),
        Limits {
            output_rows: 2,
            ..Limits::default()
        },
    )?;
    span(&store, 5)?;
    store.commit_context(&context("unrelated", 1))?;
    let mut stream = ordinary(&engine, None).await?;
    let first = next(&mut stream).await?;
    assert_eq!(
        values(first.batches.as_ref().ok_or("first page")?)?,
        vec![1, 2]
    );
    assert_eq!(first.cursor.position().ordinal, 1);
    assert!(first.cursor.read_revision() > first.cursor.position().commit_revision);
    assert!(!first.exhausted);
    let cursor = first.cursor.clone();
    stream.cancel_and_join().await?;
    let mut stream = ordinary(&engine, Some(cursor)).await?;
    let second = next(&mut stream).await?;
    let third = next(&mut stream).await?;
    assert_eq!(
        values(second.batches.as_ref().ok_or("second page")?)?,
        vec![3, 4]
    );
    assert_eq!(
        values(third.batches.as_ref().ok_or("third page")?)?,
        vec![5]
    );
    assert!(third.exhausted);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), stream.next())
            .await
            .is_err()
    );
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn resume_ignores_unmatched_input() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    let mut stream = ordinary(&engine, None).await?;
    let first = next(&mut stream).await?;
    let cursor = first.cursor.clone();
    stream.cancel_and_join().await?;
    event(&store, [9; 16], 1)?;
    store.commit_context(&context("unrelated", 1))?;
    let mut stream = ordinary(&engine, Some(cursor)).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), stream.next())
            .await
            .is_err()
    );
    event(&store, TENANT, 2)?;
    let resumed = next(&mut stream).await?;
    assert_eq!(
        values(resumed.batches.as_ref().ok_or("matched rows")?)?,
        vec![2]
    );
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn resume_reports_expired_log() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_context(&context("unrelated", 1))?;
    let mut stream = ordinary(&engine, None).await?;
    let first = next(&mut stream).await?;
    let cursor = first.cursor.clone();
    stream.cancel_and_join().await?;
    store.checkpoint()?;
    store.database().inner().rotate_journal()?;
    event(&store, TENANT, 2)?;
    store.commit_context(&context("unrelated", 2))?;
    store.checkpoint()?;
    let historical = store.read_at(cursor.read_revision())?;
    assert!(historical.context(&context("unrelated", 1).key)?.is_some());
    assert!(historical.snapshot().cursor()?.is_none());
    let anchor = if cursor.position().ordinal == u32::MAX {
        cursor.position().commit_revision
    } else {
        cursor.position().commit_revision.saturating_sub(1)
    };
    assert!(store.read_at(anchor)?.snapshot().cursor()?.is_none());
    let mut stream = ordinary(&engine, Some(cursor)).await?;
    let error = match tokio::time::timeout(Duration::from_secs(10), stream.next()).await? {
        Some(Err(error)) => error,
        _ => return Err("expired resume did not fail".into()),
    };
    assert_eq!(
        araphor_query::Failure::from(&error),
        araphor_query::Failure::CursorExpired
    );
    stream.cancel_and_join().await?;
    let mut fresh = ordinary(&engine, None).await?;
    let update = next(&mut fresh).await?;
    assert_eq!(
        values(update.batches.as_ref().ok_or("fresh rows")?)?,
        vec![1, 2]
    );
    fresh.cancel_and_join().await?;
    Ok(())
}
