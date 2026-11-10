use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn operation_cancel_preserves_parent() -> TestResult {
    let parent = AnalysisReadControl::default();
    let operation = parent.operation()?;
    operation.cancel()?;
    assert!(matches!(operation.check(), Err(crate::Error::AnalysisReadCancelled { .. })));
    parent.check()?;
    let next = parent.operation()?;
    parent.cancel()?;
    next.cancelled().await;
    assert!(matches!(next.check(), Err(crate::Error::AnalysisReadCancelled { .. })));
    Ok(())
}

#[tokio::test]
async fn query_cancellation_releases_wait() -> TestResult {
    let control = Arc::new(AnalysisReadControl::default());
    let pending = Arc::clone(&control);
    let task = tokio::spawn(async move {
        pending.query_async::<(), crate::Error>(std::future::pending()).await
    });
    control.cancel()?;
    assert!(matches!(task.await?, Err(crate::Error::AnalysisReadCancelled { .. })));
    Ok(())
}

#[test]
fn optional_deadlines_and_locks() -> TestResult {
    let parent = AnalysisReadControl::with_timeout(Duration::from_secs(1))?;
    assert!(parent.within(None)?.remaining()?.is_some());
    assert!(parent.within(Duration::from_secs(2))?.remaining()? <= parent.remaining()?);
    assert!(AnalysisReadControl::with_timeout(Duration::ZERO).is_err());
    let lock = WaitMutex::new(7);
    assert_eq!(*lock.until(&parent)?, 7);
    parent.cancel()?;
    assert!(matches!(lock.until(&parent), Err(crate::Error::AnalysisReadCancelled { .. })));
    Ok(())
}
