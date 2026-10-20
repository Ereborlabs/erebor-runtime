use super::*;

#[tokio::test]
async fn history_reads_original_receipts() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (instance, first) = historical(&fixture, "history").await?;
    assert_eq!(
        instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    fixture.authority.set(false);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let before = fixture.query.store().meta()?;
    let history = Instance::read_history(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0], first);
    assert_eq!(history[1].attempt, "second");
    assert_eq!(history[1].commit_revision, fixture.progress("history")?);
    assert!(history.iter().all(|receipt| receipt.results.len() == 2));
    for case in 0..6 {
        let mut grant = reader.grant.clone();
        let mut authority = Arc::clone(&reader);
        let mut id = "history";
        match case {
            0 => grant.principal = "other-reader".into(),
            1 => grant.authorization_id = Some("other-session".into()),
            2 => {
                grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
                authority = Arc::new(Reader::new(grant.clone()));
            }
            3 => {
                grant.selection = AnalysisSelectionV1::tenant([2; 16]);
                authority = Arc::new(Reader::new(grant.clone()));
            }
            4 => id = "missing",
            _ => grant.expires_utc_ns = Some(1),
        }
        let error = Instance::read_history(
            Arc::clone(&fixture.query),
            authority,
            grant,
            id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("unauthorized history returned")?;
        assert_eq!(
            error.status_code(),
            if matches!(case, 3 | 4) {
                erebor_runtime_error::StatusCode::NotFound
            } else {
                erebor_runtime_error::StatusCode::PermissionDenied
            }
        );
    }
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn history_checks_final_disclosure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    historical(&fixture, "history").await?;
    let before = fixture.query.store().meta()?;
    let mut reader = Reader::new(fixture.grant.clone());
    reader.deny_at = 2;
    let reader = Arc::new(reader);
    let parent = AnalysisReadControl::default();
    let error = Instance::read_history(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &parent,
    )
    .await
    .err()
    .ok_or("denied history disclosure succeeded")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(reader.checks.load(Ordering::SeqCst), 2);
    parent.check()?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    reader.announce.store(true, Ordering::SeqCst);
    assert_eq!(
        Instance::read_history(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            &parent
        )
        .await?
        .len(),
        2
    );
    assert!(reader.checks.load(Ordering::SeqCst) >= 3);
    reader.announce.store(true, Ordering::SeqCst);
    reader.revoke.store(true, Ordering::SeqCst);
    let error = Instance::read_history(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &parent,
    )
    .await
    .err()
    .ok_or("history revocation ignored")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    parent.check()?;
    parent.cancel()?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let error = Instance::read_history(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &parent,
    )
    .await
    .err()
    .ok_or("cancelled history returned")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::Cancelled
    );
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
