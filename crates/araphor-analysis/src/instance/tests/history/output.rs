use super::*;

#[tokio::test]
async fn raw_output_checks_scope() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (_, receipt) = historical(&fixture, "history").await?;
    fixture.admit("foreign", "SELECT 1").await?;
    let id = &receipt.results.values().next().ok_or("result")?.result_id;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    fixture.authority.set(false);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let before = fixture.query.store().meta()?;
    let araphor_data::PackageResponseV1::Result(output) = Instance::read_output(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        id,
        &AnalysisReadControl::default(),
    )
    .await?
    else {
        return Err("package output variant".into());
    };
    assert_eq!(output.context.context.id, "first");
    assert!(!output.current);
    assert_eq!(output.output.evidence.len(), 1);
    assert_eq!(output.output.reasons.len(), 1);
    assert_eq!(
        output
            .output
            .checkpoint
            .as_ref()
            .ok_or("checkpoint")?
            .version,
        1
    );
    for case in 0..6 {
        let mut grant = reader.grant.clone();
        let mut authority = Arc::clone(&reader);
        let mut instance = "history";
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
            4 => instance = "foreign",
            _ => grant.expires_utc_ns = Some(1),
        }
        let error = Instance::read_output(
            Arc::clone(&fixture.query),
            authority,
            grant,
            instance,
            id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("unauthorized raw output")?;
        let expected = if case == 3 {
            Code::Missing
        } else {
            Code::Denied
        };
        assert!(
            matches!(error, crate::Error::Data { source: araphor_data::Error::Package {code,..} } | crate::Error::Query { source: araphor_query::Error::Data {source: araphor_data::Error::Package {code,..}} } if code == expected),
            "case {case}: {error:?}"
        );
    }
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn raw_output_checks_disclosure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (_, receipt) = historical(&fixture, "history").await?;
    for id in [
        &receipt.results.values().next().ok_or("result")?.result_id,
        &receipt.selected.result_id,
    ] {
        let before = fixture.query.store().meta()?;
        let mut reader = Reader::new(fixture.grant.clone());
        reader.deny_at = 2;
        let reader = Arc::new(reader);
        let error = Instance::read_output(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("denied raw disclosure succeeded")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::PermissionDenied
        );
        assert_eq!(reader.checks.load(Ordering::SeqCst), 2);
        let reader = Arc::new(Reader::new(fixture.grant.clone()));
        reader.announce.store(true, Ordering::SeqCst);
        Instance::read_output(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            id,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(reader.checks.load(Ordering::SeqCst) >= 3);
        reader.announce.store(true, Ordering::SeqCst);
        reader.revoke.store(true, Ordering::SeqCst);
        let parent = AnalysisReadControl::default();
        let error = Instance::read_output(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            id,
            &parent,
        )
        .await
        .err()
        .ok_or("raw authority event ignored")?;
        parent.check()?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::PermissionDenied
        );
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        let reader = Arc::new(Reader::new(fixture.grant.clone()));
        let error = Instance::read_output(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            id,
            &cancelled,
        )
        .await
        .err()
        .ok_or("cancelled raw read succeeded")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::Cancelled
        );
        assert_eq!(fixture.query.store().meta()?, before);
    }
    Ok(())
}
