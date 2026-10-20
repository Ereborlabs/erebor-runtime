use super::*;
use araphor_data::PackageReadinessV1 as Readiness;

#[tokio::test]
async fn status_inspect_keeps_failure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (instance, _) = historical(&fixture, "history").await?;
    let store = fixture.query.store();
    let stored = store
        .managed_instance([1; 16], "history", &AnalysisReadControl::default())?
        .ok_or("stored instance")?;
    let running =
        store.set_managed_running([1; 16], "history", stored.lifecycle, true, || Ok(()))?;
    let stopped = store.suspend_managed(&running, || Ok(()))?;
    let mut expired = instance.admitted().spec.clone();
    expired.id = "expired-writer".into();
    expired.grant.expires_utc_ns = Some(1);
    let admitted = store.admit_managed(&expired, || Ok(()))?;
    let running =
        store.set_managed_running([1; 16], &expired.id, admitted.lifecycle, true, || Ok(()))?;
    store.suspend_managed(&running, || Ok(()))?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    fixture.authority.set(false);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    store.fault_write("UPDATE managed_arrow SET ipc = 'invalid'::BLOB", &[])?;
    store.fault_write(
        "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
        &[],
    )?;
    let before = store.meta()?;
    for name in ["history", "expired-writer"] {
        let status = Instance::read_status(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            name,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(
            matches!(status.readiness, Readiness::Failed { code: Code::Denied, ref field } if field == "model evaluation")
        );
        assert_eq!(status.status_progress, status.instance.progress);
        assert!(!status.instance.running);
        if name == "history" {
            assert_eq!(status.instance, stopped);
            assert!(status.status_progress > 0);
        } else {
            assert_eq!(status.instance.spec.grant.expires_utc_ns, Some(1));
            assert_eq!(status.status_progress, 0);
        }
    }
    assert_eq!(reader.checks.load(Ordering::SeqCst), 4);
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[tokio::test]
async fn status_inspect_binds_reader() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.admit("history", "SELECT 1").await?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    for case in 0..6 {
        let mut grant = reader.grant.clone();
        let mut authority = Arc::clone(&reader);
        let mut name = "history";
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
            4 => name = "missing",
            _ => grant.expires_utc_ns = Some(1),
        }
        let error = Instance::read_status(
            Arc::clone(&fixture.query),
            authority,
            grant,
            name,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("unauthorized status")?;
        let expected = if case == 3 || case == 4 {
            Code::Missing
        } else {
            Code::Denied
        };
        assert!(
            matches!(error, crate::Error::Data { source: araphor_data::Error::Package { code, .. } } | crate::Error::Query { source: araphor_query::Error::Data { source: araphor_data::Error::Package { code, .. } } } if code == expected),
            "case {case}: {error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn status_inspect_checks_disclosure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.admit("history", "SELECT 1").await?;
    let mut reader = Reader::new(fixture.grant.clone());
    reader.deny_at = 2;
    let reader = Arc::new(reader);
    let before = fixture.query.store().meta()?;
    let error = Instance::read_status(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("denied status disclosed")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                ..
            }
        }
    ));
    assert_eq!(reader.checks.load(Ordering::SeqCst), 2);
    let control = AnalysisReadControl::default();
    control.cancel()?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    assert!(Instance::read_status(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &control
    )
    .await
    .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
