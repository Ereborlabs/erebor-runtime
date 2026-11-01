use std::sync::atomic::AtomicUsize;

use super::*;

mod freshness;
mod output;
mod receipts;
mod selected;
mod status;

struct Reader {
    grant: PackageGrantV1,
    allowed: AtomicBool,
    checks: AtomicUsize,
    deny_at: usize,
    announce: AtomicBool,
    revoke: AtomicBool,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Reader {
    fn new(mut grant: PackageGrantV1) -> Self {
        grant.principal = "historical-reader".into();
        grant.authorization_id = Some("reader-session".into());
        Self {
            grant,
            allowed: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
            deny_at: usize::MAX,
            announce: AtomicBool::new(false),
            revoke: AtomicBool::new(false),
            changes: tokio::sync::watch::channel(0).0,
        }
    }
}

impl PackageAuthorization for Reader {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        grant.remaining()?;
        let check = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if action != PackageActionV1::Inspect
            || grant != &self.grant
            || !self.allowed.load(Ordering::SeqCst)
            || check >= self.deny_at
        {
            return Err(Code::Denied.error("historical reader authority"));
        }
        if self.announce.swap(false, Ordering::SeqCst) {
            if self.revoke.load(Ordering::SeqCst) {
                self.allowed.store(false, Ordering::SeqCst);
            }
            self.changes.send_modify(|revision| *revision += 1);
        }
        Ok(())
    }

    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        Err(Code::Denied.error("historical reader cannot execute images"))
    }

    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundle,
        _: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        Err(Code::Denied.error("historical reader cannot publish"))
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

async fn historical(fixture: &Fixture, name: &str) -> TestResult<(Arc<Instance>, ManagedReceipt)> {
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit(name, r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value)) UNION ALL SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(20 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    instance
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    Ok((instance, first))
}

#[tokio::test]
async fn historical_inspect_keeps_result() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (instance, receipt) = historical(&fixture, "history").await?;
    let captured = fixture
        .query
        .store()
        .managed_attempt([1; 16], "history", "first", &AnalysisReadControl::default())?
        .ok_or("historical attempt")?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    fixture.authority.set(false);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let meta = fixture.query.store().meta()?;
    for (call, reference) in &receipt.results {
        let saved = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            &reference.result_id,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert_eq!(&saved.result, reference);
        assert_eq!(call_context(&saved)?.context.id, "first");
        assert!(!saved.current);
        assert_eq!(saved.receipt, receipt);
        assert_eq!(saved.source.store_uuid, meta.store_uuid);
        assert_eq!(saved.source.schema_version, meta.schema_version);
        assert_eq!(saved.source.recovery_epoch, meta.recovery_epoch);
        assert_eq!(saved.source.commit_revision, captured.captured_revision());
        assert_eq!(
            saved.definition_revision,
            instance.admitted().spec.definition.digest()?
        );
        assert!(
            matches!(&saved.kind, araphor_data::InstanceResultKindV1::Call { call: id, .. } if id == call)
        );
        let returned = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            &reference.result_id,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert_eq!(
            serde_json::to_value(&returned)?,
            serde_json::to_value(&saved)?
        );
        let document = serde_json::to_value(&returned)?;
        for field in [
            "output",
            "grant",
            "witnesses",
            "contexts",
            "parameters",
            "manifest",
        ] {
            assert!(document.get(field).is_none(), "{field}");
        }
    }
    let selected = Instance::read_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &receipt.selected.result_id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(selected.result, receipt.selected);
    assert_eq!(selected.receipt, receipt);
    assert!(matches!(
        &selected.kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    assert!(!selected.current);
    assert_eq!(instance.admitted().spec.manifest.calls.len(), 2);
    assert_eq!(fixture.query.store().meta()?, meta);
    assert!(reader.checks.load(Ordering::SeqCst) >= 8);
    Ok(())
}

#[tokio::test]
async fn historical_inspect_skips_execution() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("history", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("once"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt.results.values().next().ok_or("result")?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let before = fixture.query.store().meta()?;
    let held = fixture.query.memory().input_reserved();
    let saved = Instance::read_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(saved.result, *reference);
    assert_eq!(call_context(&saved)?.context.id, "once");
    let error = Instance::replay_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        None,
        reader.grant.clone(),
        "history",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("Inspect authority executed replay")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    Ok(())
}

#[tokio::test]
async fn historical_inspect_binds_scope() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (_, receipt) = historical(&fixture, "history").await?;
    fixture.admit("foreign", "SELECT 1").await?;
    let id = &receipt.results.values().next().ok_or("result")?.result_id;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
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
        let error = Instance::read_result(
            Arc::clone(&fixture.query),
            authority,
            grant,
            instance,
            id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("unauthorized historical result")?;
        let expected = if case == 3 {
            Code::Missing
        } else {
            Code::Denied
        };
        assert!(
            matches!(
                error,
                crate::Error::Data {
                    source: araphor_data::Error::Package { code, .. }
                } | crate::Error::Query {
                    source: araphor_query::Error::Data {
                        source: araphor_data::Error::Package { code, .. }
                    }
                } if code == expected
            ),
            "case {case}: {error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn historical_inspect_checks_disclosure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (_, receipt) = historical(&fixture, "history").await?;
    let id = &receipt.results.values().next().ok_or("result")?.result_id;
    let mut reader = Reader::new(fixture.grant.clone());
    reader.deny_at = 2;
    let reader = Arc::new(reader);
    let error = Instance::read_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        id,
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("revoked disclosure succeeded")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(reader.checks.load(Ordering::SeqCst), 2);
    for result in [id.as_str(), receipt.selected.result_id.as_str()] {
        let mut denied = Reader::new(fixture.grant.clone());
        denied.deny_at = 2;
        let denied = Arc::new(denied);
        let error = Instance::read_result(
            Arc::clone(&fixture.query),
            denied.clone(),
            denied.grant.clone(),
            "history",
            result,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("denied query disclosure succeeded")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::PermissionDenied
        );
        assert_eq!(denied.checks.load(Ordering::SeqCst), 2);
        let reader = Arc::new(Reader::new(fixture.grant.clone()));
        reader.announce.store(true, Ordering::SeqCst);
        Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            result,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(reader.checks.load(Ordering::SeqCst) >= 3);
        reader.announce.store(true, Ordering::SeqCst);
        reader.revoke.store(true, Ordering::SeqCst);
        let active = AnalysisReadControl::default();
        let error = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            result,
            &active,
        )
        .await
        .err()
        .ok_or("authority event ignored")?;
        active.check()?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::PermissionDenied
        );
    }
    let control = AnalysisReadControl::default();
    control.cancel()?;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let error = Instance::read_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        id,
        &control,
    )
    .await
    .err()
    .ok_or("cancelled historical read succeeded")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::Cancelled
    );
    Ok(())
}

#[tokio::test]
async fn historical_replay_is_explicit() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(1024 * 1024),
        output_capacity: Some(1024 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut image = bundle("sql")?;
    image.artifacts[0].descriptor.exports[0].outputs[0].evidence_required = false;
    let model = image.artifacts[0].descriptor.exports[0].clone();
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture".into());
    };
    program.outputs.insert(
        "data".into(),
        "SELECT value FROM input ORDER BY value".into(),
    );
    fixture.install(&image)?;
    let instance = fixture.admit("indices", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(value AS BIGINT UNSIGNED) AS value FROM (VALUES (1), (2), (3)) AS source_values(value)))"#).await?;
    let receipt = instance
        .run(request("rows"), &AnalysisReadControl::default())
        .await?;
    let id = &receipt.results.values().next().ok_or("result")?.result_id;
    let before = fixture.query.store().meta()?;
    let araphor_data::PackageResponseV1::Replayed(packet) = Instance::replay_response(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        fixture.grant.clone(),
        "indices",
        id,
        &AnalysisReadControl::default(),
    )
    .await?
    else {
        return Err("replayed call variant".into());
    };
    let output = packet.decode_model(&model)?;
    assert_eq!(values(&output.datasets[0].batches)?, [1, 2, 3]);
    drop(output);
    drop(packet);
    assert_eq!(fixture.query.store().meta()?, before);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(instance);
    drop(fixture.query.memory().reserve_input(1024 * 1024)?);
    drop(fixture.query.memory().reserve_output(1024 * 1024)?);
    Ok(())
}
