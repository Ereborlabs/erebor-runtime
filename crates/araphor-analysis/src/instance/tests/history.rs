use std::sync::atomic::AtomicUsize;

use super::*;

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

    fn admit(&self, _: &PackageGrantV1, _: &PackageBundleRef<'_>) -> araphor_data::Result<()> {
        Err(Code::Denied.error("historical reader cannot execute images"))
    }

    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundleRef<'_>,
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
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    fixture.authority.set(false);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let meta = fixture.query.store().meta()?;
    let mut original = Vec::new();
    for reference in receipt.results.values() {
        let saved = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            &reference.result_id,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert_eq!(saved.commit_revision, reference.commit_revision);
        assert_eq!(
            saved.limits,
            bundle("sql")?.artifacts[0].descriptor.exports[0].limits
        );
        assert_eq!(saved.context.context.id, "first");
        assert!(!saved.current);
        assert_eq!(saved.output.evidence.len(), 1);
        assert_eq!(saved.output.reasons.len(), 1);
        assert_eq!(
            values(&saved.output.datasets[0].batches)?,
            values(
                &saved
                    .output
                    .checkpoint
                    .as_ref()
                    .ok_or("checkpoint")?
                    .datasets[0]
                    .batches
            )?
        );
        original.extend(values(&saved.output.datasets[0].batches)?);
        let selected = Instance::query_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "history",
            &reference.result_id,
            "SELECT * FROM data",
            &AnalysisReadControl::default(),
        )
        .await?;
        assert_eq!(selected.data.name, "query");
        assert_eq!(
            values(&selected.data.batches)?,
            values(&saved.output.datasets[0].batches)?
        );
        assert_eq!(selected.data.batches[0].num_columns(), 2);
        assert_eq!(
            selected.data.batches[0]
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("row index")?
                .values()
                .as_ref(),
            &[0]
        );
    }
    original.sort_unstable();
    assert_eq!(original, [10, 20]);
    assert_eq!(instance.admitted().spec.manifest.calls.len(), 2);
    assert_eq!(fixture.query.store().meta()?, meta);
    assert!(reader.checks.load(Ordering::SeqCst) >= 8);
    Ok(())
}

#[tokio::test]
async fn historical_query_keeps_limits() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = bundle("sql")?;
    image.artifacts[0].descriptor.exports[0].limits.max_rows = 2;
    let limits = image.artifacts[0].descriptor.exports[0].limits;
    fixture.install(&image)?;
    let instance = fixture.admit("limited", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("once"), &AnalysisReadControl::default())
        .await?;
    let id = &receipt.results.values().next().ok_or("result")?.result_id;
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let saved = Instance::read_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "limited",
        id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(saved.limits, limits);
    let error = Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "limited",
        id,
        "SELECT value FROM data UNION ALL SELECT value FROM data UNION ALL SELECT value FROM data",
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("descriptor row limit ignored")?;
    let crate::Error::Query { source } = error else {
        return Err("native query limit error absent".into());
    };
    assert_eq!(
        araphor_query::Failure::from(&source),
        araphor_query::Failure::ResultTooLarge
    );
    let selected = Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "limited",
        id,
        "SELECT value FROM data",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(values(&selected.data.batches)?, [7]);
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
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    reader.announce.store(true, Ordering::SeqCst);
    Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        id,
        "SELECT * FROM data",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert!(reader.checks.load(Ordering::SeqCst) >= 3);
    reader.announce.store(true, Ordering::SeqCst);
    reader.revoke.store(true, Ordering::SeqCst);
    let active = AnalysisReadControl::default();
    let error = Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "history",
        id,
        "SELECT * FROM data",
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
async fn historical_query_preserves_indices() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(1024 * 1024),
        output_capacity: Some(1024 * 1024),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut image = bundle("sql")?;
    image.artifacts[0].descriptor.exports[0].outputs[0].evidence_required = false;
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
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let selected = Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "indices",
        id,
        "SELECT * FROM data WHERE value > 1 ORDER BY value",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(values(&selected.data.batches)?, [2, 3]);
    let indices = selected
        .data
        .batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .into_iter()
                .flat_map(|column| column.values().iter().copied())
        })
        .collect::<Vec<_>>();
    assert_eq!(indices, [1, 2]);
    drop(selected);
    let empty = Instance::query_result(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "indices",
        id,
        "SELECT * FROM data WHERE FALSE",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(empty.data.batches.len(), 1);
    assert_eq!(empty.data.batches[0].num_rows(), 0);
    assert_eq!(empty.data.batches[0].schema().field(0).name(), "value");
    assert_eq!(
        empty.data.batches[0].schema().field(1).name(),
        "__row_index"
    );
    drop(empty);
    for sql in [
        "SELECT * FROM events",
        "WITH unused AS (SELECT * FROM coverage) SELECT * FROM data",
        "CREATE TABLE stolen AS SELECT * FROM data",
    ] {
        let error = Instance::query_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "indices",
            id,
            sql,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("undeclared historical query succeeded")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::InvalidArguments,
            "{sql}: {error:?}"
        );
    }
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(instance);
    drop(fixture.query.memory().reserve_input(1024 * 1024)?);
    drop(fixture.query.memory().reserve_output(1024 * 1024)?);
    Ok(())
}
