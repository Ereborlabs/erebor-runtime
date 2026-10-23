use super::*;

impl Fixture {
    async fn timed_instance(&self) -> TestResult<Arc<Instance>> {
        self.install(&bundle("sql")?)?;
        let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        self.query.store().accept_validated_batch(
            araphor_data::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "timed-history".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1_000_000_000,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        self.admit(
            "timed-history",
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (
            SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM events
            WHERE received_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds'))"#,
        )
        .await
    }
}

#[tokio::test]
async fn timed_results_keep_history() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture.timed_instance().await?;
    let control = AnalysisReadControl::default();
    let mut input = request("before-expiry");
    input.time_utc_ns = 10_000_000_000;
    let first = instance.run(input, &control).await?;
    assert_eq!(fixture.selected("timed-history", &first.attempt)?, [1]);
    let deadline = first
        .frontier
        .as_ref()
        .and_then(|frontier| frontier.next_change)
        .ok_or("native timed deadline")?;
    assert_eq!(deadline, 61_000_000_000);
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "timed-history", &control)?
        .ok_or("timed instance")?;
    assert!(!current.running);
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let instance = host.stop(instance, current.lifecycle, &control).await?;
    assert!(instance.admitted().lifecycle > current.lifecycle);
    assert_eq!(instance.admitted().progress, first.commit_revision);
    let current = instance.admitted().clone();
    assert!(!current.running);
    let reference = first.results.values().next().ok_or("timed call result")?;
    let araphor_data::ManagedOutput::Call {
        result: original, ..
    } = fixture.query.store().managed_output(
        &current,
        &reference.result_id,
        deadline - 1,
        &control,
    )?
    else {
        return Err("package output variant".into());
    };
    assert!(original.current);
    let before = fixture.query.store().meta()?;
    for now in [deadline, deadline + 1] {
        let araphor_data::ManagedOutput::Call {
            result: expired, ..
        } = fixture
            .query
            .store()
            .managed_output(&current, &reference.result_id, now, &control)?
        else {
            return Err("package output variant".into());
        };
        assert!(!expired.current);
        assert_eq!(expired.output, original.output);
        assert_eq!(expired.context, original.context);
        assert_eq!(expired.commit_revision, original.commit_revision);
    }
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    let araphor_data::PackageResponseV1::Result(expired) = Instance::read_output(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "timed-history",
        &reference.result_id,
        &control,
    )
    .await?
    else {
        return Err("package output variant".into());
    };
    assert!(!expired.current);
    assert_eq!(expired.output, original.output);
    assert_eq!(expired.context, original.context);
    assert_eq!(
        Instance::read_history(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "timed-history",
            &control
        )
        .await?,
        std::slice::from_ref(&first)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "timed-history", &control)?,
        Some(current)
    );
    assert_eq!(fixture.query.store().meta()?, before);
    let mut input = request("after-expiry");
    input.time_utc_ns = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let second = instance.run(input, &control).await?;
    assert!(second
        .frontier
        .as_ref()
        .ok_or("renewed native frontier")?
        .next_change
        .is_none());
    assert_eq!(fixture.selected("timed-history", &second.attempt)?, [0]);
    assert_eq!(fixture.selected("timed-history", &first.attempt)?, [1]);
    let reference = second
        .results
        .values()
        .next()
        .ok_or("renewed call result")?;
    let before = fixture.query.store().meta()?;
    let araphor_data::PackageResponseV1::Result(fresh) = Instance::read_output(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "timed-history",
        &reference.result_id,
        &control,
    )
    .await?
    else {
        return Err("package output variant".into());
    };
    assert!(fresh.current);
    assert_eq!(fresh.context.context.id, "after-expiry");
    assert_eq!(
        Instance::read_history(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            "timed-history",
            &control
        )
        .await?,
        [first, second]
    );
    assert!(
        !fixture
            .query
            .store()
            .managed_instance([1; 16], "timed-history", &control)?
            .ok_or("stopped timed instance")?
            .running
    );
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn timed_inspection_precedes_arrow() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture.timed_instance().await?;
    let control = AnalysisReadControl::default();
    let mut input = request("expired-corrupt-output");
    input.time_utc_ns = 10_000_000_000;
    let receipt = instance.run(input, &control).await?;
    assert_eq!(
        receipt
            .frontier
            .as_ref()
            .and_then(|frontier| frontier.next_change),
        Some(61_000_000_000)
    );
    let reference = receipt.results.values().next().ok_or("timed result")?;
    fixture.query.store().fault_write(
        "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'output'",
        &[&reference.result_id],
    )?;
    let before = fixture.query.store().meta()?;
    let held = fixture.query.memory().input_reserved();
    let reader = Arc::new(Reader::new(fixture.grant.clone()));
    reader.allowed.store(false, Ordering::SeqCst);
    let error = Instance::read_output(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "timed-history",
        &reference.result_id,
        &control,
    )
    .await
    .err()
    .ok_or("denied timed output returned")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(reader.checks.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    reader.allowed.store(true, Ordering::SeqCst);
    let error = Instance::read_output(
        Arc::clone(&fixture.query),
        reader.clone(),
        reader.grant.clone(),
        "timed-history",
        &reference.result_id,
        &control,
    )
    .await
    .err()
    .ok_or("expired corrupt output was accepted")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::AnalysisContract { .. }
        } | crate::Error::Query {
            source: araphor_query::Error::Data {
                source: araphor_data::Error::AnalysisContract { .. }
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    Ok(())
}
