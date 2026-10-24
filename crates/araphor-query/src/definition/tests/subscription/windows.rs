use std::ops::Bound;

use super::*;

mod views;

const SECOND: u64 = 1_000_000_000;
const CAPACITY: usize = 16 * 1024 * 1024;

impl Fixture {
    fn timed_event(&self, cursor: u64, received: u64) -> TestResult {
        let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        self.engine.store().accept_validated_batch(
            araphor_data::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "port-window".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: received,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }
}

fn window_inputs() -> Vec<sdk::InputPort> {
    let query = |name: &str, sql: &str| sdk::InputPort {
        port: sdk::Port::new(name, Fixture::schema("value")),
        source: sdk::InputSource::Query(sql.into()),
    };
    vec![
        query("wide", "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '10 seconds'"),
        query("narrow", "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds'"),
        sdk::InputPort {
            port: sdk::Port::new("chosen", Fixture::schema("source_cursor")),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
        query("dependent", "SELECT source_cursor AS value FROM chosen"),
    ]
}

fn window_image(inputs: Vec<sdk::InputPort>) -> PackageBundleV1 {
    let outputs = inputs
        .iter()
        .map(|input| sdk::Port::new(&input.port.name, Fixture::schema("value")))
        .collect();
    let program = SqlModelV1 {
        outputs: inputs
            .iter()
            .map(|input| {
                (
                    input.port.name.clone(),
                    format!(
                        "SELECT CAST(count(*) AS BIGINT UNSIGNED) AS value FROM \"{}\"",
                        input.port.name
                    ),
                )
            })
            .collect(),
        ..Default::default()
    };
    let mut model = sdk::Model::new("count", Vec::new(), outputs);
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = inputs;
    let mut image = Fixture::bundle();
    image.artifacts[0].descriptor.exports = vec![model];
    image.artifacts[0].implementations = vec![PackageImplementationV1::Sql {
        export: "count".into(),
        program,
    }];
    image
}

fn window_check(
    update: &crate::follow::Update,
    id: u64,
    now: u64,
    counts: &[usize],
    expiry: Option<u64>,
) -> TestResult {
    assert_eq!(update.calls.len(), 1);
    assert_eq!(update.snapshot.next_change, expiry);
    assert_eq!(update.evaluated_utc_ns, now);
    let call = &update.calls[&id];
    assert_eq!(call.evaluation().context.time_utc_ns, now as i64);
    assert_eq!(
        call.evaluation()
            .inputs
            .iter()
            .map(|input| input
                .data
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>())
            .collect::<Vec<_>>(),
        counts,
    );
    for (input, count) in call.evaluation().inputs.iter().zip(counts) {
        let output = call
            .output()
            .datasets
            .iter()
            .find(|output| output.name == input.data.name)
            .ok_or("window output absent")?;
        assert_eq!(values(&output.batches)?, [*count as u64]);
    }
    Ok(())
}

#[tokio::test]
async fn mixed_port_deadlines() -> TestResult {
    for pressure in [false, true] {
        let fixture = Fixture::limits(Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            input_capacity: Some(CAPACITY),
            output_capacity: Some(CAPACITY),
            input_bytes: 2 * 1024 * 1024,
            output_bytes: 2 * 1024 * 1024,
            ..Default::default()
        })?;
        fixture.install(&window_image(window_inputs()))?;
        let old = NOW - 8 * SECOND;
        let recent = NOW - SECOND;
        fixture.timed_event(1, old)?;
        fixture.timed_event(2, recent)?;
        let prepared = fixture
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count('wide')"#,
            ))
            .await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        let clock = Clock::new();
        let mut stream = fixture.follow(&prepared, Arc::clone(&clock))?;
        assert_eq!(stream.moving_resolution_ns(), Some(1000));
        let first = next(&mut stream).await?;
        let expiry = recent / 1000 * 1000 + 2 * SECOND + 1000;
        assert!(expiry > NOW);
        window_check(&first, id, NOW, &[2, 1, 2, 2], Some(expiry))?;
        assert_eq!(first.snapshot.received_min, Some(old));
        assert_eq!(
            first
                .snapshot
                .witnesses
                .iter()
                .map(|witness| witness.cursor)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        let retained = Arc::clone(&first.calls[&id]);
        fixture.context(1)?;
        let health = next(&mut stream).await?;
        assert!(health.batches.is_none());
        assert!(health.calls.is_empty());
        assert_eq!(health.cursor, first.cursor);
        assert!(health.snapshot.next_change.is_none());
        let before = fixture.engine.store().meta()?;
        let second = {
            let held = pressure
                .then(|| fixture.engine.reserve_evaluation([1; 16]))
                .transpose()?;
            let waiting = stream.next();
            tokio::pin!(waiting);
            assert!(futures_util::poll!(waiting.as_mut()).is_pending());
            if pressure {
                clock.set(expiry);
                assert!(futures_util::poll!(waiting.as_mut()).is_pending());
                assert_eq!(fixture.engine.store().meta()?, before);
            } else {
                clock.time.store(expiry, Ordering::SeqCst);
            }
            drop(held);
            tokio::time::timeout(Duration::from_secs(30), waiting)
                .await?
                .ok_or("window subscription stopped")??
        };
        assert!(second.clock_changed);
        let next_expiry = old / 1000 * 1000 + 10 * SECOND + 1000;
        window_check(&second, id, expiry, &[2, 0, 2, 2], Some(next_expiry))?;
        assert!(!Arc::ptr_eq(&retained, &second.calls[&id]));
        assert_eq!(fixture.engine.store().meta()?, before);
        clock.set(next_expiry);
        let third = next(&mut stream).await?;
        let final_expiry = recent / 1000 * 1000 + 10 * SECOND + 1000;
        window_check(&third, id, next_expiry, &[1, 0, 2, 2], Some(final_expiry))?;
        clock.set(final_expiry);
        let fourth = next(&mut stream).await?;
        window_check(&fourth, id, final_expiry, &[0, 0, 2, 2], None)?;
        clock.set(final_expiry + SECOND);
        let quiet = next(&mut stream).await?;
        assert!(quiet.calls.is_empty());
        assert_eq!(quiet.cursor, fourth.cursor);
        assert_eq!(quiet.evaluated_utc_ns, fourth.evaluated_utc_ns);
        assert_eq!(quiet.snapshot.next_change, None);
        assert!(quiet.clock_changed);
        assert!(quiet.batches.is_none());
        assert_eq!(fixture.engine.store().meta()?, before);
        assert!(futures_util::poll!(stream.next()).is_pending());
        tokio::time::timeout(Duration::from_secs(30), stream.cancel_and_join()).await??;
        assert_eq!(
            retained.evaluation().inputs[0]
                .data
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        drop((prepared, first, health, second, third, fourth, quiet));
        assert!(fixture.engine.memory().input_reserved() > 0);
        assert!(fixture.engine.memory().reserve_input(CAPACITY).is_err());
        drop(retained);
        assert_eq!(fixture.engine.memory().input_reserved(), 0);
        drop(fixture.engine.memory().reserve_input(CAPACITY)?);
        drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    }
    Ok(())
}

#[tokio::test]
async fn window_grant_precision() -> TestResult {
    let fixture = Fixture::installed(&window_image(vec![window_inputs().remove(1)]))?;
    let received = NOW - SECOND;
    fixture.timed_event(1, received)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.received_from = Bound::Excluded(received - 1);
    let clock = Clock::new();
    let mut stream = crate::follow::Subscription::new(
        fixture
            .engine
            .session(selection, &AnalysisReadControl::default(), NOW)?,
        Arc::new(prepared.plan.clone()),
        prepared.sources().clone(),
        prepared.resolved().sql.as_bytes(),
        None,
        clock.clone(),
        true,
    )?;
    let first = next(&mut stream).await?;
    let expiry = received / 1000 * 1000 + 2 * SECOND + 1000;
    window_check(&first, id, NOW, &[1], Some(expiry))?;
    assert_eq!(
        first.snapshot.selection.received_from,
        Bound::Excluded(received - 1)
    );
    let before = fixture.engine.store().meta()?;
    clock.set(expiry);
    let expired = next(&mut stream).await?;
    window_check(&expired, id, expiry, &[0], None)?;
    assert_eq!(fixture.engine.store().meta()?, before);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn outer_window_scope() -> TestResult {
    let fixture = Fixture::installed(&window_image(window_inputs()))?;
    let old = NOW - 8 * SECOND;
    let recent = NOW - SECOND;
    fixture.timed_event(1, old)?;
    fixture.timed_event(2, recent)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"
        SELECT p.value FROM "fixture"."r1".count('chosen') p
        CROSS JOIN (SELECT source_cursor FROM events
            WHERE received_at >= now() - INTERVAL '5 seconds') recent"#,
        ))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let clock = Clock::new();
    let mut stream = fixture.follow(&prepared, clock.clone())?;
    let first = next(&mut stream).await?;
    let expiry = recent / 1000 * 1000 + 2 * SECOND + 1000;
    window_check(&first, id, NOW, &[2, 1, 2, 2], Some(expiry))?;
    assert_eq!(
        values(first.batches.as_deref().ok_or("outer output absent")?)?,
        [2]
    );
    assert_eq!(first.snapshot.received_min, Some(old));
    let before = fixture.engine.store().meta()?;
    clock.set(expiry);
    let second = next(&mut stream).await?;
    let wide_expiry = old / 1000 * 1000 + 10 * SECOND + 1000;
    window_check(&second, id, expiry, &[2, 0, 2, 2], Some(wide_expiry))?;
    clock.set(wide_expiry);
    let third = next(&mut stream).await?;
    let outer_expiry = recent / 1000 * 1000 + 5 * SECOND + 1000;
    window_check(&third, id, wide_expiry, &[1, 0, 2, 2], Some(outer_expiry))?;
    clock.set(outer_expiry);
    let expired = next(&mut stream).await?;
    assert!(expired.clock_changed);
    assert!(values(expired.batches.as_deref().ok_or("outer removal absent")?)?.is_empty());
    assert_eq!(fixture.engine.store().meta()?, before);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn nested_window_deadline() -> TestResult {
    let mut image = window_image(vec![window_inputs().remove(1)]);
    let mut model = sdk::Model::new(
        "outer",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema("value")),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "r1".into(),
            export: "count".into(),
            output: "narrow".into(),
        })),
    });
    image.artifacts[0].descriptor.exports.push(model);
    image.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Sql {
            export: "outer".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
                ..Default::default()
            },
        });
    let fixture = Fixture::installed(&image)?;
    let recent = NOW - SECOND;
    fixture.timed_event(1, recent)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1"."outer"()"#))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    let inner = calls
        .iter()
        .find(|call| call.export() == "count")
        .ok_or("inner call")?
        .id();
    let outer = calls
        .iter()
        .find(|call| call.export() == "outer")
        .ok_or("outer call")?
        .id();
    let clock = Clock::new();
    let mut stream = fixture.follow(&prepared, clock.clone())?;
    let first = next(&mut stream).await?;
    let expiry = recent / 1000 * 1000 + 2 * SECOND + 1000;
    assert_eq!(first.snapshot.next_change, Some(expiry));
    assert_eq!(first.calls.len(), 2);
    assert_eq!(
        values(first.batches.as_deref().ok_or("nested output absent")?)?,
        [1]
    );
    assert_eq!(
        values(&first.calls[&inner].evaluation().inputs[0].data.batches)?,
        [1]
    );
    let before = fixture.engine.store().meta()?;
    clock.set(expiry);
    let expired = next(&mut stream).await?;
    assert!(expired.clock_changed);
    assert_eq!(expired.snapshot.next_change, None);
    assert_eq!(expired.calls.len(), 2);
    assert_eq!(
        values(expired.batches.as_deref().ok_or("nested removal absent")?)?,
        [0]
    );
    for id in [inner, outer] {
        assert!(!Arc::ptr_eq(&first.calls[&id], &expired.calls[&id]));
        assert_eq!(
            expired.calls[&id].evaluation().context.time_utc_ns,
            expiry as i64
        );
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn body_window_deadline() -> TestResult {
    let definition = Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#);
    let mut invalid = window_image(vec![]);
    invalid.artifacts[0].descriptor.exports[0].outputs =
        vec![sdk::Port::new("result", Fixture::schema("value"))];
    let PackageImplementationV1::Sql { program, .. } = &mut invalid.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert("result".into(), "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds'".into());
    let denied = Fixture::installed(&invalid)?;
    let before = denied.engine.store().meta()?;
    let error = denied
        .prepare(&definition)
        .await
        .err()
        .ok_or("undeclared body table accepted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
    assert_eq!(denied.engine.store().meta()?, before);
    let mut image = window_image(vec![window_inputs().remove(1)]);
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program
        .outputs
        .insert("narrow".into(), "SELECT value FROM narrow".into());
    let fixture = Fixture::installed(&image)?;
    let recent = NOW - SECOND;
    fixture.timed_event(1, recent)?;
    let prepared = fixture.prepare(&definition).await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let clock = Clock::new();
    let mut stream = fixture.follow(&prepared, clock.clone())?;
    let first = next(&mut stream).await?;
    let expiry = recent / 1000 * 1000 + 2 * SECOND + 1000;
    assert_eq!(first.snapshot.next_change, Some(expiry));
    assert_eq!(
        values(first.batches.as_deref().ok_or("body output absent")?)?,
        [1]
    );
    let before = fixture.engine.store().meta()?;
    clock.set(expiry);
    let expired = next(&mut stream).await?;
    assert_eq!(expired.snapshot.next_change, None);
    assert!(expired.clock_changed);
    assert_eq!(expired.calls.len(), 1);
    assert!(expired.calls[&id].evaluation().inputs[0]
        .data
        .batches
        .iter()
        .all(|batch| batch.num_rows() == 0));
    assert!(values(&expired.calls[&id].output().datasets[0].batches)?.is_empty());
    assert_eq!(fixture.engine.store().meta()?, before);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn scalar_clock_guard() -> TestResult {
    let scalar =
        "SELECT CAST(CASE WHEN now() IS NOT NULL THEN 1 ELSE 0 END AS BIGINT UNSIGNED) AS value";
    for (sql, body, valid) in [
        (scalar, false, true),
        (
            "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds' OR operation = 7",
            false,
            false,
        ),
        (scalar, true, true),
        (
            "SELECT value FROM source WHERE now() >= now() - INTERVAL '2 seconds' OR value = 7",
            true,
            true,
        ),
    ] {
        let mut image = window_image(vec![sdk::InputPort {
            port: sdk::Port::new("source", Fixture::schema("value")),
            source: sdk::InputSource::Query(
                if body {
                    "SELECT source_cursor AS value FROM events"
                } else {
                    sql
                }
                .into(),
            ),
        }]);
        image.artifacts[0].descriptor.exports[0]
            .outputs
            .push(sdk::Port::new("clock", Fixture::schema("value")));
        let PackageImplementationV1::Sql { program, .. } =
            &mut image.artifacts[0].implementations[0]
        else {
            return Err("SQL required".into());
        };
        if body {
            program.outputs.insert("source".into(), sql.into());
        }
        program.outputs.insert(
            "clock".into(),
            "SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into(),
        );
        let fixture = Fixture::installed(&image)?;
        fixture.timed_event(1, NOW - SECOND)?;
        let before = fixture.engine.store().meta()?;
        let prepared = fixture
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count('source')"#,
            ))
            .await?;
        let clock = Clock::new();
        if !valid {
            assert!(
                matches!(
                    fixture.follow(&prepared, clock),
                    Err(crate::Error::Invalid {
                        field: "follow clock filter",
                        ..
                    })
                ),
                "{sql}"
            );
            assert_eq!(fixture.engine.store().meta()?, before);
            continue;
        }
        assert!(crate::follow::Window::from_plan(&prepared.plan)?.is_none());
        assert_eq!(prepared.sources().contains_key("events"), body);
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let id = calls[0].id();
        let mut stream = fixture.follow(&prepared, clock.clone())?;
        let first = next(&mut stream).await?;
        assert_eq!(
            values(first.batches.as_deref().ok_or("scalar output")?)?,
            [1]
        );
        assert_eq!(first.calls.len(), 1);
        let call = &first.calls[&id];
        assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [1]);
        let stamp = call
            .output()
            .datasets
            .iter()
            .find(|output| output.name == "clock")
            .ok_or("native clock output")?;
        assert_eq!(values(&stamp.batches)?, [NOW]);
        assert_eq!(first.evaluated_utc_ns, NOW);
        assert_eq!(first.snapshot.next_change, None);
        assert!(first.completed_windows.is_empty());
        assert_eq!(fixture.engine.store().meta()?, before);
        assert!(futures_util::poll!(stream.next()).is_pending());
        clock.set(NOW + SECOND);
        let idle = next(&mut stream).await?;
        assert!(idle.clock_changed);
        assert!(idle.batches.is_none());
        assert!(idle.calls.is_empty());
        assert_eq!(idle.cursor, first.cursor);
        assert_eq!(idle.evaluated_utc_ns, NOW);
        assert_eq!(idle.snapshot.next_change, None);
        assert!(idle.completed_windows.is_empty());
        assert_eq!(values(&stamp.batches)?, [NOW]);
        assert_eq!(fixture.engine.store().meta()?, before);
        assert!(futures_util::poll!(stream.next()).is_pending());
        if body {
            fixture.timed_event(2, NOW + SECOND / 2)?;
            let after = fixture.engine.store().meta()?;
            let changed = next(&mut stream).await?;
            if sql == scalar {
                assert!(changed.batches.is_none());
            } else {
                assert_eq!(
                    values(changed.batches.as_deref().ok_or("source output")?)?,
                    [1, 2]
                );
            }
            assert_eq!(changed.calls.len(), 1);
            let call = &changed.calls[&id];
            assert_eq!(call.evaluation().context.time_utc_ns, (NOW + SECOND) as i64);
            assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [1, 2]);
            let stamp = call
                .output()
                .datasets
                .iter()
                .find(|output| output.name == "clock")
                .ok_or("changed clock output")?;
            assert_eq!(values(&stamp.batches)?, [NOW + SECOND]);
            assert_eq!(changed.evaluated_utc_ns, NOW + SECOND);
            assert_eq!(changed.snapshot.next_change, None);
            assert!(changed.completed_windows.is_empty());
            assert_eq!(fixture.engine.store().meta()?, after);
            assert!(futures_util::poll!(stream.next()).is_pending());
        }
        stream.cancel_and_join().await?;
    }
    Ok(())
}
