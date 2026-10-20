use super::*;

fn inlined_views(prepared: &PreparedDefinition, clocks: usize) -> TestResult {
    assert_eq!(crate::follow::Window::clocks(&prepared.plan)?, clocks);
    let mut hidden = 0;
    prepared.plan.apply_with_subqueries(|plan| {
        if let LogicalPlan::TableScan(scan) = plan {
            hidden += usize::from(scan.source.get_logical_plan().is_some());
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    assert_eq!(hidden, 0);
    Ok(())
}

#[tokio::test]
async fn view_window_deadline() -> TestResult {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE VIEW recent_rows AS SELECT source_cursor AS value, received_at
            FROM events WHERE received_at >= now() - INTERVAL '2 seconds';
         CREATE VIEW nested_rows AS SELECT value, received_at FROM recent_rows;",
        )?;
    let received = NOW - SECOND;
    fixture.timed_event(1, received)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            "SELECT CAST(count(*) AS BIGINT UNSIGNED) AS value FROM nested_rows",
        ))
        .await?;
    inlined_views(&prepared, 1)?;
    let window = crate::follow::Window::from_plan(&prepared.plan)
        .map_err(|error| format!("{error:?}\n{}", prepared.plan.display_indent_schema()))?;
    assert!(window.is_some());
    let clock = Clock::new();
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.received_from = Bound::Excluded(received - 1);
    let mut stream = crate::follow::Subscription::new(
        fixture
            .engine
            .session(selection.clone(), &AnalysisReadControl::default(), NOW)?,
        Arc::new(prepared.plan.clone()),
        prepared.sources().clone(),
        prepared.resolved().sql.as_bytes(),
        None,
        clock.clone(),
        true,
    )?;
    let first = next(&mut stream).await?;
    let expiry = received / 1000 * 1000 + 2 * SECOND + 1000;
    assert_eq!(stream.moving_resolution_ns(), Some(1000));
    assert_eq!(values(first.batches.as_deref().ok_or("view output")?)?, [1]);
    assert_eq!(first.snapshot.next_change, Some(expiry));
    assert_eq!(
        first.snapshot.selection.received_from,
        Bound::Excluded(received - 1)
    );
    assert_eq!(
        first
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1]
    );
    let before = fixture.engine.store().meta()?;
    for (now, expected) in [(expiry - 1, 1), (expiry, 0)] {
        let native = fixture
            .engine
            .session(selection.clone(), &AnalysisReadControl::default(), now)?
            .execute_definition(&prepared, crate::definition::Invocation::default())
            .await?;
        assert_eq!(values(&native.batches)?, [expected]);
        assert_eq!(fixture.engine.store().meta()?, before);
    }
    clock.set(expiry - 1);
    let retained = next(&mut stream).await?;
    assert!(retained.clock_changed);
    assert!(retained.batches.is_none());
    assert_eq!(retained.snapshot.next_change, Some(expiry));
    assert_eq!(
        retained.snapshot.selection.received_from,
        Bound::Excluded(received - 1)
    );
    assert_eq!(
        retained
            .snapshot
            .witnesses
            .iter()
            .map(|w| w.cursor)
            .collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    clock.set(expiry);
    let expired = next(&mut stream).await?;
    assert!(expired.clock_changed);
    assert_eq!(
        values(expired.batches.as_deref().ok_or("view removal")?)?,
        [0]
    );
    assert_eq!(expired.evaluated_utc_ns, expiry);
    assert_eq!(expired.snapshot.next_change, None);
    assert_eq!(
        expired.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn view_port_windows() -> TestResult {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE VIEW wide_rows AS SELECT source_cursor AS value FROM events
            WHERE received_at >= now() - INTERVAL '10 seconds';
         CREATE VIEW narrow_rows AS SELECT source_cursor AS value FROM events
            WHERE received_at >= now() - INTERVAL '2 seconds';",
        )?;
    fixture.install(&window_image(window_inputs()))?;
    let old = NOW - 8 * SECOND;
    let recent = NOW - SECOND;
    fixture.timed_event(1, old)?;
    fixture.timed_event(2, recent)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count('wide',
            wide => (SELECT value FROM wide_rows),
            narrow => (SELECT value FROM narrow_rows))"#,
        ))
        .await?;
    inlined_views(&prepared, 2)?;
    assert!(crate::follow::Window::from_plan(&prepared.plan)?.is_none());
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let clock = Clock::new();
    let mut stream = fixture.follow(&prepared, clock.clone())?;
    let first = next(&mut stream).await?;
    let expiry = recent / 1000 * 1000 + 2 * SECOND + 1000;
    window_check(&first, id, NOW, &[2, 1, 2, 2], Some(expiry))?;
    assert_eq!(first.snapshot.received_min, Some(old));
    let before = fixture.engine.store().meta()?;
    clock.set(expiry);
    let expired = next(&mut stream).await?;
    let next_expiry = old / 1000 * 1000 + 10 * SECOND + 1000;
    window_check(&expired, id, expiry, &[2, 0, 2, 2], Some(next_expiry))?;
    assert_eq!(fixture.engine.store().meta()?, before);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn view_clock_guard() -> TestResult {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE VIEW scalar_rows AS SELECT now() AS moment;
         CREATE VIEW or_rows AS SELECT source_cursor AS value FROM events
            WHERE received_at >= now() - INTERVAL '2 seconds' OR operation = 7;
         CREATE VIEW plain_rows AS SELECT source_cursor FROM events;
         CREATE VIEW recent_rows AS SELECT source_cursor FROM events
            WHERE received_at >= now() - INTERVAL '2 seconds';
         CREATE VIEW older_rows AS SELECT source_cursor FROM events
            WHERE received_at >= now() - INTERVAL '3 seconds';
         CREATE VIEW coarse_rows AS SELECT source_cursor AS value FROM events
            WHERE received_at >= CAST(now() - INTERVAL '2 seconds' AS TIMESTAMP(3));",
        )?;
    for (sql, clocks) in [
        ("SELECT moment FROM scalar_rows", 1),
        ("SELECT value FROM or_rows", 1),
        ("SELECT value FROM coarse_rows", 1),
        (
            "SELECT a.source_cursor FROM recent_rows a JOIN plain_rows b USING (source_cursor)",
            1,
        ),
        (
            "SELECT a.source_cursor FROM recent_rows a JOIN older_rows b USING (source_cursor)",
            2,
        ),
    ] {
        let prepared = fixture.prepare(&Fixture::sql(sql)).await?;
        inlined_views(&prepared, clocks)?;
        let before = fixture.engine.store().meta()?;
        assert!(
            matches!(
                fixture.follow(&prepared, Clock::new()),
                Err(crate::Error::Invalid {
                    field: "follow clock filter",
                    ..
                })
            ),
            "{sql}"
        );
        assert_eq!(fixture.engine.store().meta()?, before);
    }
    Ok(())
}
