use super::super::WindowSource;
use super::*;

const BIN: &str = "date_bin(INTERVAL '2 seconds', CURRENT_TIMESTAMP, TIMESTAMP '1970-01-01')";

fn sql() -> String {
    format!("SELECT count(*) AS total FROM events WHERE received_at >= {BIN} AND received_at < {BIN} + INTERVAL '2 seconds'")
}

#[test]
fn native_fixed_bounds() {
    let fixture = Fixture::new(Limits::default());
    for (origin, expected) in [
        ("1970-01-01", (2_000_000_000, 4_000_000_000)),
        ("1970-01-01 00:00:00.500", (2_500_000_000, 4_500_000_000)),
    ] {
        let bin =
            format!("date_bin(INTERVAL '2 seconds', CURRENT_TIMESTAMP, TIMESTAMP '{origin}')");
        let sql = format!("SELECT source_cursor FROM events WHERE received_at >= {bin} AND received_at < {bin} + INTERVAL '2 seconds' AND received_at < TIMESTAMP '1970-01-01 00:00:03'");
        let (plan, _) = fixture.plan(&sql, Vec::new());
        let window = Window::from_plan(&plan).unwrap().unwrap();
        assert_eq!(window.fixed_range(2_750_000_000).unwrap(), Some(expected));
        assert_eq!(
            window.fixed_range(expected.1.try_into().unwrap()).unwrap(),
            Some((expected.1, expected.1 + 2_000_000_000))
        );
        assert_eq!(window.expiry(Some(2_600_000_000)), None);
    }
    for predicate in [
        format!("received_at >= {BIN}"),
        format!("received_at > {BIN} AND received_at < {BIN} + INTERVAL '2 seconds'"),
        format!("received_at >= {BIN} AND received_at <= {BIN} + INTERVAL '2 seconds'"),
        format!("received_at >= {BIN} AND received_at < {BIN} + INTERVAL '3 seconds'"),
        format!("received_at >= {BIN} AND received_at < date_bin(INTERVAL '2 seconds', CURRENT_TIMESTAMP, TIMESTAMP '1970-01-01 00:00:01') + INTERVAL '2 seconds'"),
    ] {
        let (plan, _) = fixture.plan(&format!("SELECT source_cursor FROM events WHERE {predicate}"), Vec::new());
        assert!(Window::from_plan(&plan).is_err(), "{predicate}");
    }
}

#[tokio::test]
async fn fixed_window_keeps_cut() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 2_100_000_123);
    let clock = TestClock::new(2_500_000_000);
    let mut subscription = fixture.subscribe(&sql(), clock.clone(), None, true);
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(first.snapshot.next_change, Some(4_000_000_000));
    assert!(first.completed_windows.is_empty());
    assert_eq!(first.snapshot.windows.len(), 1);
    let window = first.snapshot.windows[0];
    assert_eq!(window.source, WindowSource::Query);
    assert_eq!(
        (window.start_utc_ns, window.end_utc_ns),
        (2_000_000_000, 4_000_000_000)
    );
    clock.set(3_000_000_000);
    let interim = next(&mut subscription).await;
    assert!(interim.completed_windows.is_empty());
    assert!(interim.batches.is_none());
    clock.set(7_500_000_000);
    let closed = next(&mut subscription).await;
    assert_eq!(closed.completed_windows, [window]);
    assert!(closed.batches.is_none());
    assert!(!Arc::ptr_eq(&closed.snapshot, &interim.snapshot));
    assert_eq!(closed.evaluated_utc_ns, 7_500_000_000);
    assert_eq!(closed.snapshot.time_utc_ns(), 7_500_000_000);
    assert_eq!(closed.cursor.evaluated(), 7_500_000_000);
    assert_eq!(closed.snapshot.windows, interim.snapshot.windows);
    assert!(closed.cursor.read_revision() >= interim.cursor.read_revision());
    let empty = next(&mut subscription).await;
    assert_eq!(values(&empty, 0), [ScalarValue::Int64(Some(0))]);
    assert!(empty.completed_windows.is_empty());
    assert_eq!(empty.snapshot.next_change, None);
    assert!(futures_util::poll!(subscription.next()).is_pending());
    fixture.commit(&fixture.source, 2, 1, 6_100_000_123);
    let later = next(&mut subscription).await;
    assert_eq!(values(&later, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(later.snapshot.windows[0].start_utc_ns, 6_000_000_000);
    clock.now.store(8_000_000_000, Ordering::SeqCst);
    fixture.commit(&fixture.source, 3, 1, 8_100_000_123);
    let closed = next(&mut subscription).await;
    assert_eq!(closed.completed_windows, later.snapshot.windows);
    assert!(!Arc::ptr_eq(&closed.snapshot, &later.snapshot));
    assert_eq!(closed.evaluated_utc_ns, 8_000_000_000);
    let current = next(&mut subscription).await;
    assert!(current.batches.is_none());
    assert_eq!(current.snapshot.windows[0].start_utc_ns, 8_000_000_000);
    subscription.cancel_and_join().await.unwrap();
}

#[tokio::test]
async fn fixed_input_retains_call() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use araphor_analysis_sdk as sdk;
    use araphor_discovery_definition::{Definition, Program, Source};
    use araphor_package::{
        PackageArtifactV1, PackageBundle, PackageBundleV1, PackageImplementationV1, PackageRefV1,
        SqlModelV1,
    };
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 2_100_000_123);
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let mut model = sdk::Model::new(
        "identity",
        Vec::new(),
        vec![
            sdk::Port::new("result", schema.clone()),
            sdk::Port::new("body_clock", schema.clone()),
        ],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("input", schema.clone()),
        source: sdk::InputSource::Query(format!("SELECT source_cursor AS value FROM events WHERE received_at >= {BIN} AND received_at < {BIN} + INTERVAL '2 seconds'")),
    }, sdk::InputPort {
        port: sdk::Port::new("clock", schema.clone()),
        source: sdk::InputSource::Query("SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into()),
    }];
    model.parameters = schema.clone();
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("clock", schema)],
    });
    let image = PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: "window-model".into(),
            revision: "1".into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor: sdk::Package::new("window-model", "1", vec![model]),
            implementations: vec![PackageImplementationV1::Sql {
                export: "identity".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([
                        ("result".into(), "SELECT value FROM input".into()),
                        ("body_clock".into(), "SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into()),
                    ]),
                    checkpoint: BTreeMap::from([("clock".into(), "SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    };
    fixture.store.install_package_image(
        fixture.source.tenant_id,
        &PackageBundle::try_from(image)?,
        || Ok(()),
    )?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(20))?;
    let prepared = fixture
        .engine
        .prepare_definition(
            fixture.source.tenant_id,
            &Definition {
                name: "window-call".into(),
                description: "Retain the native input window.".into(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: r#"SELECT value, CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS observed FROM "window-model"."1".identity('result', value => CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED))"#.into(),
                    },
                },
            },
            Arc::new(control.within(None)?),
        )
        .await?;
    let clock = TestClock::new(2_500_000_000);
    let session = fixture.engine.session(fixture.selection(), &control, 0)?;
    let mut subscription = Subscription::new(
        session,
        Arc::new(prepared.plan.clone()),
        prepared.sources().clone(),
        b"window call",
        None,
        clock.clone(),
        true,
    )?;
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(1))]);
    let (&id, result) = first.calls.iter().next().ok_or("initial call")?;
    assert_eq!(result.evaluation().context.time_utc_ns, 2_500_000_000);
    let weak = Arc::downgrade(result);
    let window = result.evaluation().inputs[0]
        .revision
        .window
        .as_ref()
        .ok_or("input window")?;
    assert_eq!(
        (window.start_utc_ns, window.end_utc_ns),
        (2_000_000_000, 4_000_000_000)
    );
    assert_eq!(
        first.snapshot.windows[0].source,
        WindowSource::Input { call: id, slot: 0 }
    );
    drop(first);
    assert!(weak.upgrade().is_some());
    clock.set(7_500_000_000);
    let closed = next(&mut subscription).await;
    assert_eq!(closed.completed_windows.len(), 1);
    assert!(weak.upgrade().is_none());
    assert_eq!(closed.evaluated_utc_ns, 7_500_000_000);
    assert_eq!(closed.snapshot.time_utc_ns(), 7_500_000_000);
    assert_eq!(closed.cursor.evaluated(), 7_500_000_000);
    assert_eq!(
        values(&closed, 1),
        [ScalarValue::UInt64(Some(7_500_000_000))]
    );
    let call = &closed.calls[&id];
    assert_eq!(call.evaluation().context.time_utc_ns, 7_500_000_000);
    let window = call.evaluation().inputs[0]
        .revision
        .window
        .as_ref()
        .ok_or("closed input window")?;
    assert_eq!(
        (window.start_utc_ns, window.end_utc_ns),
        (2_000_000_000, 4_000_000_000)
    );
    for batch in [
        &call.evaluation().inputs[1].data.batches[0],
        call.evaluation()
            .parameters
            .as_ref()
            .ok_or("clock parameters")?,
        &call.output().datasets[1].batches[0],
        &call
            .output()
            .checkpoint
            .as_ref()
            .ok_or("clock checkpoint")?
            .datasets[0]
            .batches[0],
    ] {
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0)?,
            ScalarValue::UInt64(Some(7_500_000_000))
        );
    }
    assert_eq!(
        closed.calls[&id].evaluation().inputs[0].data.batches[0].num_rows(),
        1
    );
    drop(closed);
    let current = next(&mut subscription).await;
    assert!(weak.upgrade().is_none());
    assert!(current.completed_windows.is_empty());
    subscription.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn fixed_captures_pending_intake() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 2_100_000_123);
    let clock = TestClock::new(2_500_000_000);
    let mut subscription = fixture.subscribe(&sql(), clock.clone(), None, true);
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(1))]);
    clock.now.store(4_000_000_000, Ordering::SeqCst);
    fixture.commit(&fixture.source, 2, 1, 3_900_000_123);
    let final_cut = next(&mut subscription).await;
    assert_eq!(final_cut.completed_windows, first.snapshot.windows);
    assert_eq!(values(&final_cut, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(final_cut.snapshot.windows, first.snapshot.windows);
    assert_eq!(final_cut.evaluated_utc_ns, 4_000_000_000);
    let current = next(&mut subscription).await;
    assert_eq!(values(&current, 0), [ScalarValue::Int64(Some(0))]);
    assert!(current.completed_windows.is_empty());
    assert!(futures_util::poll!(subscription.next()).is_pending());
    subscription.cancel_and_join().await.unwrap();
}

#[tokio::test]
async fn fixed_ports_close_independently() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::definition::PackageCall;
    use araphor_analysis_sdk as sdk;
    use araphor_discovery_definition::{Definition, Program, Source};
    use araphor_package::{
        PackageArtifactV1, PackageBundle, PackageBundleV1, PackageImplementationV1, PackageRefV1,
        SqlModelV1,
    };
    use sdk::arrow_array::Array as _;

    let rows = |input: &sdk::Input| -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
        let mut rows = Vec::new();
        for batch in &input.data.batches {
            let values = batch
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("window input UInt64")?;
            assert_eq!(values.null_count(), 0);
            rows.extend_from_slice(values.values());
        }
        Ok(rows)
    };
    for (nested, reopen) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = Fixture::new(Limits::default());
        fixture.commit(&fixture.source, 1, 1, 2_100_000_123);
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut model = sdk::Model::new(
            "combine",
            Vec::new(),
            vec![
                sdk::Port::new("result", schema.clone()),
                sdk::Port::new("body_clock", schema.clone()),
            ],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = [("first", "2 seconds"), ("second", "5 seconds")].map(|(name, width)| {
            let bin = format!("date_bin(INTERVAL '{width}', CURRENT_TIMESTAMP, TIMESTAMP '1970-01-01')");
            sdk::InputPort {
                port: sdk::Port::new(name, schema.clone()),
                source: sdk::InputSource::Query(format!("SELECT source_cursor AS value FROM events WHERE received_at >= {bin} AND received_at < {bin} + INTERVAL '{width}' ORDER BY source_cursor")),
            }
        }).into();
        model.inputs.push(sdk::InputPort {
            port: sdk::Port::new("clock", schema.clone()),
            source: sdk::InputSource::Query(
                "SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into(),
            ),
        });
        let mut models = vec![model];
        let mut implementations = vec![PackageImplementationV1::Sql {
            export: "combine".into(),
            program: SqlModelV1 { outputs: BTreeMap::from([
                ("result".into(), "SELECT value FROM first UNION ALL SELECT value FROM second".into()),
                ("body_clock".into(), "SELECT CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED) AS value".into()),
            ]), ..Default::default() },
        }];
        if nested {
            models.push(sdk::Model::new(
                "wrapped",
                vec![sdk::Port::new("source", schema.clone())],
                vec![sdk::Port::new("result", schema)],
            ));
            implementations.push(PackageImplementationV1::Sql {
                export: "wrapped".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
                    ..Default::default()
                },
            });
        }
        let image = PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "window-scopes".into(),
                revision: "1".into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("window-scopes", "1", models),
                implementations,
                fixtures: Vec::new(),
            }],
        };
        fixture.store.install_package_image(
            fixture.source.tenant_id,
            &PackageBundle::try_from(image)?,
            || Ok(()),
        )?;
        let sql = if nested {
            format!(
                r#"SELECT * FROM "window-scopes"."1".wrapped(source => (
                SELECT e.value FROM (SELECT source_cursor AS value FROM events WHERE received_at >= {BIN} AND received_at < {BIN} + INTERVAL '2 seconds') e
                CROSS JOIN "window-scopes"."1".combine('result') r))"#
            )
        } else {
            r#"SELECT * FROM "window-scopes"."1".combine('result')"#.into()
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(20))?;
        let prepared = fixture
            .engine
            .prepare_definition(
                fixture.source.tenant_id,
                &Definition {
                    name: "fixed-scopes".into(),
                    description: "Keep each fixed input interval.".into(),
                    labels: BTreeMap::new(),
                    program: Program::Sql {
                        source: Source::Inline { inline: sql },
                    },
                },
                Arc::new(control.within(None)?),
            )
            .await?;
        let mut id = None;
        PackageCall::any(&prepared.plan, &mut |call| {
            if call.export() == "combine" {
                id = Some(call.id());
            }
            Ok(false)
        })?;
        let id = id.ok_or("window combine call")?;
        let clock = TestClock::new(2_500_000_000);
        let session = fixture.engine.session(fixture.selection(), &control, 0)?;
        let mut subscription = Subscription::new(
            session,
            Arc::new(prepared.plan.clone()),
            prepared.sources().clone(),
            b"fixed scopes",
            None,
            clock.clone(),
            true,
        )?;
        let first = next(&mut subscription).await;
        assert_eq!(rows(&first.calls[&id].evaluation().inputs[0])?, [1]);
        assert_eq!(rows(&first.calls[&id].evaluation().inputs[1])?, [1]);
        clock.now.store(7_500_000_000, Ordering::SeqCst);
        fixture.commit(&fixture.source, 2, 1, 4_100_000_123);
        fixture.commit(&fixture.source, 3, 1, 6_100_000_123);
        let fence = fixture.store.meta()?;
        let closed_first = next(&mut subscription).await;
        if reopen {
            let resume = Cursor::decode(&closed_first.cursor.encode()?)?;
            subscription.cancel_and_join().await?;
            let control = AnalysisReadControl::with_timeout(Duration::from_secs(20))?;
            let saved = closed_first
                .snapshot
                .windows
                .iter()
                .find(|window| window.source == WindowSource::Input { call: id, slot: 1 })
                .copied()
                .ok_or("saved second window")?;
            for fault in 0..4 {
                let mut invalid = saved;
                match fault {
                    0 => {
                        invalid.source = WindowSource::Input {
                            call: u64::MAX,
                            slot: 1,
                        }
                    }
                    1 => {
                        invalid.source = WindowSource::Input {
                            call: id,
                            slot: usize::MAX,
                        }
                    }
                    2 => invalid.start_utc_ns += 1,
                    _ => invalid.end_utc_ns += 1,
                }
                let mut cursor = resume.clone();
                cursor.set_windows(&[invalid], &[]);
                let error = Subscription::new(
                    fixture.engine.session(fixture.selection(), &control, 0)?,
                    Arc::new(prepared.plan.clone()),
                    prepared.sources().clone(),
                    b"fixed scopes",
                    Some(cursor),
                    clock.clone(),
                    true,
                )
                .err()
                .ok_or("foreign retained window accepted")?;
                assert!(matches!(
                    error,
                    crate::Error::Invalid {
                        field: "cursor window",
                        ..
                    }
                ));
                assert_eq!(fixture.store.meta()?, fence);
            }
            subscription = Subscription::new(
                fixture.engine.session(fixture.selection(), &control, 0)?,
                Arc::new(prepared.plan.clone()),
                prepared.sources().clone(),
                b"fixed scopes",
                Some(resume),
                clock.clone(),
                true,
            )?;
        }
        let closed_second = next(&mut subscription).await;
        for (update, expected_end, first_rows, expected_first) in [
            (
                &closed_first,
                4_000_000_000,
                vec![1],
                (2_000_000_000, 4_000_000_000),
            ),
            (
                &closed_second,
                5_000_000_000,
                vec![3],
                (6_000_000_000, 8_000_000_000),
            ),
        ] {
            assert_eq!(update.evaluated_utc_ns, 7_500_000_000);
            assert_eq!(update.snapshot.time_utc_ns(), 7_500_000_000);
            assert_eq!(update.cursor.evaluated(), 7_500_000_000);
            assert!(!update.completed_windows.is_empty());
            assert!(update
                .completed_windows
                .iter()
                .all(|window| window.end_utc_ns == expected_end));
            assert!(update.completed_windows.iter().any(|window| window.source
                == WindowSource::Input {
                    call: id,
                    slot: usize::from(expected_end == 5_000_000_000)
                }));
            let call = &update.calls[&id];
            assert_eq!(rows(&call.evaluation().inputs[0])?, first_rows);
            assert_eq!(rows(&call.evaluation().inputs[1])?, [1, 2]);
            assert_eq!(rows(&call.evaluation().inputs[2])?, [7_500_000_000]);
            for (input, expected) in call.evaluation().inputs.iter().zip([
                Some(expected_first),
                Some((0, 5_000_000_000)),
                None,
            ]) {
                assert_eq!(
                    input
                        .revision
                        .window
                        .as_ref()
                        .map(|window| (window.start_utc_ns, window.end_utc_ns)),
                    expected
                );
            }
            assert_eq!(
                ScalarValue::try_from_array(call.output().datasets[1].batches[0].column(0), 0)?,
                ScalarValue::UInt64(Some(7_500_000_000))
            );
            assert_eq!(update.calls.len(), if nested { 2 } else { 1 });
            for call in update.calls.values() {
                assert_eq!(call.evaluation().context.time_utc_ns, 7_500_000_000);
            }
            assert_eq!(fixture.store.meta()?, fence);
        }
        for (snapshot, expected) in [
            (&closed_first.snapshot, vec![1, 2]),
            (&closed_second.snapshot, vec![1, 2, 3]),
        ] {
            let mut cursors = snapshot
                .witnesses
                .iter()
                .map(|witness| witness.cursor)
                .collect::<Vec<_>>();
            cursors.sort_unstable();
            assert_eq!(cursors, expected);
        }
        let current = next(&mut subscription).await;
        let call = &current.calls[&id];
        assert_eq!(rows(&call.evaluation().inputs[0])?, [3]);
        assert_eq!(rows(&call.evaluation().inputs[1])?, [3]);
        assert!(current.completed_windows.is_empty());
        assert!(futures_util::poll!(subscription.next()).is_pending());
        PackageCall::check_admission(&prepared.plan)?;
        drop((first, closed_first, closed_second, current, prepared));
        subscription.cancel_and_join().await?;
        assert_eq!(fixture.engine.memory().input_reserved(), 0);
    }
    Ok(())
}
