use std::time::Duration;

use sdk::arrow_array::Int64Array;

use super::*;

#[tokio::test]
async fn model_state_provenance() -> TestResult {
    for mode in ["prior", "output", "bad-evidence"] {
        let input = sdk::Port::new("events", Fixture::schema("id"));
        let mut result = sdk::Port::new("counts", Fixture::schema("count"));
        result.evidence_required = true;
        let mut model = sdk::Model::new("count", vec![input], vec![result]);
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", Fixture::schema("count"))],
        });
        model.reasons = vec![
            sdk::Reason {
                code: "fixture.repeated".into(),
                details: Fixture::schema("count"),
            },
            sdk::Reason {
                code: "fixture.empty".into(),
                details: sdk::Schema::empty(),
            },
        ];
        let image = bundle(model, SqlModelV1 {
            outputs: BTreeMap::from([("counts".into(), "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS count FROM events".into())]),
            checkpoint: BTreeMap::from([("state".into(), format!("SELECT count FROM {}", if mode == "output" { "output_counts" } else { "prior_state" }))]),
            evidence: Some(format!("SELECT 'counts' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'events' AS input_dataset, {} AS input_row FROM events", if mode == "bad-evidence" { "CAST(99 AS BIGINT UNSIGNED)" } else { "__row_index" })),
            reasons: vec![
                SqlReasonV1 { output: "counts".into(), code: "fixture.repeated".into(), sql: "SELECT __row_index AS output_row, count FROM output_counts".into() },
                SqlReasonV1 { output: "counts".into(), code: "fixture.empty".into(), sql: "SELECT __row_index AS output_row FROM output_counts".into() },
            ],
        });
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        let mut session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        let rows = sdk::RecordBatch::try_new(
            Arc::new(Fixture::schema("id")),
            vec![Arc::new(UInt64Array::from(vec![1, 2, 3]))],
        )?;
        session.register("model_rows", rows.schema(), std::slice::from_ref(&rows))?;
        let prepared = session.prepare_definition(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count('counts', events => (SELECT id FROM model_rows))"#)).await?;
        let id = Fixture::calls(&prepared.plan)?[0].id();
        let mut request = invocation("model-state");
        request.checkpoints.insert(
            id,
            sdk::Checkpoint {
                version: 1,
                datasets: vec![sdk::Dataset {
                    name: "state".into(),
                    batches: vec![sdk::RecordBatch::try_new(
                        Arc::new(Fixture::schema("count")),
                        vec![Arc::new(UInt64Array::from(vec![9]))],
                    )?],
                }],
            },
        );
        let before = fixture.engine.store().meta()?;
        let result = session.execute_definition(&prepared, request).await;
        if mode == "bad-evidence" {
            assert!(result.is_err(), "invalid input evidence row was accepted");
        } else {
            let output = result?;
            assert_eq!(values(&output.batches)?, [3]);
            assert_eq!(output.calls.len(), 1);
            let call = &output.calls[&id];
            assert_eq!(
                values(&call.evaluation().inputs[0].data.batches)?,
                [1, 2, 3]
            );
            assert_eq!(values(&dataset(call, "counts")?.batches)?, [3]);
            let state = call.output().checkpoint.as_ref().ok_or("model state")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(
                values(&state.datasets[0].batches)?,
                [if mode == "output" { 3 } else { 9 }]
            );
            assert_eq!(call.output().evidence.len(), 3);
            for (row, link) in call.output().evidence.iter().enumerate() {
                assert_eq!(link.output.dataset, "counts");
                assert_eq!(link.output.row, 0);
                assert_eq!(link.input.dataset, "events");
                assert_eq!(link.input.row, row as u64);
            }
            assert_eq!(call.output().reasons.len(), 2);
            assert_eq!(call.output().reasons[0].code, "fixture.repeated");
            assert_eq!(
                values(std::slice::from_ref(&call.output().reasons[0].details))?,
                [3]
            );
            let reason = &call.output().reasons[1];
            assert_eq!(reason.code, "fixture.empty");
            assert_eq!(reason.output.dataset, "counts");
            assert_eq!(reason.output.row, 0);
            assert_eq!(
                (reason.details.num_columns(), reason.details.num_rows()),
                (0, 1)
            );
            let packet = sdk::wire::Output::encode(
                &image.artifacts[0].descriptor,
                call.evaluation(),
                call.output(),
            )?;
            let decoded = packet.decode(&image.artifacts[0].descriptor, call.evaluation())?;
            assert_eq!(decoded.reasons[1].details.num_rows(), 1);
        }
        assert_eq!(fixture.engine.store().meta()?, before);
        drop((prepared, session, rows));
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn model_scalar_boundaries() -> TestResult {
    let schema = sdk::Schema::new(vec![
        sdk::Field::new("unsigned", sdk::DataType::UInt64, false),
        sdk::Field::new("signed", sdk::DataType::Int64, false),
        sdk::Field::new(
            "time",
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        sdk::Field::new("bytes", sdk::DataType::FixedSizeBinary(2), false),
    ]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.parameters = schema.clone();
    let image = bundle(model, SqlModelV1 {
        outputs: BTreeMap::from([("result".into(), "SELECT parameters.\"unsigned\", parameters.\"signed\", parameters.\"time\", parameters.\"bytes\" FROM parameters".into())]),
        ..Default::default()
    });
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let arguments = [
        (
            "unsigned",
            "CAST('18446744073709551615' AS BIGINT UNSIGNED)",
        ),
        ("signed", "CAST('-9223372036854775808' AS BIGINT)"),
        ("time", "TIMESTAMP '1969-12-31T23:59:59.999999999Z'"),
        ("bytes", "X'00ff'"),
    ];
    let source = |parts: Vec<String>| {
        Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count({})"#,
            parts.join(", ")
        ))
    };
    let prepared = fixture
        .prepare(&source(
            arguments
                .iter()
                .map(|(name, value)| format!("\"{name}\" => {value}"))
                .collect(),
        ))
        .await?;
    let output = fixture
        .execute(&prepared, invocation("scalar-boundary"))
        .await?;
    let expected = sdk::RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(UInt64Array::from(vec![u64::MAX])),
            Arc::new(Int64Array::from(vec![i64::MIN])),
            Arc::new(TimestampNanosecondArray::from(vec![-1]).with_timezone("UTC")),
            Arc::new(FixedSizeBinaryArray::try_from_iter(
                [[0_u8, 255]].into_iter(),
            )?),
        ],
    )?;
    assert_eq!(output.batches, vec![expected.clone()]);
    let call = output.calls.values().next().ok_or("scalar call")?;
    assert_eq!(
        call.evaluation()
            .parameters
            .as_ref()
            .ok_or("scalar parameters")?,
        &expected
    );
    assert_eq!(call.output().datasets[0].batches, vec![expected]);
    drop(output);
    let cancelled = AnalysisReadControl::default();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &cancelled, NOW)?;
    cancelled.cancel()?;
    assert!(session
        .execute_definition(&prepared, invocation("cancelled-scalar"))
        .await
        .is_err());
    drop((session, prepared));
    capacity_released(&fixture)?;
    for (field, replacement) in [
        ("unsigned", Some("-1")),
        (
            "unsigned",
            Some("CAST('18446744073709551616' AS BIGINT UNSIGNED)"),
        ),
        ("signed", Some("CAST('9223372036854775808' AS BIGINT)")),
        ("signed", Some("CAST('-9223372036854775809' AS BIGINT)")),
        ("time", Some("TIMESTAMP 'not-time'")),
        ("bytes", Some("X'00'")),
        ("unsigned", Some("NULL")),
        ("unsigned", None),
        ("unknown", Some("1")),
    ] {
        let mut parts = arguments
            .iter()
            .filter_map(|(name, value)| {
                (if *name == field {
                    replacement
                } else {
                    Some(*value)
                })
                .map(|value| format!("\"{name}\" => {value}"))
            })
            .collect::<Vec<_>>();
        if !arguments.iter().any(|(name, _)| *name == field) {
            parts.push(format!(
                "\"{field}\" => {}",
                replacement.ok_or("extra argument")?
            ));
        }
        let invalid = source(parts);
        let result = match fixture.prepare(&invalid).await {
            Ok(prepared) => fixture
                .execute(&prepared, invocation("invalid-scalar"))
                .await
                .map(|_| ()),
            Err(error) => Err(error),
        };
        assert!(
            result.is_err(),
            "invalid scalar admitted: {field}/{replacement:?}"
        );
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn model_relation_names() -> TestResult {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = [("InputRows", 7), ("INPUTROWS", 9)]
        .into_iter()
        .map(|(name, value)| sdk::InputPort {
            port: sdk::Port::new(name, Fixture::schema("value")),
            source: sdk::InputSource::Query(format!(
                "SELECT CAST({value} AS BIGINT UNSIGNED) AS value"
            )),
        })
        .collect();
    let mut image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT a.value + b.value AS value FROM \"InputRows\" a CROSS JOIN \"INPUTROWS\" b"
                    .into(),
            )]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let mut invalid = image.clone();
    invalid.artifacts[0].descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Query("SELECT missing FROM absent".into());
    let rejected = Fixture::limits(capacity_limits())?;
    rejected.install(&invalid)?;
    let before = rejected.engine.store().meta()?;
    assert!(rejected
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await
        .is_err());
    assert_eq!(rejected.engine.store().meta()?, before);
    capacity_released(&rejected)?;
    for duplicate in [false, true] {
        if duplicate {
            image.artifacts[0].descriptor.exports[0].inputs[1].port.name = "InputRows".into();
            let before = fixture.engine.store().meta()?;
            assert!(fixture.install(&image).is_err());
            assert_eq!(fixture.engine.store().meta()?, before);
        }
        let output = fixture
            .execute(&prepared, invocation("relation-names"))
            .await?;
        assert_eq!(values(&output.batches)?, [16]);
        let call = output.calls.values().next().ok_or("relation call")?;
        assert_eq!(
            call.evaluation()
                .inputs
                .iter()
                .map(|input| input.data.name.as_str())
                .collect::<Vec<_>>(),
            ["InputRows", "INPUTROWS"]
        );
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [7]);
        assert_eq!(values(&call.evaluation().inputs[1].data.batches)?, [9]);
    }
    drop(prepared);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn model_source_lifetimes() -> TestResult {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("events", Fixture::schema("id")),
        source: sdk::InputSource::Query(
            "SELECT source_cursor AS id FROM events ORDER BY source_cursor".into(),
        ),
    }];
    let image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM events".into(),
            )]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(Limits {
        output_rows: 1,
        ..capacity_limits()
    })?;
    fixture.install(&image)?;
    for cursor in 1..=3 {
        fixture.event(cursor)?;
    }
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    let first = session
        .execute_definition(&prepared, invocation("source-first"))
        .await?;
    let id = Fixture::calls(&prepared.plan)?[0].id();
    let input = &first.calls[&id].evaluation().inputs[0];
    assert_eq!(values(&input.data.batches)?, [1, 2, 3]);
    assert_eq!(values(&first.batches)?, [3]);
    assert_eq!(first.snapshot.witnesses.len(), 3);
    let revision = first.snapshot.page.extraction.meta.commit_revision;
    let sources = first.snapshot.selection.source_revisions(revision);
    for relation in [
        "events",
        "source_receipts",
        "coverage",
        "expired_ranges",
        "recovery_gaps",
    ] {
        assert!(sources.contains(&(relation.into(), revision)), "{relation}");
    }
    assert!(!sources.iter().any(|(name, _)| name == "analysis_results"));
    let second = fixture
        .engine
        .session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW + 1000,
        )?
        .execute_definition(&prepared, invocation("source-second"))
        .await?;
    assert_eq!(
        input.revision,
        second.calls[&id].evaluation().inputs[0].revision
    );
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.received_until = std::ops::Bound::Included(NOW - 1_000_000 + 2);
    let third = fixture
        .engine
        .session(selection, &AnalysisReadControl::default(), NOW + 1000)?
        .execute_definition(&prepared, invocation("source-bounded"))
        .await?;
    let bounded = &third.calls[&id].evaluation().inputs[0];
    assert_eq!(values(&bounded.data.batches)?, [1, 2]);
    assert_eq!(values(&third.batches)?, [2]);
    assert_ne!(input.revision, bounded.revision);
    assert_ne!(bounded.coverage.state, sdk::CoverageState::Complete);
    let alias = input.data.batches[0].column(0).slice(0, 1);
    drop((first, second, third, prepared, session));
    let capacity = fixture
        .engine
        .limits()
        .input_capacity
        .ok_or("input capacity")?;
    assert!(fixture.engine.memory().reserve_input(capacity).is_err());
    assert_eq!(
        alias
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("source alias")?
            .value(0),
        1
    );
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(alias);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn model_deadline_keeps_parent() -> TestResult {
    let fixture = Fixture::limits(Limits {
        evaluate_timeout: Some(Duration::from_millis(100)),
        ..capacity_limits()
    })?;
    let model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    fixture.install(&bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    ))?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let parent = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let bounded = parent.within(Duration::from_millis(1))?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &bounded, NOW)?;
    bounded.expired().await;
    let error = session
        .execute_definition(&prepared, invocation("expired-model"))
        .await
        .err()
        .ok_or("model deadline ignored")?;
    drop(session);
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::AnalysisReadDeadline { .. }
        }
    ));
    parent.check()?;
    let output = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &parent, NOW)?
        .execute_definition(&prepared, invocation("parent-model"))
        .await?;
    assert_eq!(values(&output.batches)?, [1]);
    assert_eq!(output.calls.len(), 1);
    parent.check()?;
    drop((output, prepared));
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn model_clock_children() -> TestResult {
    let clock = "CAST(CAST(CURRENT_TIMESTAMP AS BIGINT) AS BIGINT UNSIGNED)";
    for location in [None, Some(0), Some(1), Some(2), Some(3)] {
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![sdk::InputPort {
            port: sdk::Port::new("source", Fixture::schema("value")),
            source: sdk::InputSource::Query("SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into()),
        }];
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", Fixture::schema("value"))],
        });
        model.reasons.push(sdk::Reason {
            code: "fixture.expired".into(),
            details: sdk::Schema::empty(),
        });
        let mut program = SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(length('CURRENT_TIMESTAMP') AS BIGINT UNSIGNED) AS value".into(),
            )]),
            checkpoint: BTreeMap::from([(
                "state".into(),
                "SELECT value FROM output_result".into(),
            )]),
            ..Default::default()
        };
        match location {
            Some(0) => {
                program
                    .outputs
                    .insert("result".into(), format!("SELECT {clock} AS value"));
            }
            Some(1) => {
                program
                    .checkpoint
                    .insert("state".into(), format!("SELECT {clock} AS value"));
            }
            Some(2) => {
                program.evidence = Some("SELECT 'result' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source WHERE CURRENT_TIMESTAMP > TIMESTAMP '2000-01-01'".into());
            }
            Some(3) => {
                program.reasons.push(SqlReasonV1 { output: "result".into(), code: "fixture.expired".into(), sql: "SELECT __row_index AS output_row FROM output_result WHERE CURRENT_TIMESTAMP > TIMESTAMP '2000-01-01'".into() });
            }
            _ => {}
        }
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&bundle(model, program))?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let calls = Fixture::calls(&prepared.plan)?;
        let call = &calls[0];
        let children = call.inputs();
        assert!(!crate::inputs::Inputs::clocked(children[0])?);
        let body = children[1..]
            .iter()
            .map(|plan| crate::inputs::Inputs::clocked(plan))
            .collect::<crate::Result<Vec<_>>>()?;
        assert_eq!(body.into_iter().any(|value| value), location.is_some());
        assert_eq!(
            crate::follow::Window::clocks(&prepared.plan)? > 0,
            location.is_some()
        );
        let mut previous = None;
        for now in [NOW, NOW + 1_000_000_000] {
            let output = fixture
                .engine
                .session(
                    AnalysisSelectionV1::tenant([1; 16]),
                    &AnalysisReadControl::default(),
                    now,
                )?
                .execute_definition(&prepared, invocation("clock-child"))
                .await?;
            let call = output.calls.values().next().ok_or("clock call")?;
            assert_eq!(call.evaluation().context.time_utc_ns, now as i64);
            let expected = if location == Some(0) { now } else { 17 };
            assert_eq!(values(&output.batches)?, [expected]);
            let state = call.output().checkpoint.as_ref().ok_or("clock state")?;
            assert_eq!(
                values(&state.datasets[0].batches)?,
                [if location == Some(1) { now } else { expected }]
            );
            assert_eq!(
                call.output().evidence.len(),
                usize::from(location == Some(2))
            );
            assert_eq!(
                call.output().reasons.len(),
                usize::from(location == Some(3))
            );
            let revision = &call.evaluation().inputs[0].revision;
            if let Some(previous) = previous {
                assert_eq!(*revision, previous);
            }
            previous = Some(revision.clone());
        }
        drop(calls);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn model_input_clocks() -> TestResult {
    for clocked in [false, true] {
        let base = sdk::Model::new(
            "base",
            Vec::new(),
            vec![sdk::Port::new("rows", Fixture::schema("value"))],
        );
        let mut image = bundle(
            base,
            SqlModelV1 {
                outputs: BTreeMap::from([(
                    "rows".into(),
                    "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                ..Default::default()
            },
        );
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![
            sdk::InputPort {
                port: sdk::Port::new("source", Fixture::schema("value")),
                source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef { package: "fixture".into(), revision: "r1".into(), export: "base".into(), output: "rows".into() })),
            },
            sdk::InputPort {
                port: sdk::Port::new("selected", Fixture::schema("value")),
                source: sdk::InputSource::Query(if clocked {
                    "SELECT CASE WHEN CURRENT_TIMESTAMP IS NULL THEN CAST(0 AS BIGINT UNSIGNED) ELSE value END AS value FROM source"
                } else { "SELECT value + CAST(length('CURRENT_TIMESTAMP') AS BIGINT UNSIGNED) AS value FROM source" }.into()),
            },
        ];
        image.artifacts[0].descriptor.exports.push(model);
        image.artifacts[0]
            .implementations
            .push(PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "result".into(),
                        "SELECT value FROM selected".into(),
                    )]),
                    ..Default::default()
                },
            });
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let calls = Fixture::calls(&prepared.plan)?;
        let root = calls
            .iter()
            .find(|call| call.export() == "count")
            .ok_or("root call")?;
        let children = root.inputs();
        assert!(!crate::inputs::Inputs::clocked(children[0])?);
        assert_eq!(crate::inputs::Inputs::clocked(children[1])?, clocked);
        assert!(children[2..]
            .iter()
            .all(|plan| crate::follow::Window::clocks(plan).is_ok_and(|count| count == 0)));
        assert_eq!(crate::follow::Window::clocks(&prepared.plan)? > 0, clocked);
        let output = fixture
            .execute(&prepared, invocation("input-clock"))
            .await?;
        assert_eq!(values(&output.batches)?, [if clocked { 7 } else { 24 }]);
        assert_eq!(output.calls.len(), 2);
        let input = &output.calls[&root.id()].evaluation().inputs;
        assert_eq!(values(&input[0].data.batches)?, [7]);
        assert_eq!(
            values(&input[1].data.batches)?,
            [if clocked { 7 } else { 24 }]
        );
        drop((output, calls, prepared));
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_in_multithread() -> TestResult {
    super::admitted_order(Fixture::limits(capacity_limits())?).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_in_blocking() -> TestResult {
    let fixture = Fixture::limits(capacity_limits())?;
    let engine = Arc::clone(&fixture.engine);
    tokio::task::spawn_blocking(move || {
        engine.wait(async move { Ok(super::admitted_order(fixture).await) })
    })
    .await??
}
