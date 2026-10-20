use std::time::Duration;

use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};

use super::*;

#[tokio::test]
async fn operation_qualified_inputs() -> TestResult {
    let mut expected = None;
    for qualified in [false, true] {
        let port = |name| sdk::Port::new(name, Fixture::schema("value"));
        let mut model = sdk::Model::new("count", Vec::new(), vec![port("result"), port("other")]);
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = [("catalog", 7), ("second", 9)]
            .into_iter()
            .map(|(name, value)| sdk::InputPort {
                port: port(name),
                source: sdk::InputSource::Query(format!(
                    "SELECT CAST({value} AS BIGINT UNSIGNED) AS value FROM catalog LIMIT 1"
                )),
            })
            .collect();
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([
                    (
                        "result".into(),
                        format!(
                            "SELECT value FROM {}catalog",
                            if qualified { "public." } else { "" }
                        ),
                    ),
                    (
                        "other".into(),
                        format!(
                            "SELECT value FROM {}second",
                            if qualified { "datafusion.public." } else { "" }
                        ),
                    ),
                ]),
                ..Default::default()
            },
        );
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        let prepared = fixture
            .prepare(&Fixture::sql(
                r#"SELECT * FROM "fixture"."r1".count('result')"#,
            ))
            .await?;
        let output = fixture.execute(&prepared, invocation("qualified")).await?;
        assert_eq!(values(&output.batches)?, [7]);
        assert_eq!(output.calls.len(), 1);
        let call = output.calls.values().next().ok_or("qualified call")?;
        assert_eq!(call.evaluation().inputs.len(), 2);
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, [7]);
        assert_eq!(values(&call.evaluation().inputs[1].data.batches)?, [9]);
        assert_eq!(call.output().datasets.len(), 2);
        assert_eq!(values(&dataset(call, "result")?.batches)?, [7]);
        assert_eq!(values(&dataset(call, "other")?.batches)?, [9]);
        assert!(call.output().evidence.is_empty());
        assert!(call.output().reasons.is_empty());
        assert!(call.output().checkpoint.is_none());
        let package = &image.artifacts[0].descriptor;
        let inputs = call
            .evaluation()
            .inputs
            .iter()
            .zip(&package.exports[0].inputs)
            .map(|(input, port)| {
                Ok(sdk::wire::Input {
                    data: sdk::wire::Dataset::encode(
                        &input.data,
                        &port.port.schema,
                        package.exports[0].limits,
                    )?,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        let actual = (
            inputs,
            sdk::wire::Output::encode(package, call.evaluation(), call.output())?,
            output
                .snapshot
                .selection
                .source_revisions(output.snapshot.page.extraction.meta.commit_revision),
            output.snapshot.contexts().cloned().collect::<Vec<_>>(),
            output.snapshot.results().cloned().collect::<Vec<_>>(),
            output.snapshot.witnesses.clone(),
        );
        if let Some(expected) = &expected {
            assert_eq!(expected, &actual);
        } else {
            expected = Some(actual);
        }
        drop(output);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn reused_session_deadline() -> TestResult {
    let fixture = Fixture::limits(capacity_limits())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let prepared = session
        .prepare_definition(&Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value"))
        .await?;
    let output = session
        .execute_definition(&prepared, invocation("before-deadline"))
        .await?;
    assert_eq!(values(&output.batches)?, [7]);
    drop(output);
    session.set_timeout(Duration::from_millis(1))?;
    session.control().expired().await;
    let error = session
        .execute_definition(&prepared, invocation("after-deadline"))
        .await
        .err()
        .ok_or("reused session ignored its shorter deadline")?;
    assert!(
        matches!(
            &error,
            crate::Error::Data {
                source: araphor_data::Error::AnalysisReadDeadline { .. }
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::DeadlineExceeded
    );
    control.check()?;
    drop((session, prepared));
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn operation_scope_rejections() -> TestResult {
    for sql in [
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT * FROM source; DROP TABLE source",
        "SELECT * FROM absent",
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM catalog",
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM datafusion.public.catalog",
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM _query_catalog()",
        "SELECT value FROM \"araphor:port:0\"",
        "WITH unused AS (SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM catalog) SELECT value FROM source",
        "WITH unused AS (SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM _query_catalog()) SELECT value FROM source",
        "WITH unused AS (SELECT value FROM output_result) SELECT value FROM source",
    ] {
        let mut model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("result", Fixture::schema("value"))]);
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![sdk::InputPort {
            port: sdk::Port::new("source", Fixture::schema("value")),
            source: sdk::InputSource::Query("SELECT CAST(7 AS BIGINT UNSIGNED) AS value FROM catalog LIMIT 1".into()),
        }];
        let image = bundle(model, SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), sql.into())]),
            ..Default::default()
        });
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        let before = fixture.engine.store().meta()?;
        let error = fixture.prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await.err().ok_or_else(|| format!("undeclared body source admitted: {sql}"))?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery, "{sql}: {error:?}");
        assert_eq!(error.status_code(), StatusCode::InvalidArguments, "{sql}: {error:?}");
        assert_eq!(error.retry_hint(), RetryHint::NonRetryable, "{sql}: {error:?}");
        assert_eq!(fixture.engine.store().meta()?, before);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn pruned_revision_equivalence() -> TestResult {
    let mut revisions = Vec::new();
    let mut witnesses = Vec::new();
    for (sql, expected) in [
        ("SELECT CAST(operation AS BIGINT UNSIGNED) AS value FROM events WHERE operation = 7", vec![7]),
        ("SELECT CAST(operation AS BIGINT UNSIGNED) AS value FROM events WHERE operation = 7 AND false", vec![]),
        ("WITH unused AS (SELECT operation FROM events) SELECT CAST(7 AS BIGINT UNSIGNED) AS value", vec![7]),
    ] {
        let mut model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("result", Fixture::schema("value"))]);
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![sdk::InputPort {
            port: sdk::Port::new("source", Fixture::schema("value")),
            source: sdk::InputSource::Query(sql.into()),
        }];
        let image = bundle(model, SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
            ..Default::default()
        });
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        for (cursor, operation) in [(1, 9), (2, 7)] {
            let payload = araphor_data::EvidenceRecord { operation, ..Default::default() }.encode_to_vec();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&payload);
            frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
            fixture.engine.store().accept_validated_batch(
                araphor_data::EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16], node_id: "call-input".into(), node_boot_id: [2; 16],
                    label_epoch: 1, source_id: [3; 16], source_epoch: 1,
                },
                araphor_data::ValidatedEvidenceBatchV1 {
                    cpu_id: 0, first_cursor: cursor, last_cursor: cursor,
                    intake_utc_ns: NOW - 1_000_000 + cursor, frame_ends: vec![frame.len()], framed_records: frame.into(),
                },
            )?;
        }
        let prepared = fixture.prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#)).await?;
        let output = fixture.execute(&prepared, invocation("pruned-evidence")).await?;
        let call = output.calls.values().next().ok_or("pruned call")?;
        assert_eq!(values(&call.evaluation().inputs[0].data.batches)?, expected);
        assert_eq!(values(&output.batches)?, expected);
        assert_eq!(output.snapshot.witnesses.iter().map(|witness| witness.cursor).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(output.snapshot.page.extraction.sources.len(), 1);
        assert_eq!(output.snapshot.page.extraction.sources[0].receipt.contiguous_cursor, 2);
        revisions.push(call.evaluation().inputs[0].revision.clone());
        witnesses.push(output.snapshot.witnesses.clone());
        drop(output);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    assert_ne!(revisions[0], revisions[1]);
    assert_eq!(revisions[0], revisions[2]);
    assert_eq!(witnesses[0], witnesses[1]);
    assert_eq!(witnesses[0], witnesses[2]);
    Ok(())
}

#[tokio::test]
async fn named_alias_revision() -> TestResult {
    let schema = Fixture::schema("source_cursor");
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("selected", schema.clone()),
            source: sdk::InputSource::Query(
                "SELECT source_cursor FROM \"activity-log\" WHERE false".into(),
            ),
        },
        sdk::InputPort {
            port: sdk::Port::new("activity-log", schema),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ];
    let image = bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT source_cursor FROM \"activity-log\"".into(),
            )]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let mut previous = None;
    for cursor in 1..=2 {
        fixture.event(cursor)?;
        let output = fixture
            .execute(&prepared, invocation("named-alias"))
            .await?;
        assert_eq!(output.calls.len(), 1);
        let call = output.calls.values().next().ok_or("alias call")?;
        let input = &call.evaluation().inputs[0];
        assert_eq!(input.data.name, "selected");
        assert_eq!(
            input
                .data
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            0
        );
        assert!(!output
            .snapshot
            .selection
            .source_revisions(output.snapshot.page.extraction.meta.commit_revision)
            .is_empty());
        assert_eq!(output.snapshot.witnesses.len(), cursor as usize);
        assert_eq!(
            output.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            cursor
        );
        if let Some(previous) = previous {
            assert_ne!(input.revision, previous);
        }
        previous = Some(input.revision.clone());
        assert_eq!(values(&output.batches)?, (1..=cursor).collect::<Vec<_>>());
    }
    drop(prepared);
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn declared_port_case() -> TestResult {
    for (name, source, accepted) in [
        ("events", "SELECT relation FROM events", true),
        ("EVENTS", "SELECT relation FROM events", false),
        ("EVENTS", "SELECT relation FROM \"EVENTS\"", true),
    ] {
        let schema = sdk::Schema::new(vec![sdk::Field::new(
            "relation",
            sdk::DataType::Utf8,
            false,
        )]);
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![
            sdk::InputPort {
                port: sdk::Port::new(name, schema.clone()),
                source: sdk::InputSource::Table(sdk::TableRef::Named("catalog".into())),
            },
            sdk::InputPort {
                port: sdk::Port::new("selected", schema),
                source: sdk::InputSource::Query(source.into()),
            },
        ];
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT CAST(1 AS BIGINT UNSIGNED) AS value FROM selected".into(),
                )]),
                ..Default::default()
            },
        );
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        fixture.event(1)?;
        let result = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await;
        if accepted {
            let prepared = result?;
            let output = fixture
                .execute(&prepared, invocation("case-sensitive"))
                .await?;
            let call = output.calls.values().next().ok_or("case call")?;
            let inputs = &call.evaluation().inputs;
            assert_eq!(inputs[0].data.name, name);
            assert_eq!(inputs[0].data.batches, inputs[1].data.batches);
            assert!(!inputs[0].data.batches.is_empty());
            assert!(output.snapshot.witnesses.is_empty());
            assert!(output
                .snapshot
                .selection
                .source_revisions(output.snapshot.page.extraction.meta.commit_revision)
                .is_empty());
            assert!(output.snapshot.page.extraction.sources.is_empty());
            drop(output);
            drop(prepared);
        } else {
            let error = result.err().ok_or("unquoted input changed case")?;
            assert_eq!(crate::Failure::from(&error), crate::Failure::InvalidQuery);
        }
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn reordered_input_provenance() -> TestResult {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("zrows", Fixture::schema("value")),
            source: sdk::InputSource::Query("SELECT source_cursor AS value FROM \"ZRows\"".into()),
        },
        sdk::InputPort {
            port: sdk::Port::new("selected", Fixture::schema("value")),
            source: sdk::InputSource::Query("WITH unused AS (SELECT ordinal FROM \"arows\") SELECT source_cursor AS value FROM \"ZRows\"".into()),
        },
        sdk::InputPort {
            port: sdk::Port::new("arows", sdk::Schema::new(vec![sdk::Field::new("ordinal", sdk::DataType::UInt32, false)])),
            source: sdk::InputSource::Table(sdk::TableRef::Named("catalog".into())),
        },
        sdk::InputPort {
            port: sdk::Port::new("ZRows", Fixture::schema("source_cursor")),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ];
    let mut expected: Option<BTreeMap<String, sdk::wire::Input>> = None;
    let mut receipts = None;
    for indices in [&[0, 1, 2, 3][..], &[3, 0, 2, 1][..], &[3, 2, 1][..]] {
        let mut declared = model.clone();
        declared.inputs = indices
            .iter()
            .map(|index| model.inputs[*index].clone())
            .collect();
        let image = bundle(
            declared.clone(),
            SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), "SELECT value FROM selected".into())]),
                ..Default::default()
            },
        );
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        fixture.event(1)?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let admitted = prepared.resolved().clone();
        let sources = prepared.sources().clone();
        let retained = fixture.engine.memory().input_reserved();
        let output = fixture
            .execute(&prepared, invocation("ordered-provenance"))
            .await?;
        assert_eq!(prepared.resolved(), &admitted);
        assert_eq!(prepared.sources(), &sources);
        assert_eq!(output.calls.len(), 1);
        assert_eq!(values(&output.batches)?, [1]);
        let call = output.calls.values().next().ok_or("ordered call")?;
        let inputs = &call.evaluation().inputs;
        assert_eq!(
            inputs
                .iter()
                .map(|input| &input.data.name)
                .collect::<Vec<_>>(),
            declared
                .inputs
                .iter()
                .map(|input| &input.port.name)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(
                &inputs
                    .iter()
                    .find(|input| input.data.name == "selected")
                    .ok_or("selected input")?
                    .data
                    .batches
            )?,
            [1]
        );
        let actual = inputs
            .iter()
            .map(|input| {
                let port = declared
                    .inputs
                    .iter()
                    .find(|port| port.port.name == input.data.name)
                    .ok_or("declared input")?;
                Ok((
                    input.data.name.clone(),
                    sdk::wire::Input {
                        data: sdk::wire::Dataset::encode(
                            &input.data,
                            &port.port.schema,
                            declared.limits,
                        )?,
                        revision: input.revision.clone(),
                        coverage: input.coverage.clone(),
                    },
                ))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        assert_ne!(actual["ZRows"].revision, actual["arows"].revision);
        if let Some(expected) = &expected {
            if indices.contains(&0) {
                assert_eq!(expected, &actual);
            } else {
                for (name, input) in &actual {
                    assert_eq!(&expected[name], input);
                }
            }
        } else {
            expected = Some(actual);
        }
        let metadata = (
            output
                .snapshot
                .selection
                .source_revisions(output.snapshot.page.extraction.meta.commit_revision),
            output.snapshot.results().cloned().collect::<Vec<_>>(),
            output.snapshot.witnesses.clone(),
            output.snapshot.contexts().cloned().collect::<Vec<_>>(),
        );
        assert!(!metadata.0.is_empty());
        assert_eq!(
            metadata
                .2
                .iter()
                .map(|witness| witness.cursor)
                .collect::<Vec<_>>(),
            [1]
        );
        if let Some(receipts) = &receipts {
            assert_eq!(receipts, &metadata);
        } else {
            receipts = Some(metadata);
        }
        drop(output);
        assert_eq!(fixture.engine.memory().input_reserved(), retained);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn operation_error_classes() -> TestResult {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema("value")),
        source: sdk::InputSource::Query(
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value FROM catalog LIMIT 1".into(),
        ),
    }];
    let image = bundle(
        model.clone(),
        SqlModelV1 {
            outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
            ..Default::default()
        },
    );
    let fixture = Fixture::limits(capacity_limits())?;
    fixture.install(&image)?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
        .await?;
    let retained = fixture.engine.memory().input_reserved();
    let before = fixture.engine.store().meta()?;
    let missing = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."absent".count()"#))
        .await
        .err()
        .ok_or("missing image admitted")?;
    assert_eq!(
        crate::Failure::from(&missing),
        crate::Failure::StorageUnavailable
    );
    assert_eq!(missing.status_code(), StatusCode::NotFound);
    assert_eq!(missing.retry_hint(), RetryHint::NonRetryable);
    for stage in ["evaluation", "input", "output"] {
        let permit = (stage == "evaluation")
            .then(|| fixture.engine.reserve_evaluation([1; 16]))
            .transpose()?;
        let pressure = match stage {
            "input" => Some(
                fixture.engine.memory().reserve_input(
                    fixture
                        .engine
                        .limits()
                        .input_capacity
                        .ok_or("input capacity")?
                        - retained,
                )?,
            ),
            "output" => Some(
                fixture.engine.memory().reserve_output(
                    fixture
                        .engine
                        .limits()
                        .output_capacity
                        .ok_or("output capacity")?,
                )?,
            ),
            _ => None,
        };
        let error = fixture
            .execute(&prepared, invocation(stage))
            .await
            .err()
            .ok_or("operation ignored pressure")?;
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::Busy,
            "{stage}: {error:?}"
        );
        assert_eq!(
            error.status_code(),
            StatusCode::Unavailable,
            "{stage}: {error:?}"
        );
        assert_eq!(
            error.retry_hint(),
            RetryHint::Retryable,
            "{stage}: {error:?}"
        );
        drop((pressure, permit));
        assert_eq!(
            fixture.engine.memory().input_reserved(),
            retained,
            "{stage}"
        );
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        drop(
            fixture.engine.memory().reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .ok_or("output capacity")?,
            )?,
        );
    }
    let output = fixture
        .execute(&prepared, invocation("pressure-released"))
        .await?;
    assert_eq!(values(&output.batches)?, [7]);
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(output);
    drop(prepared);
    capacity_released(&fixture)?;

    for (source, fixed) in [
        (
            "SELECT CAST(relation AS BIGINT UNSIGNED) AS value FROM catalog LIMIT 1",
            false,
        ),
        (
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value FROM catalog LIMIT 1",
            true,
        ),
    ] {
        let mut model = model.clone();
        model.inputs[0].source = sdk::InputSource::Query(source.into());
        if fixed {
            model.limits.max_bytes = 1;
        }
        let image = bundle(
            model,
            SqlModelV1 {
                outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
                ..Default::default()
            },
        );
        let fixture = Fixture::limits(capacity_limits())?;
        fixture.install(&image)?;
        let prepared = fixture
            .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".count()"#))
            .await?;
        let before = fixture.engine.store().meta()?;
        let error = fixture
            .execute(&prepared, invocation("input-failure"))
            .await
            .err()
            .ok_or("invalid input was accepted")?;
        if fixed {
            assert_eq!(
                crate::Failure::from(&error),
                crate::Failure::InputTooLarge,
                "{error:?}"
            );
            assert_eq!(error.status_code(), StatusCode::InvalidArguments);
            assert_eq!(error.retry_hint(), RetryHint::NonRetryable);
        }
        assert_eq!(fixture.engine.store().meta()?, before);
        drop(prepared);
        capacity_released(&fixture)?;
    }
    Ok(())
}
