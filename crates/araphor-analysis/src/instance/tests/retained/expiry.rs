use super::*;

use araphor_query::definition::{DefinitionOutput, PreparedDefinition};

const INPUT: usize = 4 * 1024 * 1024;
const OUTPUT: usize = 64 * 1024;
const EXPIRED: &str = "source evidence retention expired";

fn indexed_consumer() -> TestResult<PackageBundleV1> {
    let mut image = consumer("expiry")?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new(
            "indexed",
            sdk::Schema::new(vec![
                sdk::Field::new("value", sdk::DataType::UInt64, false),
                sdk::Field::new("row_index", sdk::DataType::UInt64, false),
            ]),
        ),
        source: sdk::InputSource::Query(
            "SELECT value, __row_index AS row_index FROM left_input".into(),
        ),
    });
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new("trusted", model.outputs[0].schema.clone()),
        source: sdk::InputSource::Table(sdk::TableRef::Named("trusted".into())),
    });
    Ok(image)
}

async fn expiry_producer(
    fixture: &Fixture,
) -> TestResult<(Arc<Instance>, PackageResultRefV1, u64)> {
    fixture.install(&bundle("sql")?)?;
    fixture.context(1)?;
    let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    fixture.query.store().accept_validated_batch(
        araphor_data::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "retained-expiry".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    let source = fixture
        .admit(
            "retained-source",
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (
        SELECT CAST(7 AS BIGINT UNSIGNED) AS value FROM events
        WHERE EXISTS (SELECT 1 FROM context_versions)))"#,
        )
        .await?;
    let mut step = request("expiry-source");
    step.time_utc_ns = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let expiry = step.time_utc_ns + 3_600_000_000_000;
    step.witness_expiry = expiry;
    let receipt = source.run(step, &AnalysisReadControl::default()).await?;
    assert_eq!(fixture.selected("retained-source", "expiry-source")?, [7]);
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("expiry source receipt")?
        .clone();
    Ok((source, reference, expiry))
}

fn call_inputs(output: &DefinitionOutput, first: u64) -> TestResult<&[sdk::Input]> {
    for call in output.calls.values() {
        let inputs = &call.evaluation().inputs;
        if values(&inputs[0].data.batches)? == [first] {
            return Ok(inputs);
        }
    }
    Err("expiry consumer call".into())
}

fn local_invocation(
    prepared: &PreparedDefinition,
    batch: &sdk::RecordBatch,
) -> TestResult<Invocation> {
    let mut request = invocation();
    PackageCall::any(&prepared.plan, &mut |call| {
        if call.package().package_id == "runtime-fixture" && call.export() == "accumulate" {
            request.inputs.insert(
                call.id(),
                vec![sdk::Input {
                    data: sdk::Dataset {
                        name: "input".into(),
                        batches: vec![batch.clone()],
                    },
                    revision: sdk::Revision {
                        owner: "external-local".into(),
                        id: "trusted-local".into(),
                        window: None,
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Complete,
                        limits: Vec::new(),
                    },
                }],
            );
        }
        Ok(false)
    })?;
    Ok(request)
}

#[tokio::test]
async fn retained_expiry_keeps_rows() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(INPUT),
        output_capacity: Some(OUTPUT),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&indexed_consumer()?)?;
    let (source, reference, expiry) = expiry_producer(&fixture).await?;
    let original = fixture.query.store().managed_result(
        source.admitted(),
        &reference.result_id,
        expiry - 1,
        &AnalysisReadControl::default(),
    )?;
    assert!(original.current);
    let coverage = original.context.coverage.clone();
    let (witnesses, contexts) = fixture
        .query
        .store()
        .package_evidence([1; 16], std::slice::from_ref(&reference.result_id))?;
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].expires_utc_ns, expiry);
    assert!(contexts.iter().any(|context| {
        context.key.owner_id == "instance-context" && context.key.owner_revision == 1
    }));
    let revision = sdk::Revision {
        owner: "runtime-fixture.accumulate".into(),
        id: format!("{}:{}", reference.result_id, reference.commit_revision),
        window: None,
    };
    let baseline = fixture.query.memory().input_reserved();
    let before = fixture.query.store().meta()?;
    let mut prior = None;
    for now in [expiry - 1, expiry, expiry + 1] {
        let control = AnalysisReadControl::default();
        let mut session = fixture
            .query
            .session(fixture.grant.selection.clone(), &control, now)?;
        let local = sdk::RecordBatch::try_new(
            Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::UInt64,
                false,
            )])),
            vec![Arc::new(UInt64Array::from(vec![9]))],
        )?;
        session.register("local_rows", local.schema(), std::slice::from_ref(&local))?;
        session
            .register_retained("saved", "retained-source", reference.clone(), "data")
            .await?;
        let prepared = session
            .prepare_definition(&Fixture::definition(
                r#"SELECT * FROM "retained-consumer"."expiry".echo(
                left_input => (SELECT value FROM saved),
                right_input => (SELECT source_cursor AS value FROM events),
                trusted => (SELECT * FROM "runtime-fixture"."1".accumulate(
                    input => (SELECT value FROM local_rows))))"#,
            ))
            .await?;
        let output = session
            .execute_definition(&prepared, local_invocation(&prepared, &local)?)
            .await?;
        assert_eq!(values(&output.batches)?, [7]);
        assert_eq!(output.calls.len(), 2);
        assert_eq!(output.snapshot.time_utc_ns(), now);
        assert_eq!(output.snapshot.results().collect::<Vec<_>>(), [&reference]);
        for witness in &witnesses {
            assert!(output.snapshot.witnesses.contains(witness));
        }
        for context in &contexts {
            assert!(output.snapshot.contexts().any(|actual| actual == context));
        }
        let call = output
            .calls
            .values()
            .find(|call| call.evaluation().export == "echo")
            .ok_or("expiry call")?;
        assert_eq!(call.evaluation().context.time_utc_ns, now as i64);
        let inputs = &call.evaluation().inputs;
        assert_eq!(
            inputs
                .iter()
                .map(|input| input.data.name.as_str())
                .collect::<Vec<_>>(),
            ["left_input", "right_input", "indexed", "trusted"]
        );
        assert_eq!(values(&inputs[0].data.batches)?, [7]);
        assert_eq!(values(&inputs[1].data.batches)?, [1]);
        assert_eq!(values(&inputs[2].data.batches)?, [7]);
        assert_eq!(values(&inputs[3].data.batches)?, [9]);
        assert_eq!(inputs[0].revision, revision);
        assert_ne!(inputs[2].revision, revision);
        for batch in &inputs[2].data.batches {
            let indices = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("expiry row indices")?;
            assert_eq!(indices.values().as_ref(), [0]);
        }
        if now < expiry {
            assert_eq!(inputs[0].coverage, coverage);
            assert_eq!(
                inputs[3].coverage,
                sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                }
            );
            prior = Some(
                inputs
                    .iter()
                    .map(|input| input.coverage.clone())
                    .collect::<Vec<_>>(),
            );
        } else {
            for (input, baseline) in inputs.iter().zip(prior.as_ref().ok_or("expiry baseline")?) {
                let mut expected = baseline.clone();
                expected.state = sdk::CoverageState::Unknown;
                expected.limits.push(EXPIRED.into());
                expected.limits.sort_unstable();
                expected.limits.dedup();
                assert_eq!(input.coverage, expected);
            }
        }
        for input in inputs {
            assert_eq!(
                input
                    .coverage
                    .limits
                    .iter()
                    .filter(|reason| reason.as_str() == EXPIRED)
                    .count(),
                usize::from(now >= expiry)
            );
        }
        let local_call = output
            .calls
            .values()
            .find(|call| call.evaluation().export == "accumulate")
            .ok_or("local expiry call")?;
        assert_eq!(
            local_call.evaluation().inputs[0].coverage,
            sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            }
        );
        assert_eq!(
            fixture
                .query
                .store()
                .managed_result(source.admitted(), &reference.result_id, now, &control,)?
                .current,
            now < expiry
        );
        assert_eq!(fixture.query.store().meta()?, before);
        let alias = inputs[0].data.batches[0].clone();
        drop((output, prepared, session, local));
        assert!(fixture.query.memory().input_reserved() > baseline);
        assert_eq!(values(std::slice::from_ref(&alias))?, [7]);
        drop(alias);
        assert_eq!(fixture.query.memory().input_reserved(), baseline);
        control.check()?;
    }
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, expiry)?;
    session
        .register_retained("saved", "retained-source", reference.clone(), "data")
        .await?;
    let prepared = session
        .prepare_definition(&Fixture::definition("SELECT value FROM saved"))
        .await?;
    let held = fixture.query.memory().input_reserved();
    let key = &contexts
        .iter()
        .find(|context| context.key.owner_id == "instance-context")
        .ok_or("captured expiry context")?
        .key;
    fixture.query.store().fault_write(
        "DELETE FROM context_versions WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
        &[&key.tenant_id.as_slice(), &key.owner_id, &key.entity_key.as_slice(), &key.lifetime_key.as_slice(), &key.owner_revision],
    )?;
    assert_eq!(fixture.query.store().meta()?, before);
    let (entry, observed) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    let error = session
        .capture_definition(&prepared, invocation())
        .await
        .err()
        .ok_or("expired retained input skipped its missing context")?;
    assert_eq!(Failure::from(&error), Failure::StorageUnavailable);
    assert!(matches!(
        observed.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if matches!(
            cause.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Incomplete,
                field: "managed input freshness",
                ..
            })
        ) {
            break;
        }
        cause = cause.source().ok_or("missing retained context error")?;
    }
    control.check()?;
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    drop((prepared, session));
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop((original, source));
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(INPUT)?);
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn retained_expiry_stays_scoped() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(INPUT),
        output_capacity: Some(OUTPUT),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&indexed_consumer()?)?;
    let (source, reference, expiry) = expiry_producer(&fixture).await?;
    let (witnesses, _) = fixture
        .query
        .store()
        .package_evidence([1; 16], std::slice::from_ref(&reference.result_id))?;
    let independent = r#"SELECT * FROM "retained-consumer"."expiry".echo(
        left_input => (SELECT source_cursor AS value FROM events),
        right_input => (SELECT value FROM local_rows),
        trusted => (SELECT * FROM "runtime-fixture"."1".accumulate(
            input => (SELECT value FROM local_rows))))"#;
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, expiry)?;
    let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::UInt64,
        false,
    )]));
    let batch = sdk::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(UInt64Array::from(vec![9]))],
    )?;
    session.register("local_rows", schema, std::slice::from_ref(&batch))?;
    session
        .register_retained("saved", "retained-source", reference.clone(), "data")
        .await?;
    let prepared = session
        .prepare_definition(&Fixture::definition(independent))
        .await?;
    let baseline = session
        .execute_definition(&prepared, local_invocation(&prepared, &batch)?)
        .await?;
    assert_eq!(values(&baseline.batches)?, [1]);
    assert!(baseline.snapshot.results().next().is_none());
    assert!(baseline
        .snapshot
        .witnesses
        .iter()
        .all(|witness| witness.expires_utc_ns == 0));
    let expected = call_inputs(&baseline, 1)?;
    assert_eq!(values(&expected[1].data.batches)?, [9]);
    assert_eq!(
        expected[3].coverage,
        sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        }
    );
    let before = fixture.query.store().meta()?;
    let affected = r#"SELECT * FROM "retained-consumer"."expiry".echo(
        left_input => (WITH unused AS (SELECT value FROM saved)
            SELECT CAST(7 AS BIGINT UNSIGNED) AS value),
        right_input => (SELECT source_cursor AS value FROM events),
        trusted => (SELECT * FROM "runtime-fixture"."1".accumulate(
            input => (SELECT value FROM local_rows))))"#;
    for (sql, calls) in [
        (
            format!("WITH unused AS (SELECT value FROM saved) {independent}"),
            2,
        ),
        (format!("{affected} UNION ALL {independent}"), 4),
    ] {
        let prepared = session
            .prepare_definition(&Fixture::definition(&sql))
            .await?;
        let output = session
            .execute_definition(&prepared, local_invocation(&prepared, &batch)?)
            .await?;
        assert_eq!(output.calls.len(), calls);
        assert_eq!(output.snapshot.results().collect::<Vec<_>>(), [&reference]);
        for witness in &witnesses {
            assert!(output.snapshot.witnesses.contains(witness));
        }
        let actual = call_inputs(&output, 1)?;
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.data.name, expected.data.name);
            assert_eq!(actual.data.batches, expected.data.batches);
            assert_eq!(actual.revision, expected.revision);
            assert_eq!(actual.coverage, expected.coverage);
            assert!(!actual
                .coverage
                .limits
                .iter()
                .any(|reason| reason == EXPIRED));
        }
        if calls == 4 {
            assert_eq!(values(&output.batches)?, [1, 7]);
            let affected = call_inputs(&output, 7)?;
            assert_eq!(values(&affected[1].data.batches)?, [1]);
            for input in affected {
                assert_eq!(input.coverage.state, sdk::CoverageState::Unknown);
                assert_eq!(
                    input
                        .coverage
                        .limits
                        .iter()
                        .filter(|reason| reason.as_str() == EXPIRED)
                        .count(),
                    1
                );
            }
        } else {
            assert_eq!(values(&output.batches)?, [1]);
        }
        for call in output
            .calls
            .values()
            .filter(|call| call.evaluation().export == "accumulate")
        {
            assert_eq!(
                call.evaluation().inputs[0].coverage,
                sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                }
            );
        }
        assert_eq!(fixture.query.store().meta()?, before);
        control.check()?;
    }
    drop((baseline, prepared, session, batch, source));
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(INPUT)?);
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
