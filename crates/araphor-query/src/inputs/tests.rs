use std::sync::Arc;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    AnalysisStore, ContextSensitivityV1, EvidenceIntakeIdentityV1, EvidenceRecord, Selection,
    ValidatedEvidenceBatchV1,
};
use datafusion::common::ScalarValue;
use prost::Message as _;

use super::{InputSet, Inputs};
use crate::execution::{Engine, Limits};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const NOW: u64 = 1_700_000_000_123_456_789;

struct Fixture {
    engine: Arc<Engine>,
    store: Arc<AnalysisStore>,
    source: EvidenceIntakeIdentityV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let engine = Engine::new(
            Arc::clone(&store),
            Limits {
                tenant_evaluations: 1,
                extract_timeout: Duration::from_secs(10),
                evaluate_timeout: Duration::from_secs(10),
                ..Default::default()
            },
        )?;
        Ok(Self {
            engine,
            store,
            source: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "input-test".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            _directory: directory,
        })
    }

    fn event(&self, cursor: u64, received: u64) -> TestResult {
        self.event_from(&self.source, cursor, received)
    }

    fn event_from(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        cursor: u64,
        received: u64,
    ) -> TestResult {
        let bytes = EvidenceRecord {
            operation: 7,
            ..Default::default()
        }
        .encode_to_vec();
        let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        self.store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
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

    fn context(&self, revision: u64) -> TestResult {
        self.store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: self.source.tenant_id,
                owner_id: "input-context".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        })?;
        Ok(())
    }

    fn selection(&self) -> AnalysisSelectionV1 {
        let mut selection =
            AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()]);
        selection.contexts = Selection::All;
        selection
    }

    fn read(&self, definition: &Arc<Inputs>) -> TestResult<Arc<InputSet>> {
        Ok(definition.read(
            Arc::clone(&self.engine),
            self.selection(),
            "scope".into(),
            &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
            NOW,
        )?)
    }
}

fn port(name: &str, fields: Vec<(&str, sdk::DataType)>) -> sdk::Port {
    sdk::Port::new(
        name,
        sdk::Schema::new(
            fields
                .into_iter()
                .map(|(name, kind)| sdk::Field::new(name, kind, false))
                .collect::<Vec<_>>(),
        ),
    )
}

fn query(name: &str, sql: &str) -> sdk::InputPort {
    sdk::InputPort {
        port: port(name, vec![("value", sdk::DataType::UInt64)]),
        source: sdk::InputSource::Query(sql.into()),
    }
}

fn model(inputs: Vec<sdk::InputPort>) -> sdk::Model {
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![port("result", vec![("value", sdk::DataType::UInt64)])],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = inputs;
    model
}

fn values(input: &sdk::Input) -> TestResult<Vec<Vec<ScalarValue>>> {
    input
        .data
        .batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows()).map(move |row| {
                batch
                    .columns()
                    .iter()
                    .map(|column| ScalarValue::try_from_array(column, row))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
        })
        .map(|row| Ok(row?))
        .collect()
}

#[test]
fn dependent_ports_share_indices() -> TestResult {
    let fixture = Fixture::new()?;
    for cursor in 1..=3 {
        fixture.event(cursor, cursor * 1000)?;
    }
    fixture.event_from(
        &EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..fixture.source.clone()
        },
        1,
        4000,
    )?;
    let declared = model(vec![
        sdk::InputPort {
            port: port(
                "indexed",
                vec![
                    ("value", sdk::DataType::UInt64),
                    ("row_index", sdk::DataType::UInt64),
                ],
            ),
            source: sdk::InputSource::Query(
                "SELECT source_cursor AS value, __row_index AS row_index FROM chosen ORDER BY __row_index"
                    .into(),
            ),
        },
        sdk::InputPort {
            port: port("chosen", vec![("source_cursor", sdk::DataType::UInt64)]),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let _other = fixture.engine.reserve_evaluation([9; 16])?;
    let cut = fixture.read(&definition)?;
    assert_eq!(cut.now, NOW);
    assert_eq!(
        cut.inputs
            .iter()
            .map(|input| input.data.name.as_str())
            .collect::<Vec<_>>(),
        ["indexed", "chosen"]
    );
    assert_eq!(
        values(&cut.inputs[0])?,
        (1..=3)
            .map(|value| vec![
                ScalarValue::UInt64(Some(value)),
                ScalarValue::UInt64(Some(value - 1)),
            ])
            .collect::<Vec<_>>()
    );
    assert_eq!(
        values(&cut.inputs[1])?,
        (1..=3)
            .map(|value| vec![ScalarValue::UInt64(Some(value))])
            .collect::<Vec<_>>()
    );
    let snapshot = cut.snapshot.as_ref().ok_or("source snapshot")?;
    assert_eq!(snapshot.page.extraction.sources.len(), 1);
    assert_eq!(snapshot.witnesses.len(), 3);
    assert!(snapshot
        .witnesses
        .iter()
        .all(|witness| witness.identity == fixture.source));
    assert_eq!(
        snapshot.page.extraction.meta.commit_revision,
        fixture.store.meta()?.commit_revision
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    Ok(())
}

#[test]
fn materialized_name_is_not_durable() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1, 1000)?;
    let declared = model(vec![
        sdk::InputPort {
            port: port(
                "selected",
                vec![
                    ("ordinal", sdk::DataType::UInt32),
                    ("row_index", sdk::DataType::UInt64),
                ],
            ),
            source: sdk::InputSource::Query(
                "SELECT ordinal, __row_index AS row_index FROM events ORDER BY __row_index LIMIT 2"
                    .into(),
            ),
        },
        sdk::InputPort {
            port: port("events", vec![("ordinal", sdk::DataType::UInt32)]),
            source: sdk::InputSource::Table(sdk::TableRef::Named("catalog".into())),
        },
    ]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let cut = fixture.read(&definition)?;
    assert_eq!(
        values(&cut.inputs[0])?,
        [
            vec![ScalarValue::UInt32(Some(0)), ScalarValue::UInt64(Some(0))],
            vec![ScalarValue::UInt32(Some(1)), ScalarValue::UInt64(Some(1))],
        ]
    );
    let snapshot = cut.snapshot.as_ref().ok_or("source snapshot")?;
    assert!(snapshot.page.extraction.sources.is_empty());
    assert!(snapshot.witnesses.is_empty());
    assert!(cut.inputs[0]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    Ok(())
}

#[test]
fn port_receipts_stay_scoped() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1, 1000)?;
    fixture.context(1)?;
    let declared = model(vec![
        query(
            "contexts",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        ),
        query("activity", "SELECT source_cursor AS value FROM events"),
    ]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let first = fixture.read(&definition)?;
    assert_eq!(
        values(&first.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(1))]]
    );
    assert!(first.inputs[0]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    assert!(!first.inputs[1]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    let context_revision = first.inputs[0].revision.clone();
    let context_coverage = first.inputs[0].coverage.clone();
    drop(first);
    fixture.event(2, 2000)?;
    let second = fixture.read(&definition)?;
    assert_eq!(second.inputs[0].revision, context_revision);
    assert_eq!(second.inputs[0].coverage, context_coverage);
    assert_eq!(
        values(&second.inputs[1])?,
        [
            vec![ScalarValue::UInt64(Some(1))],
            vec![ScalarValue::UInt64(Some(2))]
        ]
    );
    let activity_revision = second.inputs[1].revision.clone();
    let activity_coverage = second.inputs[1].coverage.clone();
    drop(second);
    fixture.context(2)?;
    let third = fixture.read(&definition)?;
    assert_eq!(
        values(&third.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(2))]]
    );
    assert_ne!(third.inputs[0].revision, context_revision);
    assert_eq!(third.inputs[1].revision, activity_revision);
    assert_eq!(third.inputs[1].coverage, activity_coverage);
    assert_eq!(
        third
            .snapshot
            .as_ref()
            .ok_or("source snapshot")?
            .contexts()
            .count(),
        2
    );
    Ok(())
}

#[test]
fn pruned_source_keeps_witness_scope() -> TestResult {
    let fixture = Fixture::new()?;
    for (cursor, received) in [(1, 1001), (2, 2001), (3, 3001)] {
        fixture.event(cursor, received)?;
    }
    let declared = model(vec![
        query(
            "empty",
            "WITH unused AS (SELECT source_cursor FROM events) SELECT CAST(0 AS BIGINT UNSIGNED) AS value WHERE false",
        ),
        query(
            "recent",
            "SELECT source_cursor AS value FROM events WHERE received_utc_ns >= 3000",
        ),
    ]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let cut = fixture.read(&definition)?;
    assert!(values(&cut.inputs[0])?.is_empty());
    assert_eq!(
        values(&cut.inputs[1])?,
        [vec![ScalarValue::UInt64(Some(3))]]
    );
    let snapshot = cut.snapshot.as_ref().ok_or("source snapshot")?;
    assert_eq!(snapshot.selection.time_range(), Some((0, u64::MAX)));
    assert_eq!(
        snapshot
            .witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    Ok(())
}

#[test]
fn disjoint_ports_exclude_gap_witness() -> TestResult {
    let fixture = Fixture::new()?;
    for (cursor, received) in [(1, 10), (2, 20), (3, 30)] {
        fixture.event(cursor, received)?;
    }
    let declared = model(vec![
        query(
            "early",
            "SELECT source_cursor AS value FROM events WHERE received_utc_ns <= 10",
        ),
        query(
            "late",
            "SELECT source_cursor AS value FROM events WHERE received_utc_ns >= 30",
        ),
    ]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let cut = fixture.read(&definition)?;
    assert_eq!(
        values(&cut.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(1))]]
    );
    assert_eq!(
        values(&cut.inputs[1])?,
        [vec![ScalarValue::UInt64(Some(3))]]
    );
    let snapshot = cut.snapshot.as_ref().ok_or("source snapshot")?;
    assert_eq!(
        snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        3
    );
    assert_eq!(
        snapshot
            .witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    Ok(())
}

#[test]
fn native_clocks_share_time() -> TestResult {
    let fixture = Fixture::new()?;
    let kind = sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into()));
    let declared = model(
        [("first", "CURRENT_TIMESTAMP"), ("second", "now()")]
            .into_iter()
            .map(|(name, expression)| sdk::InputPort {
                port: port(name, vec![("value", kind.clone())]),
                source: sdk::InputSource::Query(format!("SELECT {expression} AS value")),
            })
            .collect(),
    );
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    assert!(definition.input_clock());
    let cut = fixture.read(&definition)?;
    assert_eq!(cut.now, NOW);
    for input in &cut.inputs {
        assert_eq!(
            values(input)?,
            [vec![ScalarValue::TimestampNanosecond(
                Some(NOW as i64),
                Some("UTC".into())
            )]]
        );
    }
    Ok(())
}

#[test]
fn zero_inputs_need_no_capacity() -> TestResult {
    let fixture = Fixture::new()?;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &model(Vec::new()))?);
    let _held = fixture
        .engine
        .reserve_evaluation(fixture.source.tenant_id)?;
    let _memory = fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)?;
    let cut = fixture.read(&definition)?;
    assert!(cut.inputs.is_empty());
    assert!(cut.snapshot.is_none());
    assert_eq!(cut.now, NOW);
    Ok(())
}

#[test]
fn provided_input_missing_preserves_control() -> TestResult {
    let fixture = Fixture::new()?;
    let mut declared = model(Vec::new());
    declared.input_mode = sdk::InputMode::Provided;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    assert!(matches!(
        definition.read(
            Arc::clone(&fixture.engine),
            fixture.selection(),
            "scope".into(),
            &control,
            NOW,
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Missing,
                ..
            }
        })
    ));
    control.check()?;
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    Ok(())
}

#[test]
fn input_failure_releases_capacity() -> TestResult {
    let fixture = Fixture::new()?;
    let mut declared = model(vec![
        query("first", "SELECT CAST(1 AS BIGINT UNSIGNED) AS value"),
        query("second", "SELECT CAST(2 AS BIGINT UNSIGNED) AS value"),
    ]);
    declared.limits.max_rows = 1;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    assert!(matches!(
        fixture.read(&definition),
        Err(error) if matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::Contract { source }) if source.code() == sdk::ErrorCode::Limit
        )
    ));
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    control.cancel()?;
    assert!(definition
        .read(
            Arc::clone(&fixture.engine),
            fixture.selection(),
            "scope".into(),
            &control,
            NOW,
        )
        .is_err());
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    Ok(())
}

#[test]
fn raw_witness_limit_precedes_input_return() -> TestResult {
    let fixture = Fixture::new()?;
    let payload = EvidenceRecord {
        operation: 7,
        ..Default::default()
    }
    .encode_to_vec();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
    let mut first = 1;
    for count in [4096, 4096, 1] {
        fixture.store.accept_validated_batch(
            fixture.source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: first + count as u64 - 1,
                intake_utc_ns: 1000,
                frame_ends: (1..=count).map(|index| index * frame.len()).collect(),
                framed_records: frame.repeat(count).into(),
            },
        )?;
        first += count as u64;
    }
    let declared = model(vec![query(
        "counted",
        "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM events",
    )]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let error = fixture
        .read(&definition)
        .err()
        .ok_or("raw witness limit accepted")?;
    let error = error.downcast_ref::<crate::Error>().ok_or("query error")?;
    assert_eq!(crate::Failure::from(error), crate::Failure::InputTooLarge);
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );
    Ok(())
}

#[test]
fn retained_trace_cut_checks_revocation() -> TestResult {
    use araphor_data::{
        TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1,
    };

    let fixture = Fixture::new()?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: fixture.source.tenant_id,
        node_id: "input-trace".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    fixture.store.accept_trace(&TraceIntentV1 {
        tenant_id: identity.tenant_id,
        request_id: identity.request_id,
        source,
        bindings: vec![TraceBindingV1 {
            identity: identity.clone(),
            binding_id: [6; 16],
            namespace_uid: "input-namespace".into(),
        }],
        authority: b"accepted".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    })?;
    fixture.store.append_trace(
        &identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"trace-input".to_vec(),
            }],
            terminal: None,
        },
        200,
    )?;
    let declared = model(vec![query(
        "captured",
        "SELECT sequence AS value FROM trace_output",
    )]);
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    let mut selection = fixture.selection();
    selection.traces = Selection::Exact(vec![identity.clone()]);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let cut = definition.read(
        Arc::clone(&fixture.engine),
        selection,
        "scope".into(),
        &control,
        NOW,
    )?;
    assert_eq!(
        values(&cut.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(1))]]
    );
    cut.check(&fixture.engine, &control)?;
    fixture
        .engine
        .wait(cut.check_async(&fixture.engine, &control))?;
    let cancelled = AnalysisReadControl::default();
    let pending = cut.check_async(&fixture.engine, &cancelled);
    cancelled.cancel()?;
    for pending in [pending, cut.check_async(&fixture.engine, &cancelled)] {
        let error = fixture
            .engine
            .wait(pending)
            .err()
            .ok_or("cancelled input check")?;
        assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    }
    let (mut state, _) = fixture
        .store
        .trace_intent(identity.tenant_id, identity.request_id)?
        .ok_or("trace intent")?;
    state.cancel_requested = true;
    state.read_revoked = true;
    fixture.store.update_trace(&state)?;
    let error = cut
        .check(&fixture.engine, &control)
        .err()
        .ok_or("revoked input accepted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    let error = fixture
        .engine
        .wait(cut.check_async(&fixture.engine, &control))
        .err()
        .ok_or("revoked async input accepted")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Denied);
    control.check()?;
    drop(cut);
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    Ok(())
}

#[test]
fn inherited_witness_expiry_wins() -> TestResult {
    use std::collections::BTreeMap;

    use araphor_data::analysis::{
        PackageActivationV1, PackageCommitV1, PackageKeyV1, PackageRevisionV1,
    };
    use araphor_data::{
        AnalysisWitnessV1, ClockDependency, InstalledContext, PackageArtifactV1, PackageGrantV1,
        PackageImplementationV1, PackageReadinessV1, PackageRefV1, ResultContext, SqlModelV1,
    };

    let fixture = Fixture::new()?;
    fixture.event(1, 1000)?;
    let mut upstream = model(Vec::new());
    upstream.name = "upstream".into();
    let descriptor = sdk::Package::new("input-upstream", "1", vec![upstream.clone()]);
    let artifact = PackageArtifactV1 {
        descriptor: descriptor.clone(),
        implementations: vec![PackageImplementationV1::Sql {
            export: upstream.name.clone(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT 7::BIGINT UNSIGNED AS value".into(),
                )]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    fixture.store.install_package(
        &[PackageRevisionV1 {
            tenant_id: fixture.source.tenant_id,
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
            descriptor: serde_json::to_vec(&descriptor)?,
            artifact: artifact.encode()?,
            dependencies: Vec::new(),
        }],
        || Ok(()),
    )?;
    let installed = InstalledContext {
        grant: PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: fixture.selection(),
            expires_utc_ns: None,
            authorization_id: None,
        },
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        parameters: None,
        readiness: PackageReadinessV1::Ready,
        status_checkpoint: 0,
        prepared: true,
        clock: ClockDependency::None,
    };
    let active = fixture.store.activate_package(
        &PackageActivationV1 {
            key: PackageKeyV1 {
                tenant_id: fixture.source.tenant_id,
                scope_id: "scope".into(),
                package_id: descriptor.id.clone(),
                export: upstream.name.clone(),
            },
            revision: descriptor.revision.clone(),
            generation: 0,
            checkpoint_revision: 0,
            result_id: None,
            grant_id: "fixture".into(),
            metadata: serde_json::to_vec(&installed)?,
            active: true,
        },
        None,
        None,
        || Ok(()),
    )?;
    let schema = &upstream.outputs[0].schema;
    let data = sdk::Dataset {
        name: "result".into(),
        batches: vec![sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![7]))],
        )?],
    };
    fixture.store.commit_package(
        &PackageCommitV1 {
            expected_checkpoint_revision: active.checkpoint_revision,
            activation: active,
            window_id: "window".into(),
            result_id: "input-upstream-1".into(),
            request: b"request".to_vec(),
            metadata: serde_json::to_vec(&ResultContext::new(
                "input-upstream-1",
                NOW - 100,
                &upstream,
                &[],
            ))?,
            datasets: serde_json::to_vec(&sdk::wire::Output {
                datasets: vec![sdk::wire::Dataset::encode(&data, schema, upstream.limits)?],
                ..Default::default()
            })?,
            checkpoint: Vec::new(),
            dependencies: Vec::new(),
            source_revisions: Vec::new(),
            witnesses: vec![AnalysisWitnessV1 {
                identity: fixture.source.clone().into(),
                cursor: 1,
                expires_utc_ns: NOW - 1,
            }],
            context_refs: Vec::new(),
            created_utc_ns: NOW - 100,
        },
        || Ok(()),
    )?;
    let reference = sdk::OutputRef {
        package: descriptor.id,
        revision: descriptor.revision,
        export: upstream.name,
        output: "result".into(),
    };
    let definition = Arc::new(Inputs::admit(
        &fixture.engine,
        &model(vec![
            sdk::InputPort {
                port: port("inherited", vec![("value", sdk::DataType::UInt64)]),
                source: sdk::InputSource::Table(sdk::TableRef::Output(reference.clone())),
            },
            query("raw", "SELECT source_cursor AS value FROM events"),
        ]),
    )?);
    let cut = fixture.read(&definition)?;
    assert_eq!(
        values(&cut.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(7))]]
    );
    assert_eq!(
        values(&cut.inputs[1])?,
        [vec![ScalarValue::UInt64(Some(1))]]
    );
    let witnesses = &cut.snapshot.as_ref().ok_or("source snapshot")?.witnesses;
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].expires_utc_ns, NOW - 1);
    assert!(cut.witnesses().next().is_none());
    assert_eq!(cut.dependencies().count(), 1);
    for input in &cut.inputs {
        assert_eq!(input.coverage.state, sdk::CoverageState::Unknown);
        assert_eq!(
            input
                .coverage
                .limits
                .iter()
                .filter(|limit| limit.as_str() == "source evidence retention expired")
                .count(),
            1
        );
    }
    drop(cut);
    let definition = Arc::new(Inputs::admit(
        &fixture.engine,
        &model(vec![
            sdk::InputPort {
                port: port("inherited", vec![("value", sdk::DataType::UInt64)]),
                source: sdk::InputSource::Table(sdk::TableRef::Output(reference.clone())),
            },
            sdk::InputPort {
                port: port(
                    "indexed",
                    vec![
                        ("value", sdk::DataType::UInt64),
                        ("row_index", sdk::DataType::UInt64),
                    ],
                ),
                source: sdk::InputSource::Query(
                    "SELECT value, __row_index AS row_index FROM inherited".into(),
                ),
            },
        ]),
    )?);
    let cut = fixture.read(&definition)?;
    assert_eq!(
        values(&cut.inputs[0])?,
        [vec![ScalarValue::UInt64(Some(7))]]
    );
    assert_eq!(
        values(&cut.inputs[1])?,
        [vec![
            ScalarValue::UInt64(Some(7)),
            ScalarValue::UInt64(Some(0))
        ]]
    );
    assert!(cut
        .snapshot
        .as_ref()
        .ok_or("package snapshot")?
        .page
        .extraction
        .sources
        .is_empty());
    assert!(cut.witnesses().next().is_none());
    assert_eq!(cut.dependencies().count(), 1);
    for input in &cut.inputs {
        assert_eq!(input.coverage.state, sdk::CoverageState::Unknown);
        assert_eq!(
            input
                .coverage
                .limits
                .iter()
                .filter(|limit| limit.as_str() == "source evidence retention expired")
                .count(),
            1
        );
    }
    drop(cut);
    let active = fixture
        .store
        .package_activation(&PackageKeyV1 {
            tenant_id: fixture.source.tenant_id,
            scope_id: "scope".into(),
            package_id: reference.package,
            export: reference.export,
        })?
        .ok_or("upstream activation")?;
    fixture.store.mark_package_stale(&active)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let error = definition
        .read(
            Arc::clone(&fixture.engine),
            fixture.selection(),
            "scope".into(),
            &control,
            NOW,
        )
        .err()
        .ok_or("stale package output accepted")?;
    let mut cause = Some(&error as &(dyn std::error::Error + 'static));
    let mut incomplete = false;
    while let Some(error) = cause {
        if matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Incomplete,
                ..
            })
        ) {
            incomplete = true;
            break;
        }
        cause = error.source();
    }
    assert!(incomplete, "expected typed incomplete input: {error:?}");
    control.check()?;
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    Ok(())
}

#[test]
fn catalog_keeps_batch_limit() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1, 1_000)?;
    let mut declared = model(vec![sdk::InputPort {
        port: port("columns", vec![("ordinal", sdk::DataType::UInt32)]),
        source: sdk::InputSource::Query("SELECT ordinal FROM catalog LIMIT 100".into()),
    }]);
    declared.limits.max_rows = 100;
    declared.limits.max_batches = 1;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &declared)?);
    assert_eq!(
        definition
            .sources
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["catalog"],
    );
    let cut = fixture.read(&definition)?;
    assert_eq!(cut.now, NOW);
    assert_eq!(cut.inputs.len(), 1);
    let input = &cut.inputs[0];
    assert_eq!(input.data.name, "columns");
    assert_eq!(input.data.batches.len(), 1);
    assert_eq!(input.data.batches[0].num_rows(), 100);
    let expected = crate::sources::SourceSnapshot::schemas()
        .values()
        .flat_map(|schema| 0..schema.fields().len())
        .take(100)
        .map(|ordinal| vec![ScalarValue::UInt32(Some(ordinal as u32))])
        .collect::<Vec<_>>();
    assert_eq!(values(input)?, expected);
    assert_eq!(
        input.data.batches[0].schema().as_ref(),
        &declared.inputs[0].port.schema
    );
    assert_eq!(input.revision.owner, "araphor-query.Inputs");
    assert!(!input.revision.id.is_empty());
    assert!(input.revision.window.is_none());
    assert!(input
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "NO_SOURCE_COVERAGE"));
    let revision = input.revision.clone();
    let snapshot = cut.snapshot.as_ref().ok_or("catalog source snapshot")?;
    assert_eq!(snapshot.page.extraction.meta, fixture.store.meta()?);
    assert!(snapshot.page.extraction.sources.is_empty());
    assert!(snapshot.witnesses.is_empty());
    assert_eq!(cut.contexts().count(), 0);
    assert_eq!(cut.dependencies().count(), 0);
    let read_revision = snapshot.page.extraction.meta.commit_revision;
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );

    let borrowed = Arc::clone(input.data.batches[0].column(0));
    drop(cut);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_err());
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(fixture.engine.limits().output_capacity)?,
    );
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0)?,
        ScalarValue::UInt32(Some(0))
    );
    drop(borrowed);
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );

    fixture.event(2, 2_000)?;
    let later = fixture.read(&definition)?;
    assert_eq!(later.inputs[0].revision, revision);
    assert_eq!(later.inputs[0].data.batches.len(), 1);
    assert_eq!(later.inputs[0].data.batches[0].num_rows(), 100);
    assert!(
        later
            .snapshot
            .as_ref()
            .ok_or("later catalog snapshot")?
            .page
            .extraction
            .meta
            .commit_revision
            > read_revision
    );
    assert!(later.witnesses().next().is_none());
    drop(later);
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)?,
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)?,
    );
    Ok(())
}

#[test]
fn quiet_check_skips_runtime() -> TestResult {
    let fixture = Fixture::new()?;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &model(Vec::new()))?);
    let input = fixture.read(&definition)?;
    assert!(input.snapshot.is_none());
    let engine = Arc::clone(&fixture.engine);
    let control = AnalysisReadControl::default();
    fixture.engine.wait(async move {
        input.check(&engine, &control)?;
        input.check_async(&engine, &control).await
    })?;
    Ok(())
}

#[test]
fn windows_keep_port_expiry() -> TestResult {
    let fixture = Fixture::new()?;
    let old = NOW - 8_000_000_000;
    let recent = NOW - 1_000_000_000;
    fixture.event(1, old)?;
    fixture.event(2, recent)?;
    let model = model(vec![
        query("wide", "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '10 seconds'"),
        query("narrow", "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds'"),
        sdk::InputPort {
            port: port("chosen", vec![("source_cursor", sdk::DataType::UInt64)]),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
        query("dependent", "SELECT source_cursor AS value FROM chosen"),
    ]);
    let inputs = Arc::new(Inputs::admit(&fixture.engine, &model)?);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let read = |now| {
        inputs.read(
            Arc::clone(&fixture.engine),
            fixture.selection(),
            "scope".into(),
            &control,
            now,
        )
    };
    let first = read(NOW)?;
    assert_eq!(
        first
            .snapshot
            .as_ref()
            .ok_or("snapshot absent")?
            .received_min,
        Some(old)
    );
    let expiry = recent / 1000 * 1000 + 2_000_000_000 + 1000;
    assert_eq!(first.expiry, Some(expiry));
    assert!(expiry > NOW);
    assert_eq!(
        first
            .inputs
            .iter()
            .map(|input| input
                .data
                .batches
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>())
            .collect::<Vec<_>>(),
        [2, 1, 2, 2]
    );
    drop(first);
    let second = read(expiry)?;
    let next = old / 1000 * 1000 + 10_000_000_000 + 1000;
    assert_eq!(second.expiry, Some(next));
    assert!(next > expiry);
    assert_eq!(
        second
            .inputs
            .iter()
            .map(|input| input
                .data
                .batches
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>())
            .collect::<Vec<_>>(),
        [2, 0, 2, 2]
    );
    drop(second);
    let third = read(next)?;
    assert_eq!(
        third.expiry,
        Some(recent / 1000 * 1000 + 10_000_000_000 + 1000)
    );
    assert_eq!(
        third
            .inputs
            .iter()
            .map(|input| input
                .data
                .batches
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>())
            .collect::<Vec<_>>(),
        [1, 0, 2, 2]
    );
    Ok(())
}

#[test]
fn window_keeps_nanosecond_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let received = NOW - 1_000_000_000;
    fixture.event(1, received)?;
    let inputs = Arc::new(Inputs::admit(&fixture.engine, &model(vec![query(
        "window", "SELECT source_cursor AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds'"
    )]))?);
    let mut selection = fixture.selection();
    selection.received_from = std::ops::Bound::Excluded(received - 1);
    let captured = inputs.read(
        Arc::clone(&fixture.engine),
        selection,
        "scope".into(),
        &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
        NOW,
    )?;
    assert_eq!(
        captured.expiry,
        Some(received / 1000 * 1000 + 2_000_000_000 + 1000)
    );
    assert_eq!(
        captured.inputs[0]
            .data
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    Ok(())
}

#[test]
fn native_function_input() -> TestResult {
    let fixture = Fixture::new()?;
    let sql = "SELECT * FROM generate_series(1, 3) AS generated(value)";
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Int64, false)]);
    let mut model = sdk::Model::new("generated", vec![], vec![]);
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new("generated", schema),
        source: sdk::InputSource::Query(sql.into()),
    });
    let definition = Arc::new(Inputs::admit(&fixture.engine, &model)?);
    let input = fixture.read(&definition)?;
    assert_eq!(
        input.inputs[0]
            .data
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        3
    );
    let values = input.inputs[0]
        .data
        .batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows())
                .map(|row| ScalarValue::try_from_array(batch.column(0), row).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            ScalarValue::Int64(Some(1)),
            ScalarValue::Int64(Some(2)),
            ScalarValue::Int64(Some(3))
        ]
    );
    assert!(input.source_revisions().is_empty());
    assert_eq!(input.witnesses().count(), 0);
    let engine = Arc::clone(&fixture.engine);
    let selection = fixture.selection();
    let update = fixture.engine.wait(async move {
        use futures_util::TryStreamExt as _;
        let mut query = engine
            .subscribe(
                sql,
                Vec::new(),
                selection,
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
                b"generated",
                None,
                Arc::new(crate::follow::SystemClock::default()),
                false,
            )
            .await?;
        let update = query.try_next().await?.ok_or_else(|| {
            crate::InvalidSnafu {
                field: "generated result",
            }
            .build()
        })?;
        assert!(query.try_next().await?.is_none());
        Ok(update)
    })?;
    assert_eq!(
        update
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        3
    );
    assert!(update.snapshot.selection.sources.is_empty());
    assert!(update.snapshot.witnesses.is_empty());
    Ok(())
}

#[test]
fn function_does_not_inherit_table() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1, NOW)?;
    let mut model = sdk::Model::new("generated", vec![], vec![]);
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new(
                "generate_series",
                sdk::Schema::new(vec![sdk::Field::new(
                    "source_cursor",
                    sdk::DataType::UInt64,
                    false,
                )]),
            ),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
        sdk::InputPort {
            port: sdk::Port::new(
                "generated",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Int64, false)]),
            ),
            source: sdk::InputSource::Query(
                "SELECT * FROM generate_series(1, 3) AS generated(value)".into(),
            ),
        },
        sdk::InputPort {
            port: sdk::Port::new("guarded", sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Int64, false)])),
            source: sdk::InputSource::Query("WITH unused AS (SELECT * FROM generate_series) SELECT * FROM generate_series(1, 3) AS generated(value)".into()),
        },
    ];
    let definition = Arc::new(Inputs::admit(&fixture.engine, &model)?);
    let first = fixture.read(&definition)?;
    fixture.event(2, NOW)?;
    let second = fixture.read(&definition)?;
    assert_ne!(first.inputs[0].revision, second.inputs[0].revision);
    assert_eq!(first.inputs[1].revision, second.inputs[1].revision);
    assert_ne!(first.inputs[2].revision, second.inputs[2].revision);
    Ok(())
}
