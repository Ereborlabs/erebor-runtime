use araphor_analysis_sdk as sdk;

use crate::analysis::PackageKeyV1;

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn grow<T>(values: &mut Vec<T>) -> usize {
    let capacity = values.capacity();
    values.reserve(64);
    (values.capacity() - capacity) * size_of::<T>()
}

fn string(value: &mut String) -> usize {
    let capacity = value.capacity();
    value.reserve(256);
    value.capacity() - capacity
}

fn dataset(name: &str) -> sdk::wire::Dataset {
    sdk::wire::Dataset {
        name: name.into(),
        arrow_ipc: vec![1, 2, 3],
    }
}

#[test]
fn bundle_capacity_is_charged() -> TestResult {
    let mut bundle = crate::package::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    let encoded = bundle.encode()?;
    let initial = BundleMemory::bundle(&bundle)?;
    let mut growth = string(&mut bundle.root.package_id) + string(&mut bundle.root.revision);
    growth += grow(&mut bundle.artifacts);
    let artifact = &mut bundle.artifacts[0];
    growth += grow(&mut artifact.implementations) + grow(&mut artifact.fixtures);
    growth += grow(&mut artifact.descriptor.exports);
    if let PackageImplementationV1::Sql {
        export, program, ..
    } = &mut artifact.implementations[0]
    {
        growth += string(export);
        for sql in program.outputs.values_mut() {
            growth += string(sql);
        }
    }
    assert_eq!(bundle.encode()?, encoded);
    assert!(BundleMemory::bundle(&bundle)? >= initial + growth);
    Ok(())
}

#[test]
fn admitted_capacity_is_charged() -> TestResult {
    let fixture = crate::package::tests::Fixture::new()?;
    let value = crate::package::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    let retained = InstalledBundle::new(
        &fixture.owner.query,
        value.clone(),
        fixture.owner.query.memory(),
    )?;
    let bytes = BundleMemory::retained(&retained.value, &retained.digest, &retained.identities)?;
    assert_eq!(retained.programs.len(), 1);
    assert_eq!(retained.programs[0].len(), 1);
    let bytes = bytes
        + retained.programs.capacity() * size_of::<Vec<Option<crate::model::AdmittedExport>>>()
        + retained.programs[0].capacity() * size_of::<Option<crate::model::AdmittedExport>>()
        + retained.programs[0][0]
            .as_ref()
            .ok_or("admitted export")?
            .allocated_bytes();
    assert_eq!(retained._memory.size(), bytes);
    assert!(
        retained.programs[0][0]
            .as_ref()
            .ok_or("admitted export")?
            .allocated_bytes()
            > 0
    );
    let query = crate::Engine::new(
        fixture.store.clone(),
        crate::Limits {
            input_bytes: 1,
            input_capacity: Some(bytes - 1),
            ..Default::default()
        },
    )?;
    assert_eq!(
        InstalledBundle::new(&query, value, query.memory())
            .err()
            .ok_or("capacity admitted")?
            .package_code(),
        Code::Limit
    );
    drop(query.memory().reserve_input(bytes - 1)?);
    Ok(())
}

#[test]
fn admission_stops_at_capacity() -> TestResult {
    let fixture = crate::package::tests::Fixture::new()?;
    let mut value = crate::package::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    let artifact = &mut value.artifacts[0];
    let mut model = artifact.descriptor.exports[0].clone();
    model.name = "later".into();
    artifact.descriptor.exports.push(model);
    let PackageImplementationV1::Sql { program, .. } = &artifact.implementations[0] else {
        return Err("SQL implementation".into());
    };
    let first = crate::model::AdmittedExport::admit(
        &fixture.owner.query,
        &artifact.descriptor.exports[0],
        Some(program),
    )?;
    let mut program = program.clone();
    program
        .outputs
        .insert("rows".into(), "SELECT missing FROM absent".into());
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "later".into(),
        program,
    });
    let bytes = BundleMemory::retained(&value, &value.digest()?, &vec![vec![None, None]])?
        .checked_add(size_of::<Vec<Option<crate::model::AdmittedExport>>>())
        .and_then(|bytes| bytes.checked_add(2 * size_of::<Option<crate::model::AdmittedExport>>()))
        .and_then(|bytes| bytes.checked_add(first.allocated_bytes()))
        .ok_or("program capacity")?
        - 1;
    let query = crate::Engine::new(
        fixture.store.clone(),
        crate::Limits {
            input_bytes: 1,
            input_capacity: Some(bytes),
            ..Default::default()
        },
    )?;
    assert_eq!(
        InstalledBundle::new(&query, value, query.memory())
            .err()
            .ok_or("capacity admitted")?
            .package_code(),
        Code::Limit
    );
    drop(query.memory().reserve_input(bytes)?);
    Ok(())
}

#[test]
fn fixture_capacity_is_charged() -> TestResult {
    let mut fixture = PackageFixtureV1 {
        name: "retained".into(),
        export: "evaluate".into(),
        time_utc_ns: 0,
        seed: None,
        inputs: vec![sdk::wire::Input {
            data: dataset("input"),
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: Some(sdk::SourceWindow {
                    source: vec![7],
                    start_utc_ns: 0,
                    end_utc_ns: 1,
                }),
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: vec!["bounded".into()],
            },
        }],
        parameters: Some(serde_json::json!({"values": ["retained"]})),
        checkpoint: Some(sdk::wire::Checkpoint {
            version: 1,
            datasets: vec![dataset("state")],
        }),
        expected: sdk::wire::Output {
            datasets: vec![dataset("data")],
            evidence: vec![sdk::EvidenceLink {
                output: sdk::RowRef {
                    dataset: "data".into(),
                    row: 0,
                },
                input: sdk::RowRef {
                    dataset: "input".into(),
                    row: 0,
                },
            }],
            reasons: vec![sdk::wire::ReasonValue {
                output: sdk::RowRef {
                    dataset: "data".into(),
                    row: 0,
                },
                code: "fixture.retained".into(),
                details: vec![1, 2, 3],
            }],
            checkpoint: Some(sdk::wire::Checkpoint {
                version: 1,
                datasets: vec![dataset("state")],
            }),
        },
    };
    let encoded = serde_json::to_vec(&fixture)?;
    let mut initial = BundleMemory { bytes: 0 };
    initial.fixture(&fixture)?;
    let mut growth = string(&mut fixture.name) + string(&mut fixture.export);
    growth += grow(&mut fixture.inputs);
    let input = &mut fixture.inputs[0];
    growth += string(&mut input.data.name) + grow(&mut input.data.arrow_ipc);
    growth += string(&mut input.revision.owner) + string(&mut input.revision.id);
    growth += grow(&mut input.revision.window.as_mut().ok_or("window")?.source);
    growth += grow(&mut input.coverage.limits) + string(&mut input.coverage.limits[0]);
    let parameters = fixture.parameters.as_mut().ok_or("parameters")?;
    let Value::Array(values) = &mut parameters["values"] else {
        return Err("parameter array".into());
    };
    growth += grow(values);
    let Value::String(value) = &mut values[0] else {
        return Err("parameter value".into());
    };
    growth += string(value);
    let checkpoint = fixture.checkpoint.as_mut().ok_or("checkpoint")?;
    growth += grow(&mut checkpoint.datasets);
    growth +=
        string(&mut checkpoint.datasets[0].name) + grow(&mut checkpoint.datasets[0].arrow_ipc);
    let expected = &mut fixture.expected;
    growth +=
        grow(&mut expected.datasets) + grow(&mut expected.evidence) + grow(&mut expected.reasons);
    growth += string(&mut expected.datasets[0].name) + grow(&mut expected.datasets[0].arrow_ipc);
    growth += string(&mut expected.evidence[0].output.dataset)
        + string(&mut expected.evidence[0].input.dataset);
    let reason = &mut expected.reasons[0];
    growth += string(&mut reason.output.dataset) + string(&mut reason.code);
    growth += grow(&mut reason.details);
    let checkpoint = expected.checkpoint.as_mut().ok_or("expected checkpoint")?;
    growth += grow(&mut checkpoint.datasets);
    growth +=
        string(&mut checkpoint.datasets[0].name) + grow(&mut checkpoint.datasets[0].arrow_ipc);
    let mut charged = BundleMemory { bytes: 0 };
    charged.fixture(&fixture)?;
    assert_eq!(serde_json::to_vec(&fixture)?, encoded);
    assert!(charged.bytes >= initial.bytes + growth);
    Ok(())
}

#[test]
fn snapshot_capacity_is_charged() -> TestResult {
    let mut pins = vec![PackageActivationV1 {
        key: PackageKeyV1 {
            tenant_id: [1; 16],
            scope_id: "test".into(),
            package_id: "fixture".into(),
            export: "evaluate".into(),
        },
        revision: "1".into(),
        generation: 1,
        checkpoint_revision: 0,
        result_id: Some("result".into()),
        grant_id: "grant".into(),
        metadata: vec![7],
        active: true,
    }];
    let mut bundles = Vec::new();
    let initial = BundleMemory::snapshot(&pins, &bundles)?;
    let mut growth = grow(&mut pins) + grow(&mut bundles);
    let pin = &mut pins[0];
    growth += string(&mut pin.key.scope_id)
        + string(&mut pin.key.package_id)
        + string(&mut pin.key.export);
    growth += string(&mut pin.revision) + string(&mut pin.grant_id);
    growth += string(pin.result_id.as_mut().ok_or("result")?) + grow(&mut pin.metadata);
    assert!(BundleMemory::snapshot(&pins, &bundles)? >= initial + growth);
    Ok(())
}

#[test]
fn memory_overflow_is_rejected() {
    let mut memory = BundleMemory { bytes: usize::MAX };
    assert!(matches!(
        memory.add(1),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Limit,
                field: "installed snapshot memory",
                ..
            }
        })
    ));
    let mut memory = BundleMemory { bytes: 0 };
    assert!(memory.tree::<String, String>(usize::MAX).is_err());
    assert_eq!(memory.bytes, 0);
}

#[test]
fn reuse_releases_before_loading() -> TestResult {
    use crate::package::{AnalysisPackageOwner, InstalledAnalysis, PackageRequestV1};
    use crate::AnalysisReadControl;
    use std::time::Duration;

    let mut fixture = crate::package::tests::Fixture::new()?;
    let mut selected = crate::package::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    let artifact = &mut selected.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.name = "evaluate".into();
    model.input_mode = sdk::InputMode::Provided;
    model.outputs = vec![sdk::Port::new(
        "data",
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
    )];
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    artifact.implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["evaluate".into()],
        artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
    }];
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: Some(serde_json::json!({
                "test.model": {"evaluate": {"mode": "echo", "amount": 7}}
            })),
        },
        &control,
    )?;
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let previous = execution.snapshot([1; 16])?;
    let snapshot = previous.snapshot.as_ref().ok_or("previous snapshot")?;
    assert_eq!(snapshot.pins.len(), 1);
    assert_eq!(snapshot.bundles.len(), 1);
    let pins = Arc::downgrade(snapshot);
    let bundle = Arc::downgrade(&snapshot.bundles[0]);
    let retained = snapshot._memory.size()
        + snapshot
            .bundles
            .iter()
            .map(|bundle| bundle._memory.size())
            .sum::<usize>();
    let mut updated = selected;
    updated.root.revision = "2".into();
    updated.artifacts[0].descriptor.revision = "2".into();
    fixture.renew();
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: updated.clone(),
        },
        &control,
    )?;
    let transient = InstalledBundle::new(
        &fixture.owner.query,
        updated.clone(),
        fixture.owner.query.memory(),
    )?;
    let transient_bytes = transient._memory.size();
    drop(transient);
    let capacity = fixture
        .owner
        .query
        .limits()
        .input_capacity
        .ok_or("configured input capacity")?;
    let pressure = fixture.owner.query.memory().reserve_input(
        capacity
            .checked_sub(retained + transient_bytes)
            .ok_or("snapshot pressure capacity")?,
    )?;
    assert!(execution.snapshot([1; 16]).is_err());
    let current = execution.snapshot_reusing([1; 16], Some(previous))?;
    assert!(pins.upgrade().is_none());
    assert!(bundle.upgrade().is_none());
    assert_eq!(current.pins()[0].revision, "2");
    assert_eq!(
        current.snapshot.as_ref().ok_or("current snapshot")?.bundles[0]
            .value
            .root,
        updated.root
    );
    let context: crate::package::InstalledContext =
        AnalysisPackageOwner::decode(&current.pins()[0].metadata)?;
    assert_eq!(context.grant, fixture.grant);
    drop(current);
    drop(pressure);
    drop(fixture.owner.query.memory().reserve_input(capacity)?);
    Ok(())
}
