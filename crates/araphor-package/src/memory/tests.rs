use araphor_analysis_sdk as sdk;

use serde_json::Value;

use super::*;
use crate::{PackageFixtureV1, PackageImplementationV1};

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
    let mut bundle = crate::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    let encoded = bundle.encode()?;
    let initial = bundle.allocated_bytes()?;
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
    assert!(bundle.allocated_bytes()? >= initial + growth);
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
    let initial = fixture.allocated_bytes()?;
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
    let charged = fixture.allocated_bytes()?;
    assert_eq!(serde_json::to_vec(&fixture)?, encoded);
    assert!(charged >= initial + growth);
    Ok(())
}

#[test]
fn native_capacity_is_charged() -> TestResult {
    let mut bundle = crate::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "count".into(),
        artifact: vec![1, 2, 3],
        qualification: Some(crate::Qualification {
            exports: vec!["count".into()],
            target: "x86_64-unknown-linux-gnu".into(),
            cpu_features: vec!["sse2".into()],
            contract_version: araphor_analysis_sdk::CONTRACT_VERSION,
            system_libraries: vec![crate::LibraryRequirement {
                name: "libc.so.6".into(),
                symbols: vec!["memcpy".into()],
                versions: vec!["GLIBC_2.14".into()],
            }],
            dependencies: vec![crate::Dependency {
                name: "helper.so".into(),
                artifact: vec![4, 5, 6],
                digest: "digest".into(),
            }],
        }),
    }];
    let encoded = serde_json::to_vec(&bundle)?;
    let initial = bundle.allocated_bytes()?;
    let PackageImplementationV1::Native {
        export,
        artifact,
        qualification: Some(qualification),
    } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("native implementation".into());
    };
    let mut growth = string(export)
        + grow(artifact)
        + grow(&mut qualification.exports)
        + string(&mut qualification.exports[0])
        + string(&mut qualification.target)
        + grow(&mut qualification.cpu_features)
        + string(&mut qualification.cpu_features[0])
        + grow(&mut qualification.system_libraries)
        + grow(&mut qualification.dependencies);
    let library = &mut qualification.system_libraries[0];
    growth += string(&mut library.name)
        + grow(&mut library.symbols)
        + string(&mut library.symbols[0])
        + grow(&mut library.versions)
        + string(&mut library.versions[0]);
    let dependency = &mut qualification.dependencies[0];
    growth += string(&mut dependency.name)
        + grow(&mut dependency.artifact)
        + string(&mut dependency.digest);
    assert_eq!(serde_json::to_vec(&bundle)?, encoded);
    assert!(bundle.allocated_bytes()? >= initial + growth);
    Ok(())
}

#[test]
fn memory_overflow_is_rejected() {
    assert!(matches!(
        sum([usize::MAX, 1]),
        Err(crate::Error::Package {
            code: ErrorCode::Limit,
            field: "package image memory",
            ..
        })
    ));
}

#[test]
fn admitted_capacity_is_charged() -> TestResult {
    let mut raw = crate::tests::bundle("1", "SELECT 7::BIGINT UNSIGNED AS count");
    string(&mut raw.root.package_id);
    string(&mut raw.root.revision);
    grow(&mut raw.artifacts);
    let heap = raw.allocated_bytes()?;
    let digest = raw.digest()?;
    let admitted = crate::PackageBundle::try_from(raw)?;
    assert_eq!(
        admitted.allocated_bytes()?,
        size_of::<crate::PackageBundle>() + heap + digest.capacity()
    );
    assert_eq!(admitted.digest(), digest);
    Ok(())
}
