use super::*;
use crate::tests::{bundle, TestResult};

#[test]
fn raw_code_preserves_native_dependencies() -> TestResult {
    let mut package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
    let sql = package.artifacts[0].implementations.remove(0);
    for name in ["wasm", "native", "legacy"] {
        let mut model = package.artifacts[0].descriptor.exports[0].clone();
        model.name = name.into();
        package.artifacts[0].descriptor.exports.push(model);
    }
    package.artifacts[0].implementations = vec![
        sql,
        PackageImplementationV1::Wasm {
            exports: vec!["wasm".into()],
            artifact: (0_u8..=255).collect(),
        },
        PackageImplementationV1::Native {
            export: "native".into(),
            artifact: vec![9, 8, 0, 255],
            qualification: Some(crate::native::Qualification {
                exports: vec!["native".into()],
                target: "x86_64-unknown-linux-gnu".into(),
                cpu_features: Vec::new(),
                contract_version: araphor_analysis_sdk::CONTRACT_VERSION,
                system_libraries: Vec::new(),
                dependencies: vec![crate::native::Dependency {
                    name: "helper.so".into(),
                    artifact: (0_u8..=255).cycle().take(16 * 1024).collect(),
                    digest: "retained-exact-digest".into(),
                }],
            }),
        },
        PackageImplementationV1::Native {
            export: "legacy".into(),
            artifact: Vec::new(),
            qualification: None,
        },
    ];
    let original = package.encode()?;
    let original_digest = package.digest()?;
    let artifact = &package.artifacts[0];
    let bytes = artifact.encode()?;
    let content = oci::Content::from_bytes(&bytes)?;
    assert_eq!(content.layers.len(), 4);
    assert_eq!(content.layers[0].bytes, (0_u8..=255).collect::<Vec<_>>());
    assert_eq!(content.layers[1].bytes, vec![9, 8, 0, 255]);
    assert_eq!(
        content.layers[2].bytes,
        (0_u8..=255).cycle().take(16 * 1024).collect::<Vec<_>>()
    );
    assert!(content.layers[3].bytes.is_empty());
    let decoded = PackageArtifactV1::from_bytes(&bytes)?;
    assert_eq!(decoded, *artifact);
    package.artifacts[0] = decoded;
    assert_eq!(package.encode()?, original);
    assert_eq!(package.digest()?, original_digest);
    Ok(())
}

#[test]
fn raw_frame_rejects_corruption() -> TestResult {
    let mut artifact = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count")
        .artifacts
        .remove(0);
    let payload = (0_u8..=255).cycle().take(1025).collect::<Vec<_>>();
    artifact.implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["count".into()],
        artifact: payload.clone(),
    }];
    let bytes = artifact.encode()?;
    let offset = bytes
        .windows(payload.len())
        .position(|part| part == payload)
        .ok_or("raw layer position")?;
    for end in [
        0,
        1,
        511,
        512,
        1023,
        1024,
        offset,
        offset + 1,
        offset + payload.len() - 1,
        bytes.len() - 1025,
        bytes.len() - 1024,
        bytes.len() - 1,
    ] {
        assert!(
            PackageArtifactV1::from_bytes(&bytes[..end]).is_err(),
            "end {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(1);
    assert!(PackageArtifactV1::from_bytes(&trailing).is_err());
    let mut changed = bytes.clone();
    changed[offset] ^= 1;
    assert!(PackageArtifactV1::from_bytes(&changed).is_err());
    let mut content = oci::Content::from_bytes(&bytes)?;
    content.layers[0].bytes[0] ^= 1;
    assert!(PackageOci::decode_artifact(content).is_err());
    let content = oci::Content::from_bytes(&bytes)?;
    let metadata: PackageArtifactV1 = content.package()?;
    let encode = |metadata: &PackageArtifactV1, layers: &[oci::Layer<'_>]| {
        oci::Layout::new(metadata, layers)?.encode()
    };
    let correct = oci::Layer {
        media_type: oci::WASM_MEDIA_TYPE,
        bytes: &payload,
    };
    assert!(PackageArtifactV1::from_bytes(&encode(&metadata, &[])?).is_err());
    assert!(PackageArtifactV1::from_bytes(&encode(
        &metadata,
        &[oci::Layer {
            media_type: oci::PYTHON_MEDIA_TYPE,
            bytes: &payload
        },]
    )?)
    .is_err());
    assert!(PackageArtifactV1::from_bytes(&encode(
        &metadata,
        &[
            oci::Layer {
                media_type: oci::WASM_MEDIA_TYPE,
                bytes: &payload
            },
            oci::Layer {
                media_type: oci::WASM_MEDIA_TYPE,
                bytes: b"unused"
            },
        ]
    )?)
    .is_err());
    assert!(PackageArtifactV1::from_bytes(&encode(&artifact, &[correct])?).is_err());
    Ok(())
}

#[test]
fn artifact_fixture_layers() -> TestResult {
    let mut artifact = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count")
        .artifacts
        .remove(0);
    let dataset = |name: &str, value: u8, size: usize| sdk::wire::Dataset {
        name: name.into(),
        arrow_ipc: vec![value; size],
    };
    artifact.fixtures.push(PackageFixtureV1 {
        name: "raw-layers".into(),
        export: "count".into(),
        time_utc_ns: 1,
        seed: Some(2),
        parameters: None,
        inputs: vec![sdk::wire::Input {
            data: dataset("source", 201, 64 * 1024),
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        checkpoint: Some(sdk::wire::Checkpoint {
            version: 1,
            datasets: vec![dataset("prior", 202, 17)],
        }),
        expected: sdk::wire::Output {
            datasets: vec![dataset("rows", 203, 19)],
            evidence: Vec::new(),
            reasons: vec![sdk::wire::ReasonValue {
                output: sdk::RowRef {
                    dataset: "rows".into(),
                    row: 0,
                },
                code: "fixture.reason".into(),
                details: vec![204; 23],
            }],
            checkpoint: Some(sdk::wire::Checkpoint {
                version: 2,
                datasets: vec![dataset("next", 205, 29)],
            }),
        },
    });
    let bytes = artifact.encode()?;
    let content = oci::Content::from_bytes(&bytes)?;
    assert_eq!(
        content
            .layers
            .iter()
            .map(|layer| layer.bytes.as_slice())
            .collect::<Vec<_>>(),
        [
            vec![201; 64 * 1024],
            vec![202; 17],
            vec![203; 19],
            vec![204; 23],
            vec![205; 29]
        ]
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>()
    );
    assert!(content
        .layers
        .iter()
        .all(|layer| layer.media_type == oci::ARROW_IPC_MEDIA_TYPE));
    let metadata: PackageArtifactV1 = content.package()?;
    let fixture = &metadata.fixtures[0];
    assert!(fixture.inputs[0].data.arrow_ipc.is_empty());
    assert!(fixture.checkpoint.as_ref().ok_or("prior")?.datasets[0]
        .arrow_ipc
        .is_empty());
    assert!(fixture.expected.datasets[0].arrow_ipc.is_empty());
    assert!(fixture.expected.reasons[0].details.is_empty());
    assert!(
        fixture.expected.checkpoint.as_ref().ok_or("next")?.datasets[0]
            .arrow_ipc
            .is_empty()
    );
    assert!(bytes.len() < 2 * 64 * 1024);
    assert_eq!(PackageArtifactV1::from_bytes(&bytes)?, artifact);
    Ok(())
}

#[test]
fn standalone_artifact_dependencies() -> TestResult {
    let mut package = bundle("1", "SELECT count FROM source");
    let artifact = &mut package.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new("source", model.outputs[0].schema.clone()),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "external.model".into(),
            revision: "2".into(),
            export: "count".into(),
            output: "rows".into(),
        })),
    });
    assert_eq!(
        PackageArtifactV1::from_bytes(&artifact.encode()?)?,
        *artifact
    );
    assert!(package.validate().is_err());
    Ok(())
}
