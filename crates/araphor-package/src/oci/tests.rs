use super::*;
use crate::tests::{bundle, TestResult};
use araphor_analysis_sdk as sdk;

#[test]
fn oci_package_identity() -> TestResult {
    let mut package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
    package.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "count".into(),
        artifact: (0_u8..=255).collect(),
        qualification: Some(super::super::native::Qualification {
            exports: vec!["count".into()],
            target: "x86_64-unknown-linux-gnu".into(),
            cpu_features: Vec::new(),
            contract_version: araphor_analysis_sdk::CONTRACT_VERSION,
            system_libraries: Vec::new(),
            dependencies: vec![super::super::native::Dependency {
                name: "helper.so".into(),
                digest: "declared-code-identity".into(),
                artifact: vec![9, 8, 255, 0],
            }],
        }),
    }];
    package.artifacts[0].fixtures.push(PackageFixtureV1 {
        name: "raw-ipc".into(),
        export: "count".into(),
        time_utc_ns: 0,
        seed: None,
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        expected: sdk::wire::Output {
            datasets: vec![sdk::wire::Dataset {
                name: "rows".into(),
                arrow_ipc: vec![0, 255, 1],
            }],
            reasons: vec![sdk::wire::ReasonValue {
                output: sdk::RowRef {
                    dataset: "rows".into(),
                    row: 0,
                },
                code: "opaque".into(),
                details: vec![1, 0, 254],
            }],
            checkpoint: Some(sdk::wire::Checkpoint {
                version: 9,
                datasets: vec![sdk::wire::Dataset {
                    name: "opaque-state".into(),
                    arrow_ipc: vec![255, 0],
                }],
            }),
            ..Default::default()
        },
    });
    let bytes = package.encode()?;
    let digest = package.digest()?;
    assert_eq!(bytes.len(), 12_800, "{digest}");
    assert_eq!(
        digest,
        "sha256:456cd25518362e31d53ca250429fc9e4e648e258986cdbd079df00d9c7a2d458"
    );
    let content = oci::Content::from_bytes(&bytes)?;
    assert_eq!(content.layers.len(), 5);
    assert_eq!(content.layers[0].media_type, oci::NATIVE_MEDIA_TYPE);
    assert_eq!(
        content.layers[1].media_type,
        oci::NATIVE_DEPENDENCY_MEDIA_TYPE
    );
    for layer in &content.layers[2..] {
        assert_eq!(layer.media_type, oci::ARROW_IPC_MEDIA_TYPE);
    }
    let metadata: PackageBundleV1 = content.package()?;
    let PackageImplementationV1::Native {
        artifact,
        qualification: Some(qualification),
        ..
    } = &metadata.artifacts[0].implementations[0]
    else {
        return Err("native metadata absent".into());
    };
    assert!(artifact.is_empty());
    assert!(qualification.dependencies[0].artifact.is_empty());
    assert!(metadata.artifacts[0].fixtures[0].expected.datasets[0]
        .arrow_ipc
        .is_empty());
    assert!(metadata.artifacts[0].fixtures[0].expected.reasons[0]
        .details
        .is_empty());
    assert!(metadata.artifacts[0].fixtures[0]
        .expected
        .checkpoint
        .as_ref()
        .ok_or("checkpoint metadata")?
        .datasets[0]
        .arrow_ipc
        .is_empty());
    let decoded = PackageBundleV1::from_bytes(&bytes)?;
    assert_eq!(decoded.artifacts, package.artifacts);
    assert_eq!(decoded.digest()?, package.digest()?);
    let directory = tempfile::tempdir()?;
    package.write_layout(directory.path())?;
    std::fs::write(directory.path().join("descriptor.json"), b"author-only")?;
    assert_eq!(
        PackageBundleV1::read(directory.path())?.artifacts,
        package.artifacts
    );
    let archive = directory.path().join("package.oci.tar");
    std::fs::write(&archive, bytes)?;
    assert_eq!(
        PackageBundleV1::read(&archive)?.digest()?,
        package.digest()?
    );
    Ok(())
}

#[test]
fn oci_raw_slot_rejections() -> TestResult {
    let mut package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
    package.artifacts[0].implementations = vec![PackageImplementationV1::Python {
        export: "count".into(),
        artifact: vec![1],
    }];
    let layers = [oci::Layer {
        media_type: oci::PYTHON_MEDIA_TYPE,
        bytes: &[1],
    }];
    assert!(PackageBundleV1::from_bytes(&oci::Layout::new(&package, &layers)?.encode()?).is_err());
    let PackageImplementationV1::Python { artifact, .. } =
        &mut package.artifacts[0].implementations[0]
    else {
        return Err("Python metadata absent".into());
    };
    artifact.clear();
    let layers = [oci::Layer {
        media_type: oci::WASM_MEDIA_TYPE,
        bytes: &[1],
    }];
    assert!(PackageBundleV1::from_bytes(&oci::Layout::new(&package, &layers)?.encode()?).is_err());
    Ok(())
}

#[test]
fn oci_directory_rejects_symlinks() -> TestResult {
    let package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
    let directory = tempfile::tempdir()?;
    let layout = directory.path().join("layout");
    package.write_layout(&layout)?;
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&layout, &alias)?;
    assert!(PackageBundleV1::read(&alias).is_err());
    assert!(PackageBundleV1::read(&alias.join("index.json")).is_err());
    let blobs = layout.join("blobs/sha256");
    let original = layout.join("saved-blobs");
    std::fs::rename(&blobs, &original)?;
    std::os::unix::fs::symlink(&original, &blobs)?;
    assert!(PackageBundleV1::read(&layout).is_err());
    Ok(())
}

mod artifact;
