use super::*;
use crate::package::tests::{bundle, TestResult};

#[test]
fn raw_code_preserves_native_dependencies() -> TestResult {
    let mut package = bundle("1", "SELECT 1::UBIGINT AS count");
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
            inputs: None,
            artifact: (0_u8..=255).collect(),
        },
        PackageImplementationV1::Native {
            export: "native".into(),
            artifact: vec![9, 8, 0, 255],
            qualification: Some(super::super::native::Qualification {
                exports: vec!["native".into()],
                inputs: None,
                target: "x86_64-unknown-linux-gnu".into(),
                cpu_features: Vec::new(),
                contract_version: 1,
                system_libraries: Vec::new(),
                dependencies: vec![super::super::native::Dependency {
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
    let (bytes, size) = StoredArtifact::encode(artifact)?;
    assert_eq!(
        size,
        crate::package::AnalysisPackageOwner::encode(&artifact.encoding(false)?)?.len()
    );
    assert!(bytes.len() < size);
    assert_eq!(StoredArtifact::frame_size(&bytes)?, size);
    StoredArtifact::validate(&bytes, &artifact.descriptor, size)?;
    let decoded = StoredArtifact::decode(&bytes, &artifact.descriptor, size)?;
    assert_eq!(decoded, *artifact);
    package.artifacts[0] = decoded;
    assert_eq!(package.encode()?, original);
    assert_eq!(package.digest()?, original_digest);
    Ok(())
}

#[test]
fn raw_frame_rejects_corruption() -> TestResult {
    let artifact = bundle("1", "SELECT 1::UBIGINT AS count")
        .artifacts
        .remove(0);
    let (bytes, size) = StoredArtifact::encode(&artifact)?;
    assert!(StoredArtifact::decode(&bytes, &artifact.descriptor, size + 1).is_err());
    for end in 0..bytes.len() {
        assert!(StoredArtifact::validate(&bytes[..end], &artifact.descriptor, size).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(StoredArtifact::validate(&trailing, &artifact.descriptor, size).is_err());
    let mut decoder = Decoder::new(&bytes);
    decoder.array()?;
    decoder.u32()?;
    decoder.u64()?;
    let metadata = decoder.bytes()?;
    let mut extra = Vec::new();
    Encoder::new(&mut extra)
        .array(4)?
        .u32(1)?
        .u64(size as u64)?
        .bytes(metadata)?
        .array(1)?
        .bytes(b"unused")?;
    assert!(StoredArtifact::validate(&extra, &artifact.descriptor, size).is_err());
    let mut changed = Vec::new();
    Encoder::new(&mut changed)
        .array(4)?
        .u32(2)?
        .u64(size as u64)?
        .bytes(metadata)?
        .array(0)?;
    assert!(StoredArtifact::validate(&changed, &artifact.descriptor, size).is_err());
    let mut forged = Vec::new();
    Encoder::new(&mut forged)
        .array(4)?
        .u32(1)?
        .u64(size as u64 - 1)?
        .bytes(metadata)?
        .array(0)?;
    assert!(forged.len() < size - 1);
    assert!(StoredArtifact::validate(&forged, &artifact.descriptor, size - 1).is_err());
    Ok(())
}

#[test]
fn raw_frame_preserves_byte_bounds() -> TestResult {
    let mut artifact = bundle("1", "SELECT 1::UBIGINT AS count")
        .artifacts
        .remove(0);
    artifact.implementations = vec![PackageImplementationV1::Python {
        export: "count".into(),
        artifact: vec![0; super::super::MAX_PACKAGE_BYTES / 2],
    }];
    let (bytes, size) = StoredArtifact::encode(&artifact)?;
    assert!(size > super::super::MAX_PACKAGE_BYTES);
    assert!(size <= crate::analysis::MAX_PACKAGE_BYTES);
    assert!(bytes.len() < super::super::MAX_PACKAGE_BYTES);
    assert_eq!(
        StoredArtifact::decode(&bytes, &artifact.descriptor, size)?,
        artifact
    );
    artifact.implementations = vec![PackageImplementationV1::Python {
        export: "count".into(),
        artifact: vec![0; super::super::MAX_PACKAGE_BYTES],
    }];
    assert!(matches!(StoredArtifact::encode(&artifact),
        Err(crate::Error::PackageEncoding { source, .. })
            if source.io_error_kind() == Some(io::ErrorKind::FileTooLarge)));
    Ok(())
}
