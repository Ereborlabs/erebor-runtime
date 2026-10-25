use super::*;
use crate::AnalysisStore;
use snafu::ResultExt as _;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod context;
mod image;

fn package(id: &str, revision: &str) -> crate::Result<PackageRevisionV1> {
    let mut descriptor = araphor_analysis_sdk::Package::new(
        id,
        revision,
        vec![araphor_analysis_sdk::Model::new(
            "model",
            Vec::new(),
            vec![araphor_analysis_sdk::Port::new(
                "rows",
                araphor_analysis_sdk::Schema::empty(),
            )],
        )],
    );
    descriptor.exports[0].input_mode = araphor_analysis_sdk::InputMode::Resolved;
    let source = crate::PackageArtifactV1 {
        descriptor: descriptor.clone(),
        implementations: vec![crate::PackageImplementationV1::Sql {
            export: "model".into(),
            program: crate::SqlModelV1 {
                outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let artifact = source.encode()?;
    Ok(PackageRevisionV1 {
        tenant_id: [1; 16],
        package_id: id.into(),
        revision: revision.into(),
        descriptor: serde_json::to_vec(&descriptor).context(crate::PackageEncodingSnafu)?,
        artifact,
        dependencies: Vec::new(),
    })
}

#[test]
fn packages_charge_stored_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let revision = package("bytes", "v1")?;
    let expected = (256
        + revision.package_id.len()
        + revision.revision.len()
        + revision.descriptor.len()
        + revision.artifact.len()
        + serde_json::to_vec(&revision.dependencies)?.len()) as u64;
    for _ in 0..2 {
        store.install_package(std::slice::from_ref(&revision), || Ok(()))?;
        assert_eq!(
            store.read_snapshot(
                |reader| AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
            )?,
            expected
        );
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.read_snapshot(
            |reader| AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
        )?,
        expected
    );
    assert_eq!(
        store.package_revision([1; 16], "bytes", "v1")?,
        Some(revision)
    );
    Ok(())
}

#[test]
fn packages_unused_artifacts_release() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    store.install_package(&[package("first", "v1")?], || Ok(()))?;
    let unrelated = package("unrelated", "v1")?;
    store.install_package(std::slice::from_ref(&unrelated), || Ok(()))?;
    store.collect_package([1; 16], "first", "v1")?;
    assert!(store.package_revision([1; 16], "first", "v1")?.is_none());
    assert_eq!(
        store.package_revision([1; 16], "unrelated", "v1")?,
        Some(unrelated)
    );
    Ok(())
}

#[test]
fn oci_descriptor_mismatch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let original = package("descriptor", "v1")?;
    let mut changed = original.clone();
    let mut descriptor: araphor_analysis_sdk::Package =
        serde_json::from_slice(&changed.descriptor)?;
    descriptor.exports[0].name = "changed".into();
    changed.descriptor = serde_json::to_vec(&descriptor)?;
    assert!(matches!(
        changed.decode_artifact(),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "retained package descriptor",
            ..
        })
    ));
    let before = store.meta()?;
    assert!(store
        .install_package(std::slice::from_ref(&changed), || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store
        .package_revision([1; 16], "descriptor", "v1")?
        .is_none());
    store.install_package(&[original], || Ok(()))?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE package_revisions SET descriptor = ? WHERE package_id = ?",
            duckdb::params![changed.descriptor, "descriptor"],
        )?;
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn retained_rows_check_contract() -> TestResult {
    use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};

    let mut artifact = package("row-root", "v1")?.decode_artifact()?;
    let dependencies = [
        package("row-first", "v1")?.decode_artifact()?,
        package("row-second", "v1")?.decode_artifact()?,
    ];
    for dependency in &dependencies {
        artifact.descriptor.exports[0]
            .inputs
            .push(araphor_analysis_sdk::InputPort {
                port: araphor_analysis_sdk::Port::new(
                    dependency.descriptor.id.clone(),
                    araphor_analysis_sdk::Schema::empty(),
                ),
                source: araphor_analysis_sdk::InputSource::Table(
                    araphor_analysis_sdk::TableRef::Output(araphor_analysis_sdk::OutputRef {
                        package: dependency.descriptor.id.clone(),
                        revision: dependency.descriptor.revision.clone(),
                        export: "model".into(),
                        output: "rows".into(),
                    }),
                ),
            });
    }
    let bundle = crate::PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: std::iter::once(artifact).chain(dependencies).collect(),
    };
    let bundle = crate::PackageBundle::try_from(bundle)?;
    let original = PackageRevisionV1::from_bundle(&bundle, [1; 16])?
        .into_iter()
        .find(|row| row.package_id == bundle.bundle().root.package_id)
        .ok_or("root revision absent")?;
    assert_eq!(original.dependencies.len(), 2);
    assert_eq!(original.decode_artifact()?, bundle.bundle().artifacts[0]);
    for fault in [
        "id",
        "revision",
        "descriptor",
        "descriptor-json",
        "oci",
        "oci-header",
        "missing",
        "extra",
        "duplicate",
        "reversed",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        store.install_package_image([1; 16], &bundle, || Ok(()))?;
        let before = store.meta()?;
        let mut changed = original.clone();
        match fault {
            "id" | "revision" => {
                let mut artifact = bundle.bundle().artifacts[0].clone();
                if fault == "id" {
                    artifact.descriptor.id = "row-other".into();
                } else {
                    artifact.descriptor.revision = "v2".into();
                }
                changed.descriptor = artifact.descriptor_bytes()?;
                changed.artifact = artifact.encode()?;
            }
            "descriptor" => {
                let mut descriptor = bundle.bundle().artifacts[0].descriptor.clone();
                descriptor.exports[0].name = "changed".into();
                changed.descriptor = serde_json::to_vec(&descriptor)?;
            }
            "descriptor-json" => changed.descriptor = b"{".to_vec(),
            "oci" => *changed.artifact.last_mut().ok_or("OCI bytes absent")? = 1,
            "oci-header" => changed.artifact = b"broken".to_vec(),
            "missing" => {
                changed.dependencies.pop();
            }
            "extra" => changed.dependencies.push(PackageRevisionRefV1 {
                package_id: "row-stray".into(),
                revision: "v1".into(),
            }),
            "duplicate" => changed.dependencies.push(changed.dependencies[0].clone()),
            _ => changed.dependencies.reverse(),
        }
        let rejected = |error: &crate::Error| match fault {
            "id" | "revision" => matches!(
                error,
                crate::Error::Package {
                    code: crate::PackageErrorCodeV1::Invalid,
                    field: "retained package key",
                    ..
                }
            ),
            "descriptor" => matches!(
                error,
                crate::Error::Package {
                    code: crate::PackageErrorCodeV1::Invalid,
                    field: "retained package descriptor",
                    ..
                }
            ),
            "descriptor-json" => {
                matches!(error, crate::Error::PackageEncoding { .. })
                    && std::error::Error::source(error).is_some()
            }
            "oci" => {
                matches!(error, crate::Error::AnalysisContract { source, .. }
                    if matches!(source, araphor_analysis_sdk::Error::Contract { code: araphor_analysis_sdk::ErrorCode::Invalid, field, .. }
                        if field == "OCI archive trailer"))
                    && std::error::Error::source(error).is_some()
            }
            "oci-header" => {
                matches!(error, crate::Error::AnalysisContract { source, .. }
                    if matches!(source, araphor_analysis_sdk::Error::Io { path, source, .. }
                        if path == std::path::Path::new("<OCI archive>")
                            && source.kind() == std::io::ErrorKind::Other
                            && source.to_string() == "failed to read entire block"))
                    && std::error::Error::source(error).is_some()
            }
            _ => matches!(
                error,
                crate::Error::Package {
                    code: crate::PackageErrorCodeV1::Invalid,
                    field: "retained package dependencies",
                    ..
                }
            ),
        };
        let retained = |error: &crate::Error| {
            if fault == "oci-header" {
                error.status_code() == StatusCode::Internal
                    && error.retry_hint() == RetryHint::NonRetryable
                    && rejected(error)
            } else {
                error.status_code() == StatusCode::IllegalState
                    && error.retry_hint() == RetryHint::NonRetryable
                    && matches!(error, crate::Error::StoredArtifact { source, .. } if rejected(source))
            }
        };
        if fault == "reversed" {
            assert_eq!(changed.decode_artifact()?, bundle.bundle().artifacts[0]);
        } else {
            let error = changed
                .decode_artifact()
                .err()
                .ok_or("invalid row decoded")?;
            assert_eq!(
                error.status_code(),
                if fault == "oci-header" {
                    StatusCode::Internal
                } else {
                    StatusCode::InvalidArguments
                }
            );
            assert_eq!(error.retry_hint(), RetryHint::NonRetryable);
            assert!(rejected(&error), "{fault}: {error:?}");
        }
        {
            let mut writer = store.writer()?;
            assert_eq!(writer.get_mut()?.execute(
                "UPDATE package_revisions SET descriptor = ?, artifact = ?, dependencies = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                duckdb::params![changed.descriptor, changed.artifact, serde_json::to_string(&changed.dependencies)?, changed.tenant_id.as_slice(), changed.package_id, changed.revision],
            )?, 1);
        }
        let result = store.package_image(
            [1; 16],
            &bundle.bundle().root.package_id,
            Some(&bundle.bundle().root.revision),
            &crate::AnalysisReadControl::default(),
        );
        if fault == "reversed" {
            let image = result?.ok_or("valid reordered image absent")?;
            assert_eq!(
                image.bundle().artifact(&bundle.bundle().root)?,
                &bundle.bundle().artifacts[0]
            );
            assert_eq!(
                image.bundle().artifacts.len(),
                bundle.bundle().artifacts.len()
            );
            assert_eq!(image.digest(), bundle.digest());
        } else {
            let error = result.err().ok_or("invalid stored row read")?;
            assert!(retained(&error), "{fault}: {error:?}");
        }
        assert_eq!(store.meta()?, before);
        drop(store);
        let reopened = AnalysisStore::open(&root);
        if fault == "reversed" {
            let store = reopened?;
            assert_eq!(
                store.package_revision([1; 16], &changed.package_id, &changed.revision)?,
                Some(changed)
            );
            let image = store
                .package_image(
                    [1; 16],
                    &bundle.bundle().root.package_id,
                    Some(&bundle.bundle().root.revision),
                    &crate::AnalysisReadControl::default(),
                )?
                .ok_or("reopened image absent")?;
            assert_eq!(image.digest(), bundle.digest());
        } else {
            let error = reopened.err().ok_or("invalid stored row reopened")?;
            assert!(retained(&error), "{fault}: {error:?}");
        }
    }
    Ok(())
}
