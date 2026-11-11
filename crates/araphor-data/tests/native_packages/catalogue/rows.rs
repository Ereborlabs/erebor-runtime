use super::*;

type Row = (PackageRevisionV1, u64, u64);

fn bundle() -> araphor_data::Result<PackageBundle> {
    let mut root = artifact("row-root", "v1");
    let dependencies = [artifact("row-first", "v1"), artifact("row-second", "v1")];
    for item in &dependencies {
        dependency(&mut root, item, &item.descriptor.id);
    }
    Ok(PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: std::iter::once(root).chain(dependencies).collect(),
    })?)
}

fn stored_row(
    store: &NativeStore,
    package: &str,
) -> Result<(Vec<u8>, Row), Box<dyn std::error::Error>> {
    for entry in store.view()?.snapshot().prefix(b"\0data/P") {
        let (key, bytes) = entry?;
        if key.len() != 15 {
            continue;
        }
        let row: Row = rmp_serde::from_slice(&bytes[1..])?;
        if row.0.package_id == package {
            return Ok((key.to_vec(), row));
        }
    }
    Err("retained row absent".into())
}

#[test]
fn reordered_dependencies_survive_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let bundle = bundle()?;
    store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let mut expected = PackageRevisionV1::from_bundle(&bundle, [1; 16])?
        .into_iter()
        .find(|row| row.package_id == "row-root")
        .ok_or("root revision")?;
    assert_eq!(expected.dependencies.len(), 2);
    expected.dependencies.reverse();
    assert_eq!(expected.decode_artifact()?, bundle.bundle().artifacts[0]);
    let (key, mut row) = stored_row(&store, "row-root")?;
    row.0.dependencies.reverse();
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&row)?].concat());
    tx.commit([])?;
    let image = store
        .package_image(
            [1; 16],
            "row-root",
            Some("v1"),
            &AnalysisReadControl::default(),
        )?
        .ok_or("reordered image")?;
    assert_eq!(
        image.bundle().artifact(&bundle.bundle().root)?,
        &bundle.bundle().artifacts[0]
    );
    assert_eq!(
        image.bundle().artifacts.len(),
        bundle.bundle().artifacts.len()
    );
    assert_eq!(image.digest(), bundle.digest());
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.view()?.package_revision(
            [1; 16],
            "row-root",
            "v1",
            &AnalysisReadControl::default()
        )?,
        Some(expected)
    );
    assert_eq!(
        store
            .package_image(
                [1; 16],
                "row-root",
                Some("v1"),
                &AnalysisReadControl::default()
            )?
            .ok_or("reopened image")?
            .digest(),
        bundle.digest()
    );
    Ok(())
}

#[test]
fn retained_rows_check_contract() -> TestResult {
    use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};

    let bundle = bundle()?;
    let original = PackageRevisionV1::from_bundle(&bundle, [1; 16])?
        .into_iter()
        .find(|row| row.package_id == "row-root")
        .ok_or("root revision")?;
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
    ] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("data");
        let store = NativeStore::open(&root)?;
        store.install_package_image([1; 16], &bundle, || Ok(()))?;
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
            "oci" => *changed.artifact.last_mut().ok_or("OCI bytes")? = 1,
            "oci-header" => changed.artifact = b"broken".to_vec(),
            "missing" => {
                changed.dependencies.pop();
            }
            "extra" => changed.dependencies.push(PackageRevisionRefV1 {
                package_id: "row-stray".into(),
                revision: "v1".into(),
            }),
            "duplicate" => changed.dependencies.push(changed.dependencies[0].clone()),
            _ => unreachable!(),
        }
        let rejected = |error: &Error| match fault {
            "id" | "revision" => matches!(
                error,
                Error::Package {
                    code: Code::Invalid,
                    field: "retained package key",
                    ..
                }
            ),
            "descriptor" => matches!(
                error,
                Error::Package {
                    code: Code::Invalid,
                    field: "retained package descriptor",
                    ..
                }
            ),
            "descriptor-json" => {
                matches!(error, Error::PackageEncoding { .. })
                    && std::error::Error::source(error).is_some()
            }
            "oci" => {
                matches!(error, Error::AnalysisContract { source, .. }
                if matches!(source, sdk::Error::Contract { code: sdk::ErrorCode::Invalid, field, .. } if field == "OCI archive trailer"))
                    && std::error::Error::source(error).is_some()
            }
            "oci-header" => {
                matches!(error, Error::AnalysisContract { source, .. }
                if matches!(source, sdk::Error::Io { path, source, .. } if path == std::path::Path::new("<OCI archive>")
                    && source.kind() == std::io::ErrorKind::Other && source.to_string() == "failed to read entire block"))
                    && std::error::Error::source(error).is_some()
            }
            _ => matches!(
                error,
                Error::Package {
                    code: Code::Invalid,
                    field: "retained package dependencies",
                    ..
                }
            ),
        };
        let retained = |error: &Error| {
            if fault == "oci-header" {
                error.status_code() == StatusCode::Internal
                    && error.retry_hint() == RetryHint::NonRetryable
                    && rejected(error)
            } else {
                error.status_code() == StatusCode::IllegalState
                    && error.retry_hint() == RetryHint::NonRetryable
                    && matches!(error, Error::StoredArtifact { source, .. } if rejected(source))
            }
        };
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
        let (key, mut row) = stored_row(&store, "row-root")?;
        let body_key = [b"\0data/@package-body/".as_slice(), &key[7..]].concat();
        row.2 = changed.artifact.len() as u64;
        let body = std::mem::take(&mut changed.artifact);
        row.0 = changed;
        let mut tx = store.write()?;
        tx.native()
            .insert(key, [vec![0], rmp_serde::to_vec(&row)?].concat());
        tx.native().insert(body_key, [vec![0], body].concat());
        tx.commit([])?;
        let before = store.meta()?;
        let cursor = store.database().inner().journal_head()?;
        let failure = store
            .package_image(
                [1; 16],
                "row-root",
                Some("v1"),
                &AnalysisReadControl::default(),
            )
            .err()
            .ok_or("invalid stored row read")?;
        assert!(retained(&failure), "{fault}: {failure:?}");
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, cursor);
        drop(store);
        let failure = NativeStore::open(&root)
            .err()
            .ok_or("invalid stored row reopened")?;
        assert!(retained(&failure), "{fault}: {failure:?}");
    }
    Ok(())
}

#[test]
fn unused_artifacts_release() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let package = |id| {
        PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact(id, "v1").reference(),
            artifacts: vec![artifact(id, "v1")],
        })
    };
    store.install_package(
        &PackageRevisionV1::from_bundle(&package("first")?, [1; 16])?,
        || Ok(()),
    )?;
    let unrelated = PackageRevisionV1::from_bundle(&package("unrelated")?, [1; 16])?;
    store.install_package(&unrelated, || Ok(()))?;
    store.collect_package([1; 16], "first", "v1")?;
    let view = store.view()?;
    assert!(view
        .package_revision([1; 16], "first", "v1", &AnalysisReadControl::default())?
        .is_none());
    assert_eq!(
        view.package_revision([1; 16], "unrelated", "v1", &AnalysisReadControl::default())?,
        Some(unrelated[0].clone())
    );
    Ok(())
}

#[test]
fn descriptor_mismatch_rejects_admission() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let artifact = artifact("descriptor", "v1");
    let mut original = PackageRevisionV1::from_artifact(&artifact, [1; 16])?;
    original.artifact = artifact.encode()?;
    let mut changed = original.clone();
    let mut descriptor = artifact.descriptor;
    descriptor.exports[0].name = "changed".into();
    changed.descriptor = serde_json::to_vec(&descriptor)?;
    assert!(matches!(
        changed.decode_artifact(),
        Err(Error::Package {
            code: Code::Invalid,
            field: "retained package descriptor",
            ..
        })
    ));
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(store
        .install_package(std::slice::from_ref(&changed), || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .view()?
        .package_revision([1; 16], "descriptor", "v1", &AnalysisReadControl::default())?
        .is_none());
    store.install_package(&[original], || Ok(()))?;
    let (key, mut row) = stored_row(&store, "descriptor")?;
    row.0.descriptor = changed.descriptor;
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&row)?].concat());
    tx.commit([])?;
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}
