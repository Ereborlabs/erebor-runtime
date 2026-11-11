use super::*;

#[test]
fn revision_reads_preserve_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    store.install_package(&[package("first", "v1")?], || Ok(()))?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let revision = store
        .package_revision([1; 16], "first", "v1")?
        .ok_or("installed revision")?;
    assert_eq!(
        store.package_revision_until([1; 16], "first", "v1", &control)?,
        Some(revision)
    );
    let cancelled = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    cancelled.cancel()?;
    assert!(matches!(
        store.package_revision_until([1; 16], "first", "v1", &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    let bundle = PackageBundle::try_from(image("v1")?)?;
    let pin = ImagePin {
        image: bundle.bundle().root.clone(),
        digest: bundle.digest().into(),
    };
    assert!(matches!(
        store.package_revision_until([1; 16], "first", "v1", &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store.package_image([1; 16], "image-root", None, &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store.retained_package_image([1; 16], &pin, &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(store
        .package_revision_until([1; 16], "first", "v1", &control)?
        .is_some());
    assert!(store
        .package_image([1; 16], "image-root", None, &control)?
        .is_none());
    assert!(store
        .retained_package_image([1; 16], &pin, &control)?
        .is_none());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    Ok(())
}

#[test]
fn image_retains_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let notices = store.subscribe_activations()?;
    let image = PackageBundle::try_from(image("v1")?)?;
    let digest = image.digest();
    let expected_metadata = image.metadata()?;
    let mut expected = image.bundle().artifacts.clone();
    expected.sort_by_key(araphor_data::PackageArtifactV1::reference);
    let metadata = PackageRevisionV1::from_artifact(&image.bundle().artifacts[0], [1; 16])?;
    assert!(metadata.artifact.is_empty());
    assert_eq!(metadata.dependencies.len(), 1);
    let installed = store.install_package_image([1; 16], &image, || Ok(()))?;
    assert_eq!(installed, store.meta()?.commit_revision);
    let saved = store.meta()?;
    let records = revisions(&store, [1; 16])?;
    assert_eq!(records.len(), 2);
    let mut checked = false;
    assert_eq!(
        store.install_package_image([1; 16], &image, || {
            checked = true;
            Ok(())
        })?,
        installed
    );
    assert!(checked);
    assert_eq!(store.meta()?, saved);
    assert_eq!(revisions(&store, [1; 16])?, records);
    assert_no_execution(&store)?;
    assert!(!notices.has_changed()?);
    let retained = inspect(&store, None)?;
    assert_eq!(retained.digest(), digest);
    assert_eq!(retained.metadata()?, expected_metadata);
    assert_eq!(inspect(&store, Some("v1"))?.bundle().artifacts, expected);
    store.install_package(&[package("unreferenced", "v1")?], || Ok(()))?;
    store.collect_package_admissions()?;
    assert!(store
        .package_revision([1; 16], "unreferenced", "v1")?
        .is_none());
    for record in &records {
        store.collect_package([1; 16], &record.package_id, &record.revision)?;
        assert_eq!(
            store.package_revision([1; 16], &record.package_id, &record.revision)?,
            Some(record.clone())
        );
    }
    let backup = root.join("backups/image");
    store.backup(&backup)?;
    drop(notices);
    drop(store);
    let reopened = NativeStore::open(&root)?;
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    for store in [&reopened, &restored] {
        let notices = store.subscribe_activations()?;
        store.collect_package_admissions()?;
        let actual = inspect(store, None)?;
        assert_eq!(actual.digest(), digest);
        assert_eq!(actual.bundle().artifacts, expected);
        assert_eq!(actual.metadata()?, expected_metadata);
        assert_no_execution(store)?;
        assert_eq!(
            store.install_package_image([1; 16], &image, || Ok(()))?,
            installed
        );
        assert!(!notices.has_changed()?);
        assert_no_execution(store)?;
    }
    Ok(())
}

#[test]
fn image_install_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let image = PackageBundle::try_from(image("v1")?)?;
    let before = store.meta()?;
    let mut checked = false;
    assert!(store
        .install_package_image([1; 16], &image, || {
            checked = true;
            Err(Code::Denied.error("image guard"))
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert!(revisions(&store, [1; 16])?.is_empty());
    assert!(store
        .package_image([1; 16], "image-root", None, &AnalysisReadControl::default())?
        .is_none());
    let installed = store.install_package_image([1; 16], &image, || Ok(()))?;
    let before = store.meta()?;
    assert!(store
        .install_package_image([1; 16], &image, || Err(Code::Denied.error("image guard")))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store.install_package_image([1; 16], &image, || Ok(()))?,
        installed
    );
    let mut changed = image.bundle().clone();
    let PackageImplementationV1::Sql { program, .. } = &mut changed.artifacts[0].implementations[0]
    else {
        return Err("SQL image fixture is absent".into());
    };
    program.outputs.insert("rows".into(), "SELECT 2".into());
    let changed = PackageBundle::try_from(changed)?;
    assert!(matches!(
        store.install_package_image([1; 16], &changed, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(inspect(&store, None)?.digest(), image.digest());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.package_image([1; 16], "image-root", None, &cancelled),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(inspect(&store, None)?.digest(), image.digest());
    Ok(())
}

#[test]
fn image_versions_and_tenants() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let first = PackageBundle::try_from(image("v1")?)?;
    let second = PackageBundle::try_from(image("v2")?)?;
    let first_revision = store.install_package_image([1; 16], &first, || Ok(()))?;
    let second_revision = store.install_package_image([1; 16], &second, || Ok(()))?;
    assert!(second_revision > first_revision);
    assert_eq!(inspect(&store, None)?.digest(), second.digest());
    assert_eq!(inspect(&store, Some("v1"))?.digest(), first.digest());
    assert_eq!(
        store.install_package_image([1; 16], &first, || Ok(()))?,
        first_revision
    );
    assert_eq!(inspect(&store, None)?.digest(), second.digest());
    let control = AnalysisReadControl::default();
    assert!(store
        .package_image([2; 16], "image-root", None, &control)?
        .is_none());
    assert!(store
        .package_image([1; 16], "image-root", Some("absent"), &control)?
        .is_none());
    store.install_package_image([2; 16], &first, || Ok(()))?;
    store.collect_package_admissions()?;
    assert_eq!(
        store
            .package_image([2; 16], "image-root", None, &control)?
            .ok_or("tenant image absent")?
            .digest(),
        first.digest()
    );
    assert_eq!(inspect(&store, Some("v1"))?.digest(), first.digest());
    Ok(())
}

#[test]
fn image_rejects_invalid_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let mut invalid = image("v1")?;
    invalid.artifacts[0].descriptor.exports[0].inputs[0]
        .port
        .schema = araphor_analysis_sdk::Schema::new(vec![araphor_analysis_sdk::Field::new(
        "id",
        araphor_analysis_sdk::DataType::UInt64,
        false,
    )]);
    let mut missing = invalid.clone();
    missing.artifacts.pop();
    let before = store.meta()?;
    assert!(PackageBundle::try_from(invalid).is_err());
    assert_eq!(store.meta()?, before);
    assert!(revisions(&store, [1; 16])?.is_empty());
    assert!(PackageBundle::try_from(missing).is_err());
    assert_eq!(store.meta()?, before);
    assert!(revisions(&store, [1; 16])?.is_empty());
    Ok(())
}

#[test]
fn image_recovery_checks_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let image = PackageBundle::try_from(image("v1")?)?;
    store.install_package_image([1; 16], &image, || Ok(()))?;
    let view = store.view()?;
    let (key, bytes) = view
        .snapshot()
        .prefix(b"\0data/I")
        .next()
        .ok_or("image record")??;
    let mut row: ([u8; 16], araphor_data::PackageRefV1, String, u64, bool) =
        rmp_serde::from_slice(&bytes[1..])?;
    row.2 = format!("sha256:{}", "0".repeat(64));
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&row)?].concat());
    tx.commit([])?;
    assert!(inspect(&store, None).is_err());
    drop(view);
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[test]
fn image_large_roundtrip() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let mut bundle = image("large")?;
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "model".into(),
        artifact: vec![255; 33 * 1024 * 1024],
        qualification: None,
    }];
    assert!(matches!(
        bundle.artifacts[0].implementation("model"),
        Err(araphor_package::Error::Package {
            code: araphor_package::ErrorCode::Unsupported,
            field: "model target",
            ..
        })
    ));
    let mut expected = PackageRevisionV1::from_artifact(&bundle.artifacts[0], [1; 16])?;
    expected.artifact = bundle.artifacts[0].encode()?;
    assert!(expected.artifact.len() > 32 * 1024 * 1024);
    let bundle = PackageBundle::try_from(bundle)?;
    let installed = store.install_package_image([1; 16], &bundle, || Ok(()))?;
    assert_no_execution(&store)?;
    let before = *store.subscribe_revision().borrow();
    assert_eq!(
        store.install_package_image([1; 16], &bundle, || Ok(()))?,
        installed
    );
    assert!(
        store.package_revision([1; 16], "image-root", "large")? == Some(expected),
        "retained revision differs"
    );
    assert_eq!(*store.subscribe_revision().borrow(), before);
    let mut expected = bundle.bundle().artifacts.iter().collect::<Vec<_>>();
    expected.sort_by_key(|artifact| artifact.reference());
    drop(store);
    let store = NativeStore::open(&root)?;
    let restored = inspect(&store, Some("large"))?;
    assert!(
        restored.bundle().artifacts.iter().collect::<Vec<_>>() == expected,
        "retained artifacts differ"
    );
    let digest = restored.digest().to_owned();
    let bytes = restored.bundle().encode()?;
    assert!(bytes.len() > 32 * 1024 * 1024);
    drop(restored);
    let restored = PackageBundleV1::from_bytes(&bytes)?;
    assert!(
        restored.artifacts.iter().collect::<Vec<_>>() == expected,
        "decoded artifacts differ"
    );
    assert_eq!(restored.digest()?, digest);
    assert_no_execution(&store)?;
    Ok(())
}
