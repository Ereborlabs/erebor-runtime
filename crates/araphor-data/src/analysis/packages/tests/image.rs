use super::*;
use crate::{AnalysisReadControl, PackageBundleV1, PackageImplementationV1};

fn image(revision: &str) -> crate::Result<PackageBundleV1> {
    let mut root = package("image-root", revision)?.decode_artifact()?;
    let mut dependency = package("image-dependency", "v1")?.decode_artifact()?;
    dependency.implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["model".into()],
        artifact: (0u8..=255).cycle().take(8193).collect(),
    }];
    root.descriptor.exports[0]
        .inputs
        .push(araphor_analysis_sdk::InputPort {
            port: araphor_analysis_sdk::Port::new("source", araphor_analysis_sdk::Schema::empty()),
            source: araphor_analysis_sdk::InputSource::Table(
                araphor_analysis_sdk::TableRef::Output(araphor_analysis_sdk::OutputRef {
                    package: dependency.descriptor.id.clone(),
                    revision: dependency.descriptor.revision.clone(),
                    export: "model".into(),
                    output: "rows".into(),
                }),
            ),
        });
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, dependency],
    })
}

fn inspect(store: &AnalysisStore, revision: Option<&str>) -> crate::Result<PackageBundleV1> {
    store
        .package_image(
            [1; 16],
            "image-root",
            revision,
            &AnalysisReadControl::default(),
        )?
        .ok_or_else(|| store.state_error("the installed test image is absent"))
}

#[test]
fn package_image_retains_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let image = image("v1")?;
    let digest = image.digest()?;
    let expected_metadata = image.metadata()?;
    let mut expected = image.artifacts.clone();
    expected.sort_by_key(crate::PackageArtifactV1::reference);
    let metadata = PackageRevisionV1::from_artifact(&image.artifacts[0], [1; 16])?;
    assert!(metadata.artifact.is_empty());
    assert_eq!(metadata.dependencies.len(), 1);
    let installed = store.install_package_image([1; 16], &image, || Ok(()))?;
    assert_eq!(installed, store.meta()?.commit_revision);
    let saved = store.meta()?;
    let charge = store.read_snapshot(|reader| AnalysisStore::logical_usage(reader, [1; 16]))?;
    let records = store.package_revisions([1; 16])?;
    assert_eq!(records.len(), 2);
    let revision_bytes = records.iter().try_fold(0usize, |bytes, record| {
        Ok::<_, serde_json::Error>(
            bytes
                + 256
                + record.package_id.len()
                + record.revision.len()
                + record.descriptor.len()
                + record.artifact.len()
                + serde_json::to_vec(&record.dependencies)?.len(),
        )
    })?;
    assert_eq!(
        charge.1,
        (revision_bytes
            + 256
            + image.root.package_id.len()
            + image.root.revision.len()
            + digest.len()) as u64
    );
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
    assert_eq!(
        store.read_snapshot(|reader| AnalysisStore::logical_usage(reader, [1; 16]))?,
        charge
    );
    assert!(store.package_activation_page(None)?.is_empty());
    let results: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM package_results", [], |row| row.get(0))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count image test results",
            })
    })?;
    assert_eq!(results, 0);
    let retained = inspect(&store, None)?;
    assert_eq!(retained.digest()?, digest);
    assert_eq!(retained.metadata()?, expected_metadata);
    assert_eq!(inspect(&store, Some("v1"))?.artifacts, expected);
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
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    for store in [&reopened, &restored] {
        store.collect_package_admissions()?;
        let actual = inspect(store, None)?;
        assert_eq!(actual.digest()?, digest);
        assert_eq!(actual.artifacts, expected);
        assert_eq!(actual.metadata()?, expected_metadata);
        assert!(store.package_activation_page(None)?.is_empty());
        assert_eq!(
            store.install_package_image([1; 16], &image, || Ok(()))?,
            installed
        );
    }
    Ok(())
}

#[test]
fn package_image_install_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let image = image("v1")?;
    let before = store.meta()?;
    let mut checked = false;
    assert!(store
        .install_package_image([1; 16], &image, || {
            checked = true;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert!(store.package_revisions([1; 16])?.is_empty());
    assert!(store
        .package_image([1; 16], "image-root", None, &AnalysisReadControl::default())?
        .is_none());
    let installed = store.install_package_image([1; 16], &image, || Ok(()))?;
    let before = store.meta()?;
    assert!(store
        .install_package_image([1; 16], &image, || crate::AnalysisReadDeniedSnafu.fail())
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store.install_package_image([1; 16], &image, || Ok(()))?,
        installed
    );
    let mut changed = image.clone();
    let PackageImplementationV1::Sql { program, .. } = &mut changed.artifacts[0].implementations[0]
    else {
        return Err("SQL image fixture is absent".into());
    };
    program.outputs.insert("rows".into(), "SELECT 2".into());
    assert!(matches!(
        store.install_package_image([1; 16], &changed, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(inspect(&store, None)?.digest()?, image.digest()?);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.package_image([1; 16], "image-root", None, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(inspect(&store, None)?.digest()?, image.digest()?);
    Ok(())
}

#[test]
fn package_image_versions_and_tenants() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let first = image("v1")?;
    let second = image("v2")?;
    let first_revision = store.install_package_image([1; 16], &first, || Ok(()))?;
    let second_revision = store.install_package_image([1; 16], &second, || Ok(()))?;
    assert!(second_revision > first_revision);
    assert_eq!(inspect(&store, None)?.digest()?, second.digest()?);
    assert_eq!(inspect(&store, Some("v1"))?.digest()?, first.digest()?);
    assert_eq!(
        store.install_package_image([1; 16], &first, || Ok(()))?,
        first_revision
    );
    assert_eq!(inspect(&store, None)?.digest()?, second.digest()?);
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
            .digest()?,
        first.digest()?
    );
    assert_eq!(inspect(&store, Some("v1"))?.digest()?, first.digest()?);
    Ok(())
}

#[test]
fn package_image_rejects_invalid_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut invalid = image("v1")?;
    invalid.artifacts[0].descriptor.exports[0].inputs[0]
        .port
        .schema = araphor_analysis_sdk::Schema::new(vec![araphor_analysis_sdk::Field::new(
        "id",
        araphor_analysis_sdk::DataType::UInt64,
        false,
    )]);
    let before = store.meta()?;
    assert!(store
        .install_package_image([1; 16], &invalid, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.package_revisions([1; 16])?.is_empty());
    invalid.artifacts.pop();
    assert!(store
        .install_package_image([1; 16], &invalid, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.package_revisions([1; 16])?.is_empty());
    Ok(())
}

#[test]
fn package_image_recovery_checks_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    store.install_package_image([1; 16], &image("v1")?, || Ok(()))?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE package_images SET digest = ?",
            [format!("sha256:{}", "0".repeat(64))],
        )?;
    }
    assert!(inspect(&store, None).is_err());
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}
