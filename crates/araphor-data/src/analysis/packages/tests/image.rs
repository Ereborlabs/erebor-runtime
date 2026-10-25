use super::*;
use crate::analysis::tests::assert_no_execution;
use crate::{AnalysisReadControl, PackageBundle, PackageBundleV1, PackageImplementationV1};

#[test]
fn revision_reads_release_capacity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("store"),
        Default::default(),
        crate::StorageLimitsV1 {
            reader_admissions: Some(16),
            ..Default::default()
        },
    )?;
    store.install_package(&[package("first", "v1")?], || Ok(()))?;
    let before = store.meta()?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let revision = store
        .package_revision([1; 16], "first", "v1")?
        .ok_or("installed artifact revision")?;
    assert_eq!(
        store.package_revision_until([1; 16], "first", "v1", &control)?,
        Some(revision)
    );
    let cancelled = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    cancelled.cancel()?;
    assert!(matches!(
        store.package_revision_until([1; 16], "first", "v1", &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(
        store
            .read_slots
            .as_ref()
            .ok_or("configured reader admissions")?
            .available_permits(),
        16
    );
    assert_eq!(store.meta()?, before);
    Ok(())
}

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

fn inspect(store: &AnalysisStore, revision: Option<&str>) -> crate::Result<PackageBundle> {
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
    let notices = store.subscribe_activations();
    let image = PackageBundle::try_from(image("v1")?)?;
    let digest = image.digest();
    let expected_metadata = image.metadata()?;
    let mut expected = image.bundle().artifacts.clone();
    expected.sort_by_key(crate::PackageArtifactV1::reference);
    let metadata = PackageRevisionV1::from_artifact(&image.bundle().artifacts[0], [1; 16])?;
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
            + image.bundle().root.package_id.len()
            + image.bundle().root.revision.len()
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
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    for store in [&reopened, &restored] {
        let notices = store.subscribe_activations();
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
fn package_image_install_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let image = PackageBundle::try_from(image("v1")?)?;
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
    let mut changed = image.bundle().clone();
    let PackageImplementationV1::Sql { program, .. } = &mut changed.artifacts[0].implementations[0]
    else {
        return Err("SQL image fixture is absent".into());
    };
    program.outputs.insert("rows".into(), "SELECT 2".into());
    let changed = PackageBundle::try_from(changed)?;
    assert!(matches!(
        store.install_package_image([1; 16], &changed, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(inspect(&store, None)?.digest(), image.digest());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.package_image([1; 16], "image-root", None, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(inspect(&store, None)?.digest(), image.digest());
    Ok(())
}

#[test]
fn package_image_versions_and_tenants() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
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
    let mut missing = invalid.clone();
    missing.artifacts.pop();
    let before = store.meta()?;
    assert!(PackageBundle::try_from(invalid).is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.package_revisions([1; 16])?.is_empty());
    assert!(PackageBundle::try_from(missing).is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.package_revisions([1; 16])?.is_empty());
    Ok(())
}

#[test]
fn package_image_recovery_checks_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let image = PackageBundle::try_from(image("v1")?)?;
    store.install_package_image([1; 16], &image, || Ok(()))?;
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

#[test]
fn package_image_large_roundtrip() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
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
    let store = AnalysisStore::open(&root)?;
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

#[test]
fn uninstall_releases_exclusive_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let first = image("v1")?;
    let mut second = first.clone();
    second.root.package_id = "second-root".into();
    second.artifacts[0].descriptor.id = second.root.package_id.clone();
    let dependency = PackageBundleV1 {
        schema_version: 1,
        root: first.artifacts[1].reference(),
        artifacts: vec![first.artifacts[1].clone()],
    };
    let first = PackageBundle::try_from(first)?;
    let second = PackageBundle::try_from(second)?;
    let dependency = PackageBundle::try_from(dependency)?;
    let pin = |image: &PackageBundle| araphor_discovery_definition::ImagePin {
        image: image.bundle().root.clone(),
        digest: image.digest().into(),
    };
    for bundle in [&first, &second, &dependency] {
        store.install_package_image([1; 16], bundle, || Ok(()))?;
    }
    store.install_package_image([2; 16], &first, || Ok(()))?;
    assert!(store.uninstall_package_image([1; 16], &pin(&first), || Ok(()))?);
    assert!(store
        .package_image(
            [1; 16],
            &first.bundle().root.package_id,
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(store
        .package_revision(
            [1; 16],
            &first.bundle().root.package_id,
            &first.bundle().root.revision
        )?
        .is_none());
    assert_eq!(
        store
            .package_image(
                [1; 16],
                &second.bundle().root.package_id,
                None,
                &AnalysisReadControl::default()
            )?
            .ok_or("shared image")?
            .digest(),
        second.digest()
    );
    assert!(store
        .package_revision(
            [1; 16],
            &dependency.bundle().root.package_id,
            &dependency.bundle().root.revision
        )?
        .is_some());
    assert!(store.uninstall_package_image([1; 16], &pin(&second), || Ok(()))?);
    assert!(store
        .package_revision(
            [1; 16],
            &second.bundle().root.package_id,
            &second.bundle().root.revision
        )?
        .is_none());
    assert_eq!(
        store
            .package_image(
                [1; 16],
                &dependency.bundle().root.package_id,
                None,
                &AnalysisReadControl::default()
            )?
            .ok_or("explicit dependency")?
            .digest(),
        dependency.digest()
    );
    assert!(store.uninstall_package_image([1; 16], &pin(&dependency), || Ok(()))?);
    assert!(store.package_revisions([1; 16])?.is_empty());
    assert_eq!(
        store
            .package_image(
                [2; 16],
                &first.bundle().root.package_id,
                None,
                &AnalysisReadControl::default()
            )?
            .ok_or("other tenant image")?
            .digest(),
        first.digest()
    );
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert!(reopened.package_revisions([1; 16])?.is_empty());
    assert_eq!(
        reopened
            .package_image(
                [2; 16],
                &first.bundle().root.package_id,
                None,
                &AnalysisReadControl::default()
            )?
            .ok_or("restored tenant image")?
            .digest(),
        first.digest()
    );
    Ok(())
}

#[test]
fn uninstall_guard_keeps_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let bundle = PackageBundle::try_from(image("v1")?)?;
    let installed = store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let pin = araphor_discovery_definition::ImagePin {
        image: bundle.bundle().root.clone(),
        digest: bundle.digest().into(),
    };
    let before = store.meta()?;
    let revisions = store.package_revisions([1; 16])?;
    let mut checked = false;
    assert!(store
        .uninstall_package_image([1; 16], &pin, || {
            checked = true;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.package_revisions([1; 16])?, revisions);
    assert_eq!(inspect(&store, None)?.digest(), pin.digest);
    assert_eq!(
        store.install_package_image([1; 16], &bundle, || Ok(()))?,
        installed
    );
    let mut forged = pin.clone();
    forged.digest = format!("sha256:{}", "0".repeat(64));
    assert!(store
        .uninstall_package_image([1; 16], &forged, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store.uninstall_package_image([1; 16], &pin, || Ok(()))?);
    let before = store.meta()?;
    checked = false;
    assert!(!store.uninstall_package_image([1; 16], &pin, || {
        checked = true;
        Ok(())
    })?);
    assert!(checked);
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn definitions_retain_uninstalled_images() -> TestResult {
    use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let first = PackageBundle::try_from(image("v1")?)?;
    let second = PackageBundle::try_from(image("v2")?)?;
    store.install_package_image([1; 16], &first, || Ok(()))?;
    let installed = store.install_package_image([1; 16], &second, || Ok(()))?;
    let pin = ImagePin {
        image: second.bundle().root.clone(),
        digest: second.digest().into(),
    };
    let sql = "SELECT * FROM \"image-root\".\"v2\".model()".to_owned();
    let definition = ResolvedDefinition::new(
        Definition {
            name: "retained-image".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: sql.clone(),
                },
            },
        },
        sql,
        vec![pin.clone()],
    )?;
    store.admit_definition([1; 16], &definition, || Ok(()))?;
    assert!(store.uninstall_package_image([1; 16], &pin, || Ok(()))?);
    assert_eq!(inspect(&store, None)?.digest(), first.digest());
    assert!(store
        .package_image(
            [1; 16],
            "image-root",
            Some("v2"),
            &AnalysisReadControl::default()
        )?
        .is_none());
    store.collect_package_admissions()?;
    assert_eq!(
        store
            .retained_package_image([1; 16], &pin, &AnalysisReadControl::default())?
            .ok_or("retained image")?
            .digest(),
        second.digest()
    );
    assert_eq!(
        store.definition(
            [1; 16],
            &definition.definition.name,
            Some(&definition.digest()?),
            &AnalysisReadControl::default()
        )?,
        Some(definition.clone())
    );
    let mut fresh = definition.clone();
    fresh.definition.name = "fresh-image".into();
    assert!(store.admit_definition([1; 16], &fresh, || Ok(())).is_err());
    let mut collision = second.bundle().clone();
    let PackageImplementationV1::Sql { program, .. } =
        &mut collision.artifacts[0].implementations[0]
    else {
        return Err("SQL image fixture".into());
    };
    program.outputs.insert("rows".into(), "SELECT 2".into());
    let collision = PackageBundle::try_from(collision)?;
    assert!(store
        .install_package_image([1; 16], &collision, || Ok(()))
        .is_err());
    let before = store.meta()?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.meta()?.commit_revision, before.commit_revision);
    assert_eq!(
        reopened
            .retained_package_image([1; 16], &pin, &AnalysisReadControl::default())?
            .ok_or("restored image")?
            .digest(),
        second.digest()
    );
    let reinstalled = reopened.install_package_image([1; 16], &second, || Ok(()))?;
    assert!(reinstalled > installed);
    assert_eq!(
        reopened.install_package_image([1; 16], &second, || Ok(()))?,
        reinstalled
    );
    assert_eq!(inspect(&reopened, None)?.digest(), second.digest());
    reopened.admit_definition([1; 16], &fresh, || Ok(()))?;
    Ok(())
}

#[test]
fn uninstall_collects_unused_native() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let mut bundle = image("native-unused")?;
    for artifact in &mut bundle.artifacts {
        artifact.implementations = artifact
            .descriptor
            .exports
            .iter()
            .map(|model| crate::PackageImplementationV1::Native {
                export: model.name.clone(),
                artifact: vec![0],
                qualification: None,
            })
            .collect();
    }
    let bundle = PackageBundle::try_from(bundle)?;
    let pin = araphor_discovery_definition::ImagePin {
        image: bundle.bundle().root.clone(),
        digest: bundle.digest().into(),
    };
    let receipt = store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let before = store.meta()?;
    assert_eq!(
        store.install_package_image([1; 16], &bundle, || Ok(()))?,
        receipt
    );
    assert_eq!(store.meta()?, before);
    assert_no_execution(&store)?;
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    assert!(store.uninstall_package_image([1; 16], &pin, || Ok(()))?);
    assert!(store.package_revisions([1; 16])?.is_empty());
    assert!(store
        .package_image(
            [1; 16],
            &pin.image.package_id,
            Some(&pin.image.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(store
        .retained_package_image([1; 16], &pin, &AnalysisReadControl::default())?
        .is_none());
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert!(reopened.package_revisions([1; 16])?.is_empty());
    assert_no_execution(&reopened)?;
    assert!(reopened
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    Ok(())
}

#[test]
fn packages_release_unused_dependencies() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let dependency = package("dependency", "v1")?;
    let mut consumer = package("consumer", "v1")?;
    let mut artifact = consumer.decode_artifact()?;
    artifact.descriptor.exports[0]
        .inputs
        .push(araphor_analysis_sdk::InputPort {
            port: araphor_analysis_sdk::Port::new("input", araphor_analysis_sdk::Schema::empty()),
            source: araphor_analysis_sdk::InputSource::Table(
                araphor_analysis_sdk::TableRef::Output(araphor_analysis_sdk::OutputRef {
                    package: "dependency".into(),
                    revision: "v1".into(),
                    export: "model".into(),
                    output: "rows".into(),
                }),
            ),
        });
    consumer.descriptor = serde_json::to_vec(&artifact.descriptor)?;
    consumer.artifact = artifact.encode()?;
    consumer.dependencies.push(PackageRevisionRefV1 {
        package_id: "dependency".into(),
        revision: "v1".into(),
    });
    store.install_package(&[consumer, dependency], || Ok(()))?;
    store.collect_package([1; 16], "dependency", "v1")?;
    assert!(store
        .package_revision([1; 16], "dependency", "v1")?
        .is_some());
    store.collect_package([1; 16], "consumer", "v1")?;
    assert!(store.package_revisions([1; 16])?.is_empty());
    drop(store);
    AnalysisStore::open(root)?;
    Ok(())
}
