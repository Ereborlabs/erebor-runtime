use super::*;

#[test]
fn uninstall_releases_exclusive_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
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
    assert!(revisions(&store, [1; 16])?.is_empty());
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
    let reopened = NativeStore::open(&root)?;
    assert!(revisions(&reopened, [1; 16])?.is_empty());
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
    let store = NativeStore::open(directory.path().join("store"))?;
    let bundle = PackageBundle::try_from(image("v1")?)?;
    let installed = store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let pin = araphor_discovery_definition::ImagePin {
        image: bundle.bundle().root.clone(),
        digest: bundle.digest().into(),
    };
    let before = store.meta()?;
    let retained = revisions(&store, [1; 16])?;
    let mut checked = false;
    assert!(store
        .uninstall_package_image([1; 16], &pin, || {
            checked = true;
            Err(Code::Denied.error("image guard"))
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert_eq!(revisions(&store, [1; 16])?, retained);
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
    let store = NativeStore::open(&root)?;
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
    let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
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
            Some(revision),
            &AnalysisReadControl::default()
        )?,
        Some((definition.clone(), revision))
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
    let reopened = NativeStore::open(&root)?;
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
    let store = NativeStore::open(&root)?;
    let mut bundle = image("native-unused")?;
    for artifact in &mut bundle.artifacts {
        artifact.implementations = artifact
            .descriptor
            .exports
            .iter()
            .map(|model| araphor_data::PackageImplementationV1::Native {
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
    assert!(revisions(&store, [1; 16])?.is_empty());
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
    let reopened = NativeStore::open(&root)?;
    assert!(revisions(&reopened, [1; 16])?.is_empty());
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
    let store = NativeStore::open(&root)?;
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
    assert!(revisions(&store, [1; 16])?.is_empty());
    drop(store);
    NativeStore::open(root)?;
    Ok(())
}
