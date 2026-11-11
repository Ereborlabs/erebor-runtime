use super::*;

#[test]
fn context_retains_large_closure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut bundle = bundle()?.bundle().clone();
    let mut root_artifact = bundle.artifacts.remove(0);
    for index in 0..1023 {
        let dependency = artifact(&format!("native-extra-{index:04}"), &"r".repeat(1024));
        root_artifact.descriptor.exports[0]
            .inputs
            .push(sdk::InputPort {
                port: sdk::Port::new(format!("source-{index}"), sdk::Schema::empty()),
                source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                    package: dependency.descriptor.id.clone(),
                    revision: dependency.descriptor.revision.clone(),
                    export: "model".into(),
                    output: "rows".into(),
                })),
            });
        bundle.artifacts.push(dependency);
    }
    let dependency = &mut bundle.artifacts[0];
    for index in 0..1024 {
        let mut model = sdk::Model::new(
            format!("model-{index}"),
            Vec::new(),
            dependency.descriptor.exports[0].outputs.clone(),
        );
        model.input_mode = sdk::InputMode::Resolved;
        dependency
            .implementations
            .push(PackageImplementationV1::Sql {
                export: model.name.clone(),
                program: SqlModelV1 {
                    outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                    ..Default::default()
                },
            });
        dependency.descriptor.exports.push(model);
    }
    bundle.artifacts.insert(0, root_artifact);
    let bundle = PackageBundle::try_from(bundle)?;
    let revisions = PackageRevisionV1::from_bundle(&bundle, [1; 16])?;
    assert_eq!(revisions.len(), 1025);
    assert_eq!(revisions[0].dependencies.len(), 1024);
    assert!(rmp_serde::to_vec_named(&revisions[0].dependencies)?.len() > 1024 * 1024);
    let initial = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(store
        .install_package(&revisions, || Err(Code::Denied.error("install guard")))
        .is_err());
    assert_eq!(store.meta()?, initial);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .view()?
        .package_revision(
            [1; 16],
            "native-root",
            "v1",
            &AnalysisReadControl::default()
        )?
        .is_none());
    store.install_package(&revisions, || Ok(()))?;
    let installed = store.meta()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    assert_eq!(store.meta()?, installed);
    retained(&store, &revisions)?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    let reference = store.intern_context(&context)?;
    let pinned = store.meta()?;
    assert_eq!(store.intern_context(&context)?, reference);
    assert_eq!(store.commit_context(&context)?, reference.commit_revision);
    assert_eq!(store.meta()?, pinned);
    assert_eq!(bundle.bundle().artifacts[1].descriptor.exports.len(), 1025);
    let export_context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().artifacts[1].reference(),
        "model-1023",
        "rows",
    )?;
    let export_revision = store.commit_context(&export_context)?;
    assert_eq!(store.commit_context(&export_context)?, export_revision);
    store.commit_context(&AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            owner_id: "binary-owner".into(),
            entity_key: b"binary".to_vec(),
            ..context.key.clone()
        },
        body: vec![0xff],
        ..context.clone()
    })?;
    store.collect_package_admissions()?;
    retained(&store, &revisions)?;
    let backup = root.join("backups/native-package");
    store.backup(&backup)?;
    drop(store);
    let reopened = NativeStore::open(&root)?;
    let restored = NativeStore::restore(&backup, &dir.path().join("restored"))?;
    for store in [&reopened, &restored] {
        store.collect_package_admissions()?;
        assert_eq!(
            store.context_version(&reference.key)?,
            Some(context.clone())
        );
        assert_eq!(
            store.context_version(&export_context.key)?,
            Some(export_context.clone())
        );
        assert_eq!(store.commit_context(&export_context)?, export_revision);
        retained(store, &revisions)?;
        let mut artifacts = Vec::new();
        let view = store.view()?;
        for revision in &revisions {
            artifacts.push(
                view.package_revision(
                    [1; 16],
                    &revision.package_id,
                    &revision.revision,
                    &AnalysisReadControl::default(),
                )?
                .ok_or("native artifact absent")?
                .decode_artifact()?,
            );
        }
        assert_eq!(
            PackageBundleV1 {
                schema_version: 1,
                root: bundle.bundle().root.clone(),
                artifacts,
            }
            .digest()?,
            bundle.digest()
        );
    }
    Ok(())
}
