use super::*;
use crate::{PackageBundleRef, PackageBundleV1, PackageRefV1};

fn bundle() -> crate::Result<PackageBundleV1> {
    let mut root = package("native-root", "v1")?.decode_artifact()?;
    let dependency = package("native-dependency", "v1")?.decode_artifact()?;
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
    let bundle = PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, dependency],
    };
    bundle.validate()?;
    Ok(bundle)
}

#[test]
fn package_context_retains_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let mut bundle = bundle()?;
    let mut artifact = bundle.artifacts.remove(0);
    for index in 0..1023 {
        let dependency =
            package(&format!("native-extra-{index:04}"), &"r".repeat(1024))?.decode_artifact()?;
        artifact.descriptor.exports[0]
            .inputs
            .push(araphor_analysis_sdk::InputPort {
                port: araphor_analysis_sdk::Port::new(
                    format!("source-{index}"),
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
        bundle.artifacts.push(dependency);
    }
    let dependency = &mut bundle.artifacts[0];
    for index in 0..1024 {
        let mut model = araphor_analysis_sdk::Model::new(
            format!("model-{index}"),
            Vec::new(),
            dependency.descriptor.exports[0].outputs.clone(),
        );
        model.input_mode = araphor_analysis_sdk::InputMode::Resolved;
        dependency
            .implementations
            .push(crate::PackageImplementationV1::Sql {
                export: model.name.clone(),
                program: crate::SqlModelV1 {
                    outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                    ..Default::default()
                },
            });
        dependency.descriptor.exports.push(model);
    }
    bundle.artifacts.insert(0, artifact);
    let revisions = PackageRevisionV1::from_bundle(&bundle, [1; 16])?;
    assert_eq!(revisions.len(), 1025);
    let dependencies = &revisions[0].dependencies;
    assert_eq!(dependencies.len(), 1024);
    assert!(serde_json::to_vec(dependencies)?.len() > 1024 * 1024);
    let initial = store.meta()?;
    assert!(store
        .install_package(&revisions, || crate::AnalysisReadDeniedSnafu.fail())
        .is_err());
    assert_eq!(store.meta()?, initial);
    assert!(store
        .package_revision([1; 16], "native-root", "v1")?
        .is_none());
    store.install_package(&revisions, || Ok(()))?;
    let installed = store.meta()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    assert_eq!(store.meta()?, installed);
    assert_eq!(store.package_revisions([1; 16])?.len(), revisions.len());
    let context =
        PackageBundleRef::new(&bundle)?.context([1; 16], &bundle.root, "model", "rows")?;
    let reference = store.intern_context(&context)?;
    let pinned = store.meta()?;
    assert_eq!(store.intern_context(&context)?, reference);
    assert_eq!(store.commit_context(&context)?, reference.commit_revision);
    assert_eq!(store.meta()?, pinned);
    assert_eq!(bundle.artifacts[1].descriptor.exports.len(), 1025);
    let export_context = PackageBundleRef::new(&bundle)?.context(
        [1; 16],
        &bundle.artifacts[1].reference(),
        "model-1023",
        "rows",
    )?;
    let export_revision = store.commit_context(&export_context)?;
    assert_eq!(store.commit_context(&export_context)?, export_revision);
    store.commit_context(&crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            owner_id: "binary-owner".into(),
            entity_key: b"binary".to_vec(),
            ..context.key.clone()
        },
        body: vec![0xff],
        ..context.clone()
    })?;
    store.collect_package_admissions()?;
    for revision in &revisions {
        assert_eq!(
            store.package_revision([1; 16], &revision.package_id, &revision.revision)?,
            Some(revision.clone())
        );
    }
    let backup = root.join("backups/native-package");
    store.backup(&backup)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
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
        assert_eq!(store.package_revisions([1; 16])?.len(), revisions.len());
        let mut retained = Vec::new();
        for revision in &revisions {
            retained.push(
                store
                    .package_revision([1; 16], &revision.package_id, &revision.revision)?
                    .ok_or("native artifact absent")?
                    .decode_artifact()?,
            );
        }
        assert_eq!(
            PackageBundleV1 {
                schema_version: 1,
                root: bundle.root.clone(),
                artifacts: retained
            }
            .digest()?,
            bundle.digest()?
        );
    }
    Ok(())
}

#[test]
fn package_context_tenant_scope() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let bundle = bundle()?;
    for tenant in [1, 2] {
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [tenant; 16])?,
            || Ok(()),
        )?;
    }
    let context =
        PackageBundleRef::new(&bundle)?.context([2; 16], &bundle.root, "model", "rows")?;
    store.intern_context(&context)?;
    let before = store.meta()?;
    let mut notice = store.subscribe_revision();
    notice.borrow_and_update();
    store.collect_package_admissions()?;
    let after = store.meta()?;
    assert_eq!(after.commit_revision, before.commit_revision + 1);
    assert!(notice.has_changed()?);
    assert_eq!(*notice.borrow_and_update(), after.commit_revision);
    assert!(store
        .package_revision([1; 16], "native-root", "v1")?
        .is_none());
    assert!(store
        .package_revision([1; 16], "native-dependency", "v1")?
        .is_none());
    assert!(store
        .package_revision([2; 16], "native-root", "v1")?
        .is_some());
    assert!(store
        .package_revision([2; 16], "native-dependency", "v1")?
        .is_some());
    store.collect_package_admissions()?;
    assert_eq!(store.meta()?, after);
    assert!(!notice.has_changed()?);
    Ok(())
}

#[test]
fn package_context_checks_artifact() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let bundle = bundle()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let context =
        PackageBundleRef::new(&bundle)?.context([1; 16], &bundle.root, "model", "rows")?;
    let original: serde_json::Value = serde_json::from_slice(&context.body)?;
    let initial = store.meta()?;
    for change in 0..7 {
        let mut candidate = context.clone();
        let mut body = original.clone();
        match change {
            0 => body["digest"] = serde_json::json!("wrong"),
            1 => {
                body["root"] = serde_json::to_value(PackageRefV1 {
                    package_id: "absent".into(),
                    revision: "v1".into(),
                })?
            }
            2 => body["export"] = serde_json::json!("absent"),
            3 => body["output"] = serde_json::json!("absent"),
            4 => body["generation"] = serde_json::json!(1),
            5 => candidate.key.tenant_id = [2; 16],
            _ => candidate.sensitivity = crate::ContextSensitivityV1::Public,
        }
        candidate.body = serde_json::to_vec(&body)?;
        candidate.key.entity_key = crate::Qualification::digest(&candidate.body).into_bytes();
        candidate.key.lifetime_key = body["digest"]
            .as_str()
            .ok_or("digest absent")?
            .as_bytes()
            .to_vec();
        assert!(store.intern_context(&candidate).is_err(), "change {change}");
        assert_eq!(store.meta()?, initial);
    }
    store.intern_context(&context)?;
    let mut changed = bundle.artifacts[0].clone();
    let crate::PackageImplementationV1::Sql { program, .. } = &mut changed.implementations[0]
    else {
        return Err("SQL implementation absent".into());
    };
    program.outputs.insert("rows".into(), "SELECT 2".into());
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact = ? WHERE package_id = ?",
        duckdb::params![changed.encode()?, changed.descriptor.id],
    )?;
    assert!(store.context_version(&context.key).is_err());
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn package_context_pins_dependency_artifact() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let bundle = bundle()?;
    store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let retained = PackageBundleRef::new(&bundle)?;
    let dependency = PackageRefV1 {
        package_id: "native-dependency".into(),
        revision: "v1".into(),
    };
    let context = retained.context([1; 16], &dependency, "model", "rows")?;
    let mut invalid = bundle.clone();
    invalid.schema_version = 0;
    assert!(matches!(
        PackageBundleRef::retained(&invalid, retained.digest()).context(
            [1; 16],
            &dependency,
            "model",
            "rows"
        ),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "bundle version or package count",
            ..
        })
    ));
    let root_context = retained.context([1; 16], &bundle.root, "model", "rows")?;
    assert_ne!(context.key, root_context.key);
    let body: serde_json::Value = serde_json::from_slice(&context.body)?;
    assert_eq!(body["root"], serde_json::to_value(&bundle.root)?);
    assert_eq!(body["package"], serde_json::to_value(&dependency)?);
    let pin = store.intern_context(&context)?;
    for (package, export, output) in [
        (
            PackageRefV1 {
                package_id: "missing".into(),
                revision: "v1".into(),
            },
            "model",
            "rows",
        ),
        (
            PackageRefV1 {
                revision: "missing".into(),
                ..dependency.clone()
            },
            "model",
            "rows",
        ),
        (dependency.clone(), "missing", "rows"),
        (dependency.clone(), "model", "missing"),
    ] {
        assert!(retained.context([1; 16], &package, export, output).is_err());
    }
    let before = store.meta()?;
    let mut forged = context.clone();
    let mut body = body;
    body["package"]["revision"] = "missing".into();
    forged.body = serde_json::to_vec(&body)?;
    forged.key.entity_key = crate::Qualification::digest(&forged.body).into_bytes();
    assert!(store.intern_context(&forged).is_err());
    assert_eq!(store.meta()?, before);
    drop(store);
    let store = AnalysisStore::open(root)?;
    assert_eq!(store.context_version(&pin.key)?, Some(context));
    Ok(())
}

#[test]
fn native_context_rejects_corruption() -> TestResult {
    for fault in ["body", "artifact", "descriptor"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let bundle = bundle()?;
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
            || Ok(()),
        )?;
        let context =
            PackageBundleRef::new(&bundle)?.context([1; 16], &bundle.root, "model", "rows")?;
        store.commit_context(&context)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            match fault {
                "body" => {
                    let mut body: serde_json::Value = serde_json::from_slice(&context.body)?;
                    body["output"] = serde_json::json!("changed");
                    writer.execute(
                        "UPDATE context_versions SET body = ? WHERE owner_id = ?",
                        duckdb::params![serde_json::to_vec(&body)?, "native-package-v1"],
                    )?;
                }
                "artifact" => {
                    writer.execute(
                        "DELETE FROM package_revisions WHERE package_id = ?",
                        duckdb::params![bundle.root.package_id],
                    )?;
                }
                _ => {
                    let mut descriptor = bundle.artifact(&bundle.root)?.descriptor.clone();
                    descriptor.exports[0].name = "changed".into();
                    writer.execute(
                        "UPDATE package_revisions SET descriptor = ? WHERE package_id = ?",
                        duckdb::params![serde_json::to_vec(&descriptor)?, bundle.root.package_id],
                    )?;
                }
            }
        }
        if fault == "body" {
            let before = store.meta()?;
            let failure = store
                .commit_context(&context)
                .err()
                .ok_or("corrupt stored context accepted")?;
            assert_eq!(
                erebor_runtime_error::ErrorExt::status_code(&failure),
                erebor_runtime_error::StatusCode::IllegalState
            );
            assert_eq!(
                erebor_runtime_error::ErrorExt::retry_hint(&failure),
                erebor_runtime_error::RetryHint::NonRetryable
            );
            assert!(matches!(
                failure,
                crate::Error::StoredArtifact { source, .. }
                    if matches!(source.as_ref(), crate::Error::Package {
                        code: crate::PackageErrorCodeV1::Invalid,
                        field: "native package context identity", ..
                    })
            ));
            assert_eq!(store.meta()?, before);
        }
        assert!(store.context_version(&context.key).is_err(), "{fault}");
        assert!(
            store
                .context_head_page([1; 16], "native-package-v1", None)
                .is_err(),
            "{fault}"
        );
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{fault}");
    }
    Ok(())
}
