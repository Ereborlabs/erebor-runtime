use super::super::*;
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
    let bundle = bundle()?;
    let revisions = PackageRevisionV1::from_bundle(&bundle, [1; 16])?;
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
    let context = PackageBundleRef::new(&bundle)?.context([1; 16], "model", "rows")?;
    let reference = store.intern_context(&context)?;
    let pinned = store.meta()?;
    assert_eq!(store.intern_context(&context)?, reference);
    assert_eq!(store.meta()?, pinned);
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
    let context = PackageBundleRef::new(&bundle)?.context([2; 16], "model", "rows")?;
    store.intern_context(&context)?;
    store.collect_package_admissions()?;
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
    let context = PackageBundleRef::new(&bundle)?.context([1; 16], "model", "rows")?;
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
