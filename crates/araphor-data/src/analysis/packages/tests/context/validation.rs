use super::super::*;

fn context(
    package: &PackageRevisionV1,
    installed: u64,
) -> crate::Result<crate::AnalysisContextVersionV1> {
    Ok(crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: package.tenant_id,
            owner_id: "graph-packages-v1".into(),
            entity_key: b"result".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&serde_json::json!({"installed_packages": [{
            "package_id": package.package_id, "revision": package.revision,
            "export": "model", "generation": installed,
            "parameters": null,
            "root": {"package_id": package.package_id, "revision": package.revision}
        }]}))
        .context(crate::PackageEncodingSnafu)?,
    })
}

#[test]
fn domain_refs_require_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let retained = package("first", "v1")?;
    store.install_package(std::slice::from_ref(&retained), || Ok(()))?;
    let input = context(&retained, store.meta()?.commit_revision)?;
    let original: serde_json::Value = serde_json::from_slice(&input.body)?;
    let before = store.meta()?.commit_revision;
    for change in 0..12 {
        let mut candidate = input.clone();
        let mut body = original.clone();
        let reference = &mut body["installed_packages"][0];
        match change {
            0 => {
                reference
                    .as_object_mut()
                    .ok_or("reference")?
                    .remove("export");
            }
            1 => {
                reference
                    .as_object_mut()
                    .ok_or("reference")?
                    .remove("parameters");
            }
            2 => reference["generation"] = serde_json::json!(0),
            3 => reference["revision"] = serde_json::json!("missing"),
            4 => reference["export"] = serde_json::json!("missing"),
            5 => reference["root"]["package_id"] = serde_json::json!("missing"),
            6 => reference["package_id"] = serde_json::json!("bad/name"),
            7 => reference["parameters"] = serde_json::json!({"first":{"model":{"extra":1}}}),
            8 => candidate.key.tenant_id = [2; 16],
            9 => candidate.sensitivity = crate::ContextSensitivityV1::Public,
            10 => {
                body["installed_packages"]
                    .as_array_mut()
                    .ok_or("references")?
                    .push(original["installed_packages"][0].clone());
            }
            _ => {
                body.as_object_mut()
                    .ok_or("body")?
                    .remove("installed_packages");
            }
        }
        candidate.body = serde_json::to_vec(&body)?;
        assert!(store.commit_context(&candidate).is_err(), "change {change}");
        assert_eq!(store.meta()?.commit_revision, before);
    }
    store.commit_context(&input)?;
    store.collect_package(retained.tenant_id, &retained.package_id, &retained.revision)?;
    assert_eq!(store.context_version(&input.key)?, Some(input));
    Ok(())
}

#[test]
fn legacy_discovery_context_reopens() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let input = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "discovery-source-v1".into(),
            entity_key: b"result".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: br#"{"kind":"SOURCE_HEALTH","unknown":true}"#.to_vec(),
    };
    store.commit_context(&input)?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.context_version(&input.key)?, Some(input));
    Ok(())
}

#[test]
fn domain_ref_corruption_rejected() -> TestResult {
    for change in 0..3 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let retained = package("first", "v1")?;
        store.install_package(std::slice::from_ref(&retained), || Ok(()))?;
        let input = context(&retained, store.meta()?.commit_revision)?;
        store.commit_context(&input)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            if change == 0 {
                writer.execute(
                    "UPDATE context_versions SET body = ? WHERE owner_id = ?",
                    duckdb::params![
                        br#"{"installed_packages":[]}"#.as_slice(),
                        "graph-packages-v1"
                    ],
                )?;
            } else if change == 1 {
                writer.execute(
                    "DELETE FROM package_revisions WHERE package_id = ?",
                    duckdb::params!["first"],
                )?;
            } else {
                let mut descriptor: araphor_analysis_sdk::Package =
                    serde_json::from_slice(&package("first", "v1")?.descriptor)?;
                descriptor.exports[0].name = "changed".into();
                writer.execute(
                    "UPDATE package_revisions SET descriptor = ? WHERE package_id = ?",
                    duckdb::params![serde_json::to_vec(&descriptor)?.as_slice(), "first"],
                )?;
            }
        }
        if change == 0 {
            let before = store.meta()?;
            assert!(matches!(
                store.commit_context(&input),
                Err(crate::Error::Package {
                    code: crate::PackageErrorCodeV1::Invalid,
                    field: "installed context reference fields",
                    ..
                })
            ));
            assert_eq!(store.meta()?, before);
        }
        assert!(store.context_version(&input.key).is_err());
        assert!(store
            .context_head_page([1; 16], "graph-packages-v1", None)
            .is_err());
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "change {change}");
    }
    Ok(())
}

#[test]
fn domain_refs_require_closure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let retained = package("first", "v1")?;
    store.install_package(std::slice::from_ref(&retained), || Ok(()))?;
    let installed = store.meta()?.commit_revision;
    let other = package("other", "v1")?;
    store.install_package(std::slice::from_ref(&other), || Ok(()))?;
    let mut input = context(&retained, installed)?;
    let mut body: serde_json::Value = serde_json::from_slice(&input.body)?;
    body["installed_packages"][0]["root"]["package_id"] = serde_json::json!("other");
    input.body = serde_json::to_vec(&body)?;
    assert!(store.commit_context(&input).is_err());
    let mut dependent = package("dependent", "v1")?;
    let mut artifact = dependent.decode_artifact()?;
    let mut descriptor: araphor_analysis_sdk::Package =
        serde_json::from_slice(&dependent.descriptor)?;
    descriptor.exports[0]
        .inputs
        .push(araphor_analysis_sdk::InputPort {
            port: araphor_analysis_sdk::Port::new("rows", araphor_analysis_sdk::Schema::empty()),
            source: araphor_analysis_sdk::InputSource::Table(
                araphor_analysis_sdk::TableRef::Output(araphor_analysis_sdk::OutputRef {
                    package: "first".into(),
                    revision: "v1".into(),
                    export: "model".into(),
                    output: "rows".into(),
                }),
            ),
        });
    dependent.descriptor = serde_json::to_vec(&descriptor)?;
    artifact.descriptor = descriptor;
    let bytes = artifact.encode()?;
    dependent.artifact = bytes;
    dependent.dependencies.push(PackageRevisionRefV1 {
        package_id: "first".into(),
        revision: "v1".into(),
    });
    store.install_package(&[dependent], || Ok(()))?;
    body["installed_packages"][0]["root"]["package_id"] = serde_json::json!("dependent");
    input.body = serde_json::to_vec(&body)?;
    store.commit_context(&input)?;
    store.collect_package(retained.tenant_id, &retained.package_id, &retained.revision)?;
    store.collect_package(other.tenant_id, &other.package_id, &other.revision)?;
    store.collect_package_admissions()?;
    assert!(store
        .package_revision([1; 16], "dependent", "v1")?
        .is_some());
    assert!(store.package_revision([1; 16], "first", "v1")?.is_some());
    let backup = root.join("backups/closure");
    store.backup(&backup)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.context_version(&input.key)?, Some(input.clone()));
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(restored.context_version(&input.key)?, Some(input));
    Ok(())
}
