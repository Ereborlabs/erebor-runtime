use super::*;

mod native;
mod validation;

#[test]
fn packages_retain_domain_references() -> TestResult {
    for owner in ["discovery-source-v1", "graph-packages-v1"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let retained = package("first", "v1")?;
        store.install_package(std::slice::from_ref(&retained), || Ok(()))?;
        let installed = store.meta()?.commit_revision;
        let key = crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: owner.into(),
            entity_key: b"result".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        };
        store.commit_context(&crate::AnalysisContextVersionV1 {
            key,
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&serde_json::json!({"installed_packages": [{
                "package_id": "first", "revision": "v1", "export": "model",
                "generation": installed, "parameters": null,
                "root": {"package_id": "first", "revision": "v1"}
            }]}))?,
        })?;
        store.commit_context(&crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "binary-owner".into(),
                entity_key: b"binary".to_vec(),
                lifetime_key: b"source".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: vec![0xff],
        })?;
        store.collect_package(retained.tenant_id, &retained.package_id, &retained.revision)?;
        store.collect_package_admissions()?;
        assert!(store.package_revision([1; 16], "first", "v1")?.is_some());
        let backup = root.join("backups/domain-reference");
        store.backup(&backup)?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        store.collect_package_admissions()?;
        assert!(store.package_revision([1; 16], "first", "v1")?.is_some());
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        restored.collect_package_admissions()?;
        assert!(restored.package_revision([1; 16], "first", "v1")?.is_some());
    }
    Ok(())
}

#[test]
fn domain_references_are_tenant_scoped() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let retained = package("first", "v1")?;
    store.install_package(std::slice::from_ref(&retained), || Ok(()))?;
    let mut other = package("first", "v1")?;
    other.tenant_id = [2; 16];
    store.install_package(&[other], || Ok(()))?;
    let installed = store.meta()?.commit_revision;
    store.commit_context(&crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [2; 16],
            owner_id: "graph-packages-v1".into(),
            entity_key: b"result".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&serde_json::json!({"installed_packages": [{
            "package_id": "first", "revision": "v1", "export": "model",
            "generation": installed, "parameters": null,
            "root": {"package_id": "first", "revision": "v1"}
        }]}))?,
    })?;
    store.collect_package(retained.tenant_id, &retained.package_id, &retained.revision)?;
    assert!(store.package_revision([1; 16], "first", "v1")?.is_none());
    assert!(store.package_revision([2; 16], "first", "v1")?.is_some());
    Ok(())
}
