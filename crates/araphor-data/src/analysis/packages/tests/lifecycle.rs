use super::*;

#[test]
fn packages_renew_preserves_checkpoint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let active = start(&store, "first")?;
    store.commit_package(&commit(active.clone(), "first"), || Ok(()))?;
    let current = store
        .package_activation(&active.key)?
        .ok_or("activation absent")?;
    assert!(store
        .renew_package(&current, b"new authority", "new-grant", || {
            crate::AnalysisConflictSnafu.fail()
        })
        .is_err());
    assert_eq!(
        store.package_activation(&active.key)?,
        Some(current.clone())
    );
    let renewed = store.renew_package(&current, b"new authority", "new-grant", || Ok(()))?;
    assert_ne!(renewed.generation, current.generation);
    assert_eq!(renewed.checkpoint_revision, current.checkpoint_revision);
    assert_eq!(renewed.result_id, current.result_id);
    assert!(!store.package_results(&active.key)?[0].stale);
    assert!(store
        .commit_package(&commit(current, "old-grant"), || Ok(()))
        .is_err());
    store.commit_package(&commit(renewed, "new-grant"), || Ok(()))?;
    drop(store);
    AnalysisStore::open(root)?;
    Ok(())
}

#[test]
fn packages_release_unused_dependencies() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let dependency = package("dependency", "v1")?;
    let mut consumer = package("consumer", "v1")?;
    let mut descriptor: araphor_analysis_sdk::Package =
        serde_json::from_slice(&consumer.descriptor)?;
    descriptor.exports[0]
        .inputs
        .push(araphor_analysis_sdk::InputPort {
            port: araphor_analysis_sdk::Port::new("input", araphor_analysis_sdk::Schema::empty()),
            source: araphor_analysis_sdk::InputSource::Output(araphor_analysis_sdk::OutputRef {
                package: "dependency".into(),
                revision: "v1".into(),
                export: "model".into(),
                output: "rows".into(),
            }),
        });
    consumer.descriptor = serde_json::to_vec(&descriptor)?;
    consumer.dependencies.push(PackageRevisionRefV1 {
        package_id: "dependency".into(),
        revision: "v1".into(),
    });
    store.install_package(&[consumer, dependency], || Ok(()))?;
    let active = store.activate_package(&activation("consumer", "v1"), None, None, || Ok(()))?;
    store.collect_package([1; 16], "dependency", "v1")?;
    assert!(store
        .package_revision([1; 16], "dependency", "v1")?
        .is_some());
    store.remove_package(&active.key, active.generation, || Ok(()))?;
    assert!(store.package_revisions([1; 16])?.is_empty());
    drop(store);
    AnalysisStore::open(root)?;
    Ok(())
}

#[test]
fn packages_preserve_newer_checkpoint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    store.commit_package(&commit(active.clone(), "first"), || Ok(()))?;
    let current = store
        .package_activation(&active.key)?
        .ok_or("activation absent")?;
    store.fail_package(&active, b"late error", || Ok(()))?;
    assert_eq!(
        store.package_activation(&active.key)?,
        Some(current.clone())
    );
    assert!(!store.package_results(&active.key)?[0].stale);
    assert!(store
        .fail_package(&current, b"current error", || crate::AnalysisConflictSnafu
            .fail())
        .is_err());
    assert!(!store.package_results(&active.key)?[0].stale);
    store.fail_package(&current, b"current error", || Ok(()))?;
    let failed = store
        .package_activation(&active.key)?
        .ok_or("activation absent")?;
    assert_eq!(failed.checkpoint_revision, current.checkpoint_revision);
    assert_eq!(failed.metadata, b"current error");
    assert!(store.package_results(&active.key)?[0].stale);
    Ok(())
}

#[test]
fn packages_suspend_retains_installation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    store.commit_package(&commit(active.clone(), "first"), || Ok(()))?;
    store.suspend_package(&active.key, active.generation, || Ok(()))?;
    let suspended = store
        .package_activation(&active.key)?
        .ok_or("activation absent")?;
    assert!(!suspended.active);
    assert_ne!(suspended.generation, active.generation);
    assert_eq!(
        store.package_activations([1; 16], &active.key.scope_id, None)?,
        vec![suspended.clone()]
    );
    assert!(store.package_results(&active.key)?[0].stale);
    assert!(store
        .package_revision([1; 16], &active.key.package_id, &active.revision)?
        .is_some());
    store.suspend_package(&active.key, suspended.generation, || Ok(()))?;
    assert_eq!(store.package_activation(&active.key)?, Some(suspended));
    Ok(())
}

#[test]
fn packages_retain_activation_root() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    store.install_package(
        &[package("root", "v1")?, package("child", "v1")?],
        || Ok(()),
    )?;
    let root = store.activate_package(&activation("root", "v1"), None, None, || Ok(()))?;
    let mut child = activation("child", "v1");
    child.metadata =
        serde_json::to_vec(&serde_json::json!({"root": {"package_id": "root", "revision": "v1"}}))?;
    let child = store.activate_package(&child, None, None, || Ok(()))?;
    store.remove_package(&root.key, root.generation, || Ok(()))?;
    store.collect_package_admissions()?;
    assert!(store.package_revision([1; 16], "root", "v1")?.is_some());
    store.remove_package(&child.key, child.generation, || Ok(()))?;
    store.collect_package([1; 16], "root", "v1")?;
    assert!(store.package_revisions([1; 16])?.is_empty());
    Ok(())
}

#[test]
fn packages_fence_source_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let first = start(&store, "first")?;
    let captured = *store.subscribe_revision().borrow();
    let mut prepared = commit(first.clone(), "first-result");
    prepared.source_revisions = vec![("context_versions".into(), captured)];
    let second = start(&store, "second")?;
    store.commit_package(&commit(second, "second-result"), || Ok(()))?;
    let receipt = store.commit_package(&prepared, || Ok(()))?;
    let current = store
        .package_activation(&first.key)?
        .ok_or("activation absent")?;
    let mut next = commit(current.clone(), "next-result");
    next.source_revisions = prepared.source_revisions.clone();
    store.commit_context(&crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "fixture".into(),
            entity_key: b"entity".to_vec(),
            lifetime_key: b"lifetime".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"context".to_vec(),
    })?;
    assert!(store.commit_package(&next, || Ok(())).is_err());
    assert_eq!(store.package_activation(&first.key)?, Some(current));
    assert!(store.package_result([1; 16], "next-result")?.is_none());
    assert_eq!(store.commit_package(&prepared, || Ok(()))?, receipt);
    Ok(())
}

#[test]
fn packages_stale_notice_race() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let first = start(&store, "first")?;
    let second = start(&store, "second")?;
    store.commit_package(&commit(first.clone(), "first-1"), || Ok(()))?;
    let observed = store
        .package_activation(&first.key)?
        .ok_or("activation absent")?;
    let latest = store.commit_package(&commit(observed.clone(), "first-2"), || Ok(()))?;
    let mut dependent = commit(second.clone(), "second-1");
    dependent.dependencies.push(latest);
    store.commit_package(&dependent, || Ok(()))?;
    let current = store
        .package_activation(&first.key)?
        .ok_or("activation absent")?;
    assert_eq!(observed.generation, current.generation);
    assert_ne!(observed.checkpoint_revision, current.checkpoint_revision);
    let revision = store.meta()?.commit_revision;
    store.mark_package_stale(&observed)?;
    assert_eq!(store.meta()?.commit_revision, revision);
    assert_eq!(store.package_activation(&first.key)?, Some(current.clone()));
    assert!(!store.package_results(&first.key)?[0].stale);
    assert!(!store.package_results(&second.key)?[0].stale);
    store.mark_package_stale(&current)?;
    assert!(store.package_results(&first.key)?[0].stale);
    assert!(store.package_results(&second.key)?[0].stale);
    Ok(())
}
