use super::*;
use crate::{AnalysisCommitStage, AnalysisStore};
use snafu::ResultExt as _;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod context;
mod crash;
mod evidence;
mod lifecycle;

fn package(id: &str, revision: &str) -> crate::Result<PackageRevisionV1> {
    let descriptor = araphor_analysis_sdk::Package::new(
        id,
        revision,
        vec![araphor_analysis_sdk::Model::new(
            "model",
            Vec::new(),
            vec![araphor_analysis_sdk::Port::new(
                "rows",
                araphor_analysis_sdk::Schema::empty(),
            )],
        )],
    );
    let source = crate::PackageArtifactV1 {
        descriptor: descriptor.clone(),
        implementations: vec![crate::PackageImplementationV1::Sql {
            export: "model".into(),
            inputs: std::collections::BTreeMap::new(),
            program: crate::SqlModelV1 {
                outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let (artifact, encoded_bytes) = crate::package::storage::StoredArtifact::encode(&source)?;
    Ok(PackageRevisionV1 {
        tenant_id: [1; 16],
        package_id: id.into(),
        revision: revision.into(),
        descriptor: serde_json::to_vec(&descriptor).context(crate::PackageEncodingSnafu)?,
        artifact,
        encoded_bytes,
        dependencies: Vec::new(),
    })
}

fn activation(id: &str, revision: &str) -> PackageActivationV1 {
    PackageActivationV1 {
        key: PackageKeyV1 {
            tenant_id: [1; 16],
            scope_id: "scope".into(),
            package_id: id.into(),
            export: "model".into(),
        },
        revision: revision.into(),
        generation: 0,
        checkpoint_revision: 0,
        result_id: None,
        grant_id: "grant".into(),
        metadata: b"{}".to_vec(),
        active: true,
    }
}

fn commit(active: PackageActivationV1, id: &str) -> PackageCommitV1 {
    PackageCommitV1 {
        expected_checkpoint_revision: active.checkpoint_revision,
        activation: active,
        window_id: "window".into(),
        result_id: id.into(),
        request: b"request".to_vec(),
        metadata: b"{}".to_vec(),
        datasets: b"rows".to_vec(),
        checkpoint: b"state".to_vec(),
        dependencies: Vec::new(),
        source_revisions: Vec::new(),
        witnesses: Vec::new(),
        context_refs: Vec::new(),
        created_utc_ns: 1,
    }
}

fn start(store: &AnalysisStore, id: &str) -> crate::Result<PackageActivationV1> {
    store.install_package(&[package(id, "v1")?], || Ok(()))?;
    store.activate_package(&activation(id, "v1"), None, None, || Ok(()))
}

#[test]
fn packages_commit_retry_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let active = start(&store, "first")?;
    let input = commit(active.clone(), "result-1");
    let receipt = store.commit_package(&input, || Ok(()))?;
    assert_eq!(store.commit_package(&input, || Ok(()))?, receipt);
    let mut changed = input.clone();
    changed.checkpoint.push(1);
    assert!(store.commit_package(&changed, || Ok(())).is_err());
    assert!(store
        .commit_package(&input, || crate::AnalysisConflictSnafu.fail())
        .is_err());
    let head = store
        .package_activation(&active.key)?
        .ok_or("missing activation")?;
    assert_eq!(head.checkpoint_revision, receipt.commit_revision);
    assert_eq!(head.result_id.as_deref(), Some("result-1"));
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.commit_package(&input, || Ok(()))?, receipt);
    assert_eq!(store.package_results(&active.key)?.len(), 1);
    Ok(())
}

#[test]
fn packages_replace_invalidates_dependents() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let first = start(&store, "first")?;
    let second = start(&store, "second")?;
    let original = commit(first.clone(), "first-1");
    let reference = store.commit_package(&original, || Ok(()))?;
    let mut dependent = commit(second.clone(), "second-1");
    dependent.dependencies.push(reference);
    store.commit_package(&dependent, || Ok(()))?;
    let current = store
        .package_activation(&first.key)?
        .ok_or("missing activation")?;
    let mut replacement = commit(current, "first-2");
    replacement.datasets.clear();
    store.commit_package(&replacement, || Ok(()))?;
    let results = store.package_results(&first.key)?;
    assert_eq!(results.len(), 1);
    assert!(results[0].datasets.is_empty());
    assert_eq!(results[0].result_id, "first-2");
    assert!(store.package_results(&second.key)?[0].stale);
    dependent.activation = store
        .package_activation(&second.key)?
        .ok_or("missing activation")?;
    dependent.expected_checkpoint_revision = dependent.activation.checkpoint_revision;
    dependent.result_id = "second-2".into();
    assert!(store.commit_package(&dependent, || Ok(())).is_err());
    Ok(())
}

#[test]
fn packages_failed_commit_atomicity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let input = commit(active.clone(), "first");
    store.set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
        crate::AnalysisConflictSnafu.fail()
    })?;
    assert!(store.commit_package(&input, || Ok(())).is_err());
    assert_eq!(store.package_activation(&active.key)?, Some(active.clone()));
    assert!(store.package_result([1; 16], "first")?.is_none());
    assert!(store
        .commit_package(&input, || crate::AnalysisConflictSnafu.fail())
        .is_err());
    assert!(store.package_results(&active.key)?.is_empty());
    store.commit_package(&input, || Ok(()))?;
    let mut concurrent = input;
    concurrent.result_id = "concurrent".into();
    assert!(store.commit_package(&concurrent, || Ok(())).is_err());
    Ok(())
}

#[test]
fn packages_upgrade_and_removal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let active = start(&store, "first")?;
    store.commit_package(&commit(active.clone(), "first-1"), || Ok(()))?;
    store.install_package(&[package("first", "v2")?], || Ok(()))?;
    let current = store
        .package_activation(&active.key)?
        .ok_or("missing activation")?;
    let mut upgraded = current.clone();
    upgraded.revision = "v2".into();
    assert!(store
        .activate_package(&upgraded, Some(current.generation), None, || Ok(()))
        .is_err());
    let prepared = commit(upgraded.clone(), "upgraded");
    assert!(store
        .activate_package(&upgraded, Some(current.generation), Some(&prepared), || {
            crate::AnalysisConflictSnafu.fail()
        })
        .is_err());
    assert_eq!(
        store.package_activation(&active.key)?,
        Some(current.clone())
    );
    let upgraded =
        store.activate_package(&upgraded, Some(current.generation), Some(&prepared), || {
            Ok(())
        })?;
    assert_eq!(upgraded.revision, "v2");
    let stale = commit(current, "stale");
    assert!(store.commit_package(&stale, || Ok(())).is_err());
    store.remove_package(&upgraded.key, upgraded.generation, || Ok(()))?;
    assert_eq!(
        store.activate_package(
            &prepared.activation,
            Some(prepared.activation.generation),
            Some(&prepared),
            || Ok(())
        )?,
        upgraded
    );
    assert!(
        !store
            .package_activation(&upgraded.key)?
            .ok_or("missing removal")?
            .active
    );
    assert!(store.package_revision([1; 16], "first", "v1")?.is_some());
    assert!(store.package_revision([1; 16], "first", "v2")?.is_some());
    assert!(store
        .commit_package(&commit(upgraded, "removed"), || Ok(()))
        .is_err());
    drop(store);
    AnalysisStore::open(&root)?;
    Ok(())
}

#[test]
fn packages_unused_artifacts_release() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let unrelated = package("unrelated", "v1")?;
    store.install_package(std::slice::from_ref(&unrelated), || Ok(()))?;
    store.remove_package(&active.key, active.generation, || Ok(()))?;
    assert!(store.package_revision([1; 16], "first", "v1")?.is_none());
    assert_eq!(
        store.package_revision([1; 16], "unrelated", "v1")?,
        Some(unrelated)
    );
    Ok(())
}

#[test]
fn packages_backup_restore() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let input = commit(active, "first");
    let receipt = store.commit_package(&input, || Ok(()))?;
    let backup = store.root.join("backups/package-test");
    store.backup(&backup)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(restored.commit_package(&input, || Ok(()))?, receipt);
    assert_eq!(
        restored.package_revisions([1; 16])?,
        store.package_revisions([1; 16])?
    );
    Ok(())
}

#[test]
fn packages_inactive_admission_notices() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    store.install_package(&[package("first", "v1")?], || Ok(()))?;
    let mut unsupported = activation("first", "v1");
    unsupported.active = false;
    let inactive = store.activate_package(&unsupported, None, None, || Ok(()))?;
    assert_eq!(store.package_activation_page(None)?, vec![inactive.clone()]);
    store.collect_package([1; 16], "first", "v1")?;
    assert!(store.package_revision([1; 16], "first", "v1")?.is_some());
    store.remove_package(&inactive.key, inactive.generation, || Ok(()))?;
    assert!(store.package_activation_page(None)?.is_empty());
    assert!(store.package_revision([1; 16], "first", "v1")?.is_none());
    let active = start(&store, "second")?;
    let before = store.meta()?.commit_revision;
    store.update_package_metadata(&active.key, active.generation, &active.metadata, || Ok(()))?;
    store.mark_package_stale(&active)?;
    assert_eq!(store.meta()?.commit_revision, before);
    store.commit_package(&commit(active.clone(), "first"), || Ok(()))?;
    let active = store
        .package_activation(&active.key)?
        .ok_or("activation absent")?;
    store.mark_package_stale(&active)?;
    let before = store.meta()?.commit_revision;
    store.mark_package_stale(&active)?;
    assert_eq!(store.meta()?.commit_revision, before);
    drop(store);
    AnalysisStore::open(&root)?;
    Ok(())
}
