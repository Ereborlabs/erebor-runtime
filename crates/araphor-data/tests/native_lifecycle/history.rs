use super::*;

const OWNED: &[u8] = b"\0data/history-policy";

fn policy(store: &AnalysisStore) -> Result<fjall::HistoryPolicy, Box<dyn std::error::Error>> {
    let view = store.view()?;
    let bytes = view.snapshot().get(OWNED)?.ok_or("owned history policy")?;
    let id = fjall::RetentionId::from_bytes(bytes.as_ref().try_into()?);
    store
        .database()
        .history()?
        .into_iter()
        .find(|policy| policy.id == id)
        .ok_or_else(|| "owned policy is absent".into())
}

fn put(store: &AnalysisStore, value: u8) -> Result<u64, Box<dyn std::error::Error>> {
    let mut tx = store.write()?;
    let revision = tx.revision();
    tx.native().insert(b"history-point", [value]);
    tx.commit([])?;
    Ok(revision)
}

#[test]
fn checkpoint_releases_unused_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let first = put(&store, 1)?;
    let held = store.read_at(first)?;
    let middle = put(&store, 2)?;
    let last = put(&store, 3)?;
    let current = store.view()?;
    let before = store.meta()?;
    store.checkpoint()?;
    assert!(matches!(
        store.read_at(middle),
        Err(araphor_data::Error::NativeStorage {
            source: fjall::Error::HistoryUnavailable(_, _),
            ..
        })
    ));
    assert_eq!(
        held.snapshot().get(b"history-point")?.as_deref(),
        Some([1].as_slice())
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(policy(&store)?.first, current.snapshot().revision());
    let journal = store.database().inner().journal_head()?;
    store.checkpoint()?;
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(store.meta()?, before);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    assert_eq!(
        held.snapshot().get(b"history-point")?.as_deref(),
        Some([1].as_slice())
    );
    drop(held);
    assert!(store.read_at(first).is_err());
    let saved = store.backup(&root.join("backups/history"))?;
    let destination = directory.path().join("restored");
    let restored = AnalysisStore::restore(&root.join("backups/history"), &destination)?;
    assert_eq!(restored.meta()?.store_uuid.to_string(), saved.store_uuid);
    assert_eq!(restored.meta()?.commit_revision, last);
    assert_eq!(restored.meta()?.recovery_epoch, saved.recovery_epoch + 1);
    assert_eq!(
        restored
            .view()?
            .snapshot()
            .get(b"history-point")?
            .as_deref(),
        Some([3].as_slice())
    );
    assert!(restored.read_at(middle).is_err());
    assert_eq!(policy(&restored)?.id, policy(&store)?.id);
    drop((restored, current, store));
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, before);
    assert!(store.read_at(middle).is_err());
    assert_eq!(
        store.view()?.snapshot().get(b"history-point")?.as_deref(),
        Some([3].as_slice())
    );
    Ok(())
}

#[test]
fn bootstrap_preserves_unknown_policies() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let old = policy(&store)?;
    let mut tx = store.write()?;
    tx.native().remove(OWNED);
    tx.commit([])?;
    let before = store.meta()?;
    let unknown = store.database().history()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
    assert_ne!(policy(&store)?.id, old.id);
    let policies = store.database().history()?;
    assert_eq!(policies.len(), unknown.len() + 1);
    for entry in &unknown {
        assert!(policies.contains(entry));
    }
    assert!(store
        .read_at(before.commit_revision)?
        .snapshot()
        .get(OWNED)?
        .is_none());
    let committed = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, committed);
    assert_eq!(store.database().history()?, policies);
    Ok(())
}

#[test]
fn policy_ownership_checks_catalogue() -> TestResult {
    for fault in ["missing", "branch", "bounded", "width"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        let owned = policy(&store)?;
        if fault == "missing" {
            store.database().release_history(owned.id)?;
        } else {
            let bytes = if fault == "branch" {
                let branch = store.database().create_branch("other")?;
                branch
                    .retain_history(branch.snapshot()?.revision()..)?
                    .to_bytes()
                    .to_vec()
            } else if fault == "bounded" {
                let cut = store.view()?.snapshot().revision();
                store
                    .branch()
                    .retain_history(cut..=cut)?
                    .to_bytes()
                    .to_vec()
            } else {
                vec![1]
            };
            let mut tx = store.write()?;
            tx.native().insert(OWNED, bytes);
            tx.commit([])?;
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{fault}");
    }
    Ok(())
}

#[test]
fn legacy_restore_keeps_revision() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let old = policy(&store)?;
    let mut tx = store.write()?;
    tx.native().remove(OWNED);
    tx.commit([])?;
    store.accept_validated_batch(identity(), batch(1))?;
    let page = store.read_page(&identity(), 1)?;
    let receipt = store.source_receipt(&identity())?;
    let unknown = store.database().history()?;
    let saved = store.backup(&root.join("backups/legacy"))?;
    let restored = AnalysisStore::restore(
        &root.join("backups/legacy"),
        &directory.path().join("restored"),
    )?;
    assert_eq!(restored.meta()?.commit_revision, saved.commit_revision);
    assert_eq!(restored.meta()?.store_uuid.to_string(), saved.store_uuid);
    assert_eq!(restored.meta()?.recovery_epoch, saved.recovery_epoch + 1);
    assert_eq!(restored.read_page(&identity(), 1)?.records, page.records);
    assert_eq!(restored.source_receipt(&identity())?, receipt);
    let owned = policy(&restored)?;
    assert_ne!(owned.id, old.id);
    let policies = restored.database().history()?;
    assert_eq!(policies.len(), unknown.len() + 1);
    for entry in &unknown {
        assert!(policies.contains(entry));
    }
    assert!(store.view()?.snapshot().get(OWNED)?.is_none());
    assert_eq!(store.database().history()?, unknown);
    assert_eq!(store.read_page(&identity(), 1)?.records, page.records);
    let before = restored.meta()?;
    drop(restored);
    let restored = AnalysisStore::open(directory.path().join("restored"))?;
    assert_eq!(restored.meta()?, before);
    assert_eq!(restored.database().history()?, policies);
    Ok(())
}

#[test]
fn foreign_owners_keep_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let first = put(&store, 1)?;
    let cut = store.view()?.snapshot().revision();
    store.branch().fork("history-child", cut)?;
    let middle = put(&store, 2)?;
    let cut = store.view()?.snapshot().revision();
    let foreign = store.branch().retain_history(cut..=cut)?;
    let last = put(&store, 3)?;
    let saved = store
        .database()
        .history()?
        .into_iter()
        .find(|policy| policy.id == foreign)
        .ok_or("foreign policy")?;
    store.checkpoint()?;
    assert_eq!(
        policy(&store)?.first,
        store.read_at(last)?.snapshot().revision()
    );
    assert!(store.database().history()?.contains(&saved));
    for (revision, value) in [(first, 1), (middle, 2), (last, 3)] {
        assert_eq!(
            store
                .read_at(revision)?
                .snapshot()
                .get(b"history-point")?
                .as_deref(),
            Some([value].as_slice())
        );
    }
    let backup = root.join("backups/branches");
    store.backup(&backup)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(restored.database().history()?, store.database().history()?);
    let child = restored
        .database()
        .branch("history-child")?
        .ok_or("restored branch")?;
    assert_eq!(
        child.snapshot()?.get(b"history-point")?.as_deref(),
        Some([1].as_slice())
    );
    restored.database().release_history(foreign)?;
    assert!(restored.read_at(middle).is_err());
    assert_eq!(
        restored
            .read_at(first)?
            .snapshot()
            .get(b"history-point")?
            .as_deref(),
        Some([1].as_slice())
    );
    assert!(store.read_at(middle).is_ok());
    Ok(())
}

#[test]
fn processors_keep_birth_before_images() -> TestResult {
    for prefix in [0, 4] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        for value in 0..prefix {
            put(&store, value)?;
        }
        let before = store.meta()?.commit_revision;
        let scope = ProcessorScopeV1 {
            processor_id: "history".into(),
            method_version: 1,
            identity: identity(),
        };
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
            before + 1
        );
        store.retire_required(&araphor_data::ProcessorRetirementV1 {
            scope: scope.clone(),
            change_id: "history".into(),
            reason: "Stop this processor.".into(),
            expected_cursor: 0,
            cutoff_cursor: 0,
        })?;
        store.checkpoint()?;
        assert_eq!(
            policy(&store)?.first,
            store.read_at(before)?.snapshot().revision()
        );
        if before != 0 {
            assert!(store.read_at(0).is_err());
        }
        store.database().inner().flush_memtables()?;
        store.database().inner().major_compact()?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert!(store
            .read_at(before)?
            .snapshot()
            .prefix(b"\0data/@progress/state/")
            .next()
            .is_none());
        assert!(store.processor_retirement(&scope)?.is_some());
    }
    Ok(())
}
