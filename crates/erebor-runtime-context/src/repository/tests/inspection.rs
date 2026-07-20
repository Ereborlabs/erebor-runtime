use std::{fs, io};

use erebor_runtime_error::{ErrorExt, StatusCode};

use super::{run_git, Fixture, TestResult};
use crate::{
    ContextObjectId, ContextRepository, ContextRepositoryError, ContextTree, ForkTarget, ScopeRef,
    ScopeStart, Snapshot, TreeEdit,
};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

fn entry(tree: &ContextTree, name: &[u8]) -> TestResult<ContextObjectId> {
    tree.entries()
        .iter()
        .find(|entry| entry.name() == name)
        .map(|entry| entry.object())
        .ok_or_else(|| {
            io::Error::other(format!(
                "tree {} has no `{}` entry",
                tree.id(),
                String::from_utf8_lossy(name)
            ))
            .into()
        })
}

#[test]
fn inspection_preserves_scope_heads_parent_order_and_pinned_snapshots_after_packing(
) -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("codex/results/initial", b"initial")])?,
        "Initialize root",
    )?;
    let parent = ScopeRef::scope("session-8421", "parent")?;
    fixture
        .repository
        .create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    let child = ScopeRef::scope("session-8421", "child")?;
    fixture
        .repository
        .fork_scope(root, child.clone(), ForkTarget::reuse_causal_commit(), None)?;
    let parent_next = fixture.repository.append_snapshot(
        parent.clone(),
        root,
        snapshot(&[("codex/results/parent", b"parent")])?,
        "Parent result",
    )?;
    let child_next = fixture.repository.append_snapshot(
        child.clone(),
        root,
        snapshot(&[("codex/results/child", b"child")])?,
        "Child result",
    )?;
    let merged_tree = fixture
        .repository
        .create_tree(snapshot(&[("codex/results/merged", b"merged")])?)?;
    let merge = fixture.repository.append_pinned_merge(
        parent.clone(),
        parent_next,
        child_next,
        merged_tree,
        "Consume child result",
    )?;

    let inspected = fixture.reopen()?;
    assert_eq!(inspected.scope_head(&parent)?, merge);
    assert_eq!(inspected.scope_head(&child)?, child_next);
    assert_eq!(
        inspected
            .scope_refs()?
            .into_iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>(),
        vec![
            ScopeRef::root("session-8421")?.to_string(),
            child.to_string(),
            parent.to_string(),
        ]
    );
    assert_eq!(
        inspected.read_commit(merge)?.parents(),
        &[parent_next, child_next]
    );
    assert!(inspected.is_ancestor(root, merge)?);
    assert!(inspected.is_ancestor(child_next, merge)?);
    assert!(!inspected.is_ancestor(merge, child_next)?);

    let root_tree = inspected.read_tree(inspected.read_commit(root)?.tree())?;
    let codex_tree = inspected.read_tree(entry(&root_tree, b"codex")?)?;
    let results = inspected.read_tree(entry(&codex_tree, b"results")?)?;
    assert_eq!(
        results
            .entries()
            .iter()
            .map(|entry| entry.name())
            .collect::<Vec<_>>(),
        vec![b"initial".as_slice()]
    );
    assert!(matches!(
        inspected.is_ancestor(entry(&results, b"initial")?, merge),
        Err(ContextRepositoryError::WrongObjectKind { .. })
    ));

    let verification = inspected.verify_full()?;
    assert_eq!(verification.scope_count(), 3);
    assert_eq!(verification.commit_count(), 4);
    assert_eq!(verification.tree_count(), 12);
    assert_eq!(verification.blob_count(), 4);
    run_git(&fixture.path, &["fsck", "--full"])?;
    run_git(&fixture.path, &["pack-refs", "--all", "--prune"])?;
    run_git(&fixture.path, &["repack", "-ad"])?;

    let packed = fixture.reopen()?;
    assert_eq!(packed.scope_head(&parent)?, merge);
    assert_eq!(
        packed.read_commit(merge)?.parents(),
        &[parent_next, child_next]
    );
    assert_eq!(packed.verify_full()?, verification);
    run_git(&fixture.path, &["fsck", "--full"])?;
    Ok(())
}

#[test]
fn bounded_open_defers_deep_blob_integrity_to_lazy_reads_and_full_verification() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("deep/value", b"retained")])?,
        "Initialize root",
    )?;
    fixture.repository.append_snapshot(
        ScopeRef::root("session-8421")?,
        root,
        snapshot(&[("later/value", b"new")])?,
        "Later append",
    )?;
    let root_tree = fixture
        .repository
        .read_tree(fixture.repository.read_commit(root)?.tree())?;
    let deep_tree = fixture.repository.read_tree(entry(&root_tree, b"deep")?)?;
    let deep_blob = entry(&deep_tree, b"value")?;
    let hex = deep_blob.to_string();
    fs::remove_file(fixture.path.join("objects").join(&hex[..2]).join(&hex[2..]))?;

    let reopened = fixture.reopen()?;
    assert!(matches!(
        reopened.read_object(deep_blob),
        Err(ContextRepositoryError::ObjectNotFound { .. })
            | Err(ContextRepositoryError::ReadObject { .. })
    ));
    let expected_entry = deep_blob.to_string();
    let verification_error = reopened
        .verify_full()
        .err()
        .ok_or_else(|| io::Error::other("full verification unexpectedly succeeded"))?;
    assert_eq!(verification_error.status_code(), StatusCode::NotFound);
    assert!(matches!(
        verification_error,
        ContextRepositoryError::TreeEntryRead { path, entry, .. }
            if path.as_ref() == "deep/value" && entry.as_ref() == expected_entry.as_str()
    ));
    assert!(run_git(&fixture.path, &["fsck", "--full"]).is_err());
    Ok(())
}

#[test]
fn open_rejects_malformed_and_symbolic_scope_refs_and_preserves_stale_locks() -> TestResult<()> {
    let malformed = Fixture::init()?;
    let malformed_root = malformed.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let malformed_ref = malformed.path.join("refs/scopes/session-8421/not-a-scope");
    let malformed_parent = malformed_ref
        .parent()
        .ok_or_else(|| io::Error::other("malformed ref path has no parent"))?;
    fs::create_dir_all(malformed_parent)?;
    fs::write(&malformed_ref, format!("{malformed_root}\n"))?;
    assert!(matches!(
        ContextRepository::open(&malformed.path, super::FixedMetadataSource::new()?),
        Err(ContextRepositoryError::InvalidScopeRef { .. })
    ));

    let symbolic = Fixture::init()?;
    let symbolic_root = symbolic.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let symbolic_scope = ScopeRef::scope("session-8421", "symbolic")?;
    run_git(
        &symbolic.path,
        &[
            "symbolic-ref",
            symbolic_scope.as_str(),
            ScopeRef::root("session-8421")?.as_str(),
        ],
    )?;
    assert!(matches!(
        ContextRepository::open(&symbolic.path, super::FixedMetadataSource::new()?),
        Err(ContextRepositoryError::SymbolicScopeRef { .. })
    ));
    assert_eq!(
        symbolic
            .repository
            .scope_head(&ScopeRef::root("session-8421")?)?,
        symbolic_root
    );

    let locked = Fixture::init()?;
    let locked_root = locked.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let root_scope = ScopeRef::root("session-8421")?;
    let lock = locked.path.join(format!("{}.lock", root_scope.as_str()));
    fs::write(&lock, "another writer owns this lock\n")?;
    assert!(matches!(
        locked.repository.append_snapshot(
            root_scope.clone(),
            locked_root,
            snapshot(&[("blocked", b"append")])?,
            "Blocked append",
        ),
        Err(ContextRepositoryError::UpdateScopeRef { .. })
    ));
    assert!(lock.exists());
    let recovered = locked.reopen()?;
    assert_eq!(recovered.scope_head(&root_scope)?, locked_root);
    assert_eq!(recovered.verify_full()?.scope_count(), 1);
    Ok(())
}

#[test]
fn open_rejects_missing_and_non_commit_scope_heads_and_missing_head_trees() -> TestResult<()> {
    let missing = Fixture::init()?;
    let missing_root = missing.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let missing_ref = missing.path.join("refs/scopes/session-8421/scope/missing");
    let missing_parent = missing_ref
        .parent()
        .ok_or_else(|| io::Error::other("missing ref path has no parent"))?;
    fs::create_dir_all(missing_parent)?;
    fs::write(&missing_ref, format!("{}\n", "a".repeat(64)))?;
    assert!(matches!(
        ContextRepository::open(&missing.path, super::FixedMetadataSource::new()?),
        Err(ContextRepositoryError::ObjectNotFound { .. })
            | Err(ContextRepositoryError::ReadObject { .. })
    ));
    assert_eq!(
        missing
            .repository
            .scope_head(&ScopeRef::root("session-8421")?)?,
        missing_root
    );

    let non_commit = Fixture::init()?;
    non_commit.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let non_commit_ref = ScopeRef::scope("session-8421", "blob")?;
    let blob = non_commit.repository.write_blob(b"not a commit")?;
    run_git(
        &non_commit.path,
        &["update-ref", non_commit_ref.as_str(), &blob.to_string()],
    )?;
    assert!(matches!(
        ContextRepository::open(&non_commit.path, super::FixedMetadataSource::new()?),
        Err(ContextRepositoryError::ScopeTargetNotCommit { .. })
    ));

    let missing_tree = Fixture::init()?;
    let tree_commit = missing_tree.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize root",
    )?;
    let tree = missing_tree
        .repository
        .read_commit(tree_commit)?
        .tree()
        .to_string();
    fs::remove_file(
        missing_tree
            .path
            .join("objects")
            .join(&tree[..2])
            .join(&tree[2..]),
    )?;
    assert!(matches!(
        ContextRepository::open(&missing_tree.path, super::FixedMetadataSource::new()?),
        Err(ContextRepositoryError::ObjectNotFound { .. })
            | Err(ContextRepositoryError::ReadObject { .. })
    ));
    Ok(())
}
