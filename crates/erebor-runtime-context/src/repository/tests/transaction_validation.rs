use super::{run_git, Fixture, TestResult};
use crate::{
    ContextObjectId, ContextRepositoryError, ForkTarget, ScopeRef, ScopeStart, Snapshot, TreeEdit,
};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

#[test]
fn fork_and_pinned_merge_reject_invalid_git_shapes() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let tree = fixture
        .repository
        .create_tree(snapshot(&[("result", b"selected")])?)?;

    assert!(matches!(
        fixture.repository.fork_scope(
            tree,
            ScopeRef::scope("session-8421", "tree-causal")?,
            ForkTarget::reuse_causal_commit(),
            None,
        ),
        Err(ContextRepositoryError::WrongObjectKind { .. })
    ));
    assert!(matches!(
        fixture.repository.fork_scope(
            root,
            ScopeRef::scope("session-8421", "commit-tree")?,
            ForkTarget::selected_tree(root, "Commit cannot be a tree"),
            None,
        ),
        Err(ContextRepositoryError::WrongObjectKind { .. })
    ));
    let missing: ContextObjectId =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse()?;
    assert!(matches!(
        fixture.repository.fork_scope(
            missing,
            ScopeRef::scope("session-8421", "missing")?,
            ForkTarget::reuse_causal_commit(),
            None,
        ),
        Err(ContextRepositoryError::ObjectNotFound { .. })
    ));
    let foreign = Fixture::init()?;
    let foreign_commit = foreign.repository.initialize_root(
        "other-session",
        snapshot(&[("foreign", b"commit")])?,
        "Initialize foreign root",
    )?;
    assert!(matches!(
        fixture.repository.fork_scope(
            foreign_commit,
            ScopeRef::scope("session-8421", "foreign")?,
            ForkTarget::reuse_causal_commit(),
            None,
        ),
        Err(ContextRepositoryError::ObjectNotFound { .. })
    ));

    let receiver = ScopeRef::scope("session-8421", "receiver")?;
    fixture
        .repository
        .create_scope(receiver.clone(), ScopeStart::existing_commit(root))?;
    assert!(matches!(
        fixture.repository.append_pinned_merge(
            receiver.clone(),
            root,
            tree,
            tree,
            "Tree cannot be source parent",
        ),
        Err(ContextRepositoryError::WrongObjectKind { .. })
    ));
    assert!(matches!(
        fixture.repository.append_pinned_merge(
            receiver.clone(),
            root,
            root,
            root,
            "Commit cannot be result tree",
        ),
        Err(ContextRepositoryError::WrongObjectKind { .. })
    ));
    let receiver_next = fixture.repository.append_snapshot(
        receiver.clone(),
        root,
        snapshot(&[("receiver/state", b"advanced")])?,
        "Advance receiver",
    )?;
    assert!(matches!(
        fixture.repository.append_pinned_merge(
            receiver.clone(),
            root,
            root,
            tree,
            "Stale receiver",
        ),
        Err(ContextRepositoryError::StaleScopeHead { .. })
    ));

    let symbolic = ScopeRef::scope("session-8421", "symbolic")?;
    fixture
        .repository
        .create_scope(symbolic.clone(), ScopeStart::existing_commit(root))?;
    run_git(
        &fixture.path,
        &[
            "symbolic-ref",
            symbolic.as_str(),
            ScopeRef::root("session-8421")?.as_str(),
        ],
    )?;
    assert!(matches!(
        fixture
            .repository
            .append_pinned_merge(symbolic, root, root, tree, "Symbolic receiver",),
        Err(ContextRepositoryError::SymbolicScopeRef { .. })
    ));
    assert_eq!(fixture.repository.scope_head(&receiver)?, receiver_next);
    Ok(())
}
