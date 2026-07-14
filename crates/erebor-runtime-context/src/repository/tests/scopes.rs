use std::{io, sync::Barrier, thread};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};

use super::{run_git, tree_entry_id, FixedMetadataSource, Fixture, TestResult};
use crate::{
    ContextObjectId, ContextRepository, ContextRepositoryError, ScopeRef, ScopeStart, Snapshot,
    TreeEdit,
};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

fn parent_count(fixture: &Fixture, commit: ContextObjectId) -> TestResult<usize> {
    Ok(
        run_git(&fixture.path, &["cat-file", "-p", &commit.to_string()])?
            .matches("parent ")
            .count(),
    )
}

fn only_parent(fixture: &Fixture, commit: ContextObjectId) -> TestResult<ContextObjectId> {
    let contents = run_git(&fixture.path, &["cat-file", "-p", &commit.to_string()])?;
    let parent = contents
        .lines()
        .find_map(|line| line.strip_prefix("parent "))
        .ok_or_else(|| io::Error::other("commit did not have one parent"))?;
    Ok(parent.parse()?)
}

fn commit_tree_id(
    repository: &ContextRepository,
    commit: ContextObjectId,
) -> TestResult<ContextObjectId> {
    let local = repository.repository();
    let commit = local.find_commit(gix::hash::ObjectId::from_hex(
        commit.to_string().as_bytes(),
    )?)?;
    Ok(commit.tree_id()?.detach().to_string().parse()?)
}

#[test]
fn scopes_are_independent_git_branches_for_one_session() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("shared/base", b"base")])?,
        "Initialize session root",
    )?;
    let parent = ScopeRef::scope("session-8421", "parent")?;
    let unknown = ScopeRef::unknown("session-8421")?;
    let parent_start = fixture
        .repository
        .create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    let unknown_start = fixture
        .repository
        .create_scope(unknown.clone(), ScopeStart::existing_commit(root))?;

    let parent_next = fixture.repository.append_snapshot(
        parent.clone(),
        parent_start,
        snapshot(&[("actors/parent/turn", b"one")])?,
        "Parent turn",
    )?;
    let unknown_next = fixture.repository.append_snapshot(
        unknown.clone(),
        unknown_start,
        snapshot(&[("unclassified/input", b"late")])?,
        "Unknown input",
    )?;

    assert_eq!(
        fixture
            .repository
            .scope_head(&ScopeRef::root("session-8421")?)?,
        root
    );
    assert_eq!(fixture.repository.scope_head(&parent)?, parent_next);
    assert_eq!(fixture.repository.scope_head(&unknown)?, unknown_next);
    assert_eq!(parent_count(&fixture, root)?, 0);
    assert_eq!(parent_start, root);
    assert_eq!(unknown_start, root);
    assert_eq!(parent_count(&fixture, parent_next)?, 1);
    assert_eq!(parent_count(&fixture, unknown_next)?, 1);
    assert!(run_git(
        &fixture.path,
        &[
            "merge-base",
            "--is-ancestor",
            &root.to_string(),
            &parent_next.to_string()
        ]
    )?
    .is_empty());
    assert!(run_git(
        &fixture.path,
        &[
            "merge-base",
            "--is-ancestor",
            &root.to_string(),
            &unknown_next.to_string()
        ]
    )?
    .is_empty());
    Ok(())
}

#[test]
fn branches_can_reuse_or_deliberately_change_the_selected_tree() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("source/value", b"root")])?,
        "Initialize session root",
    )?;
    let reused = fixture.repository.create_scope(
        ScopeRef::scope("session-8421", "reused")?,
        ScopeStart::existing_commit(root),
    )?;
    let changed = fixture.repository.create_scope(
        ScopeRef::scope("session-8421", "changed")?,
        ScopeStart::snapshot(
            root,
            snapshot(&[("source/value", b"selected")])?,
            "Select changed tree",
        ),
    )?;

    assert_eq!(reused, root);
    assert_ne!(changed, root);
    assert_eq!(parent_count(&fixture, changed)?, 1);
    assert_ne!(
        commit_tree_id(&fixture.repository, root)?,
        commit_tree_id(&fixture.repository, changed)?
    );

    let unchanged = fixture.repository.create_scope(
        ScopeRef::scope("session-8421", "unchanged")?,
        ScopeStart::snapshot(root, Snapshot::default(), "Do not create this"),
    );
    assert!(matches!(
        unchanged,
        Err(ContextRepositoryError::SelectedTreeUnchanged { .. })
    ));
    Ok(())
}

#[test]
fn appending_preserves_unmodified_subtrees_and_unknown_entries() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[
            ("unknown/retained", b"must remain"),
            ("known/current", b"before"),
        ])?,
        "Initialize session root",
    )?;
    let scope = ScopeRef::scope("session-8421", "parent")?;
    fixture
        .repository
        .create_scope(scope.clone(), ScopeStart::existing_commit(root))?;
    let before_tree = commit_tree_id(&fixture.repository, root)?;
    let before_unknown = tree_entry_id(&fixture.repository, before_tree, "unknown")?;

    let next = fixture.repository.append_snapshot(
        scope,
        root,
        snapshot(&[("known/current", b"after")])?,
        "Replace one known value",
    )?;
    let after_tree = commit_tree_id(&fixture.repository, next)?;
    assert_ne!(before_tree, after_tree);
    assert_eq!(
        tree_entry_id(&fixture.repository, after_tree, "unknown")?,
        before_unknown
    );
    assert_eq!(
        fixture
            .repository
            .read_object(tree_entry_id(
                &fixture.repository,
                after_tree,
                "unknown/retained",
            )?)?
            .bytes(),
        b"must remain"
    );
    Ok(())
}

#[test]
fn packed_direct_refs_reopen_and_compare_and_swap_without_reflog_reads() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let scope = ScopeRef::scope("session-8421", "worker")?;
    fixture
        .repository
        .create_scope(scope.clone(), ScopeStart::existing_commit(root))?;
    run_git(&fixture.path, &["pack-refs", "--all", "--prune"])?;

    let reopened = fixture.reopen()?;
    assert_eq!(reopened.scope_head(&scope)?, root);
    let next = reopened.append_snapshot(
        scope.clone(),
        root,
        snapshot(&[("worker/result", b"done")])?,
        "Worker result",
    )?;
    assert_eq!(fixture.reopen()?.scope_head(&scope)?, next);
    Ok(())
}

#[test]
fn independent_handles_race_one_append_and_the_loser_is_retryable() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let scope = ScopeRef::scope("session-8421", "worker")?;
    fixture
        .repository
        .create_scope(scope.clone(), ScopeStart::existing_commit(root))?;

    let barrier = std::sync::Arc::new(Barrier::new(2));
    let mut writers = Vec::new();
    for (path, bytes) in [
        ("worker/one", b"one".as_slice()),
        ("worker/two", b"two".as_slice()),
    ] {
        let path_to_repository = fixture.path.clone();
        let scope = scope.clone();
        let barrier = barrier.clone();
        writers.push(thread::spawn(
            move || -> TestResult<crate::Result<ContextObjectId>> {
                let repository =
                    ContextRepository::open(path_to_repository, FixedMetadataSource::new()?)?;
                let snapshot = Snapshot::new(vec![TreeEdit::blob(path, bytes)?])?;
                barrier.wait();
                Ok(repository.append_snapshot(scope, root, snapshot, "Concurrent append"))
            },
        ));
    }
    let outcomes = writers
        .into_iter()
        .map(|writer| {
            writer
                .join()
                .map_err(|_| io::Error::other("scope writer panicked"))?
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let loser = outcomes
        .into_iter()
        .find_map(std::result::Result::err)
        .ok_or_else(|| io::Error::other("both scope writers succeeded"))?;
    assert!(matches!(
        loser,
        ContextRepositoryError::StaleScopeHead { .. }
    ));
    assert_eq!(loser.status_code(), StatusCode::IllegalState);
    assert_eq!(loser.retry_hint(), RetryHint::Retryable);
    Ok(())
}

#[test]
fn unrelated_scope_refs_advance_concurrently_without_touching_each_other() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let first = ScopeRef::scope("session-8421", "first")?;
    let second = ScopeRef::scope("session-8421", "second")?;
    fixture
        .repository
        .create_scope(first.clone(), ScopeStart::existing_commit(root))?;
    fixture
        .repository
        .create_scope(second.clone(), ScopeStart::existing_commit(root))?;

    let barrier = std::sync::Arc::new(Barrier::new(2));
    let mut writers = Vec::new();
    for (scope, path, bytes) in [
        (first.clone(), "first/value", b"first".as_slice()),
        (second.clone(), "second/value", b"second".as_slice()),
    ] {
        let repository_path = fixture.path.clone();
        let barrier = barrier.clone();
        writers.push(thread::spawn(move || -> TestResult<ContextObjectId> {
            let repository = ContextRepository::open(repository_path, FixedMetadataSource::new()?)?;
            barrier.wait();
            Ok(repository.append_snapshot(
                scope,
                root,
                Snapshot::new(vec![TreeEdit::blob(path, bytes)?])?,
                "Independent scope append",
            )?)
        }));
    }
    let commits = writers
        .into_iter()
        .map(|writer| {
            writer
                .join()
                .map_err(|_| io::Error::other("scope writer panicked"))?
        })
        .collect::<TestResult<Vec<_>>>()?;

    assert_eq!(fixture.reopen()?.scope_head(&first)?, commits[0]);
    assert_eq!(fixture.reopen()?.scope_head(&second)?, commits[1]);
    assert_eq!(only_parent(&fixture, commits[0])?, root);
    assert_eq!(only_parent(&fixture, commits[1])?, root);
    Ok(())
}
