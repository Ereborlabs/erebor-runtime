use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
};

use super::{CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, FixedMetadataSource};
use super::{Fixture, TestResult};
use crate::{
    ContextObjectId, ContextRepository, ContextRepositoryError, ForkParentAppend, ForkTarget,
    ScopeRef, ScopeStart, Snapshot, TreeEdit,
};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

fn parent_ids(fixture: &Fixture, commit: ContextObjectId) -> TestResult<Vec<ContextObjectId>> {
    let contents = super::run_git(&fixture.path, &["cat-file", "-p", &commit.to_string()])?;
    contents
        .lines()
        .filter_map(|line| line.strip_prefix("parent "))
        .map(str::parse)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

#[test]
fn fork_transaction_creates_independent_child_and_parent_branches() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("shared/base", b"base")])?,
        "Initialize session root",
    )?;
    let parent = ScopeRef::scope("session-8421", "parent")?;
    fixture
        .repository
        .create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    let causal = fixture.repository.append_snapshot(
        parent.clone(),
        root,
        snapshot(&[("parent/open-action", b"A")])?,
        "Start A",
    )?;
    let child = ScopeRef::scope("session-8421", "child-a")?;
    let child_tree = fixture
        .repository
        .create_tree(snapshot(&[("child/history", b"selected A")])?)?;
    let parent_tree = fixture
        .repository
        .create_tree(snapshot(&[("parent/next-action", b"B")])?)?;

    let result = fixture.repository.fork_scope(
        causal,
        child.clone(),
        ForkTarget::selected_tree(child_tree, "Select A for child"),
        Some(ForkParentAppend::new(
            parent.clone(),
            causal,
            parent_tree,
            "Start B on parent",
        )),
    )?;
    let parent_next = result
        .parent()
        .ok_or_else(|| io::Error::other("fork did not return parent commit"))?;

    assert_eq!(fixture.repository.scope_head(&child)?, result.child());
    assert_eq!(fixture.repository.scope_head(&parent)?, parent_next);
    assert_eq!(parent_ids(&fixture, result.child())?, vec![causal]);
    assert_eq!(parent_ids(&fixture, parent_next)?, vec![causal]);

    let reused = ScopeRef::scope("session-8421", "child-reused")?;
    let reused_result = fixture.repository.fork_scope(
        causal,
        reused.clone(),
        ForkTarget::reuse_causal_commit(),
        None,
    )?;
    assert_eq!(reused_result.child(), causal);
    assert_eq!(reused_result.parent(), None);
    assert_eq!(fixture.repository.scope_head(&reused)?, causal);
    Ok(())
}

#[derive(Clone)]
struct BlockingMetadataSource {
    metadata: CommitMetadata,
    reached_write: Arc<Barrier>,
    release_write: Arc<Barrier>,
    block_once: Arc<AtomicBool>,
}

impl CommitMetadataSource for BlockingMetadataSource {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError> {
        if self.block_once.swap(false, Ordering::SeqCst) {
            self.reached_write.wait();
            self.release_write.wait();
        }
        Ok(self.metadata.clone())
    }
}

#[test]
fn stale_preparation_leaves_every_requested_fork_ref_unchanged() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let parent = ScopeRef::scope("session-8421", "parent")?;
    fixture
        .repository
        .create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    let causal = fixture.repository.append_snapshot(
        parent.clone(),
        root,
        snapshot(&[("parent/open-action", b"A")])?,
        "Start A",
    )?;
    let child = ScopeRef::scope("session-8421", "child-a")?;
    let parent_tree = fixture
        .repository
        .create_tree(snapshot(&[("parent/next-action", b"B")])?)?;
    let metadata = FixedMetadataSource::new()?.metadata()?;
    let reached_write = Arc::new(Barrier::new(2));
    let release_write = Arc::new(Barrier::new(2));
    let source = BlockingMetadataSource {
        metadata,
        reached_write: reached_write.clone(),
        release_write: release_write.clone(),
        block_once: Arc::new(AtomicBool::new(true)),
    };
    let path = fixture.path.clone();
    let parent_for_fork = parent.clone();
    let child_for_fork = child.clone();
    let fork = thread::spawn(move || -> TestResult<crate::Result<crate::ForkResult>> {
        let repository = ContextRepository::open(path, source)?;
        Ok(repository.fork_scope(
            causal,
            child_for_fork,
            ForkTarget::reuse_causal_commit(),
            Some(ForkParentAppend::new(
                parent_for_fork,
                causal,
                parent_tree,
                "Start B on parent",
            )),
        ))
    });

    reached_write.wait();
    let intervening_parent = fixture.repository.append_snapshot(
        parent.clone(),
        causal,
        snapshot(&[("parent/intervening", b"other writer")])?,
        "Intervening parent append",
    )?;
    release_write.wait();
    let error = fork
        .join()
        .map_err(|_| io::Error::other("fork writer panicked"))??
        .err()
        .ok_or_else(|| io::Error::other("stale fork unexpectedly succeeded"))?;

    assert!(matches!(
        error,
        ContextRepositoryError::StaleScopeHead { .. }
    ));
    assert_eq!(fixture.repository.scope_head(&parent)?, intervening_parent);
    assert!(matches!(
        fixture.repository.scope_head(&child),
        Err(ContextRepositoryError::ScopeNotFound { .. })
    ));
    Ok(())
}

#[test]
fn forked_parent_and_child_refs_advance_concurrently_without_crossing() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let parent = ScopeRef::scope("session-8421", "parent")?;
    fixture
        .repository
        .create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    let causal = fixture.repository.append_snapshot(
        parent.clone(),
        root,
        snapshot(&[("parent/open-action", b"A")])?,
        "Start A",
    )?;
    let child = ScopeRef::scope("session-8421", "child-a")?;
    fixture.repository.fork_scope(
        causal,
        child.clone(),
        ForkTarget::reuse_causal_commit(),
        None,
    )?;

    let barrier = Arc::new(Barrier::new(2));
    let mut writers = Vec::new();
    for (scope, path, bytes) in [
        (parent.clone(), "parent/next-action", b"B".as_slice()),
        (
            child.clone(),
            "child/continued-action",
            b"A result".as_slice(),
        ),
    ] {
        let path_to_repository = fixture.path.clone();
        let barrier = barrier.clone();
        writers.push(thread::spawn(move || -> TestResult<ContextObjectId> {
            let repository =
                ContextRepository::open(path_to_repository, FixedMetadataSource::new()?)?;
            barrier.wait();
            Ok(repository.append_snapshot(
                scope,
                causal,
                Snapshot::new(vec![TreeEdit::blob(path, bytes)?])?,
                "Concurrent forked scope append",
            )?)
        }));
    }
    let commits = writers
        .into_iter()
        .map(|writer| {
            writer
                .join()
                .map_err(|_| io::Error::other("forked scope writer panicked"))?
        })
        .collect::<TestResult<Vec<_>>>()?;

    assert_eq!(fixture.reopen()?.scope_head(&parent)?, commits[0]);
    assert_eq!(fixture.reopen()?.scope_head(&child)?, commits[1]);
    assert_eq!(parent_ids(&fixture, commits[0])?, vec![causal]);
    assert_eq!(parent_ids(&fixture, commits[1])?, vec![causal]);
    Ok(())
}
