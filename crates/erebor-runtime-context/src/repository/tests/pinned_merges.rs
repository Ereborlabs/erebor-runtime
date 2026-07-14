use super::{run_git, tree_entry_id, Fixture, TestResult};
use crate::{ContextObjectId, ForkTarget, ScopeRef, ScopeStart, Snapshot, TreeEdit};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

fn commit_tree_id(fixture: &Fixture, commit: ContextObjectId) -> TestResult<ContextObjectId> {
    let local = fixture.repository.repository();
    let commit = local.find_commit(gix::hash::ObjectId::from_hex(
        commit.to_string().as_bytes(),
    )?)?;
    Ok(commit.tree_id()?.detach().to_string().parse()?)
}

fn parent_ids(fixture: &Fixture, commit: ContextObjectId) -> TestResult<Vec<ContextObjectId>> {
    run_git(&fixture.path, &["cat-file", "-p", &commit.to_string()])?
        .lines()
        .filter_map(|line| line.strip_prefix("parent "))
        .map(str::parse)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

#[test]
fn pinned_merge_keeps_exact_source_commit_and_only_selected_result_tree() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let receiver = ScopeRef::scope("session-8421", "parent")?;
    let source = ScopeRef::scope("session-8421", "child")?;
    fixture
        .repository
        .create_scope(receiver.clone(), ScopeStart::existing_commit(root))?;
    fixture
        .repository
        .create_scope(source.clone(), ScopeStart::existing_commit(root))?;
    let receiver_head = fixture.repository.append_snapshot(
        receiver.clone(),
        root,
        snapshot(&[("parent/state", b"before consumption")])?,
        "Receiver state",
    )?;
    let payload = b"same partial payload";
    let first_source = fixture.repository.append_snapshot(
        source.clone(),
        root,
        snapshot(&[("source/partial", payload)])?,
        "Produce partial",
    )?;
    let later_source = fixture.repository.append_snapshot(
        source.clone(),
        first_source,
        snapshot(&[("source/repeated", payload)])?,
        "Produce repeated partial",
    )?;
    let later_tree = commit_tree_id(&fixture, later_source)?;
    assert_eq!(
        tree_entry_id(&fixture.repository, later_tree, "source/partial")?,
        tree_entry_id(&fixture.repository, later_tree, "source/repeated")?
    );

    let result_tree = fixture
        .repository
        .create_tree(snapshot(&[("receiver/inbox", payload)])?)?;
    let merge = fixture.repository.append_pinned_merge(
        receiver.clone(),
        receiver_head,
        first_source,
        result_tree,
        "Consume selected partial",
    )?;
    let reopened = fixture.reopen()?;

    assert_eq!(
        parent_ids(&fixture, merge)?,
        vec![receiver_head, first_source]
    );
    assert_eq!(commit_tree_id(&fixture, merge)?, result_tree);
    assert_eq!(reopened.scope_head(&receiver)?, merge);
    assert_eq!(reopened.scope_head(&source)?, later_source);
    let selected_paths = run_git(
        &fixture.path,
        &["ls-tree", "-r", "--name-only", &merge.to_string()],
    )?;
    assert_eq!(
        selected_paths.lines().collect::<Vec<_>>(),
        vec!["receiver/inbox"]
    );
    Ok(())
}

#[test]
fn selected_fork_tree_reuses_the_causal_commit_when_it_is_identical() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let child = ScopeRef::scope("session-8421", "child")?;
    let causal_tree = commit_tree_id(&fixture, root)?;
    let result = fixture.repository.fork_scope(
        root,
        child.clone(),
        ForkTarget::selected_tree(causal_tree, "Identical selected tree"),
        None,
    )?;
    assert_eq!(result.child(), root);
    assert_eq!(fixture.repository.scope_head(&child)?, root);
    Ok(())
}
