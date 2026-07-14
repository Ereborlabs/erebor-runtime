use super::{run_git, Fixture, TestResult};
use crate::{ContextRepositoryError, ScopeRef, ScopeStart, Snapshot, TreeEdit};

fn snapshot(entries: &[(&str, &[u8])]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(
        entries
            .iter()
            .map(|(path, bytes)| TreeEdit::blob(*path, *bytes))
            .collect::<crate::Result<Vec<_>>>()?,
    )?)
}

#[test]
fn ref_validation_rejects_reserved_symbolic_wrong_target_and_prefix_conflicts() -> TestResult<()> {
    assert!(matches!(
        ScopeRef::root("invalid/session"),
        Err(ContextRepositoryError::InvalidScopeRef { .. })
    ));
    assert!(matches!(
        ScopeRef::scope("session-8421", "root"),
        Err(ContextRepositoryError::ReservedScopeName { .. })
    ));
    assert!(matches!(
        TreeEdit::blob("bad//path", b"value"),
        Err(ContextRepositoryError::InvalidTreeEdit { .. })
    ));
    let duplicate = TreeEdit::blob("same", b"value")?;
    assert!(matches!(
        Snapshot::new(vec![duplicate.clone(), duplicate]),
        Err(ContextRepositoryError::DuplicateTreeEditPath { .. })
    ));

    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    assert!(matches!(
        fixture.repository.initialize_root(
            "session-8421",
            snapshot(&[("replacement", b"must not replace")])?,
            "Do not replace root",
        ),
        Err(ContextRepositoryError::ScopeAlreadyExists { .. })
    ));
    let x = ScopeRef::scope("session-8421", "x")?;
    fixture
        .repository
        .create_scope(x.clone(), ScopeStart::existing_commit(root))?;
    let child_conflict = fixture.repository.create_scope(
        ScopeRef::scope("session-8421", "x/y")?,
        ScopeStart::existing_commit(root),
    );
    assert!(matches!(
        child_conflict,
        Err(ContextRepositoryError::ScopeRefPrefixConflict { .. })
    ));

    let second = Fixture::init()?;
    let second_root = second.repository.initialize_root(
        "session-8421",
        snapshot(&[("base", b"root")])?,
        "Initialize session root",
    )?;
    let y = ScopeRef::scope("session-8421", "x/y")?;
    second
        .repository
        .create_scope(y, ScopeStart::existing_commit(second_root))?;
    let parent_conflict = second.repository.create_scope(
        ScopeRef::scope("session-8421", "x")?,
        ScopeStart::existing_commit(second_root),
    );
    assert!(matches!(
        parent_conflict,
        Err(ContextRepositoryError::ScopeRefPrefixConflict { .. })
    ));

    let symbolic = ScopeRef::scope("session-8421", "symbolic")?;
    run_git(
        &second.path,
        &[
            "symbolic-ref",
            symbolic.as_str(),
            ScopeRef::root("session-8421")?.as_str(),
        ],
    )?;
    assert!(matches!(
        second.repository.scope_head(&symbolic),
        Err(ContextRepositoryError::SymbolicScopeRef { .. })
    ));

    let wrong_target = ScopeRef::scope("session-8421", "wrong-target")?;
    let blob = second.repository.write_blob(b"not a commit")?;
    run_git(
        &second.path,
        &["update-ref", wrong_target.as_str(), &blob.to_string()],
    )?;
    assert!(matches!(
        second.repository.scope_head(&wrong_target),
        Err(ContextRepositoryError::ScopeTargetNotCommit { .. })
    ));
    Ok(())
}
