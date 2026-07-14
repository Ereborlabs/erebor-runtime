use super::{run_git, Fixture, TestResult};
use crate::{
    ContextObjectId, ContextPin, ContextPinSelection, ContextRepositoryError, ScopeRef, ScopeStart,
    Snapshot, TreeEdit,
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
fn pin_detaches_one_scope_head_and_returns_only_selected_blob_bytes() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = ScopeRef::root("session-8421")?;
    let commit = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[
            ("codex/results/partial", b"partial response"),
            ("codex/private/unselected", b"must not be returned"),
        ])?,
        "Initialize context",
    )?;

    let pinned = fixture
        .repository
        .pin_scope_head(root, &[ContextPinSelection::blob("codex/results/partial")])?;

    assert_eq!(pinned.session_id(), "session-8421");
    assert_eq!(pinned.pin().commit_id(), commit.to_string());
    assert_eq!(pinned.pin().used_paths(), ["codex/results/partial"]);
    assert_eq!(pinned.selected_blobs().len(), 1);
    assert_eq!(pinned.selected_blobs()[0].bytes(), b"partial response");
    assert_eq!(
        pinned.selected_blobs()[0].id().to_string(),
        pinned.pin().used_blob_ids()[0]
    );
    fixture.repository.validate_pin(pinned.pin())?;
    Ok(())
}

#[test]
fn later_scope_head_does_not_change_a_detached_pin_or_its_selected_bytes() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = ScopeRef::root("session-8421")?;
    let first = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("result", b"early")])?,
        "Initialize context",
    )?;
    let pinned = fixture
        .repository
        .pin_scope_head(root.clone(), &[ContextPinSelection::blob("result")])?;
    let later = fixture.repository.append_snapshot(
        root,
        first,
        snapshot(&[("result", b"later")])?,
        "Later context",
    )?;

    assert_ne!(later.to_string(), pinned.pin().commit_id());
    assert_eq!(pinned.selected_blobs()[0].bytes(), b"early");
    fixture.repository.validate_pin(pinned.pin())?;
    Ok(())
}

#[test]
fn pin_supports_root_unknown_and_named_direct_scopes() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("result", b"root")])?,
        "Initialize context",
    )?;
    let unknown = ScopeRef::unknown("session-8421")?;
    let named = ScopeRef::scope("session-8421", "worker")?;
    fixture
        .repository
        .create_scope(unknown.clone(), ScopeStart::existing_commit(root))?;
    fixture
        .repository
        .create_scope(named.clone(), ScopeStart::existing_commit(root))?;

    for scope in [ScopeRef::root("session-8421")?, unknown, named] {
        let pin = fixture
            .repository
            .pin_scope_head(scope, &[ContextPinSelection::blob("result")])?;
        assert_eq!(pin.selected_blobs()[0].bytes(), b"root");
    }
    Ok(())
}

#[test]
fn pin_rejects_unknown_tree_and_mismatched_blob_selections() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = ScopeRef::root("session-8421")?;
    fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("codex/results/partial", b"partial")])?,
        "Initialize context",
    )?;

    assert!(matches!(
        fixture
            .repository
            .pin_scope_head(root.clone(), &[ContextPinSelection::blob("missing")]),
        Err(ContextRepositoryError::ContextPinPathNotFound { .. })
    ));
    assert!(matches!(
        fixture
            .repository
            .pin_scope_head(root.clone(), &[ContextPinSelection::blob("codex/results")]),
        Err(ContextRepositoryError::ContextPinPathNotBlob { actual: "tree", .. })
    ));
    let wrong: ContextObjectId =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse()?;
    assert!(matches!(
        fixture.repository.pin_scope_head(
            root,
            &[ContextPinSelection::exact_blob(
                "codex/results/partial",
                wrong
            )]
        ),
        Err(ContextRepositoryError::ContextPinBlobMismatch { .. })
    ));
    for path in ["", "/result", "../result", "result//again"] {
        assert!(matches!(
            fixture.repository.pin_scope_head(
                ScopeRef::root("session-8421")?,
                &[ContextPinSelection::blob(path)]
            ),
            Err(ContextRepositoryError::InvalidContextPinPath { .. })
        ));
    }
    Ok(())
}

#[test]
fn deserialized_pins_cannot_claim_another_blob_or_missing_commit() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = ScopeRef::root("session-8421")?;
    fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("result", b"value")])?,
        "Initialize context",
    )?;
    let pinned = fixture
        .repository
        .pin_scope_head(root, &[ContextPinSelection::blob("result")])?;
    let mut encoded = serde_json::to_value(pinned.pin())?;
    encoded["used_blob_ids"][0] =
        serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mismatched: ContextPin = serde_json::from_value(encoded.clone())?;
    assert!(matches!(
        fixture.repository.validate_pin(&mismatched),
        Err(ContextRepositoryError::ContextPinBlobMismatch { .. })
    ));

    encoded["commit_id"] =
        serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let missing: ContextPin = serde_json::from_value(encoded.clone())?;
    assert!(matches!(
        fixture.repository.validate_pin(&missing),
        Err(ContextRepositoryError::ObjectNotFound { .. })
    ));

    encoded["commit_id"] = serde_json::json!(pinned.pin().commit_id());
    encoded["used_blob_ids"][0] = serde_json::json!(pinned.pin().used_blob_ids()[0]);
    encoded["scope_ref"] = serde_json::json!("refs/scopes/other-session/root");
    let wrong_session: ContextPin = serde_json::from_value(encoded)?;
    assert!(matches!(
        fixture
            .repository
            .validate_session_pin("session-8421", &wrong_session),
        Err(ContextRepositoryError::InvalidContextPin { .. })
    ));
    Ok(())
}

#[test]
fn pin_rejects_a_symbolic_scope_ref_before_selecting_any_blob() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let root = ScopeRef::root("session-8421")?;
    let unknown = ScopeRef::unknown("session-8421")?;
    let commit = fixture.repository.initialize_root(
        "session-8421",
        snapshot(&[("result", b"value")])?,
        "Initialize context",
    )?;
    fixture
        .repository
        .create_scope(unknown.clone(), ScopeStart::existing_commit(commit))?;
    run_git(
        &fixture.path,
        &["symbolic-ref", root.as_str(), unknown.as_str()],
    )?;

    assert!(matches!(
        fixture
            .repository
            .pin_scope_head(root, &[ContextPinSelection::blob("result")]),
        Err(ContextRepositoryError::SymbolicScopeRef { .. })
    ));
    Ok(())
}
