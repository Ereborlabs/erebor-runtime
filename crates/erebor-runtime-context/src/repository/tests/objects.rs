use std::fs;

use super::{tree_entry_id, FixedMetadataSource, Fixture, ObjectGraph, TestResult};
use crate::{ContextObjectFormat, ContextObjectKind, ContextRepository};

#[test]
fn initializes_and_reopens_exact_bare_sha256_repository() -> TestResult<()> {
    let fixture = Fixture::init()?;

    assert_eq!(fixture.repository.path(), fixture.path);
    assert_eq!(
        fixture.repository.object_format(),
        ContextObjectFormat::Sha256
    );
    assert!(fixture.path.join("HEAD").is_file());
    assert!(fixture.path.join("objects").is_dir());
    assert!(!fixture.path.join(".git").exists());

    let reopened = fixture.reopen()?;
    assert_eq!(reopened.path(), fixture.path);
    assert_eq!(reopened.object_format(), ContextObjectFormat::Sha256);
    let local = reopened.repository();
    assert!(local.is_bare());
    assert_eq!(local.object_hash(), gix::hash::Kind::Sha256);
    assert_eq!(local.git_dir(), fixture.path);
    Ok(())
}

#[test]
fn objects_and_parent_shapes_survive_reopen_and_pass_git_oracles() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let graph = ObjectGraph::write(&fixture.repository)?;
    let before_reopen = graph
        .ids()
        .into_iter()
        .map(|id| fixture.repository.read_object(id))
        .collect::<crate::Result<Vec<_>>>()?;

    let reopened = fixture.reopen()?;
    for expected in before_reopen {
        assert_eq!(reopened.read_object(expected.id())?, expected);
    }
    assert_eq!(
        reopened.read_object(graph.first_blob)?.kind(),
        ContextObjectKind::Blob
    );
    assert_eq!(
        reopened.read_object(graph.first_tree)?.kind(),
        ContextObjectKind::Tree
    );
    assert_eq!(
        reopened.read_object(graph.merge_commit)?.kind(),
        ContextObjectKind::Commit
    );

    for id in graph.ids() {
        let expected_kind = reopened.read_object(id)?.kind().to_string();
        let actual_kind = super::run_git(&fixture.path, &["cat-file", "-t", &id.to_string()])?;
        assert_eq!(actual_kind.trim(), expected_kind);
    }
    for (id, expected_parents) in [
        (graph.root_commit, 0),
        (graph.child_commit, 1),
        (graph.merge_commit, 2),
    ] {
        let commit = super::run_git(&fixture.path, &["cat-file", "-p", &id.to_string()])?;
        assert_eq!(commit.matches("parent ").count(), expected_parents);
    }
    let merge = super::run_git(
        &fixture.path,
        &["cat-file", "-p", &graph.merge_commit.to_string()],
    )?;
    assert!(merge.contains("Consumed child response"));
    super::run_git(&fixture.path, &["fsck", "--full"])?;
    Ok(())
}

#[test]
fn changing_one_leaf_reuses_the_unchanged_subtree() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let left = fixture.repository.write_blob(b"left v1")?;
    let right = fixture.repository.write_blob(b"right v1")?;
    let with_left =
        fixture
            .repository
            .write_tree_entry(None, "left/value", ContextObjectKind::Blob, left)?;
    let base = fixture.repository.write_tree_entry(
        Some(with_left),
        "right/value",
        ContextObjectKind::Blob,
        right,
    )?;
    let base_left = tree_entry_id(&fixture.repository, base, "left")?;
    let base_right = tree_entry_id(&fixture.repository, base, "right")?;

    let changed_blob = fixture.repository.write_blob(b"left v2")?;
    let changed = fixture.repository.write_tree_entry(
        Some(base),
        "left/value",
        ContextObjectKind::Blob,
        changed_blob,
    )?;

    assert_ne!(changed, base);
    assert_ne!(
        tree_entry_id(&fixture.repository, changed, "left")?,
        base_left
    );
    assert_eq!(
        tree_entry_id(&fixture.repository, changed, "right")?,
        base_right
    );
    Ok(())
}

#[test]
fn fixed_inputs_produce_identical_ids_in_independent_repositories() -> TestResult<()> {
    let first = Fixture::init()?;
    let second_temp = tempfile::tempdir()?;
    let second_path = second_temp.path().join("context.git");
    let second = ContextRepository::init(&second_path, FixedMetadataSource::new()?)?;

    let first_graph = ObjectGraph::write(&first.repository)?;
    let second_graph = ObjectGraph::write(&second)?;

    assert_eq!(first_graph, second_graph);
    for id in first_graph.ids() {
        assert_eq!(first.repository.read_object(id)?, second.read_object(id)?);
    }
    Ok(())
}

#[test]
fn duplicate_blob_and_tree_writes_reuse_git_object_ids() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let first_blob = fixture.repository.write_blob(b"same bytes")?;
    let second_blob = fixture.repository.write_blob(b"same bytes")?;
    assert_eq!(first_blob, second_blob);

    let first_tree = fixture.repository.write_tree_entry(
        None,
        "caller/chosen-name",
        ContextObjectKind::Blob,
        first_blob,
    )?;
    let second_tree = fixture.repository.write_tree_entry(
        None,
        "caller/chosen-name",
        ContextObjectKind::Blob,
        second_blob,
    )?;
    assert_eq!(first_tree, second_tree);

    let object_path = first_blob.to_string();
    assert!(fs::metadata(
        fixture
            .path
            .join("objects")
            .join(&object_path[..2])
            .join(&object_path[2..])
    )?
    .is_file());
    Ok(())
}
