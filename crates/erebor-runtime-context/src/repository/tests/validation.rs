use std::{env, fs, io, process::Command};

use erebor_runtime_error::{ErrorExt, StatusCode};
use gix::{
    create::{Kind as RepositoryKind, Options as CreateOptions},
    hash::Kind as HashKind,
    ThreadSafeRepository,
};

use super::{FixedMetadataSource, Fixture, ObjectGraph, TestResult};
use crate::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, ContextObjectId,
    ContextObjectKind, ContextRepository, ContextRepositoryError,
};

#[test]
fn missing_paths_and_parent_repository_discovery_are_rejected() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let parent = temp.path().join("parent.git");
    ContextRepository::init(&parent, FixedMetadataSource::new()?)?;
    let missing = parent.join("nested").join("context.git");

    let error = ContextRepository::open(&missing, FixedMetadataSource::new()?)
        .err()
        .ok_or_else(|| io::Error::other("missing repository unexpectedly opened"))?;
    assert!(matches!(
        error,
        ContextRepositoryError::MissingRepository { .. }
    ));
    assert_eq!(error.status_code(), StatusCode::NotFound);
    Ok(())
}

#[test]
fn worktree_and_sha1_repositories_are_rejected() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    ThreadSafeRepository::init(
        &worktree,
        RepositoryKind::WithWorktree,
        CreateOptions {
            object_hash: Some(HashKind::Sha256),
            ..CreateOptions::default()
        },
    )?;
    let worktree_error =
        ContextRepository::open(worktree.join(".git"), FixedMetadataSource::new()?)
            .err()
            .ok_or_else(|| io::Error::other("worktree repository unexpectedly opened"))?;
    assert!(matches!(
        worktree_error,
        ContextRepositoryError::UnsupportedRepositoryKind { .. }
    ));

    let sha1 = temp.path().join("sha1.git");
    ThreadSafeRepository::init(
        &sha1,
        RepositoryKind::Bare,
        CreateOptions {
            object_hash: Some(HashKind::Sha1),
            ..CreateOptions::default()
        },
    )?;
    let sha1_error = ContextRepository::open(&sha1, FixedMetadataSource::new()?)
        .err()
        .ok_or_else(|| io::Error::other("SHA-1 repository unexpectedly opened"))?;
    assert!(matches!(
        sha1_error,
        ContextRepositoryError::UnsupportedObjectFormat { .. }
    ));
    assert_eq!(sha1_error.status_code(), StatusCode::Unsupported);
    Ok(())
}

#[test]
fn alternates_are_rejected_before_object_access() -> TestResult<()> {
    let fixture = Fixture::init()?;
    fs::write(
        fixture.path.join("objects/info/alternates"),
        b"/tmp/not-authorized\n",
    )?;

    let error = ContextRepository::open(&fixture.path, FixedMetadataSource::new()?)
        .err()
        .ok_or_else(|| io::Error::other("repository with alternates unexpectedly opened"))?;
    assert!(matches!(
        error,
        ContextRepositoryError::UnsupportedAlternates { .. }
    ));
    Ok(())
}

#[test]
fn malformed_missing_and_wrong_kind_objects_return_typed_errors() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let blob = fixture.repository.write_blob(b"will be corrupted")?;
    let wrong_kind = fixture
        .repository
        .write_commit(blob, &[], "invalid tree")
        .err()
        .ok_or_else(|| io::Error::other("blob was accepted as a commit tree"))?;
    assert!(matches!(
        wrong_kind,
        ContextRepositoryError::WrongObjectKind { .. }
    ));

    let missing: ContextObjectId =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse()?;
    let missing_error = fixture
        .repository
        .read_object(missing)
        .err()
        .ok_or_else(|| io::Error::other("missing object unexpectedly resolved"))?;
    assert!(matches!(
        missing_error,
        ContextRepositoryError::ObjectNotFound { .. }
    ));

    let hex = blob.to_string();
    let object_path = fixture.path.join("objects").join(&hex[..2]).join(&hex[2..]);
    fs::remove_file(&object_path)?;
    fs::write(&object_path, b"not a zlib-compressed Git object")?;
    let reopened = fixture.reopen()?;
    let malformed = reopened
        .read_object(blob)
        .err()
        .ok_or_else(|| io::Error::other("malformed object unexpectedly decoded"))?;
    assert!(matches!(
        malformed,
        ContextRepositoryError::ReadObject { .. }
    ));
    assert_eq!(malformed.status_code(), StatusCode::InvalidSyntax);
    Ok(())
}

#[test]
fn invalid_inputs_and_gitoxide_failures_return_typed_errors() -> TestResult<()> {
    let malformed_id = "not-an-object-id".parse::<ContextObjectId>();
    assert!(matches!(
        malformed_id,
        Err(ContextRepositoryError::InvalidObjectId { .. })
    ));
    let sha1_id = "0000000000000000000000000000000000000000".parse::<ContextObjectId>();
    assert!(matches!(
        sha1_id,
        Err(ContextRepositoryError::UnsupportedObjectIdFormat { .. })
    ));

    let fixture = Fixture::init()?;
    let blob = fixture.repository.write_blob(b"value")?;
    let invalid_tree =
        fixture
            .repository
            .write_tree_entry(None, "bad//path", ContextObjectKind::Blob, blob);
    assert!(matches!(
        invalid_tree,
        Err(ContextRepositoryError::EditTree { .. })
    ));

    let temp = tempfile::tempdir()?;
    let nonempty = temp.path().join("nonempty.git");
    fs::create_dir(&nonempty)?;
    fs::write(nonempty.join("occupied"), b"data")?;
    let initialization = ContextRepository::init(&nonempty, FixedMetadataSource::new()?);
    assert!(matches!(
        initialization,
        Err(ContextRepositoryError::InitializeRepository { .. })
    ));
    Ok(())
}

struct FailingMetadataSource;

impl CommitMetadataSource for FailingMetadataSource {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError> {
        Err(io::Error::other("clock unavailable").into())
    }
}

#[test]
fn metadata_source_failures_and_excess_parents_are_typed() -> TestResult<()> {
    let fixture = Fixture::init()?;
    let blob = fixture.repository.write_blob(b"value")?;
    let tree = fixture
        .repository
        .write_tree_entry(None, "value", ContextObjectKind::Blob, blob)?;
    let root = fixture.repository.write_commit(tree, &[], "root")?;
    let too_many = fixture
        .repository
        .write_commit(tree, &[root, root, root], "invalid");
    assert!(matches!(
        too_many,
        Err(ContextRepositoryError::InvalidParentCount { count: 3, .. })
    ));

    let reopened = ContextRepository::open(&fixture.path, FailingMetadataSource)?;
    let metadata_error = reopened
        .write_commit(tree, &[root], "metadata failure")
        .err()
        .ok_or_else(|| io::Error::other("failing metadata source unexpectedly succeeded"))?;
    assert!(matches!(
        metadata_error,
        ContextRepositoryError::CommitMetadataSource { .. }
    ));
    Ok(())
}

const AMBIENT_CHILD: &str = "EREBOR_CONTEXT_AMBIENT_TEST_CHILD";

#[test]
fn ambient_git_configuration_is_ignored() -> TestResult<()> {
    if env::var_os(AMBIENT_CHILD).is_some() {
        return run_ambient_child();
    }

    let baseline = Fixture::init()?;
    let expected = ObjectGraph::write(&baseline.repository)?.merge_commit;
    let child_temp = tempfile::tempdir()?;
    let target = child_temp.path().join("target.git");
    let decoy = child_temp.path().join("decoy.git");
    ThreadSafeRepository::init(
        &decoy,
        RepositoryKind::Bare,
        CreateOptions {
            object_hash: Some(HashKind::Sha1),
            ..CreateOptions::default()
        },
    )?;
    let global_config = child_temp.path().join("hostile-gitconfig");
    fs::write(
        &global_config,
        b"[user]\nname = Ambient User\nemail = ambient@example.invalid\n[init]\ndefaultBranch = ambient\n",
    )?;

    let output = Command::new(env::current_exe()?)
        .arg("ambient_git_configuration_is_ignored")
        .arg("--nocapture")
        .env(AMBIENT_CHILD, "1")
        .env("EREBOR_CONTEXT_EXPECTED_ID", expected.to_string())
        .env("EREBOR_CONTEXT_TARGET", &target)
        .env("GIT_DIR", &decoy)
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("GIT_AUTHOR_NAME", "Ambient Author")
        .env("GIT_AUTHOR_EMAIL", "ambient-author@example.invalid")
        .env("GIT_COMMITTER_NAME", "Ambient Committer")
        .env("GIT_COMMITTER_EMAIL", "ambient-committer@example.invalid")
        .env("GIT_DEFAULT_HASH", "sha1")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "ambient configuration child failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    assert!(target.join("objects").is_dir());
    assert_eq!(
        ThreadSafeRepository::open(&decoy)
            .map(|repository| repository.to_thread_local().object_hash())?,
        HashKind::Sha1
    );
    Ok(())
}

fn run_ambient_child() -> TestResult<()> {
    let target = env::var_os("EREBOR_CONTEXT_TARGET")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::other("missing child target path"))?;
    let expected: ContextObjectId = env::var("EREBOR_CONTEXT_EXPECTED_ID")?.parse()?;
    let repository = ContextRepository::init(&target, FixedMetadataSource::new()?)?;
    let actual = ObjectGraph::write(&repository)?.merge_commit;
    assert_eq!(repository.path(), target);
    assert_eq!(actual, expected);
    Ok(())
}
