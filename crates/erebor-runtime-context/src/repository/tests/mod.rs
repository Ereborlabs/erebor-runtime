use std::{error::Error, io, path::Path, path::PathBuf, process::Command};

use tempfile::TempDir;

use super::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextObjectId, ContextObjectKind, ContextRepository,
};

mod fork_transactions;
mod objects;
mod pinned_merges;
mod scope_validation;
mod scopes;
mod transaction_validation;
mod validation;

type TestResult<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone)]
struct FixedMetadataSource {
    metadata: CommitMetadata,
}

impl FixedMetadataSource {
    fn new() -> TestResult<Self> {
        let time = CommitTime::new(1_700_000_000, 0)?;
        let signature = CommitSignature::new("Erebor Context", "context@erebor.dev", time)?;
        Ok(Self {
            metadata: CommitMetadata::new(signature.clone(), signature),
        })
    }
}

impl CommitMetadataSource for FixedMetadataSource {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError> {
        Ok(self.metadata.clone())
    }
}

struct Fixture {
    _temp: TempDir,
    path: PathBuf,
    repository: ContextRepository,
}

impl Fixture {
    fn init() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("context.git");
        let repository = ContextRepository::init(&path, FixedMetadataSource::new()?)?;
        Ok(Self {
            _temp: temp,
            path,
            repository,
        })
    }

    fn reopen(&self) -> TestResult<ContextRepository> {
        Ok(ContextRepository::open(
            &self.path,
            FixedMetadataSource::new()?,
        )?)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ObjectGraph {
    first_blob: ContextObjectId,
    first_tree: ContextObjectId,
    root_commit: ContextObjectId,
    second_blob: ContextObjectId,
    second_tree: ContextObjectId,
    child_commit: ContextObjectId,
    merge_commit: ContextObjectId,
}

impl ObjectGraph {
    fn write(repository: &ContextRepository) -> TestResult<Self> {
        let first_blob = repository.write_blob(b"partial LLM response")?;
        let first_tree = repository.write_tree_entry(
            None,
            "codex/results/partial",
            ContextObjectKind::Blob,
            first_blob,
        )?;
        let root_commit = repository.write_commit(first_tree, &[], "Produced partial response")?;

        let second_blob = repository.write_blob(b"final LLM response")?;
        let second_tree = repository.write_tree_entry(
            Some(first_tree),
            "codex/results/final",
            ContextObjectKind::Blob,
            second_blob,
        )?;
        let child_commit =
            repository.write_commit(second_tree, &[root_commit], "Produced final response")?;
        let merge_commit = repository.write_commit(
            second_tree,
            &[root_commit, child_commit],
            "Consumed child response",
        )?;

        Ok(Self {
            first_blob,
            first_tree,
            root_commit,
            second_blob,
            second_tree,
            child_commit,
            merge_commit,
        })
    }

    fn ids(&self) -> [ContextObjectId; 7] {
        [
            self.first_blob,
            self.first_tree,
            self.root_commit,
            self.second_blob,
            self.second_tree,
            self.child_commit,
            self.merge_commit,
        ]
    }
}

fn tree_entry_id(
    repository: &ContextRepository,
    tree: ContextObjectId,
    path: &str,
) -> TestResult<ContextObjectId> {
    let local = repository.repository();
    let git_tree = local.find_tree(gix::hash::ObjectId::from_hex(tree.to_string().as_bytes())?)?;
    let entry = git_tree
        .lookup_entry_by_path(path)?
        .ok_or_else(|| io::Error::other(format!("tree entry `{path}` was not found")))?;
    Ok(entry.object_id().to_string().parse()?)
}

fn run_git(repository_path: &Path, arguments: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repository_path)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git {} failed with status {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
