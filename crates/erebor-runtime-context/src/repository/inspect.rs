use std::collections::HashSet;

use gix::{hash::Kind as HashKind, objs};
use snafu::ResultExt;

use super::{
    refs::SCOPE_PREFIX, ContextObjectId, ContextObjectKind, ContextRepository, PinnedContextBlob,
    ScopeRef,
};
use crate::error::{
    BoxedError, ReadScopeRefSnafu, Result, TreeEntryReadSnafu, TreeEntryWrongKindSnafu,
};

/// Immutable Git facts recorded by one context commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextCommit {
    id: ContextObjectId,
    tree: ContextObjectId,
    parents: Vec<ContextObjectId>,
}

impl ContextCommit {
    #[must_use]
    pub const fn id(&self) -> ContextObjectId {
        self.id
    }

    #[must_use]
    pub const fn tree(&self) -> ContextObjectId {
        self.tree
    }

    #[must_use]
    pub fn parents(&self) -> &[ContextObjectId] {
        &self.parents
    }
}

/// Immutable Git facts recorded by one tree object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextTree {
    id: ContextObjectId,
    entries: Vec<ContextTreeEntry>,
}

impl ContextTree {
    #[must_use]
    pub const fn id(&self) -> ContextObjectId {
        self.id
    }

    #[must_use]
    pub fn entries(&self) -> &[ContextTreeEntry] {
        &self.entries
    }
}

/// The Git object kind selected by a tree entry mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextTreeEntryKind {
    Blob,
    Tree,
    Commit,
}

impl ContextTreeEntryKind {
    fn object_kind(self) -> ContextObjectKind {
        match self {
            Self::Blob => ContextObjectKind::Blob,
            Self::Tree => ContextObjectKind::Tree,
            Self::Commit => ContextObjectKind::Commit,
        }
    }
}

/// One unmodified Git tree entry, including exact name bytes and mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextTreeEntry {
    name: Vec<u8>,
    mode: u16,
    kind: ContextTreeEntryKind,
    object: ContextObjectId,
}

impl ContextTreeEntry {
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }

    #[must_use]
    pub const fn kind(&self) -> ContextTreeEntryKind {
        self.kind
    }

    #[must_use]
    pub const fn object(&self) -> ContextObjectId {
        self.object
    }
}

/// Counts from an explicit full retained-graph verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextVerification {
    scope_count: usize,
    commit_count: usize,
    tree_count: usize,
    blob_count: usize,
}

impl ContextVerification {
    #[must_use]
    pub const fn scope_count(self) -> usize {
        self.scope_count
    }

    #[must_use]
    pub const fn commit_count(self) -> usize {
        self.commit_count
    }

    #[must_use]
    pub const fn tree_count(self) -> usize {
        self.tree_count
    }

    #[must_use]
    pub const fn blob_count(self) -> usize {
        self.blob_count
    }
}

#[derive(Default)]
struct VerificationState {
    commits: HashSet<ContextObjectId>,
    trees: HashSet<ContextObjectId>,
    blobs: HashSet<ContextObjectId>,
}

impl ContextRepository {
    /// Read every blob below one validated relative directory from an exact
    /// immutable commit. Callers receive paths and bytes only; no mutable ref
    /// lookup is performed after the commit is supplied.
    pub fn list_commit_blobs_under(
        &self,
        commit_id: ContextObjectId,
        directory: &str,
    ) -> Result<Vec<PinnedContextBlob>> {
        let commit = self.read_commit(commit_id)?;
        let components = Self::pin_path_components(directory)?;
        let mut tree = commit.tree();
        for component in components {
            let entries = self.read_tree(tree)?;
            let Some(entry) = entries
                .entries()
                .iter()
                .find(|entry| entry.name() == component.as_bytes())
            else {
                return Ok(Vec::new());
            };
            if entry.kind() != ContextTreeEntryKind::Tree {
                return TreeEntryWrongKindSnafu {
                    tree: Box::<str>::from(tree.to_string()),
                    path: Box::<str>::from(directory),
                    entry: Box::<str>::from(entry.object().to_string()),
                    expected: Box::<str>::from("tree"),
                    actual: Box::<str>::from(format!("{:?}", entry.kind()).to_lowercase()),
                }
                .fail();
            }
            tree = entry.object();
        }
        let mut blobs = Vec::new();
        self.collect_commit_blobs(tree, directory, &mut blobs)?;
        blobs.sort_by(|left, right| left.path().cmp(right.path()));
        Ok(blobs)
    }

    fn collect_commit_blobs(
        &self,
        tree: ContextObjectId,
        prefix: &str,
        blobs: &mut Vec<PinnedContextBlob>,
    ) -> Result<()> {
        for entry in self.read_tree(tree)?.entries() {
            let name = String::from_utf8_lossy(entry.name());
            let path = format!("{prefix}/{name}");
            match entry.kind() {
                ContextTreeEntryKind::Blob => {
                    let object = self.read_object(entry.object())?;
                    if object.kind() != ContextObjectKind::Blob {
                        return TreeEntryWrongKindSnafu {
                            tree: Box::<str>::from(tree.to_string()),
                            path: Box::<str>::from(path),
                            entry: Box::<str>::from(entry.object().to_string()),
                            expected: Box::<str>::from("blob"),
                            actual: Box::<str>::from(object.kind().to_string()),
                        }
                        .fail();
                    }
                    blobs.push(PinnedContextBlob::from_parts(
                        path,
                        object.id(),
                        object.into_bytes(),
                    ));
                }
                ContextTreeEntryKind::Tree => {
                    self.collect_commit_blobs(entry.object(), &path, blobs)?
                }
                ContextTreeEntryKind::Commit => {
                    return TreeEntryWrongKindSnafu {
                        tree: Box::<str>::from(tree.to_string()),
                        path: Box::<str>::from(path),
                        entry: Box::<str>::from(entry.object().to_string()),
                        expected: Box::<str>::from("blob or tree"),
                        actual: Box::<str>::from("commit"),
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }

    pub fn scope_refs(&self) -> Result<Vec<ScopeRef>> {
        let repository = self.repository();
        if repository
            .try_find_reference(SCOPE_PREFIX)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: SCOPE_PREFIX,
            })?
            .is_some()
        {
            ScopeRef::from_full_name(SCOPE_PREFIX.to_owned())?;
        }
        let reference_platform = repository
            .references()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: SCOPE_PREFIX,
            })?;
        let prefix = format!("{SCOPE_PREFIX}/");
        let references = reference_platform
            .prefixed(prefix.as_str())
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: SCOPE_PREFIX,
            })?;
        let mut scopes = Vec::new();
        for reference in references {
            let reference = reference.context(ReadScopeRefSnafu {
                scope: SCOPE_PREFIX,
            })?;
            let name = reference.name().to_string();
            scopes.push(ScopeRef::from_full_name(name)?);
        }
        scopes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(scopes)
    }

    pub fn read_commit(&self, id: ContextObjectId) -> Result<ContextCommit> {
        self.require_object_kind(id, ContextObjectKind::Commit)?;
        let object = self.read_object(id)?;
        let commit = objs::CommitRef::from_bytes(object.bytes(), HashKind::Sha256)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(crate::error::ReadObjectSnafu { id: id.to_string() })?;
        let tree = ContextObjectId::from_object_id(commit.tree())?;
        let parents = commit
            .parents()
            .map(ContextObjectId::from_object_id)
            .collect::<Result<Vec<_>>>()?;
        Ok(ContextCommit { id, tree, parents })
    }

    pub fn read_tree(&self, id: ContextObjectId) -> Result<ContextTree> {
        self.require_object_kind(id, ContextObjectKind::Tree)?;
        let object = self.read_object(id)?;
        let tree = objs::TreeRef::from_bytes(object.bytes(), HashKind::Sha256)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(crate::error::ReadObjectSnafu { id: id.to_string() })?;
        let entries = tree
            .entries
            .into_iter()
            .map(|entry| {
                let kind = match entry.mode.kind() {
                    objs::tree::EntryKind::Tree => ContextTreeEntryKind::Tree,
                    objs::tree::EntryKind::Commit => ContextTreeEntryKind::Commit,
                    objs::tree::EntryKind::Blob
                    | objs::tree::EntryKind::BlobExecutable
                    | objs::tree::EntryKind::Link => ContextTreeEntryKind::Blob,
                };
                Ok(ContextTreeEntry {
                    name: entry.filename.to_vec(),
                    mode: entry.mode.value(),
                    kind,
                    object: ContextObjectId::from_object_id(entry.oid.to_owned())?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ContextTree { id, entries })
    }

    pub fn is_ancestor(
        &self,
        ancestor: ContextObjectId,
        descendant: ContextObjectId,
    ) -> Result<bool> {
        self.require_object_kind(ancestor, ContextObjectKind::Commit)?;
        let mut pending = vec![descendant];
        let mut visited = HashSet::new();
        while let Some(commit) = pending.pop() {
            if !visited.insert(commit) {
                continue;
            }
            if commit == ancestor {
                return Ok(true);
            }
            pending.extend(self.read_commit(commit)?.parents);
        }
        Ok(false)
    }

    pub fn verify_full(&self) -> Result<ContextVerification> {
        let scopes = self.scope_refs()?;
        let mut state = VerificationState::default();
        let mut pending_commits = Vec::with_capacity(scopes.len());
        let mut pending_trees = Vec::new();
        for scope in &scopes {
            pending_commits.push(self.scope_head(scope)?);
        }
        while !pending_commits.is_empty() || !pending_trees.is_empty() {
            while let Some(commit_id) = pending_commits.pop() {
                if !state.commits.insert(commit_id) {
                    continue;
                }
                let commit = self.read_commit(commit_id)?;
                pending_trees.push((commit.tree, String::new()));
                pending_commits.extend(commit.parents);
            }
            let Some((tree_id, prefix)) = pending_trees.pop() else {
                continue;
            };
            if !state.trees.insert(tree_id) {
                continue;
            }
            let tree = self.read_tree(tree_id)?;
            for entry in tree.entries {
                let name = String::from_utf8_lossy(entry.name()).into_owned();
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                let object = self
                    .read_object(entry.object)
                    .map_err(|source| Box::new(source) as BoxedError)
                    .context(TreeEntryReadSnafu {
                        tree: Box::<str>::from(tree_id.to_string()),
                        path: Box::<str>::from(path.clone()),
                        entry: Box::<str>::from(entry.object.to_string()),
                    })?;
                let expected = entry.kind.object_kind();
                if object.kind() != expected {
                    return TreeEntryWrongKindSnafu {
                        tree: Box::<str>::from(tree_id.to_string()),
                        path: Box::<str>::from(path),
                        entry: Box::<str>::from(entry.object.to_string()),
                        expected: Box::<str>::from(expected.to_string()),
                        actual: Box::<str>::from(object.kind().to_string()),
                    }
                    .fail();
                }
                match entry.kind {
                    ContextTreeEntryKind::Blob => {
                        state.blobs.insert(entry.object);
                    }
                    ContextTreeEntryKind::Tree => pending_trees.push((entry.object, path)),
                    ContextTreeEntryKind::Commit => pending_commits.push(entry.object),
                }
            }
        }
        Ok(ContextVerification {
            scope_count: scopes.len(),
            commit_count: state.commits.len(),
            tree_count: state.trees.len(),
            blob_count: state.blobs.len(),
        })
    }

    pub(super) fn validate_scope_refs(&self) -> Result<()> {
        for scope in self.scope_refs()? {
            let head = self.scope_head(&scope)?;
            self.require_object_kind(self.read_commit(head)?.tree, ContextObjectKind::Tree)?;
        }
        Ok(())
    }
}
