use std::{collections::HashSet, str::FromStr};

use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt};

use super::{
    ContextObjectId, ContextObjectKind, ContextRepository, ContextTreeEntryKind, ScopeRef,
};
use crate::error::{
    ContextPinBlobMismatchSnafu, ContextPinPathNotBlobSnafu, ContextPinPathNotFoundSnafu,
    DuplicateContextPinPathSnafu, InvalidContextPinPathSnafu, InvalidContextPinSnafu, Result,
};

/// A caller-selected blob path and, optionally, the exact blob it must resolve to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextPinSelection {
    path: String,
    expected_blob: Option<ContextObjectId>,
}

impl ContextPinSelection {
    #[must_use]
    pub fn blob(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            expected_blob: None,
        }
    }

    #[must_use]
    pub fn exact_blob(path: impl Into<String>, expected_blob: ContextObjectId) -> Self {
        Self {
            path: path.into(),
            expected_blob: Some(expected_blob),
        }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn expected_blob(&self) -> Option<ContextObjectId> {
        self.expected_blob
    }
}

/// Serializable immutable Git references recorded with one context-aware decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextPin {
    scope_ref: String,
    commit_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    used_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    used_blob_ids: Vec<String>,
}

impl ContextPin {
    #[must_use]
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }

    #[must_use]
    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    #[must_use]
    pub fn used_paths(&self) -> &[String] {
        &self.used_paths
    }

    #[must_use]
    pub fn used_blob_ids(&self) -> &[String] {
        &self.used_blob_ids
    }

    /// Decode the persisted scope reference through the repository-owned
    /// scope parser.
    pub fn scope(&self) -> Result<ScopeRef> {
        ScopeRef::parse(self.scope_ref.clone())
    }

    /// Decode the persisted immutable commit identifier.
    pub fn commit(&self) -> Result<ContextObjectId> {
        ContextObjectId::from_str(&self.commit_id)
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.used_paths.len() == self.used_blob_ids.len(),
            InvalidContextPinSnafu {
                reason: "selected paths and blob ids must have the same length",
            }
        );
        let mut paths = HashSet::with_capacity(self.used_paths.len());
        for path in &self.used_paths {
            ContextRepository::pin_path_components(path)?;
            if !paths.insert(path) {
                return DuplicateContextPinPathSnafu {
                    path: Box::<str>::from(path.as_str()),
                }
                .fail();
            }
        }
        Ok(())
    }
}

/// A blob selected from the exact detached commit represented by a [`PinnedContext`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedContextBlob {
    path: String,
    id: ContextObjectId,
    bytes: Vec<u8>,
}

impl PinnedContextBlob {
    pub(super) fn from_parts(path: String, id: ContextObjectId, bytes: Vec<u8>) -> Self {
        Self { path, id, bytes }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn id(&self) -> ContextObjectId {
        self.id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A repository-validated detached commit and the caller-selected blob bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedContext {
    pin: ContextPin,
    session_id: String,
    selected_blobs: Vec<PinnedContextBlob>,
}

impl PinnedContext {
    #[must_use]
    pub fn pin(&self) -> &ContextPin {
        &self.pin
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn selected_blobs(&self) -> &[PinnedContextBlob] {
        &self.selected_blobs
    }
}

impl ContextRepository {
    /// Read one checked blob path from an exact immutable commit. A missing
    /// path is not an error; a malformed path or non-blob tree entry is.
    pub fn read_commit_blob(
        &self,
        commit_id: ContextObjectId,
        path: &str,
    ) -> Result<Option<PinnedContextBlob>> {
        let commit = self.read_commit(commit_id)?;
        let components = Self::pin_path_components(path)?;
        let mut tree = commit.tree();
        for (index, component) in components.iter().enumerate() {
            let tree_object = self.read_tree(tree)?;
            let Some(entry) = tree_object
                .entries()
                .iter()
                .find(|entry| entry.name() == component.as_bytes())
            else {
                return Ok(None);
            };
            if index + 1 != components.len() {
                if entry.kind() != ContextTreeEntryKind::Tree {
                    return ContextPinPathNotBlobSnafu {
                        path: Box::<str>::from(path),
                        actual: Self::tree_entry_kind_name(entry.kind()),
                    }
                    .fail();
                }
                tree = entry.object();
                continue;
            }
            if entry.kind() != ContextTreeEntryKind::Blob {
                return ContextPinPathNotBlobSnafu {
                    path: Box::<str>::from(path),
                    actual: Self::tree_entry_kind_name(entry.kind()),
                }
                .fail();
            }
            let object = self.read_object(entry.object())?;
            if object.kind() != ContextObjectKind::Blob {
                return ContextPinPathNotBlobSnafu {
                    path: Box::<str>::from(path),
                    actual: Self::object_kind_name(object.kind()),
                }
                .fail();
            }
            return Ok(Some(PinnedContextBlob {
                path: path.to_owned(),
                id: object.id(),
                bytes: object.into_bytes(),
            }));
        }
        unreachable!("validated context pin paths contain at least one component")
    }

    /// Detach one direct scope head and return only caller-selected blob bytes from its tree.
    pub fn pin_scope_head(
        &self,
        scope: ScopeRef,
        selections: &[ContextPinSelection],
    ) -> Result<PinnedContext> {
        let head = self.scope_head(&scope)?;
        self.pin_commit(scope, head, selections)
    }

    /// Detach one known immutable commit and return only caller-selected blob
    /// bytes. The caller supplies a checked scope identity because a causal
    /// pin may intentionally predate that scope's current head.
    pub fn pin_commit(
        &self,
        scope: ScopeRef,
        commit: ContextObjectId,
        selections: &[ContextPinSelection],
    ) -> Result<PinnedContext> {
        let tree = self.read_commit(commit)?.tree();
        self.read_tree(tree)?;
        let mut selected_paths = HashSet::with_capacity(selections.len());
        let mut selected_blobs = Vec::with_capacity(selections.len());
        for selection in selections {
            Self::pin_path_components(selection.path())?;
            if !selected_paths.insert(selection.path()) {
                return DuplicateContextPinPathSnafu {
                    path: Box::<str>::from(selection.path()),
                }
                .fail();
            }
            let selected = self.resolve_pinned_blob(tree, selection.path())?;
            if let Some(expected) = selection.expected_blob() {
                if expected != selected.id {
                    return ContextPinBlobMismatchSnafu {
                        path: Box::<str>::from(selection.path()),
                        expected: Box::<str>::from(expected.to_string()),
                        actual: Box::<str>::from(selected.id.to_string()),
                    }
                    .fail();
                }
            }
            selected_blobs.push(selected);
        }
        let pin = ContextPin {
            scope_ref: scope.to_string(),
            commit_id: commit.to_string(),
            used_paths: selected_blobs
                .iter()
                .map(|blob| blob.path.clone())
                .collect(),
            used_blob_ids: selected_blobs
                .iter()
                .map(|blob| blob.id.to_string())
                .collect(),
        };
        Ok(PinnedContext {
            pin,
            session_id: scope.session_id().to_owned(),
            selected_blobs,
        })
    }

    /// Rehydrate the exact blob bytes named by a previously validated-looking
    /// pin. This never reads a mutable scope head.
    pub fn read_pinned_context(&self, pin: &ContextPin) -> Result<PinnedContext> {
        pin.validate_shape()?;
        let scope = pin.scope()?;
        let commit = pin.commit()?;
        let selections = pin
            .used_paths
            .iter()
            .zip(&pin.used_blob_ids)
            .map(|(path, blob_id)| {
                ContextObjectId::from_str(blob_id)
                    .map(|blob| ContextPinSelection::exact_blob(path.clone(), blob))
            })
            .collect::<Result<Vec<_>>>()?;
        self.pin_commit(scope, commit, &selections)
    }

    /// Verify that a deserialized audit pin still identifies the exact recorded objects.
    pub fn validate_pin(&self, pin: &ContextPin) -> Result<()> {
        self.read_pinned_context(pin).map(|_context| ())
    }

    /// Verify that a deserialized audit pin belongs to one session and its exact recorded objects.
    pub fn validate_session_pin(&self, session_id: &str, pin: &ContextPin) -> Result<()> {
        let scope = pin.scope()?;
        ensure!(
            scope.session_id() == session_id,
            InvalidContextPinSnafu {
                reason: "scope ref session id does not match the audit event session id",
            }
        );
        self.read_pinned_context(pin).map(|_context| ())
    }

    pub(super) fn pin_path_components(path: &str) -> Result<Vec<&str>> {
        ensure!(
            !path.is_empty(),
            InvalidContextPinPathSnafu {
                path: Box::<str>::from(path),
                reason: "must not be empty",
            }
        );
        ensure!(
            !path.starts_with('/'),
            InvalidContextPinPathSnafu {
                path: Box::<str>::from(path),
                reason: "must be relative",
            }
        );
        ensure!(
            !path.as_bytes().contains(&0),
            InvalidContextPinPathSnafu {
                path: Box::<str>::from(path),
                reason: "must not contain NUL",
            }
        );
        let components = path.split('/').collect::<Vec<_>>();
        for component in &components {
            ensure!(
                !component.is_empty(),
                InvalidContextPinPathSnafu {
                    path: Box::<str>::from(path),
                    reason: "must not contain empty path components",
                }
            );
            ensure!(
                *component != "." && *component != "..",
                InvalidContextPinPathSnafu {
                    path: Box::<str>::from(path),
                    reason: "must not contain relative path components",
                }
            );
        }
        Ok(components)
    }

    fn resolve_pinned_blob(&self, root: ContextObjectId, path: &str) -> Result<PinnedContextBlob> {
        let components = Self::pin_path_components(path)?;
        let mut tree = root;
        for (index, component) in components.iter().enumerate() {
            let tree_object = self.read_tree(tree)?;
            let entry = tree_object
                .entries()
                .iter()
                .find(|entry| entry.name() == component.as_bytes())
                .context(ContextPinPathNotFoundSnafu {
                    path: Box::<str>::from(path),
                })?;
            if index + 1 != components.len() {
                if entry.kind() != ContextTreeEntryKind::Tree {
                    return ContextPinPathNotBlobSnafu {
                        path: Box::<str>::from(path),
                        actual: Self::tree_entry_kind_name(entry.kind()),
                    }
                    .fail();
                }
                tree = entry.object();
                continue;
            }
            if entry.kind() != ContextTreeEntryKind::Blob {
                return ContextPinPathNotBlobSnafu {
                    path: Box::<str>::from(path),
                    actual: Self::tree_entry_kind_name(entry.kind()),
                }
                .fail();
            }
            let object = self.read_object(entry.object())?;
            if object.kind() != ContextObjectKind::Blob {
                return ContextPinPathNotBlobSnafu {
                    path: Box::<str>::from(path),
                    actual: Self::object_kind_name(object.kind()),
                }
                .fail();
            }
            return Ok(PinnedContextBlob {
                path: path.to_owned(),
                id: object.id(),
                bytes: object.into_bytes(),
            });
        }
        unreachable!("validated context pin paths contain at least one component")
    }

    const fn tree_entry_kind_name(kind: ContextTreeEntryKind) -> &'static str {
        match kind {
            ContextTreeEntryKind::Blob => "blob",
            ContextTreeEntryKind::Tree => "tree",
            ContextTreeEntryKind::Commit => "commit",
        }
    }

    const fn object_kind_name(kind: ContextObjectKind) -> &'static str {
        match kind {
            ContextObjectKind::Blob => "blob",
            ContextObjectKind::Tree => "tree",
            ContextObjectKind::Commit => "commit",
        }
    }
}
