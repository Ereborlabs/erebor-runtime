use std::collections::HashSet;

use gix::{hash::ObjectId, objs::tree::EntryKind};
use snafu::{ensure, ResultExt};

use super::{ContextObjectId, ContextObjectKind, ContextRepository};
use crate::error::{
    BoxedError, DuplicateTreeEditPathSnafu, EditTreeSnafu, InvalidTreeEditSnafu, Result,
};

/// A blob replacement at one path in a complete Git tree snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEdit {
    path: String,
    bytes: Vec<u8>,
}

impl TreeEdit {
    pub fn blob(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let path = path.into();
        Self::validate_path(&path)?;
        Ok(Self {
            path,
            bytes: bytes.into(),
        })
    }

    fn validate_path(path: &str) -> Result<()> {
        ensure!(
            !path.is_empty(),
            InvalidTreeEditSnafu {
                path,
                reason: "must not be empty",
            }
        );
        ensure!(
            !path.starts_with('/'),
            InvalidTreeEditSnafu {
                path,
                reason: "must be relative",
            }
        );
        ensure!(
            !path.as_bytes().contains(&0),
            InvalidTreeEditSnafu {
                path,
                reason: "must not contain NUL",
            }
        );
        for component in path.split('/') {
            ensure!(
                !component.is_empty(),
                InvalidTreeEditSnafu {
                    path,
                    reason: "must not contain empty path components",
                }
            );
            ensure!(
                component != "." && component != "..",
                InvalidTreeEditSnafu {
                    path,
                    reason: "must not contain relative path components",
                }
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Caller-supplied blob edits used to construct a complete Git tree snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    edits: Vec<TreeEdit>,
}

impl Snapshot {
    pub fn new(edits: Vec<TreeEdit>) -> Result<Self> {
        let mut paths = HashSet::with_capacity(edits.len());
        for edit in &edits {
            if !paths.insert(edit.path.clone()) {
                return DuplicateTreeEditPathSnafu {
                    path: edit.path.clone(),
                }
                .fail();
            }
        }
        Ok(Self { edits })
    }

    #[must_use]
    pub fn edits(&self) -> &[TreeEdit] {
        &self.edits
    }
}

impl ContextRepository {
    /// Materialize a complete caller-selected Git root tree from an empty base.
    pub fn create_tree(&self, snapshot: Snapshot) -> Result<ContextObjectId> {
        self.write_snapshot_tree(None, &snapshot)
    }

    /// Construct a replacement tree from the exact tree of one existing
    /// commit. This keeps callers out of raw Git tree editing while allowing a
    /// checked parent-side fact or merge result to retain all prior content.
    pub fn create_tree_from_commit(
        &self,
        base_commit: ContextObjectId,
        snapshot: Snapshot,
    ) -> Result<ContextObjectId> {
        self.require_object_kind(base_commit, ContextObjectKind::Commit)?;
        self.write_snapshot_tree(Some(self.commit_tree_id(base_commit)?), &snapshot)
    }

    pub(super) fn write_snapshot_tree(
        &self,
        base_tree: Option<ContextObjectId>,
        snapshot: &Snapshot,
    ) -> Result<ContextObjectId> {
        let base = match base_tree {
            Some(tree) => {
                self.require_object_kind(tree, ContextObjectKind::Tree)?;
                tree.0
            }
            None => ObjectId::empty_tree(gix::hash::Kind::Sha256),
        };
        let repository = self.repository();
        let mut editor = repository
            .edit_tree(base)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(EditTreeSnafu)?;
        for edit in snapshot.edits() {
            let blob = self.write_blob(edit.bytes())?.0;
            editor
                .upsert(edit.path(), EntryKind::Blob, blob)
                .map_err(|source| Box::new(source) as BoxedError)
                .context(EditTreeSnafu)?;
        }
        let tree = editor
            .write()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(EditTreeSnafu)?
            .detach();
        crate::write_boundary::reach(crate::write_boundary::WriteBoundary::Tree);
        ContextObjectId::from_object_id(tree)
    }
}
