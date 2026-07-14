use std::{fmt, str::FromStr};

use gix::{
    actor,
    hash::{Kind as HashKind, ObjectId},
    objs::{self, tree::EntryKind},
};
use snafu::{OptionExt, ResultExt};

use super::{CommitSignature, ContextRepository};
use crate::error::{
    BoxedError, CommitMetadataSourceSnafu, EditTreeSnafu, InvalidObjectIdSnafu,
    InvalidParentCountSnafu, InvalidTreeEntryKindSnafu, ObjectNotFoundSnafu, ReadObjectSnafu,
    Result, UnsupportedObjectIdFormatSnafu, UnsupportedObjectKindSnafu, WriteObjectSnafu,
    WrongObjectKindSnafu,
};

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextObjectId(pub(in crate::repository) ObjectId);

impl ContextObjectId {
    pub(in crate::repository) fn from_object_id(id: ObjectId) -> Result<Self> {
        if id.kind() != HashKind::Sha256 {
            return UnsupportedObjectIdFormatSnafu {
                id: id.to_string(),
                actual: format!("{:?}", id.kind()).to_lowercase(),
            }
            .fail();
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl FromStr for ContextObjectId {
    type Err = crate::ContextRepositoryError;

    fn from_str(value: &str) -> Result<Self> {
        let id = ObjectId::from_hex(value.as_bytes())
            .map_err(|source| Box::new(source) as BoxedError)
            .context(InvalidObjectIdSnafu { value })?;
        Self::from_object_id(id)
    }
}

impl fmt::Debug for ContextObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for ContextObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextObjectKind {
    Blob,
    Tree,
    Commit,
}

impl ContextObjectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
        }
    }

    fn from_git(kind: objs::Kind, id: ContextObjectId) -> Result<Self> {
        match kind {
            objs::Kind::Blob => Ok(Self::Blob),
            objs::Kind::Tree => Ok(Self::Tree),
            objs::Kind::Commit => Ok(Self::Commit),
            objs::Kind::Tag => UnsupportedObjectKindSnafu {
                id: id.to_string(),
                actual: "tag",
            }
            .fail(),
        }
    }
}

impl fmt::Display for ContextObjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextObject {
    id: ContextObjectId,
    kind: ContextObjectKind,
    bytes: Vec<u8>,
}

impl ContextObject {
    #[must_use]
    pub const fn id(&self) -> ContextObjectId {
        self.id
    }

    #[must_use]
    pub const fn kind(&self) -> ContextObjectKind {
        self.kind
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl ContextRepository {
    pub fn read_object(&self, id: ContextObjectId) -> Result<ContextObject> {
        let repository = self.repository();
        let object = repository
            .try_find_object(id.0)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadObjectSnafu { id: id.to_string() })?
            .context(ObjectNotFoundSnafu { id: id.to_string() })?;
        let kind = ContextObjectKind::from_git(object.kind, id)?;
        match kind {
            ContextObjectKind::Blob => {}
            ContextObjectKind::Tree => {
                objs::TreeRef::from_bytes(&object.data, HashKind::Sha256)
                    .map_err(|source| Box::new(source) as BoxedError)
                    .context(ReadObjectSnafu { id: id.to_string() })?;
            }
            ContextObjectKind::Commit => {
                objs::CommitRef::from_bytes(&object.data, HashKind::Sha256)
                    .map_err(|source| Box::new(source) as BoxedError)
                    .context(ReadObjectSnafu { id: id.to_string() })?;
            }
        }
        let object = object.detach();
        Ok(ContextObject {
            id,
            kind,
            bytes: object.data,
        })
    }

    pub(super) fn write_blob(&self, bytes: &[u8]) -> Result<ContextObjectId> {
        let repository = self.repository();
        let id = repository
            .write_blob(bytes)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(WriteObjectSnafu { kind: "blob" })?
            .detach();
        crate::write_boundary::reach(crate::write_boundary::WriteBoundary::Blob);
        ContextObjectId::from_object_id(id)
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "used by the crate-local low-level Git object tests"
        )
    )]
    pub(super) fn write_tree_entry(
        &self,
        base_tree: Option<ContextObjectId>,
        path: &str,
        kind: ContextObjectKind,
        id: ContextObjectId,
    ) -> Result<ContextObjectId> {
        let git_kind = match kind {
            ContextObjectKind::Blob => EntryKind::Blob,
            ContextObjectKind::Tree => EntryKind::Tree,
            ContextObjectKind::Commit => {
                return InvalidTreeEntryKindSnafu {
                    kind: ContextObjectKind::Commit.as_str(),
                }
                .fail();
            }
        };
        self.require_object_kind(id, kind)?;
        let repository = self.repository();
        let base = match base_tree {
            Some(base) => {
                self.require_object_kind(base, ContextObjectKind::Tree)?;
                base.0
            }
            None => ObjectId::empty_tree(HashKind::Sha256),
        };
        let mut editor = repository
            .edit_tree(base)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(EditTreeSnafu)?;
        editor
            .upsert(path, git_kind, id.0)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(EditTreeSnafu)?;
        let tree = editor
            .write()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(EditTreeSnafu)?
            .detach();
        ContextObjectId::from_object_id(tree)
    }

    pub(super) fn write_commit(
        &self,
        tree: ContextObjectId,
        parents: &[ContextObjectId],
        message: &str,
    ) -> Result<ContextObjectId> {
        if parents.len() > 2 {
            return InvalidParentCountSnafu {
                count: parents.len(),
            }
            .fail();
        }
        self.require_object_kind(tree, ContextObjectKind::Tree)?;
        for parent in parents {
            self.require_object_kind(*parent, ContextObjectKind::Commit)?;
        }
        let metadata = self
            .metadata_source
            .metadata()
            .context(CommitMetadataSourceSnafu)?;
        let author = Self::git_signature(metadata.author());
        let committer = Self::git_signature(metadata.committer());
        let mut author_time = gix::date::parse::TimeBuf::default();
        let mut committer_time = gix::date::parse::TimeBuf::default();
        let repository = self.repository();
        let commit = repository
            .new_commit_as(
                committer.to_ref(&mut committer_time),
                author.to_ref(&mut author_time),
                message,
                tree.0,
                parents.iter().map(|parent| parent.0),
            )
            .map_err(|source| Box::new(source) as BoxedError)
            .context(WriteObjectSnafu { kind: "commit" })?;
        crate::write_boundary::reach(crate::write_boundary::WriteBoundary::Commit);
        ContextObjectId::from_object_id(commit.id)
    }

    pub(super) fn require_object_kind(
        &self,
        id: ContextObjectId,
        expected: ContextObjectKind,
    ) -> Result<()> {
        let actual = self.read_object(id)?.kind();
        if actual != expected {
            return WrongObjectKindSnafu {
                id: id.to_string(),
                expected: expected.as_str(),
                actual: actual.as_str(),
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn commit_tree_id(&self, commit: ContextObjectId) -> Result<ContextObjectId> {
        self.require_object_kind(commit, ContextObjectKind::Commit)?;
        let repository = self.repository();
        let tree = repository
            .find_commit(commit.0)
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadObjectSnafu {
                id: commit.to_string(),
            })?
            .tree_id()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadObjectSnafu {
                id: commit.to_string(),
            })?
            .detach();
        ContextObjectId::from_object_id(tree)
    }

    pub(super) fn git_signature(signature: &CommitSignature) -> actor::Signature {
        actor::Signature {
            name: signature.name().into(),
            email: signature.email().into(),
            time: gix::date::Time::new(
                signature.time().seconds(),
                signature.time().offset_seconds(),
            ),
        }
    }
}
