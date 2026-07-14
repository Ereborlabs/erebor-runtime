use std::fmt;

use gix::refs::{
    transaction::{Change, LogChange, PreviousValue, RefEdit},
    Target,
};
use snafu::{ensure, OptionExt, ResultExt};

use super::{ContextObjectId, ContextObjectKind, ContextRepository, Snapshot};
use crate::error::{
    BoxedError, CommitMetadataSourceSnafu, InvalidScopeRefSnafu, ReadScopeRefSnafu,
    ReservedScopeNameSnafu, Result, ScopeAlreadyExistsSnafu, ScopeNotFoundSnafu,
    ScopeRefPrefixConflictSnafu, ScopeTargetNotCommitSnafu, SelectedTreeUnchangedSnafu,
    StaleScopeHeadSnafu, SymbolicScopeRefSnafu, UpdateScopeRefSnafu,
};

const SCOPE_PREFIX: &str = "refs/scopes";

pub(super) struct DirectScopeRefUpdate {
    scope: ScopeRef,
    expected: PreviousValue,
    target: ContextObjectId,
}

impl DirectScopeRefUpdate {
    pub(super) fn create(scope: ScopeRef, target: ContextObjectId) -> Self {
        Self {
            scope,
            expected: PreviousValue::MustNotExist,
            target,
        }
    }

    pub(super) fn compare_and_swap(
        scope: ScopeRef,
        expected: ContextObjectId,
        target: ContextObjectId,
    ) -> Self {
        Self {
            scope,
            expected: PreviousValue::MustExistAndMatch(Target::Object(expected.0)),
            target,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopeKind {
    Root,
    Named,
    Unknown,
}

/// A validated direct-ref name inside Erebor's per-session scope namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRef {
    session_id: String,
    full_name: String,
    kind: ScopeKind,
}

impl ScopeRef {
    pub fn root(session_id: impl Into<String>) -> Result<Self> {
        Self::for_leaf(session_id.into(), "root", ScopeKind::Root)
    }

    pub fn unknown(session_id: impl Into<String>) -> Result<Self> {
        Self::for_leaf(session_id.into(), "unknown", ScopeKind::Unknown)
    }

    pub fn scope(session_id: impl Into<String>, scope_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        let scope_id = scope_id.into();
        if matches!(scope_id.as_str(), "root" | "unknown") {
            return ReservedScopeNameSnafu { scope_id }.fail();
        }
        Self::for_leaf(session_id, &format!("scope/{scope_id}"), ScopeKind::Named)
    }

    fn for_leaf(session_id: String, leaf: &str, kind: ScopeKind) -> Result<Self> {
        ensure!(
            !session_id.is_empty() && !session_id.contains('/'),
            InvalidScopeRefSnafu {
                component: "session id",
                value: session_id,
                reason: "must be one non-empty Git ref component".to_owned(),
            }
        );
        let full_name = format!("{SCOPE_PREFIX}/{session_id}/{leaf}");
        if gix::refs::FullName::try_from(full_name.as_str()).is_err() {
            return InvalidScopeRefSnafu {
                component: "scope ref",
                value: full_name,
                reason: "is not a valid Git ref name".to_owned(),
            }
            .fail();
        }
        Ok(Self {
            session_id,
            full_name,
            kind,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full_name
    }

    fn git_name(&self) -> Result<gix::refs::FullName> {
        gix::refs::FullName::try_from(self.full_name.as_str()).map_err(|_| {
            InvalidScopeRefSnafu {
                component: "scope ref",
                value: self.full_name.clone(),
                reason: "is not a valid Git ref name".to_owned(),
            }
            .build()
        })
    }

    fn is_root(&self) -> bool {
        self.kind == ScopeKind::Root
    }

    fn ancestors(&self) -> Vec<String> {
        let named_prefix = format!("{SCOPE_PREFIX}/{}/scope/", self.session_id);
        self.full_name
            .strip_prefix(&named_prefix)
            .map_or_else(Vec::new, |suffix| {
                suffix
                    .match_indices('/')
                    .map(|(index, _)| format!("{named_prefix}{}", &suffix[..index]))
                    .collect()
            })
    }
}

impl fmt::Display for ScopeRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.full_name)
    }
}

/// The causal starting point for a newly created non-root scope ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeStart {
    ExistingCommit(ContextObjectId),
    Snapshot {
        parent: ContextObjectId,
        snapshot: Snapshot,
        message: String,
    },
}

impl ScopeStart {
    #[must_use]
    pub const fn existing_commit(commit: ContextObjectId) -> Self {
        Self::ExistingCommit(commit)
    }

    #[must_use]
    pub fn snapshot(
        parent: ContextObjectId,
        snapshot: Snapshot,
        message: impl Into<String>,
    ) -> Self {
        Self::Snapshot {
            parent,
            snapshot,
            message: message.into(),
        }
    }
}

impl ContextRepository {
    pub fn initialize_root(
        &self,
        session_id: impl Into<String>,
        snapshot: Snapshot,
        message: impl AsRef<str>,
    ) -> Result<ContextObjectId> {
        let root = ScopeRef::root(session_id)?;
        self.ensure_scope_can_be_created(&root)?;
        let tree = self.write_snapshot_tree(None, &snapshot)?;
        let commit = self.write_commit(tree, &[], message.as_ref())?;
        self.create_direct_scope_ref(&root, commit)?;
        Ok(commit)
    }

    pub fn create_scope(&self, scope: ScopeRef, start: ScopeStart) -> Result<ContextObjectId> {
        ensure!(
            !scope.is_root(),
            InvalidScopeRefSnafu {
                component: "scope ref",
                value: scope.to_string(),
                reason: "the root ref can only be created by initialize_root".to_owned(),
            }
        );
        self.ensure_scope_can_be_created(&scope)?;
        let commit = match start {
            ScopeStart::ExistingCommit(commit) => {
                self.require_object_kind(commit, ContextObjectKind::Commit)?;
                commit
            }
            ScopeStart::Snapshot {
                parent,
                snapshot,
                message,
            } => {
                let parent_tree = self.commit_tree_id(parent)?;
                let tree = self.write_snapshot_tree(Some(parent_tree), &snapshot)?;
                if tree == parent_tree {
                    return SelectedTreeUnchangedSnafu {
                        parent: parent.to_string(),
                    }
                    .fail();
                }
                self.write_commit(tree, &[parent], &message)?
            }
        };
        self.create_direct_scope_ref(&scope, commit)?;
        Ok(commit)
    }

    pub fn append_snapshot(
        &self,
        scope: ScopeRef,
        expected_head: ContextObjectId,
        snapshot: Snapshot,
        message: impl AsRef<str>,
    ) -> Result<ContextObjectId> {
        let actual_head = self.scope_head(&scope)?;
        if actual_head != expected_head {
            return StaleScopeHeadSnafu {
                scope: scope.to_string(),
                expected: expected_head.to_string(),
                actual: actual_head.to_string(),
            }
            .fail();
        }
        let tree =
            self.write_snapshot_tree(Some(self.commit_tree_id(expected_head)?), &snapshot)?;
        let commit = self.write_commit(tree, &[expected_head], message.as_ref())?;
        self.compare_and_swap_direct_scope_ref(&scope, expected_head, commit)?;
        Ok(commit)
    }

    pub fn scope_head(&self, scope: &ScopeRef) -> Result<ContextObjectId> {
        let repository = self.repository();
        let reference = repository
            .try_find_reference(scope.as_str())
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: scope.to_string(),
            })?
            .context(ScopeNotFoundSnafu {
                scope: scope.to_string(),
            })?;
        let target = reference
            .try_id()
            .map(|id| id.detach())
            .context(SymbolicScopeRefSnafu {
                scope: scope.to_string(),
            })?;
        let target = ContextObjectId::from_object_id(target)?;
        let actual = self.read_object(target)?.kind();
        if actual != ContextObjectKind::Commit {
            return ScopeTargetNotCommitSnafu {
                scope: scope.to_string(),
                target: target.to_string(),
                actual: actual.to_string(),
            }
            .fail();
        }
        Ok(target)
    }

    pub(super) fn ensure_scope_can_be_created(&self, scope: &ScopeRef) -> Result<()> {
        let repository = self.repository();
        if repository
            .try_find_reference(scope.as_str())
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: scope.to_string(),
            })?
            .is_some()
        {
            self.scope_head(scope)?;
            return ScopeAlreadyExistsSnafu {
                scope: scope.to_string(),
            }
            .fail();
        }
        for ancestor in scope.ancestors() {
            if repository
                .try_find_reference(ancestor.as_str())
                .map_err(|source| Box::new(source) as BoxedError)
                .context(ReadScopeRefSnafu {
                    scope: scope.to_string(),
                })?
                .is_some()
            {
                return ScopeRefPrefixConflictSnafu {
                    scope: scope.to_string(),
                    existing: ancestor,
                }
                .fail();
            }
        }
        let descendant_prefix = format!("{}/", scope.as_str());
        let reference_platform = repository
            .references()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: scope.to_string(),
            })?;
        let references = reference_platform
            .all()
            .map_err(|source| Box::new(source) as BoxedError)
            .context(ReadScopeRefSnafu {
                scope: scope.to_string(),
            })?;
        for reference in references {
            let reference = reference.context(ReadScopeRefSnafu {
                scope: scope.to_string(),
            })?;
            let name = reference.name().to_string();
            if name.starts_with(&descendant_prefix) {
                return ScopeRefPrefixConflictSnafu {
                    scope: scope.to_string(),
                    existing: name,
                }
                .fail();
            }
        }
        Ok(())
    }

    fn create_direct_scope_ref(&self, scope: &ScopeRef, commit: ContextObjectId) -> Result<()> {
        match self.edit_direct_scope_refs([DirectScopeRefUpdate::create(scope.clone(), commit)]) {
            Ok(()) => Ok(()),
            Err(source) if self.scope_head(scope).is_ok() => ScopeAlreadyExistsSnafu {
                scope: scope.to_string(),
            }
            .fail(),
            Err(source) => Err(source).context(UpdateScopeRefSnafu {
                scope: scope.to_string(),
            }),
        }
    }

    pub(super) fn compare_and_swap_direct_scope_ref(
        &self,
        scope: &ScopeRef,
        expected: ContextObjectId,
        commit: ContextObjectId,
    ) -> Result<()> {
        match self.edit_direct_scope_ref(scope, expected, commit) {
            Ok(()) => Ok(()),
            Err(source) => match self.scope_head(scope) {
                Ok(actual) if actual != expected => StaleScopeHeadSnafu {
                    scope: scope.to_string(),
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                }
                .fail(),
                Ok(_) | Err(_) => Err(source).context(UpdateScopeRefSnafu {
                    scope: scope.to_string(),
                }),
            },
        }
    }

    fn edit_direct_scope_ref(
        &self,
        scope: &ScopeRef,
        expected: ContextObjectId,
        commit: ContextObjectId,
    ) -> std::result::Result<(), BoxedError> {
        self.edit_direct_scope_refs([DirectScopeRefUpdate::compare_and_swap(
            scope.clone(),
            expected,
            commit,
        )])
    }

    pub(super) fn edit_direct_scope_refs(
        &self,
        updates: impl IntoIterator<Item = DirectScopeRefUpdate>,
    ) -> std::result::Result<(), BoxedError> {
        let metadata = self
            .metadata_source
            .metadata()
            .context(CommitMetadataSourceSnafu)
            .map_err(|error| Box::new(error) as BoxedError)?;
        let committer = Self::git_signature(metadata.committer());
        let mut time = gix::date::parse::TimeBuf::default();
        let repository = self.repository();
        let edits = updates
            .into_iter()
            .map(|update| {
                Ok(RefEdit {
                    change: Change::Update {
                        log: LogChange::default(),
                        expected: update.expected,
                        new: Target::Object(update.target.0),
                    },
                    name: update
                        .scope
                        .git_name()
                        .map_err(|error| Box::new(error) as BoxedError)?,
                    deref: false,
                })
            })
            .collect::<std::result::Result<Vec<_>, BoxedError>>()?;
        repository
            .edit_references_as(edits, Some(committer.to_ref(&mut time)))
            .map(|_| ())
            .map_err(|source| Box::new(source) as BoxedError)
    }
}
