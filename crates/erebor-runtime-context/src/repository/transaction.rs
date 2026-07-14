use snafu::{ensure, ResultExt};

use super::{
    refs::DirectScopeRefUpdate, ContextObjectId, ContextObjectKind, ContextRepository, ScopeRef,
};
use crate::error::{
    BoxedError, InvalidScopeRefSnafu, Result, ScopeAlreadyExistsSnafu, StaleScopeHeadSnafu,
    UpdateScopeRefSnafu,
};

/// How a child scope starts from its causal commit at a fork boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkTarget {
    ReuseCausalCommit,
    SelectedTree {
        tree: ContextObjectId,
        message: String,
    },
}

impl ForkTarget {
    #[must_use]
    pub const fn reuse_causal_commit() -> Self {
        Self::ReuseCausalCommit
    }

    #[must_use]
    pub fn selected_tree(tree: ContextObjectId, message: impl Into<String>) -> Self {
        Self::SelectedTree {
            tree,
            message: message.into(),
        }
    }
}

/// An optional one-parent update included in the same checked fork transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkParentAppend {
    scope: ScopeRef,
    expected_head: ContextObjectId,
    tree: ContextObjectId,
    message: String,
}

impl ForkParentAppend {
    #[must_use]
    pub fn new(
        scope: ScopeRef,
        expected_head: ContextObjectId,
        tree: ContextObjectId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            expected_head,
            tree,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }

    #[must_use]
    pub const fn expected_head(&self) -> ContextObjectId {
        self.expected_head
    }
}

/// The exact commits reached by a successful fork call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkResult {
    child: ContextObjectId,
    parent: Option<ContextObjectId>,
}

impl ForkResult {
    #[must_use]
    pub const fn child(&self) -> ContextObjectId {
        self.child
    }

    #[must_use]
    pub const fn parent(&self) -> Option<ContextObjectId> {
        self.parent
    }
}

impl ContextRepository {
    pub fn fork_scope(
        &self,
        causal: ContextObjectId,
        child: ScopeRef,
        target: ForkTarget,
        parent_append: Option<ForkParentAppend>,
    ) -> Result<ForkResult> {
        self.require_object_kind(causal, ContextObjectKind::Commit)?;
        self.ensure_scope_can_be_created(&child)?;
        if let Some(parent_append) = &parent_append {
            ensure!(
                parent_append.scope != child,
                InvalidScopeRefSnafu {
                    component: "fork scope",
                    value: child.to_string(),
                    reason: "child and parent scope refs must differ".to_owned(),
                }
            );
            self.require_expected_scope_head(&parent_append.scope, parent_append.expected_head)?;
            self.require_object_kind(parent_append.tree, ContextObjectKind::Tree)?;
        }

        let child_commit = self.fork_child_commit(causal, target)?;
        let parent_commit = parent_append
            .as_ref()
            .map(|parent_append| {
                self.write_commit(
                    parent_append.tree,
                    &[parent_append.expected_head],
                    &parent_append.message,
                )
            })
            .transpose()?;
        let mut updates = vec![DirectScopeRefUpdate::create(child.clone(), child_commit)];
        if let (Some(parent_append), Some(parent_commit)) = (&parent_append, parent_commit) {
            updates.push(DirectScopeRefUpdate::compare_and_swap(
                parent_append.scope.clone(),
                parent_append.expected_head,
                parent_commit,
            ));
        }
        match self.edit_direct_scope_refs(updates) {
            Ok(()) => Ok(ForkResult {
                child: child_commit,
                parent: parent_commit,
            }),
            Err(source) => {
                self.classify_fork_transaction_failure(&child, parent_append.as_ref(), source)
            }
        }
    }

    pub fn append_pinned_merge(
        &self,
        receiver: ScopeRef,
        expected_receiver: ContextObjectId,
        source: ContextObjectId,
        result_tree: ContextObjectId,
        message: impl AsRef<str>,
    ) -> Result<ContextObjectId> {
        self.require_expected_scope_head(&receiver, expected_receiver)?;
        self.require_object_kind(source, ContextObjectKind::Commit)?;
        self.require_object_kind(result_tree, ContextObjectKind::Tree)?;
        let merge =
            self.write_commit(result_tree, &[expected_receiver, source], message.as_ref())?;
        self.compare_and_swap_direct_scope_ref(&receiver, expected_receiver, merge)?;
        Ok(merge)
    }

    fn fork_child_commit(
        &self,
        causal: ContextObjectId,
        target: ForkTarget,
    ) -> Result<ContextObjectId> {
        match target {
            ForkTarget::ReuseCausalCommit => Ok(causal),
            ForkTarget::SelectedTree { tree, message } => {
                self.require_object_kind(tree, ContextObjectKind::Tree)?;
                if tree == self.commit_tree_id(causal)? {
                    Ok(causal)
                } else {
                    self.write_commit(tree, &[causal], &message)
                }
            }
        }
    }

    fn require_expected_scope_head(
        &self,
        scope: &ScopeRef,
        expected: ContextObjectId,
    ) -> Result<()> {
        let actual = self.scope_head(scope)?;
        if actual != expected {
            return StaleScopeHeadSnafu {
                scope: scope.to_string(),
                expected: expected.to_string(),
                actual: actual.to_string(),
            }
            .fail();
        }
        Ok(())
    }

    fn classify_fork_transaction_failure(
        &self,
        child: &ScopeRef,
        parent_append: Option<&ForkParentAppend>,
        source: BoxedError,
    ) -> Result<ForkResult> {
        if let Some(parent_append) = parent_append {
            if let Ok(actual) = self.scope_head(&parent_append.scope) {
                if actual != parent_append.expected_head {
                    return StaleScopeHeadSnafu {
                        scope: parent_append.scope.to_string(),
                        expected: parent_append.expected_head.to_string(),
                        actual: actual.to_string(),
                    }
                    .fail();
                }
            }
        }
        if self.scope_head(child).is_ok() {
            return ScopeAlreadyExistsSnafu {
                scope: child.to_string(),
            }
            .fail();
        }
        Err(source).context(UpdateScopeRefSnafu {
            scope: child.to_string(),
        })
    }
}
