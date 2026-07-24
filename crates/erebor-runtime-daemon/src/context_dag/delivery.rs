use std::collections::HashSet;

use erebor_runtime_context::{ContextObjectId, ContextPin, ScopeRef, Snapshot, TreeEdit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::InvalidRequestSnafu, Result};

use super::{
    ContextChildEdge, ContextDagCoordinator, ContextExecutionBinding, CONTEXT_DAG_METADATA_PREFIX,
};

const DELIVERY_SCHEMA_VERSION: u32 = 1;
const MAX_DELIVERY_BYTES: usize = 32 * 1024;
const DELIVERY_DIRECTORY: &str = "deliveries";
const RECEIPT_DIRECTORY: &str = "receipts";
const REJECTION_DIRECTORY: &str = "rejections";
const RESULT_DIRECTORY: &str = "agents/codex/received-deliveries";

/// The bounded content that an authenticated child asks the daemon to retain.
/// The child never selects a parent scope, merge source, or receipt path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextDeliveryPublication {
    child_scope: ScopeRef,
    sequence: u64,
    kind: ContextDeliveryKind,
    mode: ContextDeliveryMode,
    selected_bytes: Vec<u8>,
}

impl ContextDeliveryPublication {
    pub(crate) fn new(
        child_scope: ScopeRef,
        sequence: u64,
        kind: ContextDeliveryKind,
        mode: ContextDeliveryMode,
        selected_bytes: Vec<u8>,
    ) -> Result<Self> {
        if sequence == 0 {
            return InvalidRequestSnafu {
                reason: String::from("context delivery sequence must start at one"),
            }
            .fail();
        }
        if selected_bytes.is_empty() || selected_bytes.len() > MAX_DELIVERY_BYTES {
            return InvalidRequestSnafu {
                reason: format!(
                    "context delivery must contain between one and {MAX_DELIVERY_BYTES} bytes"
                ),
            }
            .fail();
        }
        Ok(Self {
            child_scope,
            sequence,
            kind,
            mode,
            selected_bytes,
        })
    }

    pub(crate) const fn child_scope(&self) -> &ScopeRef {
        &self.child_scope
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextDeliveryKind {
    Message,
    Result,
    Failure,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ContextDeliveryMode {
    Queue,
    FollowUp,
}

/// One immutable child-owned delivery, read only from its pinned child commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ContextDelivery {
    schema_version: u32,
    parent_context: ContextPin,
    receiver_scope: String,
    execution_binding: ContextExecutionBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_identity: Option<String>,
    source_context: ContextPin,
    sequence: u64,
    kind: ContextDeliveryKind,
    mode: ContextDeliveryMode,
    selected_bytes: Vec<u8>,
}

/// One derived direct-parent inbox record. The delivery itself remains in the
/// child scope at `delivery_commit` until the parent explicitly decides it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextDeliveryRecord {
    receiver_scope: ScopeRef,
    source_scope: ScopeRef,
    delivery_path: String,
    delivery_commit: ContextObjectId,
}

impl ContextDeliveryRecord {
    pub(crate) const fn receiver_scope(&self) -> &ScopeRef {
        &self.receiver_scope
    }

    pub(crate) const fn source_scope(&self) -> &ScopeRef {
        &self.source_scope
    }

    pub(crate) const fn delivery_commit(&self) -> ContextObjectId {
        self.delivery_commit
    }

    pub(crate) fn delivery_path(&self) -> &str {
        &self.delivery_path
    }
}

/// Stable result of a parent-owned receive or reject. Its deterministic receipt
/// makes retry and daemon restart decisions observable without a mutable
/// decision ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextDeliveryReceipt {
    parent_head: ContextObjectId,
    receipt_path: String,
    rejected: bool,
}

impl ContextDeliveryReceipt {
    pub(crate) const fn parent_head(&self) -> ContextObjectId {
        self.parent_head
    }

    pub(crate) fn receipt_path(&self) -> &str {
        &self.receipt_path
    }

    pub(crate) const fn rejected(&self) -> bool {
        self.rejected
    }
}

#[derive(Serialize)]
struct DeliveryReceipt<'a> {
    schema_version: u32,
    action: &'a str,
    child_scope: String,
    delivery_path: &'a str,
    delivery_commit: String,
    source_context: &'a ContextPin,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

#[derive(Deserialize)]
struct RecordedDeliveryReceipt {
    schema_version: u32,
    child_scope: String,
    delivery_path: String,
}

impl ContextDagCoordinator {
    /// Append one deterministic delivery blob to the authenticated child's own
    /// scope. It intentionally cannot write a parent ref.
    pub(crate) fn publish_delivery(
        &self,
        publication: ContextDeliveryPublication,
    ) -> Result<ContextDeliveryRecord> {
        let _guard = self.lock_mutations()?;
        self.ensure_contained_child(publication.child_scope())?;
        let child_head = self.scope_head(publication.child_scope(), "delivery child")?;
        let path = Self::delivery_path(publication.sequence);
        let sequence = publication.sequence;
        let child_scope = publication.child_scope().clone();
        let edge = self.direct_edge(publication.child_scope())?;
        let delivery = self.delivery_from_publication(&edge, publication, child_head)?;
        if let Some(existing) = self.read_delivery(child_head, &path)? {
            if existing.sequence == delivery.sequence
                && existing.kind == delivery.kind
                && existing.mode == delivery.mode
                && existing.selected_bytes == delivery.selected_bytes
                && existing.parent_context == delivery.parent_context
                && existing.execution_binding == delivery.execution_binding
                && existing.source_identity == delivery.source_identity
            {
                self.validate_delivery(&child_scope, child_head, &path, &existing)?;
                return Ok(ContextDeliveryRecord {
                    receiver_scope: existing
                        .parent_context
                        .scope()
                        .map_err(Self::invalid_context)?,
                    source_scope: child_scope,
                    delivery_path: path,
                    delivery_commit: child_head,
                });
            }
            return InvalidRequestSnafu {
                reason: String::from("context delivery sequence was already published differently"),
            }
            .fail();
        }
        if sequence > 1
            && self
                .read_delivery(child_head, &Self::delivery_path(sequence - 1))?
                .is_none()
        {
            return InvalidRequestSnafu {
                reason: String::from("context deliveries must be published in sequence order"),
            }
            .fail();
        }
        let bytes = serde_json::to_vec(&delivery).map_err(Self::invalid_json)?;
        let receiver_scope = delivery
            .parent_context
            .scope()
            .map_err(Self::invalid_context)?;
        let next_head = self
            .repository
            .append_snapshot(
                child_scope.clone(),
                child_head,
                Snapshot::new(vec![
                    TreeEdit::blob(path.clone(), bytes).map_err(Self::invalid_context)?
                ])
                .map_err(Self::invalid_context)?,
                "Publish child context delivery",
            )
            .map_err(Self::invalid_context)?;
        Ok(ContextDeliveryRecord {
            receiver_scope,
            source_scope: child_scope,
            delivery_path: path,
            delivery_commit: next_head,
        })
    }

    /// Derive the direct parent's inbox from direct child refs. Delivery blobs
    /// remain in child scope; parent history is not changed by this query.
    pub(crate) fn inbox(&self, parent_scope: &ScopeRef) -> Result<Vec<ContextDeliveryRecord>> {
        let _guard = self.lock_mutations()?;
        let parent_head = self.scope_head(parent_scope, "delivery parent")?;
        let mut items = Vec::new();
        for child_scope in self
            .repository
            .scope_refs()
            .map_err(Self::invalid_context)?
        {
            if child_scope == *parent_scope || self.direct_edge(&child_scope).is_err() {
                continue;
            }
            let edge = self.direct_edge(&child_scope)?;
            if edge.parent_context.scope().map_err(Self::invalid_context)? != *parent_scope {
                continue;
            }
            let child_head = self.scope_head(&child_scope, "delivery child")?;
            for (path, delivery) in self.deliveries_at(child_head)? {
                if self.decision_exists(parent_head, &child_scope, &path, child_head)? {
                    continue;
                }
                self.validate_delivery(&child_scope, child_head, &path, &delivery)?;
                items.push(ContextDeliveryRecord {
                    receiver_scope: parent_scope.clone(),
                    source_scope: child_scope.clone(),
                    delivery_path: path,
                    delivery_commit: child_head,
                });
            }
        }
        items.sort_by(|left, right| left.delivery_path.cmp(&right.delivery_path));
        Ok(items)
    }

    /// A parent client names its daemon session, never an arbitrary receiver
    /// scope. All scopes belonging to that session are queried and the later
    /// receive request re-derives the exact receiver from the delivery blob.
    pub(crate) fn inbox_for_session(
        &self,
        parent_session_id: &str,
    ) -> Result<Vec<ContextDeliveryRecord>> {
        let scopes = self
            .repository
            .scope_refs()
            .map_err(Self::invalid_context)?;
        let mut items = Vec::new();
        for scope in scopes
            .into_iter()
            .filter(|scope| scope.session_id() == parent_session_id)
        {
            items.extend(self.inbox(&scope)?);
        }
        items.sort_by(|left, right| {
            left.receiver_scope
                .as_str()
                .cmp(right.receiver_scope.as_str())
                .then_with(|| left.delivery_path.cmp(&right.delivery_path))
        });
        Ok(items)
    }

    /// The direct parent explicitly selects one delivery. The result tree uses
    /// only the current parent tree plus one receipt and selected adapter result;
    /// the child tree never becomes visible by wholesale copy.
    pub(crate) fn receive_delivery(
        &self,
        parent_scope: &ScopeRef,
        delivery_path: &str,
        delivery_commit: ContextObjectId,
        expected_parent_head: ContextObjectId,
    ) -> Result<ContextDeliveryReceipt> {
        self.decide_delivery(
            parent_scope,
            delivery_path,
            delivery_commit,
            expected_parent_head,
            None,
        )
    }

    pub(crate) fn delivery_receiver(
        &self,
        delivery_path: &str,
        delivery_commit: ContextObjectId,
    ) -> Result<ScopeRef> {
        let delivery = self
            .read_delivery(delivery_commit, delivery_path)?
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: String::from(
                        "requested child delivery is not present at its pinned commit",
                    ),
                }
                .build()
            })?;
        delivery
            .parent_context
            .scope()
            .map_err(Self::invalid_context)
    }

    pub(crate) fn reject_delivery(
        &self,
        parent_scope: &ScopeRef,
        delivery_path: &str,
        delivery_commit: ContextObjectId,
        expected_parent_head: ContextObjectId,
        reason: &str,
    ) -> Result<ContextDeliveryReceipt> {
        if reason.is_empty() || reason.len() > 512 || reason.contains('\0') {
            return InvalidRequestSnafu {
                reason: String::from(
                    "context delivery rejection reason must be non-empty, bounded, and NUL-free",
                ),
            }
            .fail();
        }
        self.decide_delivery(
            parent_scope,
            delivery_path,
            delivery_commit,
            expected_parent_head,
            Some(reason),
        )
    }

    fn decide_delivery(
        &self,
        parent_scope: &ScopeRef,
        delivery_path: &str,
        delivery_commit: ContextObjectId,
        expected_parent_head: ContextObjectId,
        rejection_reason: Option<&str>,
    ) -> Result<ContextDeliveryReceipt> {
        let _guard = self.lock_mutations()?;
        let delivery = self
            .read_delivery(delivery_commit, delivery_path)?
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: String::from(
                        "requested child delivery is not present at its pinned commit",
                    ),
                }
                .build()
            })?;
        let child_scope = delivery
            .source_context
            .scope()
            .map_err(Self::invalid_context)?;
        self.validate_delivery(&child_scope, delivery_commit, delivery_path, &delivery)?;
        let receiver = delivery
            .parent_context
            .scope()
            .map_err(Self::invalid_context)?;
        if receiver != *parent_scope {
            return InvalidRequestSnafu {
                reason: String::from("only the delivery's direct parent may receive or reject it"),
            }
            .fail();
        }
        let parent_head = self.scope_head(parent_scope, "delivery parent")?;
        let receipt_path = Self::decision_path(
            &child_scope,
            delivery_path,
            delivery_commit,
            rejection_reason.is_some(),
        );
        let opposite_path = Self::decision_path(
            &child_scope,
            delivery_path,
            delivery_commit,
            rejection_reason.is_none(),
        );
        if self
            .repository
            .read_commit_blob(parent_head, &receipt_path)
            .map_err(Self::invalid_context)?
            .is_some()
        {
            return Ok(ContextDeliveryReceipt {
                parent_head,
                receipt_path,
                rejected: rejection_reason.is_some(),
            });
        }
        if self
            .repository
            .read_commit_blob(parent_head, &opposite_path)
            .map_err(Self::invalid_context)?
            .is_some()
        {
            return InvalidRequestSnafu {
                reason: String::from("context delivery already has the opposite parent decision"),
            }
            .fail();
        }
        if parent_head != expected_parent_head {
            return InvalidRequestSnafu {
                reason: String::from("context delivery parent head changed before the decision"),
            }
            .fail();
        }
        if delivery.sequence > 1
            && !self.prior_delivery_is_decided(
                parent_head,
                &child_scope,
                &Self::delivery_path(delivery.sequence - 1),
            )?
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "a child delivery must be received or rejected after its prior sequence",
                ),
            }
            .fail();
        }
        let receipt = DeliveryReceipt {
            schema_version: DELIVERY_SCHEMA_VERSION,
            action: if rejection_reason.is_some() {
                "rejected"
            } else {
                "received"
            },
            child_scope: child_scope.to_string(),
            delivery_path,
            delivery_commit: delivery_commit.to_string(),
            source_context: &delivery.source_context,
            reason: rejection_reason,
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(Self::invalid_json)?;
        let receipt_edit =
            TreeEdit::blob(receipt_path.clone(), receipt_bytes).map_err(Self::invalid_context)?;
        let mut edits = vec![receipt_edit.clone()];
        if rejection_reason.is_none() {
            let result_path = Self::result_path(&child_scope, delivery_path, delivery_commit);
            edits.push(
                TreeEdit::blob(result_path, delivery.selected_bytes.clone())
                    .map_err(Self::invalid_context)?,
            );
        }
        let tree = self
            .repository
            .create_tree_from_commit(
                parent_head,
                Snapshot::new(edits).map_err(Self::invalid_context)?,
            )
            .map_err(Self::invalid_context)?;
        let next_head = if rejection_reason.is_some() {
            self.repository
                .append_snapshot(
                    parent_scope.clone(),
                    parent_head,
                    Snapshot::new(vec![receipt_edit]).map_err(Self::invalid_context)?,
                    "Reject child context delivery",
                )
                .map_err(Self::invalid_context)?
        } else {
            self.repository
                .append_pinned_merge(
                    parent_scope.clone(),
                    parent_head,
                    delivery_commit,
                    tree,
                    "Receive child context delivery",
                )
                .map_err(Self::invalid_context)?
        };
        Ok(ContextDeliveryReceipt {
            parent_head: next_head,
            receipt_path,
            rejected: rejection_reason.is_some(),
        })
    }

    fn delivery_from_publication(
        &self,
        edge: &ContextChildEdge,
        publication: ContextDeliveryPublication,
        source_commit: ContextObjectId,
    ) -> Result<ContextDelivery> {
        let receiver_scope = edge.parent_context.scope().map_err(Self::invalid_context)?;
        self.repository
            .validate_pin(&edge.parent_context)
            .map_err(Self::invalid_context)?;
        let source_context = self
            .repository
            .pin_commit(publication.child_scope.clone(), source_commit, &[])
            .map_err(Self::invalid_context)?
            .pin()
            .clone();
        Ok(ContextDelivery {
            schema_version: DELIVERY_SCHEMA_VERSION,
            parent_context: edge.parent_context.clone(),
            receiver_scope: receiver_scope.to_string(),
            execution_binding: edge.execution_binding,
            source_identity: edge.source_identity.clone(),
            source_context,
            sequence: publication.sequence,
            kind: publication.kind,
            mode: publication.mode,
            selected_bytes: publication.selected_bytes,
        })
    }

    fn validate_delivery(
        &self,
        child_scope: &ScopeRef,
        delivery_commit: ContextObjectId,
        delivery_path: &str,
        delivery: &ContextDelivery,
    ) -> Result<()> {
        if delivery.schema_version != DELIVERY_SCHEMA_VERSION
            || delivery.selected_bytes.is_empty()
            || delivery.selected_bytes.len() > MAX_DELIVERY_BYTES
            || delivery.sequence == 0
            || delivery.receiver_scope
                != delivery
                    .parent_context
                    .scope()
                    .map_err(Self::invalid_context)?
                    .as_str()
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery has an unsupported schema or invalid bounded fields",
                ),
            }
            .fail();
        }
        if delivery_path != Self::delivery_path(delivery.sequence) {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery path does not match its deterministic sequence",
                ),
            }
            .fail();
        }
        let edge = self.direct_edge(child_scope)?;
        if edge.parent_context != delivery.parent_context
            || edge.execution_binding != delivery.execution_binding
            || edge.source_identity != delivery.source_identity
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery does not match its checked direct-parent edge",
                ),
            }
            .fail();
        }
        let source_scope = delivery
            .source_context
            .scope()
            .map_err(Self::invalid_context)?;
        if source_scope != *child_scope {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery source context does not belong to its child scope",
                ),
            }
            .fail();
        }
        self.repository
            .validate_pin(&delivery.source_context)
            .map_err(Self::invalid_context)?;
        let source_commit = delivery
            .source_context
            .commit()
            .map_err(Self::invalid_context)?;
        if !self
            .repository
            .is_ancestor(source_commit, delivery_commit)
            .map_err(Self::invalid_context)?
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery commit is not causally descended from its source pin",
                ),
            }
            .fail();
        }
        if self.read_delivery(delivery_commit, delivery_path)?.as_ref() != Some(delivery) {
            return InvalidRequestSnafu {
                reason: String::from(
                    "child delivery path does not retain the requested immutable blob",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn deliveries_at(&self, commit: ContextObjectId) -> Result<Vec<(String, ContextDelivery)>> {
        let prefix = format!("{CONTEXT_DAG_METADATA_PREFIX}/{DELIVERY_DIRECTORY}");
        self.repository
            .list_commit_blobs_under(commit, &prefix)
            .map_err(Self::invalid_context)?
            .into_iter()
            .map(|blob| {
                let delivery = serde_json::from_slice(blob.bytes()).map_err(Self::invalid_json)?;
                Ok((blob.path().to_owned(), delivery))
            })
            .collect()
    }

    fn read_delivery(
        &self,
        commit: ContextObjectId,
        path: &str,
    ) -> Result<Option<ContextDelivery>> {
        if !path.starts_with(&format!(
            "{CONTEXT_DAG_METADATA_PREFIX}/{DELIVERY_DIRECTORY}/"
        )) {
            return InvalidRequestSnafu {
                reason: String::from(
                    "context delivery path is outside the daemon-owned delivery directory",
                ),
            }
            .fail();
        }
        self.repository
            .read_commit_blob(commit, path)
            .map_err(Self::invalid_context)?
            .map(|blob| serde_json::from_slice(blob.bytes()).map_err(Self::invalid_json))
            .transpose()
    }

    fn decision_exists(
        &self,
        parent_head: ContextObjectId,
        child_scope: &ScopeRef,
        path: &str,
        delivery_commit: ContextObjectId,
    ) -> Result<bool> {
        Ok(self
            .repository
            .read_commit_blob(
                parent_head,
                &Self::decision_path(child_scope, path, delivery_commit, false),
            )
            .map_err(Self::invalid_context)?
            .is_some()
            || self
                .repository
                .read_commit_blob(
                    parent_head,
                    &Self::decision_path(child_scope, path, delivery_commit, true),
                )
                .map_err(Self::invalid_context)?
                .is_some())
    }

    fn prior_delivery_is_decided(
        &self,
        parent_head: ContextObjectId,
        child_scope: &ScopeRef,
        delivery_path: &str,
    ) -> Result<bool> {
        for directory in [RECEIPT_DIRECTORY, REJECTION_DIRECTORY] {
            let prefix = format!("{CONTEXT_DAG_METADATA_PREFIX}/{directory}");
            for blob in self
                .repository
                .list_commit_blobs_under(parent_head, &prefix)
                .map_err(Self::invalid_context)?
            {
                let receipt: RecordedDeliveryReceipt =
                    serde_json::from_slice(blob.bytes()).map_err(Self::invalid_json)?;
                if receipt.schema_version == DELIVERY_SCHEMA_VERSION
                    && receipt.child_scope == child_scope.as_str()
                    && receipt.delivery_path == delivery_path
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn ensure_contained_child(&self, child_scope: &ScopeRef) -> Result<()> {
        self.scope_depth(child_scope, &mut HashSet::new())?;
        Ok(())
    }

    fn scope_head(&self, scope: &ScopeRef, label: &str) -> Result<ContextObjectId> {
        self.repository.scope_head(scope).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not read {label} scope head: {error}"),
            }
            .build()
        })
    }

    fn lock_mutations(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.mutation_lock.lock().map_err(|_error| {
            InvalidRequestSnafu {
                reason: String::from("context DAG coordinator mutation lock is poisoned"),
            }
            .build()
        })
    }

    fn delivery_path(sequence: u64) -> String {
        format!("{CONTEXT_DAG_METADATA_PREFIX}/{DELIVERY_DIRECTORY}/{sequence:020}.json")
    }

    fn decision_path(
        child_scope: &ScopeRef,
        path: &str,
        commit: ContextObjectId,
        rejected: bool,
    ) -> String {
        let digest = Self::decision_digest(child_scope, path, commit).finalize();
        let directory = if rejected {
            REJECTION_DIRECTORY
        } else {
            RECEIPT_DIRECTORY
        };
        format!("{CONTEXT_DAG_METADATA_PREFIX}/{directory}/{digest:x}.json")
    }

    fn result_path(child_scope: &ScopeRef, path: &str, commit: ContextObjectId) -> String {
        let digest = Self::decision_digest(child_scope, path, commit).finalize();
        format!("{RESULT_DIRECTORY}/{digest:x}.json")
    }

    fn decision_digest(child_scope: &ScopeRef, path: &str, commit: ContextObjectId) -> Sha256 {
        let mut digest = Sha256::new();
        digest.update(child_scope.as_str().as_bytes());
        digest.update([0]);
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(commit.to_string().as_bytes());
        digest
    }

    fn invalid_context(error: impl std::fmt::Display) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: error.to_string(),
        }
        .build()
    }

    fn invalid_json(error: serde_json::Error) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: format!("could not encode or decode context delivery JSON: {error}"),
        }
        .build()
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, ContextRepository, ScopeRef, Snapshot,
    };

    use super::{
        ContextDagCoordinator, ContextDeliveryKind, ContextDeliveryMode, ContextDeliveryPublication,
    };
    use crate::context_dag::{ContextChildForkRequest, ContextExecutionBinding};

    type Fixture = (
        tempfile::TempDir,
        Arc<ContextRepository>,
        ScopeRef,
        ScopeRef,
        ContextDagCoordinator,
    );

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadata,
        )?);
        let parent = ScopeRef::root("parent")?;
        repository.initialize_root("parent", Snapshot::default(), "Initialize parent")?;
        let parent_pin = repository
            .pin_scope_head(parent.clone(), &[])?
            .pin()
            .clone();
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), parent.clone())?;
        let child = ScopeRef::root("child")?;
        coordinator.admit_child(ContextChildForkRequest::new(
            parent_pin,
            child.clone(),
            ContextExecutionBinding::DaemonPhysical,
            Some(String::from("codex-v1:fixture")),
        )?)?;
        Ok((temporary, repository, parent, child, coordinator))
    }

    fn delivery(
        child: ScopeRef,
        sequence: u64,
        text: &str,
    ) -> Result<ContextDeliveryPublication, Box<dyn Error>> {
        Ok(ContextDeliveryPublication::new(
            child,
            sequence,
            ContextDeliveryKind::Result,
            ContextDeliveryMode::Queue,
            text.as_bytes().to_vec(),
        )?)
    }

    #[test]
    fn child_delivery_is_ordered_idempotent_and_parent_owned() -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, parent, child, coordinator) = fixture()?;
        let parent_before = repository.scope_head(&parent)?;
        let published = coordinator.publish_delivery(delivery(child.clone(), 1, "first")?)?;
        let child_after_first = published.delivery_commit();
        assert_eq!(repository.scope_head(&parent)?, parent_before);
        assert_eq!(
            coordinator
                .publish_delivery(delivery(child.clone(), 1, "first")?)?
                .delivery_commit(),
            child_after_first
        );
        assert!(coordinator
            .publish_delivery(delivery(child.clone(), 3, "third")?)
            .is_err());
        assert!(coordinator
            .publish_delivery(delivery(child.clone(), 1, "changed")?)
            .is_err());

        let inbox = coordinator.inbox(&parent)?;
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].delivery_path(), published.delivery_path());
        let received = coordinator.receive_delivery(
            &parent,
            published.delivery_path(),
            child_after_first,
            parent_before,
        )?;
        assert!(!received.rejected());
        let parent_after = received.parent_head();
        let merge = repository.read_commit(parent_after)?;
        assert_eq!(merge.parents(), &[parent_before, child_after_first]);
        assert_eq!(repository.scope_head(&child)?, child_after_first);
        assert!(repository
            .read_commit_blob(parent_after, received.receipt_path())?
            .is_some());
        assert!(coordinator.inbox(&parent)?.is_empty());
        assert_eq!(
            coordinator
                .receive_delivery(
                    &parent,
                    published.delivery_path(),
                    child_after_first,
                    parent_before,
                )?
                .parent_head(),
            parent_after
        );
        Ok(())
    }

    #[test]
    fn rejection_is_one_parent_and_a_sibling_cannot_receive() -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, parent, child, coordinator) = fixture()?;
        let published = coordinator.publish_delivery(delivery(child, 1, "declined")?)?;
        let parent_before = repository.scope_head(&parent)?;
        let sibling = ScopeRef::root("sibling")?;
        let sibling_pin = repository
            .pin_scope_head(parent.clone(), &[])?
            .pin()
            .clone();
        coordinator.admit_child(ContextChildForkRequest::new(
            sibling_pin,
            sibling.clone(),
            ContextExecutionBinding::DaemonPhysical,
            Some(String::from("codex-v1:fixture")),
        )?)?;
        assert!(coordinator
            .receive_delivery(
                &sibling,
                published.delivery_path(),
                published.delivery_commit(),
                repository.scope_head(&sibling)?,
            )
            .is_err());
        let rejected = coordinator.reject_delivery(
            &parent,
            published.delivery_path(),
            published.delivery_commit(),
            repository.scope_head(&parent)?,
            "parent does not need this result",
        )?;
        assert!(rejected.rejected());
        let commit = repository.read_commit(rejected.parent_head())?;
        assert_eq!(commit.parents().len(), 1);
        assert!(repository
            .read_commit_blob(rejected.parent_head(), rejected.receipt_path())?
            .is_some());
        assert_ne!(repository.scope_head(&parent)?, parent_before);
        Ok(())
    }

    #[test]
    fn concurrent_children_produce_ordered_two_parent_merges_and_one_rejection(
    ) -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, parent, child_b, coordinator) = fixture()?;
        let child_c = ScopeRef::root("child-c")?;
        let parent_pin = repository
            .pin_scope_head(parent.clone(), &[])?
            .pin()
            .clone();
        coordinator.admit_child(ContextChildForkRequest::new(
            parent_pin,
            child_c.clone(),
            ContextExecutionBinding::DaemonPhysical,
            Some(String::from("codex-v1:fixture")),
        )?)?;
        let b_first = coordinator.publish_delivery(delivery(child_b.clone(), 1, "b-1")?)?;
        let b_second = coordinator.publish_delivery(delivery(child_b.clone(), 2, "b-2")?)?;
        let c_first = coordinator.publish_delivery(delivery(child_c.clone(), 1, "c-1")?)?;
        let c_second = coordinator.publish_delivery(delivery(child_c.clone(), 2, "c-2")?)?;
        let b_head = repository.scope_head(&child_b)?;
        let c_head = repository.scope_head(&child_c)?;
        let mut parent_head = repository.scope_head(&parent)?;
        assert_eq!(coordinator.inbox(&parent)?.len(), 4);
        assert!(coordinator
            .receive_delivery(&parent, b_second.delivery_path(), b_head, parent_head,)
            .is_err());

        for (path, commit) in [
            (b_first.delivery_path(), b_head),
            (c_first.delivery_path(), c_head),
            (
                "erebor/context-dag/deliveries/00000000000000000002.json",
                b_head,
            ),
        ] {
            let received = coordinator.receive_delivery(&parent, path, commit, parent_head)?;
            let merge = repository.read_commit(received.parent_head())?;
            assert_eq!(merge.parents().len(), 2);
            assert_eq!(merge.parents()[0], parent_head);
            assert_eq!(merge.parents()[1], commit);
            parent_head = received.parent_head();
        }
        let rejected = coordinator.reject_delivery(
            &parent,
            c_second.delivery_path(),
            c_head,
            parent_head,
            "not selected",
        )?;
        assert!(rejected.rejected());
        assert_eq!(
            repository
                .read_commit(rejected.parent_head())?
                .parents()
                .len(),
            1
        );
        assert_eq!(repository.scope_head(&child_b)?, b_head);
        assert_eq!(repository.scope_head(&child_c)?, c_head);
        assert!(coordinator.inbox(&parent)?.is_empty());
        Ok(())
    }

    struct FixedMetadata;

    impl CommitMetadataSource for FixedMetadata {
        fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
            let time = CommitTime::new(1_700_000_000, 0)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            let signature = CommitSignature::new("Erebor", "runtime@example.test", time)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            Ok(CommitMetadata::new(signature.clone(), signature))
        }
    }
}
