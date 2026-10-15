use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::ops::RangeBounds;
use std::sync::Arc;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, ContextSensitivityV1,
};
use serde::Serialize;
use snafu::ResultExt as _;

use super::{ControlStore, ControlStoreState, ControlTransactionV1, PolicyRolloutKeyV1};
use crate::{error::JsonSnafu, AllowedNodeIdentity, Result};

pub(super) struct ContextLimit<W>(pub(super) usize, pub(super) W);

impl<W: std::io::Write> std::io::Write for ContextLimit<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("the policy context exceeds its byte bound"))?;
        self.1.write_all(bytes)?;
        self.0 = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.1.flush()
    }
}

#[derive(Serialize)]
struct PolicyContext<'a> {
    source: &'a crate::PolicySourceRevisionV1,
    document: &'a crate::PolicyDocumentV1,
}

#[derive(Serialize)]
struct PublicAuthorityApproval<'a> {
    request_id: &'a [u8; 16],
    tenant_id: &'a [u8; 16],
    approver_principal_id: &'a [u8; 16],
    trust_revision: u64,
    proof_id: &'a [u8; 16],
    claim_slot_id: &'a [u8; 16],
    accepted_utc_ns: i64,
    expires_utc_ns: i64,
    state: crate::AuthorityIntentStateV1,
    provider_proof: crate::ProviderAuthorityProofV1,
}

impl<'a> From<&'a crate::AuthorityApprovalV1> for PublicAuthorityApproval<'a> {
    fn from(approval: &'a crate::AuthorityApprovalV1) -> Self {
        Self {
            request_id: &approval.request_id,
            tenant_id: &approval.tenant_id,
            approver_principal_id: &approval.approver_principal_id,
            trust_revision: approval.trust_revision,
            proof_id: &approval.proof_id,
            claim_slot_id: &approval.claim_slot_id,
            accepted_utc_ns: approval.accepted_utc_ns,
            expires_utc_ns: approval.expires_utc_ns,
            state: approval.state,
            provider_proof: crate::ProviderAuthorityProofV1::Missing,
        }
    }
}

enum ContextCursor {
    Policy(Option<String>),
    Trust(Option<u64>),
    Rollout(Option<PolicyRolloutKeyV1>),
    Target(Option<String>, usize, usize),
    Authority(u8, Option<[u8; 16]>),
    End,
}

#[derive(Default)]
pub(super) struct ContextChanges {
    // These positions are not durable. Startup reads all stored facts.
    policy: BTreeMap<String, u64>,
    trust: BTreeMap<u64, u64>,
    rollout: BTreeMap<PolicyRolloutKeyV1, u64>,
    target: BTreeMap<String, u64>,
    authority: [BTreeMap<[u8; 16], u64>; 4],
}

impl ContextChanges {
    pub(super) fn record(
        &mut self,
        transaction: &ControlTransactionV1,
        before: &ControlStoreState,
        after: &ControlStoreState,
    ) {
        let revision = after.commit_index;
        match transaction {
            ControlTransactionV1::SourceAccepted {
                source_revision, ..
            } => {
                let id = &source_revision.policy_source_revision_id;
                if before.source_revisions.get(id) != after.source_revisions.get(id)
                    || before.policy_documents.get(id) != after.policy_documents.get(id)
                {
                    self.policy.insert(id.clone(), revision);
                }
            }
            ControlTransactionV1::TrustInstalled { generation } => {
                self.trust.insert(generation.generation, revision);
            }
            ControlTransactionV1::RolloutCreated { rollout } => {
                self.rollout(rollout, before, after);
            }
            ControlTransactionV1::TargetSetReconciled { reconciliation } => {
                self.rollout(&reconciliation.desired, before, after);
                if let Some(retirement) = &reconciliation.retirement {
                    self.rollout(retirement, before, after);
                }
            }
            ControlTransactionV1::NodeSessionAdvanced { advance } => {
                for rollout in &advance.policy_rollout_states {
                    self.rollout_state(rollout, before, after);
                }
            }
            ControlTransactionV1::Acknowledged { result } => {
                self.rollout_state(&result.rollout_state, before, after);
            }
            ControlTransactionV1::AuthorityUpdated { .. } => {
                Self::changed(
                    &mut self.authority[0],
                    &before.authority.requests,
                    &after.authority.requests,
                    revision,
                );
                Self::changed(
                    &mut self.authority[1],
                    &before.authority.approvals,
                    &after.authority.approvals,
                    revision,
                );
                Self::changed(
                    &mut self.authority[2],
                    &before.authority.leases,
                    &after.authority.leases,
                    revision,
                );
                Self::changed(
                    &mut self.authority[3],
                    &before.authority.handles,
                    &after.authority.handles,
                    revision,
                );
            }
            ControlTransactionV1::KubernetesNodeBound { .. }
            | ControlTransactionV1::Compiled { .. }
            | ControlTransactionV1::ExceptionDesired { .. }
            | ControlTransactionV1::ExceptionAcknowledged { .. }
            | ControlTransactionV1::TrustAcknowledged { .. }
            | ControlTransactionV1::NodeDecommissionUpdated { .. } => {}
        }
    }

    fn rollout(
        &mut self,
        rollout: &super::PolicyRolloutTransactionV1,
        before: &ControlStoreState,
        after: &ControlStoreState,
    ) {
        let id = &rollout.target_snapshot.target_snapshot_digest;
        if before.target_snapshots.get(id) != after.target_snapshots.get(id) {
            self.target.insert(id.clone(), after.commit_index);
        }
        for state in &rollout.rollout_states {
            self.rollout_state(state, before, after);
        }
    }

    fn rollout_state(
        &mut self,
        state: &crate::PolicyRolloutStateV1,
        before: &ControlStoreState,
        after: &ControlStoreState,
    ) {
        let key = PolicyRolloutKeyV1 {
            candidate_content_id: state.desired_candidate_content_id.clone(),
            node_id: state.target.node_id.clone(),
        };
        if before.rollout_states.get(&key) != after.rollout_states.get(&key) {
            self.rollout.insert(key, after.commit_index);
        }
    }

    fn changed<K: Ord + Clone, V: PartialEq>(
        positions: &mut BTreeMap<K, u64>,
        before: &BTreeMap<K, V>,
        after: &BTreeMap<K, V>,
        revision: u64,
    ) {
        positions.retain(|key, _| after.contains_key(key));
        for (key, value) in after {
            if before.get(key) != Some(value) {
                positions.insert(key.clone(), revision);
            }
        }
    }

    fn since(&self, since: u64, through: u64) -> Self {
        Self {
            policy: Self::positions(&self.policy, since, through),
            trust: Self::positions(&self.trust, since, through),
            rollout: Self::positions(&self.rollout, since, through),
            target: Self::positions(&self.target, since, through),
            authority: self
                .authority
                .each_ref()
                .map(|positions| Self::positions(positions, since, through)),
        }
    }

    fn positions<K: Ord + Clone>(
        positions: &BTreeMap<K, u64>,
        since: u64,
        through: u64,
    ) -> BTreeMap<K, u64> {
        positions
            .iter()
            .filter(|(_, revision)| since < **revision && **revision <= through)
            .map(|(key, revision)| (key.clone(), *revision))
            .collect()
    }

    fn next<'a, K: Ord, V>(
        values: &'a BTreeMap<K, V>,
        selected: Option<&BTreeMap<K, u64>>,
        bounds: impl RangeBounds<K>,
    ) -> Option<(&'a K, &'a V)> {
        match selected {
            Some(selected) => selected
                .range(bounds)
                .find_map(|(key, _)| values.get_key_value(key)),
            None => values.range(bounds).next(),
        }
    }
}

/// Copies committed Control facts. Copies never grant policy authority.
pub struct ControlContextOwner {
    store: ControlStore,
    data: Arc<AnalysisStore>,
    tenants: Vec<[u8; 16]>,
    tenant: usize,
    cursor: ContextCursor,
    changes: tokio::sync::watch::Receiver<u64>,
    revision: u64,
    complete: bool,
    selected: Option<ContextChanges>,
}

impl ControlContextOwner {
    pub fn new(
        store: ControlStore,
        data: Arc<AnalysisStore>,
        allowed: &[AllowedNodeIdentity],
    ) -> Result<Self> {
        let mut tenants = BTreeSet::new();
        for node in allowed {
            let tenant = uuid::Uuid::parse_str(&node.tenant_id)
                .ok()
                .filter(|id| !id.is_nil())
                .ok_or_else(|| {
                    crate::error::InvalidConfigurationSnafu {
                        reason: "context projection requires a nonzero tenant UUID",
                    }
                    .build()
                })?;
            tenants.insert(tenant.into_bytes());
        }
        let mut changes = store.subscribe_revision()?;
        let revision = *changes.borrow_and_update();
        Ok(Self {
            store,
            data,
            tenants: tenants.into_iter().collect(),
            tenant: 0,
            cursor: ContextCursor::Policy(None),
            changes,
            revision,
            complete: false,
            selected: None,
        })
    }

    /// Reads at most 16 Control entries. Storage failures keep the retry cursor.
    pub fn reconcile(&mut self) -> Result<usize> {
        if self.tenants.is_empty() {
            self.revision = *self.changes.borrow_and_update();
            self.complete = true;
            return Ok(0);
        }
        if self.complete {
            let revision = *self.changes.borrow_and_update();
            if revision == self.revision {
                return Ok(0);
            }
            self.selected = Some(self.store.context_changes(self.revision, revision)?);
            self.revision = revision;
            self.complete = false;
        }
        let mut copied = 0;
        for _ in 0..16 {
            let (record, next) = self.store.next_context(
                self.tenants[self.tenant],
                &self.cursor,
                self.selected.as_ref(),
            )?;
            if let Some(record) = record {
                let record = match record {
                    Ok(record) => record,
                    Err(error) => {
                        self.cursor = next;
                        return Err(error);
                    }
                };
                self.data
                    .commit_context(&record)
                    .map_err(|source| crate::Error::DataStore {
                        source: Box::new(source),
                        location: snafu::Location::default(),
                    })?;
                copied += 1;
            }
            self.cursor = next;
            if matches!(self.cursor, ContextCursor::End) {
                self.cursor = ContextCursor::Policy(None);
                self.tenant += 1;
                if self.tenant == self.tenants.len() {
                    self.tenant = 0;
                    self.complete = true;
                }
                break;
            }
        }
        Ok(copied)
    }

    pub(crate) fn idle(&self) -> bool {
        self.complete && *self.changes.borrow() == self.revision
    }

    pub(crate) async fn changed(&mut self) {
        let _changed = self.changes.changed().await;
    }
}

impl ControlStore {
    pub(crate) fn subscribe_revision(&self) -> Result<tokio::sync::watch::Receiver<u64>> {
        Ok(self.lock()?.changes.subscribe())
    }

    fn context_changes(&self, since: u64, through: u64) -> Result<ContextChanges> {
        Ok(self.evidence_lock()?.context_changes.since(since, through))
    }

    fn next_context(
        &self,
        tenant: [u8; 16],
        cursor: &ContextCursor,
        selected: Option<&ContextChanges>,
    ) -> Result<(Option<Result<AnalysisContextVersionV1>>, ContextCursor)> {
        let inner = self.evidence_lock()?;
        let matches = |id: &str| uuid::Uuid::parse_str(id).is_ok_and(|id| id.as_bytes() == &tenant);
        let record = match cursor {
            ContextCursor::Policy(after) => {
                let bounds = (after.as_ref().map_or(Unbounded, Excluded), Unbounded);
                let Some((id, source)) = ContextChanges::next(
                    &inner.state.source_revisions,
                    selected.map(|selected| &selected.policy),
                    bounds,
                ) else {
                    return Ok((None, ContextCursor::Trust(None)));
                };
                let next = ContextCursor::Policy(Some(id.clone()));
                let record = matches(&source.tenant_id).then(|| {
                    let document = inner.state.policy_documents.get(id).ok_or_else(|| {
                        crate::error::ControlStoreSnafu {
                            path: inner.root.clone(),
                            reason: "the context source has no committed policy document"
                                .to_owned(),
                        }
                        .build()
                    })?;
                    Self::encode_context(
                        &inner.root,
                        AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: "mithril-control/policy".into(),
                            entity_key: source.object_uid.as_bytes().to_vec(),
                            lifetime_key: source.policy_source_revision_id.as_bytes().to_vec(),
                            owner_revision: source.object_generation,
                        },
                        &PolicyContext { source, document },
                    )
                });
                (record, next)
            }
            ContextCursor::Trust(after) => {
                let bounds = (after.as_ref().map_or(Unbounded, Excluded), Unbounded);
                let Some((generation, trust)) = ContextChanges::next(
                    &inner.state.trust_generations,
                    selected.map(|selected| &selected.trust),
                    bounds,
                ) else {
                    return Ok((None, ContextCursor::Rollout(None)));
                };
                let record = Self::encode_context(
                    &inner.root,
                    AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: "mithril-control/trust".into(),
                        entity_key: b"trust".to_vec(),
                        lifetime_key: trust.bundle_digest.as_bytes().to_vec(),
                        owner_revision: *generation,
                    },
                    trust,
                );
                (Some(record), ContextCursor::Trust(Some(*generation)))
            }
            ContextCursor::Rollout(after) => {
                let bounds = (after.as_ref().map_or(Unbounded, Excluded), Unbounded);
                let Some((key, rollout)) = ContextChanges::next(
                    &inner.state.rollout_states,
                    selected.map(|selected| &selected.rollout),
                    bounds,
                ) else {
                    return Ok((None, ContextCursor::Target(None, 0, 0)));
                };
                let next = ContextCursor::Rollout(Some(key.clone()));
                let record = matches(&rollout.target.tenant_id).then(|| {
                    Self::encode_context(
                        &inner.root,
                        AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: "mithril-control/rollout".into(),
                            entity_key: rollout.target.node_id.as_bytes().to_vec(),
                            lifetime_key: rollout.desired_candidate_content_id.as_bytes().to_vec(),
                            owner_revision: rollout.transition_version,
                        },
                        rollout,
                    )
                });
                (record, next)
            }
            ContextCursor::Target(after, target_index, fact_index) => {
                let bounds = (after.as_ref().map_or(Unbounded, Included), Unbounded);
                let Some((id, snapshot)) = ContextChanges::next(
                    &inner.state.target_snapshots,
                    selected.map(|selected| &selected.target),
                    bounds,
                ) else {
                    return Ok((None, ContextCursor::Authority(0, None)));
                };
                let (target_index, fact_index) = if after.as_ref() == Some(id) {
                    (*target_index, *fact_index)
                } else {
                    (0, 0)
                };
                let Some(target) = snapshot.targets.get(target_index) else {
                    let next = ContextChanges::next(
                        &inner.state.target_snapshots,
                        selected.map(|selected| &selected.target),
                        (Excluded(id), Unbounded),
                    )
                    .map_or(ContextCursor::Authority(0, None), |(id, _)| {
                        ContextCursor::Target(Some(id.clone()), 0, 0)
                    });
                    return Ok((None, next));
                };
                let Some(fact) = target.workload_targets.get(fact_index) else {
                    return Ok((
                        None,
                        ContextCursor::Target(Some(id.clone()), target_index + 1, 0),
                    ));
                };
                let next = ContextCursor::Target(Some(id.clone()), target_index, fact_index + 1);
                let record = matches(&target.tenant_id).then(|| {
                    let entity = fact
                        .kubernetes
                        .as_ref()
                        .map_or(fact.execution_set_id.as_str(), |identity| {
                            identity.binding_id.as_str()
                        });
                    Self::encode_context(
                        &inner.root,
                        AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: "mithril-control/target".into(),
                            entity_key: entity.as_bytes().to_vec(),
                            lifetime_key: fact
                                .workload_binding_generation_digest
                                .as_bytes()
                                .to_vec(),
                            owner_revision: 1,
                        },
                        fact,
                    )
                });
                (record, next)
            }
            ContextCursor::Authority(stage, after) => {
                let bounds = (
                    after.as_ref().map_or(Unbounded, Excluded),
                    Unbounded::<&[u8; 16]>,
                );
                let key =
                    |owner: &str, entity: [u8; 16], lifetime: [u8; 16]| AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: owner.into(),
                        entity_key: entity.to_vec(),
                        lifetime_key: lifetime.to_vec(),
                        owner_revision: 1,
                    };
                let authority = &inner.state.authority;
                match stage {
                    0 => {
                        let Some((id, request)) = ContextChanges::next(
                            &authority.requests,
                            selected.map(|selected| &selected.authority[0]),
                            bounds,
                        ) else {
                            return Ok((None, ContextCursor::Authority(1, None)));
                        };
                        (
                            (request.tenant_id == tenant).then(|| {
                                Self::encode_context(
                                    &inner.root,
                                    key(
                                        "mithril-control/authority-request",
                                        *id,
                                        request.body.request_nonce,
                                    ),
                                    request,
                                )
                            }),
                            ContextCursor::Authority(0, Some(*id)),
                        )
                    }
                    1 => {
                        let Some((id, approval)) = ContextChanges::next(
                            &authority.approvals,
                            selected.map(|selected| &selected.authority[1]),
                            bounds,
                        ) else {
                            return Ok((None, ContextCursor::Authority(2, None)));
                        };
                        (
                            (approval.tenant_id == tenant).then(|| {
                                Self::encode_context(
                                    &inner.root,
                                    key(
                                        "mithril-control/authority-approval",
                                        *id,
                                        approval.proof_id,
                                    ),
                                    &PublicAuthorityApproval::from(approval),
                                )
                            }),
                            ContextCursor::Authority(1, Some(*id)),
                        )
                    }
                    2 => {
                        let Some((id, lease)) = ContextChanges::next(
                            &authority.leases,
                            selected.map(|selected| &selected.authority[2]),
                            bounds,
                        ) else {
                            return Ok((None, ContextCursor::Authority(3, None)));
                        };
                        (
                            (lease.tenant_id == tenant).then(|| {
                                Self::encode_context(
                                    &inner.root,
                                    key(
                                        "mithril-control/authority-lease",
                                        *id,
                                        lease.request_nonce,
                                    ),
                                    lease,
                                )
                            }),
                            ContextCursor::Authority(2, Some(*id)),
                        )
                    }
                    3 => {
                        let Some((id, handle)) = ContextChanges::next(
                            &authority.handles,
                            selected.map(|selected| &selected.authority[3]),
                            bounds,
                        ) else {
                            return Ok((None, ContextCursor::End));
                        };
                        (
                            (handle.tenant_id == tenant).then(|| {
                                Self::encode_context(
                                    &inner.root,
                                    key("mithril-control/authority-audit", *id, handle.lease_id),
                                    handle,
                                )
                            }),
                            ContextCursor::Authority(3, Some(*id)),
                        )
                    }
                    _ => {
                        return Err(
                            crate::AuthorityErrorCodeV1::Invalid.error("authority context cursor")
                        )
                    }
                }
            }
            ContextCursor::End => (None, ContextCursor::End),
        };
        Ok(record)
    }

    fn encode_context(
        path: &std::path::Path,
        key: AnalysisContextKeyV1,
        fact: &impl Serialize,
    ) -> Result<AnalysisContextVersionV1> {
        let mut output = ContextLimit(32 * 1024, Vec::new());
        serde_json::to_writer(&mut output, fact).context(JsonSnafu { path })?;
        let body = output.1;
        Ok(AnalysisContextVersionV1 {
            key,
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        kubernetes_target, rollout_transaction, signed_artifact, source_revision,
    };
    use super::*;
    use crate::TrustGenerationV1;

    #[test]
    fn control_context_retained_targets() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store_path = directory.path().join("control");
        let data_path = directory.path().join("data");
        let store = ControlStore::open(&store_path)?;
        let data = Arc::new(AnalysisStore::open(&data_path)?);
        let document = crate::PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, crate::PolicySourceStateV1::Accepted, 1, '8')?;
        let artifact = signed_artifact(&document, 1)?;
        store.accept_compiled_source_revision(
            source.clone(),
            document.clone(),
            artifact.clone(),
        )?;
        let mut target = kubernetes_target(
            &source,
            &document,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            1,
        )?;
        let base = target.workload_targets[0].clone();
        target.workload_targets.clear();
        for index in 1..=18_u128 {
            let mut fact = base.clone();
            let id = uuid::Uuid::from_u128(index).to_string();
            fact.execution_set_id = id.clone();
            fact.pod_uid = id.clone();
            fact.container_id = format!("containerd://{index}");
            fact.kubernetes
                .as_mut()
                .ok_or("missing identity")?
                .binding_id = id;
            fact.workload_binding_generation_digest = crate::workload_target_fact_digest(&fact)?;
            target.workload_targets.push(fact);
        }
        target.workload_targets.sort_by(|left, right| {
            left.workload_binding_generation_digest
                .cmp(&right.workload_binding_generation_digest)
        });
        target.workload_binding_generation_digests = target
            .workload_targets
            .iter()
            .map(|fact| fact.workload_binding_generation_digest.clone())
            .collect();
        let facts = target.workload_targets.clone();
        let rollout = rollout_transaction(
            &source,
            &artifact,
            vec![(target, None)],
            crate::PolicyDeliveryOperationV1::Activate,
            1,
            1,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )?;
        store.create_rollout(
            rollout.target_snapshot,
            rollout.bundles,
            rollout.rollout_states,
        )?;
        let authority = store.commit_index();
        let tenant = uuid::Uuid::parse_str(&source.tenant_id)?.into_bytes();
        let allowed = [AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: source.tenant_id,
        }];
        let key = |fact: &crate::WorkloadTargetFactV1| -> std::result::Result<AnalysisContextKeyV1, Box<dyn std::error::Error>> {
            Ok(AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "mithril-control/target".into(),
                entity_key: fact.kubernetes.as_ref().ok_or("missing identity")?.binding_id.as_bytes().to_vec(),
                lifetime_key: fact.workload_binding_generation_digest.as_bytes().to_vec(),
                owner_revision: 1,
            })
        };
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert!(owner.reconcile()? <= 16);
        assert!(data
            .context_version(&key(facts.last().ok_or("missing fact")?)?)?
            .is_none());
        for _ in 0..4 {
            assert!(owner.reconcile()? <= 16);
        }
        for fact in &facts {
            let context = data
                .context_version(&key(fact)?)?
                .ok_or("missing retained target")?;
            assert_eq!(
                serde_json::from_slice::<crate::WorkloadTargetFactV1>(&context.body)?,
                *fact
            );
            assert_eq!(context.sensitivity, ContextSensitivityV1::Tenant);
            assert_eq!(context.valid_from_utc_ns, None);
            assert_eq!(context.valid_until_utc_ns, None);
            let mut foreign = context.key.clone();
            foreign.tenant_id = [9; 16];
            assert!(data.context_version(&foreign)?.is_none());
        }
        let before = data.meta()?;
        assert_eq!(store.commit_index(), authority);
        drop(owner);
        drop(store);
        drop(data);
        let store = ControlStore::open(store_path)?;
        let data = Arc::new(AnalysisStore::open(data_path)?);
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        for _ in 0..4 {
            assert!(owner.reconcile()? <= 16);
        }
        assert_eq!(data.meta()?, before);
        assert_eq!(store.commit_index(), authority);
        for fact in &facts {
            assert!(data.context_version(&key(fact)?)?.is_some());
        }
        Ok(())
    }

    #[test]
    fn control_context_retries_write() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("data"),
            Default::default(),
            araphor_data::StorageLimitsV1 {
                logical_max_bytes: 1,
                tenant_max_bytes: 1,
                ..Default::default()
            },
        )?);
        let allowed = [AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }];
        store.install_trust_generation(TrustGenerationV1 {
            generation: 1,
            bundle_digest: "a".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        let mut owner = ControlContextOwner::new(store, data.clone(), &allowed)?;
        for _ in 0..2 {
            assert!(
                matches!(owner.reconcile(), Err(crate::Error::DataStore { source, .. })
                if matches!(*source, araphor_data::Error::StorageCapacity { .. }))
            );
            assert!(matches!(owner.cursor, ContextCursor::Trust(None)));
            assert_eq!(data.meta()?.commit_revision, 0);
        }
        Ok(())
    }

    #[test]
    fn control_context_bounded_replay() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data_path = directory.path().join("data");
        let data = Arc::new(AnalysisStore::open(&data_path)?);
        let allowed = vec![AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }];
        let mut invalid = allowed.clone();
        invalid[0].tenant_id = uuid::Uuid::nil().to_string();
        assert!(ControlContextOwner::new(store.clone(), data.clone(), &invalid).is_err());
        for generation in 1..=20 {
            store.install_trust_generation(TrustGenerationV1 {
                generation,
                bundle_digest: format!("{generation:064x}"),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            })?;
        }
        let authority = store.commit_index();
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 15);
        assert_eq!(data.meta()?.commit_revision, 15);
        assert_eq!(owner.reconcile()?, 5);
        let before = data.meta()?;
        for _ in 0..4 {
            owner.reconcile()?;
        }
        assert!(owner.idle());
        assert_eq!(owner.reconcile()?, 0);
        assert!(!owner.changes.has_changed()?);
        assert_eq!(data.meta()?, before);
        assert_eq!(store.commit_index(), authority);
        let key = AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "mithril-control/trust".into(),
            entity_key: b"trust".to_vec(),
            lifetime_key: format!("{:064x}", 1).into_bytes(),
            owner_revision: 1,
        };
        let context = data.context_version(&key)?.ok_or("missing context")?;
        assert_eq!(context.valid_from_utc_ns, None);
        assert_eq!(context.valid_until_utc_ns, None);
        let fact: TrustGenerationV1 = serde_json::from_slice(&context.body)?;
        assert_eq!(fact.generation, 1);
        let mut foreign = key.clone();
        foreign.tenant_id = [2; 16];
        assert_eq!(data.context_version(&foreign)?, None);
        drop(owner);
        drop(data);
        let reopened = Arc::new(AnalysisStore::open(data_path)?);
        assert_eq!(reopened.context_version(&key)?, Some(context));
        let mut owner = ControlContextOwner::new(store, reopened.clone(), &allowed)?;
        owner.reconcile()?;
        owner.reconcile()?;
        assert_eq!(reopened.meta()?, before);
        let mut oversized = TrustGenerationV1 {
            generation: 21,
            bundle_digest: "e".repeat(64),
            policy_issuer_sequence_epoch: 1,
            policy_signers: (0..300)
                .map(|index| crate::PolicySignerTrustV1 {
                    signing_key_id: format!("signer-{index:03}"),
                    ed25519_public_key_hex: "a".repeat(64),
                    revoked: false,
                })
                .collect(),
        }
        .with_computed_bundle_digest();
        owner.store.install_trust_generation(oversized.clone())?;
        oversized.generation = 22;
        oversized.policy_signers.clear();
        owner.store.install_trust_generation(oversized)?;
        assert!(!owner.idle());
        assert!(owner.changes.has_changed()?);
        assert!(owner.reconcile().is_err());
        assert_eq!(reopened.meta()?, before);
        assert_eq!(owner.reconcile()?, 1);
        assert_eq!(reopened.meta()?.commit_revision, before.commit_revision + 1);
        assert!(owner.idle());
        let trust = owner
            .store
            .current_trust_generation()?
            .ok_or("missing trust")?;
        owner
            .store
            .acknowledge_trust_generation(crate::TrustGenerationAcknowledgementV1 {
                node_id: "node-a".into(),
                node_boot_id: [3; 16],
                label_epoch: 1,
                generation: trust.generation,
                bundle_digest: trust.bundle_digest,
            })?;
        assert_eq!(owner.reconcile()?, 0);
        assert!(owner.idle());
        assert_eq!(reopened.meta()?.commit_revision, before.commit_revision + 1);
        Ok(())
    }

    #[test]
    fn control_context_preserves_changed_body_conflicts(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let allowed = [AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }];
        store.update_authority(|state| {
            state.approvals.insert(
                [2; 16],
                crate::AuthorityApprovalV1 {
                    request_id: [2; 16],
                    tenant_id: [1; 16],
                    approver_principal_id: [3; 16],
                    trust_revision: 1,
                    proof_id: [4; 16],
                    claim_slot_id: [5; 16],
                    accepted_utc_ns: 1,
                    expires_utc_ns: 100,
                    signed_intent: vec![6],
                    state: crate::AuthorityIntentStateV1::Pending,
                },
            );
            Ok(true)
        })?;
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 1);
        assert!(owner.idle());
        let before = data.meta()?;
        let prior = data
            .context_version(&AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "mithril-control/authority-approval".into(),
                entity_key: vec![2; 16],
                lifetime_key: vec![4; 16],
                owner_revision: 1,
            })?
            .ok_or("missing retained approval")?;
        store.update_authority(|state| Ok(state.proofs.insert([7; 16])))?;
        assert_eq!(owner.reconcile()?, 0);
        assert!(owner.idle());
        assert_eq!(data.meta()?, before);
        store.update_authority(|state| {
            let approval = state.approvals.get_mut(&[2; 16]).ok_or_else(|| {
                crate::AuthorityErrorCodeV1::Invalid.error("missing test approval")
            })?;
            approval.state = crate::AuthorityIntentStateV1::Cancelled;
            Ok(true)
        })?;
        for _ in 0..2 {
            assert!(
                matches!(owner.reconcile(), Err(crate::Error::DataStore { source, .. })
                if matches!(*source, araphor_data::Error::AnalysisConflict { .. }))
            );
            assert!(matches!(owner.cursor, ContextCursor::Authority(1, None)));
            assert_eq!(data.meta()?, before);
        }
        store.update_authority(|state| {
            let mut approval = state.approvals.remove(&[2; 16]).ok_or_else(|| {
                crate::AuthorityErrorCodeV1::Invalid.error("missing test approval")
            })?;
            approval.request_id = [8; 16];
            state.approvals.insert(approval.request_id, approval);
            Ok(true)
        })?;
        assert_eq!(
            store.evidence_lock()?.context_changes.authority[1]
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![[8; 16]]
        );
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.reconcile()?, 1);
        assert!(owner.idle());
        let mut current = prior.key.clone();
        current.entity_key = vec![8; 16];
        assert!(data.context_version(&current)?.is_some());
        assert_eq!(data.context_version(&prior.key)?, Some(prior));
        assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
        Ok(())
    }

    #[test]
    fn control_context_empty_tenants_stay_idle(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let mut owner = ControlContextOwner::new(store.clone(), data, &[])?;
        assert_eq!(owner.reconcile()?, 0);
        store.update_authority(|state| Ok(state.proofs.insert([7; 16])))?;
        assert_eq!(owner.reconcile()?, 0);
        assert!(owner.idle());
        Ok(())
    }
}
