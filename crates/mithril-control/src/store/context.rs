use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, CompiledPolicyContextV1,
    ContextSensitivityV1, DiscoveryPolicyKeyV1, TargetContextV1,
};
use serde::Serialize;
use snafu::ResultExt as _;

use super::{ControlStore, ControlStoreInner, ControlStoreState, PolicyRolloutKeyV1};
use crate::{error::JsonSnafu, AllowedNodeIdentity, Result};

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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ContextSource {
    Policy(String),
    Compiled(String),
    Trust(u64),
    Rollout(PolicyRolloutKeyV1),
    Candidate(String),
    Acknowledgement(PolicyRolloutKeyV1, u64),
    Target(String),
    Request([u8; 16]),
    Approval([u8; 16]),
    Lease([u8; 16]),
    Audit([u8; 16]),
}

pub(super) type ContextChanges = Vec<(ContextSource, bool)>;

pub(super) struct ContextIndex {
    pub(super) sources: BTreeMap<ContextSource, u64>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl ContextIndex {
    pub(super) fn new(state: &ControlStoreState) -> Self {
        let mut sources = BTreeMap::new();
        let revision = state.commit_index;
        for id in state.source_revisions.keys() {
            sources.insert(ContextSource::Policy(id.clone()), revision);
        }
        for id in state.compiled_artifacts.keys() {
            sources.insert(ContextSource::Compiled(id.clone()), revision);
        }
        for generation in state.trust_generations.keys() {
            sources.insert(ContextSource::Trust(*generation), revision);
        }
        for id in state.rollout_states.keys() {
            sources.insert(ContextSource::Rollout(id.clone()), revision);
        }
        for id in state.bundles.keys() {
            sources.insert(ContextSource::Candidate(id.clone()), revision);
        }
        for (id, version) in state.policy_acknowledgement_results.keys() {
            sources.insert(
                ContextSource::Acknowledgement(id.clone(), *version),
                revision,
            );
        }
        for id in state.target_snapshots.keys() {
            sources.insert(ContextSource::Target(id.clone()), revision);
        }
        for id in state.authority.requests.keys() {
            sources.insert(ContextSource::Request(*id), revision);
        }
        for id in state.authority.approvals.keys() {
            sources.insert(ContextSource::Approval(*id), revision);
        }
        for id in state.authority.leases.keys() {
            sources.insert(ContextSource::Lease(*id), revision);
        }
        for id in state.authority.handles.keys() {
            sources.insert(ContextSource::Audit(*id), revision);
        }
        Self {
            sources,
            changes: tokio::sync::watch::channel(revision).0,
        }
    }

    pub(super) fn apply(&mut self, changes: ContextChanges, revision: u64) {
        if changes.is_empty() {
            return;
        }
        for (source, present) in changes {
            if present {
                self.sources.insert(source, revision);
            } else {
                self.sources.remove(&source);
            }
        }
        self.changes.send_replace(revision);
    }
}

impl ContextSource {
    pub(super) fn insert<K: Ord + Clone, V: PartialEq>(
        changes: &mut ContextChanges,
        values: &mut BTreeMap<K, V>,
        key: K,
        value: V,
        source: impl FnOnce(K) -> Self,
    ) -> Option<V> {
        let previous = values.insert(key.clone(), value);
        if previous.as_ref() != values.get(&key) {
            changes.push((source(key), true));
        }
        previous
    }

    pub(super) fn changed<K: Ord + Clone, V: PartialEq>(
        changes: &mut ContextChanges,
        before: &BTreeMap<K, V>,
        after: &BTreeMap<K, V>,
        source: impl Fn(K) -> Self,
    ) {
        for key in before.keys().filter(|key| !after.contains_key(*key)) {
            changes.push((source(key.clone()), false));
        }
        for (key, value) in after {
            if before.get(key) != Some(value) {
                changes.push((source(key.clone()), true));
            }
        }
    }

    fn record(
        &self,
        inner: &ControlStoreInner,
        tenants: &[[u8; 16]],
        position: &mut Option<(usize, usize)>,
    ) -> Option<Result<AnalysisContextVersionV1>> {
        let state = &inner.state;
        let selected = |id: &str| {
            uuid::Uuid::parse_str(id)
                .ok()
                .map(|id| id.into_bytes())
                .filter(|tenant| tenants.binary_search(tenant).is_ok())
        };
        let key = |owner: &str, tenant: [u8; 16], entity: [u8; 16], lifetime: [u8; 16]| {
            tenants
                .binary_search(&tenant)
                .is_ok()
                .then(|| AnalysisContextKeyV1 {
                    tenant_id: tenant,
                    owner_id: owner.into(),
                    entity_key: entity.to_vec(),
                    lifetime_key: lifetime.to_vec(),
                    owner_revision: 1,
                })
        };
        match self {
            Self::Policy(id) => {
                let source = state.source_revisions.get(id)?;
                selected(&source.tenant_id).map(|tenant| {
                    let document = state.policy_documents.get(id).ok_or_else(|| {
                        crate::error::ControlStoreSnafu {
                            path: inner.root.clone(),
                            reason: "the context source has no committed policy document"
                                .to_owned(),
                        }
                        .build()
                    })?;
                    ControlStore::encode_context(
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
                })
            }
            Self::Compiled(id) => {
                let source = state.source_revisions.get(id)?;
                let artifact = state.compiled_artifacts.get(id)?;
                selected(&source.tenant_id).map(|tenant| {
                    let digest = super::artifact_digest(artifact, &inner.root)?;
                    let proof = CompiledPolicyContextV1 {
                        source_revision_id: id.clone(),
                        signed_profile_digest: digest.clone(),
                        profile_id: artifact.header.profile_id.clone(),
                        profile_version: artifact.header.profile_version,
                        policy_document_digest: artifact.header.policy_document_digest.clone(),
                        execution_set_ids: artifact
                            .policy_document
                            .protected_universe
                            .execution_set_ids
                            .clone(),
                        compiled_keys: artifact
                            .compiled_profile
                            .compiled_cells
                            .iter()
                            .map(|cell| DiscoveryPolicyKeyV1::try_from(&cell.key))
                            .collect::<araphor_data::Result<_>>()?,
                    };
                    Ok(AnalysisContextVersionV1 {
                        key: AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: "mithril-control/compiled-policy".into(),
                            entity_key: id.as_bytes().to_vec(),
                            lifetime_key: digest.into_bytes(),
                            owner_revision: 1,
                        },
                        valid_from_utc_ns: None,
                        valid_until_utc_ns: None,
                        sensitivity: ContextSensitivityV1::Tenant,
                        body: proof.encode()?,
                    })
                })
            }
            Self::Trust(generation) => {
                let trust = state.trust_generations.get(generation)?;
                let index = position.map_or(0, |(index, _)| index);
                let tenant = *tenants.get(index)?;
                *position = (index + 1 < tenants.len()).then_some((index + 1, 0));
                Some(ControlStore::encode_context(
                    &inner.root,
                    AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: "mithril-control/trust".into(),
                        entity_key: b"trust".to_vec(),
                        lifetime_key: trust.bundle_digest.as_bytes().to_vec(),
                        owner_revision: *generation,
                    },
                    trust,
                ))
            }
            Self::Rollout(id) => {
                let rollout = state.rollout_states.get(id)?;
                selected(&rollout.target.tenant_id).map(|tenant| {
                    ControlStore::encode_context(
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
                })
            }
            Self::Candidate(id) => {
                let bundle = state.bundles.get(id)?;
                selected(&bundle.candidate.tenant_id)?;
                super::graph::GraphCandidate::capture(inner, id)
            }
            Self::Acknowledgement(id, version) => {
                let result = state
                    .policy_acknowledgement_results
                    .get(&(id.clone(), *version))?;
                let ack = &result.acknowledgement;
                let tenant = selected(&ack.tenant_id)?;
                Some(ControlStore::encode_context(
                    &inner.root,
                    AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: "mithril-control/activation-ack".into(),
                        entity_key: id.candidate_content_id.as_bytes().to_vec(),
                        lifetime_key: id.node_id.as_bytes().to_vec(),
                        owner_revision: *version,
                    },
                    ack,
                ))
            }
            Self::Target(id) => {
                let snapshot = state.target_snapshots.get(id)?;
                let (target_index, fact_index) = position.unwrap_or_default();
                let Some(target) = snapshot.targets.get(target_index) else {
                    *position = None;
                    return None;
                };
                let Some(fact) = target.workload_targets.get(fact_index) else {
                    *position = Some((target_index + 1, 0));
                    return None;
                };
                *position = Some((target_index, fact_index + 1));
                selected(&target.tenant_id).map(|tenant| {
                    let entity = fact
                        .kubernetes
                        .as_ref()
                        .map_or(fact.execution_set_id.as_str(), |identity| {
                            identity.binding_id.as_str()
                        });
                    ControlStore::encode_context(
                        &inner.root,
                        AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: "mithril-control/target".into(),
                            entity_key: entity.as_bytes().to_vec(),
                            lifetime_key: format!(
                                "{}:{}",
                                snapshot.target_snapshot_digest,
                                fact.workload_binding_generation_digest
                            )
                            .into_bytes(),
                            owner_revision: 1,
                        },
                        &TargetContextV1 {
                            workload: fact.clone(),
                            workload_digest_valid: crate::workload_target_fact_digest(fact)?
                                == fact.workload_binding_generation_digest,
                            policy_source_revision_id: snapshot.policy_source_revision_id.clone(),
                            target_snapshot_digest: snapshot.target_snapshot_digest.clone(),
                            signed_profile_digest: snapshot.signed_profile_digest.clone(),
                        },
                    )
                })
            }
            Self::Request(id) => {
                let request = state.authority.requests.get(id)?;
                Some(ControlStore::encode_context(
                    &inner.root,
                    key(
                        "mithril-control/authority-request",
                        request.tenant_id,
                        *id,
                        request.body.request_nonce,
                    )?,
                    request,
                ))
            }
            Self::Approval(id) => {
                let approval = state.authority.approvals.get(id)?;
                Some(ControlStore::encode_context(
                    &inner.root,
                    key(
                        "mithril-control/authority-approval",
                        approval.tenant_id,
                        *id,
                        approval.proof_id,
                    )?,
                    &PublicAuthorityApproval::from(approval),
                ))
            }
            Self::Lease(id) => {
                let lease = state.authority.leases.get(id)?;
                Some(ControlStore::encode_context(
                    &inner.root,
                    key(
                        "mithril-control/authority-lease",
                        lease.tenant_id,
                        *id,
                        lease.request_nonce,
                    )?,
                    lease,
                ))
            }
            Self::Audit(id) => {
                let handle = state.authority.handles.get(id)?;
                Some(ControlStore::encode_context(
                    &inner.root,
                    key(
                        "mithril-control/authority-audit",
                        handle.tenant_id,
                        *id,
                        handle.lease_id,
                    )?,
                    handle,
                ))
            }
        }
    }
}

/// Copies committed Control facts. Copies never grant policy authority.
pub struct ControlContextOwner {
    store: ControlStore,
    data: Arc<AnalysisStore>,
    tenants: Vec<[u8; 16]>,
    revision: Option<u64>,
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
        Ok(Self {
            store,
            data,
            tenants: tenants.into_iter().collect(),
            revision: None,
        })
    }

    /// Commits all changed facts from one Control revision in one Data transaction.
    pub fn reconcile(&mut self) -> Result<usize> {
        let (revision, records) = self.store.context_records(&self.tenants, self.revision)?;
        if !records.is_empty() {
            self.data
                .commit_contexts(&records)
                .map_err(|source| crate::Error::DataStore {
                    source: Box::new(source),
                    location: snafu::Location::default(),
                })?;
        }
        self.revision = Some(revision);
        Ok(records.len())
    }
}

impl ControlStore {
    #[cfg(test)]
    pub(crate) fn subscribe_revision(&self) -> Result<tokio::sync::watch::Receiver<u64>> {
        Ok(self.lock()?.changes.subscribe())
    }

    pub(crate) fn subscribe_context(&self) -> Result<tokio::sync::watch::Receiver<u64>> {
        Ok(self.lock()?.context_index.changes.subscribe())
    }

    fn context_records(
        &self,
        tenants: &[[u8; 16]],
        since: Option<u64>,
    ) -> Result<(u64, Vec<AnalysisContextVersionV1>)> {
        let inner = self.evidence_lock()?;
        let revision = inner.state.commit_index;
        let mut records = Vec::new();
        if tenants.is_empty()
            || since.is_some_and(|since| *inner.context_index.changes.borrow() <= since)
        {
            return Ok((revision, records));
        }
        for (source, changed) in &inner.context_index.sources {
            if since.is_some_and(|since| *changed <= since) {
                continue;
            }
            let mut position = None;
            loop {
                if let Some(record) = source.record(&inner, tenants, &mut position) {
                    records.push(record?);
                }
                if position.is_none() {
                    break;
                }
            }
        }
        Ok((revision, records))
    }

    pub(super) fn encode_context(
        path: &std::path::Path,
        key: AnalysisContextKeyV1,
        fact: &impl Serialize,
    ) -> Result<AnalysisContextVersionV1> {
        Ok(AnalysisContextVersionV1 {
            key,
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(fact).context(JsonSnafu { path })?,
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
            vec![(target.clone(), None)],
            crate::PolicyDeliveryOperationV1::Activate,
            1,
            1,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )?;
        let first = rollout.target_snapshot.clone();
        let predecessor = rollout
            .bundles
            .first()
            .ok_or("missing first candidate")?
            .candidate
            .candidate_content_id
            .clone();
        store.create_rollout(
            rollout.target_snapshot,
            rollout.bundles,
            rollout.rollout_states,
        )?;
        let second = source_revision(&document, crate::PolicySourceStateV1::Accepted, 2, '9')?;
        let artifact = signed_artifact(&document, 2)?;
        store.accept_compiled_source_revision(
            second.clone(),
            document.clone(),
            artifact.clone(),
        )?;
        let rollout = rollout_transaction(
            &second,
            &artifact,
            vec![(target, Some(predecessor))],
            crate::PolicyDeliveryOperationV1::Replace,
            2,
            2,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )?;
        let snapshots = [first, rollout.target_snapshot.clone()];
        assert_eq!(snapshots[0].targets, snapshots[1].targets);
        assert_ne!(
            snapshots[0].policy_source_revision_id,
            snapshots[1].policy_source_revision_id
        );
        assert_ne!(
            snapshots[0].signed_profile_digest,
            snapshots[1].signed_profile_digest
        );
        assert_ne!(
            snapshots[0].target_snapshot_digest,
            snapshots[1].target_snapshot_digest
        );
        store.create_rollout(
            rollout.target_snapshot,
            rollout.bundles,
            rollout.rollout_states,
        )?;
        assert_eq!(
            store
                .evidence_lock()?
                .context_index
                .sources
                .keys()
                .filter(|source| matches!(source, ContextSource::Target(_)))
                .count(),
            2
        );
        let authority = store.commit_index();
        let tenant = uuid::Uuid::parse_str(&source.tenant_id)?.into_bytes();
        let allowed = [AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: source.tenant_id,
        }];
        let key =
            |snapshot: &crate::PolicyTargetSnapshotV1,
             fact: &crate::WorkloadTargetFactV1|
             -> std::result::Result<AnalysisContextKeyV1, Box<dyn std::error::Error>> {
                Ok(AnalysisContextKeyV1 {
                    tenant_id: tenant,
                    owner_id: "mithril-control/target".into(),
                    entity_key: fact
                        .kubernetes
                        .as_ref()
                        .ok_or("missing identity")?
                        .binding_id
                        .as_bytes()
                        .to_vec(),
                    lifetime_key: format!(
                        "{}:{}",
                        snapshot.target_snapshot_digest, fact.workload_binding_generation_digest
                    )
                    .into_bytes(),
                    owner_revision: 1,
                })
            };
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, snapshots.len() * (facts.len() + 4));
        assert_eq!(data.meta()?.commit_revision, 1);
        assert_eq!(owner.revision, Some(authority));
        for snapshot in &snapshots {
            for fact in &facts {
                let context = data
                    .context_version(&key(snapshot, fact)?)?
                    .ok_or("missing retained target")?;
                let retained: TargetContextV1 = serde_json::from_slice(&context.body)?;
                assert_eq!(retained.workload, *fact);
                assert!(retained.workload_digest_valid);
                assert_eq!(
                    retained.policy_source_revision_id,
                    snapshot.policy_source_revision_id
                );
                assert_eq!(
                    retained.target_snapshot_digest,
                    snapshot.target_snapshot_digest
                );
                assert_eq!(
                    retained.signed_profile_digest,
                    snapshot.signed_profile_digest
                );
                assert_eq!(context.sensitivity, ContextSensitivityV1::Tenant);
                assert_eq!(context.valid_from_utc_ns, None);
                assert_eq!(context.valid_until_utc_ns, None);
                let mut foreign = context.key.clone();
                foreign.tenant_id = [9; 16];
                assert!(data.context_version(&foreign)?.is_none());
            }
        }
        let before = data.meta()?;
        assert_eq!(store.commit_index(), authority);
        drop(owner);
        drop(store);
        drop(data);
        let store = ControlStore::open(store_path)?;
        let data = Arc::new(AnalysisStore::open(data_path)?);
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, snapshots.len() * (facts.len() + 4));
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(data.meta()?, before);
        assert_eq!(store.commit_index(), authority);
        for snapshot in &snapshots {
            for fact in &facts {
                assert!(data.context_version(&key(snapshot, fact)?)?.is_some());
            }
        }
        Ok(())
    }

    #[test]
    fn control_context_compiled_refresh() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let control_path = directory.path().join("control");
        let data_path = directory.path().join("data");
        let store = ControlStore::open(&control_path)?;
        let data = Arc::new(AnalysisStore::open(&data_path)?);
        let document = crate::PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, crate::PolicySourceStateV1::Accepted, 1, '8')?;
        let tenant = uuid::Uuid::parse_str(&source.tenant_id)?.into_bytes();
        let artifact = signed_artifact(&document, 1)?;
        store.accept_compiled_source_revision(source.clone(), document.clone(), artifact)?;
        let target = kubernetes_target(
            &source,
            &document,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            1,
        )?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let initial = rollout_transaction(
            &source,
            &store
                .compiled_artifact(&source.policy_source_revision_id)?
                .ok_or("missing initial artifact")?,
            vec![(target.clone(), None)],
            crate::PolicyDeliveryOperationV1::Activate,
            document.rollout.rollout_generation,
            1,
            &signing,
        )?;
        let initial_digest = initial.target_snapshot.signed_profile_digest.clone();
        let predecessor = initial.bundles[0].candidate.candidate_content_id.clone();
        store.create_rollout(
            initial.target_snapshot,
            initial.bundles,
            initial.rollout_states,
        )?;
        let allowed = [AllowedNodeIdentity {
            node_id: target.node_id.clone(),
            certificate_sha256: "a".repeat(64),
            tenant_id: source.tenant_id.clone(),
        }];
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 5);
        let artifact = signed_artifact(&document, 2)?;
        let refreshed = rollout_transaction(
            &source,
            &artifact,
            vec![(target, Some(predecessor))],
            crate::PolicyDeliveryOperationV1::Replace,
            document.rollout.rollout_generation,
            2,
            &signing,
        )?;
        let snapshot = refreshed.target_snapshot.clone();
        let mut notices = store.subscribe_context()?;
        store.reconcile_target_set(
            refreshed.target_snapshot,
            refreshed.bundles,
            refreshed.rollout_states,
            Some(artifact.clone()),
        )?;
        assert!(notices.has_changed()?);
        notices.borrow_and_update();
        assert_eq!(owner.reconcile()?, 4);
        assert_eq!(data.meta()?.commit_revision, 2);
        let proof_key = |digest: &str| AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: "mithril-control/compiled-policy".into(),
            entity_key: source.policy_source_revision_id.as_bytes().to_vec(),
            lifetime_key: digest.as_bytes().to_vec(),
            owner_revision: 1,
        };
        assert!(data.context_version(&proof_key(&initial_digest))?.is_some());
        let retained = data
            .context_version(&proof_key(&snapshot.signed_profile_digest))?
            .ok_or("missing refreshed proof")?;
        let expected = CompiledPolicyContextV1 {
            source_revision_id: source.policy_source_revision_id.clone(),
            signed_profile_digest: snapshot.signed_profile_digest.clone(),
            profile_id: artifact.header.profile_id.clone(),
            profile_version: artifact.header.profile_version,
            policy_document_digest: artifact.header.policy_document_digest.clone(),
            execution_set_ids: artifact
                .policy_document
                .protected_universe
                .execution_set_ids
                .clone(),
            compiled_keys: artifact
                .compiled_profile
                .compiled_cells
                .iter()
                .map(|cell| DiscoveryPolicyKeyV1::try_from(&cell.key))
                .collect::<araphor_data::Result<_>>()?,
        };
        assert_eq!(retained.body, expected.encode()?);
        let columns = araphor_data::AnalysisTableRequests::from([
            ("compiled_policies".into(), Some(Default::default())),
            ("targets".into(), Some(Default::default())),
        ]);
        let page = data.read_tables(
            &araphor_data::AnalysisSelectionV1::tenant(tenant),
            araphor_data::AnalysisTableRead {
                requests: &columns,
                event_ranges: None,
                inputs: None,
                mode: araphor_data::AnalysisReadModeV1::Complete,
                now: 1,
            },
            araphor_data::AnalysisExtractLimits::default(),
            &araphor_data::AnalysisReadControl::default(),
        )?;
        let refreshed_refs = page
            .extraction
            .references
            .iter()
            .filter_map(|value| value.context())
            .filter(|reference| {
                reference.key == retained.key
                    || (reference.key.owner_id == "mithril-control/target"
                        && reference
                            .key
                            .lifetime_key
                            .starts_with(snapshot.target_snapshot_digest.as_bytes()))
            })
            .collect::<Vec<_>>();
        assert_eq!(refreshed_refs.len(), 2);
        assert!(refreshed_refs
            .iter()
            .all(|reference| reference.commit_revision == 2));
        let before = data.meta()?;
        drop(owner);
        drop(store);
        drop(data);
        let store = ControlStore::open(control_path)?;
        let data = Arc::new(AnalysisStore::open(data_path)?);
        let mut owner = ControlContextOwner::new(store, data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 8);
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(data.meta()?, before);
        assert_eq!(data.context_version(&retained.key)?, Some(retained));
        assert!(data.context_version(&proof_key(&initial_digest))?.is_some());
        Ok(())
    }

    #[test]
    fn discovery_context_notices_without_projection(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = AnalysisStore::open(directory.path().join("data"))?;
        let mut changes = store.subscribe_revision()?;
        assert!(!changes.has_changed()?);
        assert_eq!(data.meta()?.commit_revision, 0);
        store.install_trust_generation(TrustGenerationV1 {
            generation: 1,
            bundle_digest: "a".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        assert!(changes.has_changed()?);
        assert_eq!(*changes.borrow_and_update(), store.commit_index());
        assert_eq!(data.meta()?.commit_revision, 0);
        assert!(!changes.has_changed()?);
        Ok(())
    }

    #[test]
    fn control_context_relevant_notices() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
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
        let mut changes = store.subscribe_context()?;
        let mut global = store.subscribe_revision()?;
        let context_revision = *changes.borrow_and_update();
        assert!(!changes.has_changed()?);
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 1);
        let before = data.meta()?;
        store.update_authority(|state| Ok(state.proofs.insert([7; 16])))?;
        assert!(global.has_changed()?);
        assert_eq!(*global.borrow_and_update(), store.commit_index());
        assert!(!changes.has_changed()?);
        assert_eq!(*changes.borrow(), context_revision);
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert_eq!(data.meta()?, before);
        store.install_trust_generation(TrustGenerationV1 {
            generation: 2,
            bundle_digest: "b".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        assert!(global.has_changed()?);
        assert!(changes.has_changed()?);
        assert_eq!(*changes.borrow_and_update(), store.commit_index());
        assert_eq!(data.meta()?, before);
        assert_eq!(owner.reconcile()?, 1);
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
        assert!(!changes.has_changed()?);
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
                logical_max_bytes: Some(1),
                tenant_max_bytes: Some(1),
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
            assert_eq!(owner.revision, None);
            assert_eq!(data.meta()?.commit_revision, 0);
        }
        Ok(())
    }

    #[test]
    fn control_context_captured_revision() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path().join("control"))?;
        let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let allowed = [AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }];
        for generation in 1..=2 {
            store.install_trust_generation(TrustGenerationV1 {
                generation,
                bundle_digest: format!("{generation:064x}"),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            })?;
        }
        let mut changes = store.subscribe_context()?;
        changes.borrow_and_update();
        let (revision, records) = store.context_records(&[[1; 16]], None)?;
        assert_eq!(records.len(), 2);
        assert_eq!(revision, store.commit_index());
        store.install_trust_generation(TrustGenerationV1 {
            generation: 3,
            bundle_digest: format!("{:064x}", 3),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        let references = data.commit_contexts(&records)?;
        assert_eq!(references.len(), 2);
        assert!(references
            .iter()
            .all(|reference| reference.commit_revision == 1));
        for record in &records {
            assert_eq!(data.context_version(&record.key)?, Some(record.clone()));
        }
        let later = AnalysisContextKeyV1 {
            owner_revision: 3,
            lifetime_key: format!("{:064x}", 3).into_bytes(),
            ..records[0].key.clone()
        };
        assert!(data.context_version(&later)?.is_none());
        assert!(changes.has_changed()?);
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        owner.revision = Some(revision);
        assert_eq!(owner.reconcile()?, 1);
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert_eq!(data.meta()?.commit_revision, 2);
        assert!(data.context_version(&later)?.is_some());
        for record in &records {
            assert_eq!(data.context_version(&record.key)?, Some(record.clone()));
        }
        Ok(())
    }

    #[test]
    fn control_context_atomic_replay() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(owner.reconcile()?, 20);
        assert_eq!(data.meta()?.commit_revision, 1);
        let before = data.meta()?;
        assert_eq!(owner.revision, Some(authority));
        assert_eq!(owner.reconcile()?, 0);
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
        drop(store);
        drop(data);
        let store = ControlStore::open(directory.path().join("control"))?;
        assert_eq!(store.commit_index(), authority);
        let reopened = Arc::new(AnalysisStore::open(data_path)?);
        assert_eq!(reopened.context_version(&key)?, Some(context));
        let mut owner = ControlContextOwner::new(store, reopened.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 20);
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(reopened.meta()?, before);
        let mut changes = owner.store.subscribe_context()?;
        let oversized = TrustGenerationV1 {
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
        let pending = owner.store.evidence_lock()?.state_file.temporary.clone();
        std::fs::create_dir(&pending)?;
        assert!(owner
            .store
            .install_trust_generation(oversized.clone())
            .is_err());
        assert_eq!(owner.store.commit_index(), authority);
        assert!(!owner
            .store
            .evidence_lock()?
            .context_index
            .sources
            .contains_key(&ContextSource::Trust(21)));
        assert!(!changes.has_changed()?);
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.revision, Some(authority));
        assert_eq!(reopened.meta()?, before);
        std::fs::remove_dir(&pending)?;
        owner.store.install_trust_generation(oversized.clone())?;
        let mut latest = oversized.clone();
        latest.generation = 22;
        latest.policy_signers.clear();
        owner.store.install_trust_generation(latest)?;
        assert_ne!(owner.revision, Some(owner.store.commit_index()));
        assert!(changes.has_changed()?);
        assert_eq!(reopened.meta()?, before);
        changes.borrow_and_update();
        assert_eq!(owner.reconcile()?, 2);
        assert_eq!(reopened.meta()?.commit_revision, before.commit_revision + 1);
        assert_eq!(owner.revision, Some(owner.store.commit_index()));
        assert!(!changes.has_changed()?);
        let large = reopened
            .context_version(&AnalysisContextKeyV1 {
                lifetime_key: oversized.bundle_digest.as_bytes().to_vec(),
                owner_revision: oversized.generation,
                ..key.clone()
            })?
            .ok_or("missing large trust")?;
        assert!(large.body.len() > 32 * 1024);
        assert_eq!(
            serde_json::from_slice::<TrustGenerationV1>(&large.body)?,
            oversized
        );
        let trust = owner
            .store
            .current_trust_generation()?
            .ok_or("missing trust")?;
        let context = reopened
            .context_version(&AnalysisContextKeyV1 {
                lifetime_key: trust.bundle_digest.as_bytes().to_vec(),
                owner_revision: trust.generation,
                ..key
            })?
            .ok_or("missing changed trust")?;
        assert_eq!(
            serde_json::from_slice::<TrustGenerationV1>(&context.body)?,
            trust
        );
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
        assert_eq!(owner.revision, Some(owner.store.commit_index()));
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
        assert_eq!(owner.revision, Some(store.commit_index()));
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
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert_eq!(data.meta()?, before);
        let published = owner.revision;
        store.update_authority(|state| {
            let approval = state.approvals.get_mut(&[2; 16]).ok_or_else(|| {
                crate::AuthorityErrorCodeV1::Invalid.error("missing test approval")
            })?;
            approval.state = crate::AuthorityIntentStateV1::Cancelled;
            Ok(true)
        })?;
        store.install_trust_generation(TrustGenerationV1 {
            generation: 1,
            bundle_digest: "a".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        let trust = AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "mithril-control/trust".into(),
            entity_key: b"trust".to_vec(),
            lifetime_key: vec![b'a'; 64],
            owner_revision: 1,
        };
        for _ in 0..2 {
            assert!(
                matches!(owner.reconcile(), Err(crate::Error::DataStore { source, .. })
                if matches!(*source, araphor_data::Error::AnalysisConflict { .. }))
            );
            assert_eq!(owner.revision, published);
            assert_eq!(data.meta()?, before);
            assert!(data.context_version(&trust)?.is_none());
            assert_eq!(data.context_version(&prior.key)?, Some(prior.clone()));
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
            store
                .evidence_lock()?
                .context_index
                .sources
                .keys()
                .filter_map(|source| match source {
                    ContextSource::Approval(id) => Some(*id),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![[8; 16]]
        );
        assert_eq!(owner.reconcile()?, 2);
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert!(data.context_version(&trust)?.is_some());
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
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &[])?;
        assert_eq!(owner.reconcile()?, 0);
        store.update_authority(|state| Ok(state.proofs.insert([7; 16])))?;
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.revision, Some(store.commit_index()));
        let allowed: Vec<_> = [1, 2]
            .into_iter()
            .map(|tenant| AllowedNodeIdentity {
                node_id: format!("node-{tenant}"),
                certificate_sha256: "a".repeat(64),
                tenant_id: uuid::Uuid::from_bytes([tenant; 16]).to_string(),
            })
            .collect();
        let mut owner = ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.revision, Some(store.commit_index()));
        store.update_authority(|state| Ok(state.proofs.insert([8; 16])))?;
        assert_eq!(owner.reconcile()?, 0);
        assert_eq!(owner.revision, Some(store.commit_index()));
        store.install_trust_generation(TrustGenerationV1 {
            generation: 1,
            bundle_digest: "a".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })?;
        assert_ne!(owner.revision, Some(store.commit_index()));
        assert_eq!(owner.reconcile()?, 2);
        assert_eq!(owner.revision, Some(store.commit_index()));
        assert_eq!(owner.reconcile()?, 0);
        for tenant in [1, 2] {
            assert!(data
                .context_version(&AnalysisContextKeyV1 {
                    tenant_id: [tenant; 16],
                    owner_id: "mithril-control/trust".into(),
                    entity_key: b"trust".to_vec(),
                    lifetime_key: vec![b'a'; 64],
                    owner_revision: 1,
                })?
                .is_some());
        }
        Ok(())
    }
}
