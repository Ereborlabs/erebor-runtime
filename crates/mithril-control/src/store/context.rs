use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::Arc;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, ContextSensitivityV1,
};
use serde::Serialize;
use snafu::ResultExt as _;

use super::{ControlStore, PolicyRolloutKeyV1};
use crate::{error::JsonSnafu, AllowedNodeIdentity, Result};

pub(super) struct ContextLimit(pub(super) usize);

impl std::io::Write for ContextLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("the policy context exceeds its byte bound"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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

/// Copies committed Control facts. Copies never grant policy authority.
pub struct ControlContextOwner {
    store: ControlStore,
    data: Arc<AnalysisStore>,
    tenants: Vec<[u8; 16]>,
    tenant: usize,
    cursor: ContextCursor,
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
            tenant: 0,
            cursor: ContextCursor::Policy(None),
        })
    }

    /// Reads at most 16 Control entries. Storage failures keep the retry cursor.
    pub fn reconcile(&mut self) -> Result<usize> {
        if self.tenants.is_empty() {
            return Ok(0);
        }
        let mut copied = 0;
        for _ in 0..16 {
            let (record, next) = self
                .store
                .next_context(self.tenants[self.tenant], &self.cursor)?;
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
                self.tenant = (self.tenant + 1) % self.tenants.len();
                break;
            }
        }
        Ok(copied)
    }
}

impl ControlStore {
    fn next_context(
        &self,
        tenant: [u8; 16],
        cursor: &ContextCursor,
    ) -> Result<(Option<Result<AnalysisContextVersionV1>>, ContextCursor)> {
        // ponytail: scan each tenant in bounded pages; add a tenant index if scans dominate.
        let inner = self.evidence_lock()?;
        let matches = |id: &str| uuid::Uuid::parse_str(id).is_ok_and(|id| id.as_bytes() == &tenant);
        let record = match cursor {
            ContextCursor::Policy(after) => {
                let bounds = (after.as_ref().map_or(Unbounded, Excluded), Unbounded);
                let Some((id, source)) = inner
                    .state
                    .source_revisions
                    .range::<String, _>(bounds)
                    .next()
                else {
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
                let Some((generation, trust)) = inner.state.trust_generations.range(bounds).next()
                else {
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
                let Some((key, rollout)) = inner.state.rollout_states.range(bounds).next() else {
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
                let Some((id, snapshot)) = inner
                    .state
                    .target_snapshots
                    .range::<String, _>(bounds)
                    .next()
                else {
                    return Ok((None, ContextCursor::Authority(0, None)));
                };
                let (target_index, fact_index) = if after.as_ref() == Some(id) {
                    (*target_index, *fact_index)
                } else {
                    (0, 0)
                };
                let Some(target) = snapshot.targets.get(target_index) else {
                    let next = inner
                        .state
                        .target_snapshots
                        .range::<String, _>((Excluded(id), Unbounded))
                        .next()
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
                        let Some((id, request)) = authority.requests.range::<[u8; 16], _>(bounds).next() else {
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
                        let Some((id, approval)) = authority.approvals.range::<[u8; 16], _>(bounds).next() else {
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
                        let Some((id, lease)) = authority.leases.range::<[u8; 16], _>(bounds).next() else {
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
                        let Some((id, handle)) = authority.handles.range::<[u8; 16], _>(bounds).next() else {
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
        serde_json::to_writer(ContextLimit(32 * 1024), fact).context(JsonSnafu { path })?;
        let body = serde_json::to_vec(fact).context(JsonSnafu { path })?;
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
        assert_eq!(owner.reconcile()?, 15);
        assert!(owner.reconcile().is_err());
        assert_eq!(reopened.meta()?, before);
        assert_eq!(owner.reconcile()?, 1);
        assert_eq!(reopened.meta()?.commit_revision, before.commit_revision + 1);
        Ok(())
    }
}
