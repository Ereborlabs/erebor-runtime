use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, ContextSensitivityV1,
};
use serde::Serialize;
use snafu::ResultExt as _;

use super::{ControlStore, PolicyRolloutKeyV1};
use crate::{error::JsonSnafu, AllowedNodeIdentity, Result};

#[derive(Serialize)]
struct PolicyContext<'a> {
    source: &'a crate::PolicySourceRevisionV1,
    document: &'a crate::PolicyDocumentV1,
}

enum ContextCursor {
    Policy(Option<String>),
    Trust(Option<u64>),
    Rollout(Option<PolicyRolloutKeyV1>),
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

    /// Reads at most 16 Control entries. A failed entry is retried on the next pass.
    pub fn reconcile(&mut self) -> Result<usize> {
        if self.tenants.is_empty() {
            return Ok(0);
        }
        let mut copied = 0;
        for _ in 0..16 {
            let (record, next) = self
                .store
                .next_context(self.tenants[self.tenant], &self.cursor)?;
            self.cursor = next;
            if let Some(record) = record {
                self.data
                    .commit_context(&record?)
                    .map_err(|source| crate::Error::DataStore {
                        source: Box::new(source),
                        location: snafu::Location::default(),
                    })?;
                copied += 1;
            }
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
                    return Ok((None, ContextCursor::End));
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
            ContextCursor::End => (None, ContextCursor::End),
        };
        Ok(record)
    }

    fn encode_context(
        path: &std::path::Path,
        key: AnalysisContextKeyV1,
        fact: &impl Serialize,
    ) -> Result<AnalysisContextVersionV1> {
        serde_json::to_writer(crate::discovery::InputByteLimit(32 * 1024), fact)
            .context(JsonSnafu { path })?;
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
    use super::*;
    use crate::TrustGenerationV1;

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
