use super::*;
use crate::{CompiledDecisionCellV1, ObjectClassifierSelectorV1, PolicyDeliveryCandidateV1};
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct GraphCandidate {
    pub(super) candidate: PolicyDeliveryCandidateV1,
    pub(super) source_tenant: String,
    pub(super) profile_id: String,
    pub(super) profile_version: u64,
    pub(super) policy_digest: String,
    pub(super) cells: Vec<CompiledDecisionCellV1>,
    pub(super) execution_sets: Vec<String>,
    pub(super) credential_objects: Vec<String>,
}

impl GraphCandidate {
    pub(in crate::store) fn capture(
        inner: &ControlStoreInner,
        id: &str,
    ) -> Option<Result<AnalysisContextVersionV1>> {
        let bundle = inner.state.bundles.get(id)?;
        let candidate = &bundle.candidate;
        let source = inner
            .state
            .source_revisions
            .get(&candidate.policy_source_revision_id)?;
        let tenant = uuid::Uuid::parse_str(&candidate.tenant_id)
            .ok()?
            .into_bytes();
        let artifact = &bundle.profile_artifact;
        let classes = artifact
            .policy_document
            .classifier_bindings
            .iter()
            .filter(|binding| {
                matches!(
                    binding.selector,
                    ObjectClassifierSelectorV1::ProjectedServiceAccountToken { .. }
                )
            })
            .map(|binding| binding.object_class_id.as_str())
            .collect::<BTreeSet<_>>();
        let material = Self {
            candidate: candidate.clone(),
            source_tenant: source.tenant_id.clone(),
            profile_id: artifact.header.profile_id.clone(),
            profile_version: artifact.header.profile_version,
            policy_digest: artifact.header.policy_document_digest.clone(),
            cells: artifact.compiled_profile.compiled_cells.clone(),
            execution_sets: artifact
                .policy_document
                .protected_universe
                .execution_set_ids
                .clone(),
            credential_objects: classes
                .iter()
                .map(|id| format!("CLASS:{id}"))
                .chain(
                    artifact
                        .policy_document
                        .path_selectors
                        .iter()
                        .filter(|selector| classes.contains(selector.object_class_id.as_str()))
                        .map(|selector| format!("PATH:{}", selector.path_selector_id)),
                )
                .collect(),
        };
        Some(ControlStore::encode_context(
            &inner.root,
            AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "mithril-control/policy-candidate".into(),
                entity_key: id.as_bytes().to_vec(),
                lifetime_key: candidate.exact_target.node_id.as_bytes().to_vec(),
                owner_revision: 1,
            },
            &material,
        ))
    }
}

pub(super) struct GraphContext {
    pub(super) candidates: BTreeMap<String, GraphCandidate>,
    pub(super) acknowledgements:
        BTreeMap<(PolicyRolloutKeyV1, u64), PolicyActivationAcknowledgementV1>,
}

impl GraphContext {
    pub(super) fn new(contexts: &[AnalysisContextVersionV1]) -> Result<Self> {
        let mut candidates = BTreeMap::new();
        let mut acknowledgements = BTreeMap::new();
        for context in contexts {
            let key = &context.key;
            match key.owner_id.as_str() {
                "mithril-control/policy-candidate" => {
                    let material: GraphCandidate =
                        serde_json::from_slice(&context.body).map_err(|source| {
                            crate::error::DiscoverySnafu {
                                code: "GRAPH_CANDIDATE",
                                reason: source.to_string(),
                            }
                            .build()
                        })?;
                    let candidate = &material.candidate;
                    if key.tenant_id == [0; 16]
                        || material.candidate.schema_version != 1
                        || key.owner_revision != 1
                        || uuid::Uuid::parse_str(&candidate.tenant_id)
                            .ok()
                            .map(|id| id.into_bytes())
                            != Some(key.tenant_id)
                        || key.entity_key != candidate.candidate_content_id.as_bytes()
                        || key.lifetime_key != candidate.exact_target.node_id.as_bytes()
                        || candidate.exact_target.tenant_id != candidate.tenant_id
                        || context.valid_from_utc_ns.is_some()
                        || context.valid_until_utc_ns.is_some()
                        || context.sensitivity != ContextSensitivityV1::Tenant
                    {
                        return crate::error::DiscoverySnafu {
                            code: "GRAPH_CANDIDATE",
                            reason: "the retained candidate identity differs".to_owned(),
                        }
                        .fail();
                    }
                    match candidates.entry(candidate.candidate_content_id.clone()) {
                        Entry::Occupied(previous) if previous.get() != &material => {
                            return crate::error::DiscoverySnafu {
                                code: "GRAPH_CANDIDATE",
                                reason: "the retained candidate changed".to_owned(),
                            }
                            .fail();
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(material);
                        }
                        Entry::Occupied(_) => {}
                    }
                }
                "mithril-control/activation-ack" => {
                    let ack: PolicyActivationAcknowledgementV1 =
                        serde_json::from_slice(&context.body).map_err(|source| {
                            crate::error::DiscoverySnafu {
                                code: "GRAPH_ACK",
                                reason: source.to_string(),
                            }
                            .build()
                        })?;
                    ack.validate()?;
                    if key.tenant_id == [0; 16]
                        || key.owner_revision == 0
                        || uuid::Uuid::parse_str(&ack.tenant_id)
                            .ok()
                            .map(|id| id.into_bytes())
                            != Some(key.tenant_id)
                        || key.entity_key != ack.candidate_content_id.as_bytes()
                        || key.lifetime_key != ack.node_id.as_bytes()
                        || context.valid_from_utc_ns.is_some()
                        || context.valid_until_utc_ns.is_some()
                        || context.sensitivity != ContextSensitivityV1::Tenant
                    {
                        return crate::error::DiscoverySnafu {
                            code: "GRAPH_ACK",
                            reason: "the retained acknowledgement identity differs".to_owned(),
                        }
                        .fail();
                    }
                    let identity = (
                        PolicyRolloutKeyV1 {
                            candidate_content_id: ack.candidate_content_id.clone(),
                            node_id: ack.node_id.clone(),
                        },
                        key.owner_revision,
                    );
                    match acknowledgements.entry(identity) {
                        Entry::Occupied(previous) if previous.get() != &ack => {
                            return crate::error::DiscoverySnafu {
                                code: "GRAPH_ACK",
                                reason: "the retained acknowledgement changed".to_owned(),
                            }
                            .fail();
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(ack);
                        }
                        Entry::Occupied(_) => {}
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            candidates,
            acknowledgements,
        })
    }
}
