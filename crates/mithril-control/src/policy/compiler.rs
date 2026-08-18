use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;

use super::canonical::canonical_cbor;
use super::source::{
    BindingLifecycleV1, EffectFamilyV1, EntryKindV1, PolicyDocumentV1, ProfileModeV1, RuleMatchV1,
};
use super::validation::Validate as _;
use crate::error::PolicyValidationSnafu;
use crate::Result;

mod conversion;
mod expansion;

pub use conversion::CompiledOperationV1;
use expansion::{LocalActionPlan, RuleDecision, RuleDimensions};

const MAX_COMPILED_CELLS: usize = 65_536;

/// One exact selector key after the compiler expands all policy dimensions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct StaticDecisionKeyV1 {
    pub workload_selector_id: String,
    pub protected_scope_id: String,
    pub execution_set_id: String,
    pub entry_kind: EntryKindV1,
    pub role_id: String,
    pub process_state_id: String,
    pub effect_family: EffectFamilyV1,
    pub operation_id: String,
    pub object_selector: String,
    pub binding_lifecycle: BindingLifecycleV1,
}

impl StaticDecisionKeyV1 {
    pub fn digest(&self, policy_id: &str) -> Result<String> {
        canonical_cbor(policy_id, self).map(|bytes| digest(&bytes))
    }
}

/// The physical kernel result for one compiled policy cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompiledPhysicalResultV1 {
    AllowEffect,
    AuditAllowEffect,
    SimulatablePolicyDeny,
    DenyEffect,
}

/// One final decision and its signed provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledDecisionCellV1 {
    pub key: StaticDecisionKeyV1,
    pub physical_result: CompiledPhysicalResultV1,
    pub errno: Option<i16>,
    pub consuming_exception_id: Option<String>,
    pub action_plan_digest: String,
    pub source_rule_ids: Vec<String>,
}

/// The complete static result of one policy compilation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StaticExpandedProfileV1 {
    pub profile_id: String,
    pub profile_version: u64,
    pub source_policy_digest: String,
    pub canonical_policy: Vec<u8>,
    pub compiled_cells: Vec<CompiledDecisionCellV1>,
    pub compiled_rule_cell_digests: Vec<String>,
    pub rollout_generation: u64,
    pub mode: ProfileModeV1,
}

#[derive(Default)]
pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile(&self, document: &PolicyDocumentV1) -> Result<StaticExpandedProfileV1> {
        document
            .validate()
            .map_err(|error| error.for_policy(document.profile_id()))?;
        let canonical_policy = canonical_cbor(document.profile_id(), document)?;
        let source_policy_digest = digest(&canonical_policy);
        let cells = self.expand_rules(document)?;
        document.validate_compiled_exceptions(&cells)?;
        let compiled_rule_cell_digests = cells
            .iter()
            .map(|cell| canonical_cbor(document.profile_id(), cell).map(|bytes| digest(&bytes)))
            .collect::<Result<Vec<_>>>()?;

        Ok(StaticExpandedProfileV1 {
            profile_id: document.metadata.profile_id.clone(),
            profile_version: document.metadata.profile_version,
            source_policy_digest,
            canonical_policy,
            compiled_cells: cells,
            compiled_rule_cell_digests,
            rollout_generation: document.rollout.rollout_generation,
            mode: document.rollout.desired_profile_mode,
        })
    }

    fn expand_rules(&self, document: &PolicyDocumentV1) -> Result<Vec<CompiledDecisionCellV1>> {
        let mut contributions = BTreeMap::<StaticDecisionKeyV1, Vec<RuleDecision<'_>>>::new();
        for rule in document.rules.iter().filter(|rule| rule.enabled) {
            let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match else {
                continue;
            };
            let physical_result = CompiledPhysicalResultV1::try_from((
                rule.requested_disposition,
                document.rollout.desired_profile_mode,
            ))
            .map_err(|_| {
                PolicyValidationSnafu {
                    policy_id: document.profile_id(),
                    code: "CFG_STAGE_DISPOSITION",
                    reason: format!("rule `{}` cannot REJECT a local effect", rule.rule_id),
                }
                .build()
            })?;
            let action_plan_digest =
                LocalActionPlan::from((rule, effect)).digest(document.profile_id())?;
            let dimensions = RuleDimensions::for_effect(document, effect);
            for key in dimensions.keys(document.profile_id())? {
                contributions.entry(key).or_default().push(RuleDecision {
                    rule,
                    physical_result,
                    errno: rule.errno.map(super::source::ErrnoV1::negative),
                    action_plan_digest: action_plan_digest.clone(),
                });
                ensure!(
                    contributions.len() <= MAX_COMPILED_CELLS,
                    PolicyValidationSnafu {
                        policy_id: document.profile_id(),
                        code: "CFG_MAP_CAPACITY",
                        reason: "expanded decision cells exceed the verified map capacity",
                    }
                );
            }
        }

        let mut cells = contributions
            .into_iter()
            .map(|(key, candidates)| {
                CompiledDecisionCellV1::resolve(document.profile_id(), key, &candidates)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|cell| (cell.key.clone(), cell))
            .collect::<BTreeMap<_, _>>();
        let mut default_cells = BTreeMap::<StaticDecisionKeyV1, CompiledDecisionCellV1>::new();
        for default in &document.effect_family_defaults {
            let physical_result = CompiledPhysicalResultV1::try_from((
                default.requested_disposition,
                document.rollout.desired_profile_mode,
            ))
            .map_err(|_| {
                PolicyValidationSnafu {
                    policy_id: document.profile_id(),
                    code: "CFG_STAGE_DISPOSITION",
                    reason: "an effect-family default cannot REJECT a local effect".to_owned(),
                }
                .build()
            })?;
            let action_plan_digest =
                canonical_cbor(document.profile_id(), default).map(|bytes| digest(&bytes))?;
            for key in RuleDimensions::default_keys(document, default)? {
                let candidate = CompiledDecisionCellV1 {
                    key: key.clone(),
                    physical_result,
                    errno: default.errno.map(super::source::ErrnoV1::negative),
                    consuming_exception_id: None,
                    action_plan_digest: action_plan_digest.clone(),
                    source_rule_ids: Vec::new(),
                };
                if let Some(existing) = default_cells.get(&key) {
                    ensure!(
                        existing.physical_result == candidate.physical_result
                            && existing.errno == candidate.errno
                            && existing.action_plan_digest == candidate.action_plan_digest,
                        PolicyValidationSnafu {
                            policy_id: document.profile_id(),
                            code: "CFG_EXACT_KEY_CONFLICT",
                            reason: "unequal effect-family defaults overlap one exact compiled key",
                        }
                    );
                } else {
                    default_cells.insert(key, candidate);
                }
            }
        }

        for (key, default) in default_cells {
            cells.entry(key).or_insert(default);
            ensure!(
                cells.len() <= MAX_COMPILED_CELLS,
                PolicyValidationSnafu {
                    policy_id: document.profile_id(),
                    code: "CFG_MAP_CAPACITY",
                    reason: "expanded decision cells exceed the verified map capacity",
                }
            );
        }
        Ok(cells.into_values().collect())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
