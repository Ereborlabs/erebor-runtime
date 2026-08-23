use serde::Serialize;
use snafu::ensure;

use super::{
    digest, CompiledDecisionCellV1, CompiledPhysicalResultV1, StaticDecisionKeyV1,
    MAX_COMPILED_CELLS,
};
use crate::error::PolicyValidationSnafu;
use crate::policy::canonical::canonical_cbor;
use crate::policy::source::{
    BindingLifecycleV1, DetectionDispositionRuleV1, EffectFamilyDefaultV1, EffectFamilyV1,
    EntryKindV1, EvaluationStageV1, LocalEffectMatchV1, PolicyDispositionV1, PolicyDocumentV1,
};
use crate::policy::source_proof::ProofQualityPredicateV1;
use crate::Result;

pub(super) struct RuleDecision<'a> {
    pub(super) rule: &'a DetectionDispositionRuleV1,
    pub(super) physical_result: CompiledPhysicalResultV1,
    pub(super) errno: Option<i16>,
    pub(super) action_plan_digest: String,
    pub(super) consuming_exception_id: Option<&'a str>,
}

impl CompiledDecisionCellV1 {
    pub(super) fn resolve(
        policy_id: &str,
        key: StaticDecisionKeyV1,
        candidates: &[RuleDecision<'_>],
    ) -> Result<Self> {
        let first = &candidates[0];
        if candidates.iter().all(|candidate| {
            candidate.physical_result == first.physical_result
                && candidate.errno == first.errno
                && candidate.action_plan_digest == first.action_plan_digest
                && candidate.consuming_exception_id == first.consuming_exception_id
        }) {
            let mut source_rule_ids = candidates
                .iter()
                .map(|candidate| candidate.rule.rule_id.clone())
                .collect::<Vec<_>>();
            source_rule_ids.sort();
            return Ok(Self {
                key,
                physical_result: first.physical_result,
                errno: first.errno,
                consuming_exception_id: first.consuming_exception_id.map(str::to_owned),
                action_plan_digest: first.action_plan_digest.clone(),
                source_rule_ids,
            });
        }

        let winner = candidates.iter().find(|candidate| {
            candidates.iter().all(|other| {
                candidate.rule.rule_id == other.rule.rule_id
                    || candidate
                        .rule
                        .overrides_rule_ids
                        .contains(&other.rule.rule_id)
            })
        });
        let Some(winner) = winner else {
            return PolicyValidationSnafu {
                policy_id,
                code: "CFG_EXACT_KEY_CONFLICT",
                reason: format!(
                    "unequal physical decisions overlap at {key:?} without one exact override"
                ),
            }
            .fail();
        };

        Ok(Self {
            key,
            physical_result: winner.physical_result,
            errno: winner.errno,
            consuming_exception_id: winner.consuming_exception_id.map(str::to_owned),
            action_plan_digest: winner.action_plan_digest.clone(),
            source_rule_ids: vec![winner.rule.rule_id.clone()],
        })
    }
}

#[derive(Serialize)]
pub(super) struct LocalActionPlan<'a> {
    evaluation_stage: EvaluationStageV1,
    requested_disposition: PolicyDispositionV1,
    errno: Option<crate::policy::source::ErrnoV1>,
    finding: &'a Option<crate::policy::source::FindingSpecV1>,
    response_binding_ids: &'a [String],
    required_proof: &'a ProofQualityPredicateV1,
    fallback_by_condition: &'a [crate::policy::source::FallbackV1],
    budgets: &'a crate::policy::source::BudgetSetV1,
    exception_ids: &'a [String],
    valid_from_utc_ns: Option<i64>,
    valid_until_utc_ns: Option<i64>,
}

impl<'a> From<(&'a DetectionDispositionRuleV1, &'a LocalEffectMatchV1)> for LocalActionPlan<'a> {
    fn from((rule, effect): (&'a DetectionDispositionRuleV1, &'a LocalEffectMatchV1)) -> Self {
        Self {
            evaluation_stage: rule.evaluation_stage,
            requested_disposition: rule.requested_disposition,
            errno: rule.errno,
            finding: &rule.finding,
            response_binding_ids: &rule.response_binding_ids,
            required_proof: &effect.required_proof,
            fallback_by_condition: &rule.fallback_by_condition,
            budgets: &rule.budgets,
            exception_ids: &rule.exception_ids,
            valid_from_utc_ns: rule.valid_from_utc_ns,
            valid_until_utc_ns: rule.valid_until_utc_ns,
        }
    }
}

impl LocalActionPlan<'_> {
    pub(super) fn digest(&self, policy_id: &str) -> Result<String> {
        canonical_cbor(policy_id, self).map(|bytes| digest(&bytes))
    }
}

pub(super) struct RuleDimensions<'a> {
    workload_selectors: Vec<&'a str>,
    protected_scopes: Vec<&'a str>,
    execution_sets: Vec<&'a str>,
    entry_kinds: Vec<EntryKindV1>,
    roles: Vec<&'a str>,
    process_states: Vec<&'a str>,
    effect_families: Vec<EffectFamilyV1>,
    operations: Vec<&'a str>,
    objects: Vec<String>,
    lifecycles: Vec<BindingLifecycleV1>,
}

impl<'a> RuleDimensions<'a> {
    pub(super) fn for_effect(
        document: &'a PolicyDocumentV1,
        effect: &'a LocalEffectMatchV1,
    ) -> Self {
        let whole = &document.protected_universe;
        Self {
            workload_selectors: Self::selected_or_universe(
                &effect.subject.workload_selector_ids,
                &whole.workload_selector_ids,
            ),
            protected_scopes: Self::selected_or_universe(
                &effect.subject.protected_scope_ids,
                &whole.protected_scope_ids,
            ),
            execution_sets: Self::selected_or_universe(
                &effect.subject.execution_set_ids,
                &whole.execution_set_ids,
            ),
            entry_kinds: Self::copied_or_universe(
                &effect.subject.entry_kind_ids,
                &whole.entry_kind_ids,
            ),
            roles: Self::selected_or_universe(&effect.subject.role_ids, &whole.role_ids),
            process_states: if effect.subject.required_process_state_ids.is_empty() {
                document
                    .process_state_definitions
                    .iter()
                    .map(|state| state.process_state_id.as_str())
                    .filter(|state| {
                        !effect
                            .subject
                            .forbidden_process_state_ids
                            .iter()
                            .any(|forbidden| forbidden.as_str() == *state)
                    })
                    .collect()
            } else {
                effect
                    .subject
                    .required_process_state_ids
                    .iter()
                    .map(String::as_str)
                    .collect()
            },
            effect_families: effect.effect_families.clone(),
            operations: effect.operation_ids.iter().map(String::as_str).collect(),
            objects: Vec::from(&effect.object),
            lifecycles: if effect.binding_lifecycle_states.is_empty() {
                vec![
                    BindingLifecycleV1::Preparing,
                    BindingLifecycleV1::Active,
                    BindingLifecycleV1::Draining,
                    BindingLifecycleV1::Terminating,
                    BindingLifecycleV1::Tombstoned,
                ]
            } else {
                effect.binding_lifecycle_states.clone()
            },
        }
    }

    pub(super) fn default_keys(
        document: &'a PolicyDocumentV1,
        default: &'a EffectFamilyDefaultV1,
    ) -> Result<Vec<StaticDecisionKeyV1>> {
        let whole = &document.protected_universe;
        let mut keys = Vec::new();

        for role_id in &default.role_ids {
            let role = document
                .roles
                .iter()
                .find(|role| role.role_id == *role_id)
                .ok_or_else(|| {
                    PolicyValidationSnafu {
                        policy_id: document.profile_id(),
                        code: "CFG_ROLE_REFERENCE",
                        reason: format!("effect-family default has unknown role `{role_id}`"),
                    }
                    .build()
                })?;
            let dimensions = Self {
                workload_selectors: whole
                    .workload_selector_ids
                    .iter()
                    .map(String::as_str)
                    .collect(),
                protected_scopes: whole
                    .protected_scope_ids
                    .iter()
                    .map(String::as_str)
                    .collect(),
                execution_sets: whole.execution_set_ids.iter().map(String::as_str).collect(),
                entry_kinds: role.permitted_entry_kinds.clone(),
                roles: vec![role_id],
                process_states: vec![role.default_process_state_id.as_str()],
                effect_families: vec![default.effect_family],
                operations: default.operations.iter().map(String::as_str).collect(),
                // A default applies only when no specific object cell matches.
                objects: vec!["DEFAULT".to_owned()],
                lifecycles: vec![
                    BindingLifecycleV1::Preparing,
                    BindingLifecycleV1::Active,
                    BindingLifecycleV1::Draining,
                    BindingLifecycleV1::Terminating,
                    BindingLifecycleV1::Tombstoned,
                ],
            };
            keys.extend(dimensions.keys(document.profile_id())?);
        }

        Ok(keys)
    }

    pub(super) fn keys(&self, policy_id: &str) -> Result<Vec<StaticDecisionKeyV1>> {
        let lengths = [
            self.workload_selectors.len(),
            self.protected_scopes.len(),
            self.execution_sets.len(),
            self.entry_kinds.len(),
            self.roles.len(),
            self.process_states.len(),
            self.effect_families.len(),
            self.operations.len(),
            self.objects.len(),
            self.lifecycles.len(),
        ];
        ensure!(
            lengths.iter().all(|length| *length > 0),
            PolicyValidationSnafu {
                policy_id,
                code: "CFG_EMPTY_EXPANSION",
                reason: "a local rule selector expands to no signed decision cells",
            }
        );
        let count = lengths
            .into_iter()
            .try_fold(1_usize, usize::checked_mul)
            .unwrap_or(usize::MAX);
        ensure!(
            count <= MAX_COMPILED_CELLS,
            PolicyValidationSnafu {
                policy_id,
                code: "CFG_MAP_CAPACITY",
                reason: "one rule expands beyond the verified decision-cell capacity",
            }
        );

        let mut keys = Vec::with_capacity(count);
        for workload_selector_id in &self.workload_selectors {
            for protected_scope_id in &self.protected_scopes {
                for execution_set_id in &self.execution_sets {
                    for entry_kind in &self.entry_kinds {
                        for role_id in &self.roles {
                            for process_state_id in &self.process_states {
                                for effect_family in &self.effect_families {
                                    for operation_id in &self.operations {
                                        for object_selector in &self.objects {
                                            for binding_lifecycle in &self.lifecycles {
                                                keys.push(StaticDecisionKeyV1 {
                                                    workload_selector_id: (*workload_selector_id)
                                                        .to_owned(),
                                                    protected_scope_id: (*protected_scope_id)
                                                        .to_owned(),
                                                    execution_set_id: (*execution_set_id)
                                                        .to_owned(),
                                                    entry_kind: *entry_kind,
                                                    role_id: (*role_id).to_owned(),
                                                    process_state_id: (*process_state_id)
                                                        .to_owned(),
                                                    effect_family: *effect_family,
                                                    operation_id: (*operation_id).to_owned(),
                                                    object_selector: object_selector.clone(),
                                                    binding_lifecycle: *binding_lifecycle,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(keys)
    }

    fn selected_or_universe(selected: &'a [String], universe: &'a [String]) -> Vec<&'a str> {
        if selected.is_empty() {
            universe
        } else {
            selected
        }
        .iter()
        .map(String::as_str)
        .collect()
    }

    fn copied_or_universe<T: Copy>(selected: &[T], universe: &[T]) -> Vec<T> {
        if selected.is_empty() {
            universe
        } else {
            selected
        }
        .to_vec()
    }
}
