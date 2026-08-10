use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use super::canonical::canonical_cbor;
use super::source::{
    duplicate_ids, ordered_unique, BindingLifecycleV1, DetectionDispositionRuleV1, EffectFamilyV1,
    EntryKindV1, EvaluationStageV1, LocalObjectSelectorV1, PolicyDispositionV1, PolicyDocumentV1,
    ProfileModeV1, RuleMatchV1, StateBitScopeV1,
};
use crate::error::PolicyValidationSnafu;
use crate::Result;

const MAX_COMPILED_CELLS: usize = 65_536;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompiledPhysicalResultV1 {
    AllowEffect,
    AuditAllowEffect,
    SimulatablePolicyDeny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledDecisionCellV1 {
    pub key: StaticDecisionKeyV1,
    pub physical_result: CompiledPhysicalResultV1,
    pub errno: Option<i16>,
    pub source_rule_ids: Vec<String>,
}

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
        self.validate(document)?;
        let canonical_policy = canonical_cbor(document.profile_id(), document)?;
        let source_policy_digest = digest(&canonical_policy);
        let cells = self.expand_rules(document)?;
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

    fn validate(&self, document: &PolicyDocumentV1) -> Result<()> {
        let policy_id = document.profile_id();
        check(
            policy_id,
            document.api_version == "mithril.erebor.dev/v1" && document.kind == "ProtectionPolicy",
            "CFG_SCHEMA_VERSION",
            "api_version and kind must be exactly the Version 1 values",
        )?;
        validate_uuid(policy_id, &document.metadata.profile_id, "profile_id")?;
        validate_uuid(
            policy_id,
            &document.metadata.trust_domain_id,
            "trust_domain_id",
        )?;
        check(
            policy_id,
            document.metadata.profile_version > 0 && document.rollout.rollout_generation > 0,
            "CFG_ZERO_GENERATION",
            "profile and rollout generations must be nonzero",
        )?;
        let valid_from = parse_utc(policy_id, &document.metadata.valid_from_utc)?;
        if let Some(until) = &document.metadata.valid_until_utc {
            check(
                policy_id,
                parse_utc(policy_id, until)? > valid_from,
                "CFG_VALIDITY_WINDOW",
                "valid_until_utc must be after valid_from_utc",
            )?;
        }
        check(
            policy_id,
            document.rollout.desired_profile_mode == ProfileModeV1::Observe,
            "CFG_PHASE3_MODE",
            "Phase 3 accepts OBSERVE candidates only",
        )?;
        validate_ids(document)?;
        validate_references(document)?;
        validate_states(document)?;
        validate_rules(document)?;
        validate_role_reachability(document)?;
        validate_rollout(document)?;
        Ok(())
    }

    fn expand_rules(&self, document: &PolicyDocumentV1) -> Result<Vec<CompiledDecisionCellV1>> {
        let mut contributions = BTreeMap::<StaticDecisionKeyV1, Vec<RuleDecision<'_>>>::new();
        for rule in document.rules.iter().filter(|rule| rule.enabled) {
            let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match else {
                continue;
            };
            let physical_result = physical_result(rule).ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: document.profile_id(),
                    code: "CFG_STAGE_DISPOSITION",
                    reason: format!("rule `{}` cannot REJECT a local effect", rule.rule_id),
                }
                .build()
            })?;
            let dimensions = RuleDimensions::new(document, effect)?;
            for key in dimensions.keys(document.profile_id())? {
                contributions.entry(key).or_default().push(RuleDecision {
                    rule,
                    physical_result,
                    errno: rule.errno.map(super::source::ErrnoV1::negative),
                });
                check(
                    document.profile_id(),
                    contributions.len() <= MAX_COMPILED_CELLS,
                    "CFG_MAP_CAPACITY",
                    "expanded decision cells exceed the verified map capacity",
                )?;
            }
        }
        contributions
            .into_iter()
            .map(|(key, candidates)| resolve_cell(document.profile_id(), key, &candidates))
            .collect()
    }
}

impl EffectFamilyV1 {
    #[must_use]
    pub const fn kernel_id(self) -> KernelEffectFamilyV1 {
        match self {
            Self::Exec => KernelEffectFamilyV1::Exec,
            Self::File => KernelEffectFamilyV1::File,
            Self::Network => KernelEffectFamilyV1::Network,
            Self::Device => KernelEffectFamilyV1::Device,
            Self::Privilege => KernelEffectFamilyV1::Privilege,
            Self::Ipc => KernelEffectFamilyV1::Ipc,
            Self::Mount => KernelEffectFamilyV1::Mount,
        }
    }
}

#[must_use]
pub fn kernel_operation_id(operation: &str) -> Option<KernelEffectOperationV1> {
    match operation {
        "EXECUTE" => Some(KernelEffectOperationV1::Execute),
        "OPEN_READ" => Some(KernelEffectOperationV1::OpenRead),
        "OPEN_WRITE" => Some(KernelEffectOperationV1::OpenWrite),
        "READ" => Some(KernelEffectOperationV1::Read),
        "WRITE" => Some(KernelEffectOperationV1::Write),
        "IOCTL" => Some(KernelEffectOperationV1::Ioctl),
        "MMAP_READ" => Some(KernelEffectOperationV1::MmapRead),
        "MMAP_WRITE" => Some(KernelEffectOperationV1::MmapWrite),
        "MMAP_EXEC" => Some(KernelEffectOperationV1::MmapExec),
        "MPROTECT" => Some(KernelEffectOperationV1::Mprotect),
        "IPC_ACCESS" => Some(KernelEffectOperationV1::IpcAccess),
        "CONNECT" => Some(KernelEffectOperationV1::Connect),
        "SEND" => Some(KernelEffectOperationV1::Send),
        "PTRACE" => Some(KernelEffectOperationV1::Ptrace),
        "SIGNAL" => Some(KernelEffectOperationV1::Signal),
        "UNLINK" => Some(KernelEffectOperationV1::Unlink),
        "LINK" => Some(KernelEffectOperationV1::Link),
        "RENAME" => Some(KernelEffectOperationV1::Rename),
        "MOUNT" => Some(KernelEffectOperationV1::Mount),
        "UNMOUNT" => Some(KernelEffectOperationV1::Unmount),
        "PIVOT_ROOT" => Some(KernelEffectOperationV1::PivotRoot),
        "MOVE_MOUNT" => Some(KernelEffectOperationV1::MoveMount),
        "CAPABILITY" => Some(KernelEffectOperationV1::Capability),
        "BPF" => Some(KernelEffectOperationV1::Bpf),
        _ => None,
    }
}

struct RuleDecision<'a> {
    rule: &'a DetectionDispositionRuleV1,
    physical_result: CompiledPhysicalResultV1,
    errno: Option<i16>,
}

fn resolve_cell(
    policy_id: &str,
    key: StaticDecisionKeyV1,
    candidates: &[RuleDecision<'_>],
) -> Result<CompiledDecisionCellV1> {
    let first = &candidates[0];
    if candidates.iter().all(|candidate| {
        candidate.physical_result == first.physical_result && candidate.errno == first.errno
    }) {
        let mut source_rule_ids = candidates
            .iter()
            .map(|candidate| candidate.rule.rule_id.clone())
            .collect::<Vec<_>>();
        source_rule_ids.sort();
        return Ok(CompiledDecisionCellV1 {
            key,
            physical_result: first.physical_result,
            errno: first.errno,
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
    Ok(CompiledDecisionCellV1 {
        key,
        physical_result: winner.physical_result,
        errno: winner.errno,
        source_rule_ids: vec![winner.rule.rule_id.clone()],
    })
}

fn physical_result(rule: &DetectionDispositionRuleV1) -> Option<CompiledPhysicalResultV1> {
    match rule.requested_disposition {
        PolicyDispositionV1::Allow => Some(CompiledPhysicalResultV1::AllowEffect),
        PolicyDispositionV1::Alert => Some(CompiledPhysicalResultV1::AuditAllowEffect),
        PolicyDispositionV1::Deny => Some(CompiledPhysicalResultV1::SimulatablePolicyDeny),
        PolicyDispositionV1::Reject => None,
    }
}

struct RuleDimensions<'a> {
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
    fn new(
        document: &'a PolicyDocumentV1,
        effect: &'a super::source::LocalEffectMatchV1,
    ) -> Result<Self> {
        let whole = &document.protected_universe;
        Ok(Self {
            workload_selectors: whole_or(
                &effect.subject.workload_selector_ids,
                &whole.workload_selector_ids,
            ),
            protected_scopes: whole_or(
                &effect.subject.protected_scope_ids,
                &whole.protected_scope_ids,
            ),
            execution_sets: whole_or(&effect.subject.execution_set_ids, &whole.execution_set_ids),
            entry_kinds: whole_or_copy(&effect.subject.entry_kind_ids, &whole.entry_kind_ids),
            roles: whole_or(&effect.subject.role_ids, &whole.role_ids),
            process_states: if effect.subject.required_process_state_ids.is_empty() {
                document
                    .process_state_definitions
                    .iter()
                    .map(|state| state.process_state_id.as_str())
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
            objects: object_cells(&effect.object),
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
        })
    }

    fn keys(&self, policy_id: &str) -> Result<Vec<StaticDecisionKeyV1>> {
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
        let count = lengths
            .into_iter()
            .try_fold(1_usize, usize::checked_mul)
            .unwrap_or(usize::MAX);
        check(
            policy_id,
            count <= MAX_COMPILED_CELLS,
            "CFG_MAP_CAPACITY",
            "one rule expands beyond the verified decision-cell capacity",
        )?;
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
}

fn whole_or<'a>(selected: &'a [String], universe: &'a [String]) -> Vec<&'a str> {
    if selected.is_empty() {
        universe
    } else {
        selected
    }
    .iter()
    .map(String::as_str)
    .collect()
}

fn whole_or_copy<T: Copy>(selected: &[T], universe: &[T]) -> Vec<T> {
    if selected.is_empty() {
        universe
    } else {
        selected
    }
    .to_vec()
}

fn object_cells(selector: &LocalObjectSelectorV1) -> Vec<String> {
    match selector {
        LocalObjectSelectorV1::ExactObjectKeys {
            exact_object_key_ids,
        } => exact_object_key_ids
            .iter()
            .map(|id| format!("EXACT:{id}"))
            .collect(),
        LocalObjectSelectorV1::ObjectClasses { object_class_ids } => object_class_ids
            .iter()
            .map(|id| format!("CLASS:{id}"))
            .collect(),
        LocalObjectSelectorV1::Destinations {
            destination_policy_ids,
        } => destination_policy_ids
            .iter()
            .map(|id| format!("DESTINATION:{id}"))
            .collect(),
        LocalObjectSelectorV1::Devices {
            device_class_ids,
            ioctl_command_ids,
        } => {
            let commands = if ioctl_command_ids.is_empty() {
                vec!["*".to_owned()]
            } else {
                ioctl_command_ids.iter().map(u32::to_string).collect()
            };
            device_class_ids
                .iter()
                .flat_map(|device| {
                    commands
                        .iter()
                        .map(move |command| format!("DEVICE:{device}:{command}"))
                })
                .collect()
        }
        LocalObjectSelectorV1::SecurityObjects {
            security_object_ids,
            target_selector_ids,
        } => {
            let targets = if target_selector_ids.is_empty() {
                vec!["*".to_owned()]
            } else {
                target_selector_ids.clone()
            };
            security_object_ids
                .iter()
                .flat_map(|object| {
                    targets
                        .iter()
                        .map(move |target| format!("SECURITY:{object}:{target}"))
                })
                .collect()
        }
    }
}

fn validate_ids(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    for id in document
        .protected_universe
        .workload_selector_ids
        .iter()
        .chain(&document.protected_universe.role_ids)
        .chain(
            document
                .workload_selectors
                .iter()
                .map(|selector| &selector.workload_selector_id),
        )
        .chain(
            document
                .classifier_bindings
                .iter()
                .map(|binding| &binding.classifier_binding_id),
        )
        .chain(document.roles.iter().map(|role| &role.role_id))
        .chain(
            document
                .entry_role_assignments
                .iter()
                .map(|entry| &entry.assignment_id),
        )
        .chain(
            document
                .native_transition_rules
                .iter()
                .map(|rule| &rule.transition_rule_id),
        )
        .chain(
            document
                .process_state_definitions
                .iter()
                .map(|state| &state.process_state_id),
        )
        .chain(document.rules.iter().map(|rule| &rule.rule_id))
        .chain(
            document
                .exceptions
                .iter()
                .map(|exception| &exception.exception_id),
        )
    {
        check(
            policy_id,
            valid_local_id(id),
            "CFG_LOCAL_ID",
            &format!("`{id}` is not a PolicyLocalIdV1"),
        )?;
    }
    for symbol in document
        .required_capability_ids
        .iter()
        .chain(&document.protected_universe.object_class_ids)
        .chain(
            document
                .rules
                .iter()
                .flat_map(|rule| match &rule.rule_match {
                    RuleMatchV1::LocalPreEffect(effect) => effect.operation_ids.iter(),
                    RuleMatchV1::NativeTransition(_) => [].iter(),
                }),
        )
    {
        check(
            policy_id,
            valid_registry_symbol(symbol),
            "CFG_REGISTRY_SYMBOL",
            &format!("`{symbol}` is not an uppercase registry symbol"),
        )?;
    }
    let duplicates = duplicate_ids(document.roles.iter().map(|role| role.role_id.as_str()));
    check(
        policy_id,
        duplicates.is_empty(),
        "CFG_DUPLICATE_ID",
        &format!("duplicate role IDs: {duplicates:?}"),
    )
}

fn validate_references(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    let roles = document
        .roles
        .iter()
        .map(|role| role.role_id.as_str())
        .collect::<BTreeSet<_>>();
    let universe_roles = document
        .protected_universe
        .role_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    check(
        policy_id,
        roles == universe_roles,
        "CFG_ROLE_REGISTRY",
        "protected_universe.role_ids must exactly equal the defined role IDs",
    )?;
    let selectors = document
        .workload_selectors
        .iter()
        .map(|selector| selector.workload_selector_id.as_str())
        .collect::<BTreeSet<_>>();
    let universe_selectors = document
        .protected_universe
        .workload_selector_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    check(
        policy_id,
        selectors == universe_selectors,
        "CFG_SELECTOR_REGISTRY",
        "protected_universe.workload_selector_ids must exactly equal the defined selectors",
    )?;
    for role in &document.roles {
        check(
            policy_id,
            document
                .process_state_definitions
                .iter()
                .any(|state| state.process_state_id == role.default_process_state_id),
            "CFG_STATE_REFERENCE",
            &format!(
                "role `{}` references missing default state `{}`",
                role.role_id, role.default_process_state_id
            ),
        )?;
    }
    for entry in &document.entry_role_assignments {
        check(
            policy_id,
            roles.contains(entry.resulting_role_id.as_str()),
            "CFG_ROLE_REFERENCE",
            &format!("entry `{}` has an unknown role", entry.assignment_id),
        )?;
        for selector in &entry.workload_selector_ids {
            check(
                policy_id,
                selectors.contains(selector.as_str()),
                "CFG_SELECTOR_REFERENCE",
                &format!("entry `{}` has an unknown selector", entry.assignment_id),
            )?;
        }
    }
    Ok(())
}

fn validate_states(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    let mut indices = BTreeSet::new();
    let mut semantics = BTreeSet::new();
    for bit in &document.state_bit_definitions {
        check(
            policy_id,
            bit.bit_index < 64 && bit.monotonic,
            "CFG_STATE_BIT",
            "state bits must be in 0..63 and monotonic",
        )?;
        check(
            policy_id,
            indices.insert((bit.scope, bit.bit_index))
                && semantics.insert((bit.scope, bit.semantic_id.as_str())),
            "CFG_DUPLICATE_STATE_BIT",
            "state bit indices and semantics must be unique per scope",
        )?;
    }
    let process_bits = document
        .state_bit_definitions
        .iter()
        .filter(|bit| bit.scope == StateBitScopeV1::Process)
        .map(|bit| bit.bit_index)
        .collect::<BTreeSet<_>>();
    for state in &document.process_state_definitions {
        check(
            policy_id,
            ordered_unique(&state.state_bits),
            "CFG_STATE_ORDER",
            "process state bits must be sorted and unique",
        )?;
        check(
            policy_id,
            state
                .state_bits
                .iter()
                .all(|bit| process_bits.contains(bit)),
            "CFG_STATE_REFERENCE",
            &format!(
                "state `{}` references an undefined process bit",
                state.process_state_id
            ),
        )?;
    }
    Ok(())
}

fn validate_rules(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    let rule_ids = document
        .rules
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    check(
        policy_id,
        rule_ids.len() == document.rules.len(),
        "CFG_DUPLICATE_ID",
        "rule IDs must be unique",
    )?;
    let universe = RuleUniverse::new(document);
    for rule in &document.rules {
        check(
            policy_id,
            rule.schema_version == 1,
            "CFG_RULE_SCHEMA",
            &format!("rule `{}` schema_version must be 1", rule.rule_id),
        )?;
        let match_stage = match rule.rule_match {
            RuleMatchV1::LocalPreEffect(_) => EvaluationStageV1::LocalPreEffect,
            RuleMatchV1::NativeTransition(_) => EvaluationStageV1::NativeTransition,
        };
        check(
            policy_id,
            rule.evaluation_stage == match_stage,
            "CFG_STAGE_MATCH",
            &format!(
                "rule `{}` match kind disagrees with evaluation_stage",
                rule.rule_id
            ),
        )?;
        let legal = match rule.evaluation_stage {
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(
                rule.requested_disposition,
                PolicyDispositionV1::Allow
                    | PolicyDispositionV1::Alert
                    | PolicyDispositionV1::Reject
            ),
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(
                rule.requested_disposition,
                PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Deny
            ),
            EvaluationStageV1::PostEffect => matches!(
                rule.requested_disposition,
                PolicyDispositionV1::Allow | PolicyDispositionV1::Alert
            ),
        };
        check(
            policy_id,
            legal,
            "CFG_STAGE_DISPOSITION",
            &format!(
                "rule `{}` requests a disposition illegal at its stage",
                rule.rule_id
            ),
        )?;
        check(
            policy_id,
            (rule.requested_disposition == PolicyDispositionV1::Deny) == rule.errno.is_some(),
            "CFG_ERRNO_PRESENCE",
            &format!(
                "rule `{}` errno must be present exactly for DENY",
                rule.rule_id
            ),
        )?;
        for overridden in &rule.overrides_rule_ids {
            check(
                policy_id,
                overridden != &rule.rule_id && rule_ids.contains(overridden.as_str()),
                "CFG_OVERRIDE_REFERENCE",
                &format!("rule `{}` has an invalid override", rule.rule_id),
            )?;
        }
        if let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match {
            universe.validate_subject(policy_id, &rule.rule_id, &effect.subject)?;
            check(
                policy_id,
                !effect.effect_families.is_empty()
                    && !effect.operation_ids.is_empty()
                    && !object_cells(&effect.object).is_empty()
                    && ordered_unique(&effect.effect_families)
                    && ordered_unique(&effect.operation_ids)
                    && ordered_unique(&effect.binding_lifecycle_states),
                "CFG_EMPTY_REQUIRED_SELECTOR",
                &format!(
                    "rule `{}` has an empty or unordered local selector",
                    rule.rule_id
                ),
            )?;
            match &effect.object {
                LocalObjectSelectorV1::ExactObjectKeys {
                    exact_object_key_ids,
                } => check(
                    policy_id,
                    ordered_unique(exact_object_key_ids)
                        && exact_object_key_ids.iter().all(|id| *id > 0),
                    "CFG_EXACT_OBJECT_SELECTOR",
                    &format!(
                        "rule `{}` exact object IDs must be nonzero, sorted, and unique",
                        rule.rule_id
                    ),
                )?,
                LocalObjectSelectorV1::ObjectClasses { object_class_ids } => check(
                    policy_id,
                    ordered_unique(object_class_ids)
                        && object_class_ids
                            .iter()
                            .all(|id| universe.object_classes.contains(id.as_str())),
                    "CFG_OBJECT_CLASS_REFERENCE",
                    &format!(
                        "rule `{}` object classes must be sorted signed-universe members",
                        rule.rule_id
                    ),
                )?,
                _ => {}
            }
            for family in &effect.effect_families {
                for operation in &effect.operation_ids {
                    check(
                        policy_id,
                        operation_belongs_to_family(*family, operation),
                        "CFG_OPERATION_REGISTRY",
                        &format!(
                            "rule `{}` uses unsupported operation `{operation}` for {family:?}",
                            rule.rule_id
                        ),
                    )?;
                }
            }
        } else if let RuleMatchV1::NativeTransition(transition) = &rule.rule_match {
            universe.validate_subject(policy_id, &rule.rule_id, &transition.subject)?;
            check(
                policy_id,
                !transition.operations.is_empty()
                    && ordered_unique(&transition.operations)
                    && ordered_unique(&transition.executable_object_ids)
                    && ordered_unique(&transition.source_role_ids)
                    && ordered_unique(&transition.target_role_ids)
                    && transition
                        .source_role_ids
                        .iter()
                        .chain(&transition.target_role_ids)
                        .all(|role| universe.roles.contains(role.as_str())),
                "CFG_NATIVE_TRANSITION_MATCH",
                &format!(
                    "rule `{}` has an invalid native-transition selector",
                    rule.rule_id
                ),
            )?;
        }
    }
    Ok(())
}

struct RuleUniverse<'a> {
    selectors: BTreeSet<&'a str>,
    scopes: BTreeSet<&'a str>,
    execution_sets: BTreeSet<&'a str>,
    entry_kinds: BTreeSet<EntryKindV1>,
    roles: BTreeSet<&'a str>,
    process_states: BTreeSet<&'a str>,
    object_classes: BTreeSet<&'a str>,
}

impl<'a> RuleUniverse<'a> {
    fn new(document: &'a PolicyDocumentV1) -> Self {
        let strings = |values: &'a [String]| values.iter().map(String::as_str).collect();
        Self {
            selectors: strings(&document.protected_universe.workload_selector_ids),
            scopes: strings(&document.protected_universe.protected_scope_ids),
            execution_sets: strings(&document.protected_universe.execution_set_ids),
            entry_kinds: document
                .protected_universe
                .entry_kind_ids
                .iter()
                .copied()
                .collect(),
            roles: strings(&document.protected_universe.role_ids),
            process_states: document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str())
                .collect(),
            object_classes: strings(&document.protected_universe.object_class_ids),
        }
    }

    fn validate_subject(
        &self,
        policy_id: &str,
        rule_id: &str,
        subject: &super::source::CommonSubjectMatchV1,
    ) -> Result<()> {
        let state_ordered = ordered_unique(&subject.required_process_state_ids)
            && ordered_unique(&subject.forbidden_process_state_ids);
        let required = subject
            .required_process_state_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        check(
            policy_id,
            ordered_unique(&subject.workload_selector_ids)
                && ordered_unique(&subject.protected_scope_ids)
                && ordered_unique(&subject.execution_set_ids)
                && ordered_unique(&subject.entry_kind_ids)
                && ordered_unique(&subject.role_ids)
                && state_ordered
                && subject
                    .workload_selector_ids
                    .iter()
                    .all(|id| self.selectors.contains(id.as_str()))
                && subject
                    .protected_scope_ids
                    .iter()
                    .all(|id| self.scopes.contains(id.as_str()))
                && subject
                    .execution_set_ids
                    .iter()
                    .all(|id| self.execution_sets.contains(id.as_str()))
                && subject
                    .entry_kind_ids
                    .iter()
                    .all(|kind| self.entry_kinds.contains(kind))
                && subject
                    .role_ids
                    .iter()
                    .all(|id| self.roles.contains(id.as_str()))
                && subject
                    .required_process_state_ids
                    .iter()
                    .chain(&subject.forbidden_process_state_ids)
                    .all(|id| self.process_states.contains(id.as_str()))
                && subject
                    .forbidden_process_state_ids
                    .iter()
                    .all(|id| !required.contains(id.as_str())),
            "CFG_SUBJECT_REFERENCE",
            &format!(
                "rule `{rule_id}` subject dimensions must be sorted, unique, disjoint, and signed-universe members"
            ),
        )
    }
}

fn operation_belongs_to_family(family: EffectFamilyV1, operation: &str) -> bool {
    match family {
        EffectFamilyV1::Exec => matches!(operation, "EXECUTE" | "MMAP_EXEC" | "MPROTECT"),
        EffectFamilyV1::File => matches!(
            operation,
            "OPEN_READ"
                | "OPEN_WRITE"
                | "READ"
                | "WRITE"
                | "MMAP_READ"
                | "MMAP_WRITE"
                | "MPROTECT"
                | "UNLINK"
                | "LINK"
                | "RENAME"
        ),
        EffectFamilyV1::Network => matches!(operation, "CONNECT" | "SEND"),
        EffectFamilyV1::Device => operation == "IOCTL",
        EffectFamilyV1::Privilege => {
            matches!(operation, "PTRACE" | "SIGNAL" | "CAPABILITY" | "BPF")
        }
        EffectFamilyV1::Ipc => operation == "IPC_ACCESS",
        EffectFamilyV1::Mount => {
            matches!(operation, "MOUNT" | "UNMOUNT" | "PIVOT_ROOT" | "MOVE_MOUNT")
        }
    }
}

fn validate_role_reachability(document: &PolicyDocumentV1) -> Result<()> {
    let mut reachable = document
        .entry_role_assignments
        .iter()
        .map(|entry| entry.resulting_role_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut pending = VecDeque::from_iter(&document.native_transition_rules);
    let mut made_progress = true;
    while made_progress {
        made_progress = false;
        pending.retain(|transition| {
            if transition
                .source_role_ids
                .iter()
                .any(|role| reachable.contains(role.as_str()))
            {
                made_progress |= reachable.insert(&transition.resulting_role_id);
                false
            } else {
                true
            }
        });
    }
    let missing = document
        .roles
        .iter()
        .filter(|role| !reachable.contains(role.role_id.as_str()))
        .map(|role| role.role_id.clone())
        .collect::<Vec<_>>();
    check(
        document.profile_id(),
        missing.is_empty(),
        "CFG_UNREACHABLE_ROLE",
        &format!("unreachable roles: {missing:?}"),
    )
}

fn validate_rollout(document: &PolicyDocumentV1) -> Result<()> {
    let rollout = &document.rollout;
    check(
        document.profile_id(),
        ordered_unique(&rollout.selected_bucket_ids),
        "CFG_ROLLOUT_ORDER",
        "selected buckets must be sorted and unique",
    )?;
    check(
        document.profile_id(),
        rollout.selector_hash_modulus > 0
            && rollout
                .selected_bucket_ids
                .iter()
                .all(|bucket| *bucket < rollout.selector_hash_modulus),
        "CFG_ROLLOUT_BUCKET",
        "rollout modulus must be nonzero and every bucket must be below it",
    )
}

fn validate_uuid(policy_id: &str, value: &str, field: &str) -> Result<()> {
    check(
        policy_id,
        Uuid::parse_str(value).is_ok(),
        "CFG_ID128",
        &format!("{field} must be an Id128 UUID"),
    )
}

fn parse_utc(policy_id: &str, value: &str) -> Result<i64> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_TIMESTAMP",
            reason: error.to_string(),
        }
        .build()
    })?;
    check(
        policy_id,
        parsed.offset().is_utc(),
        "CFG_TIMESTAMP_OFFSET",
        "timestamps must use the UTC offset",
    )?;
    parsed.unix_timestamp_nanos().try_into().map_err(|error| {
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_TIMESTAMP_RANGE",
            reason: format!("timestamp is outside the signed nanosecond range: {error}"),
        }
        .build()
    })
}

fn valid_local_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_registry_symbol(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn check(policy_id: &str, condition: bool, code: &'static str, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        PolicyValidationSnafu {
            policy_id,
            code,
            reason,
        }
        .fail()
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
