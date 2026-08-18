use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use super::canonical::canonical_cbor;
use super::source::{
    BindingLifecycleV1, DetectionDispositionRuleV1, EffectFamilyV1, EntryKindV1, EvaluationStageV1,
    LocalObjectSelectorV1, PolicyDispositionV1, PolicyDocumentV1, ProfileModeV1, RuleMatchV1,
};
use super::source_proof::ProofQualityPredicateV1;
use super::validation::Validate as _;
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
    DenyEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledDecisionCellV1 {
    pub key: StaticDecisionKeyV1,
    pub physical_result: CompiledPhysicalResultV1,
    pub errno: Option<i16>,
    pub consuming_exception_id: Option<String>,
    pub action_plan_digest: String,
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
            let physical_result = physical_result(rule, document.rollout.desired_profile_mode)
                .ok_or_else(|| {
                    PolicyValidationSnafu {
                        policy_id: document.profile_id(),
                        code: "CFG_STAGE_DISPOSITION",
                        reason: format!("rule `{}` cannot REJECT a local effect", rule.rule_id),
                    }
                    .build()
                })?;
            let action_plan_digest = local_action_plan_digest(document.profile_id(), rule, effect)?;
            let dimensions = RuleDimensions::new(document, effect)?;
            for key in dimensions.keys(document.profile_id())? {
                contributions.entry(key).or_default().push(RuleDecision {
                    rule,
                    physical_result,
                    errno: rule.errno.map(super::source::ErrnoV1::negative),
                    action_plan_digest: action_plan_digest.clone(),
                });
                check(
                    document.profile_id(),
                    contributions.len() <= MAX_COMPILED_CELLS,
                    "CFG_MAP_CAPACITY",
                    "expanded decision cells exceed the verified map capacity",
                )?;
            }
        }
        let mut cells = contributions
            .into_iter()
            .map(|(key, candidates)| resolve_cell(document.profile_id(), key, &candidates))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|cell| (cell.key.clone(), cell))
            .collect::<BTreeMap<_, _>>();
        let mut default_cells = BTreeMap::<StaticDecisionKeyV1, CompiledDecisionCellV1>::new();
        for default in &document.effect_family_defaults {
            let physical_result = disposition_result(
                default.requested_disposition,
                document.rollout.desired_profile_mode,
            )
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: document.profile_id(),
                    code: "CFG_STAGE_DISPOSITION",
                    reason: "an effect-family default cannot REJECT a local effect".to_owned(),
                }
                .build()
            })?;
            let action_plan_digest =
                canonical_cbor(document.profile_id(), default).map(|bytes| digest(&bytes))?;
            for key in default_keys(document, default)? {
                let candidate = CompiledDecisionCellV1 {
                    key: key.clone(),
                    physical_result,
                    errno: default.errno.map(super::source::ErrnoV1::negative),
                    consuming_exception_id: None,
                    action_plan_digest: action_plan_digest.clone(),
                    source_rule_ids: Vec::new(),
                };
                if let Some(existing) = default_cells.get(&key) {
                    check(
                        document.profile_id(),
                        existing.physical_result == candidate.physical_result
                            && existing.errno == candidate.errno
                            && existing.action_plan_digest == candidate.action_plan_digest,
                        "CFG_EXACT_KEY_CONFLICT",
                        "unequal effect-family defaults overlap one exact compiled key",
                    )?;
                } else {
                    default_cells.insert(key, candidate);
                }
            }
        }
        for (key, default) in default_cells {
            cells.entry(key).or_insert(default);
            check(
                document.profile_id(),
                cells.len() <= MAX_COMPILED_CELLS,
                "CFG_MAP_CAPACITY",
                "expanded decision cells exceed the verified map capacity",
            )?;
        }
        Ok(cells.into_values().collect())
    }
}

pub fn compiled_key_digest(policy_id: &str, key: &StaticDecisionKeyV1) -> Result<String> {
    canonical_cbor(policy_id, key).map(|bytes| digest(&bytes))
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
        operation if operation_argument(operation, "PTRACE_ACCESS_").is_some() => {
            Some(KernelEffectOperationV1::Ptrace)
        }
        "SIGNAL" => Some(KernelEffectOperationV1::Signal),
        operation if operation_argument(operation, "SIGNAL_").is_some() => {
            Some(KernelEffectOperationV1::Signal)
        }
        "CREATE" => Some(KernelEffectOperationV1::Create),
        "SETATTR" => Some(KernelEffectOperationV1::Setattr),
        "UNLINK" => Some(KernelEffectOperationV1::Unlink),
        "LINK" => Some(KernelEffectOperationV1::Link),
        "RENAME" => Some(KernelEffectOperationV1::Rename),
        "MOUNT" => Some(KernelEffectOperationV1::Mount),
        "UNMOUNT" => Some(KernelEffectOperationV1::Unmount),
        "PIVOT_ROOT" => Some(KernelEffectOperationV1::PivotRoot),
        "MOVE_MOUNT" => Some(KernelEffectOperationV1::MoveMount),
        "CAPABILITY" => Some(KernelEffectOperationV1::Capability),
        "BPF" => Some(KernelEffectOperationV1::Bpf),
        "IO_URING_SETUP" => Some(KernelEffectOperationV1::IoUringSetup),
        "IO_URING_REGISTER" => Some(KernelEffectOperationV1::IoUringRegister),
        "IO_URING_SQPOLL" => Some(KernelEffectOperationV1::IoUringSqpoll),
        "IO_URING_OVERRIDE_CREDS" => Some(KernelEffectOperationV1::IoUringOverrideCreds),
        "IO_URING_COMMAND" => Some(KernelEffectOperationV1::IoUringCommand),
        _ => None,
    }
}

/// Return the exact Linux hook argument and whether the signed operation is a
/// denial-only wildcard.
#[must_use]
pub fn process_control_operation(operation: &str) -> Option<(KernelEffectOperationV1, u32, bool)> {
    match operation {
        "PTRACE" => Some((KernelEffectOperationV1::Ptrace, 0, true)),
        "SIGNAL" => Some((KernelEffectOperationV1::Signal, 0, true)),
        operation => operation_argument(operation, "PTRACE_ACCESS_")
            .map(|argument| (KernelEffectOperationV1::Ptrace, argument, false))
            .or_else(|| {
                operation_argument(operation, "SIGNAL_")
                    .map(|argument| (KernelEffectOperationV1::Signal, argument, false))
            }),
    }
}

fn operation_argument(operation: &str, prefix: &str) -> Option<u32> {
    let argument = operation.strip_prefix(prefix)?;
    if argument.is_empty() || (argument.len() > 1 && argument.starts_with('0')) {
        return None;
    }
    argument.parse().ok()
}

struct RuleDecision<'a> {
    rule: &'a DetectionDispositionRuleV1,
    physical_result: CompiledPhysicalResultV1,
    errno: Option<i16>,
    action_plan_digest: String,
}

fn resolve_cell(
    policy_id: &str,
    key: StaticDecisionKeyV1,
    candidates: &[RuleDecision<'_>],
) -> Result<CompiledDecisionCellV1> {
    let first = &candidates[0];
    if candidates.iter().all(|candidate| {
        candidate.physical_result == first.physical_result
            && candidate.errno == first.errno
            && candidate.action_plan_digest == first.action_plan_digest
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
            consuming_exception_id: first.rule.exception_ids.first().cloned(),
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
    Ok(CompiledDecisionCellV1 {
        key,
        physical_result: winner.physical_result,
        errno: winner.errno,
        consuming_exception_id: winner.rule.exception_ids.first().cloned(),
        action_plan_digest: winner.action_plan_digest.clone(),
        source_rule_ids: vec![winner.rule.rule_id.clone()],
    })
}

#[derive(Serialize)]
struct LocalActionPlan<'a> {
    evaluation_stage: EvaluationStageV1,
    requested_disposition: PolicyDispositionV1,
    errno: Option<super::source::ErrnoV1>,
    finding: &'a Option<super::source::FindingSpecV1>,
    response_binding_ids: &'a [String],
    required_proof: &'a ProofQualityPredicateV1,
    fallback_by_condition: &'a [super::source::FallbackV1],
    budgets: &'a super::source::BudgetSetV1,
    exception_ids: &'a [String],
    valid_from_utc_ns: Option<i64>,
    valid_until_utc_ns: Option<i64>,
}

fn local_action_plan_digest(
    policy_id: &str,
    rule: &DetectionDispositionRuleV1,
    effect: &super::source::LocalEffectMatchV1,
) -> Result<String> {
    let plan = LocalActionPlan {
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
    };
    canonical_cbor(policy_id, &plan).map(|bytes| digest(&bytes))
}

fn physical_result(
    rule: &DetectionDispositionRuleV1,
    mode: ProfileModeV1,
) -> Option<CompiledPhysicalResultV1> {
    disposition_result(rule.requested_disposition, mode)
}

fn disposition_result(
    disposition: PolicyDispositionV1,
    mode: ProfileModeV1,
) -> Option<CompiledPhysicalResultV1> {
    match disposition {
        PolicyDispositionV1::Allow => Some(CompiledPhysicalResultV1::AllowEffect),
        PolicyDispositionV1::Alert => Some(CompiledPhysicalResultV1::AuditAllowEffect),
        PolicyDispositionV1::Deny => Some(match mode {
            ProfileModeV1::Observe => CompiledPhysicalResultV1::SimulatablePolicyDeny,
            ProfileModeV1::Protect => CompiledPhysicalResultV1::DenyEffect,
        }),
        PolicyDispositionV1::Reject => None,
    }
}

fn default_keys(
    document: &PolicyDocumentV1,
    default: &super::source::EffectFamilyDefaultV1,
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
        let dimensions = RuleDimensions {
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
            // A family default is the signed result when no more specific
            // object cell is available. It is not one row per object class.
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
        check(
            policy_id,
            lengths.iter().all(|length| *length > 0),
            "CFG_EMPTY_EXPANSION",
            "a local rule selector expands to no signed decision cells",
        )?;
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

pub(super) fn object_cells(selector: &LocalObjectSelectorV1) -> Vec<String> {
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

pub(super) fn check(
    policy_id: &str,
    condition: bool,
    code: &'static str,
    reason: &str,
) -> Result<()> {
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
