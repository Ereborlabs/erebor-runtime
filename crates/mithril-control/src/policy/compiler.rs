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
    PostEffectMatchV1, ProfileModeV1, RuleMatchV1, StateBitScopeV1,
};
use super::source_proof::ProofQualityPredicateV1;
use crate::error::PolicyValidationSnafu;
use crate::Result;

const MAX_COMPILED_CELLS: usize = 65_536;
const MAX_EXCEPTION_STATES: usize = 4_096;

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
        self.validate(document)?;
        let canonical_policy = canonical_cbor(document.profile_id(), document)?;
        let source_policy_digest = digest(&canonical_policy);
        let cells = self.expand_rules(document)?;
        validate_compiled_exceptions(document, &cells)?;
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
        check(
            policy_id,
            document.exceptions.len() <= MAX_EXCEPTION_STATES,
            "CFG_MAP_CAPACITY",
            "exception states exceed the verified kernel map capacity",
        )?;
        check(
            policy_id,
            document.exceptions.is_empty()
                || document.rollout.desired_profile_mode == ProfileModeV1::Protect,
            "CFG_EXCEPTION_MODE",
            "bounded exceptions require PROTECT mode",
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
        validate_ids(document)?;
        validate_references(document)?;
        validate_entry_assignments(document)?;
        validate_states(document)?;
        validate_supporting_definitions(document)?;
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

fn validate_compiled_exceptions(
    document: &PolicyDocumentV1,
    cells: &[CompiledDecisionCellV1],
) -> Result<()> {
    for exception in &document.exceptions {
        let exception_id = exception.exception_id.as_str();
        let bound_cells = cells
            .iter()
            .filter(|cell| cell.consuming_exception_id.as_deref() == Some(exception_id))
            .collect::<Vec<_>>();
        let subject = &exception.exact_subject;
        let compiled_key_digests = bound_cells
            .iter()
            .map(|cell| compiled_key_digest(document.profile_id(), &cell.key))
            .collect::<Result<BTreeSet<_>>>()?;
        let protected_scope_ids = bound_cells
            .iter()
            .map(|cell| cell.key.protected_scope_id.as_str())
            .collect::<BTreeSet<_>>();
        let execution_set_ids = bound_cells
            .iter()
            .map(|cell| cell.key.execution_set_id.as_str())
            .collect::<BTreeSet<_>>();
        let entry_kind_ids = bound_cells
            .iter()
            .map(|cell| cell.key.entry_kind)
            .collect::<BTreeSet<_>>();
        let role_ids = bound_cells
            .iter()
            .map(|cell| cell.key.role_id.as_str())
            .collect::<BTreeSet<_>>();
        let changed_rule_ids = bound_cells
            .iter()
            .flat_map(|cell| cell.source_rule_ids.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        check(
            document.profile_id(),
            !bound_cells.is_empty()
                && bound_cells.len() == 1
                && matches!(
                    bound_cells[0].key.operation_id.as_str(),
                    "OPEN_READ" | "OPEN_WRITE"
                )
                && bound_cells
                    .iter()
                    .all(|cell| cell.physical_result == CompiledPhysicalResultV1::AllowEffect)
                && protected_scope_ids
                    == subject
                        .protected_scope_ids
                        .iter()
                        .map(String::as_str)
                        .collect()
                && execution_set_ids
                    == subject
                        .execution_set_ids
                        .iter()
                        .map(String::as_str)
                        .collect()
                && entry_kind_ids == subject.entry_kind_ids.iter().copied().collect()
                && role_ids == subject.role_ids.iter().map(String::as_str).collect()
                && compiled_key_digests
                    == subject.exact_compiled_key_digests.iter().cloned().collect()
                && compiled_key_digests
                    == exception
                        .authority_delta
                        .added_or_removed_operation_cells
                        .iter()
                        .cloned()
                        .collect()
                && exception
                    .authority_delta
                    .added_or_removed_transition_cells
                    .is_empty()
                && changed_rule_ids
                    == exception
                        .changed_rule_ids
                        .iter()
                        .map(String::as_str)
                        .collect(),
            "CFG_EXCEPTION_CELL",
            &format!(
                "exception `{exception_id}` does not exactly bind one qualified file-open allow cell"
            ),
        )?;
    }
    Ok(())
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
                .ipc_relationship_rules
                .iter()
                .map(|rule| &rule.relationship_rule_id),
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
                    RuleMatchV1::PostEffect(PostEffectMatchV1::LocalCompletion {
                        operation_ids,
                        ..
                    }) => operation_ids.iter(),
                    RuleMatchV1::EntryAdmission(_)
                    | RuleMatchV1::NativeTransition(_)
                    | RuleMatchV1::RemotePreAdmission(_)
                    | RuleMatchV1::PostEffect(_) => [].iter(),
                }),
        )
        .chain(
            document
                .ipc_relationship_rules
                .iter()
                .flat_map(|rule| rule.channel_class_ids.iter().chain(&rule.operations)),
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

fn validate_entry_assignments(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    for assignment in &document.entry_role_assignments {
        let role = document
            .roles
            .iter()
            .find(|role| role.role_id == assignment.resulting_role_id)
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_ROLE_REFERENCE",
                    reason: format!("entry `{}` has an unknown role", assignment.assignment_id),
                }
                .build()
            })?;
        check(
            policy_id,
            !assignment.workload_selector_ids.is_empty()
                && !assignment.entry_kinds.is_empty()
                && !assignment.container_kinds.is_empty()
                && !assignment.accepted_classifications.is_empty()
                && ordered_unique(&assignment.workload_selector_ids)
                && ordered_unique(&assignment.entry_kinds)
                && ordered_unique(&assignment.container_kinds)
                && ordered_unique(&assignment.immutable_definition_digests)
                && ordered_unique(&assignment.accepted_classifications)
                && assignment
                    .entry_kinds
                    .iter()
                    .all(|kind| role.permitted_entry_kinds.contains(kind)),
            "CFG_ENTRY_ASSIGNMENT",
            &format!(
                "entry `{}` must use nonempty ordered selectors and a role that permits every entry kind",
                assignment.assignment_id
            ),
        )?;
        let administrative_kind = assignment
            .entry_kinds
            .contains(&EntryKindV1::ApprovedAdministrativeExec);
        let administrative_classification = assignment
            .accepted_classifications
            .contains(&super::source::RootClassificationV1::ApprovedAdministrativeNextMatch);
        check(
            policy_id,
            if assignment.required_administrative_exec_approval
                || administrative_kind
                || administrative_classification
            {
                assignment.entry_kinds == [EntryKindV1::ApprovedAdministrativeExec]
                    && assignment.accepted_classifications
                        == [super::source::RootClassificationV1::ApprovedAdministrativeNextMatch]
                    && assignment.required_administrative_exec_approval
                    && assignment.required_purpose_source_capability_id.is_none()
                    && assignment.unknown_restricted_role_id.is_none()
            } else {
                true
            },
            "CFG_ADMINISTRATIVE_ENTRY",
            &format!(
                "entry `{}` must bind administrative approval to only APPROVED_ADMINISTRATIVE_EXEC and APPROVED_ADMINISTRATIVE_NEXT_MATCH",
                assignment.assignment_id
            ),
        )?;
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

fn validate_supporting_definitions(document: &PolicyDocumentV1) -> Result<()> {
    let policy_id = document.profile_id();
    let roles = document
        .roles
        .iter()
        .map(|role| role.role_id.as_str())
        .collect::<BTreeSet<_>>();
    let routes = document
        .notification_routes
        .iter()
        .map(|route| route.route_id.as_str())
        .collect::<BTreeSet<_>>();
    let responses = document
        .response_bindings
        .iter()
        .map(|binding| binding.binding_id.as_str())
        .collect::<BTreeSet<_>>();
    let exceptions = document
        .exceptions
        .iter()
        .map(|exception| exception.exception_id.as_str())
        .collect::<BTreeSet<_>>();
    check_unique(
        policy_id,
        document
            .notification_routes
            .iter()
            .map(|route| route.route_id.as_str()),
        "notification route",
    )?;
    check_unique(
        policy_id,
        document
            .response_bindings
            .iter()
            .map(|binding| binding.binding_id.as_str()),
        "response binding",
    )?;
    check_unique(
        policy_id,
        document
            .exceptions
            .iter()
            .map(|exception| exception.exception_id.as_str()),
        "exception",
    )?;
    check_unique(
        policy_id,
        document
            .ipc_relationship_rules
            .iter()
            .map(|rule| rule.relationship_rule_id.as_str()),
        "IPC relationship",
    )?;
    let mut ipc_decisions = BTreeMap::new();
    for relationship in &document.ipc_relationship_rules {
        check(
            policy_id,
            !relationship.source_role_ids.is_empty()
                && ordered_unique(&relationship.source_role_ids)
                && relationship
                    .source_role_ids
                    .iter()
                    .all(|role| roles.contains(role.as_str()))
                && !relationship.peer_role_ids.is_empty()
                && ordered_unique(&relationship.peer_role_ids)
                && relationship
                    .peer_role_ids
                    .iter()
                    .all(|role| roles.contains(role.as_str()))
                && relationship.channel_class_ids == ["UNIX_STREAM"]
                && relationship.operations == ["IPC_ACCESS"]
                && relationship.requested_disposition != PolicyDispositionV1::Reject
                && (relationship.requested_disposition == PolicyDispositionV1::Deny)
                    == relationship.errno.is_some(),
            "CFG_IPC_RELATIONSHIP",
            &format!(
                "IPC relationship `{}` must use defined roles, the UNIX_STREAM IPC_ACCESS surface, and an errno only for DENY",
                relationship.relationship_rule_id
            ),
        )?;
        for source in &relationship.source_role_ids {
            for peer in &relationship.peer_role_ids {
                let pair = if source <= peer {
                    (source.as_str(), peer.as_str())
                } else {
                    (peer.as_str(), source.as_str())
                };
                let decision = (relationship.requested_disposition, relationship.errno);
                if let Some(existing) = ipc_decisions.insert(pair, decision) {
                    check(
                        policy_id,
                        existing == decision,
                        "CFG_IPC_RELATIONSHIP_CONFLICT",
                        &format!(
                            "IPC relationship `{}` conflicts with another rule for roles `{}` and `{}`",
                            relationship.relationship_rule_id, pair.0, pair.1
                        ),
                    )?;
                }
            }
        }
    }
    check(
        policy_id,
        document.unmatched_ipc_disposition != PolicyDispositionV1::Reject,
        "CFG_IPC_UNMATCHED",
        "unmatched IPC must ALLOW, ALERT, or DENY at a local pre-effect hook",
    )?;
    for route in &document.notification_routes {
        check(
            policy_id,
            valid_local_id(&route.route_id)
                && valid_local_id(&route.sink_binding_id)
                && !route.grouping_fields.is_empty()
                && ordered_unique(&route.grouping_fields)
                && !route.allowed_evidence_fields.is_empty()
                && ordered_unique(&route.allowed_evidence_fields)
                && valid_duration(&route.dedupe_window, true),
            "CFG_NOTIFICATION_ROUTE",
            &format!("notification route `{}` is invalid", route.route_id),
        )?;
    }
    for binding in &document.response_bindings {
        check(
            policy_id,
            valid_local_id(&binding.binding_id)
                && proof_predicate_is_ordered(&binding.required_proof)
                && valid_duration(&binding.watch_interval, false)
                && response_contract_is_compatible(binding),
            "CFG_RESPONSE_BINDING",
            &format!(
                "response binding `{}` has an incompatible exact contract",
                binding.binding_id
            ),
        )?;
    }
    for default in &document.effect_family_defaults {
        check(
            policy_id,
            !default.role_ids.is_empty()
                && ordered_unique(&default.role_ids)
                && default
                    .role_ids
                    .iter()
                    .all(|role| roles.contains(role.as_str()))
                && !default.operations.is_empty()
                && ordered_unique(&default.operations)
                && default
                    .operations
                    .iter()
                    .all(|operation| operation_belongs_to_family(default.effect_family, operation))
                && matches!(
                    default.requested_disposition,
                    PolicyDispositionV1::Allow
                        | PolicyDispositionV1::Alert
                        | PolicyDispositionV1::Deny
                )
                && (default.requested_disposition == PolicyDispositionV1::Deny)
                    == default.errno.is_some()
                && (default.requested_disposition != PolicyDispositionV1::Alert
                    || default.finding.is_some()),
            "CFG_EFFECT_DEFAULT",
            "effect-family defaults must be exact, ordered local decisions",
        )?;
        check(
            policy_id,
            default.requested_disposition == PolicyDispositionV1::Deny
                || default
                    .operations
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "CAPABILITY" | "BPF")),
            "CFG_PRIVILEGE_WILDCARD",
            "generic CAPABILITY and BPF effect-family defaults are denial-only",
        )?;
        check(
            policy_id,
            default.requested_disposition == PolicyDispositionV1::Deny
                || default
                    .operations
                    .iter()
                    .all(|operation| !io_uring_denial_only_operation(operation)),
            "CFG_IO_URING_UNQUALIFIED_AUTHORITY",
            "io_uring register, SQPOLL, credential override, and command defaults are denial-only",
        )?;
        check(
            policy_id,
            default.requested_disposition == PolicyDispositionV1::Deny
                || default.effect_family != EffectFamilyV1::Network,
            "CFG_NETWORK_DEFAULT_AUTHORITY",
            "NETWORK effect-family defaults are denial-only",
        )?;
        check(
            policy_id,
            default.requested_disposition == PolicyDispositionV1::Deny
                || default.effect_family != EffectFamilyV1::Mount,
            "CFG_MOUNT_DEFAULT_AUTHORITY",
            "MOUNT effect-family defaults are denial-only",
        )?;
        check(
            policy_id,
            default.requested_disposition == PolicyDispositionV1::Deny
                || default.effect_family != EffectFamilyV1::Exec
                || default.operations.iter().all(|operation| {
                    !matches!(operation.as_str(), "EXECUTE" | "MMAP_EXEC" | "MPROTECT")
                }),
            "CFG_EXECUTABLE_MEMORY_AUTHORITY",
            "unqualified executable-image and executable-memory defaults are denial-only",
        )?;
        if let Some(finding) = &default.finding {
            validate_finding(policy_id, finding, &routes)?;
        }
    }
    for posture in [
        &document.default_postures.missing_task_identity,
        &document.default_postures.required_classifier_unknown,
        &document.default_postures.unresolved_or_external_root,
    ] {
        check(
            policy_id,
            posture.requested_disposition != PolicyDispositionV1::Allow
                && posture
                    .unknown_restricted_role_id
                    .as_ref()
                    .is_none_or(|role| roles.contains(role.as_str()))
                && (posture.requested_disposition != PolicyDispositionV1::Alert
                    || posture.unknown_restricted_role_id.is_some()),
            "CFG_DEFAULT_POSTURE",
            "an alerting default posture needs an installed restricted role",
        )?;
        validate_finding(policy_id, &posture.finding, &routes)?;
    }
    for rule in &document.rules {
        check(
            policy_id,
            ordered_unique(&rule.response_binding_ids)
                && rule
                    .response_binding_ids
                    .iter()
                    .all(|binding| responses.contains(binding.as_str()))
                && ordered_unique(&rule.exception_ids)
                && rule
                    .exception_ids
                    .iter()
                    .all(|exception| exceptions.contains(exception.as_str()))
                && rule.exception_ids.len() <= 1
                && (rule.exception_ids.is_empty()
                    || (rule.evaluation_stage == EvaluationStageV1::LocalPreEffect
                        && rule.requested_disposition == PolicyDispositionV1::Allow))
                && ordered_unique(&rule.overrides_rule_ids)
                && budget_is_empty(&rule.budgets)
                && (rule.finding.is_some()
                    || (rule.response_binding_ids.is_empty()
                        && rule.requested_disposition != PolicyDispositionV1::Alert))
                && match (rule.valid_from_utc_ns, rule.valid_until_utc_ns) {
                    (Some(from), Some(until)) => until > from,
                    _ => true,
                },
            "CFG_RULE_ACTION",
            &format!("rule `{}` has an invalid action plan", rule.rule_id),
        )?;
        if let Some(finding) = &rule.finding {
            validate_finding(policy_id, finding, &routes)?;
        }
        check(
            policy_id,
            ordered_unique(
                &rule
                    .fallback_by_condition
                    .iter()
                    .map(|fallback| fallback.condition)
                    .collect::<Vec<_>>(),
            ),
            "CFG_FALLBACK_ORDER",
            &format!(
                "rule `{}` fallbacks must be sorted and unique",
                rule.rule_id
            ),
        )?;
        for fallback in &rule.fallback_by_condition {
            check(
                policy_id,
                fallback_legal(rule.evaluation_stage, fallback.requested_disposition)
                    && (fallback.requested_disposition == PolicyDispositionV1::Deny)
                        == fallback.errno.is_some()
                    && fallback
                        .unknown_restricted_role_id
                        .as_ref()
                        .is_none_or(|role| roles.contains(role.as_str()))
                    && (fallback.requested_disposition != PolicyDispositionV1::Alert
                        || fallback.unknown_restricted_role_id.is_some()),
                "CFG_FALLBACK_STAGE",
                &format!("rule `{}` has an unsafe fallback", rule.rule_id),
            )?;
            validate_finding(policy_id, &fallback.finding, &routes)?;
        }
    }
    validate_exceptions(document, &roles)?;
    validate_authority_rules(document, &routes, &responses)?;
    validate_coverage_rules(document, &routes, &responses)?;
    Ok(())
}

fn validate_finding(
    policy_id: &str,
    finding: &super::source::FindingSpecV1,
    routes: &BTreeSet<&str>,
) -> Result<()> {
    check(
        policy_id,
        valid_registry_symbol(&finding.reason_code)
            && ordered_unique(&finding.route_ids)
            && finding
                .route_ids
                .iter()
                .all(|route| routes.contains(route.as_str()))
            && finding
                .title_template_id
                .as_ref()
                .is_none_or(|id| valid_local_id(id)),
        "CFG_FINDING",
        "finding reason, routes, or title template is invalid",
    )
}

fn budget_is_empty(budget: &super::source::BudgetSetV1) -> bool {
    budget.rate_limits.is_empty()
        && budget.concurrency_limits.is_empty()
        && budget.maximum_lifetime.is_none()
        && budget.automatic_response_limit.is_none()
}

fn fallback_legal(stage: EvaluationStageV1, disposition: PolicyDispositionV1) -> bool {
    match stage {
        EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(
            disposition,
            PolicyDispositionV1::Alert | PolicyDispositionV1::Reject
        ),
        EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(
            disposition,
            PolicyDispositionV1::Alert | PolicyDispositionV1::Deny
        ),
        EvaluationStageV1::PostEffect => disposition == PolicyDispositionV1::Alert,
    }
}

fn response_contract_is_compatible(binding: &super::source_response::ResponseBindingV1) -> bool {
    use super::source_response::{
        BlastRadiusLimitV1 as Blast, PhysicalPostconditionV1 as Post,
        ResponseActionSpecV1 as Action, TargetRevalidationV1 as Target,
    };

    matches!(
        (
            &binding.action_spec,
            binding.target_revalidation,
            binding.physical_postcondition,
            &binding.maximum_blast_radius
        ),
        (
            Action::RestrictLineage,
            Target::LineageRootAndCompleteEffectiveResponseSet,
            Post::ResponseSetInstalledAndDescendantsReconciled,
            Blast::Local { .. }
        ) | (
            Action::FenceSockets,
            Target::SocketCookieProvenanceAndLiveBinding,
            Post::SocketSetFencedAndExistingFlowOraclePassed,
            Blast::Local { .. }
        ) | (
            Action::FreezeCgroup,
            Target::CgroupFdNonceAndMemberSet,
            Post::CgroupFrozenAndPacketFenceActive,
            Blast::Local { .. }
        ) | (
            Action::TerminateProcessPidfd,
            Target::ProcessPidfdTaskCookieStarttimeCgroupBinding,
            Post::ProcessStoppedViaPidfd,
            Blast::Local { .. }
        ) | (
            Action::RejectKubernetesReplacement { .. },
            Target::KubernetesUidResourceVersion,
            Post::ReplacementRejectedThroughWatchWatermark,
            Blast::Kubernetes { .. }
        ) | (
            Action::RevokeCredential { .. },
            Target::ProviderStableIdRevisionAndAuthority,
            Post::ProviderCredentialActionReadBack,
            Blast::Credential { .. }
        ) | (
            Action::DisableMeshDevice { .. },
            Target::ProviderStableIdRevisionAndAuthority,
            Post::MeshDeviceDisabledAndHandshakeRejected,
            Blast::Mesh { .. }
        ) | (
            Action::QuarantineArtifact { .. },
            Target::ArtifactImmutableDigestAndStoreRevision,
            Post::ArtifactQuarantinedAndConsumerLoadRejected,
            Blast::Artifact { .. }
        ) | (
            Action::SuspendInstallation { .. },
            Target::ProviderStableIdRevisionAndAuthority,
            Post::ProviderOperationSpecificPostcondition,
            Blast::SourceControl { .. }
        ) | (
            Action::ProviderSpecific { .. },
            Target::ProviderStableIdRevisionAndAuthority,
            Post::ProviderOperationSpecificPostcondition,
            Blast::ProviderResources { .. }
        )
    ) && blast_radius_is_bounded(&binding.maximum_blast_radius)
}

fn blast_radius_is_bounded(limit: &super::source_response::BlastRadiusLimitV1) -> bool {
    use super::source_response::BlastRadiusLimitV1 as Blast;
    match limit {
        Blast::Local {
            permitted_target_selector_ids,
            process_count,
            execution_set_count,
            socket_count,
            node_count,
        } => {
            ordered_unique(permitted_target_selector_ids)
                && [
                    *process_count,
                    *execution_set_count,
                    *socket_count,
                    *node_count,
                ]
                .into_iter()
                .all(|count| count > 0)
        }
        Blast::Kubernetes {
            permitted_namespace_uids,
            object_count,
            controller_count,
            node_count,
        } => {
            ordered_unique(permitted_namespace_uids)
                && [*object_count, *controller_count, *node_count]
                    .into_iter()
                    .all(|count| count > 0)
        }
        Blast::Credential {
            permitted_provider_account_ids,
            session_count,
            principal_count,
            role_count,
            account_count,
        } => {
            ordered_unique(permitted_provider_account_ids)
                && [
                    *session_count,
                    *principal_count,
                    *role_count,
                    *account_count,
                ]
                .into_iter()
                .all(|count| count > 0)
        }
        Blast::Mesh {
            permitted_tailnet_or_tenant_ids,
            device_count,
            route_count,
            auth_key_count,
        } => {
            ordered_unique(permitted_tailnet_or_tenant_ids)
                && [*device_count, *route_count, *auth_key_count]
                    .into_iter()
                    .all(|count| count > 0)
        }
        Blast::SourceControl {
            permitted_organization_ids,
            installation_count,
            repository_count,
            ref_or_pr_count,
        } => {
            ordered_unique(permitted_organization_ids)
                && [*installation_count, *repository_count, *ref_or_pr_count]
                    .into_iter()
                    .all(|count| count > 0)
        }
        Blast::Artifact {
            permitted_store_ids,
            artifact_count,
            consumer_count,
        } => ordered_unique(permitted_store_ids) && *artifact_count > 0 && *consumer_count > 0,
        Blast::ProviderResources {
            permitted_provider_account_ids,
            permitted_resource_selector_ids,
            resource_count,
            principal_count,
        } => {
            ordered_unique(permitted_provider_account_ids)
                && ordered_unique(permitted_resource_selector_ids)
                && *resource_count > 0
                && *principal_count > 0
        }
    }
}

fn validate_exceptions(document: &PolicyDocumentV1, roles: &BTreeSet<&str>) -> Result<()> {
    let policy_id = document.profile_id();
    let rule_ids = document
        .rules
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    let scopes = document
        .protected_universe
        .protected_scope_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let execution_sets = document
        .protected_universe
        .execution_set_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for exception in &document.exceptions {
        let subject = &exception.exact_subject;
        check(
            policy_id,
            valid_local_id(&exception.exception_id)
                && Uuid::parse_str(&exception.exception_instance_id).is_ok()
                && Uuid::parse_str(&exception.approver_principal_id).is_ok()
                && valid_digest(&exception.approval_proof_digest)
                && valid_registry_symbol(&exception.closed_reason_code)
                && exception.valid_until_utc_ns > exception.valid_from_utc_ns
                && exception.maximum_uses > 0
                && exception.maximum_lifetime_ns > 0
                && !exception.changed_rule_ids.is_empty()
                && ordered_unique(&exception.changed_rule_ids)
                && exception
                    .changed_rule_ids
                    .iter()
                    .all(|rule| rule_ids.contains(rule.as_str()))
                && !subject.protected_scope_ids.is_empty()
                && ordered_unique(&subject.protected_scope_ids)
                && subject
                    .protected_scope_ids
                    .iter()
                    .all(|scope| scopes.contains(scope.as_str()))
                && !subject.execution_set_ids.is_empty()
                && ordered_unique(&subject.execution_set_ids)
                && subject
                    .execution_set_ids
                    .iter()
                    .all(|set| execution_sets.contains(set.as_str()))
                && !subject.entry_kind_ids.is_empty()
                && ordered_unique(&subject.entry_kind_ids)
                && !subject.role_ids.is_empty()
                && ordered_unique(&subject.role_ids)
                && subject
                    .role_ids
                    .iter()
                    .all(|role| roles.contains(role.as_str()))
                && ordered_unique(&subject.immutable_definition_digests)
                && subject
                    .immutable_definition_digests
                    .iter()
                    .all(|digest| valid_digest(digest))
                && !subject.exact_compiled_key_digests.is_empty()
                && ordered_unique(&subject.exact_compiled_key_digests)
                && subject
                    .exact_compiled_key_digests
                    .iter()
                    .all(|digest| valid_digest(digest))
                && exception.authority_delta.from_physical_result == "DENY_ERRNO"
                && exception.authority_delta.to_physical_result == "ALLOW_EFFECT"
                && ordered_unique(&exception.authority_delta.added_or_removed_operation_cells)
                && exception
                    .authority_delta
                    .added_or_removed_operation_cells
                    .iter()
                    .all(|digest| valid_digest(digest))
                && ordered_unique(&exception.authority_delta.added_or_removed_transition_cells)
                && exception
                    .authority_delta
                    .added_or_removed_transition_cells
                    .iter()
                    .all(|digest| valid_digest(digest))
                && blast_radius_is_bounded(&exception.authority_delta.maximum_blast_radius),
            "CFG_EXCEPTION",
            &format!(
                "exception `{}` is not a bounded exact authority delta",
                exception.exception_id
            ),
        )?;
    }
    Ok(())
}

fn validate_authority_rules(
    document: &PolicyDocumentV1,
    routes: &BTreeSet<&str>,
    responses: &BTreeSet<&str>,
) -> Result<()> {
    use super::source::AuthorityBehaviorRuleV1 as Rule;

    let policy_id = document.profile_id();
    let ids = document
        .authority_behavior_rules
        .iter()
        .map(|rule| match rule {
            Rule::RemoteAdmission { rule_id, .. } | Rule::PostEffectResult { rule_id, .. } => {
                rule_id.as_str()
            }
        })
        .collect::<Vec<_>>();
    check_unique(policy_id, ids.iter().copied(), "authority behavior rule")?;
    for rule in &document.authority_behavior_rules {
        let (
            rule_id,
            accounts,
            principals,
            operations,
            resources,
            proof,
            disposition,
            finding,
            response_ids,
            budgets,
            legal,
        ) = match rule {
            Rule::RemoteAdmission {
                rule_id,
                authorization_interface_capability_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                ..
            } => (
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                valid_local_id(authorization_interface_capability_id)
                    && matches!(
                        requested_disposition,
                        PolicyDispositionV1::Allow
                            | PolicyDispositionV1::Alert
                            | PolicyDispositionV1::Reject
                    ),
            ),
            Rule::PostEffectResult {
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                authoritative_results,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                ..
            } => (
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                !authoritative_results.is_empty()
                    && ordered_unique(authoritative_results)
                    && matches!(
                        requested_disposition,
                        PolicyDispositionV1::Allow | PolicyDispositionV1::Alert
                    ),
            ),
        };
        check(
            policy_id,
            valid_local_id(rule_id)
                && legal
                && ordered_unique(accounts)
                && ordered_unique(principals)
                && !operations.is_empty()
                && ordered_unique(operations)
                && ordered_unique(resources)
                && proof_predicate_is_ordered(proof)
                && ordered_unique(response_ids)
                && response_ids
                    .iter()
                    .all(|id| responses.contains(id.as_str()))
                && budget_is_empty(budgets)
                && (finding.is_some()
                    || (response_ids.is_empty() && *disposition != PolicyDispositionV1::Alert)),
            "CFG_AUTHORITY_RULE",
            &format!("authority behavior rule `{rule_id}` is invalid"),
        )?;
        if let Some(finding) = finding {
            validate_finding(policy_id, finding, routes)?;
        }
    }
    Ok(())
}

fn validate_coverage_rules(
    document: &PolicyDocumentV1,
    routes: &BTreeSet<&str>,
    responses: &BTreeSet<&str>,
) -> Result<()> {
    use super::source::CoverageGapActionV1 as Action;

    let policy_id = document.profile_id();
    check_unique(
        policy_id,
        document
            .source_coverage_health_rules
            .iter()
            .map(|rule| rule.health_rule_id.as_str()),
        "source coverage health rule",
    )?;
    let scopes = document
        .protected_universe
        .protected_scope_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for rule in &document.source_coverage_health_rules {
        let independent = match rule.on_gap {
            Action::Alert => {
                rule.independent_admission_interface_binding_id.is_none()
                    && rule.independent_admission_capability_id.is_none()
                    && rule.independent_response_binding_ids.is_empty()
            }
            Action::RejectNewAdmission => {
                rule.independent_admission_interface_binding_id.is_some()
                    && rule.independent_admission_capability_id.is_some()
            }
            Action::InstallIndependentFence => !rule.independent_response_binding_ids.is_empty(),
        };
        check(
            policy_id,
            valid_local_id(&rule.health_rule_id)
                && valid_local_id(&rule.required_source_id)
                && !rule.protected_scope_ids.is_empty()
                && ordered_unique(&rule.protected_scope_ids)
                && rule
                    .protected_scope_ids
                    .iter()
                    .all(|scope| scopes.contains(scope.as_str()))
                && valid_duration(&rule.maximum_gap, false)
                && rule
                    .independent_admission_interface_binding_id
                    .as_ref()
                    .is_none_or(|id| valid_local_id(id))
                && rule
                    .independent_admission_capability_id
                    .as_ref()
                    .is_none_or(|id| valid_local_id(id))
                && ordered_unique(&rule.independent_response_binding_ids)
                && rule
                    .independent_response_binding_ids
                    .iter()
                    .all(|id| responses.contains(id.as_str()))
                && independent,
            "CFG_COVERAGE_RULE",
            &format!(
                "coverage rule `{}` lacks an independent exact fallback",
                rule.health_rule_id
            ),
        )?;
        validate_finding(policy_id, &rule.finding, routes)?;
    }
    Ok(())
}

fn check_unique<'a>(policy_id: &str, ids: impl Iterator<Item = &'a str>, kind: &str) -> Result<()> {
    let duplicates = duplicate_ids(ids);
    check(
        policy_id,
        duplicates.is_empty(),
        "CFG_DUPLICATE_ID",
        &format!("duplicate {kind} IDs: {duplicates:?}"),
    )
}

fn valid_duration(value: &str, zero_allowed: bool) -> bool {
    let suffix_length = if value.ends_with("ns") || value.ends_with("us") || value.ends_with("ms") {
        2
    } else if value.ends_with('s') || value.ends_with('m') || value.ends_with('h') {
        1
    } else {
        return false;
    };
    let digits = &value[..value.len() - suffix_length];
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && digits
            .parse::<u64>()
            .is_ok_and(|duration| zero_allowed || duration > 0)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
            RuleMatchV1::EntryAdmission(_) => EvaluationStageV1::EntryAdmission,
            RuleMatchV1::LocalPreEffect(_) => EvaluationStageV1::LocalPreEffect,
            RuleMatchV1::NativeTransition(_) => EvaluationStageV1::NativeTransition,
            RuleMatchV1::RemotePreAdmission(_) => EvaluationStageV1::RemotePreAdmission,
            RuleMatchV1::PostEffect(_) => EvaluationStageV1::PostEffect,
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
                    && ordered_unique(&effect.binding_lifecycle_states)
                    && proof_predicate_is_ordered(&effect.required_proof),
                "CFG_EMPTY_REQUIRED_SELECTOR",
                &format!(
                    "rule `{}` has an empty or unordered local selector",
                    rule.rule_id
                ),
            )?;
            check(
                policy_id,
                rule.requested_disposition == PolicyDispositionV1::Deny
                    || effect
                        .operation_ids
                        .iter()
                        .all(|operation| !matches!(operation.as_str(), "CAPABILITY" | "BPF")),
                "CFG_PRIVILEGE_WILDCARD",
                &format!(
                    "rule `{}` uses generic CAPABILITY or BPF authority; these operations are denial-only",
                    rule.rule_id
                ),
            )?;
            check(
                policy_id,
                rule.requested_disposition == PolicyDispositionV1::Deny
                    || effect
                        .operation_ids
                        .iter()
                        .all(|operation| !io_uring_denial_only_operation(operation)),
                "CFG_IO_URING_UNQUALIFIED_AUTHORITY",
                &format!(
                    "rule `{}` uses unqualified io_uring authority; register, SQPOLL, credential override, and command operations are denial-only",
                    rule.rule_id
                ),
            )?;
            check(
                policy_id,
                rule.requested_disposition == PolicyDispositionV1::Deny
                    || !effect.effect_families.contains(&EffectFamilyV1::Exec)
                    || effect
                        .operation_ids
                        .iter()
                        .all(|operation| !matches!(operation.as_str(), "MMAP_EXEC" | "MPROTECT"))
                    || matches!(
                        &effect.object,
                        LocalObjectSelectorV1::ExactObjectKeys { .. }
                    ),
                "CFG_EXECUTABLE_MEMORY_AUTHORITY",
                &format!(
                    "rule `{}` must use exact object keys to allow or alert on executable memory",
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
                LocalObjectSelectorV1::Devices {
                    ioctl_command_ids, ..
                } => check(
                    policy_id,
                    rule.requested_disposition == PolicyDispositionV1::Deny
                        || !ioctl_command_ids.is_empty(),
                    "CFG_DEVICE_IOCTL_WILDCARD",
                    &format!(
                        "rule `{}` must name exact ioctl commands to allow or alert",
                        rule.rule_id
                    ),
                )?,
                _ => {}
            }
            if let LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                target_selector_ids,
            } = &effect.object
            {
                if security_object_ids.iter().any(|object| object == "PROCESS") {
                    check(
                        policy_id,
                        security_object_ids.as_slice() == ["PROCESS"]
                            && target_selector_ids.len() == 1
                            && universe.roles.contains(target_selector_ids[0].as_str())
                            && effect.effect_families.as_slice() == [EffectFamilyV1::Privilege]
                            && effect.operation_ids.iter().all(|operation| {
                                process_control_operation(operation).is_some_and(
                                    |(_, _, wildcard)| {
                                        !wildcard
                                            || rule.requested_disposition
                                                == PolicyDispositionV1::Deny
                                    },
                                )
                            }),
                        "CFG_PROCESS_CONTROL_KEY",
                        &format!(
                            "rule `{}` must name one target role and exact process-control arguments; a wildcard is denial-only",
                            rule.rule_id
                        ),
                    )?;
                }
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
        } else if let RuleMatchV1::EntryAdmission(entry) = &rule.rule_match {
            universe.validate_subject(policy_id, &rule.rule_id, &entry.subject)?;
            check(
                policy_id,
                !entry.runtime_operations.is_empty()
                    && !entry.root_classifications.is_empty()
                    && ordered_unique(&entry.runtime_operations)
                    && ordered_unique(&entry.root_classifications)
                    && ordered_unique(&entry.source_proof_qualities)
                    && ordered_unique(&entry.required_purpose_source_capability_ids)
                    && ordered_unique(&entry.immutable_definition_digests),
                "CFG_ENTRY_ADMISSION_MATCH",
                &format!("rule `{}` has an invalid entry selector", rule.rule_id),
            )?;
        } else if let RuleMatchV1::RemotePreAdmission(remote) = &rule.rule_match {
            universe.validate_subject(policy_id, &rule.rule_id, &remote.subject)?;
            check(
                policy_id,
                !remote.gate_capability_ids.is_empty()
                    && !remote.providers.is_empty()
                    && !remote.operation_ids.is_empty()
                    && ordered_unique(&remote.gate_capability_ids)
                    && ordered_unique(&remote.providers)
                    && ordered_unique(&remote.provider_account_ids)
                    && ordered_unique(&remote.operation_ids)
                    && ordered_unique(&remote.resources)
                    && ordered_unique(&remote.required_lease_permission_ids)
                    && proof_predicate_is_ordered(&remote.required_proof),
                "CFG_REMOTE_ADMISSION_MATCH",
                &format!("rule `{}` has an invalid remote selector", rule.rule_id),
            )?;
        } else if let RuleMatchV1::PostEffect(post) = &rule.rule_match {
            validate_post_effect(policy_id, &rule.rule_id, post, &universe)?;
        }
    }
    Ok(())
}

fn validate_post_effect(
    policy_id: &str,
    rule_id: &str,
    post: &PostEffectMatchV1,
    universe: &RuleUniverse<'_>,
) -> Result<()> {
    let valid = match post {
        PostEffectMatchV1::LocalCompletion {
            subject,
            effect_families,
            operation_ids,
            authoritative_results,
            required_proof,
        } => {
            universe.validate_subject(policy_id, rule_id, subject)?;
            !effect_families.is_empty()
                && !operation_ids.is_empty()
                && !authoritative_results.is_empty()
                && ordered_unique(effect_families)
                && ordered_unique(operation_ids)
                && ordered_unique(authoritative_results)
                && effect_families.iter().all(|family| {
                    operation_ids
                        .iter()
                        .all(|operation| operation_belongs_to_family(*family, operation))
                })
                && proof_predicate_is_ordered(required_proof)
        }
        PostEffectMatchV1::ProviderResult {
            providers,
            provider_account_ids,
            operation_ids,
            resources,
            authoritative_results,
            required_proof,
        } => {
            !providers.is_empty()
                && !operation_ids.is_empty()
                && !authoritative_results.is_empty()
                && ordered_unique(providers)
                && ordered_unique(provider_account_ids)
                && ordered_unique(operation_ids)
                && ordered_unique(resources)
                && ordered_unique(authoritative_results)
                && proof_predicate_is_ordered(required_proof)
        }
        PostEffectMatchV1::CorrelationFinding {
            package_ids,
            reason_codes,
            finding_states,
            required_proof,
        } => {
            !package_ids.is_empty()
                && !finding_states.is_empty()
                && ordered_unique(package_ids)
                && ordered_unique(reason_codes)
                && ordered_unique(finding_states)
                && proof_predicate_is_ordered(required_proof)
        }
    };
    check(
        policy_id,
        valid,
        "CFG_POST_EFFECT_MATCH",
        &format!("rule `{rule_id}` has an invalid post-effect selector"),
    )
}

fn proof_predicate_is_ordered(proof: &ProofQualityPredicateV1) -> bool {
    ordered_unique(&proof.source_authority)
        && ordered_unique(&proof.local_subject_binding)
        && ordered_unique(&proof.remote_subject_binding)
        && ordered_unique(&proof.operation_result_authority)
        && ordered_unique(&proof.temporal_coverage)
        && ordered_unique(&proof.integrity)
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
                | "CREATE"
                | "SETATTR"
                | "UNLINK"
                | "LINK"
                | "RENAME"
        ),
        EffectFamilyV1::Network => matches!(operation, "CONNECT" | "SEND"),
        EffectFamilyV1::Device => operation == "IOCTL",
        EffectFamilyV1::Privilege => {
            matches!(operation, "CAPABILITY" | "BPF")
                || matches!(
                    operation,
                    "IO_URING_SETUP"
                        | "IO_URING_REGISTER"
                        | "IO_URING_SQPOLL"
                        | "IO_URING_OVERRIDE_CREDS"
                        | "IO_URING_COMMAND"
                )
                || process_control_operation(operation).is_some()
        }
        EffectFamilyV1::Ipc => operation == "IPC_ACCESS",
        EffectFamilyV1::Mount => {
            matches!(operation, "MOUNT" | "UNMOUNT" | "PIVOT_ROOT" | "MOVE_MOUNT")
        }
    }
}

fn io_uring_denial_only_operation(operation: &str) -> bool {
    matches!(
        operation,
        "IO_URING_REGISTER" | "IO_URING_SQPOLL" | "IO_URING_OVERRIDE_CREDS" | "IO_URING_COMMAND"
    )
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
        Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value),
        "CFG_ID128",
        &format!("{field} must be a canonical lowercase hyphenated Id128 UUID"),
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
