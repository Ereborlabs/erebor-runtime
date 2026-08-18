use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_saphyr::granit_parser::{Event, Parser};
use serde_saphyr::{Budget, DuplicateKeyPolicy, MergeKeyPolicy, Options};
use snafu::ResultExt as _;

use crate::error::{PolicySourceSnafu, PolicyValidationSnafu};
use crate::Result;

use super::source_proof::{
    AuthoritativeResultV1, FindingStateV1, ProofQualityPredicateV1, ProofQualityV1, ProviderV1,
    ResourceSelectorV1, RuntimeOperationV1,
};
use super::source_response::{BlastRadiusLimitV1, NotificationRouteV1, ResponseBindingV1};

pub const MAX_POLICY_SOURCE_BYTES: usize = 1_048_576;
const MAX_POLICY_NODES: usize = 32_768;
const MAX_POLICY_DEPTH: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentV1 {
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadataV1,
    pub required_capability_ids: Vec<String>,
    pub protected_universe: ProtectedUniverseV1,
    pub workload_selectors: Vec<WorkloadSelectorV1>,
    pub classifier_bindings: Vec<ObjectClassifierBindingV1>,
    #[serde(default)]
    pub path_tree_deny_floors: Vec<PathTreeDenyFloorV1>,
    pub roles: Vec<RoleDefinitionV1>,
    pub entry_role_assignments: Vec<EntryRoleAssignmentV1>,
    pub native_transition_rules: Vec<NativeRoleTransitionRuleV1>,
    pub state_bit_definitions: Vec<StateBitDefinitionV1>,
    pub process_state_definitions: Vec<ProcessStateDefinitionV1>,
    pub native_authority_state_rules: Vec<NativeAuthorityStateRuleV1>,
    pub ipc_relationship_rules: Vec<IpcRelationshipRuleV1>,
    pub unmatched_ipc_disposition: PolicyDispositionV1,
    pub effect_family_defaults: Vec<EffectFamilyDefaultV1>,
    pub authority_behavior_rules: Vec<AuthorityBehaviorRuleV1>,
    pub correlation_package_bindings: Vec<CorrelationPackageBindingV1>,
    pub default_postures: DefaultPosturesV1,
    pub notification_routes: Vec<NotificationRouteV1>,
    pub response_bindings: Vec<ResponseBindingV1>,
    pub exceptions: Vec<ExceptionV1>,
    pub rules: Vec<DetectionDispositionRuleV1>,
    pub source_coverage_health_rules: Vec<SourceCoverageHealthRuleV1>,
    pub rollout: RolloutV1,
}

impl PolicyDocumentV1 {
    pub fn parse(path: &Path, source: &[u8]) -> Result<Self> {
        if source.len() > MAX_POLICY_SOURCE_BYTES {
            return PolicyValidationSnafu {
                policy_id: "<unparsed>",
                code: "CFG_SOURCE_SIZE",
                reason: format!(
                    "source is {} bytes; the Version 1 limit is {MAX_POLICY_SOURCE_BYTES}",
                    source.len()
                ),
            }
            .fail();
        }
        let text = std::str::from_utf8(source).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: "<unparsed>",
                code: "CFG_SOURCE_UTF8",
                reason: error.to_string(),
            }
            .build()
        })?;
        reject_yaml_extensions(text)?;
        let mut budget = Budget::default();
        budget.max_reader_input_bytes = Some(MAX_POLICY_SOURCE_BYTES);
        budget.max_events = MAX_POLICY_NODES.saturating_mul(3);
        budget.max_aliases = 0;
        budget.max_anchors = 0;
        budget.max_depth = MAX_POLICY_DEPTH;
        budget.max_inclusion_depth = 0;
        budget.max_documents = 1;
        budget.max_nodes = MAX_POLICY_NODES;
        budget.max_total_scalar_bytes = MAX_POLICY_SOURCE_BYTES;
        budget.max_total_comment_bytes = MAX_POLICY_SOURCE_BYTES;
        budget.max_merge_keys = 0;
        let mut options = Options::default();
        options.budget = Some(budget);
        options.duplicate_keys = DuplicateKeyPolicy::Error;
        options.merge_keys = MergeKeyPolicy::Error;
        options.alias_limits = serde_saphyr::alias_limits! {
            max_total_replayed_events: 0,
            max_replay_stack_depth: 0,
            max_alias_expansions_per_anchor: 0,
        };
        options.strict_booleans = true;
        options.reject_non_finite_typeless_float = true;
        serde_saphyr::from_slice_with_options(source, options).context(PolicySourceSnafu {
            path: PathBuf::from(path),
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.metadata.profile_id
    }
}

fn reject_yaml_extensions(source: &str) -> Result<()> {
    let mut documents = 0_usize;
    for parsed in Parser::new_from_str(source) {
        let (event, _span) = parsed.map_err(|error| {
            PolicyValidationSnafu {
                policy_id: "<unparsed>",
                code: "CFG_YAML_SYNTAX",
                reason: error.to_string(),
            }
            .build()
        })?;
        let forbidden = match event {
            Event::DocumentStart(_, _) => {
                documents = documents.saturating_add(1);
                None
            }
            Event::Alias(_) => Some("aliases are forbidden"),
            Event::Scalar(_, _, anchor, ref tag) => extension_reason(anchor, tag.as_deref()),
            Event::SequenceStart(_, anchor, ref tag) | Event::MappingStart(_, anchor, ref tag) => {
                extension_reason(anchor, tag.as_deref())
            }
            _ => None,
        };
        if let Some(reason) = forbidden {
            return PolicyValidationSnafu {
                policy_id: "<unparsed>",
                code: "CFG_YAML_EXTENSION",
                reason,
            }
            .fail();
        }
    }
    if documents != 1 {
        return PolicyValidationSnafu {
            policy_id: "<unparsed>",
            code: "CFG_YAML_DOCUMENT_COUNT",
            reason: format!("expected one YAML document, found {documents}"),
        }
        .fail();
    }
    Ok(())
}

fn extension_reason(
    anchor: usize,
    tag: Option<&serde_saphyr::granit_parser::Tag>,
) -> Option<&'static str> {
    if anchor != 0 {
        Some("anchors are forbidden")
    } else if tag.is_some_and(|tag| !tag.is_yaml_core_schema()) {
        Some("custom tags are forbidden")
    } else {
        None
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadataV1 {
    pub profile_id: String,
    pub profile_version: u64,
    pub trust_domain_id: String,
    pub valid_from_utc: String,
    pub valid_until_utc: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedUniverseV1 {
    pub workload_selector_ids: Vec<String>,
    pub protected_scope_ids: Vec<String>,
    pub execution_set_ids: Vec<String>,
    pub role_ids: Vec<String>,
    pub entry_kind_ids: Vec<EntryKindV1>,
    pub object_class_ids: Vec<String>,
    pub provider_account_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRequirementV1 {
    pub key: String,
    pub operator: LabelOperatorV1,
    pub values: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LabelOperatorV1 {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSelectorV1 {
    pub workload_selector_id: String,
    pub cluster_uids: Vec<String>,
    pub namespace_uids: Vec<String>,
    pub controller_uids: Vec<String>,
    pub service_account_uids: Vec<String>,
    pub pod_label_requirements: Vec<LabelRequirementV1>,
    pub container_names: Vec<String>,
    pub container_kinds: Vec<ContainerKindV1>,
    pub image_digests: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainerKindV1 {
    Init,
    Sidecar,
    Application,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectClassifierBindingV1 {
    pub classifier_binding_id: String,
    pub object_class_id: String,
    pub selector: ObjectClassifierSelectorV1,
    pub required_capability_ids: Vec<String>,
    pub unknown_result: UnknownClassifierResultV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectClassifierSelectorV1 {
    ProjectedServiceAccountToken {
        workload_selector_ids: Vec<String>,
        service_account_uids: Vec<String>,
        required_projected_source: ProjectedSourceV1,
        required_mount_read_only: bool,
    },
    FilesystemObject {
        workload_selector_ids: Vec<String>,
        mount_source_class_ids: Vec<String>,
        relative_component_bytes: Vec<String>,
        filesystem_type_ids: Vec<String>,
        required_object_type: FilesystemObjectTypeV1,
    },
    ImmutableArtifact {
        artifact_digests: Vec<String>,
    },
    Destination {
        destination_policy_ids: Vec<String>,
    },
    Device {
        device_class_ids: Vec<String>,
    },
    KernelSecurityObject {
        security_object_ids: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectedSourceV1 {
    KubernetesServiceaccountToken,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemObjectTypeV1 {
    RegularFile,
    Directory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownClassifierResultV1 {
    Deny,
    Alert,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDefinitionV1 {
    pub role_id: String,
    pub maximum_native_depth: u16,
    pub default_process_state_id: String,
    pub permitted_entry_kinds: Vec<EntryKindV1>,
    pub description_artifact_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryKindV1 {
    ContainerStart,
    ExternalRuntimeUnknown,
    QualifiedJoinedPurpose,
    ApprovedAdministrativeExec,
    RestoredUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryRoleAssignmentV1 {
    pub assignment_id: String,
    pub workload_selector_ids: Vec<String>,
    pub entry_kinds: Vec<EntryKindV1>,
    pub container_kinds: Vec<ContainerKindV1>,
    pub immutable_definition_digests: Vec<String>,
    pub accepted_classifications: Vec<RootClassificationV1>,
    pub required_purpose_source_capability_id: Option<String>,
    pub required_administrative_exec_approval: bool,
    pub resulting_role_id: String,
    pub on_missing_or_unequal_ambiguity: AmbiguityDispositionV1,
    pub unknown_restricted_role_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootClassificationV1 {
    ExactInitial,
    ConservativeExternalUnknown,
    QualifiedJoinedPurpose,
    ApprovedAdministrativeNextMatch,
    UnresolvedProtected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AmbiguityDispositionV1 {
    RestrictExternal,
    DenyProtectedEffects,
    RejectWhenStockInterfaceSupports,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRoleTransitionRuleV1 {
    pub transition_rule_id: String,
    pub source_role_ids: Vec<String>,
    pub operation: NativeOperationV1,
    pub executable_object_ids: Vec<u64>,
    pub required_process_state_ids: Vec<String>,
    pub resulting_role_id: String,
    pub resulting_process_state_id: String,
    pub requested_disposition: PolicyDispositionV1,
    pub errno: Option<ErrnoV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeOperationV1 {
    Fork,
    ThreadCreate,
    Exec,
    PrivilegeTransition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateBitDefinitionV1 {
    pub scope: StateBitScopeV1,
    pub bit_index: u8,
    pub semantic_id: String,
    pub monotonic: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateBitScopeV1 {
    Process,
    NativeAuthorityDomain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStateDefinitionV1 {
    pub process_state_id: String,
    pub state_bits: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthorityStateRuleV1 {
    pub state_rule_id: String,
    pub triggering_object_class_ids: Vec<String>,
    pub triggering_operations: Vec<String>,
    pub set_sensitive_bits: Vec<u8>,
    pub resulting_restriction_semantic_ids: Vec<String>,
    pub monotonic: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRelationshipRuleV1 {
    pub relationship_rule_id: String,
    pub source_role_ids: Vec<String>,
    pub peer_role_ids: Vec<String>,
    pub channel_class_ids: Vec<String>,
    pub operations: Vec<String>,
    pub requested_disposition: PolicyDispositionV1,
    pub errno: Option<ErrnoV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFamilyDefaultV1 {
    pub role_ids: Vec<String>,
    pub effect_family: EffectFamilyV1,
    pub operations: Vec<String>,
    pub requested_disposition: PolicyDispositionV1,
    pub errno: Option<ErrnoV1>,
    pub finding: Option<FindingSpecV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectFamilyV1 {
    Exec,
    File,
    Network,
    Device,
    Privilege,
    Ipc,
    Mount,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathTreeDenyFloorV1 {
    pub schema_version: u32,
    pub rule_id: String,
    pub canonical_path: String,
    pub recursive: bool,
    pub effect_families: Vec<EffectFamilyV1>,
    pub operation_ids: Vec<String>,
    pub requested_disposition: PolicyDispositionV1,
    pub exception_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDispositionV1 {
    Allow,
    Alert,
    Deny,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrnoV1 {
    Eacces,
    Eperm,
    Eagain,
    Econnrefused,
}

impl ErrnoV1 {
    #[must_use]
    pub const fn negative(self) -> i16 {
        match self {
            Self::Eacces => -13,
            Self::Eperm => -1,
            Self::Eagain => -11,
            Self::Econnrefused => -111,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSpecV1 {
    pub reason_code: String,
    pub severity: SeverityV1,
    pub route_ids: Vec<String>,
    pub evidence_level: EvidenceLevelV1,
    pub title_template_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeverityV1 {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLevelV1 {
    Minimal,
    Standard,
    Forensic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultPosturesV1 {
    pub missing_task_identity: DefaultPostureActionV1,
    pub required_classifier_unknown: DefaultPostureActionV1,
    pub unresolved_or_external_root: DefaultPostureActionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultPostureActionV1 {
    pub requested_disposition: PolicyDispositionV1,
    pub finding: FindingSpecV1,
    pub unknown_restricted_role_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionDispositionRuleV1 {
    pub schema_version: u32,
    pub rule_id: String,
    pub enabled: bool,
    pub priority: i32,
    pub evaluation_stage: EvaluationStageV1,
    #[serde(rename = "match")]
    pub rule_match: RuleMatchV1,
    pub requested_disposition: PolicyDispositionV1,
    pub errno: Option<ErrnoV1>,
    pub finding: Option<FindingSpecV1>,
    pub response_binding_ids: Vec<String>,
    pub fallback_by_condition: Vec<FallbackV1>,
    pub budgets: BudgetSetV1,
    pub overrides_rule_ids: Vec<String>,
    pub exception_ids: Vec<String>,
    pub valid_from_utc_ns: Option<i64>,
    pub valid_until_utc_ns: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationStageV1 {
    EntryAdmission,
    NativeTransition,
    LocalPreEffect,
    RemotePreAdmission,
    PostEffect,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleMatchV1 {
    EntryAdmission(EntryAdmissionMatchV1),
    LocalPreEffect(LocalEffectMatchV1),
    NativeTransition(NativeTransitionMatchV1),
    RemotePreAdmission(RemoteAdmissionMatchV1),
    PostEffect(PostEffectMatchV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonSubjectMatchV1 {
    pub workload_selector_ids: Vec<String>,
    pub protected_scope_ids: Vec<String>,
    pub execution_set_ids: Vec<String>,
    pub entry_kind_ids: Vec<EntryKindV1>,
    pub role_ids: Vec<String>,
    pub required_process_state_ids: Vec<String>,
    pub forbidden_process_state_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEffectMatchV1 {
    pub subject: CommonSubjectMatchV1,
    pub effect_families: Vec<EffectFamilyV1>,
    pub operation_ids: Vec<String>,
    pub object: LocalObjectSelectorV1,
    pub binding_lifecycle_states: Vec<BindingLifecycleV1>,
    pub required_proof: ProofQualityPredicateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryAdmissionMatchV1 {
    pub subject: CommonSubjectMatchV1,
    pub runtime_operations: Vec<RuntimeOperationV1>,
    pub root_classifications: Vec<RootClassificationV1>,
    pub source_proof_qualities: Vec<ProofQualityV1>,
    pub required_purpose_source_capability_ids: Vec<String>,
    pub immutable_definition_digests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTransitionMatchV1 {
    pub subject: CommonSubjectMatchV1,
    pub operations: Vec<NativeOperationV1>,
    pub executable_object_ids: Vec<u64>,
    pub source_role_ids: Vec<String>,
    pub target_role_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAdmissionMatchV1 {
    pub subject: CommonSubjectMatchV1,
    pub gate_capability_ids: Vec<String>,
    pub providers: Vec<ProviderV1>,
    pub provider_account_ids: Vec<String>,
    pub operation_ids: Vec<u32>,
    pub resources: Vec<ResourceSelectorV1>,
    pub required_lease_permission_ids: Vec<u32>,
    pub required_proof: ProofQualityPredicateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostEffectMatchV1 {
    LocalCompletion {
        subject: CommonSubjectMatchV1,
        effect_families: Vec<EffectFamilyV1>,
        operation_ids: Vec<String>,
        authoritative_results: Vec<AuthoritativeResultV1>,
        required_proof: ProofQualityPredicateV1,
    },
    ProviderResult {
        providers: Vec<ProviderV1>,
        provider_account_ids: Vec<String>,
        operation_ids: Vec<u32>,
        resources: Vec<ResourceSelectorV1>,
        authoritative_results: Vec<AuthoritativeResultV1>,
        required_proof: ProofQualityPredicateV1,
    },
    CorrelationFinding {
        package_ids: Vec<String>,
        reason_codes: Vec<String>,
        finding_states: Vec<FindingStateV1>,
        required_proof: ProofQualityPredicateV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalObjectSelectorV1 {
    ExactObjectKeys {
        exact_object_key_ids: Vec<u64>,
    },
    ObjectClasses {
        object_class_ids: Vec<String>,
    },
    Destinations {
        destination_policy_ids: Vec<String>,
    },
    Devices {
        device_class_ids: Vec<String>,
        ioctl_command_ids: Vec<u32>,
    },
    SecurityObjects {
        security_object_ids: Vec<String>,
        target_selector_ids: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingLifecycleV1 {
    Preparing,
    Active,
    Draining,
    Terminating,
    Tombstoned,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSetV1 {
    pub rate_limits: Vec<UnsupportedPolicyValueV1>,
    pub concurrency_limits: Vec<UnsupportedPolicyValueV1>,
    pub maximum_lifetime: Option<UnsupportedPolicyValueV1>,
    pub automatic_response_limit: Option<UnsupportedPolicyValueV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UnsupportedPolicyValueV1 {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackV1 {
    pub condition: FallbackConditionV1,
    pub requested_disposition: PolicyDispositionV1,
    pub errno: Option<ErrnoV1>,
    pub finding: FindingSpecV1,
    pub unknown_restricted_role_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FallbackConditionV1 {
    SourceGapped,
    ClassifierUnknown,
    IntentMissing,
    IntentAmbiguous,
    ProofBelowRequired,
    MapCapacity,
    AdapterUnavailable,
    ResponseUnverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionV1 {
    pub exception_id: String,
    pub exception_instance_id: String,
    pub changed_rule_ids: Vec<String>,
    pub exact_subject: ExactExceptionSubjectSelectorV1,
    pub authority_delta: PermittedAuthorityDeltaV1,
    pub approver_principal_id: String,
    pub approval_proof_digest: String,
    pub closed_reason_code: String,
    pub valid_from_utc_ns: i64,
    pub valid_until_utc_ns: i64,
    pub consumption_scope: ExceptionConsumptionScopeV1,
    pub maximum_uses: u32,
    pub maximum_lifetime_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExceptionConsumptionScopeV1 {
    PerTargetNode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactExceptionSubjectSelectorV1 {
    pub protected_scope_ids: Vec<String>,
    pub execution_set_ids: Vec<String>,
    pub entry_kind_ids: Vec<EntryKindV1>,
    pub role_ids: Vec<String>,
    pub immutable_definition_digests: Vec<String>,
    pub exact_compiled_key_digests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermittedAuthorityDeltaV1 {
    pub from_physical_result: String,
    pub to_physical_result: String,
    pub added_or_removed_operation_cells: Vec<String>,
    pub added_or_removed_transition_cells: Vec<String>,
    pub maximum_blast_radius: BlastRadiusLimitV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityBehaviorRuleV1 {
    RemoteAdmission {
        rule_id: String,
        authorization_interface_capability_id: String,
        provider: ProviderV1,
        provider_accounts: Vec<String>,
        principal_or_lease_selectors: Vec<String>,
        operations: Vec<u32>,
        resources: Vec<ResourceSelectorV1>,
        required_proof: ProofQualityPredicateV1,
        requested_disposition: PolicyDispositionV1,
        finding: Option<FindingSpecV1>,
        response_binding_ids: Vec<String>,
        budgets: BudgetSetV1,
    },
    PostEffectResult {
        rule_id: String,
        provider: ProviderV1,
        provider_accounts: Vec<String>,
        principal_or_lease_selectors: Vec<String>,
        operations: Vec<u32>,
        resources: Vec<ResourceSelectorV1>,
        authoritative_results: Vec<AuthoritativeResultV1>,
        required_proof: ProofQualityPredicateV1,
        requested_disposition: PolicyDispositionV1,
        finding: Option<FindingSpecV1>,
        response_binding_ids: Vec<String>,
        budgets: BudgetSetV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationPackageBindingV1 {
    pub binding_id: String,
    pub package_id: String,
    pub package_version: u32,
    pub required_source_ids: Vec<String>,
    pub parameter_digest: String,
    pub finding: FindingSpecV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCoverageHealthRuleV1 {
    pub health_rule_id: String,
    pub required_source_id: String,
    pub protected_scope_ids: Vec<String>,
    pub maximum_gap: String,
    pub on_gap: CoverageGapActionV1,
    pub finding: FindingSpecV1,
    pub independent_admission_interface_binding_id: Option<String>,
    pub independent_admission_capability_id: Option<String>,
    pub independent_response_binding_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageGapActionV1 {
    Alert,
    RejectNewAdmission,
    InstallIndependentFence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutV1 {
    pub rollout_generation: u64,
    pub desired_profile_mode: ProfileModeV1,
    pub cohort_selection: CohortSelectionV1,
    pub explicit_execution_set_ids: Vec<String>,
    pub selector_hash_modulus: u32,
    pub selected_bucket_ids: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProfileModeV1 {
    Observe,
    Protect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CohortSelectionV1 {
    AllBoundExecutionSets,
    ExplicitExecutionSets,
    HashedExecutionSetBinding,
}

pub(crate) fn ordered_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
