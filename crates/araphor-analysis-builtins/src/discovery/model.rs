use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::EvidenceIntakeIdentityV1;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryProofKindV1 {
    ObservedRuntime,
    RecordedInput,
    Synthetic,
    ConfigurationScan,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordIdV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub durable_cursor: u64,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryCoverageStateV1 {
    Healthy,
    Gapped,
    Unknown,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCoverageV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub expected_records: u64,
    pub coverage_revision: u64,
    pub coverage_interval_id: [u8; 16],
    pub state: DiscoveryCoverageStateV1,
    pub gap_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPolicyKeyV1 {
    pub workload_selector_id: String,
    pub protected_scope_id: String,
    pub execution_set_id: String,
    pub entry_kind: String,
    pub role_id: String,
    pub process_state_id: String,
    pub effect_family: u16,
    pub operation_id: String,
    pub operation: u16,
    pub operation_argument: u32,
    pub argument_wildcard: bool,
    pub object_selector: String,
    pub binding_lifecycle: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPolicyRevisionV1 {
    pub profile_id: String,
    pub profile_version: u64,
    pub source_revision_id: String,
    pub signed_profile_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextBindingV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub subject_revision: String,
    pub image_digest: String,
    pub configuration_digest: String,
    pub process_instance_id: [u8; 16],
    pub entry_instance_id: [u8; 16],
    pub binding_id: [u8; 16],
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub catalog_revision: u64,
    pub static_key: DiscoveryPolicyKeyV1,
    pub policy_revision: DiscoveryPolicyRevisionV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryLifecycleCaseV1 {
    Startup,
    SteadyWork,
    Probes,
    Restart,
    Rollout,
    Shutdown,
    Recovery,
    ScheduledWork,
    ApprovedMaintenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryLifecycleStateV1 {
    Recorded { records: Vec<DiscoveryRecordIdV1> },
    Declared { reason: String },
    Missing,
    NotApplicable { reason: String },
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLifecycleEntryV1 {
    pub case: DiscoveryLifecycleCaseV1,
    pub state: DiscoveryLifecycleStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryUnresolvedV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub reason: String,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryPhysicalResultV1 {
    Prevented,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryFileObjectV1 {
    pub profile_generation_ref_id: u64,
    pub mount_id_unique: u64,
    pub inode: u64,
    pub inode_generation: u64,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryEffectKeyV1 {
    pub task_cookie: u64,
    pub target_task_cookie: Option<u64>,
    pub process_lineage_id: Vec<u8>,
    pub authority_domain_id: Vec<u8>,
    pub execution_set_id: Vec<u8>,
    pub exact_object_id: Vec<u8>,
    pub destination_id: u64,
    pub policy_rule_id: u64,
    pub reason: u32,
    pub decision: u32,
    pub effect_family: u32,
    pub operation: u32,
    pub operation_argument: Option<u32>,
    pub configured_errno: i32,
    pub kernel_result: i32,
    pub exact_file_object: Option<DiscoveryFileObjectV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAtomKeyV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub subject_revision: String,
    pub image_digest: String,
    pub configuration_digest: String,
    pub process_instance_id: [u8; 16],
    pub entry_instance_id: [u8; 16],
    pub binding_id: [u8; 16],
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub catalog_revision: u64,
    pub static_key: DiscoveryPolicyKeyV1,
    pub policy_revision: DiscoveryPolicyRevisionV1,
    pub generation: u64,
    pub coverage_interval_id: [u8; 16],
    pub temporal_coverage: i32,
    pub effect: DiscoveryEffectKeyV1,
    pub physical_result: DiscoveryPhysicalResultV1,
    pub proof_kind: DiscoveryProofKindV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAtomV1 {
    pub key: BehaviorAtomKeyV1,
    pub count: u64,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub evidence_sample: Vec<DiscoveryRecordIdV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BehaviorDisplayKeyV1 {
    pub subject_revision: String,
    pub image_digest: String,
    pub configuration_digest: String,
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub static_key: DiscoveryPolicyKeyV1,
    pub policy_revision: DiscoveryPolicyRevisionV1,
    pub source_reason: u32,
    pub source_decision: u32,
    pub kernel_result: i32,
    pub physical_result: DiscoveryPhysicalResultV1,
    pub proof_kind: DiscoveryProofKindV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BehaviorDisplayGroupV1 {
    pub key: BehaviorDisplayKeyV1,
    pub count: u64,
    pub members: Vec<BehaviorAtomKeyV1>,
    pub evidence_sample: Vec<DiscoveryRecordIdV1>,
    pub coverage: Vec<DiscoveryCoverageV1>,
}

impl DiscoveryLifecycleCaseV1 {
    pub const ALL: [Self; 9] = [
        Self::Startup,
        Self::SteadyWork,
        Self::Probes,
        Self::Restart,
        Self::Rollout,
        Self::Shutdown,
        Self::Recovery,
        Self::ScheduledWork,
        Self::ApprovedMaintenance,
    ];
}

impl From<&BehaviorAtomKeyV1> for BehaviorDisplayKeyV1 {
    fn from(key: &BehaviorAtomKeyV1) -> Self {
        Self {
            subject_revision: key.subject_revision.clone(),
            image_digest: key.image_digest.clone(),
            configuration_digest: key.configuration_digest.clone(),
            role_id: key.role_id,
            state_id: key.state_id,
            entry_rule_id: key.entry_rule_id,
            static_key: key.static_key.clone(),
            policy_revision: key.policy_revision.clone(),
            source_reason: key.effect.reason,
            source_decision: key.effect.decision,
            kernel_result: key.effect.kernel_result,
            physical_result: key.physical_result,
            proof_kind: key.proof_kind,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetime {
    pub process: Vec<u8>,
    pub entry: Vec<u8>,
    pub binding: Vec<u8>,
    pub role: u32,
    pub state: u32,
    pub rule: u32,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: DiscoveryRecordIdV1,
    pub bytes: String,
    pub range: u64,
    pub temporal: i32,
    pub effect: DiscoveryEffectKeyV1,
    pub generation: Option<u64>,
    pub original_sequence: Option<u64>,
    pub source: Option<Lifetime>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub record_id: DiscoveryRecordIdV1,
    pub atom_key: Option<BehaviorAtomKeyV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub duplicates: u64,
    pub accepted: u64,
    pub included: u64,
    pub unresolved: u64,
    pub excluded: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub tenant_id: [u8; 16],
    pub source_revision: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub counts: Counts,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Side<T> {
    pub side: u8,
    pub value: T,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatchState {
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub lifecycle: Vec<DiscoveryLifecycleEntryV1>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSelection {
    pub selector_version: u32,
    pub from_utc_ns: u64,
    pub cutoff_utc_ns: u64,
    pub host_packet: String,
}

impl BehaviorDisplayKeyV1 {
    pub(super) fn outcome(&self) -> impl Ord + '_ {
        (
            &self.subject_revision,
            &self.image_digest,
            &self.configuration_digest,
            self.role_id,
            self.state_id,
            self.entry_rule_id,
            &self.static_key,
            &self.policy_revision,
            self.proof_kind,
        )
    }

    pub(super) fn identity(&self) -> impl Ord + '_ {
        (
            self.role_id,
            self.state_id,
            self.entry_rule_id,
            &self.static_key,
            self.source_reason,
            self.source_decision,
            self.kernel_result,
            self.physical_result,
            self.proof_kind,
        )
    }

    pub(super) fn revision(&self) -> impl Ord + '_ {
        (
            &self.subject_revision,
            &self.image_digest,
            &self.configuration_digest,
            &self.policy_revision,
        )
    }
}

impl BehaviorAtomKeyV1 {
    pub(super) fn resource(&self) -> impl Ord + '_ {
        (
            &self.subject_revision,
            &self.static_key,
            &self.binding_id,
            &self.effect.exact_object_id,
            &self.effect.exact_file_object,
        )
    }
}

impl From<(&DiscoveryRecordIdV1, &BehaviorAtomKeyV1)> for DiscoveryContextBindingV1 {
    fn from((record_id, key): (&DiscoveryRecordIdV1, &BehaviorAtomKeyV1)) -> Self {
        Self {
            record_id: record_id.clone(),
            subject_revision: key.subject_revision.clone(),
            image_digest: key.image_digest.clone(),
            configuration_digest: key.configuration_digest.clone(),
            process_instance_id: key.process_instance_id,
            entry_instance_id: key.entry_instance_id,
            binding_id: key.binding_id,
            role_id: key.role_id,
            state_id: key.state_id,
            entry_rule_id: key.entry_rule_id,
            catalog_revision: key.catalog_revision,
            static_key: key.static_key.clone(),
            policy_revision: key.policy_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryGroupChangeV1 {
    pub before: BehaviorDisplayGroupV1,
    pub after: BehaviorDisplayGroupV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryComparisonV1 {
    pub added: Vec<BehaviorDisplayGroupV1>,
    pub removed: Vec<BehaviorDisplayGroupV1>,
    pub changed_counts: Vec<DiscoveryGroupChangeV1>,
    pub changed_results: Vec<DiscoveryGroupChangeV1>,
    pub changed_identities: Vec<DiscoveryGroupChangeV1>,
    pub new_resources: Vec<BehaviorAtomKeyV1>,
    pub coverage_before: Vec<DiscoveryCoverageV1>,
    pub coverage_after: Vec<DiscoveryCoverageV1>,
    pub lifecycle_before: Vec<DiscoveryLifecycleEntryV1>,
    pub lifecycle_after: Vec<DiscoveryLifecycleEntryV1>,
    pub forbidden_groups: Vec<BehaviorDisplayGroupV1>,
}
