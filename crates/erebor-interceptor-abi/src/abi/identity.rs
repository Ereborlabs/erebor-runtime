use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub const MAX_ANCESTOR_PROCESS_LINEAGES_V1: usize = 8;
pub const MAX_EXEC_CANDIDATES_V1: usize = 8;
pub const MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1: usize = 4096;
pub const EXECUTION_ARGV_CHUNK_BYTES_V1: usize = 4096;
const EXECUTION_ARGV_CHUNK_BYTES_U64_V1: u64 = 4096;
pub const EXECUTION_ARGV_CHUNK_TERMINAL_V1: u32 = 1;
pub const EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1: u8 = 2;
pub const EXECUTION_APPROVAL_TRACE_STAGE_EXECVEAT_ENTRY_V1: u8 = 3;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PENDING_MISSING_V1: u64 = 1 << 0;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PENDING_STATE_V1: u64 = 1 << 1;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_TASK_COOKIE_V1: u64 = 1 << 2;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_ATTEMPT_SEQUENCE_V1: u64 = 1 << 3;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PROFILE_GENERATION_V1: u64 = 1 << 4;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_MISSING_V1: u64 = 1 << 5;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_IDENTITY_V1: u64 = 1 << 6;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_STATE_V1: u64 = 1 << 7;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_GUARD_V1: u64 = 1 << 8;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PROOF_V1: u64 = 1 << 9;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_CLAIM_SLOT_V1: u64 = 1 << 10;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_TARGET_ROLE_V1: u64 = 1 << 11;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_EXPECTED_EXECUTABLE_V1: u64 = 1 << 12;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_OBSERVED_UNRESOLVED_V1: u64 = 1 << 13;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_OBSERVED_EXECUTABLE_V1: u64 = 1 << 14;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_LABEL_V1: u64 = 1 << 15;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_PROCESS_V1: u64 = 1 << 16;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ENTRY_V1: u64 = 1 << 17;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_RUNTIME_LABEL_V1: u64 = 1 << 18;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_BINDING_LABEL_V1: u64 = 1 << 19;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_PROCESS_STATE_V1: u64 = 1 << 20;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_TRANSITION_GUARD_V1: u64 = 1 << 21;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_EXEC_GUARD_V1: u64 = 1 << 22;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_CLASSIFICATION_V1: u64 = 1 << 23;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ROOT_CLASS_V1: u64 = 1 << 24;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_PURPOSE_V1: u64 = 1 << 25;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ROLE_V1: u64 = 1 << 26;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_SLOT_GUARD_V1: u64 = 1 << 27;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1: u64 = 1 << 28;
pub const EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_MAP_UPDATE_V1: u64 = 1 << 29;
pub const TASK_REFERENCE_ENTRY_V1: u64 = 1 << 0;
pub const TASK_REFERENCE_PROCESS_V1: u64 = 1 << 1;
pub const TASK_REFERENCE_PROFILE_GENERATION_V1: u64 = 1 << 2;
pub const TASK_REFERENCE_ALL_V1: u64 =
    TASK_REFERENCE_ENTRY_V1 | TASK_REFERENCE_PROCESS_V1 | TASK_REFERENCE_PROFILE_GENERATION_V1;
pub const TASK_ALLOC_HOOK_LSM_V1: u32 = 1;
pub const CONSERVATIVE_PROCESS_STATE_VECTOR_V1: u32 = 1;

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    FromBytes,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct Id128V1 {
    pub high: u64,
    pub low: u64,
}

impl Id128V1 {
    pub const ZERO: Self = Self { high: 0, low: 0 };

    #[must_use]
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.high == 0 && self.low == 0
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 16] {
        (((self.high as u128) << 64) | self.low as u128).to_be_bytes()
    }
}

impl From<u128> for Id128V1 {
    fn from(value: u128) -> Self {
        Self::new((value >> 64) as u64, value as u64)
    }
}

impl From<[u8; 16]> for Id128V1 {
    fn from(value: [u8; 16]) -> Self {
        u128::from_be_bytes(value).into()
    }
}

impl From<[u8; 32]> for Id128V1 {
    fn from(digest: [u8; 32]) -> Self {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes.into()
    }
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum TaskCoordinateStateV1 {
    #[default]
    Unknown = 0,
    Allocating = 1,
    CoordinatesFinalized = 2,
    Runnable = 3,
    Exited = 4,
    Failed = 5,
    FailClosedUnknown = 6,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum KernelRealParentChangeReasonV1 {
    #[default]
    Unknown = 0,
    Birth = 1,
    CloneParent = 2,
    ParentExitOrReparent = 3,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ProcessSecurityStateKindV1 {
    #[default]
    Unknown = 0,
    Allocating = 1,
    Active = 2,
    Exiting = 3,
    Reclaimable = 4,
    FailClosedOverflow = 5,
    Corrupt = 6,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ProcessStateVectorStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Retiring = 3,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ExecGuardStateV1 {
    #[default]
    None = 0,
    Preparing = 1,
    CommitPending = 2,
    OutcomeUnknown = 3,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum PendingExecStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    CommitPending = 2,
    PrePonrFailed = 3,
    PostPonrFatal = 4,
    Success = 5,
    OutcomeUnknown = 6,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ImageProvenanceStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Complete = 3,
    OutcomeUnknown = 4,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ProcessExecutionStartedByV1 {
    #[default]
    Unknown = 0,
    ProcessBirth = 1,
    ExecCommit = 2,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ProcessExecutionStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Complete = 3,
    OutcomeUnknown = 4,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum EntryAdmissionStateV1 {
    #[default]
    Unknown = 0,
    Pending = 1,
    Claiming = 2,
    Committed = 3,
    Terminal = 4,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum EntryLifetimeStateV1 {
    #[default]
    Inactive = 0,
    Active = 1,
    Draining = 2,
    Complete = 3,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum AuthorityDomainStateKindV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Reclaimable = 3,
    FailClosedOverflow = 4,
    Corrupt = 5,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ExternalRootClassV1 {
    #[default]
    Unknown = 0,
    InitialContainerRoot = 1,
    ExternalRuntimeRoot = 2,
    RestoredOrUnknownRoot = 3,
    UnresolvedProtected = 4,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum EntryPurposeV1 {
    #[default]
    Unknown = 0,
    QualifiedJoinedPurpose = 1,
    ApprovedAdministrativeNextMatch = 2,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum InstalledRoleClassV1 {
    #[default]
    Unknown = 0,
    InitialRole = 1,
    RuntimeExternalRestricted = 2,
    FailClosedUnknown = 3,
    QualifiedRegisteredRole = 4,
    ApprovedAdministrativeRole = 5,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ReferenceTombstoneStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Owned = 2,
    Released = 3,
    Reclaimable = 4,
}

#[repr(u64)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum InitialRootStateV1 {
    #[default]
    Unarmed = 0,
    Available = 1,
    Consumed = 2,
}

// The kernel owns the only transition from trusted runtime setup to workload
// enforcement. A failed exec can return only its own reservation to PREPARED.
#[repr(u64)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum PreparedContainerStateV1 {
    #[default]
    Unarmed = 0,
    Prepared = 1,
    ExecPending = 2,
    Active = 3,
    Expired = 4,
    Corrupt = 5,
}

// BPF compare-and-swap is 64-bit on every supported target. Keep the slot
// state in that directly atomic representation instead of adding a second
// lock owner around this one-use transition.
#[repr(u64)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum ExecutionApprovalSlotStateV1 {
    #[default]
    Unknown = 0,
    Armed = 1,
    Consumed = 2,
    Expired = 3,
    Cancelled = 4,
    Corrupt = 5,
    Reserved = 6,
    Tampered = 7,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum PendingExecutionApprovalStateV1 {
    #[default]
    Unknown = 0,
    ArgumentsMatched = 1,
    SlotReserved = 2,
    KernelArgvVerified = 3,
    SlotConsumed = 4,
    Tampered = 5,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct TaskPlacementExpectationV1 {
    pub protected_root_binding_id: Id128V1,
    pub protected_root_binding_nonce: Id128V1,
    pub allowed_descendant_policy_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct TaskLabelV1 {
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub task_cookie: u64,
    pub process_lineage_id: Id128V1,
    pub process_instance_id: Id128V1,
    pub process_state_id: Id128V1,
    pub entry_instance_id: Id128V1,
    pub execution_set_id: Id128V1,
    pub birth_profile_generation_ref_id: u64,
    pub birth_execution_id: Id128V1,
    pub birth_authority_domain_id: Id128V1,
    pub lineage_depth: u16,
    pub reserved: [u8; 6],
    pub ancestor_process_lineage_ids: [Id128V1; MAX_ANCESTOR_PROCESS_LINEAGES_V1],
    pub placement: TaskPlacementExpectationV1,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct TaskCoordinateV1 {
    pub task_cookie: u64,
    pub process_instance_id: Id128V1,
    pub process_state_id: Id128V1,
    pub task_start_boottime_ns: u64,
    pub finalized_boottime_ns: u64,
    pub real_parent_interval_sequence: u64,
    pub transition_version: u64,
    pub host_tid: u32,
    pub host_tgid: u32,
    pub pid_namespace_inode: u32,
    pub state: TaskCoordinateStateV1,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct KernelRealParentIntervalKeyV1 {
    pub child_task_cookie: u64,
    pub interval_sequence: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct KernelRealParentIntervalV1 {
    pub child_task_cookie: u64,
    pub real_parent_task_cookie: u64,
    pub real_parent_host_tid: u32,
    pub real_parent_host_tgid: u32,
    pub real_parent_pid_namespace_inode: u32,
    pub change_reason: KernelRealParentChangeReasonV1,
    pub kernel_direct_proof: u8,
    pub reserved: [u8; 2],
    pub real_parent_start_boottime_ns: u64,
    pub interval_start_boottime_ns: u64,
    pub interval_end_boottime_ns: u64,
    pub transition_version: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct CreatedByEdgeV1 {
    pub child_task_cookie: u64,
    pub creator_task_cookie: u64,
    pub child_process_lineage_id: Id128V1,
    pub creator_process_lineage_id: Id128V1,
    pub clone_attempt_id: Id128V1,
    pub clone_flags: u64,
    pub task_alloc_hook_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ProcessSecurityStateV1 {
    pub process_state_id: Id128V1,
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub process_lineage_id: Id128V1,
    pub process_instance_id: Id128V1,
    pub entry_instance_id: Id128V1,
    pub entry_root_process_state_id: Id128V1,
    pub active_execution_id: Id128V1,
    pub active_role_id: u32,
    pub process_state_vector_id: u32,
    pub active_profile_generation_ref_id: u64,
    pub authority_domain_id: Id128V1,
    pub effective_response_set_ref_id: u64,
    pub pending_exec_id: Id128V1,
    pub pending_target_execution_id: Id128V1,
    pub pending_target_role_id: u32,
    pub runtime_entry_bootstrap_prepared: u32,
    pub transition_guard: u64,
    pub pending_exec_response_set_ref_id: u64,
    pub exec_without_transition_task_cookie: u64,
    pub transition_version: u64,
    pub live_thread_refs: u64,
    pub exec_guard_state: ExecGuardStateV1,
    pub state: ProcessSecurityStateKindV1,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ProcessStateVectorV1 {
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub state_bits: u64,
    pub profile_generation_ref_id: u64,
    pub transition_version: u64,
    pub process_state_vector_id: u32,
    pub state: ProcessStateVectorStateV1,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct EntrySecurityStateV1 {
    pub entry_instance_id: Id128V1,
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub execution_set_id: Id128V1,
    pub claim_slot_id: Id128V1,
    pub root_task_cookie: u64,
    pub root_process_state_id: Id128V1,
    pub committed_execution_id: Id128V1,
    pub live_task_refs: u64,
    pub transition_version: u64,
    pub admission_state: EntryAdmissionStateV1,
    pub lifetime_state: EntryLifetimeStateV1,
    pub terminal_reason: u8,
    pub reserved: u8,
    pub admitted_entry_rule_id: u32,
    pub transition_guard: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct EntryAdmissionRuleKeyV1 {
    pub profile_generation_ref_id: u64,
    pub binding_id: Id128V1,
    pub composite_atom_id: u64,
    pub source_role_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct EntryAdmissionRuleV1 {
    pub target_role_id: u32,
    pub target_process_state_vector_id: u32,
    pub admitted_entry_rule_id: u32,
    pub reserved: u32,
    pub exact_object_key_id: u64,
    pub executable_object: super::ExactFileObjectKeyV1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes)]
pub struct DeclaredEntryRequestV1 {
    pub path_length: u32,
    pub reserved: u32,
    pub path: [u8; MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1],
}

impl Default for DeclaredEntryRequestV1 {
    fn default() -> Self {
        Self {
            path_length: 0,
            reserved: 0,
            path: [0; MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1],
        }
    }
}

impl DeclaredEntryRequestV1 {
    #[must_use]
    pub fn from_path(path: &[u8]) -> Option<Self> {
        if path.is_empty()
            || path.len() >= MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1
            || path.contains(&0)
        {
            return None;
        }
        let mut request = Self {
            path_length: u32::try_from(path.len()).ok()?,
            ..Self::default()
        };
        request.path[..path.len()].copy_from_slice(path);
        Some(request)
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct AuthorityDomainStateV1 {
    pub authority_domain_id: Id128V1,
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub domain_epoch: u64,
    pub live_process_refs: u64,
    pub response_plan_refs: u64,
    pub reconciliation_hold_refs: u64,
    pub potential_sensitive_bits: u64,
    pub observed_sensitive_bits: u64,
    pub effective_restriction_set_ref_id: u64,
    pub effective_response_set_ref_id: u64,
    pub retained_generation_set_ref_id: u64,
    pub transition_version: u64,
    pub transition_guard: u64,
    pub state: AuthorityDomainStateKindV1,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ExecutionSetBindingStateV1 {
    pub binding_id: Id128V1,
    pub binding_nonce: Id128V1,
    pub node_boot_id: Id128V1,
    pub execution_set_id: Id128V1,
    pub protected_scope_id: Id128V1,
    pub profile_id: Id128V1,
    pub label_epoch: u64,
    pub active_profile_generation_ref_id: u64,
    pub root_cgroup_id: u64,
    pub root_cgroup_live_interval_id: Id128V1,
    pub container_generation: u64,
    pub lifecycle_generation: u64,
    pub transition_version: u64,
    pub initial_role_id: u32,
    pub external_role_id: u32,
    pub lifecycle_state: super::BindingLifecycleStateV1,
    pub reserved: [u8; 7],
    pub initial_root_state: InitialRootStateV1,
    pub prepared_container_state: PreparedContainerStateV1,
    pub prepared_container_entry_instance_id: Id128V1,
    pub prepared_container_exec_task_cookie: u64,
    pub prepared_container_initial_host_tgid: u32,
    /// Zero, pending, or complete for the one post-mount bootstrap exec.
    pub prepared_container_bootstrap_state: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct BindingActivationTargetKeyV1 {
    pub binding_id: Id128V1,
    pub profile_generation_ref_id: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ProcessGenerationMigrationKeyV1 {
    pub source_profile_generation_ref_id: u64,
    pub target_profile_generation_ref_id: u64,
    pub source_state_bits: u64,
    pub source_role_id: u32,
    pub source_process_state_vector_id: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ProcessGenerationMigrationV1 {
    pub target_state_bits: u64,
    pub target_role_id: u32,
    pub target_process_state_vector_id: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ExecutionArgvSnapshotV1 {
    pub snapshot_id: Id128V1,
    pub argument_count: u64,
    pub total_argument_span: u64,
    pub chunk_count: u32,
    pub reserved: u32,
}

impl ExecutionArgvSnapshotV1 {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.snapshot_id.is_zero()
            && self.argument_count > 0
            && self.total_argument_span >= self.argument_count
            && self.total_argument_span <= u64::from(u32::MAX)
            && self.chunk_count > 0
            && u64::from(self.chunk_count)
                == ((self.total_argument_span - 1) / EXECUTION_ARGV_CHUNK_BYTES_U64_V1) + 1
            && self.reserved == 0
    }
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    FromBytes,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
)]
pub struct ExecutionArgvChunkKeyV1 {
    pub snapshot_id: Id128V1,
    pub chunk_index: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct ExecutionArgvChunkV1 {
    pub length: u32,
    pub flags: u32,
    pub bytes: [u8; EXECUTION_ARGV_CHUNK_BYTES_V1],
}

impl Default for ExecutionArgvChunkV1 {
    fn default() -> Self {
        Self {
            length: 0,
            flags: 0,
            bytes: [0; EXECUTION_ARGV_CHUNK_BYTES_V1],
        }
    }
}

impl ExecutionArgvChunkV1 {
    #[must_use]
    pub fn is_valid_for(&self, snapshot: &ExecutionArgvSnapshotV1, chunk_index: u32) -> bool {
        if !snapshot.is_valid() || chunk_index >= snapshot.chunk_count {
            return false;
        }
        let preceding = u64::from(chunk_index) * EXECUTION_ARGV_CHUNK_BYTES_U64_V1;
        let expected_length =
            (snapshot.total_argument_span - preceding).min(EXECUTION_ARGV_CHUNK_BYTES_U64_V1);
        u64::from(self.length) == expected_length
            && self.flags
                == if chunk_index + 1 == snapshot.chunk_count {
                    EXECUTION_ARGV_CHUNK_TERMINAL_V1
                } else {
                    0
                }
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ExecutionApprovalSlotKeyV1 {
    pub node_boot_id: Id128V1,
    pub cgroup_binding_id: Id128V1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes)]
pub struct ExecutionApprovalSlotV1 {
    pub proof_id: Id128V1,
    pub claim_slot_id: Id128V1,
    pub authorization_body_sha256: [u8; 32],
    pub cgroup_binding_nonce: Id128V1,
    pub container_generation: u64,
    pub expected_argv: ExecutionArgvSnapshotV1,
    pub resolved_executable: ExactExecutableCandidateV1,
    pub target_role_numeric_id: u32,
    pub expected_root_class: ExternalRootClassV1,
    pub reserved_0: [u8; 3],
    pub profile_generation_ref_id: u64,
    pub exception_numeric_handle: u32,
    pub admitted_entry_rule_id: u32,
    pub deadline_boottime_ns: u64,
    pub state: ExecutionApprovalSlotStateV1,
    pub transition_version: u64,
}

impl Default for ExecutionApprovalSlotV1 {
    fn default() -> Self {
        Self {
            proof_id: Id128V1::ZERO,
            claim_slot_id: Id128V1::ZERO,
            authorization_body_sha256: [0; 32],
            cgroup_binding_nonce: Id128V1::ZERO,
            container_generation: 0,
            expected_argv: ExecutionArgvSnapshotV1::default(),
            resolved_executable: ExactExecutableCandidateV1::default(),
            target_role_numeric_id: 0,
            expected_root_class: ExternalRootClassV1::Unknown,
            reserved_0: [0; 3],
            profile_generation_ref_id: 0,
            exception_numeric_handle: 0,
            admitted_entry_rule_id: 0,
            deadline_boottime_ns: 0,
            state: ExecutionApprovalSlotStateV1::Unknown,
            transition_version: 0,
        }
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct PendingExecutionApprovalV1 {
    pub task_cookie: u64,
    pub exec_attempt_sequence: u64,
    pub proof_id: Id128V1,
    pub claim_slot_id: Id128V1,
    pub target_role_numeric_id: u32,
    pub reserved_0: u32,
    pub profile_generation_ref_id: u64,
    pub resolved_executable: ExactExecutableCandidateV1,
    pub transition_version: u64,
    pub state: PendingExecutionApprovalStateV1,
    pub reserved_1: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct ExactExecutableCandidateV1 {
    pub inode: u64,
    pub inode_generation: u64,
    pub mount_namespace_inode: u32,
    pub mount_id: u32,
    pub filesystem_device: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct ExecutionApprovalTraceV1 {
    pub exec_attempt_sequence: u64,
    pub failed_checks: u64,
    pub expected_executable: ExactExecutableCandidateV1,
    pub observed_executable: ExactExecutableCandidateV1,
    pub syscall_flags: u32,
    pub pending_state: u8,
    pub slot_state: u8,
    pub stage: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ImageProvenanceV1 {
    pub image_provenance_id: Id128V1,
    pub candidate_count: u16,
    pub reserved_0: [u8; 6],
    pub ordered_candidates: [ExactExecutableCandidateV1; MAX_EXEC_CANDIDATES_V1],
    pub transition_version: u64,
    pub state: ImageProvenanceStateV1,
    pub reserved_1: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ProcessExecutionInstanceV1 {
    pub process_execution_instance_id: Id128V1,
    pub process_lineage_id: Id128V1,
    pub image_provenance_id: Id128V1,
    pub start_boottime_ns: u64,
    pub end_boottime_ns: u64,
    pub transition_version: u64,
    pub started_by: ProcessExecutionStartedByV1,
    pub state: ProcessExecutionStateV1,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct PendingExecV1 {
    pub pending_exec_id: Id128V1,
    pub task_cookie: u64,
    pub process_state_id: Id128V1,
    pub exec_attempt_sequence: u64,
    pub source_execution_id: Id128V1,
    pub source_role_id: u32,
    pub candidate_count: u16,
    /// One trusted-runtime exec that did not satisfy workload policy.
    pub prepared_runtime_exec: u8,
    /// The matching exec policy requires exact object identity.
    pub exact_object_required: u8,
    pub source_profile_generation_ref_id: u64,
    pub pending_exec_response_set_ref_id: u64,
    pub target_execution_id: Id128V1,
    pub target_image_provenance_id: Id128V1,
    pub ordered_candidates: [ExactExecutableCandidateV1; MAX_EXEC_CANDIDATES_V1],
    pub transition_version: u64,
    pub admitted_entry_rule_id: u32,
    pub state: PendingExecStateV1,
    pub reserved_1: [u8; 3],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct TaskReferenceTombstoneV1 {
    pub task_cookie: u64,
    pub birth_transaction_id: Id128V1,
    pub birth_transition_version: u64,
    pub entry_instance_id: Id128V1,
    pub process_state_id: Id128V1,
    pub authority_domain_id_at_birth: Id128V1,
    pub profile_generation_ref_id: u64,
    pub acquired_bits: u64,
    pub released_bits: u64,
    pub transition_version: u64,
    pub task_free_observed: u8,
    pub wal_acknowledged: u8,
    pub state: ReferenceTombstoneStateV1,
    pub reserved: [u8; 5],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct ExternalRootClassificationV1 {
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub task_cookie: u64,
    pub process_state_id: Id128V1,
    pub entry_instance_id: Id128V1,
    pub execution_set_id: Id128V1,
    pub cgroup_binding_id: Id128V1,
    pub cgroup_lifetime_id: Id128V1,
    pub creator_task_cookie: u64,
    pub administrative_approval_proof_id: Id128V1,
    pub administrative_claim_slot_id: Id128V1,
    pub profile_generation_ref_id: u64,
    pub installed_role_numeric_id: u32,
    pub root_class: ExternalRootClassV1,
    pub purpose: EntryPurposeV1,
    pub installed_role_class: InstalledRoleClassV1,
    pub reserved: u8,
    pub classified_boottime_ns: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct IdentityRuntimeConfigV1 {
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub next_id: u64,
    pub effect_controller_cgroup_id: u64,
    pub first_effect_errno: i32,
    pub enabled: u8,
    pub effect_policy_enabled: u8,
    pub reserved: [u8; 2],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct IdentityHealthV1 {
    pub allocation_failures: u64,
    pub coordinate_failures: u64,
    pub placement_mismatches: u64,
    pub missing_identity_denials: u64,
    pub exec_guard_denials: u64,
    pub reconciliation_required: u64,
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::*;
    use crate::BindingLifecycleStateV1;

    #[test]
    fn native_identity_abi_has_stable_sizes_and_offsets() {
        assert_eq!(size_of::<Id128V1>(), 16);
        assert_eq!(size_of::<TaskPlacementExpectationV1>(), 40);
        assert_eq!(size_of::<TaskLabelV1>(), 328);
        assert_eq!(offset_of!(TaskLabelV1, process_state_id), 64);
        assert_eq!(offset_of!(TaskLabelV1, placement), 288);
        assert_eq!(size_of::<TaskCoordinateV1>(), 88);
        assert_eq!(size_of::<CreatedByEdgeV1>(), 80);
        assert_eq!(align_of::<ProcessSecurityStateV1>(), 8);
        assert_eq!(size_of::<ProcessSecurityStateV1>(), 248);
        assert_eq!(
            offset_of!(ProcessSecurityStateV1, exec_without_transition_task_cookie),
            216
        );
        assert_eq!(size_of::<ExactExecutableCandidateV1>(), 32);
        assert_eq!(size_of::<ProcessExecutionInstanceV1>(), 80);
        assert_eq!(size_of::<ExecutionSetBindingStateV1>(), 224);
        assert_eq!(size_of::<ProcessGenerationMigrationKeyV1>(), 32);
        assert_eq!(size_of::<ProcessGenerationMigrationV1>(), 16);
        assert_eq!(size_of::<IdentityRuntimeConfigV1>(), 48);
        assert_eq!(size_of::<EntryAdmissionRuleV1>(), 64);
        assert_eq!(size_of::<DeclaredEntryRequestV1>(), 4_104);
        assert_eq!(size_of::<ExecutionArgvSnapshotV1>(), 40);
        assert_eq!(size_of::<ExecutionArgvChunkKeyV1>(), 24);
        assert_eq!(size_of::<ExecutionArgvChunkV1>(), 4_104);
        assert_eq!(size_of::<ExecutionApprovalSlotV1>(), 208);
        assert_eq!(
            offset_of!(ExecutionApprovalSlotV1, exception_numeric_handle),
            176
        );
        assert_eq!(
            offset_of!(ExecutionApprovalSlotV1, deadline_boottime_ns),
            184
        );
    }

    #[test]
    fn closed_identity_enums_keep_unknown_at_zero() {
        assert_eq!(TaskCoordinateStateV1::Unknown as u8, 0);
        assert_eq!(ExternalRootClassV1::UnresolvedProtected as u8, 4);
        assert_eq!(ExecGuardStateV1::OutcomeUnknown as u8, 3);
        assert_eq!(PendingExecStateV1::Success as u8, 5);
        assert_eq!(InstalledRoleClassV1::ApprovedAdministrativeRole as u8, 5);
        assert_eq!(InitialRootStateV1::Unarmed as u64, 0);
        assert_eq!(InitialRootStateV1::Consumed as u64, 2);
        assert_eq!(PreparedContainerStateV1::Unarmed as u64, 0);
        assert_eq!(PreparedContainerStateV1::Prepared as u64, 1);
        assert_eq!(PreparedContainerStateV1::ExecPending as u64, 2);
        assert_eq!(PreparedContainerStateV1::Active as u64, 3);
        assert_eq!(PreparedContainerStateV1::Corrupt as u64, 5);
        assert_eq!(ExecutionApprovalSlotStateV1::Reserved as u64, 6);
        assert_eq!(ExecutionApprovalSlotStateV1::Tampered as u64, 7);
        assert_eq!(PendingExecutionApprovalStateV1::SlotReserved as u8, 2);
        assert_eq!(PendingExecutionApprovalStateV1::KernelArgvVerified as u8, 3);
        assert_eq!(PendingExecutionApprovalStateV1::SlotConsumed as u8, 4);
        assert_eq!(PendingExecutionApprovalStateV1::Tampered as u8, 5);
        assert_eq!(TASK_REFERENCE_ALL_V1, 0b111);
    }

    #[test]
    fn checked_decoders_reject_invalid_enum_values() {
        let binding = ExecutionSetBindingStateV1 {
            lifecycle_state: BindingLifecycleStateV1::Active,
            initial_root_state: InitialRootStateV1::Available,
            prepared_container_state: PreparedContainerStateV1::Prepared,
            ..ExecutionSetBindingStateV1::default()
        };
        let mut binding_bytes = binding.as_bytes().to_vec();
        binding_bytes[offset_of!(ExecutionSetBindingStateV1, lifecycle_state)] = u8::MAX;
        assert!(ExecutionSetBindingStateV1::try_read_from_bytes(&binding_bytes).is_err());
        let mut binding_bytes = binding.as_bytes().to_vec();
        let state_offset = offset_of!(ExecutionSetBindingStateV1, prepared_container_state);
        binding_bytes[state_offset..state_offset + size_of::<u64>()].fill(u8::MAX);
        assert!(ExecutionSetBindingStateV1::try_read_from_bytes(&binding_bytes).is_err());
        let slot = ExecutionApprovalSlotV1 {
            state: ExecutionApprovalSlotStateV1::Armed,
            ..ExecutionApprovalSlotV1::default()
        };
        let mut slot_bytes = slot.as_bytes().to_vec();
        let state_offset = offset_of!(ExecutionApprovalSlotV1, state);
        slot_bytes[state_offset..state_offset + size_of::<u64>()].fill(u8::MAX);
        assert!(ExecutionApprovalSlotV1::try_read_from_bytes(&slot_bytes).is_err());
    }

    #[test]
    fn execution_approval_argv_snapshot_is_closed() {
        let snapshot = ExecutionArgvSnapshotV1 {
            snapshot_id: Id128V1::new(1, 2),
            argument_count: 2,
            total_argument_span: 9,
            chunk_count: 1,
            reserved: 0,
        };
        assert!(snapshot.is_valid());
        assert!(!ExecutionArgvSnapshotV1::default().is_valid());
        assert!(!ExecutionArgvSnapshotV1 {
            snapshot_id: Id128V1::new(1, 2),
            argument_count: 2,
            total_argument_span: 1,
            chunk_count: 1,
            reserved: 0,
        }
        .is_valid());
        let chunk = ExecutionArgvChunkV1 {
            length: 9,
            flags: EXECUTION_ARGV_CHUNK_TERMINAL_V1,
            ..ExecutionArgvChunkV1::default()
        };
        assert!(chunk.is_valid_for(&snapshot, 0));
        assert!(!ExecutionArgvChunkV1 { flags: 0, ..chunk }.is_valid_for(&snapshot, 0));
    }
}
