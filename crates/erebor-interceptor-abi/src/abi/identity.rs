use zerocopy::{Immutable, IntoBytes, KnownLayout};

pub const MAX_ANCESTOR_PROCESS_LINEAGES_V1: usize = 8;
pub const MAX_EXEC_CANDIDATES_V1: usize = 8;
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
    Eq,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
)]
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
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum ExecGuardStateV1 {
    #[default]
    None = 0,
    Preparing = 1,
    CommitPending = 2,
    OutcomeUnknown = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum EntryAdmissionStateV1 {
    #[default]
    Unknown = 0,
    Pending = 1,
    Claiming = 2,
    Committed = 3,
    Terminal = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum EntryLifetimeStateV1 {
    #[default]
    Inactive = 0,
    Active = 1,
    Draining = 2,
    Complete = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum ExternalRootClassV1 {
    #[default]
    Unknown = 0,
    InitialContainerRoot = 1,
    ExternalRuntimeRoot = 2,
    RestoredOrUnknownRoot = 3,
    UnresolvedProtected = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum EntryPurposeV1 {
    #[default]
    Unknown = 0,
    QualifiedJoinedPurpose = 1,
    ApprovedAdministrativeNextMatch = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum EntryKindV1 {
    #[default]
    Unknown = 0,
    ContainerStart = 1,
    QualifiedExecProbe = 2,
    QualifiedLifecyclePoststart = 3,
    QualifiedLifecyclePrestop = 4,
    ApprovedAdministrativeExecNextMatch = 5,
    EphemeralContainer = 6,
    QualifiedCiContainerAction = 7,
    CheckpointRestoreUnknown = 8,
    UnknownExternal = 9,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum ReferenceTombstoneStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Owned = 2,
    Released = 3,
    Reclaimable = 4,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub enum InitialRootStateV1 {
    #[default]
    Unarmed = 0,
    Available = 1,
    Consumed = 2,
}

impl InitialRootStateV1 {
    #[must_use]
    pub const fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Unarmed),
            1 => Some(Self::Available),
            2 => Some(Self::Consumed),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct TaskPlacementExpectationV1 {
    pub protected_root_binding_id: Id128V1,
    pub protected_root_binding_nonce: Id128V1,
    pub allowed_descendant_policy_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct TaskCoordinateV1 {
    pub task_cookie: u64,
    pub process_instance_id: Id128V1,
    pub process_state_id: Id128V1,
    pub host_tid: u32,
    pub host_tgid: u32,
    pub pid_namespace_inode: u64,
    pub task_start_boottime_ns: u64,
    pub finalized_boottime_ns: u64,
    pub transition_version: u64,
    pub state: TaskCoordinateStateV1,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
    pub reserved_pending_role: u32,
    pub transition_guard: u64,
    pub pending_exec_response_set_ref_id: u64,
    pub transition_version: u64,
    pub live_thread_refs: u64,
    pub exec_guard_state: ExecGuardStateV1,
    pub state: ProcessSecurityStateKindV1,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
    pub entry_kind: EntryKindV1,
    pub admission_state: EntryAdmissionStateV1,
    pub lifetime_state: EntryLifetimeStateV1,
    pub terminal_reason: u8,
    pub reserved_state: [u8; 4],
    pub transition_guard: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct ExecutionSetBindingStateV1 {
    pub binding_id: Id128V1,
    pub binding_nonce: Id128V1,
    pub node_boot_id: Id128V1,
    pub execution_set_id: Id128V1,
    pub profile_id: Id128V1,
    pub label_epoch: u64,
    pub active_profile_generation_ref_id: u64,
    pub root_cgroup_id: u64,
    pub root_cgroup_live_interval_id: Id128V1,
    pub lifecycle_generation: u64,
    pub transition_version: u64,
    pub initial_role_id: u32,
    pub external_role_id: u32,
    pub lifecycle_state: super::BindingLifecycleStateV1,
    pub reserved: [u8; 7],
    pub initial_root_state: InitialRootStateV1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct ExactExecutableCandidateV1 {
    pub mount_id: u64,
    pub inode: u64,
    pub inode_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct PendingExecV1 {
    pub pending_exec_id: Id128V1,
    pub task_cookie: u64,
    pub process_state_id: Id128V1,
    pub exec_attempt_sequence: u64,
    pub source_execution_id: Id128V1,
    pub source_role_id: u32,
    pub candidate_count: u16,
    pub reserved_0: u16,
    pub source_profile_generation_ref_id: u64,
    pub pending_exec_response_set_ref_id: u64,
    pub target_execution_id: Id128V1,
    pub ordered_candidates: [ExactExecutableCandidateV1; MAX_EXEC_CANDIDATES_V1],
    pub transition_version: u64,
    pub state: PendingExecStateV1,
    pub reserved_1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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
    pub profile_generation_ref_id: u64,
    pub installed_role_numeric_id: u32,
    pub root_class: ExternalRootClassV1,
    pub purpose: EntryPurposeV1,
    pub installed_role_class: InstalledRoleClassV1,
    pub reserved: u8,
    pub classified_boottime_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct IdentityRuntimeConfigV1 {
    pub node_boot_id: Id128V1,
    pub label_epoch: u64,
    pub next_id: u64,
    pub first_effect_errno: i32,
    pub enabled: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
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

    #[test]
    fn phase2_identity_abi_has_stable_sizes_and_offsets() {
        assert_eq!(size_of::<Id128V1>(), 16);
        assert_eq!(size_of::<TaskPlacementExpectationV1>(), 40);
        assert_eq!(size_of::<TaskLabelV1>(), 328);
        assert_eq!(offset_of!(TaskLabelV1, process_state_id), 64);
        assert_eq!(offset_of!(TaskLabelV1, placement), 288);
        assert_eq!(size_of::<TaskCoordinateV1>(), 88);
        assert_eq!(size_of::<CreatedByEdgeV1>(), 80);
        assert_eq!(align_of::<ProcessSecurityStateV1>(), 8);
        assert_eq!(size_of::<ExactExecutableCandidateV1>(), 24);
        assert_eq!(size_of::<IdentityRuntimeConfigV1>(), 40);
    }

    #[test]
    fn closed_identity_enums_keep_unknown_at_zero() {
        assert_eq!(TaskCoordinateStateV1::Unknown as u8, 0);
        assert_eq!(ExternalRootClassV1::UnresolvedProtected as u8, 4);
        assert_eq!(ExecGuardStateV1::OutcomeUnknown as u8, 3);
        assert_eq!(PendingExecStateV1::Success as u8, 5);
        assert_eq!(InstalledRoleClassV1::ApprovedAdministrativeRole as u8, 5);
        assert_eq!(EntryKindV1::UnknownExternal as u8, 9);
        assert_eq!(InitialRootStateV1::Unarmed as u64, 0);
        assert_eq!(InitialRootStateV1::Consumed as u64, 2);
        assert_eq!(TASK_REFERENCE_ALL_V1, 0b111);
    }
}
