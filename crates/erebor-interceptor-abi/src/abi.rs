mod identity;
mod ipc;
mod network;
mod path;

pub use identity::*;
pub use ipc::*;
pub use network::*;
pub use path::*;

pub const MAX_NESTED_EFFECT_ATTEMPTS_V1: usize = 4;
pub const MAX_IO_URING_ENTRIES_V1: u32 = 4_096;

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum BindingLifecycleStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Unarmed = 3,
    Prepared = 4,
    ExecPending = 5,
    Recovering = 6,
    ActiveRecovered = 7,
    Draining = 8,
    Terminating = 9,
    Tombstoned = 10,
    Expired = 11,
    Corrupt = 12,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum PhysicalDecisionKindV1 {
    #[default]
    Allow = 0,
    AuditAllow = 1,
    Deny = 2,
}

#[repr(u16)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub enum KernelEffectFamilyV1 {
    #[default]
    Unknown = 0,
    Exec = 1,
    File = 2,
    Network = 3,
    Device = 4,
    Privilege = 5,
    Ipc = 6,
    Mount = 7,
}

#[repr(u16)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub enum KernelEffectOperationV1 {
    #[default]
    Unknown = 0,
    Execute = 1,
    OpenRead = 2,
    OpenWrite = 3,
    Read = 4,
    Write = 5,
    Ioctl = 6,
    MmapRead = 7,
    MmapWrite = 8,
    MmapExec = 9,
    Mprotect = 10,
    IpcAccess = 11,
    Connect = 12,
    Send = 13,
    Ptrace = 14,
    Signal = 15,
    Unlink = 16,
    Link = 17,
    Rename = 18,
    Mount = 19,
    Unmount = 20,
    PivotRoot = 21,
    MoveMount = 22,
    Capability = 23,
    Bpf = 24,
    Create = 25,
    Setattr = 26,
    IoUringSetup = 27,
    IoUringRegister = 28,
    IoUringSqpoll = 29,
    IoUringOverrideCreds = 30,
    IoUringCommand = 31,
    SocketCreate = 32,
    Bind = 33,
    Listen = 34,
    Accept = 35,
    Receive = 36,
    Shutdown = 37,
    Setsockopt = 38,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExactDeviceTypeV1 {
    #[default]
    Unknown = 0,
    Character = 1,
    Block = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskLabelCandidateV1 {
    pub label: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileOpenTargetV1 {
    pub inode: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileOpenEventV1 {
    pub inode: u64,
    pub result: i32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct EffectDecisionKeyV1 {
    pub profile_generation_ref_id: u64,
    pub active_role_id: u32,
    pub effect_family: u16,
    pub operation: u16,
    pub composite_atom_id: u64,
    pub exact_object_key_id: u64,
    pub process_state_vector_id: u32,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub reserved_tail: [u8; 3],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct PhysicalDecisionV1 {
    pub decision: PhysicalDecisionKindV1,
    pub reserved: u8,
    pub errno: i16,
    pub evidence_class_id: u32,
    pub transition_id: u32,
    pub exception_numeric_handle: u32,
}

pub const MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1: usize = 80;

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum PolicyActivationProbeMapKindV1 {
    #[default]
    Unknown = 0,
    EffectDecision = 1,
    EffectDefault = 2,
    IpcRelationship = 3,
    DeviceEffect = 4,
    ProcessControl = 5,
    ExecutionApprovalSlotCancel = 6,
    MountReconciliation = 7,
    NetworkDestination = 8,
    RecoveredContainerActivation = 9,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct PolicyActivationProbeV1 {
    pub map_kind: PolicyActivationProbeMapKindV1,
    pub reserved: [u8; 7],
    pub key_size: u32,
    pub reserved_alignment: u32,
    pub key: [u8; MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1],
    pub expected: PhysicalDecisionV1,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionRuntimeStateKeyV1 {
    pub node_id: Id128V1,
    pub exception_instance_id: Id128V1,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionHandleBindingKeyV1 {
    pub profile_generation_ref_id: u64,
    pub exception_numeric_handle: u32,
    pub reserved: u32,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExceptionBindingStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Active = 2,
    Retiring = 3,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionHandleBindingV1 {
    pub runtime_state_key: ExceptionRuntimeStateKeyV1,
    pub state: ExceptionBindingStateV1,
    pub reserved: [u8; 7],
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExceptionRuntimeStateKindV1 {
    #[default]
    Unknown = 0,
    Active = 1,
    Exhausted = 2,
    Expired = 3,
    ReconciliationRequired = 4,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionRuntimeStateV1 {
    /// Zero-initialized storage used as `struct bpf_spin_lock` by BPF.
    pub lock: u32,
    pub maximum_uses: u32,
    pub consumed_uses: u32,
    pub bound_profile_generation_refs: u32,
    pub deadline_boottime_ns: u64,
    pub transition_version: u64,
    pub exception_definition_sha256: [u8; 32],
    pub state: ExceptionRuntimeStateKindV1,
    pub reserved: [u8; 7],
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExceptionUseIdentityKindV1 {
    #[default]
    Unknown = 0,
    ClaimSlot = 1,
    KernelEffectAttempt = 2,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionUseIdentityV1 {
    pub kind: ExceptionUseIdentityKindV1,
    pub reserved_0: [u8; 7],
    pub claim_slot_id: Id128V1,
    pub task_cookie: u64,
    pub process_state_id: Id128V1,
    pub syscall_entry_sequence: u64,
    pub effect_attempt_sequence: u64,
    pub effect_family: u16,
    pub operation: u16,
    pub reserved_1: [u8; 4],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionUseReceiptKeyV1 {
    pub runtime_state_key: ExceptionRuntimeStateKeyV1,
    pub use_identity: ExceptionUseIdentityV1,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExceptionReceiptStateV1 {
    #[default]
    Unknown = 0,
    Claiming = 1,
    Consumed = 2,
    DeniedExhausted = 3,
    DeniedExpired = 4,
    DeniedCorrupt = 5,
    ReconciliationRequired = 6,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExceptionUseReceiptV1 {
    pub consumed_ordinal: u32,
    pub state: ExceptionReceiptStateV1,
    pub reserved: [u8; 3],
    pub claimed_boottime_ns: u64,
    pub transition_version: u64,
}

#[repr(u16)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum EffectAttemptHookV1 {
    #[default]
    Unknown = 0,
    FileOpen = 1,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum TaskEffectAttemptFrameStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    Decided = 2,
    Returned = 3,
    Cancelled = 4,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum TaskEffectAttemptStateKindV1 {
    #[default]
    Inactive = 0,
    Active = 1,
    OverflowFailClosed = 2,
    TaskExited = 3,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct TaskEffectAttemptFrameV1 {
    pub effect_attempt_sequence: u64,
    pub effect_family: u16,
    pub operation: u16,
    pub hook_discriminator: EffectAttemptHookV1,
    pub repeated_lsm_pass_count: u16,
    pub state: TaskEffectAttemptFrameStateV1,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct TaskEffectAttemptStateV1 {
    pub task_cookie: u64,
    pub syscall_entry_sequence: u64,
    pub next_effect_attempt_sequence: u64,
    pub frames: [TaskEffectAttemptFrameV1; MAX_NESTED_EFFECT_ATTEMPTS_V1],
    pub depth: u16,
    pub state: TaskEffectAttemptStateKindV1,
    pub reserved: [u8; 5],
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum IoUringSetupStateKindV1 {
    #[default]
    Inactive = 0,
    Prepared = 1,
    Authorized = 2,
    Invalid = 3,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum IoUringRestrictionStateV1 {
    #[default]
    Unknown = 0,
    None = 1,
    ExactReadWrite = 2,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum IoUringRingStateKindV1 {
    #[default]
    Unknown = 0,
    Disabled = 1,
    Restricted = 2,
    Active = 3,
    Corrupt = 4,
    Closed = 5,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum IoUringRequestStateKindV1 {
    #[default]
    Unknown = 0,
    Submitted = 1,
    Completed = 2,
    Corrupt = 3,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum IoUringExecutionStateKindV1 {
    #[default]
    Inactive = 0,
    Active = 1,
    FailClosed = 2,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct IoUringSetupStateV1 {
    pub task_cookie: u64,
    pub setup_attempt_sequence: u64,
    pub entries: u32,
    pub flags: u32,
    pub state: IoUringSetupStateKindV1,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct IoUringActorSnapshotV1 {
    pub node_boot_id: Id128V1,
    pub process_lineage_id: Id128V1,
    pub process_instance_id: Id128V1,
    pub process_state_id: Id128V1,
    pub entry_instance_id: Id128V1,
    pub authority_domain_id: Id128V1,
    pub binding_id: Id128V1,
    pub binding_nonce: Id128V1,
    pub execution_set_id: Id128V1,
    pub profile_id: Id128V1,
    pub task_cookie: u64,
    pub label_epoch: u64,
    pub profile_generation_ref_id: u64,
    pub root_cgroup_id: u64,
    pub container_generation: u64,
    pub lifecycle_generation: u64,
    pub process_transition_version: u64,
    pub active_role_id: u32,
    pub process_state_vector_id: u32,
    pub admitted_entry_rule_id: u32,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct IoUringRingStateV1 {
    pub owner: IoUringActorSnapshotV1,
    pub binding: ExecutionSetBindingStateV1,
    pub ring_id: Id128V1,
    pub context_cookie: u64,
    pub ring_generation: u64,
    pub next_submission_sequence: u64,
    pub transition_version: u64,
    pub outstanding_requests: u64,
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub setup_flags: u32,
    pub state: IoUringRingStateKindV1,
    pub restriction_state: IoUringRestrictionStateV1,
    pub reserved: [u8; 2],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct IoUringRequestStateV1 {
    pub actor: IoUringActorSnapshotV1,
    pub ring_id: Id128V1,
    pub context_cookie: u64,
    pub request_cookie: u64,
    pub ring_generation: u64,
    pub submission_sequence: u64,
    pub user_data: u64,
    pub file_offset: i64,
    pub buffer_address: u64,
    pub file_cookie: u64,
    pub transition_version: u64,
    pub byte_length: u32,
    pub sqe_index: u32,
    pub request_flags: u32,
    pub rw_flags: u32,
    pub opcode: u16,
    pub state: IoUringRequestStateKindV1,
    pub reserved: [u8; 5],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct IoUringExecutionStateV1 {
    pub ring_id: Id128V1,
    pub context_cookie: u64,
    pub request_cookie: u64,
    pub submission_sequence: u64,
    pub user_data: u64,
    pub executor_pid_tgid: u64,
    pub opcode: u16,
    pub state: IoUringExecutionStateKindV1,
    pub reserved: [u8; 5],
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct EffectDefaultKeyV1 {
    pub profile_generation_ref_id: u64,
    pub active_role_id: u32,
    pub effect_family: u16,
    pub operation: u16,
    pub composite_atom_id: u64,
    pub process_state_vector_id: u32,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub reserved_tail: [u8; 3],
}

/// One signed ioctl decision for the current actor and one live device object.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct DeviceEffectKeyV1 {
    pub profile_generation_ref_id: u64,
    pub mount_id_unique: u64,
    pub inode: u64,
    pub exact_object_key_id: u64,
    pub inode_generation: u64,
    pub active_role_id: u32,
    pub process_state_vector_id: u32,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
    pub device_major: u32,
    pub device_minor: u32,
    pub ioctl_command: u32,
    pub operation: u16,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub device_type: ExactDeviceTypeV1,
    /// One only for a policy row that explicitly names all ioctl commands.
    pub command_wildcard: u8,
    pub reserved: [u8; 7],
}

/// A signed role relationship used to bind one exact controller-target pair.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ProcessControlRuleKeyV1 {
    pub profile_generation_ref_id: u64,
    pub controller_role_id: u32,
    pub controller_process_state_vector_id: u32,
    pub target_role_id: u32,
    pub target_process_state_vector_id: u32,
    pub operation_argument: u32,
    pub operation: u16,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub argument_wildcard: u8,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum PolicyGenerationStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    ReadBack = 2,
    Active = 3,
    Rejected = 4,
    Retiring = 5,
    Tombstoned = 6,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum PolicyGenerationModeV1 {
    #[default]
    Unknown = 0,
    Observe = 1,
    Protect = 2,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ProfileGenerationDescriptorV1 {
    pub node_boot_id: Id128V1,
    pub profile_id: Id128V1,
    pub label_epoch: u64,
    pub profile_generation_ref_id: u64,
    pub owner_generation: u64,
    pub row_count: u32,
    pub default_count: u32,
    pub state: PolicyGenerationStateV1,
    pub mode: PolicyGenerationModeV1,
    pub reserved: [u8; 6],
    pub table_digest: [u8; 32],
    pub transition_version: u64,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct ExactFileObjectKeyV1 {
    pub profile_generation_ref_id: u64,
    pub mount_id_unique: u64,
    pub inode: u64,
    pub inode_generation: u64,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub enum ExactFileMeasurementStateV1 {
    #[default]
    Unknown = 0,
    Requested = 1,
    Measured = 2,
    Invalid = 3,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::TryFromBytes,
)]
pub struct ExactFileMeasurementV1 {
    pub request_nonce: u64,
    pub mount_id_unique: u64,
    pub inode: u64,
    pub inode_generation: u64,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
    pub state: ExactFileMeasurementStateV1,
    pub reserved: [u8; 7],
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub enum ExactObjectBindingStateV1 {
    #[default]
    Unknown = 0,
    ReadBack = 1,
    ActiveDynamic = 2,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct ExactObjectBindingV1 {
    pub profile_generation_ref_id: u64,
    pub exact_object_key_id: u64,
    pub composite_atom_id: u64,
    pub state: ExactObjectBindingStateV1,
    pub reserved: [u8; 7],
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub enum EffectObservationReasonV1 {
    #[default]
    Unknown = 0,
    ExactPolicyAllow = 1,
    ExactPolicyAuditAllow = 2,
    WouldDeny = 3,
    PriorLsmDenial = 4,
    MissingIdentity = 5,
    CorruptIdentityOrGeneration = 6,
    UnresolvedObject = 7,
    UnsupportedObject = 8,
    ExactPolicyDeny = 9,
    ExceptionUnavailable = 10,
    PathTreePolicyDeny = 11,
    NetworkResponseFence = 12,
    PreparedRuntimeInfrastructure = 13,
    ApplicationDefaultAllow = 14,
    RuntimeEntryInfrastructure = 15,
    ExecutionApprovalVerificationFailed = 16,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub enum EffectPhysicalResultV1 {
    #[default]
    UnknownAfterPreEffect = 0,
    DeniedBeforeEffect = 1,
    PacketDroppedAfterRewrite = 2,
    TerminationQueuedBeforeUserMode = 3,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct EffectObservationV1 {
    pub observed_boottime_ns: u64,
    pub source_sequence: u64,
    pub source_cpu_id: u32,
    pub admitted_entry_rule_id: u32,
    pub task_cookie: u64,
    pub profile_generation_ref_id: u64,
    pub process_lineage_id: Id128V1,
    pub process_instance_id: Id128V1,
    pub entry_instance_id: Id128V1,
    pub authority_domain_id: Id128V1,
    pub binding_id: Id128V1,
    pub execution_set_id: Id128V1,
    pub file_object: ExactFileObjectKeyV1,
    pub exact_object_key_id: u64,
    pub composite_atom_id: u64,
    pub active_role_id: u32,
    pub process_state_vector_id: u32,
    pub effect_family: u16,
    pub operation: u16,
    pub configured_errno: i16,
    pub reserved_effect: [u8; 2],
    pub kernel_result: i32,
    pub reason: u8,
    pub physical_result: u8,
    pub reserved: [u8; 2],
    pub controller_process_state_id: Id128V1,
    pub controller_transition_version: u64,
    pub target_task_cookie: u64,
    pub target_profile_generation_ref_id: u64,
    pub target_process_state_id: Id128V1,
    pub target_transition_version: u64,
    pub target_role_id: u32,
    pub target_process_state_vector_id: u32,
    pub operation_argument: u32,
    pub reserved_process_control: [u8; 4],
    pub network_socket_key_id: u64,
    pub network_socket_generation: u64,
    pub network_flow_generation: u64,
    pub network_flow_authorization_id: Id128V1,
    pub network_destination_policy_handle: u64,
    pub network_creator_destination_policy_handle: u64,
    pub network_flow_authorizer_profile_generation_ref_id: u64,
    pub network_parent_socket_key_id: u64,
    pub network_parent_socket_generation: u64,
    pub network_namespace: NetworkNamespaceGenerationV1,
    pub network_current_namespace: NetworkNamespaceGenerationV1,
    pub network_creator_profile_generation_ref_id: u64,
    pub network_peer_address: [u8; 16],
    pub network_peer_port: u16,
    pub network_address_family: u8,
    pub network_protocol: u8,
    pub network_socket_state: u8,
    pub network_response_scope: u8,
    pub reserved_network: [u8; 2],
    pub io_uring_ring_id: Id128V1,
    pub io_uring_ring_generation: u64,
    pub io_uring_submission_sequence: u64,
    pub io_uring_user_data: u64,
    pub io_uring_file_offset: i64,
    pub io_uring_buffer_address: u64,
    pub io_uring_file_cookie: u64,
    pub io_uring_executor_pid_tgid: u64,
    pub io_uring_byte_length: u32,
    pub io_uring_sqe_index: u32,
    pub io_uring_request_flags: u32,
    pub io_uring_rw_flags: u32,
    pub io_uring_opcode: u16,
    pub reserved_io_uring: [u8; 6],
    pub execution_approval_trace: ExecutionApprovalTraceV1,
}

#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct EffectObservationHealthV1 {
    pub attempted: u64,
    pub suppressed: u64,
    pub requested: u64,
    pub emitted: u64,
    pub lost: u64,
    pub classifier_miss_count: u64,
    pub unresolved: u64,
    pub next_sequence: u64,
}

impl EffectDecisionKeyV1 {
    #[must_use]
    pub fn encode_le(self) -> [u8; 40] {
        let mut bytes = [0_u8; 40];
        bytes[0..8].copy_from_slice(&self.profile_generation_ref_id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.active_role_id.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.effect_family.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.operation.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.composite_atom_id.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.exact_object_key_id.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.process_state_vector_id.to_le_bytes());
        bytes[36] = self.binding_lifecycle_state as u8;
        bytes[37..40].copy_from_slice(&self.reserved_tail);
        bytes
    }
}

impl PhysicalDecisionV1 {
    #[must_use]
    pub fn encode_le(self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[0] = self.decision as u8;
        bytes[1] = self.reserved;
        bytes[2..4].copy_from_slice(&self.errno.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.evidence_class_id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.transition_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.exception_numeric_handle.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BindingLifecycleStateV1, EffectDecisionKeyV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
    };

    #[test]
    fn decision_key_and_result_encode_little_endian() {
        let key = EffectDecisionKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 2,
            effect_family: 4,
            operation: 5,
            composite_atom_id: 6,
            exact_object_key_id: 7,
            process_state_vector_id: 8,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert_eq!(
            key.encode_le(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 5, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0,
                0, 0, 0, 0, 8, 0, 0, 0, 2, 0, 0, 0,
            ]
        );
        let decision = PhysicalDecisionV1 {
            decision: PhysicalDecisionKindV1::Deny,
            reserved: 0,
            errno: -13,
            evidence_class_id: 0,
            transition_id: 0,
            exception_numeric_handle: 0,
        };
        assert_eq!(
            decision.encode_le(),
            [2, 0, 243, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
