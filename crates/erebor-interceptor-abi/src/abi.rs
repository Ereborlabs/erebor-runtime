mod identity;
mod path;

pub use identity::*;
pub use path::*;

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
    Draining = 3,
    Terminating = 4,
    Tombstoned = 5,
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
    pub entry_kind: u16,
    pub effect_family: u16,
    pub operation: u16,
    pub reserved: u16,
    pub reserved_alignment: [u8; 4],
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
)]
pub struct PhysicalDecisionV1 {
    pub decision: PhysicalDecisionKindV1,
    pub reserved: u8,
    pub errno: i16,
    pub evidence_class_id: u32,
    pub transition_id: u32,
    pub exception_numeric_handle: u32,
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
pub struct ExceptionRuntimeStateKeyV1 {
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
    pub exception_numeric_handle: u32,
    pub deadline_boottime_ns: u64,
    pub transition_version: u64,
    pub state: ExceptionRuntimeStateKindV1,
    pub reserved: [u8; 7],
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
    pub entry_kind: u16,
    pub effect_family: u16,
    pub operation: u16,
    pub reserved: u16,
    pub reserved_alignment: [u8; 4],
    pub composite_atom_id: u64,
    pub process_state_vector_id: u32,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub reserved_tail: [u8; 3],
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
pub enum PolicyGenerationStateV1 {
    #[default]
    Unknown = 0,
    Preparing = 1,
    ReadBack = 2,
    Active = 3,
    Rejected = 4,
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
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
    pub inode_generation: u32,
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
    pub entry_kind: u16,
    pub effect_family: u16,
    pub operation: u16,
    pub configured_errno: i16,
    pub kernel_result: i32,
    pub reason: u8,
    pub physical_result: u8,
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
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
pub struct EffectObservationHealthV1 {
    pub attempted: u64,
    pub emitted: u64,
    pub lost: u64,
    pub unresolved: u64,
}

impl EffectDecisionKeyV1 {
    #[must_use]
    pub fn encode_le(self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..8].copy_from_slice(&self.profile_generation_ref_id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.active_role_id.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.entry_kind.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.effect_family.to_le_bytes());
        bytes[16..18].copy_from_slice(&self.operation.to_le_bytes());
        bytes[18..20].copy_from_slice(&self.reserved.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.reserved_alignment);
        bytes[24..32].copy_from_slice(&self.composite_atom_id.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.exact_object_key_id.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.process_state_vector_id.to_le_bytes());
        bytes[44] = self.binding_lifecycle_state as u8;
        bytes[45..48].copy_from_slice(&self.reserved_tail);
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
    use std::mem::{align_of, offset_of, size_of};

    use super::{
        BindingLifecycleStateV1, EffectDecisionKeyV1, EffectDefaultKeyV1,
        EffectObservationHealthV1, EffectObservationV1, ExactFileObjectKeyV1, ExactObjectBindingV1,
        ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1,
        FileOpenEventV1, FileOpenTargetV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
        PolicyGenerationModeV1, ProfileGenerationDescriptorV1, TaskLabelCandidateV1,
    };

    #[test]
    fn decision_abi_layout_and_values_are_closed() {
        assert_eq!(size_of::<EffectDecisionKeyV1>(), 48);
        assert_eq!(align_of::<EffectDecisionKeyV1>(), 8);
        assert_eq!(offset_of!(EffectDecisionKeyV1, composite_atom_id), 24);
        assert_eq!(offset_of!(EffectDecisionKeyV1, exact_object_key_id), 32);
        assert_eq!(offset_of!(EffectDecisionKeyV1, binding_lifecycle_state), 44);
        assert_eq!(size_of::<PhysicalDecisionV1>(), 16);
        assert_eq!(align_of::<PhysicalDecisionV1>(), 4);
        assert_eq!(size_of::<EffectDefaultKeyV1>(), 40);
        assert_eq!(size_of::<ProfileGenerationDescriptorV1>(), 112);
        assert_eq!(offset_of!(ProfileGenerationDescriptorV1, mode), 65);
        assert_eq!(size_of::<ExceptionRuntimeStateKeyV1>(), 16);
        assert_eq!(size_of::<ExceptionRuntimeStateV1>(), 40);
        assert_eq!(
            offset_of!(ExceptionRuntimeStateV1, deadline_boottime_ns),
            16
        );
        assert_eq!(PolicyGenerationModeV1::Observe as u8, 1);
        assert_eq!(PolicyGenerationModeV1::Protect as u8, 2);
        assert_eq!(ExceptionRuntimeStateKindV1::Active as u8, 1);
        assert_eq!(ExceptionRuntimeStateKindV1::ReconciliationRequired as u8, 4);
        assert_eq!(size_of::<ExactFileObjectKeyV1>(), 40);
        assert_eq!(size_of::<ExactObjectBindingV1>(), 32);
        assert_eq!(size_of::<EffectObservationV1>(), 200);
        assert_eq!(size_of::<EffectObservationHealthV1>(), 32);
        assert_eq!(offset_of!(EffectObservationV1, file_object), 120);
        assert_eq!(offset_of!(EffectObservationV1, kernel_result), 192);
        assert_eq!(PhysicalDecisionKindV1::Allow as u8, 0);
        assert_eq!(PhysicalDecisionKindV1::AuditAllow as u8, 1);
        assert_eq!(PhysicalDecisionKindV1::Deny as u8, 2);
        assert_eq!(BindingLifecycleStateV1::Unknown as u8, 0);
        assert_eq!(BindingLifecycleStateV1::Tombstoned as u8, 5);
    }

    #[test]
    fn proven_file_open_abi_has_no_implicit_padding() {
        assert_eq!(size_of::<TaskLabelCandidateV1>(), 8);
        assert_eq!(size_of::<FileOpenTargetV1>(), 8);
        assert_eq!(size_of::<FileOpenEventV1>(), 16);
        assert_eq!(offset_of!(FileOpenEventV1, result), 8);
        assert_eq!(offset_of!(FileOpenEventV1, reserved), 12);
    }

    #[test]
    fn decision_set_golden_bytes_are_stable_and_missing_state_denies() {
        let key = EffectDecisionKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 2,
            entry_kind: 3,
            effect_family: 4,
            operation: 5,
            reserved: 0,
            reserved_alignment: [0; 4],
            composite_atom_id: 6,
            exact_object_key_id: 7,
            process_state_vector_id: 8,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert_eq!(
            key.encode_le(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0,
                0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 2, 0, 0, 0,
            ]
        );
        let missing_state = PhysicalDecisionV1 {
            decision: PhysicalDecisionKindV1::Deny,
            reserved: 0,
            errno: -13,
            evidence_class_id: 0,
            transition_id: 0,
            exception_numeric_handle: 0,
        };
        assert_eq!(
            missing_state.encode_le(),
            [2, 0, 243, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
