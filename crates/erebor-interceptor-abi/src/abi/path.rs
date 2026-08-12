use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::Id128V1;

pub const MAX_CANONICAL_PATH_COMPONENTS_V1: usize = 64;
pub const MAX_CANONICAL_COMPONENT_BYTES_V1: usize = 255;
pub const CANONICAL_COMPONENT_STORAGE_BYTES_V1: usize = 256;

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum MountTopologyStateV1 {
    #[default]
    Unknown = 0,
    Dirty = 1,
    Clean = 2,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct MountSecurityViewStateV1 {
    pub topology_generation: u64,
    pub snapshot_digest_id: u64,
    pub pending_mutations: u64,
    pub state: MountTopologyStateV1,
    pub reserved: [u8; 7],
    pub transition_version: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct MountReconciliationProposalV1 {
    pub topology_generation: u64,
    pub snapshot_digest_id: u64,
    pub expected_transition_version: u64,
    pub transition_version: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct CanonicalMountRootKeyV1 {
    pub profile_generation_ref_id: u64,
    pub binding_id: Id128V1,
    pub topology_generation: u64,
    pub root_inode: u64,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct CanonicalMountRootV1 {
    pub selected_mount_id_unique: u64,
    pub snapshot_digest_id: u64,
    pub graph_prefix_state_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct CanonicalPathComponentV1 {
    pub length: u16,
    pub bytes: [u8; CANONICAL_COMPONENT_STORAGE_BYTES_V1],
}

impl Default for CanonicalPathComponentV1 {
    fn default() -> Self {
        Self {
            length: 0,
            bytes: [0; CANONICAL_COMPONENT_STORAGE_BYTES_V1],
        }
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct PathGraphTransitionKeyV1 {
    pub profile_generation_ref_id: u64,
    pub current_state_id: u32,
    pub component: CanonicalPathComponentV1,
    pub reserved: u16,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct PathGraphStateKeyV1 {
    pub profile_generation_ref_id: u64,
    pub state_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct PathGraphTransitionV1 {
    pub next_state_id: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct PathGraphTerminalV1 {
    pub composite_atom_id: u64,
    pub rule_numeric_id: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct MountMutationAttemptV1 {
    pub mount_namespace_inode: u32,
    pub active: u8,
    pub reserved: [u8; 3],
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn canonical_path_abi_is_bounded_and_padding_is_explicit() {
        assert_eq!(size_of::<CanonicalPathComponentV1>(), 258);
        assert_eq!(size_of::<PathGraphTransitionKeyV1>(), 272);
        assert_eq!(align_of::<PathGraphTransitionKeyV1>(), 8);
        assert_eq!(size_of::<MountSecurityViewStateV1>(), 40);
        assert_eq!(size_of::<MountReconciliationProposalV1>(), 32);
        assert_eq!(size_of::<CanonicalMountRootKeyV1>(), 48);
        assert_eq!(size_of::<CanonicalMountRootV1>(), 24);
        assert_eq!(size_of::<PathGraphStateKeyV1>(), 16);
        assert_eq!(size_of::<PathGraphTransitionV1>(), 8);
        assert_eq!(size_of::<PathGraphTerminalV1>(), 16);
        assert_eq!(size_of::<MountMutationAttemptV1>(), 8);
    }

    #[test]
    fn canonical_path_component_preserves_the_platform_bound() {
        let bytes = vec![b'x'; MAX_CANONICAL_COMPONENT_BYTES_V1];
        let mut component = CanonicalPathComponentV1 {
            length: bytes.len() as u16,
            ..CanonicalPathComponentV1::default()
        };
        component.bytes[..bytes.len()].copy_from_slice(&bytes);

        assert_eq!(usize::from(component.length), bytes.len());
        assert_eq!(&component.bytes[..bytes.len()], bytes);
        assert_eq!(component.bytes[bytes.len()], 0);
    }
}
