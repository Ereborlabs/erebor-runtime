use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::{BindingLifecycleStateV1, Id128V1};

pub const MAX_NETWORK_PORT_RANGES_V1: usize = 8;

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum NetworkAddressFamilyV1 {
    #[default]
    Unknown = 0,
    Ipv4 = 1,
    Ipv6 = 2,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum NetworkProtocolV1 {
    #[default]
    Unknown = 0,
    Tcp = 6,
    Udp = 17,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum NetworkSocketStateKindV1 {
    #[default]
    Unknown = 0,
    Active = 1,
    Fenced = 2,
    Tombstoned = 3,
    ReconciliationRequired = 4,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum NetworkResponseScopeV1 {
    #[default]
    Unknown = 0,
    WholeSocket = 1,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct NetworkNamespaceGenerationV1 {
    pub network_namespace_address: u64,
    pub network_namespace_inode: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct NetworkPortRangeV1 {
    pub first: u16,
    pub last: u16,
}

/// One IPv4 longest-prefix-match key.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct NetworkIpv4LpmKeyV1 {
    pub prefix_length: u32,
    pub reserved_alignment: u32,
    pub profile_generation_ref_id: u64,
    pub protocol: NetworkProtocolV1,
    pub reserved: [u8; 7],
    pub address: [u8; 4],
    pub reserved_tail: [u8; 4],
}

/// One IPv6 longest-prefix-match key.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct NetworkIpv6LpmKeyV1 {
    pub prefix_length: u32,
    pub reserved_alignment: u32,
    pub profile_generation_ref_id: u64,
    pub protocol: NetworkProtocolV1,
    pub reserved: [u8; 7],
    pub address: [u8; 16],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct NetworkDestinationClassV1 {
    pub destination_policy_handle: u64,
    pub port_ranges: [NetworkPortRangeV1; MAX_NETWORK_PORT_RANGES_V1],
    pub port_range_count: u8,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct NetworkDestinationDecisionKeyV1 {
    pub profile_generation_ref_id: u64,
    pub destination_policy_handle: u64,
    pub active_role_id: u32,
    pub process_state_vector_id: u32,
    pub entry_kind: u16,
    pub operation: u16,
    pub protocol: NetworkProtocolV1,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub reserved: [u8; 2],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct NetworkSocketStateV1 {
    pub socket_network_namespace: NetworkNamespaceGenerationV1,
    pub creator_profile_generation_ref_id: u64,
    pub socket_key_id: u64,
    pub socket_generation: u64,
    pub flow_generation: u64,
    pub flow_authorization_id: Id128V1,
    pub destination_policy_handle: u64,
    pub creator_destination_policy_handle: u64,
    pub flow_authorizer_profile_generation_ref_id: u64,
    pub parent_socket_key_id: u64,
    pub parent_socket_generation: u64,
    pub creator_role_id: u32,
    pub creator_process_state_vector_id: u32,
    pub creator_entry_kind: u16,
    pub address_family: NetworkAddressFamilyV1,
    pub protocol: NetworkProtocolV1,
    pub peer_port: u16,
    pub peer_address: [u8; 16],
    pub creator_binding_lifecycle_state: BindingLifecycleStateV1,
    pub state: NetworkSocketStateKindV1,
    pub application_default_flow: u8,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct NetworkResponseFloorKeyV1 {
    pub profile_generation_ref_id: u64,
    pub socket_key_id: u64,
    pub socket_generation: u64,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct NetworkResponseFloorV1 {
    pub scope: NetworkResponseScopeV1,
    pub reserved: [u8; 7],
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::{
        NetworkDestinationClassV1, NetworkDestinationDecisionKeyV1, NetworkIpv4LpmKeyV1,
        NetworkIpv6LpmKeyV1, NetworkResponseFloorKeyV1, NetworkResponseFloorV1,
        NetworkSocketStateV1,
    };

    #[test]
    fn network_abi_is_closed() {
        assert_eq!(size_of::<NetworkIpv4LpmKeyV1>(), 32);
        assert_eq!(size_of::<NetworkIpv6LpmKeyV1>(), 40);
        assert_eq!(size_of::<NetworkDestinationClassV1>(), 48);
        assert_eq!(size_of::<NetworkDestinationDecisionKeyV1>(), 32);
        assert_eq!(size_of::<NetworkSocketStateV1>(), 144);
        assert_eq!(size_of::<NetworkResponseFloorKeyV1>(), 24);
        assert_eq!(size_of::<NetworkResponseFloorV1>(), 8);
        assert_eq!(align_of::<NetworkSocketStateV1>(), 8);
        assert_eq!(offset_of!(NetworkSocketStateV1, socket_key_id), 24);
        assert_eq!(offset_of!(NetworkSocketStateV1, peer_address), 118);
        assert_eq!(
            offset_of!(NetworkSocketStateV1, application_default_flow),
            136
        );
    }
}
