use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::Id128V1;

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum IpcChannelKindV1 {
    #[default]
    Unknown = 0,
    UnixStream = 1,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum IpcOperationV1 {
    #[default]
    Unknown = 0,
    Connect = 1,
    Send = 2,
    Receive = 3,
}

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub enum IpcSocketStateKindV1 {
    #[default]
    Unknown = 0,
    Endpoint = 1,
    Connected = 2,
}

/// One signed, directional Unix-stream relationship lookup.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct IpcRelationshipDecisionKeyV1 {
    pub actor_profile_generation_ref_id: u64,
    pub actor_role_id: u32,
    /// Zero selects the signed unmatched-IPC disposition.
    pub peer_role_id: u32,
    pub channel_kind: IpcChannelKindV1,
    pub operation: IpcOperationV1,
    pub reserved: [u8; 6],
}

/// Socket-local provenance for one endpoint or one connected Unix stream.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes,
)]
pub struct IpcSocketStateV1 {
    pub channel_state_id: Id128V1,
    pub endpoint_a_process_state_id: Id128V1,
    pub endpoint_b_process_state_id: Id128V1,
    pub endpoint_a_binding_id: Id128V1,
    pub endpoint_b_binding_id: Id128V1,
    pub endpoint_a_binding_nonce: Id128V1,
    pub endpoint_b_binding_nonce: Id128V1,
    pub endpoint_a_execution_set_id: Id128V1,
    pub endpoint_b_execution_set_id: Id128V1,
    pub endpoint_a_profile_generation_ref_id: u64,
    pub endpoint_b_profile_generation_ref_id: u64,
    pub endpoint_a_process_transition_version: u64,
    pub endpoint_b_process_transition_version: u64,
    pub endpoint_a_root_cgroup_id: u64,
    pub endpoint_b_root_cgroup_id: u64,
    pub endpoint_a_role_id: u32,
    pub endpoint_b_role_id: u32,
    pub transition_version: u64,
    pub channel_kind: IpcChannelKindV1,
    pub state: IpcSocketStateKindV1,
    pub reserved: [u8; 6],
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::{
        IpcChannelKindV1, IpcOperationV1, IpcRelationshipDecisionKeyV1, IpcSocketStateKindV1,
        IpcSocketStateV1,
    };

    #[test]
    fn unix_stream_relationship_abi_is_closed() {
        assert_eq!(size_of::<IpcRelationshipDecisionKeyV1>(), 24);
        assert_eq!(align_of::<IpcRelationshipDecisionKeyV1>(), 8);
        assert_eq!(offset_of!(IpcRelationshipDecisionKeyV1, channel_kind), 16);
        assert_eq!(size_of::<IpcSocketStateV1>(), 216);
        assert_eq!(align_of::<IpcSocketStateV1>(), 8);
        assert_eq!(offset_of!(IpcSocketStateV1, transition_version), 200);
        assert_eq!(offset_of!(IpcSocketStateV1, state), 209);
        assert_eq!(IpcChannelKindV1::UnixStream as u8, 1);
        assert_eq!(IpcOperationV1::Receive as u8, 3);
        assert_eq!(IpcSocketStateKindV1::Connected as u8, 2);
    }
}
