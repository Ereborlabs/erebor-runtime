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
