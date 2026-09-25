tonic::include_proto!("erebor.mithril.control.v1");

pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("erebor.mithril.control.v1");

pub const IDENTITY_BYTES: usize = 16;
pub use araphor_data::{node_id_is_valid, MAX_NODE_ID_BYTES};
// The limit bounds one complete policy bundle while chunk fields keep each transfer request bounded.
pub const MAX_POLICY_GRPC_MESSAGE_BYTES: usize = 128 * 1_024;
