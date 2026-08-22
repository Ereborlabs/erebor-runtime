tonic::include_proto!("erebor.mithril.control.v1");

pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("erebor.mithril.control.v1");

pub const IDENTITY_BYTES: usize = 16;
pub const MAX_NODE_ID_BYTES: usize = 128;
pub const MAX_POLICY_GRPC_MESSAGE_BYTES: usize = 128 * 1_024;

#[must_use]
pub fn node_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['/', '\\', '\0'])
}
