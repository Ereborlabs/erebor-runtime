tonic::include_proto!("erebor.mithril.control.v1");

pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
pub const IDENTITY_BYTES: usize = 16;
pub const MAX_NODE_ID_BYTES: usize = 128;

#[must_use]
pub fn node_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['/', '\\', '\0'])
}

impl NodeEnvelope {
    #[must_use]
    pub fn has_supported_header(&self) -> bool {
        self.protocol_version == CONTROL_PROTOCOL_VERSION
            && node_id_is_valid(&self.node_id)
            && self.node_boot_id.len() == IDENTITY_BYTES
            && self.connection_nonce.len() == IDENTITY_BYTES
            && self.sequence > 0
    }
}

impl ControlEnvelope {
    #[must_use]
    pub fn has_supported_header(&self) -> bool {
        self.protocol_version == CONTROL_PROTOCOL_VERSION
            && node_id_is_valid(&self.node_id)
            && self.node_boot_id.len() == IDENTITY_BYTES
            && self.connection_nonce.len() == IDENTITY_BYTES
            && self.sequence > 0
    }
}
