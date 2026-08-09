tonic::include_proto!("erebor.mithril.control.v1");

pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
pub const IDENTITY_BYTES: usize = 16;

impl NodeEnvelope {
    #[must_use]
    pub fn has_supported_header(&self) -> bool {
        self.protocol_version == CONTROL_PROTOCOL_VERSION
            && !self.node_id.is_empty()
            && self.node_boot_id.len() == IDENTITY_BYTES
            && self.connection_nonce.len() == IDENTITY_BYTES
            && self.sequence > 0
    }
}

impl ControlEnvelope {
    #[must_use]
    pub fn has_supported_header(&self) -> bool {
        self.protocol_version == CONTROL_PROTOCOL_VERSION
            && !self.node_id.is_empty()
            && self.node_boot_id.len() == IDENTITY_BYTES
            && self.connection_nonce.len() == IDENTITY_BYTES
            && self.sequence > 0
    }
}
