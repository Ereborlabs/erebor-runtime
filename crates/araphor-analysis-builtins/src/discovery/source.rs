use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_NODE_ID_BYTES: usize = 128;

#[must_use]
pub fn node_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['/', '\\', '\0'])
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Separates retained input by authenticated source and source epoch.
pub struct EvidenceIntakeIdentityV1 {
    #[serde(with = "serde_bytes")]
    #[schemars(with = "[u8; 16]")]
    pub tenant_id: [u8; 16],
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "[u8; 16]")]
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "[u8; 16]")]
    pub source_id: [u8; 16],
    pub source_epoch: u64,
}

impl EvidenceIntakeIdentityV1 {
    pub const MAX_KEY_BYTES: usize = 67 + MAX_NODE_ID_BYTES;

    pub fn exact_key(&self) -> Vec<u8> {
        self.key()
    }

    pub fn valid(&self) -> bool {
        node_id_is_valid(&self.node_id)
            && self.tenant_id != [0; 16]
            && self.node_boot_id != [0; 16]
            && self.source_id != [0; 16]
            && self.label_epoch != 0
            && self.source_epoch != 0
    }

    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(67 + self.node_id.len());
        key.push(0);
        key.extend_from_slice(&self.tenant_id);
        key.extend_from_slice(&self.node_boot_id);
        key.extend_from_slice(&self.source_id);
        key.extend_from_slice(&self.label_epoch.to_be_bytes());
        key.extend_from_slice(&self.source_epoch.to_be_bytes());
        key.extend_from_slice(&(self.node_id.len() as u16).to_be_bytes());
        key.extend_from_slice(self.node_id.as_bytes());
        key
    }

    pub fn epoch_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(42 + self.node_id.len());
        key.extend_from_slice(&self.tenant_id);
        key.extend_from_slice(&(self.node_id.len() as u16).to_be_bytes());
        key.extend_from_slice(self.node_id.as_bytes());
        key.extend_from_slice(&self.source_id);
        key.extend_from_slice(&self.source_epoch.to_be_bytes());
        key
    }
}
