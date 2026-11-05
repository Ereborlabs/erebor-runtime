use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use sdk::arrow_array::{Array, BinaryArray, StringArray, UInt64Array};
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

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
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

    pub fn from_batch(
        batch: &sdk::RecordBatch,
    ) -> sdk::Result<impl Iterator<Item = sdk::Result<Self>> + '_> {
        let invalid = || sdk::Error::contract(sdk::ErrorCode::Invalid, "source identity columns");
        let binary = |name| {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or_else(invalid)
        };
        let number = |name| {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or_else(invalid)
        };
        let tenant = binary("tenant_id")?;
        let node = batch
            .column_by_name("node_id")
            .and_then(|column| column.as_any().downcast_ref::<StringArray>())
            .ok_or_else(invalid)?;
        let boot = binary("node_boot_id")?;
        let label = number("label_epoch")?;
        let source = binary("source_id")?;
        let epoch = number("source_epoch")?;
        if [tenant as &dyn Array, node, boot, label, source, epoch]
            .iter()
            .any(|column| column.null_count() != 0)
        {
            return Err(invalid());
        }
        Ok((0..batch.num_rows()).map(move |row| {
            let value = Self {
                tenant_id: tenant.value(row).try_into().map_err(|_| invalid())?,
                node_id: node.value(row).into(),
                node_boot_id: boot.value(row).try_into().map_err(|_| invalid())?,
                label_epoch: label.value(row),
                source_id: source.value(row).try_into().map_err(|_| invalid())?,
                source_epoch: epoch.value(row),
            };
            if !value.valid() {
                return Err(invalid());
            }
            Ok(value)
        }))
    }

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


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordIdV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub durable_cursor: u64,
}


#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryCoverageStateV1 {
    Healthy,
    Gapped,
    Unknown,
    Closed,
}


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCoverageV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub expected_records: u64,
    pub coverage_revision: u64,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub coverage_interval_id: [u8; 16],
    pub state: DiscoveryCoverageStateV1,
    pub gap_reasons: Vec<String>,
}


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryFileObjectV1 {
    pub profile_generation_ref_id: u64,
    pub mount_id_unique: u64,
    pub inode: u64,
    pub inode_generation: u64,
    pub mount_namespace_inode: u32,
    pub filesystem_device: u32,
}


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryEffectKeyV1 {
    pub task_cookie: u64,
    pub target_task_cookie: Option<u64>,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub process_lineage_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub authority_domain_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub execution_set_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub exact_object_id: Vec<u8>,
    pub destination_id: u64,
    pub policy_rule_id: u64,
    pub reason: u32,
    pub decision: u32,
    pub effect_family: u32,
    pub operation: u32,
    pub operation_argument: Option<u32>,
    pub configured_errno: i32,
    pub kernel_result: i32,
    pub exact_file_object: Option<DiscoveryFileObjectV1>,
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorScopeV1 {
    pub processor_id: String,
    pub method_version: u64,
    pub identity: EvidenceIntakeIdentityV1,
}

impl ProcessorScopeV1 {
    pub fn valid(&self) -> bool {
        !self.processor_id.is_empty() && self.method_version > 0 && self.identity.valid()
    }
}


#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct StorePositionV1 {
    pub commit_revision: u64,
    pub ordinal: u32,
}
