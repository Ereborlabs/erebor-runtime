use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupManifestV1 {
    pub store_uuid: String,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
    pub database_bytes: u64,
    pub database_files: Vec<AnalysisBackupFileV1>,
    pub reserved_bytes: u64,
    pub reserved_entries: usize,
    pub segments: Vec<AnalysisBackupSegmentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupSegmentV1 {
    pub segment_id: u64,
    pub file_name: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupFileV1 {
    pub file_name: String,
    pub bytes: u64,
    pub crc32c: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisRecoveryStatusV1 {
    Complete,
    Partial { first_cursor: u64, last_cursor: u64 },
}
