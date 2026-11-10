


#[cfg(any(test, feature = "test-fixtures"))]
use crate::EvidenceIntakeIdentityV1;

const RETENTION_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionLimitsV1 {
    pub raw_max_age_ns: Option<u64>,
    pub raw_max_bytes: Option<u64>,
}

#[cfg(test)]
impl RetentionLimitsV1 {
    pub(super) fn fixture() -> Self {
        Self {
            raw_max_age_ns: Some(24 * 60 * 60 * 1_000_000_000),
            raw_max_bytes: Some(2 * 1024 * 1024 * 1024),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionStepV1 {
    pub removed_records: u32,
    pub more: bool,
    pub next_deadline_utc_ns: Option<u64>,
    pub read_revision: u64,
}

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionResultV1 {
    pub removed_records: u32,
    pub retained_bytes: u64,
    pub retained_floor: u64,
    pub commit_revision: u64,
}

