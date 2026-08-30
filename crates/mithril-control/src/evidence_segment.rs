use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{ControlStoreSnafu, IoSnafu};
use crate::Result;

const MAX_SEGMENT_BYTES: u64 = 8 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStoreCapacityPolicyV1 {
    #[default]
    Block,
    Retain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStoreLimitsV1 {
    pub maximum_retained_bytes: u64,
    pub maximum_retained_records: u64,
    #[serde(default)]
    pub capacity_policy: EvidenceStoreCapacityPolicyV1,
}

impl EvidenceStoreLimitsV1 {
    pub fn validate(self) -> Result<()> {
        if self.maximum_retained_bytes < MAX_SEGMENT_BYTES || self.maximum_retained_records == 0 {
            return ControlStoreSnafu {
                path: PathBuf::from("<evidence-store-limits>"),
                reason: "evidence store bounds are zero or smaller than one segment".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl Default for EvidenceStoreLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_retained_bytes: 1_024 * 1_024 * 1_024,
            maximum_retained_records: 1_000_000,
            capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSegmentRefV1 {
    pub(crate) sha256: [u8; 32],
}

pub(crate) struct EvidenceSegmentOwner {
    root: PathBuf,
    retained_bytes: u64,
    limits: EvidenceStoreLimitsV1,
}

impl EvidenceSegmentOwner {
    pub(crate) fn open(control_root: &Path, limits: EvidenceStoreLimitsV1) -> Result<Self> {
        limits.validate()?;
        let root = control_root.join("evidence").join("segments");
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let retained_bytes = fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .try_fold(0_u64, |total, entry| {
                let path = entry.context(IoSnafu { path: &root })?.path();
                let metadata = fs::metadata(&path).context(IoSnafu { path: &path })?;
                if !metadata.is_file()
                    || path.extension().and_then(|value| value.to_str()) != Some("pb")
                {
                    return ControlStoreSnafu {
                        path,
                        reason: "the evidence segment directory contains an unknown entry"
                            .to_owned(),
                    }
                    .fail();
                }
                total.checked_add(metadata.len()).ok_or_else(|| {
                    ControlStoreSnafu {
                        path: root.clone(),
                        reason: "the retained evidence byte count is exhausted".to_owned(),
                    }
                    .build()
                })
            })?;
        Ok(Self {
            root,
            retained_bytes,
            limits,
        })
    }

    pub(crate) fn write<M: Message>(
        &mut self,
        message: &M,
        retained_records: u64,
        additional_records: u64,
    ) -> Result<EvidenceSegmentRefV1> {
        let encoded = message.encode_to_vec();
        if encoded.is_empty() || encoded.len() as u64 > MAX_SEGMENT_BYTES {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "evidence segment exceeds its size bound".to_owned(),
            }
            .fail();
        }
        let reference = EvidenceSegmentRefV1 {
            sha256: Sha256::digest(&encoded).into(),
        };
        let path = self.path(reference);
        let additional_bytes = if path.exists() {
            0
        } else {
            encoded.len() as u64
        };
        let next_bytes = self.retained_bytes.checked_add(additional_bytes);
        let next_records = retained_records.checked_add(additional_records);
        if self.limits.capacity_policy == EvidenceStoreCapacityPolicyV1::Block
            && (next_bytes.is_none_or(|bytes| bytes > self.limits.maximum_retained_bytes)
                || next_records
                    .is_none_or(|records| records > self.limits.maximum_retained_records))
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence store retention capacity is exhausted".to_owned(),
            }
            .fail();
        }
        if path.exists() {
            self.verify(reference)?;
            return Ok(reference);
        }
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .context(IoSnafu { path: &temporary })?;
        file.write_all(&encoded)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &path).context(IoSnafu { path: &path })?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .context(IoSnafu { path: &self.root })?;
        self.retained_bytes = next_bytes.unwrap_or(u64::MAX);
        Ok(reference)
    }

    pub(crate) fn validate_retention(&self, retained_records: u64) -> Result<()> {
        if self.limits.capacity_policy == EvidenceStoreCapacityPolicyV1::Block
            && (self.retained_bytes > self.limits.maximum_retained_bytes
                || retained_records > self.limits.maximum_retained_records)
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence store exceeds its configured retention capacity".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn read<M: Message + Default>(
        &self,
        reference: EvidenceSegmentRefV1,
        maximum_decoded_bytes: usize,
    ) -> Result<M> {
        let encoded = self.bytes(reference)?;
        if encoded.len() > maximum_decoded_bytes {
            return ControlStoreSnafu {
                path: self.path(reference),
                reason: "evidence segment exceeds its decoded size bound".to_owned(),
            }
            .fail();
        }
        M::decode(encoded.as_slice()).map_err(|error| {
            ControlStoreSnafu {
                path: self.path(reference),
                reason: format!("evidence segment decoding failed: {error}"),
            }
            .build()
        })
    }

    pub(crate) fn verify(&self, reference: EvidenceSegmentRefV1) -> Result<()> {
        self.bytes(reference).map(|_bytes| ())
    }

    pub(crate) fn exists(&self, reference: EvidenceSegmentRefV1) -> Result<bool> {
        match fs::metadata(self.path(reference)) {
            Ok(metadata) => Ok(metadata.is_file() && metadata.len() > 0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(crate::Error::Io {
                path: self.path(reference),
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    fn bytes(&self, reference: EvidenceSegmentRefV1) -> Result<Vec<u8>> {
        let path = self.path(reference);
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        if bytes.is_empty()
            || bytes.len() as u64 > MAX_SEGMENT_BYTES
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != reference.sha256
        {
            return ControlStoreSnafu {
                path,
                reason: "evidence segment checksum or size is invalid".to_owned(),
            }
            .fail();
        }
        Ok(bytes)
    }

    fn path(&self, reference: EvidenceSegmentRefV1) -> PathBuf {
        self.root
            .join(format!("{}.pb", hex::encode(reference.sha256)))
    }
}

#[cfg(test)]
mod tests {
    use super::{EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1};

    #[test]
    fn evidence_store_capacity_policy_defaults_to_block_and_accepts_retain(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block: EvidenceStoreLimitsV1 = serde_json::from_value(serde_json::json!({
            "maximum_retained_bytes": 8 * 1_024 * 1_024,
            "maximum_retained_records": 1
        }))?;
        assert_eq!(block.capacity_policy, EvidenceStoreCapacityPolicyV1::Block);

        let retain: EvidenceStoreLimitsV1 = serde_json::from_value(serde_json::json!({
            "maximum_retained_bytes": 8 * 1_024 * 1_024,
            "maximum_retained_records": 1,
            "capacity_policy": "RETAIN"
        }))?;
        assert_eq!(
            retain.capacity_policy,
            EvidenceStoreCapacityPolicyV1::Retain
        );
        Ok(())
    }
}
