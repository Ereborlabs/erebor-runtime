use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use prost::Message;
use serde::{Deserialize, Serialize};
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
    pub(crate) id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceSegmentKindV1 {
    Records {
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
    },
    Coverage {
        stream_id: u64,
        revision: u64,
    },
}

impl EvidenceSegmentKindV1 {
    pub(crate) fn stream_id(self) -> u64 {
        match self {
            Self::Records { stream_id, .. } | Self::Coverage { stream_id, .. } => stream_id,
        }
    }

    fn retained_records(self) -> Result<u64> {
        match self {
            Self::Records {
                first_cursor,
                last_cursor,
                ..
            } => last_cursor
                .checked_sub(first_cursor)
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: PathBuf::from("<evidence-segment>"),
                        reason: "evidence segment cursor range is invalid".to_owned(),
                    }
                    .build()
                }),
            Self::Coverage { .. } => Ok(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceSegmentDescriptorV1 {
    pub(crate) reference: EvidenceSegmentRefV1,
    pub(crate) kind: EvidenceSegmentKindV1,
}

#[derive(Clone, Copy)]
struct EvidenceSegmentStateV1 {
    descriptor: EvidenceSegmentDescriptorV1,
    bytes: u64,
}

pub(crate) struct EvidenceSegmentOwner {
    root: PathBuf,
    segments: BTreeMap<EvidenceSegmentRefV1, EvidenceSegmentStateV1>,
    retained_bytes: u64,
    retained_records: u64,
    next_id: u64,
    limits: EvidenceStoreLimitsV1,
}

impl EvidenceSegmentOwner {
    pub(crate) fn open(control_root: &Path, limits: EvidenceStoreLimitsV1) -> Result<Self> {
        limits.validate()?;
        let root = control_root.join("evidence").join("segments");
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let temporary = root.join("segment.tmp");
        match fs::remove_file(&temporary) {
            Ok(()) => Self::sync(&root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::Error::Io {
                    path: temporary,
                    source,
                    location: snafu::Location::default(),
                });
            }
        }

        let mut segments = BTreeMap::new();
        let mut retained_bytes = 0_u64;
        let mut retained_records = 0_u64;
        let mut next_id = 1_u64;
        for entry in fs::read_dir(&root).context(IoSnafu { path: &root })? {
            let path = entry.context(IoSnafu { path: &root })?.path();
            let metadata = fs::metadata(&path).context(IoSnafu { path: &path })?;
            if !metadata.is_file() {
                return ControlStoreSnafu {
                    path,
                    reason: "the evidence segment directory contains a non-file entry".to_owned(),
                }
                .fail();
            }
            let descriptor = Self::descriptor(&path)?;
            Self::validate_size(descriptor.kind, metadata.len(), &path)?;
            retained_bytes = retained_bytes.checked_add(metadata.len()).ok_or_else(|| {
                ControlStoreSnafu {
                    path: root.clone(),
                    reason: "the retained evidence byte count is exhausted".to_owned(),
                }
                .build()
            })?;
            retained_records = retained_records
                .checked_add(descriptor.kind.retained_records()?)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: root.clone(),
                        reason: "the retained evidence record count is exhausted".to_owned(),
                    }
                    .build()
                })?;
            next_id = next_id.max(descriptor.reference.id.checked_add(1).ok_or_else(|| {
                ControlStoreSnafu {
                    path: root.clone(),
                    reason: "the evidence segment sequence is exhausted".to_owned(),
                }
                .build()
            })?);
            if segments
                .insert(
                    descriptor.reference,
                    EvidenceSegmentStateV1 {
                        descriptor,
                        bytes: metadata.len(),
                    },
                )
                .is_some()
            {
                return ControlStoreSnafu {
                    path,
                    reason: "the evidence segment sequence is duplicated".to_owned(),
                }
                .fail();
            }
        }
        let owner = Self {
            root,
            segments,
            retained_bytes,
            retained_records,
            next_id,
            limits,
        };
        owner.validate_retention()?;
        Ok(owner)
    }

    pub(crate) fn write_records(
        &mut self,
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
        records: &crate::EvidenceRecords,
    ) -> Result<EvidenceSegmentRefV1> {
        self.write(
            EvidenceSegmentKindV1::Records {
                stream_id,
                first_cursor,
                last_cursor,
            },
            &records.encode_to_vec(),
        )
    }

    pub(crate) fn write_coverage(
        &mut self,
        stream_id: u64,
        revision: u64,
        report: &crate::CoverageReport,
    ) -> Result<EvidenceSegmentRefV1> {
        self.write(
            EvidenceSegmentKindV1::Coverage {
                stream_id,
                revision,
            },
            &report.encode_to_vec(),
        )
    }

    pub(crate) fn read_records(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
        maximum_decoded_bytes: usize,
    ) -> Result<crate::EvidenceRecords> {
        self.read(reference, expected, maximum_decoded_bytes)
    }

    pub(crate) fn read_coverage(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
        maximum_decoded_bytes: usize,
    ) -> Result<crate::CoverageReport> {
        self.read(reference, expected, maximum_decoded_bytes)
    }

    pub(crate) fn descriptors(&self) -> impl Iterator<Item = EvidenceSegmentDescriptorV1> + '_ {
        self.segments.values().map(|state| state.descriptor)
    }

    pub(crate) fn ensure_next_id_after(&mut self, committed_id: u64) -> Result<()> {
        self.next_id = self.next_id.max(committed_id.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence segment sequence is exhausted".to_owned(),
            }
            .build()
        })?);
        Ok(())
    }

    pub(crate) fn reclaim_after(&mut self, committed_id: u64) -> Result<()> {
        let references = self
            .segments
            .keys()
            .copied()
            .filter(|reference| reference.id > committed_id)
            .collect::<BTreeSet<_>>();
        self.reclaim(&references)
    }

    pub(crate) fn reclaim_unreferenced(
        &mut self,
        references: &BTreeSet<EvidenceSegmentRefV1>,
    ) -> Result<()> {
        let discarded = self
            .segments
            .keys()
            .copied()
            .filter(|reference| !references.contains(reference))
            .collect::<BTreeSet<_>>();
        self.reclaim(&discarded)
    }

    pub(crate) fn validate_retention(&self) -> Result<()> {
        if self.limits.capacity_policy == EvidenceStoreCapacityPolicyV1::Block
            && (self.retained_bytes > self.limits.maximum_retained_bytes
                || self.retained_records > self.limits.maximum_retained_records)
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence store exceeds its configured retention capacity".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn write(
        &mut self,
        kind: EvidenceSegmentKindV1,
        encoded: &[u8],
    ) -> Result<EvidenceSegmentRefV1> {
        let reference = EvidenceSegmentRefV1 { id: self.next_id };
        let descriptor = EvidenceSegmentDescriptorV1 { reference, kind };
        let path = self.path(descriptor);
        Self::validate_descriptor(descriptor, &path)?;
        Self::validate_size(kind, encoded.len() as u64, &path)?;
        let next_bytes = self.retained_bytes.checked_add(encoded.len() as u64);
        let next_records = self.retained_records.checked_add(kind.retained_records()?);
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
            return ControlStoreSnafu {
                path,
                reason: "the next evidence segment already exists".to_owned(),
            }
            .fail();
        }
        let temporary = self.root.join("segment.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .context(IoSnafu { path: &temporary })?;
        file.write_all(encoded)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &path).context(IoSnafu { path: &path })?;
        Self::sync(&self.root)?;
        self.retained_bytes = next_bytes.unwrap_or(u64::MAX);
        self.retained_records = next_records.unwrap_or(u64::MAX);
        self.next_id = self.next_id.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence segment sequence is exhausted".to_owned(),
            }
            .build()
        })?;
        self.segments.insert(
            reference,
            EvidenceSegmentStateV1 {
                descriptor,
                bytes: encoded.len() as u64,
            },
        );
        Ok(reference)
    }

    fn read<M: Message + Default>(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
        maximum_decoded_bytes: usize,
    ) -> Result<M> {
        let state = self.segments.get(&reference).ok_or_else(|| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: format!("evidence segment {} is missing", reference.id),
            }
            .build()
        })?;
        if state.descriptor.kind != expected {
            return ControlStoreSnafu {
                path: self.path(state.descriptor),
                reason: "evidence segment metadata does not match its index".to_owned(),
            }
            .fail();
        }
        let path = self.path(state.descriptor);
        let encoded = fs::read(&path).context(IoSnafu { path: &path })?;
        if encoded.len() > maximum_decoded_bytes {
            return ControlStoreSnafu {
                path,
                reason: "evidence segment exceeds its decoded size bound".to_owned(),
            }
            .fail();
        }
        M::decode(encoded.as_slice()).map_err(|error| {
            ControlStoreSnafu {
                path,
                reason: format!("evidence segment decoding failed: {error}"),
            }
            .build()
        })
    }

    fn reclaim(&mut self, references: &BTreeSet<EvidenceSegmentRefV1>) -> Result<()> {
        if references.is_empty() {
            return Ok(());
        }
        let mut reclaimed_bytes = 0_u64;
        let mut reclaimed_records = 0_u64;
        for reference in references {
            let Some(state) = self.segments.get(reference).copied() else {
                continue;
            };
            let path = self.path(state.descriptor);
            fs::remove_file(&path).context(IoSnafu { path: &path })?;
            reclaimed_bytes = reclaimed_bytes.checked_add(state.bytes).ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the reclaimed evidence byte count is exhausted".to_owned(),
                }
                .build()
            })?;
            reclaimed_records = reclaimed_records
                .checked_add(state.descriptor.kind.retained_records()?)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: self.root.clone(),
                        reason: "the reclaimed evidence record count is exhausted".to_owned(),
                    }
                    .build()
                })?;
            self.segments.remove(reference);
        }
        self.retained_bytes = self
            .retained_bytes
            .checked_sub(reclaimed_bytes)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the reclaimed evidence byte count exceeds retained storage".to_owned(),
                }
                .build()
            })?;
        self.retained_records = self
            .retained_records
            .checked_sub(reclaimed_records)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the reclaimed evidence record count exceeds retained storage"
                        .to_owned(),
                }
                .build()
            })?;
        Self::sync(&self.root)
    }

    fn descriptor(path: &Path) -> Result<EvidenceSegmentDescriptorV1> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let fields = name.split('.').collect::<Vec<_>>();
        let reference = EvidenceSegmentRefV1 {
            id: Self::field(&fields, 0, path)?,
        };
        let kind = match fields.as_slice() {
            [_, "r", _, _, _] => EvidenceSegmentKindV1::Records {
                stream_id: Self::field(&fields, 2, path)?,
                first_cursor: Self::field(&fields, 3, path)?,
                last_cursor: Self::field(&fields, 4, path)?,
            },
            [_, "c", _, _] => EvidenceSegmentKindV1::Coverage {
                stream_id: Self::field(&fields, 2, path)?,
                revision: Self::field(&fields, 3, path)?,
            },
            _ => {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the evidence segment name is invalid".to_owned(),
                }
                .fail();
            }
        };
        let descriptor = EvidenceSegmentDescriptorV1 { reference, kind };
        Self::validate_descriptor(descriptor, path)?;
        Ok(descriptor)
    }

    fn validate_descriptor(descriptor: EvidenceSegmentDescriptorV1, path: &Path) -> Result<()> {
        let valid = descriptor.reference.id > 0
            && descriptor.kind.stream_id() > 0
            && match descriptor.kind {
                EvidenceSegmentKindV1::Records {
                    first_cursor,
                    last_cursor,
                    ..
                } => first_cursor > 0 && last_cursor >= first_cursor,
                EvidenceSegmentKindV1::Coverage { revision, .. } => revision > 0,
            };
        if !valid {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn validate_size(kind: EvidenceSegmentKindV1, bytes: u64, path: &Path) -> Result<()> {
        let valid = match kind {
            EvidenceSegmentKindV1::Records { .. } | EvidenceSegmentKindV1::Coverage { .. } => {
                bytes > 0 && bytes <= MAX_SEGMENT_BYTES
            }
        };
        if !valid {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "evidence segment size is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn field(fields: &[&str], index: usize, path: &Path) -> Result<u64> {
        let field = fields.get(index).copied().unwrap_or_default();
        if field.len() != 16 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index field is invalid".to_owned(),
            }
            .fail();
        }
        u64::from_str_radix(field, 16).map_err(|error| {
            ControlStoreSnafu {
                path: path.to_owned(),
                reason: format!("the evidence segment index is invalid: {error}"),
            }
            .build()
        })
    }

    fn path(&self, descriptor: EvidenceSegmentDescriptorV1) -> PathBuf {
        let id = descriptor.reference.id;
        match descriptor.kind {
            EvidenceSegmentKindV1::Records {
                stream_id,
                first_cursor,
                last_cursor,
            } => self.root.join(format!(
                "{id:016x}.r.{stream_id:016x}.{first_cursor:016x}.{last_cursor:016x}"
            )),
            EvidenceSegmentKindV1::Coverage {
                stream_id,
                revision,
            } => self
                .root
                .join(format!("{id:016x}.c.{stream_id:016x}.{revision:016x}")),
        }
    }

    fn sync(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .context(IoSnafu { path })
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use tempfile::TempDir;

    use super::{EvidenceSegmentKindV1, EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1};

    #[test]
    fn evidence_segment_is_the_uncompressed_protobuf_payload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let mut owner =
            super::EvidenceSegmentOwner::open(directory.path(), EvidenceStoreLimitsV1::default())?;
        let records = crate::EvidenceRecords {
            records: vec![crate::EvidenceRecord {
                observed_boottime_ns: 1,
                task_cookie: 2,
                coverage_interval_id: vec![3; 16],
                reason: 1,
                decision: 1,
                effect_family: 1,
                operation: 1,
                configured_errno: -13,
                kernel_result: -13,
                temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                ..crate::EvidenceRecord::default()
            }],
        };
        let expected = records.encode_to_vec();

        let reference = owner.write_records(1, 1, 1, &records)?;
        let descriptor = owner
            .descriptors()
            .find(|descriptor| descriptor.reference == reference)
            .ok_or("the segment descriptor is absent")?;

        assert_eq!(std::fs::read(owner.path(descriptor))?, expected);
        assert_eq!(
            owner.read_records(reference, descriptor.kind, expected.len())?,
            records
        );
        Ok(())
    }

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
