use std::fs;
use std::os::unix::fs::MetadataExt as _;

use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{IoSnafu, Result, StorageCapacitySnafu};

const WRITE_RESERVE: u64 = 256 * 1024 * 1024;
const MAX_STORAGE_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageLimitsV1 {
    pub disk_max_bytes: u64,
    pub policy_reserve_bytes: u64,
    pub logical_max_bytes: u64,
    pub tenant_max_bytes: u64,
    pub witness_max_bytes: u64,
}

impl Default for StorageLimitsV1 {
    fn default() -> Self {
        Self {
            disk_max_bytes: 8 * 1024 * 1024 * 1024,
            policy_reserve_bytes: 256 * 1024 * 1024,
            logical_max_bytes: 8 * 1024 * 1024 * 1024,
            tenant_max_bytes: 2 * 1024 * 1024 * 1024,
            witness_max_bytes: 512 * 1024 * 1024,
        }
    }
}

impl StorageLimitsV1 {
    pub fn valid(&self) -> bool {
        self.disk_max_bytes >= 4 * WRITE_RESERVE
            && self.policy_reserve_bytes >= WRITE_RESERVE
            && self.tenant_max_bytes > 0
            && self.tenant_max_bytes <= self.logical_max_bytes
            && self.witness_max_bytes > 0
            && self
                .policy_reserve_bytes
                .checked_add(self.disk_max_bytes)
                .is_some()
    }

    pub(super) fn check(&self, usage: StorageUsageV1, maintenance: bool) -> Result<()> {
        let reserve = self.maintenance_bytes();
        let reserve = if maintenance {
            reserve
        } else {
            reserve + self.disk_max_bytes / 4
        };
        if usage.available_bytes < reserve {
            return StorageCapacitySnafu {
                resource: "filesystem reserve",
            }
            .fail();
        }
        if !maintenance && usage.file_bytes > self.disk_max_bytes - WRITE_RESERVE {
            return StorageCapacitySnafu {
                resource: "data files",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn maintenance_bytes(&self) -> u64 {
        self.policy_reserve_bytes + WRITE_RESERVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, RetentionLimitsV1,
        ValidatedEvidenceBatchV1,
    };

    #[test]
    fn analysis_store_capacity_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::default();
        assert!(limits.valid());
        assert!(!StorageLimitsV1 {
            disk_max_bytes: u64::MAX,
            ..limits
        }
        .valid());
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes - WRITE_RESERVE,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes() + limits.disk_max_bytes / 4,
        };
        limits.check(usage, false)?;
        assert!(limits
            .check(
                StorageUsageV1 {
                    file_bytes: usage.file_bytes + 1,
                    ..usage
                },
                false
            )
            .is_err());
        assert!(limits
            .check(
                StorageUsageV1 {
                    available_bytes: usage.available_bytes - 1,
                    ..usage
                },
                false
            )
            .is_err());
        limits.check(
            StorageUsageV1 {
                file_bytes: u64::MAX,
                available_bytes: limits.maintenance_bytes(),
                ..usage
            },
            true,
        )?;
        assert!(limits
            .check(
                StorageUsageV1 {
                    available_bytes: limits.maintenance_bytes() - 1,
                    ..usage
                },
                true
            )
            .is_err());

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(&root, RetentionLimitsV1::default(), limits)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let first = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        };
        store.accept_validated_batch(identity.clone(), first.clone())?;
        let before = store.meta()?;
        let padding = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota-test"))?;
        padding.set_len(limits.disk_max_bytes)?;
        let usage = store.storage_usage()?;
        assert!(usage.file_bytes >= limits.disk_max_bytes);
        assert!(usage.allocated_bytes < usage.file_bytes);
        let mut next = first.clone();
        next.first_cursor = 2;
        next.last_cursor = 2;
        assert!(matches!(
            store.accept_validated_batch(identity.clone(), next.clone()),
            Err(crate::Error::StorageCapacity { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store.accept_validated_batch(identity.clone(), first)?,
            EvidenceStoreOutcomeV1::Accepted
        );
        store.checkpoint()?;
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        assert!(store
            .accept_validated_batch(identity.clone(), next.clone())
            .is_err());
        padding.set_len(0)?;
        store.accept_validated_batch(identity, next)?;
        assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
        Ok(())
    }

    #[test]
    fn analysis_store_native_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let reader_guard = store.reader()?;
        let reader = reader_guard.get()?;
        let settings: (String, String, String, u64) = reader.query_row(
            "SELECT current_setting('memory_limit'), current_setting('wal_autocheckpoint'), current_setting('max_temp_directory_size'), current_setting('threads')",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(
            settings,
            ("128.0 MiB".into(), "64.0 MiB".into(), "128.0 MiB".into(), 2)
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StorageUsageV1 {
    pub file_bytes: u64,
    pub allocated_bytes: u64,
    pub available_bytes: u64,
}

impl AnalysisStore {
    pub fn storage_usage(&self) -> Result<StorageUsageV1> {
        let volume = rustix::fs::statvfs(&self.root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &self.root })?;
        let available_bytes = volume
            .f_bavail
            .checked_mul(volume.f_frsize)
            .ok_or_else(|| self.state_error("the available storage size is invalid"))?;
        let mut usage = StorageUsageV1 {
            available_bytes,
            ..Default::default()
        };
        let mut pending = vec![self.root.clone()];
        let mut entries = 0;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let entry = entry.context(IoSnafu { path: &directory })?;
                entries += 1;
                if entries > MAX_STORAGE_ENTRIES {
                    return self.reject("the data directory exceeds its entry bound");
                }
                let path = entry.path();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                if metadata.is_dir() {
                    pending.push(path);
                } else if !metadata.is_file() {
                    return self.reject("the data directory contains a non-file entry");
                }
                let allocated = metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| self.state_error("allocated data bytes overflow"))?;
                usage.allocated_bytes = usage
                    .allocated_bytes
                    .checked_add(allocated)
                    .ok_or_else(|| self.state_error("allocated data bytes overflow"))?;
                usage.file_bytes = usage
                    .file_bytes
                    .checked_add(metadata.len().max(allocated))
                    .ok_or_else(|| self.state_error("data file bytes overflow"))?;
            }
        }
        Ok(usage)
    }

    pub(super) fn require_capacity(&self, maintenance: bool) -> Result<()> {
        self.storage.check(self.storage_usage()?, maintenance)
    }
}
