use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{IoSnafu, Result, StorageCapacitySnafu};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageLimitsV1 {
    pub reader_admissions: Option<usize>,
    pub native_memory_bytes: Option<u64>,
    pub native_temp_bytes: Option<u64>,
    pub disk_max_bytes: Option<u64>,
    pub policy_reserve_bytes: Option<u64>,
    pub write_reserve_bytes: Option<u64>,
    pub logical_max_bytes: Option<u64>,
    pub tenant_max_bytes: Option<u64>,
    pub witness_max_bytes: Option<u64>,
    pub context_max_bytes: Option<u64>,
    pub storage_entries: Option<usize>,
    pub diagnostic_entries: Option<usize>,
    pub source_entries: Option<usize>,
    pub diagnostic_sources: Option<usize>,
    pub tenant_diagnostic_sources: Option<usize>,
    pub retained_revisions: Option<u64>,
    pub tenant_revisions: Option<u64>,
    pub manifest_max_bytes: Option<u64>,
}

impl StorageLimitsV1 {
    pub fn valid(&self) -> bool {
        let reserve = self
            .policy_reserve_bytes
            .unwrap_or(0)
            .checked_add(self.write_reserve_bytes.unwrap_or(0));
        self.reader_admissions
            .is_none_or(|limit| limit <= tokio::sync::Semaphore::MAX_PERMITS)
            && reserve.is_some_and(|reserve| {
                self.disk_max_bytes.is_none_or(|limit| {
                    limit >= self.write_reserve_bytes.unwrap_or(0)
                        && reserve.checked_add(limit).is_some()
                })
            })
            && self
                .tenant_max_bytes
                .zip(self.logical_max_bytes)
                .is_none_or(|(tenant, total)| tenant <= total)
    }

    fn bound(limit: Option<u64>, value: u64, resource: &'static str) -> Result<()> {
        if limit.is_some_and(|limit| value > limit) {
            return StorageCapacitySnafu { resource }.fail();
        }
        Ok(())
    }

    pub(super) fn check(&self, usage: StorageUsageV1, maintenance: bool) -> Result<()> {
        let reserve = self
            .maintenance_bytes()?
            .checked_add(if maintenance {
                0
            } else {
                self.disk_max_bytes.map_or(0, |limit| limit / 4)
            })
            .ok_or_else(|| {
                StorageCapacitySnafu {
                    resource: "filesystem reserve",
                }
                .build()
            })?;
        if usage.available_bytes < reserve {
            return StorageCapacitySnafu {
                resource: "filesystem reserve",
            }
            .fail();
        }
        if !maintenance {
            let limit = self
                .disk_max_bytes
                .map(|limit| {
                    limit
                        .checked_sub(self.write_reserve_bytes.unwrap_or(0))
                        .ok_or_else(|| {
                            StorageCapacitySnafu {
                                resource: "data files",
                            }
                            .build()
                        })
                })
                .transpose()?;
            Self::bound(limit, usage.file_bytes, "data files")?;
        }
        Ok(())
    }

    pub(super) fn maintenance_bytes(&self) -> Result<u64> {
        self.policy_reserve_bytes
            .unwrap_or(0)
            .checked_add(self.write_reserve_bytes.unwrap_or(0))
            .ok_or_else(|| {
                StorageCapacitySnafu {
                    resource: "filesystem reserve",
                }
                .build()
            })
    }

    pub(super) fn check_append(&self, usage: StorageUsageV1, bytes: u64) -> Result<()> {
        self.check_pending(usage, bytes, false)
    }

    pub(super) fn check_terminal(&self, usage: StorageUsageV1, bytes: u64) -> Result<()> {
        self.check_pending(usage, bytes, true)
    }

    fn check_pending(&self, usage: StorageUsageV1, bytes: u64, maintenance: bool) -> Result<()> {
        let projected = usage
            .file_bytes
            .checked_add(bytes)
            .and_then(|file_bytes| {
                Some(StorageUsageV1 {
                    file_bytes,
                    available_bytes: usage.available_bytes.checked_sub(bytes)?,
                    ..usage
                })
            })
            .ok_or_else(|| {
                StorageCapacitySnafu {
                    resource: "pending segment bytes",
                }
                .build()
            })?;
        if maintenance {
            Self::bound(self.disk_max_bytes, projected.file_bytes, "data files")?;
        }
        self.check(projected, maintenance)
    }

    pub(super) fn check_copy(&self, available: u64, bytes: u64) -> Result<()> {
        let required = bytes.checked_add(self.maintenance_bytes()?);
        if required.is_none_or(|size| available < size) {
            return StorageCapacitySnafu {
                resource: "copy reserve",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn check_backup(&self, usage: StorageUsageV1, bytes: u64) -> Result<()> {
        self.check_copy(usage.available_bytes, bytes)?;
        let projected = StorageUsageV1 {
            file_bytes: usage.file_bytes.checked_add(bytes).ok_or_else(|| {
                StorageCapacitySnafu {
                    resource: "backup files",
                }
                .build()
            })?,
            available_bytes: usage.available_bytes.checked_sub(bytes).ok_or_else(|| {
                StorageCapacitySnafu {
                    resource: "backup files",
                }
                .build()
            })?,
            ..usage
        };
        self.check(projected, false)
    }

    pub(super) fn check_entries(&self, entries: usize, diagnostics: usize) -> Result<()> {
        if self.storage_entries.is_some_and(|limit| entries > limit) {
            return StorageCapacitySnafu {
                resource: "storage entries",
            }
            .fail();
        }
        if self
            .diagnostic_entries
            .is_some_and(|limit| diagnostics > limit)
        {
            return StorageCapacitySnafu {
                resource: "diagnostic storage entries",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn check_sources(
        &self,
        total: usize,
        tenant: usize,
        diagnostic: bool,
    ) -> Result<()> {
        let resource = if diagnostic {
            "diagnostic sources"
        } else {
            "source bindings"
        };
        let limit = if diagnostic {
            self.diagnostic_sources
        } else {
            self.source_entries
        };
        if limit.is_some_and(|limit| total > limit)
            || (diagnostic
                && self
                    .tenant_diagnostic_sources
                    .is_some_and(|limit| tenant > limit))
        {
            return StorageCapacitySnafu { resource }.fail();
        }
        Ok(())
    }

    pub(super) fn check_logical(&self, total: u64, tenant: u64, maintenance: bool) -> Result<()> {
        let allowance = |limit| {
            if maintenance {
                limit
            } else {
                limit - limit / 4
            }
        };
        Self::bound(
            self.tenant_max_bytes.map(allowance),
            tenant,
            "tenant logical bytes",
        )?;
        Self::bound(
            self.logical_max_bytes.map(allowance),
            total,
            "global logical bytes",
        )
    }

    pub(super) fn check_diagnostics(&self, total: u64, tenant: u64) -> Result<()> {
        Self::bound(
            self.tenant_max_bytes.map(|limit| limit / 8),
            tenant,
            "diagnostic logical bytes",
        )?;
        Self::bound(
            self.logical_max_bytes.map(|limit| limit / 8),
            total,
            "diagnostic logical bytes",
        )
    }

    pub(super) fn check_revisions(&self, total: u64, tenant: u64) -> Result<()> {
        Self::bound(self.tenant_revisions, tenant, "tenant retained revisions")?;
        Self::bound(self.retained_revisions, total, "global retained revisions")
    }

    pub(super) fn check_witness(&self, bytes: u64) -> Result<()> {
        Self::bound(self.witness_max_bytes, bytes, "tenant witness bytes")
    }

    pub(super) fn check_context(&self, bytes: u64) -> Result<()> {
        Self::bound(self.context_max_bytes, bytes, "context version bytes")
    }

    pub(super) fn check_manifest(&self, bytes: u64) -> Result<()> {
        Self::bound(self.manifest_max_bytes, bytes, "backup manifest bytes")
    }
}

#[cfg(test)]
impl StorageLimitsV1 {
    pub(super) fn fixture() -> Self {
        Self {
            reader_admissions: None,
            native_memory_bytes: Some(128 * 1024 * 1024),
            native_temp_bytes: Some(128 * 1024 * 1024),
            disk_max_bytes: Some(8 * 1024 * 1024 * 1024),
            policy_reserve_bytes: Some(256 * 1024 * 1024),
            write_reserve_bytes: Some(256 * 1024 * 1024),
            logical_max_bytes: Some(8 * 1024 * 1024 * 1024),
            tenant_max_bytes: Some(2 * 1024 * 1024 * 1024),
            witness_max_bytes: Some(512 * 1024 * 1024),
            context_max_bytes: None,
            storage_entries: Some(4096),
            diagnostic_entries: Some(1024),
            source_entries: Some(4096),
            diagnostic_sources: Some(1024),
            tenant_diagnostic_sources: Some(256),
            retained_revisions: Some(4096),
            tenant_revisions: Some(1024),
            manifest_max_bytes: Some(2 * 1024 * 1024),
        }
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
    fn storage_defaults_disable_quotas() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits: StorageLimitsV1 = serde_json::from_str("{}")?;
        assert_eq!(limits, StorageLimitsV1::default());
        assert!(limits.valid());
        assert_eq!(limits.reader_admissions, None);
        assert_eq!(limits.native_memory_bytes, None);
        assert_eq!(limits.native_temp_bytes, None);
        assert_eq!(limits.maintenance_bytes()?, 0);
        limits.check(
            StorageUsageV1 {
                file_bytes: u64::MAX,
                ..Default::default()
            },
            false,
        )?;
        limits.check_entries(usize::MAX, usize::MAX)?;
        limits.check_sources(usize::MAX, usize::MAX, false)?;
        limits.check_sources(usize::MAX, usize::MAX, true)?;
        limits.check_logical(u64::MAX, u64::MAX, false)?;
        limits.check_diagnostics(u64::MAX, u64::MAX)?;
        limits.check_revisions(u64::MAX, u64::MAX)?;
        limits.check_witness(u64::MAX)?;
        limits.check_context(u64::MAX)?;
        limits.check_manifest(u64::MAX)?;
        let available = StorageUsageV1 {
            available_bytes: 5,
            ..Default::default()
        };
        limits.check_append(available, 5)?;
        limits.check_terminal(available, 5)?;
        limits.check_backup(available, 5)?;
        limits.check_copy(5, 5)?;
        assert!(limits.check_append(available, 6).is_err());
        assert!(limits.check_backup(available, 6).is_err());
        assert!(limits.check_copy(5, 6).is_err());
        assert!(limits
            .check_append(
                StorageUsageV1 {
                    file_bytes: u64::MAX,
                    available_bytes: 1,
                    ..Default::default()
                },
                1
            )
            .is_err());
        let limits: StorageLimitsV1 = serde_json::from_str(
            r#"{"reader_admissions":2,"native_memory_bytes":16777216,"native_temp_bytes":33554432,"tenant_max_bytes":8,"source_entries":1,"tenant_revisions":1}"#,
        )?;
        assert!(limits.valid());
        assert_eq!(limits.reader_admissions, Some(2));
        for reader_admissions in [
            None,
            Some(0),
            Some(1),
            Some(tokio::sync::Semaphore::MAX_PERMITS),
        ] {
            assert!(StorageLimitsV1 {
                reader_admissions,
                ..Default::default()
            }
            .valid());
        }
        assert!(!StorageLimitsV1 {
            reader_admissions: Some(tokio::sync::Semaphore::MAX_PERMITS + 1),
            ..Default::default()
        }
        .valid());
        assert_eq!(limits.native_memory_bytes, Some(16 * 1024 * 1024));
        assert_eq!(limits.native_temp_bytes, Some(32 * 1024 * 1024));
        limits.check_logical(100, 6, false)?;
        assert!(limits.check_logical(100, 7, false).is_err());
        limits.check_logical(100, 8, true)?;
        assert!(limits.check_logical(100, 9, true).is_err());
        limits.check_diagnostics(100, 1)?;
        assert!(limits.check_diagnostics(100, 2).is_err());
        limits.check_sources(1, 1, false)?;
        assert!(limits.check_sources(2, 1, false).is_err());
        limits.check_revisions(100, 1)?;
        assert!(limits.check_revisions(100, 2).is_err());
        assert!(serde_json::from_str::<StorageLimitsV1>(r#"{"unknown":1}"#).is_err());
        Ok(())
    }

    #[test]
    fn source_quota_preserves_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = StorageLimitsV1 {
            source_entries: Some(1),
            ..Default::default()
        };
        let source = |epoch| EvidenceIntakeIdentityV1 {
            source_epoch: epoch,
            ..crate::analysis::tests::identity()
        };
        let batch = || ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        assert_eq!(
            store.accept_validated_batch(source(1), batch())?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let before = store.meta()?;
        assert!(matches!(
            store.accept_validated_batch(source(2), batch()),
            Err(crate::Error::StorageCapacity {
                resource: "source bindings",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.source_receipt(&source(2))?.is_none());
        assert_eq!(
            store.accept_validated_batch(source(1), batch())?,
            EvidenceStoreOutcomeV1::Accepted
        );
        drop(store);
        let store = AnalysisStore::open_retention(&root)?;
        assert_eq!(
            store.accept_validated_batch(source(2), batch())?,
            EvidenceStoreOutcomeV1::Accepted
        );
        drop(store);
        let store = AnalysisStore::open_with_limits(
            &root,
            RetentionLimitsV1 {
                raw_max_age_ns: Some(1),
                ..Default::default()
            },
            StorageLimitsV1 {
                disk_max_bytes: Some(0),
                storage_entries: Some(0),
                ..limits
            },
        )?;
        assert_eq!(store.read_page(&source(1), 1)?.records.len(), 1);
        assert_eq!(store.read_page(&source(2), 1)?.records.len(), 1);
        assert!(store.storage_usage()?.file_bytes > 0);
        let retained = crate::EvidenceRetentionOwner::new(&store).retain(&source(1), 200)?;
        assert_eq!(retained.removed_records, 1);
        assert_eq!(store.read_page(&source(2), 1)?.records.len(), 1);
        let before = store.meta()?;
        assert!(matches!(
            store.accept_validated_batch(source(3), batch()),
            Err(crate::Error::StorageCapacity {
                resource: "source bindings",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        let step = crate::EvidenceRetentionOwner::new(&store).step(100)?;
        assert_eq!(step.removed_records, 0);
        assert!(!step.more);
        assert_eq!(step.next_deadline_utc_ns, Some(101));
        assert_eq!(store.read_page(&source(2), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn observability_terminal_reserve() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::fixture();
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes.ok_or("configured disk limit")? - 1024,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes()? + 1024,
        };
        assert!(limits.check_append(usage, 1024).is_err());
        limits.check_terminal(usage, 1024)?;
        assert!(limits.check_terminal(usage, 1025).is_err());
        assert!(limits
            .check_terminal(
                StorageUsageV1 {
                    available_bytes: usage.available_bytes - 1,
                    ..usage
                },
                1024
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn observability_entry_partition() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("data"),
            Default::default(),
            StorageLimitsV1::fixture(),
        )?;
        let baseline = store.storage_with_reserve(1, 0)?;
        assert_eq!(
            store.storage_with_reserve(1, 1024)?.file_bytes,
            baseline.file_bytes
        );
        assert!(matches!(
            store.storage_with_reserve(0, 1024 + 1),
            Err(crate::Error::StorageCapacity {
                resource: "diagnostic storage entries",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn analysis_store_copy_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::fixture();
        for bytes in [0, 1, 3, 4, 1024 * 1024] {
            let required = bytes + limits.maintenance_bytes()?;
            limits.check_copy(required, bytes)?;
            assert!(matches!(
                limits.check_copy(required - 1, bytes),
                Err(crate::Error::StorageCapacity {
                    resource: "copy reserve",
                    ..
                })
            ));
        }
        assert!(limits.check_copy(u64::MAX, u64::MAX).is_err());
        assert!(limits
            .check_copy(u64::MAX, u64::MAX - limits.maintenance_bytes()? + 1)
            .is_err());
        let bytes = 1024 * 1024;
        let reserve = bytes;
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes.ok_or("configured disk limit")?
                - limits
                    .write_reserve_bytes
                    .ok_or("configured write reserve")?
                - reserve,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes()?
                + limits.disk_max_bytes.ok_or("configured disk limit")? / 4
                + reserve,
        };
        limits.check_backup(usage, bytes)?;
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    file_bytes: usage.file_bytes + 1,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    available_bytes: usage.available_bytes - 1,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    file_bytes: u64::MAX,
                    available_bytes: u64::MAX,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits.check_backup(usage, u64::MAX).is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_capacity_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::fixture();
        assert!(limits.valid());
        assert!(!StorageLimitsV1 {
            disk_max_bytes: Some(u64::MAX),
            ..limits
        }
        .valid());
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes.ok_or("configured disk limit")?
                - limits
                    .write_reserve_bytes
                    .ok_or("configured write reserve")?,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes()?
                + limits.disk_max_bytes.ok_or("configured disk limit")? / 4,
        };
        limits.check(usage, false)?;
        let pending = StorageUsageV1 {
            file_bytes: usage.file_bytes - 1024,
            available_bytes: usage.available_bytes + 1024,
            ..usage
        };
        limits.check_append(pending, 1024)?;
        assert!(limits.check_append(pending, 1025).is_err());
        assert!(limits
            .check_append(
                StorageUsageV1 {
                    file_bytes: 0,
                    available_bytes: 0,
                    ..usage
                },
                1
            )
            .is_err());
        assert!(limits
            .check_append(
                StorageUsageV1 {
                    file_bytes: u64::MAX,
                    available_bytes: u64::MAX,
                    ..usage
                },
                1
            )
            .is_err());
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
                available_bytes: limits.maintenance_bytes()?,
                ..usage
            },
            true,
        )?;
        assert!(limits
            .check(
                StorageUsageV1 {
                    available_bytes: limits.maintenance_bytes()? - 1,
                    ..usage
                },
                true
            )
            .is_err());

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(&root, RetentionLimitsV1::default(), limits)?;
        let identity = crate::analysis::tests::identity();
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
        let mut next = first.clone();
        next.first_cursor = 2;
        next.last_cursor = 2;
        let ordinary = limits.disk_max_bytes.ok_or("configured disk limit")?
            - limits
                .write_reserve_bytes
                .ok_or("configured write reserve")?;
        let usage = store.storage_usage()?;
        padding.set_len(ordinary - usage.file_bytes - 4)?;
        assert!(matches!(
            store.accept_validated_batch(identity.clone(), next.clone()),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.storage_usage()?.file_bytes, ordinary - 4);
        padding.set_len(ordinary - usage.file_bytes - 5)?;
        let mut fresh = identity.clone();
        fresh.source_epoch = 2;
        assert!(matches!(
            store.accept_validated_batch(fresh.clone(), first.clone()),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(store.source_receipt(&fresh)?.is_none());
        assert_eq!(store.meta()?, before);
        assert_eq!(store.storage_usage()?.file_bytes, ordinary - 5);
        padding.set_len(limits.disk_max_bytes.ok_or("configured disk limit")?)?;
        let usage = store.storage_usage()?;
        assert!(usage.file_bytes >= limits.disk_max_bytes.ok_or("configured disk limit")?);
        assert!(usage.allocated_bytes < usage.file_bytes);
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
    fn analysis_store_segment_usage() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(100),
            ..Default::default()
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let source = EvidenceIntakeIdentityV1 {
            node_id: "capacity-node".into(),
            ..crate::analysis::tests::identity()
        };
        let batch = |cursor| ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        };
        let check = |store: &AnalysisStore, count: usize| -> Result<()> {
            let raw = store
                .raw
                .lock()
                .map_err(|_| store.state_error("raw lock"))?;
            let (_, evidence, diagnostic) = raw
                .storage_summary()?
                .ok_or_else(|| store.state_error("segment summary"))?;
            assert_eq!((evidence, diagnostic), (count, 0));
            let summary = store.storage_for_append(&raw, 0, 0)?;
            let inspected = AnalysisStore::storage_at(&root, 0, 0)?;
            assert_eq!(
                (summary.file_bytes, summary.allocated_bytes),
                (inspected.file_bytes, inspected.allocated_bytes)
            );
            Ok(())
        };
        store.accept_validated_batch(source.clone(), batch(1))?;
        check(&store, 1)?;
        store.accept_validated_batch(source.clone(), batch(2))?;
        check(&store, 1)?;
        store.checkpoint()?;
        check(&store, 1)?;
        store
            .raw
            .lock()
            .map_err(|_| store.state_error("raw lock"))?
            .seal_all()?;
        check(&store, 1)?;
        store.accept_validated_batch(source.clone(), batch(3))?;
        check(&store, 2)?;
        crate::EvidenceRetentionOwner::new(&store).retain(&source, 500)?;
        check(&store, 0)?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        check(&store, 0)?;
        store.accept_validated_batch(source.clone(), batch(4))?;
        check(&store, 1)?;

        let unknown = root.join("segments/unknown");
        let padding = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&unknown)?;
        padding.set_len(1024 * 1024)?;
        {
            let raw = store
                .raw
                .lock()
                .map_err(|_| store.state_error("raw lock"))?;
            assert!(raw.storage_summary()?.is_none());
            let summary = store.storage_for_append(&raw, 0, 0)?;
            let inspected = store.storage_usage()?;
            assert_eq!(
                (summary.file_bytes, summary.allocated_bytes),
                (inspected.file_bytes, inspected.allocated_bytes)
            );
        }
        padding.set_len(2 * 1024 * 1024)?;
        {
            let raw = store
                .raw
                .lock()
                .map_err(|_| store.state_error("raw lock"))?;
            assert_eq!(
                store.storage_for_append(&raw, 0, 0)?.file_bytes,
                store.storage_usage()?.file_bytes
            );
        }
        drop(padding);
        fs::remove_file(&unknown)?;
        let before = store.meta()?;
        let link = root.join("segments/link");
        symlink(root.join("analysis.duckdb"), &link)?;
        assert!(store
            .accept_validated_batch(source.clone(), batch(5))
            .is_err());
        assert_eq!(store.meta()?, before);
        fs::remove_file(link)?;
        store.accept_validated_batch(source, batch(5))?;
        Ok(())
    }

    #[test]
    fn analysis_store_native_configuration() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        for (limits, memory, temporary) in [
            (StorageLimitsV1::default(), "16383.9 PiB", "16383.9 PiB"),
            (
                StorageLimitsV1 {
                    native_memory_bytes: Some(128 * 1024 * 1024),
                    native_temp_bytes: Some(64 * 1024 * 1024),
                    ..Default::default()
                },
                "128.0 MiB",
                "64.0 MiB",
            ),
        ] {
            let check = |connection: &duckdb::Connection| -> std::result::Result<
                (),
                Box<dyn std::error::Error>,
            > {
                let settings: (String, String, bool, bool, bool) = connection.query_row(
                    "SELECT current_setting('memory_limit'), current_setting('max_temp_directory_size'), current_setting('autoload_known_extensions'), current_setting('autoinstall_known_extensions'), current_setting('enable_external_access')",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )?;
                assert_eq!(settings, (memory.into(), temporary.into(), false, false, false));
                Ok(())
            };
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
            check(store.reader()?.get()?)?;
            store.recover()?;
            check(store.reader()?.get()?)?;
            store.fault_write("UPDATE store_meta SET singleton = singleton", &[])?;
            check(store.reader()?.get()?)?;
            assert!(store
                .fault_write("INSERT INTO absent VALUES (1)", &[])
                .is_err());
            check(store.reader()?.get()?)?;
            let backup = root.join("backups/saved");
            store.backup(&backup)?;
            check(store.reader()?.get()?)?;
            {
                let connection = AnalysisStore::open_native(
                    &backup.join("analysis.duckdb"),
                    limits,
                    duckdb::AccessMode::ReadOnly,
                )?;
                check(&connection)?;
                assert_eq!(
                    connection.query_row(
                        "SELECT current_setting('temp_directory')",
                        [],
                        |row| row.get::<_, String>(0)
                    )?,
                    "",
                );
                assert!(connection
                    .execute_batch("CREATE TABLE absent (value BIGINT)")
                    .is_err());
            }
            let restored = AnalysisStore::restore_with_limits(
                &backup,
                &directory.path().join("restored"),
                limits,
            )?;
            check(restored.reader()?.get()?)?;
            drop(store);
            let reopened = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
            check(reopened.reader()?.get()?)?;
        }
        Ok(())
    }

    #[test]
    fn analysis_store_native_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let memory = 128 * 1024 * 1024_u64;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            StorageLimitsV1 {
                native_memory_bytes: Some(memory),
                native_temp_bytes: Some(64 * 1024 * 1024),
                ..Default::default()
            },
        )?;
        let reader_guard = store.reader()?;
        let reader = reader_guard.get()?;
        let settings: (String, String, String, u64, u64, String) = reader.query_row(
            "SELECT current_setting('memory_limit'), current_setting('wal_autocheckpoint'), current_setting('max_temp_directory_size'), current_setting('threads'), current_setting('vacuum_rebuild_indexes'), current_setting('allocator_bulk_deallocation_flush_threshold')",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )?;
        assert_eq!(
            settings,
            (
                "128.0 MiB".into(),
                "16.0 MiB".into(),
                "64.0 MiB".into(),
                2,
                0,
                "0 bytes".into(),
            )
        );
        drop(reader_guard);
        let writer = store.maintenance_writer()?;
        let connection = writer.get()?;
        connection.execute_batch("CREATE TEMP TABLE native_limit (payload BLOB)")?;
        let control =
            super::super::AnalysisReadControl::with_timeout(std::time::Duration::from_secs(10))?;
        let bytes = i64::try_from(memory + 1)?;
        let result = control.query_run(connection, || {
            Ok(connection.execute(
                "INSERT INTO native_limit SELECT CAST(repeat('x', ?) AS BLOB)",
                [bytes],
            ))
        })?;
        assert!(
            matches!(
                &result,
                Err(duckdb::Error::DuckDBFailure(_, Some(message)))
                    if message.starts_with("Out of Memory Error:")
            ),
            "{result:?}"
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM native_limit", [], |row| {
                row.get::<_, u64>(0)
            })?,
            0
        );
        Ok(())
    }

    #[test]
    #[ignore = "release-only isolated process RSS qualification on Linux"]
    fn analysis_store_thread_memory() -> std::result::Result<(), Box<dyn std::error::Error>> {
        check_thread_memory(1, StorageLimitsV1::fixture())
    }

    #[test]
    #[ignore = "release-only configured global quota RSS qualification on Linux"]
    fn analysis_store_global_memory() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut limits = StorageLimitsV1::fixture();
        if let Some(bytes) = std::env::var_os("ARAPHOR_GLOBAL_BYTES") {
            limits.logical_max_bytes = Some(
                bytes
                    .to_str()
                    .ok_or("the global test quota is not UTF-8")?
                    .parse()?,
            );
            limits.tenant_max_bytes = Some(
                limits
                    .tenant_max_bytes
                    .ok_or("configured tenant limit")?
                    .min(limits.logical_max_bytes.ok_or("configured logical limit")?),
            );
        }
        check_thread_memory(5, limits)
    }

    fn check_thread_memory(
        tenants: u8,
        limits: StorageLimitsV1,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::{sync::mpsc, thread};

        if cfg!(debug_assertions) {
            return Err("run this test alone with --release --ignored --exact".into());
        }
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        println!(
            "MEMORY_QUOTA tenants={tenants} logical_bytes={} tenant_bytes={}",
            store
                .storage
                .logical_max_bytes
                .ok_or("configured logical limit")?,
            store
                .storage
                .tenant_max_bytes
                .ok_or("configured tenant limit")?
        );
        store.writer()?.get()?.execute_batch(
            "SET logging_storage = 'stdout';
             SET logging_level = 'debug';
             SET logging_mode = 'ENABLE_SELECTED';
             SET enabled_log_types = 'Checkpoint';
             SET enable_logging = true;",
        )?;
        let identities: Vec<_> = (1..=tenants)
            .map(|tenant| EvidenceIntakeIdentityV1 {
                tenant_id: [tenant; 16],
                node_id: format!("node-{tenant}"),
                ..crate::analysis::tests::identity()
            })
            .collect();
        let expected_limit = if tenants == 1 {
            "tenant logical bytes"
        } else {
            "global logical bytes"
        };
        let native = |store: &AnalysisStore| -> std::result::Result<
            Vec<(String, u64)>,
            Box<dyn std::error::Error>,
        > {
            let reader = store.reader()?;
            let mut query = reader.get()?.prepare(
                "SELECT tag, memory_usage_bytes FROM duckdb_memory() WHERE memory_usage_bytes > 0 ORDER BY tag",
            )?;
            let values = query
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)))?
                .collect::<duckdb::Result<Vec<_>>>()?;
            Ok(values)
        };
        let memory =
            |store: &AnalysisStore| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let status = fs::read_to_string("/proc/self/status")?;
                let peak: u64 = status
                    .lines()
                    .find(|line| line.starts_with("VmHWM:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .ok_or("the process memory peak is absent")?
                    .parse()?;
                if peak > 512 * 1024 {
                    let native = native(store)?;
                    let cursors = identities
                        .iter()
                        .map(|identity| {
                            store.source_receipt(identity).map(|receipt| {
                                receipt.map_or(0, |receipt| receipt.contiguous_cursor)
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    return Err(format!("process peak {peak} KiB exceeds 512 MiB at cursors {cursors:?}; native bytes: {native:?}").into());
                }
                Ok(())
            };
        let cursors = thread::scope(
            |scope| -> std::result::Result<Vec<u64>, Box<dyn std::error::Error>> {
                let workers: Vec<_> =
                    (0..4)
                        .map(|_| {
                            let (send, requests) =
                                mpsc::sync_channel::<(usize, ValidatedEvidenceBatchV1)>(1);
                            let (reply, receive) = mpsc::sync_channel(1);
                            let store = &store;
                            let identities = &identities;
                            scope.spawn(move || {
                                for (tenant, batch) in requests {
                                    if reply
                                        .send(store.accept_validated_batch(
                                            identities[tenant].clone(),
                                            batch,
                                        ))
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            });
                            (send, receive)
                        })
                        .collect();
                let mut cursors = vec![0_u64; identities.len()];
                let mut sample = None;
                let limit = if tenants == 1 {
                    store
                        .storage
                        .tenant_max_bytes
                        .ok_or("configured tenant limit")?
                } else {
                    store
                        .storage
                        .logical_max_bytes
                        .ok_or("configured logical limit")?
                };
                let allowance = limit - limit / 4;
                let frame_bytes = 128 * 1024;
                let batch_limit = allowance
                    .checked_div(frame_bytes as u64)
                    .and_then(|count| count.checked_add(2))
                    .ok_or("the quota batch bound overflows")?;
                for group in 0..batch_limit {
                    if group % 64 == 0 {
                        sample = Some((group, native(&store)?, store.storage_usage()?));
                    }
                    let tenant = group as usize % identities.len();
                    let accepted = cursors[tenant];
                    let mut frames = vec![0_u8; frame_bytes];
                    for index in 0..1024 {
                        let cursor = accepted + index as u64 + 1;
                        frames[index * 128..index * 128 + 8].copy_from_slice(&cursor.to_be_bytes());
                    }
                    let batch = ValidatedEvidenceBatchV1 {
                        cpu_id: 0,
                        first_cursor: accepted + 1,
                        last_cursor: accepted + 1024,
                        intake_utc_ns: 1_800_000_000_000_000_000,
                        framed_records: frames.into(),
                        frame_ends: (1..=1024).map(|index| index * 128).collect(),
                    };
                    let (send, receive) = &workers[group as usize % workers.len()];
                    let prior = store.meta()?;
                    send.send((tenant, batch))?;
                    match receive.recv()? {
                        Ok(outcome) => assert_eq!(outcome, EvidenceStoreOutcomeV1::Accepted),
                        Err(crate::Error::StorageCapacity { resource, .. })
                            if resource == expected_limit =>
                        {
                            assert_eq!(store.meta()?, prior);
                            assert_eq!(
                                store
                                    .source_receipt(&identities[tenant])?
                                    .ok_or("receipt absent")?
                                    .contiguous_cursor,
                                accepted
                            );
                            memory(&store)?;
                            return Ok(cursors);
                        }
                        Err(error) => {
                            return Err(format!(
                                "batch {group} failed; prior successful cursors {cursors:?}; last sample (batch, native bytes, storage) {sample:?}: {error:?}"
                            ).into());
                        }
                    }
                    cursors[tenant] += 1024;
                    assert_eq!(
                        store
                            .source_receipt(&identities[tenant])?
                            .ok_or("receipt absent")?
                            .contiguous_cursor,
                        cursors[tenant]
                    );
                    memory(&store)?;
                }
                Err(format!("the configured {expected_limit} limit was not reached").into())
            },
        )?;
        println!("MEMORY_CURSORS {cursors:?}");
        let receipts = identities
            .iter()
            .map(|identity| store.source_receipt(identity))
            .collect::<Result<Vec<_>>>()?;
        for (receipt, cursor) in receipts.iter().zip(&cursors) {
            assert!(*cursor > 0);
            assert_eq!(
                receipt.as_ref().ok_or("receipt absent")?.contiguous_cursor,
                *cursor
            );
        }
        store.checkpoint()?;
        memory(&store)?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        for ((identity, receipt), cursor) in identities.iter().zip(receipts).zip(cursors) {
            assert_eq!(store.source_receipt(identity)?, receipt);
            let last = store.read_page(identity, cursor)?;
            let mut expected = vec![0_u8; 128];
            expected[..8].copy_from_slice(&cursor.to_be_bytes());
            assert_eq!(last.records.len(), 1);
            assert_eq!(last.records[0].framed_record, expected);
        }
        memory(&store)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StorageUsageV1 {
    pub file_bytes: u64,
    pub allocated_bytes: u64,
    pub available_bytes: u64,
}

impl StorageUsageV1 {
    pub(super) fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self> {
        let allocated_bytes = metadata.blocks().checked_mul(512).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path,
                reason: "allocated data bytes overflow",
            }
            .build()
        })?;
        Ok(Self {
            file_bytes: metadata.len().max(allocated_bytes),
            allocated_bytes,
            available_bytes: 0,
        })
    }

    pub(super) fn add(&mut self, other: Self, path: &Path) -> Result<()> {
        let file_bytes = self.file_bytes.checked_add(other.file_bytes);
        let allocated_bytes = self.allocated_bytes.checked_add(other.allocated_bytes);
        let (Some(file_bytes), Some(allocated_bytes)) = (file_bytes, allocated_bytes) else {
            return crate::AnalysisStateSnafu {
                path,
                reason: "data file bytes overflow",
            }
            .fail();
        };
        self.file_bytes = file_bytes;
        self.allocated_bytes = allocated_bytes;
        Ok(())
    }

    pub(super) fn subtract(&mut self, other: Self, path: &Path) -> Result<()> {
        let file_bytes = self.file_bytes.checked_sub(other.file_bytes);
        let allocated_bytes = self.allocated_bytes.checked_sub(other.allocated_bytes);
        let (Some(file_bytes), Some(allocated_bytes)) = (file_bytes, allocated_bytes) else {
            return crate::AnalysisStateSnafu {
                path,
                reason: "data file bytes underflow",
            }
            .fail();
        };
        self.file_bytes = file_bytes;
        self.allocated_bytes = allocated_bytes;
        Ok(())
    }

    pub(super) fn free_bytes(root: &Path) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        volume.f_bavail.checked_mul(volume.f_frsize).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the available storage size is invalid",
            }
            .build()
        })
    }
}

impl AnalysisStore {
    pub fn storage_usage(&self) -> Result<StorageUsageV1> {
        Self::storage_at(&self.root, 0, 0)
    }

    pub(super) fn storage_with_entries(&self, entries: usize) -> Result<StorageUsageV1> {
        self.storage_with_reserve(entries, 0)
    }

    pub(super) fn storage_with_reserve(
        &self,
        entries: usize,
        diagnostics: usize,
    ) -> Result<StorageUsageV1> {
        Self::inspect_storage(&self.root, entries, diagnostics, None, self.storage)
    }

    pub(super) fn storage_at(
        root: &Path,
        entries: usize,
        diagnostics: usize,
    ) -> Result<StorageUsageV1> {
        Self::inspect_storage(root, entries, diagnostics, None, StorageLimitsV1::default())
    }

    pub(super) fn storage_for_append(
        &self,
        raw: &super::raw::RawJournal,
        entries: usize,
        diagnostics: usize,
    ) -> Result<StorageUsageV1> {
        Self::inspect_storage(&self.root, entries, diagnostics, Some(raw), self.storage)
    }

    fn inspect_storage(
        root: &Path,
        mut entries: usize,
        mut diagnostics: usize,
        raw: Option<&super::raw::RawJournal>,
        limits: StorageLimitsV1,
    ) -> Result<StorageUsageV1> {
        limits.check_entries(entries, diagnostics)?;
        let mut usage = StorageUsageV1 {
            available_bytes: StorageUsageV1::free_bytes(root)?,
            ..Default::default()
        };
        let known = raw.map(|raw| raw.storage_summary()).transpose()?.flatten();
        let segment_root = root.join("segments");
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let entry = entry.context(IoSnafu { path: &directory })?;
                let path = entry.path();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                if metadata.is_file()
                    && entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.split('.').nth(1) == Some("d"))
                {
                    diagnostics = diagnostics.checked_add(1).ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the diagnostic entry count overflows",
                        }
                        .build()
                    })?;
                } else {
                    entries = entries.checked_add(1).ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the storage entry count overflows",
                        }
                        .build()
                    })?;
                }
                if metadata.is_dir() {
                    if path == segment_root {
                        if let Some((segment_usage, evidence, diagnostic)) = known {
                            usage.add(segment_usage, root)?;
                            entries = entries.checked_add(evidence).ok_or_else(|| {
                                crate::AnalysisStateSnafu {
                                    path: root,
                                    reason: "the storage entry count overflows",
                                }
                                .build()
                            })?;
                            diagnostics = diagnostics.checked_add(diagnostic).ok_or_else(|| {
                                crate::AnalysisStateSnafu {
                                    path: root,
                                    reason: "the diagnostic entry count overflows",
                                }
                                .build()
                            })?;
                        } else {
                            pending.push(path.clone());
                        }
                    } else {
                        pending.push(path.clone());
                    }
                } else if !metadata.is_file() {
                    return Self::reject_path(root, "the data directory contains a non-file entry");
                }
                limits.check_entries(entries, diagnostics)?;
                usage.add(StorageUsageV1::from_metadata(&path, &metadata)?, root)?;
            }
        }
        Ok(usage)
    }

    pub(super) fn require_capacity(&self, maintenance: bool) -> Result<()> {
        let usage = if maintenance {
            self.storage_usage()?
        } else {
            self.storage_with_entries(0)?
        };
        self.storage.check(usage, maintenance)
    }
}
