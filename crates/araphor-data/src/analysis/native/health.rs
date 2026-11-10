use std::sync::atomic::Ordering;

use snafu::ResultExt as _;

use super::NativeStore;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result, StorageHealthV1, StorageLimitsV1};

impl NativeStore {
    pub fn storage_usage(&self) -> Result<crate::StorageUsageV1> {
        self.check()?;
        crate::StorageUsageV1::at(&self.root, 0, 0)
    }

    pub fn retention_healthy(&self) -> bool {
        self.retention_healthy.load(Ordering::Acquire)
    }

    pub fn storage_limits(&self) -> &StorageLimitsV1 {
        &self.storage
    }

    pub fn storage_health(&self) -> Result<StorageHealthV1> {
        let usage = crate::StorageUsageV1::at(&self.root, 0, 0)?;
        let view = self.published.read().map_err(|_| {
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })?;
        let first = Self::required(&view.snapshot, &Self::cut(0))?;
        let first = fjall::Revision::from_bytes(first.as_slice().try_into().map_err(|_| {
            NativeStateSnafu {
                field: "initial cut width",
            }
            .build()
        })?);
        let retained = self
            .database
            .history()
            .context(NativeStorageSnafu {
                operation: "read health history protection",
            })?
            .iter()
            .any(|policy| {
                policy.branch == self.branch.id()
                    && policy.first <= first
                    && policy.last.to_bytes() == u64::MAX.to_be_bytes()
            });
        let limits = self.storage_limits();
        Ok(StorageHealthV1 {
            write_ready: self.ready.load(Ordering::Acquire),
            retention_healthy: retained && self.retention_healthy.load(Ordering::Acquire),
            intake_capacity: limits.check(usage, false).is_ok(),
            maintenance_capacity: limits.check(usage, true).is_ok(),
            usage,
        })
    }
}
