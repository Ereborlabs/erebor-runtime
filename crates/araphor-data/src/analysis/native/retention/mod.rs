use std::sync::atomic::Ordering;

use super::{DataWrite, NativeStore};
use crate::{NativeStateSnafu, Result, RetentionStepV1};

mod expiry;
mod selection;
mod write;
pub(in crate::analysis::native) use expiry::ExpiredSegment;

pub struct EvidenceRetentionOwner<'a> {
    store: &'a NativeStore,
}

impl<'a> EvidenceRetentionOwner<'a> {
    pub fn new(store: &'a NativeStore) -> Self {
        Self { store }
    }

    pub fn enabled(&self) -> bool {
        self.store.retention.raw_max_age_ns.is_some()
            || self.store.retention.raw_max_bytes.is_some()
    }

    pub fn step(&self, now: u64) -> Result<RetentionStepV1> {
        self.run(now, None)
    }

    fn run(
        &self,
        now: u64,
        source: Option<&crate::analysis::raw::RawIdentity>,
    ) -> Result<RetentionStepV1> {
        if now == 0 {
            return crate::Error::reject_path(&self.store.root, "the retention time is invalid");
        }
        if !self.enabled() {
            return Ok(RetentionStepV1 {
                removed_records: 0,
                more: false,
                next_deadline_utc_ns: None,
                read_revision: self.store.view()?.revision,
            });
        }
        let result = self.run_batch(now, source);
        let healthy = result.is_ok();
        if self.store.retention_healthy.swap(healthy, Ordering::AcqRel) != healthy {
            self.store.controls.send_replace(());
        }
        result
    }

    fn run_batch(
        &self,
        now: u64,
        source: Option<&crate::analysis::raw::RawIdentity>,
    ) -> Result<RetentionStepV1> {
        let mut tx = self.store.maintenance_write()?;
        let _maintenance = self.store.maintenance.write().map_err(|_| {
            NativeStateSnafu {
                field: "maintenance lock",
            }
            .build()
        })?;
        let mut raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        raw.reconcile_all(self.store.retention)?;
        let selection = self.select(&tx, &raw, now, source)?;
        let mut removed = 0u32;
        if selection.ids.is_empty() {
            return Ok(RetentionStepV1 {
                removed_records: 0,
                more: false,
                next_deadline_utc_ns: selection.deadline,
                read_revision: self.store.view()?.revision,
            });
        }
        raw.seal_all()?;
        tx.raw = raw.index.clone();
        let records = tx.expire_segments(&raw, &selection.ids, now, &mut removed)?;
        let revision = tx.revision;
        drop(raw);
        #[cfg(any(test, feature = "test-fixtures"))]
        self.store
            .run_commit_hook(crate::AnalysisCommitStage::BeforeRetentionCommit)?;
        let (_, _writer) = tx.commit_locked([], || {})?;
        let completed =
            ExpiredSegment::remove_files(&self.store.root, records.into_iter().map(Ok))?;
        let mut raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        for id in completed {
            raw.forget_segment(id)?;
            raw.budget.deletions.insert(id);
        }
        raw.directory_changed(false)?;
        drop(raw);
        Ok(RetentionStepV1 {
            removed_records: removed,
            more: selection.more,
            next_deadline_utc_ns: selection.deadline,
            read_revision: revision,
        })
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn retain(
        &self,
        identity: &crate::EvidenceIntakeIdentityV1,
        now: u64,
    ) -> Result<crate::RetentionResultV1> {
        self.retain_source(&identity.clone().into(), now)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn retain_trace(
        &self,
        identity: &crate::TraceIdentityV1,
        now: u64,
    ) -> Result<crate::RetentionResultV1> {
        self.retain_source(&identity.clone().into(), now)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn retain_source(
        &self,
        source: &crate::analysis::raw::RawIdentity,
        now: u64,
    ) -> Result<crate::RetentionResultV1> {
        if !source.valid() {
            return crate::Error::reject_path(&self.store.root, "the retention source is invalid");
        }
        let step = self.run(now, Some(source))?;
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let key = source.key();
        let receipt = raw.index.sources.get(&key).ok_or_else(|| {
            NativeStateSnafu {
                field: "retention source",
            }
            .build()
        })?;
        Ok(crate::RetentionResultV1 {
            removed_records: step.removed_records,
            retained_bytes: raw
                .segments
                .values()
                .filter(|segment| segment.source == key)
                .map(|segment| segment.end)
                .sum(),
            retained_floor: receipt.receipt.floor(),
            commit_revision: step.read_revision,
        })
    }
}

impl NativeStore {
    pub(in crate::analysis::native) fn require_retention(&self) -> Result<()> {
        if !self.retention_healthy() {
            return crate::RetentionUnavailableSnafu.fail();
        }
        Ok(())
    }
}
