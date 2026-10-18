use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::{AnalysisRecordV1, AnalysisStore};
#[cfg(test)]
use crate::EvidenceIntakeIdentityV1;
use crate::{AnalysisDatabaseSnafu, IoSnafu, Result};

pub(super) struct SegmentRange {
    pub(super) segment_id: u64,
    pub(super) byte_start: u64,
    pub(super) byte_end: u64,
    pub(super) first_cursor: u64,
    pub(super) reader: super::raw::RawRead,
    pub(super) scan_bytes: usize,
    pub(super) intake: u64,
}

impl SegmentRange {
    pub(super) fn read(&self, root: &Path) -> Result<Vec<AnalysisRecordV1>> {
        if self
            .byte_end
            .checked_sub(self.byte_start)
            .is_none_or(|bytes| bytes == 0 || bytes > self.scan_bytes as u64)
        {
            return AnalysisStore::reject_path(root, "the selected raw byte range is invalid");
        }
        self.reader.read(root)
    }

    #[cfg(test)]
    pub(super) fn path(root: &Path, segment_id: u64) -> PathBuf {
        fs::read_dir(root.join("segments"))
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{segment_id:016x}."))
            })
            .map_or_else(
                || {
                    root.join("segments")
                        .join(format!("{segment_id:016x}.missing"))
                },
                |entry| entry.path(),
            )
    }
}

impl AnalysisStore {
    pub(super) fn segment_directory(root: &Path) -> Result<()> {
        let path = root.join("segments");
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                File::open(root)
                    .context(IoSnafu { path: root })?
                    .sync_all()
                    .context(IoSnafu { path: root })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        }
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Self::reject_path(root, "the segment directory is not private");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn raw_ranges(
        &self,
        writer: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        limit: usize,
    ) -> Result<Vec<SegmentRange>> {
        let revision = Self::read_meta_from(writer, &self.root)?.commit_revision;
        let raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        raw.select_ranges(&identity.clone().into(), first, last, revision, None, limit)
    }

    pub(super) fn remove_segments(
        writer: &mut Connection,
        root: &Path,
        raw: &super::raw::RawJournal,
        ids: &BTreeSet<u64>,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let encoded = serde_json::to_string(ids).context(crate::JsonSnafu { path: root })?;
        let removals = writer
            .prepare(
                "SELECT s.segment_id, s.file_name, s.first_cursor, s.last_cursor, s.last_intake_utc_ns, s.committed_end FROM segments s WHERE s.segment_id IN (SELECT unnest(CAST(? AS UBIGINT[])))
                 AND s.state = 'Deleting'
                 AND NOT EXISTS (SELECT 1 FROM evidence_refs r WHERE r.segment_id = s.segment_id)
                 AND EXISTS (SELECT 1 FROM expired_ranges x WHERE x.segment_id = s.segment_id
                     AND x.stream_key = s.stream_key AND x.tenant_id = s.tenant_id)
                 ORDER BY s.segment_id",
            )
            .context(AnalysisDatabaseSnafu { operation: "prepare recorded segment removals" })?
            .query_map(params![encoded], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?, row.get::<_, u64>(5)?))
            })
            .context(AnalysisDatabaseSnafu { operation: "check recorded segment removal" })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu { operation: "decode recorded segment removals" })?;
        if removals.len() != ids.len() {
            return Self::reject_path(root, "the segment has no complete removal authorization");
        }
        let mut expiry = writer
            .prepare(
                "SELECT EXISTS(SELECT 1 FROM expired_ranges WHERE segment_id = ? AND stream_key = ?
             AND tenant_id = ? AND first_cursor <= ? AND last_cursor >= ?)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare segment expiry coverage",
            })?;
        for (id, _, first, last, intake, end) in &removals {
            if !raw.segments.contains_key(id) {
                continue;
            }
            for entry in raw.segment_entries(*id, *first, *last, *intake, *end)? {
                for span in &entry.commit.spans {
                    let expired: bool = expiry
                        .query_row(
                            params![
                                entry.reference.id,
                                entry.identity.key().as_slice(),
                                entry.identity.tenant().as_slice(),
                                span.first,
                                span.last
                            ],
                            |row| row.get(0),
                        )
                        .context(AnalysisDatabaseSnafu {
                            operation: "check segment expiry coverage",
                        })?;
                    if !expired {
                        return Self::reject_path(
                            root,
                            "the removed segment has unrecorded expiry",
                        );
                    }
                }
            }
        }
        drop(expiry);
        let current = raw.directory_current()?;
        for (_, name, _, _, _, _) in removals {
            let path = super::raw::RawJournal::file_path(root, &name)?;
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                        return Self::reject_path(
                            root,
                            "the removable segment is not a private file",
                        );
                    }
                    fs::remove_file(&path).context(IoSnafu { path: &path })?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(source).context(IoSnafu { path: &path }),
            }
            #[cfg(test)]
            Self::crash_path(root, "retention.unlinked");
        }
        let directory = root.join("segments");
        File::open(&directory)
            .context(IoSnafu { path: &directory })?
            .sync_all()
            .context(IoSnafu { path: &directory })?;
        raw.directory_changed(current)?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin segment cleanup",
        })?;
        transaction.execute(
            "DELETE FROM segments WHERE segment_id IN (SELECT unnest(CAST(? AS UBIGINT[]))) AND state = 'Deleting'",
            params![encoded],
        ).context(AnalysisDatabaseSnafu { operation: "remove expired segment metadata" })?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit segment cleanup",
        })?;
        #[cfg(test)]
        Self::crash_path(root, "retention.cleaned");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceRetentionOwner, ProcessorClassV1,
        ProcessorScopeV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
    };

    fn source() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            node_id: "segment-node".into(),
            ..crate::analysis::tests::identity()
        }
    }

    #[test]
    fn segment_batch_requires_full_expiry() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        for epoch in 1..=2 {
            store.accept_validated_batch(
                EvidenceIntakeIdentityV1 {
                    source_epoch: epoch,
                    ..source()
                },
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: epoch,
                    intake_utc_ns: 100,
                    framed_records: vec![7; epoch as usize].into(),
                    frame_ends: (1..=epoch as usize).collect(),
                },
            )?;
        }
        let mut guard = store.maintenance_writer()?;
        let writer = guard.get_mut()?;
        let raw = store.raw.lock().map_err(|_| "raw lock poisoned")?;
        let files = [raw.segment_path(1)?, raw.segment_path(2)?];
        let original = [fs::read(files[0])?, fs::read(files[1])?];
        writer.execute_batch(
            "UPDATE segments SET state = 'Deleting';
             INSERT INTO expired_ranges
             SELECT segment_id, stream_key, tenant_id, 1, 1, 1 FROM segments",
        )?;
        let charge: u64 = writer.query_row(
            &format!(
                "SELECT logical_bytes FROM ({})",
                AnalysisStore::usage_projection()
            ),
            [],
            |row| row.get(0),
        )?;
        assert!(matches!(
            AnalysisStore::remove_segments(writer, &store.root, &raw, &BTreeSet::from([1, 2])),
            Err(crate::Error::AnalysisState { reason, .. })
                if reason == "the removed segment has unrecorded expiry"
        ));
        for (file, bytes) in files.iter().zip(original) {
            assert_eq!(fs::read(file)?, bytes);
        }
        assert_eq!(
            writer.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({})",
                    AnalysisStore::usage_projection()
                ),
                [],
                |row| row.get::<_, u64>(0)
            )?,
            charge
        );
        assert_eq!(
            writer.query_row("SELECT COUNT(*) FROM segments", [], |row| row
                .get::<_, u64>(0))?,
            2
        );
        Ok(())
    }

    #[test]
    fn segment_recovery_checks_ownership() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = source();
        assert_eq!(store.meta()?.commit_revision, 0);
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let live = SegmentRange::path(&root, 1);
        let length = fs::metadata(&live)?.len();
        let mut tail = fs::OpenOptions::new().append(true).open(&live)?;
        tail.write_all(&[0, 0])?;
        tail.sync_all()?;
        drop(tail);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(fs::metadata(&live)?.len(), length);
        assert_eq!(
            store.read_page(&identity, 1)?.records[0].framed_record,
            b"frame"
        );
        drop(store);
        let unknown = root.join("segments/ffffffffffffffff.seg");
        fs::write(&unknown, b"unknown")?;
        assert!(AnalysisStore::open(&root).is_err());
        assert_eq!(fs::read(&unknown)?, b"unknown");
        assert_eq!(fs::metadata(&live)?.len(), length);
        Ok(())
    }

    #[test]
    fn segment_recovery_rejects_corruption() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        for fault in ["missing", "short", "header", "changed"] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open(&root)?;
            store.accept_validated_batch(
                source(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 100,
                    framed_records: b"frame".to_vec().into(),
                    frame_ends: vec![5],
                },
            )?;
            store.checkpoint()?;
            drop(store);
            let file = SegmentRange::path(&root, 1);
            let mut bytes = fs::read(&file)?;
            match fault {
                "missing" => fs::rename(&file, directory.path().join("saved"))?,
                "short" => {
                    bytes.pop();
                    fs::write(&file, &bytes)?;
                }
                "header" => {
                    bytes[0] ^= 1;
                    fs::write(&file, &bytes)?;
                }
                "changed" => {
                    *bytes.last_mut().ok_or("segment is empty")? ^= 1;
                    fs::write(&file, &bytes)?;
                }
                _ => return Err("unknown fault".into()),
            }
            for _ in 0..2 {
                assert!(AnalysisStore::open(&root).is_err(), "{fault}");
                if fault == "missing" {
                    assert!(!file.exists());
                    assert_eq!(fs::read(directory.path().join("saved"))?, bytes);
                } else {
                    assert_eq!(fs::read(&file)?, bytes, "{fault}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn segment_retention_keeps_witnesses() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(100),
            raw_max_bytes: Some(64 * 1024 * 1024),
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let identity = source();
        for group in 0..4_u64 {
            store.accept_validated_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: group * 1024 + 1,
                    last_cursor: (group + 1) * 1024,
                    intake_utc_ns: 100,
                    framed_records: vec![group as u8; 4 * 1024 * 1024].into(),
                    frame_ends: (1..=1024).map(|index| index * 4096).collect(),
                },
            )?;
        }
        let scope = ProcessorScopeV1 {
            processor_id: "witness".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 4096,
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            ..crate::analysis::tests::result(scope, "pin-first-segment".into())
        })?;
        let retention = EvidenceRetentionOwner::new(&store);
        let removed = retention.retain(&identity, 201)?;
        assert_eq!(removed.removed_records, 1024);
        assert_eq!(removed.retained_floor, 0);
        assert_eq!(
            store.read_page(&identity, 1)?.records[0].framed_record,
            vec![0; 4096]
        );
        assert!(matches!(
            store.read_page(&identity, 3073),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(fs::read_dir(root.join("segments"))?.count(), 1);
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let removed = EvidenceRetentionOwner::new(&store).retain(&identity, 301)?;
        assert_eq!(removed.removed_records, 3072);
        assert_eq!(removed.retained_floor, 4096);
        assert_eq!(removed.retained_bytes, 0);
        assert_eq!(fs::read_dir(root.join("segments"))?.count(), 0);
        drop(store);
        AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        Ok(())
    }

    #[test]
    fn segment_growth_keeps_budget() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let identity = source();
        let mut store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            crate::StorageLimitsV1::default(),
        )?;
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let pinned_bytes = fs::metadata(SegmentRange::path(&store.root, 1))?.len();
        store.storage.witness_max_bytes = Some(pinned_bytes);
        let scope = ProcessorScopeV1 {
            processor_id: "witness".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            ..crate::analysis::tests::result(scope, "pin".into())
        })?;
        let before = store.meta()?;
        let next = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 2,
            last_cursor: 2,
            intake_utc_ns: 102,
            framed_records: b"x".to_vec().into(),
            frame_ends: vec![1],
        };
        assert!(matches!(
            store.accept_validated_batch(identity.clone(), next.clone()),
            Err(crate::Error::StorageCapacity {
                resource: "tenant witness bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert_eq!(
            fs::metadata(SegmentRange::path(&store.root, 1))?.len(),
            pinned_bytes
        );
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                intake_utc_ns: 301,
                ..next
            },
        )?;
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        Ok(())
    }
}
