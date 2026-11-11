use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use super::AnalysisRecordV1;
#[cfg(test)]
use crate::EvidenceIntakeIdentityV1;
use crate::Result;

#[derive(Clone)]
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
    pub(super) fn window(
        &self,
        after: Option<super::StorePositionV1>,
        limit: usize,
    ) -> Option<Self> {
        let mut next = self.clone();
        next.reader = self.reader.window(after, limit)?;
        next.first_cursor = next.reader.first();
        Some(next)
    }

    pub(super) fn end(&self) -> super::StorePositionV1 {
        self.reader.end()
    }

    pub(super) fn metadata_bytes(&self) -> usize {
        self.reader.metadata_bytes()
    }

    pub(super) fn read(&self, root: &Path) -> Result<(Vec<AnalysisRecordV1>, usize, usize)> {
        if self
            .byte_end
            .checked_sub(self.byte_start)
            .is_none_or(|bytes| bytes == 0 || bytes > self.scan_bytes as u64)
        {
            return crate::Error::reject_path(root, "the selected raw byte range is invalid");
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
             SELECT segment_id, stream_key, tenant_id, 1, 1, 1, 1, last_intake_utc_ns FROM segments",
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
        let store = AnalysisStore::open_with_retention(&root, limits)?;
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
        let store = AnalysisStore::open_with_retention(&root, limits)?;
        let removed = EvidenceRetentionOwner::new(&store).retain(&identity, 301)?;
        assert_eq!(removed.removed_records, 3072);
        assert_eq!(removed.retained_floor, 4096);
        assert_eq!(removed.retained_bytes, 0);
        assert_eq!(fs::read_dir(root.join("segments"))?.count(), 0);
        drop(store);
        AnalysisStore::open_with_retention(&root, limits)?;
        Ok(())
    }
}
