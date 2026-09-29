use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use duckdb::{params, Connection};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{source_key, AnalysisRecordV1, AnalysisStore, SegmentFile, StorePositionV1};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, IoSnafu, JsonSnafu, Result};

pub(super) struct SegmentRange {
    pub(super) segment_id: u64,
    pub(super) byte_start: u64,
    pub(super) byte_end: u64,
    pub(super) first_cursor: u64,
    pub(super) last_cursor: u64,
    pub(super) frame_ends: String,
    pub(super) content_sha256: Vec<u8>,
    pub(super) commit_revision: u64,
    pub(super) ordinal: u32,
    committed_end: u64,
    pub(super) file_name: String,
}

impl TryFrom<&duckdb::Row<'_>> for SegmentRange {
    type Error = duckdb::Error;

    fn try_from(row: &duckdb::Row<'_>) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            segment_id: row.get(0)?,
            byte_start: row.get(1)?,
            byte_end: row.get(2)?,
            first_cursor: row.get(3)?,
            last_cursor: row.get(4)?,
            frame_ends: row.get(5)?,
            content_sha256: row.get(6)?,
            commit_revision: row.get(7)?,
            ordinal: row.get(8)?,
            committed_end: row.get(9)?,
            file_name: row.get(10)?,
        })
    }
}

impl SegmentRange {
    pub(super) fn read(&self, root: &Path) -> Result<Vec<AnalysisRecordV1>> {
        if !self
            .file_name
            .starts_with(&format!("{:016x}.", self.segment_id))
        {
            return AnalysisStore::reject_path(
                root,
                "the segment file name differs from its identity",
            );
        }
        let path = super::raw::RawJournal::file_path(root, &self.file_name)?;
        let length = self.byte_end.checked_sub(self.byte_start);
        let count = self
            .last_cursor
            .checked_sub(self.first_cursor)
            .and_then(|count| count.checked_add(1));
        if self.first_cursor == 0
            || self.commit_revision == 0
            || self.byte_end > self.committed_end
            || length.is_none_or(|size| {
                size == 0 || size > crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES as u64
            })
            || count.is_none_or(|count| count > crate::MAX_EVIDENCE_BATCH_RECORDS as u64)
            || self.frame_ends.len() > crate::MAX_EVIDENCE_BATCH_RECORDS * 16
        {
            return AnalysisStore::reject_path(root, "the committed batch bounds are invalid");
        }
        let bytes =
            SegmentFile::reader(&path)?.read(self.byte_start, length.unwrap_or(0) as usize)?;
        let ends: Vec<usize> =
            serde_json::from_str(&self.frame_ends).context(JsonSnafu { path: &path })?;
        let mut digest = Sha256::new();
        digest.update((ends.len() as u64).to_be_bytes());
        for end in &ends {
            digest.update((*end as u64).to_be_bytes());
        }
        digest.update(&bytes);
        if digest.finalize().as_slice() != self.content_sha256 {
            return AnalysisStore::reject_path(root, "the committed batch digest is invalid");
        }
        if Some(ends.len() as u64) != count || ends.last() != Some(&bytes.len()) {
            return AnalysisStore::reject_path(root, "the committed frame count or end is invalid");
        }
        let mut records = Vec::with_capacity(ends.len());
        let mut start = 0;
        for (index, end) in ends.into_iter().enumerate() {
            if end <= start || end > bytes.len() {
                return AnalysisStore::reject_path(root, "the committed frame offsets are invalid");
            }
            let ordinal = self.ordinal.checked_add(index as u32).ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the committed ordinal is exhausted",
                }
                .build()
            })?;
            records.push(AnalysisRecordV1 {
                cursor: self.first_cursor + index as u64,
                framed_record: bytes[start..end].to_vec(),
                position: StorePositionV1 {
                    commit_revision: self.commit_revision,
                    ordinal,
                },
            });
            start = end;
        }
        Ok(records)
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

    pub(super) fn raw_ranges(
        writer: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        limit: usize,
    ) -> Result<Vec<SegmentRange>> {
        let mut statement = writer
            .prepare(
                "SELECT b.segment_id, b.byte_start, b.byte_end, b.first_cursor, b.last_cursor,
                        b.frame_ends::VARCHAR, b.content_sha256, b.commit_revision, b.ordinal, s.committed_end, s.file_name
                 FROM batch_ranges b JOIN segments s USING (segment_id)
                 WHERE b.stream_key = ? AND b.tenant_id = ? AND s.state = 'Live'
                   AND b.first_cursor <= ? AND b.last_cursor >= ?
                 ORDER BY b.first_cursor LIMIT ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare committed batch ranges",
            })?;
        statement
            .query_map(
                params![
                    source_key(identity).as_slice(),
                    identity.tenant_id.as_slice(),
                    last,
                    first,
                    limit as u64
                ],
                |row| SegmentRange::try_from(row),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read committed batch ranges",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode committed batch ranges",
            })
    }

    pub(super) fn remove_segment(
        writer: &mut Connection,
        root: &Path,
        segment_id: u64,
        state: &str,
    ) -> Result<()> {
        let removable: bool = writer.query_row(
            "SELECT EXISTS(SELECT 1 FROM segments s WHERE s.segment_id = ? AND s.state = ?
                AND s.state = 'Deleting' AND NOT EXISTS (
                    SELECT 1 FROM batch_ranges b WHERE b.segment_id = s.segment_id
                        AND (NOT EXISTS (SELECT 1 FROM expired_ranges x
                            WHERE x.stream_key = b.stream_key AND x.tenant_id = b.tenant_id
                                AND x.first_cursor <= b.first_cursor AND x.last_cursor >= b.last_cursor)
                        OR EXISTS (SELECT 1 FROM evidence_refs r WHERE r.stream_key = b.stream_key
                            AND r.tenant_id = b.tenant_id AND r.durable_cursor
                                BETWEEN b.first_cursor AND b.last_cursor))))",
            params![segment_id, state], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check recorded segment removal" })?;
        if !removable {
            return Self::reject_path(root, "the segment has no complete removal authorization");
        }
        let path = super::raw::RawJournal::catalog_path(writer, root, segment_id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return Self::reject_path(root, "the removable segment is not a private file");
                }
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        }
        #[cfg(test)]
        Self::crash_path(root, "retention.unlinked");
        let directory = root.join("segments");
        File::open(&directory)
            .context(IoSnafu { path: &directory })?
            .sync_all()
            .context(IoSnafu { path: &directory })?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin segment cleanup",
        })?;
        let (tenant, bytes): (Vec<u8>, i64) = transaction
            .query_row(
                "SELECT tenant_id, (256 + committed_end + octet_length(encode(identity_json))
                + COALESCE((SELECT SUM(256 + 4 * (last_cursor::HUGEINT - first_cursor + 1))
                    FROM batch_ranges WHERE segment_id = ?), 0))::BIGINT
                FROM segments WHERE segment_id = ? AND state = ?",
                params![segment_id, segment_id, state],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read removed segment charge",
            })?;
        transaction
            .execute(
                "DELETE FROM batch_ranges WHERE segment_id = ?",
                params![segment_id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "remove expired batch metadata",
            })?;
        transaction
            .execute(
                "DELETE FROM segments WHERE segment_id = ? AND state = ?",
                params![segment_id, state],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "remove expired segment metadata",
            })?;
        super::quota::UsageChange::from(-bytes).apply(&transaction, &tenant)?;
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
            tenant_id: [1; 16],
            node_id: "segment-node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
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
            raw_max_age_ns: 100,
            raw_max_bytes: 64 * 1024 * 1024,
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
            scope,
            expected_cursor: 0,
            consumed_cursor: 4096,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "pin-first-segment".into(),
            body: b"finding".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            context_refs: vec![],
        })?;
        let retention = EvidenceRetentionOwner::new(&store, limits)?;
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
        let removed = EvidenceRetentionOwner::new(&store, limits)?.retain(&identity, 301)?;
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
        store.storage.witness_max_bytes = pinned_bytes;
        let scope = ProcessorScopeV1 {
            processor_id: "witness".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "pin".into(),
            body: b"finding".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            context_refs: vec![],
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
