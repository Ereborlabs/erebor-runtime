use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use duckdb::{params, Connection, OptionalExt as _};
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
        })
    }
}

impl SegmentRange {
    pub(super) fn read(&self, root: &Path) -> Result<Vec<AnalysisRecordV1>> {
        let path = Self::path(root, self.segment_id);
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

    pub(super) fn path(root: &Path, segment_id: u64) -> PathBuf {
        root.join("segments").join(format!("{segment_id:016x}.seg"))
    }
}

pub(super) struct SegmentAppend {
    pub(super) segment_id: u64,
    pub(super) byte_start: u64,
    pub(super) reserved: bool,
}

pub(super) struct PendingBatch {
    pub(super) bytes: Vec<u8>,
    pub(super) records: u32,
    ranges: Vec<PendingRange>,
}

struct PendingRange {
    first_cursor: u64,
    last_cursor: u64,
    byte_start: usize,
    byte_end: usize,
    frame_ends: Vec<usize>,
    ordinal: u32,
}

impl PendingBatch {
    pub(super) fn insert(
        &self,
        writer: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        append: &SegmentAppend,
        revision: u64,
        intake: u64,
    ) -> Result<()> {
        for range in &self.ranges {
            let ends = serde_json::to_string(&range.frame_ends).context(JsonSnafu {
                path: Path::new("<batch-frame-offsets>"),
            })?;
            let mut digest = Sha256::new();
            digest.update((range.frame_ends.len() as u64).to_be_bytes());
            for end in &range.frame_ends {
                digest.update((*end as u64).to_be_bytes());
            }
            digest.update(&self.bytes[range.byte_start..range.byte_end]);
            writer
                .execute(
                "INSERT INTO batch_ranges VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS UINTEGER[]), ?, ?, ?, ?)",
                    params![
                        append.segment_id,
                        source_key(identity).as_slice(),
                        identity.tenant_id.as_slice(),
                        append.byte_start + range.byte_start as u64,
                        append.byte_start + range.byte_end as u64,
                        range.first_cursor,
                        range.last_cursor,
                        ends,
                        digest.finalize().as_slice(),
                        revision,
                        range.ordinal,
                        intake,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert committed batch range",
                })?;
        }
        writer
            .execute(
                "UPDATE segments SET state = 'Live', committed_end = ? WHERE segment_id = ?",
                params![
                    append.byte_start + self.bytes.len() as u64,
                    append.segment_id
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "publish committed segment end",
            })?;
        Ok(())
    }
}

impl AnalysisStore {
    pub(super) fn prepare_batch(
        &self,
        writer: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        batch: &super::ValidatedEvidenceBatchV1,
        contiguous: u64,
    ) -> Result<PendingBatch> {
        let mut retained = vec![false; batch.frame_ends.len()];
        let ranges = Self::raw_ranges(
            writer,
            identity,
            batch.first_cursor,
            batch.last_cursor,
            crate::MAX_EVIDENCE_BATCH_RECORDS + 1,
        )?;
        if ranges.len() > crate::MAX_EVIDENCE_BATCH_RECORDS {
            return self.reject("the retained batch catalog overlaps");
        }
        for range in ranges {
            for record in range.read(&self.root)? {
                if record.cursor < batch.first_cursor || record.cursor > batch.last_cursor {
                    continue;
                }
                let index = (record.cursor - batch.first_cursor) as usize;
                let start = if index == 0 {
                    0
                } else {
                    batch.frame_ends[index - 1]
                };
                if record.framed_record != batch.framed_records[start..batch.frame_ends[index]] {
                    return self.reject("an evidence retry has conflicting record content");
                }
                if std::mem::replace(&mut retained[index], true) {
                    return self.reject("the retained batch catalog overlaps");
                }
            }
        }
        let mut pending = PendingBatch {
            bytes: Vec::new(),
            records: 0,
            ranges: Vec::new(),
        };
        let mut start = 0;
        for (index, end) in batch.frame_ends.iter().copied().enumerate() {
            let cursor = batch.first_cursor + index as u64;
            if !retained[index] {
                if cursor <= contiguous {
                    return self.reject("an acknowledged evidence record is not retained");
                }
                if pending
                    .ranges
                    .last()
                    .is_none_or(|range| range.last_cursor.checked_add(1) != Some(cursor))
                {
                    pending.ranges.push(PendingRange {
                        first_cursor: cursor,
                        last_cursor: cursor,
                        byte_start: pending.bytes.len(),
                        byte_end: pending.bytes.len(),
                        frame_ends: Vec::new(),
                        ordinal: pending.records,
                    });
                }
                pending
                    .bytes
                    .extend_from_slice(&batch.framed_records[start..end]);
                let range = pending
                    .ranges
                    .last_mut()
                    .ok_or_else(|| self.state_error("the prepared batch range is absent"))?;
                range.last_cursor = cursor;
                range.byte_end = pending.bytes.len();
                range.frame_ends.push(range.byte_end - range.byte_start);
                pending.records += 1;
            }
            start = end;
        }
        Ok(pending)
    }

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

    pub(super) fn reserve_segment(
        &self,
        writer: &mut Connection,
        identity: &EvidenceIntakeIdentityV1,
        cpu_id: u32,
        bytes: usize,
    ) -> Result<SegmentAppend> {
        let key = source_key(identity);
        let active: Option<(u64, u64)> = writer
            .query_row(
                "SELECT segment_id, committed_end FROM segments
                 WHERE stream_key = ? AND tenant_id = ? AND state = 'Live' AND NOT sealed
                 ORDER BY segment_id DESC LIMIT 1",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read active segment",
            })?;
        if let Some((segment_id, byte_start)) = active.filter(|(_, end)| {
            end.checked_add(bytes as u64)
                .is_some_and(|end| end <= super::MAX_EVIDENCE_SEGMENT_BYTES as u64)
        }) {
            return Ok(SegmentAppend {
                segment_id,
                byte_start,
                reserved: false,
            });
        }
        self.storage_with_entries(1)?;
        let header = SegmentFile::encode_identity(identity)?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin segment reservation",
        })?;
        let segment_id: u64 = transaction
            .query_row("SELECT next_segment_id FROM store_meta", [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read next segment identity",
            })?;
        let next_id = segment_id
            .checked_add(1)
            .ok_or_else(|| self.state_error("the segment identity is exhausted"))?;
        transaction
            .execute(
                "UPDATE store_meta SET next_segment_id = ?",
                params![next_id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "reserve segment identity",
            })?;
        transaction
            .execute(
                "UPDATE segments SET sealed = true
                 WHERE stream_key = ? AND tenant_id = ? AND state = 'Live' AND NOT sealed",
                params![key.as_slice(), identity.tenant_id.as_slice()],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "seal previous segment",
            })?;
        let identity_json =
            serde_json::to_string(identity).context(JsonSnafu { path: &self.root })?;
        transaction
            .execute(
                "INSERT INTO segments VALUES (?, ?, ?, ?, ?, 'records', 'Reserved', false, ?)",
                params![
                    segment_id,
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    identity_json,
                    cpu_id,
                    header.len() as u64,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert reserved segment",
            })?;
        // No file is created until its non-reusable identity is durable.
        self.commit_metadata(transaction, "commit segment reservation")?;
        #[cfg(test)]
        self.crash_at("segment.reserved");
        Ok(SegmentAppend {
            segment_id,
            byte_start: header.len() as u64,
            reserved: true,
        })
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
                        b.frame_ends::VARCHAR, b.content_sha256, b.commit_revision, b.ordinal, s.committed_end
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

    pub(super) fn sync_append(
        &self,
        append: &SegmentAppend,
        identity: &EvidenceIntakeIdentityV1,
        bytes: &[u8],
    ) -> Result<()> {
        let path = SegmentRange::path(&self.root, append.segment_id);
        let file = if append.reserved {
            SegmentFile::create(&path, &SegmentFile::encode_identity(identity)?)?
        } else {
            SegmentFile::open(&path)?
        };
        file.append(append.byte_start, bytes)?;
        #[cfg(test)]
        self.crash_at("segment.appended");
        file.sync()?;
        if append.reserved {
            let directory = self.root.join("segments");
            File::open(&directory)
                .context(IoSnafu { path: &directory })?
                .sync_all()
                .context(IoSnafu { path: &directory })?;
        }
        #[cfg(test)]
        self.crash_at("segment.synced");
        Ok(())
    }

    pub(super) fn recover_segments(writer: &mut Connection, root: &Path) -> Result<()> {
        let directory = root.join("segments");
        let metadata = fs::symlink_metadata(&directory).context(IoSnafu { path: &directory })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Self::reject_path(root, "the segment directory is not private");
        }
        for (count, entry) in fs::read_dir(&directory)
            .context(IoSnafu { path: &directory })?
            .enumerate()
        {
            if count >= 4096 {
                return Self::reject_path(root, "the segment directory exceeds its entry bound");
            }
            let entry = entry.context(IoSnafu { path: &directory })?;
            let name = entry.file_name();
            let segment_id = name.to_str().and_then(|name| {
                name.strip_suffix(".seg")
                    .filter(|stem| stem.len() == 16)
                    .and_then(|stem| u64::from_str_radix(stem, 16).ok())
            });
            let Some(segment_id) = segment_id else {
                return Self::reject_path(root, "the segment directory contains an unknown file");
            };
            let known: bool = writer
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM segments WHERE segment_id = ?)",
                    params![segment_id],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check owned segment file",
                })?;
            if !known || entry.path() != SegmentRange::path(root, segment_id) {
                return Self::reject_path(root, "the segment file has no catalog owner");
            }
            SegmentFile::reader(&entry.path())?;
        }
        let mut after = 0;
        loop {
            let rows = {
                let mut statement = writer
                    .prepare(
                        "SELECT segment_id, identity_json, state, committed_end, stream_key, tenant_id
                         FROM segments WHERE segment_id > ? ORDER BY segment_id LIMIT 128",
                    )
                    .context(AnalysisDatabaseSnafu { operation: "prepare segment recovery" })?;
                statement
                    .query_map(params![after], |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    })
                    .context(AnalysisDatabaseSnafu {
                        operation: "read segment recovery page",
                    })?
                    .collect::<duckdb::Result<Vec<_>>>()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode segment recovery page",
                    })?
            };
            if rows.is_empty() {
                break;
            }
            for (segment_id, json, state, committed_end, key, tenant) in rows {
                let path = SegmentRange::path(root, segment_id);
                let identity: EvidenceIntakeIdentityV1 =
                    serde_json::from_str(&json).context(JsonSnafu { path: &path })?;
                if !super::valid_source_identity(&identity)
                    || source_key(&identity).as_slice() != key
                    || identity.tenant_id.as_slice() != tenant
                {
                    return Self::reject_path(root, "the segment source identity is invalid");
                }
                match state.as_str() {
                    "Live" => {
                        let header = SegmentFile::encode_identity(&identity)?;
                        let file = SegmentFile::open(&path)?;
                        if committed_end < header.len() as u64
                            || committed_end > file.length()?
                            || file.read(0, header.len())? != header
                        {
                            return Self::reject_path(
                                root,
                                "the committed segment header or end is invalid",
                            );
                        }
                        Self::validate_segment(
                            writer,
                            root,
                            segment_id,
                            header.len() as u64,
                            committed_end,
                        )?;
                        if file.length()? > committed_end {
                            file.discard_tail(committed_end)?;
                        }
                    }
                    "Reserved" | "Deleting" => {
                        Self::remove_segment(writer, root, segment_id, &state)?
                    }
                    _ => return Self::reject_path(root, "the segment state is invalid"),
                }
                after = segment_id;
            }
        }
        Ok(())
    }

    fn validate_segment(
        writer: &Connection,
        root: &Path,
        segment_id: u64,
        mut offset: u64,
        committed_end: u64,
    ) -> Result<()> {
        loop {
            let ranges = {
                let mut statement = writer
                    .prepare(
                        "SELECT segment_id, byte_start, byte_end, first_cursor, last_cursor,
                            frame_ends::VARCHAR, content_sha256, commit_revision, ordinal, ? AS committed_end
                     FROM batch_ranges WHERE segment_id = ? AND byte_start >= ?
                     ORDER BY byte_start LIMIT 128",
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare segment batch validation",
                    })?;
                statement
                    .query_map(params![committed_end, segment_id, offset], |row| {
                        SegmentRange::try_from(row)
                    })
                    .context(AnalysisDatabaseSnafu {
                        operation: "read segment validation page",
                    })?
                    .collect::<duckdb::Result<Vec<_>>>()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode segment validation page",
                    })?
            };
            if ranges.is_empty() {
                break;
            }
            for range in ranges {
                if range.byte_start != offset || range.byte_end > committed_end {
                    return Self::reject_path(
                        root,
                        "the segment has an invalid committed byte range",
                    );
                }
                let records = range.read(root)?;
                let mut statement = writer.prepare(
                    "SELECT r.durable_cursor, r.frame_sha256 FROM evidence_refs r
                     JOIN batch_ranges b ON r.tenant_id = b.tenant_id AND r.stream_key = b.stream_key
                     WHERE b.segment_id = ? AND b.byte_start = ?
                        AND r.durable_cursor BETWEEN b.first_cursor AND b.last_cursor",
                ).context(AnalysisDatabaseSnafu { operation: "prepare witness digest validation" })?;
                let mut rows = statement
                    .query(params![segment_id, range.byte_start])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read retained witness digests",
                    })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "read retained witness digest",
                })? {
                    let cursor: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                        operation: "decode witness cursor",
                    })?;
                    let digest: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                        operation: "decode witness digest",
                    })?;
                    let record = records
                        .get((cursor - range.first_cursor) as usize)
                        .ok_or_else(|| {
                            crate::AnalysisStateSnafu {
                                path: root,
                                reason: "the witness cursor is outside its batch",
                            }
                            .build()
                        })?;
                    if Sha256::digest(&record.framed_record).as_slice() != digest {
                        return Self::reject_path(root, "the retained witness digest is invalid");
                    }
                }
                offset = range.byte_end;
            }
        }
        if offset != committed_end {
            return Self::reject_path(root, "the committed segment end has no batch range");
        }
        Ok(())
    }

    pub(super) fn remove_segment(
        writer: &mut Connection,
        root: &Path,
        segment_id: u64,
        state: &str,
    ) -> Result<()> {
        let removable: bool = writer.query_row(
            "SELECT EXISTS(SELECT 1 FROM segments s WHERE s.segment_id = ? AND s.state = ?
                AND ((s.state = 'Reserved' AND NOT EXISTS (
                    SELECT 1 FROM batch_ranges b WHERE b.segment_id = s.segment_id))
                OR (s.state = 'Deleting' AND NOT EXISTS (
                    SELECT 1 FROM batch_ranges b WHERE b.segment_id = s.segment_id
                        AND (NOT EXISTS (SELECT 1 FROM expired_ranges x
                            WHERE x.stream_key = b.stream_key AND x.tenant_id = b.tenant_id
                                AND x.first_cursor <= b.first_cursor AND x.last_cursor >= b.last_cursor)
                        OR EXISTS (SELECT 1 FROM evidence_refs r WHERE r.stream_key = b.stream_key
                            AND r.tenant_id = b.tenant_id AND r.durable_cursor
                                BETWEEN b.first_cursor AND b.last_cursor))))))",
            params![segment_id, state], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check recorded segment removal" })?;
        if !removable {
            return Self::reject_path(root, "the segment has no complete removal authorization");
        }
        let path = SegmentRange::path(root, segment_id);
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
        let reserved = {
            let mut writer = store.writer()?;
            store.reserve_segment(writer.get_mut()?, &identity, 0, 5)?
        };
        let path = SegmentRange::path(&root, reserved.segment_id);
        SegmentFile::create(&path, b"torn")?.sync()?;
        assert_eq!(store.meta()?.commit_revision, 0);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert!(!path.exists());
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
        let live = SegmentRange::path(&root, reserved.segment_id + 1);
        let length = fs::metadata(&live)?.len();
        let mut tail = fs::OpenOptions::new().append(true).open(&live)?;
        tail.write_all(b"uncommitted")?;
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
        let pinned_bytes = SegmentFile::encode_identity(&identity)?.len() as u64 + 5;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            crate::StorageLimitsV1 {
                witness_max_bytes: pinned_bytes,
                ..Default::default()
            },
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
