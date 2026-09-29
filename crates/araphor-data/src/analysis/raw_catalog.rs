use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::raw::RawJournal;
use super::{source_key, AnalysisSourceReceiptV1, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, JsonSnafu, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_recovers_partial_group() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        for cursor in 1..=65 {
            store.accept_validated_batch(
                identity.clone(),
                super::super::ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: cursor,
                    framed_records: vec![cursor as u8].into(),
                    frame_ends: vec![1],
                },
            )?;
        }
        {
            let mut guard = store.writer.lock().map_err(|_| "writer lock poisoned")?;
            let writer = guard.as_mut().ok_or("writer closed")?;
            let mut raw = store.raw.lock().map_err(|_| "raw lock poisoned")?;
            assert!(raw.project_group(writer)?);
            assert_eq!(
                AnalysisStore::read_meta_from(writer, &root)?.commit_revision,
                64
            );
            assert_eq!(
                AnalysisStore::read_receipt_from(writer, &root, &identity, &source_key(&identity))?
                    .ok_or("receipt absent")?
                    .contiguous_cursor,
                64
            );
            assert_eq!(
                raw.sources[&source_key(&identity)]
                    .receipt
                    .contiguous_cursor,
                65
            );
        }
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, 65);
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 65);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct RawBudget {
    pub usage: BTreeMap<[u8; 16], u64>,
    pub total: u64,
    pub required: BTreeMap<[u8; 32], u64>,
    pub protected: BTreeMap<[u8; 16], u64>,
    pub oldest: BTreeMap<[u8; 32], u64>,
    pub pins: BTreeMap<u64, ([u8; 16], u64)>,
    pub contexts: BTreeMap<[u8; 16], u64>,
    pub expired: BTreeMap<([u8; 32], u64), u64>,
}

impl RawJournal {
    pub(super) fn project_paths(&self, writer: &Connection) -> Result<()> {
        let names = {
            let mut statement = writer
                .prepare("SELECT segment_id, file_name FROM segments WHERE state = 'Live'")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare segment file names",
                })?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read segment file names",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode segment file names",
                })?
        };
        for (id, saved) in names {
            let path = self.segments.file_path(id)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| self.invalid("the raw segment name is invalid"))?;
            if name != saved {
                writer
                    .execute(
                        "UPDATE segments SET file_name = ?, sealed = ? WHERE segment_id = ?",
                        params![name, !name.ends_with(".open"), id],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "publish segment rotation",
                    })?;
            }
        }
        Ok(())
    }

    pub(super) fn file_path(root: &Path, name: &str) -> Result<std::path::PathBuf> {
        if Path::new(name).components().count() != 1
            || name == "."
            || name == ".."
            || name.starts_with('/')
        {
            return AnalysisStore::reject_path(root, "the catalogue segment name is invalid");
        }
        Ok(root.join("segments").join(name))
    }
}

impl AnalysisStore {
    pub(super) fn recover_segments(writer: &mut Connection, root: &Path) -> Result<RawJournal> {
        Self::segment_directory(root)?;
        let deleting = {
            let mut statement = writer
                .prepare("SELECT segment_id FROM segments WHERE state = 'Deleting'")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare raw deletion recovery",
                })?;
            statement
                .query_map([], |row| row.get::<_, u64>(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw deletion recovery",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode raw deletion recovery",
                })?
        };
        for id in deleting {
            Self::remove_segment(writer, root, id, "Deleting")?;
        }
        let committed = {
            let mut statement = writer
                .prepare("SELECT segment_id, committed_end FROM segments")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare protected raw boundaries",
                })?;
            statement
                .query_map([], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)))
                .context(AnalysisDatabaseSnafu {
                    operation: "read protected raw boundaries",
                })?
                .collect::<duckdb::Result<BTreeMap<_, _>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode protected raw boundaries",
                })?
        };
        let mut raw = RawJournal::open(root, u64::MAX, &committed)?;
        raw.restore_receipts(writer)?;
        raw.validate_catalog(writer)?;
        raw.project(writer, None)?;
        raw.project_paths(writer)?;
        Self::validate_state(writer, root)?;
        raw.refresh_budget(writer)?;
        Ok(raw)
    }
}

impl RawJournal {
    fn validate_catalog(&self, writer: &Connection) -> Result<()> {
        let revision = AnalysisStore::read_meta_from(writer, &self.root)?.commit_revision;
        {
            let mut statement = writer.prepare("SELECT segment_id, committed_end, identity_json, cpu_id, file_name FROM segments")
                .context(AnalysisDatabaseSnafu { operation: "prepare raw segment catalogue check" })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw segment catalogue check",
                })?;
            let projected: BTreeMap<u64, _> = self
                .entries
                .range(..=revision)
                .map(|(_, entry)| (entry.reference.id, entry))
                .collect();
            for row in rows {
                let (id, end, json, cpu, name) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw segment catalogue check",
                })?;
                let entry = projected
                    .get(&id)
                    .ok_or_else(|| self.invalid("a catalogued raw segment is absent"))?;
                let identity: EvidenceIntakeIdentityV1 =
                    serde_json::from_str(&json).context(JsonSnafu { path: &self.root })?;
                let path = self.segments.file_path(id)?;
                let current = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| self.invalid("the raw segment name is invalid"))?;
                let rotated = name.ends_with(".open")
                    && name.split('.').take(4).eq(current.split('.').take(4));
                if end != entry.reference.offset
                    || identity != entry.identity
                    || cpu != entry.commit.cpu
                    || (name != current && !rotated)
                {
                    return Err(
                        self.invalid("the raw segment catalogue differs from its durable file")
                    );
                }
            }
        }
        let mut statement = writer.prepare("SELECT segment_id, byte_start, byte_end, first_cursor, last_cursor, frame_ends::VARCHAR, content_sha256, commit_revision, ordinal, intake_utc_ns FROM batch_ranges")
            .context(AnalysisDatabaseSnafu { operation: "prepare raw catalogue validation" })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read raw catalogue validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read raw catalogue range",
        })? {
            let decode = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, u64>(7)?,
                    row.get::<_, u32>(8)?,
                    row.get::<_, u64>(9)?,
                ))
            })();
            let (id, start, end, first, last, ends, digest, revision, ordinal, intake) = decode
                .context(AnalysisDatabaseSnafu {
                    operation: "decode raw catalogue range",
                })?;
            let entry = self
                .entries
                .get(&revision)
                .ok_or_else(|| self.invalid("a catalogued raw commit is absent"))?;
            let index = entry
                .commit
                .spans
                .iter()
                .position(|span| span.first == first)
                .ok_or_else(|| self.invalid("a catalogued raw range is absent"))?;
            let span = &entry.commit.spans[index];
            let ends: Vec<u32> =
                serde_json::from_str(&ends).context(JsonSnafu { path: &self.root })?;
            if id != entry.reference.id
                || start != entry.body_start + u64::from(span.start)
                || end != start + u64::from(*span.ends.last().unwrap_or(&0))
                || last != span.last
                || ends != span.ends
                || digest != entry.digests[index]
                || ordinal != span.ordinal
                || intake != entry.commit.intake
            {
                return Err(self.invalid("the raw catalogue differs from its segment commit"));
            }
        }
        let count: u64 = writer
            .query_row("SELECT COUNT(*) FROM batch_ranges", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "count projected raw ranges",
            })?;
        let expected: usize = self
            .entries
            .range(..=revision)
            .map(|(_, entry)| entry.commit.spans.len())
            .sum();
        if count != expected as u64 {
            return Err(self.invalid("the raw catalogue is missing a committed range"));
        }
        {
            use sha2::{Digest as _, Sha256};
            let mut statement = writer
                .prepare(
                    "SELECT r.stream_key, r.durable_cursor, r.frame_sha256 FROM evidence_refs r",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare raw witness validation",
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw witness validation",
                })?;
            for row in rows {
                let (key, cursor, digest) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw witness validation",
                })?;
                let key: [u8; 32] = key
                    .try_into()
                    .map_err(|_| self.invalid("the raw witness key is invalid"))?;
                let (_, &(revision, index)) = self
                    .ranges
                    .range((key, 0)..=(key, cursor))
                    .next_back()
                    .ok_or_else(|| self.invalid("the raw witness range is absent"))?;
                let entry = &self.entries[&revision];
                let span = &entry.commit.spans[index];
                if cursor > span.last {
                    return Err(self.invalid("the raw witness cursor is absent"));
                }
                let offset = (cursor - span.first) as usize;
                let start = span.start as usize
                    + if offset == 0 {
                        0
                    } else {
                        span.ends[offset - 1] as usize
                    };
                let end = span.start as usize + span.ends[offset] as usize;
                let commit = self.read_entry(entry)?;
                if Sha256::digest(&commit.body[start..end]).as_slice() != digest {
                    return Err(self.invalid("the retained witness digest is invalid"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn refresh_budget(&mut self, writer: &Connection) -> Result<()> {
        self.restore_receipts(writer)?;
        let mut budget = RawBudget::default();
        {
            let mut statement = writer
                .prepare("SELECT tenant_id, logical_bytes FROM tenant_usage")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare raw quota totals",
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw quota totals",
                })?;
            for row in rows {
                let (tenant, bytes) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw quota total",
                })?;
                let tenant = tenant
                    .try_into()
                    .map_err(|_| self.invalid("the raw quota tenant is invalid"))?;
                budget.usage.insert(tenant, bytes);
                budget.total = budget
                    .total
                    .checked_add(bytes)
                    .ok_or_else(|| self.invalid("the raw quota total is exhausted"))?;
            }
        }
        {
            let mut statement = writer.prepare("SELECT stream_key, MIN(consumed_cursor)::UBIGINT FROM processor_progress WHERE class = 'required' AND NOT retired GROUP BY stream_key")
                .context(AnalysisDatabaseSnafu { operation: "prepare raw processor floors" })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw processor floors",
                })?;
            for row in rows {
                let (key, cursor) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw processor floor",
                })?;
                budget.required.insert(
                    key.try_into()
                        .map_err(|_| self.invalid("the raw processor key is invalid"))?,
                    cursor,
                );
            }
        }
        {
            let mut statement = writer.prepare("SELECT b.segment_id, b.tenant_id, MAX(r.expires_utc_ns)::UBIGINT FROM evidence_refs r JOIN batch_ranges b ON r.stream_key = b.stream_key AND r.tenant_id = b.tenant_id AND r.durable_cursor BETWEEN b.first_cursor AND b.last_cursor GROUP BY b.segment_id, b.tenant_id")
                .context(AnalysisDatabaseSnafu { operation: "prepare raw witness pins" })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw witness pins",
                })?;
            for row in rows {
                let (id, tenant, expiry) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw witness pin",
                })?;
                budget.pins.insert(
                    id,
                    (
                        tenant
                            .try_into()
                            .map_err(|_| self.invalid("the raw witness tenant is invalid"))?,
                        expiry,
                    ),
                );
            }
        }
        {
            let mut statement = writer.prepare("SELECT c.tenant_id, SUM(256 + octet_length(c.body) + octet_length(encode(c.owner_id)) + octet_length(c.entity_key) + octet_length(c.lifetime_key))::UBIGINT FROM context_versions c SEMI JOIN context_refs r USING (tenant_id, owner_id, entity_key, lifetime_key, owner_revision) GROUP BY c.tenant_id")
                .context(AnalysisDatabaseSnafu { operation: "prepare raw context charges" })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw context charges",
                })?;
            for row in rows {
                let (tenant, bytes) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw context charge",
                })?;
                budget.contexts.insert(
                    tenant
                        .try_into()
                        .map_err(|_| self.invalid("the raw context tenant is invalid"))?,
                    bytes,
                );
            }
        }
        {
            let mut statement = writer
                .prepare("SELECT stream_key, first_cursor, last_cursor FROM expired_ranges")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare raw expired ranges",
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw expired ranges",
                })?;
            for row in rows {
                let (key, first, last) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw expired range",
                })?;
                budget.expired.insert(
                    (
                        key.try_into()
                            .map_err(|_| self.invalid("the raw expiry key is invalid"))?,
                        first,
                    ),
                    last,
                );
            }
        }
        let ids: BTreeSet<u64> = {
            let mut statement = writer
                .prepare("SELECT segment_id FROM segments WHERE state = 'Live'")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare retained raw identities",
                })?;
            statement
                .query_map([], |row| row.get(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "read retained raw identities",
                })?
                .collect::<duckdb::Result<_>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode retained raw identities",
                })?
        };
        let removed: Vec<_> = self
            .segments
            .descriptors()
            .map(|entry| entry.reference.id)
            .filter(|id| !ids.contains(id))
            .collect();
        for id in removed {
            self.segments.forget(id)?;
        }
        self.entries
            .retain(|_, entry| ids.contains(&entry.reference.id));
        self.ranges
            .retain(|_, (revision, _)| self.entries.contains_key(revision));
        for entry in self.entries.values() {
            let key = source_key(&entry.identity);
            let Some(&floor) = budget.required.get(&key) else {
                continue;
            };
            let contiguous = self.sources[&key].receipt.contiguous_cursor;
            for span in &entry.commit.spans {
                if span.last <= floor {
                    continue;
                }
                let consumed = if floor >= span.first {
                    span.ends[(floor - span.first) as usize]
                } else {
                    0
                };
                *budget
                    .protected
                    .entry(entry.identity.tenant_id)
                    .or_default() += u64::from(*span.ends.last().unwrap_or(&0) - consumed);
                if span.first <= contiguous {
                    budget
                        .oldest
                        .entry(key)
                        .and_modify(|time| *time = (*time).min(entry.commit.intake))
                        .or_insert(entry.commit.intake);
                }
            }
        }
        self.budget = budget;
        Ok(())
    }

    pub(super) fn project(
        &mut self,
        writer: &mut Connection,
        control: Option<&super::AnalysisReadControl>,
    ) -> Result<()> {
        loop {
            if let Some(control) = control {
                control.check()?;
            }
            if !self.project_group(writer)? {
                return Ok(());
            }
        }
    }

    fn project_group(&mut self, writer: &mut Connection) -> Result<bool> {
        let revision = AnalysisStore::read_meta_from(writer, &self.root)?.commit_revision;
        let pending: Vec<_> = self
            .entries
            .range((
                std::ops::Bound::Excluded(revision),
                std::ops::Bound::Unbounded,
            ))
            .take(64)
            .scan(0_usize, |records, (_, entry)| {
                let count: usize = entry.commit.spans.iter().map(|span| span.ends.len()).sum();
                if *records != 0 && *records + count > crate::MAX_EVIDENCE_BATCH_RECORDS {
                    return None;
                }
                *records += count;
                Some(entry)
            })
            .collect();
        if pending.is_empty() {
            return Ok(false);
        }
        let group_revision = pending
            .last()
            .ok_or_else(|| self.invalid("the raw projection group is empty"))?
            .commit
            .revision;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin raw catalogue publication",
        })?;
        let mut charges = BTreeMap::<[u8; 16], i64>::new();
        let mut sources = BTreeMap::new();
        let mut binding_revision = 0;
        let mut segments = BTreeMap::new();
        let mut insert = transaction.prepare("INSERT INTO batch_ranges VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS UINTEGER[]), ?, ?, ?, ?)")
            .context(AnalysisDatabaseSnafu { operation: "prepare raw range publication" })?;
        for entry in &pending {
            let key = source_key(&entry.identity);
            sources.entry(key).or_insert(entry.commit.revision);
            segments.insert(entry.reference.id, *entry);
            for (span, digest) in entry.commit.spans.iter().zip(&entry.digests) {
                let ends =
                    serde_json::to_string(&span.ends).context(JsonSnafu { path: &self.root })?;
                let start = entry.body_start + u64::from(span.start);
                let end = start + u64::from(*span.ends.last().unwrap_or(&0));
                insert
                    .execute(params![
                        entry.reference.id,
                        key.as_slice(),
                        entry.identity.tenant_id.as_slice(),
                        start,
                        end,
                        span.first,
                        span.last,
                        ends,
                        digest.as_slice(),
                        entry.commit.revision,
                        span.ordinal,
                        entry.commit.intake
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "publish raw range",
                    })?;
                *charges.entry(entry.identity.tenant_id).or_default() +=
                    256 + 4 * span.ends.len() as i64;
            }
        }
        drop(insert);
        for (id, entry) in segments {
            let key = source_key(&entry.identity);
            let json =
                serde_json::to_string(&entry.identity).context(JsonSnafu { path: &self.root })?;
            let prior: Option<u64> = transaction
                .query_row(
                    "SELECT committed_end FROM segments WHERE segment_id = ? AND state = 'Live'",
                    params![id],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read projected raw segment",
                })?;
            let path = self.segments.file_path(id)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| self.invalid("the raw segment name is invalid"))?;
            if let Some(prior) = prior {
                transaction.execute(
                    "UPDATE segments SET committed_end = ?, file_name = ?, sealed = ? WHERE segment_id = ?",
                    params![entry.reference.offset, name, !name.ends_with(".open"), id],
                ).context(AnalysisDatabaseSnafu { operation: "advance projected raw segment" })?;
                *charges.entry(entry.identity.tenant_id).or_default() +=
                    (entry.reference.offset - prior) as i64;
            } else {
                transaction
                    .execute(
                        "INSERT INTO segments VALUES (?, ?, ?, ?, ?, 'records', 'Live', ?, ?, ?)",
                        params![
                            id,
                            key.as_slice(),
                            entry.identity.tenant_id.as_slice(),
                            json,
                            entry.commit.cpu,
                            !name.ends_with(".open"),
                            entry.reference.offset,
                            name
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "publish raw segment",
                    })?;
                *charges.entry(entry.identity.tenant_id).or_default() +=
                    256 + json.len() as i64 + entry.reference.offset as i64;
            }
        }
        for (key, first_revision) in sources {
            let source = &self.sources[&key];
            let receipt = &source.receipt;
            let json =
                serde_json::to_string(&receipt.identity).context(JsonSnafu { path: &self.root })?;
            let mut contiguous = AnalysisStore::read_receipt_from(
                &transaction,
                &self.root,
                &receipt.identity,
                &key,
            )?
            .map_or(0, |receipt| receipt.contiguous_cursor);
            for (_, &(revision, index)) in self.ranges.range((
                std::ops::Bound::Excluded((key, contiguous)),
                std::ops::Bound::Included((key, u64::MAX)),
            )) {
                let span = &self.entries[&revision].commit.spans[index];
                if revision > group_revision || span.first > contiguous.saturating_add(1) {
                    break;
                }
                contiguous = span.last;
            }
            if AnalysisStore::bind_source(&transaction, &self.root, &receipt.identity)? {
                binding_revision = binding_revision.max(first_revision);
            }
            let changed = transaction
                .execute(
                    "UPDATE source_receipts SET contiguous_cursor = ? WHERE stream_key = ?",
                    params![contiguous, key.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance projected raw receipt",
                })?;
            if changed == 0 {
                transaction
                    .execute(
                        "INSERT INTO source_receipts VALUES (?, ?, ?, ?, ?, ?, ?)",
                        params![
                            key.as_slice(),
                            json,
                            receipt.identity.tenant_id.as_slice(),
                            receipt.cpu_id,
                            contiguous,
                            receipt.coverage_revision,
                            receipt.retained_floor
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "publish raw receipt",
                    })?;
                *charges.entry(receipt.identity.tenant_id).or_default() += 256 + json.len() as i64;
            }
        }
        self.project_paths(&transaction)?;
        for (tenant, bytes) in charges {
            super::quota::UsageChange::from(bytes).apply(&transaction, &tenant)?;
        }
        transaction
            .execute(
                "UPDATE store_meta SET next_segment_id = ?",
                params![self.segments.next_id()],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "publish raw identity high water",
            })?;
        if binding_revision != 0 {
            AnalysisStore::record_revision(&transaction, binding_revision, &["source_bindings"])?;
        }
        AnalysisStore::record_revision(
            &transaction,
            group_revision,
            &["events", "source_receipts"],
        )?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit raw catalogue publication",
        })?;
        Ok(true)
    }

    pub(super) fn restore_receipts(&mut self, writer: &Connection) -> Result<()> {
        let next: u64 = writer
            .query_row("SELECT next_segment_id FROM store_meta", [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read raw identity high water",
            })?;
        self.segments.advance_id(next);
        let mut statement = writer.prepare("SELECT identity_json, cpu_id, contiguous_cursor, coverage_revision, retained_floor FROM source_receipts")
            .context(AnalysisDatabaseSnafu { operation: "prepare durable raw receipts" })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read durable raw receipts",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read durable raw receipt",
        })? {
            let json: String = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read raw receipt identity",
            })?;
            let identity: EvidenceIntakeIdentityV1 =
                serde_json::from_str(&json).context(JsonSnafu { path: &self.root })?;
            let receipt = AnalysisSourceReceiptV1 {
                identity,
                cpu_id: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "read raw CPU",
                })?,
                contiguous_cursor: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "read raw cursor",
                })?,
                coverage_revision: row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "read raw coverage revision",
                })?,
                retained_floor: row.get(4).context(AnalysisDatabaseSnafu {
                    operation: "read raw retained floor",
                })?,
            };
            let key = source_key(&receipt.identity);
            if let Some(source) = self.sources.get_mut(&key) {
                if source.receipt.identity != receipt.identity
                    || source.receipt.cpu_id != receipt.cpu_id
                {
                    return AnalysisStore::reject_path(
                        &self.root,
                        "the durable raw receipt conflicts with its segments",
                    );
                }
                source.receipt.contiguous_cursor = source
                    .receipt
                    .contiguous_cursor
                    .max(receipt.contiguous_cursor);
                source.receipt.coverage_revision = receipt.coverage_revision;
                source.receipt.retained_floor = receipt.retained_floor;
            } else {
                self.sources.insert(key, receipt.into());
            }
        }
        self.refresh_receipts()
    }

    pub(super) fn catalog_path(
        writer: &Connection,
        root: &Path,
        id: u64,
    ) -> Result<std::path::PathBuf> {
        let name: String = writer
            .query_row(
                "SELECT file_name FROM segments WHERE segment_id = ?",
                params![id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read raw segment file name",
            })?;
        Self::file_path(root, &name)
    }
}
