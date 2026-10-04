use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::raw::{RawIdentity, RawJournal, RawReceipt, RawSource, TraceOutputReceiptV1};
use super::{source_key, AnalysisSourceReceiptV1, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, JsonSnafu, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_matches_charge_reads() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(&directory.path().join("analysis"))?;
        let mut guard = store.writer.lock().map_err(|_| "writer lock poisoned")?;
        let writer = guard.as_mut().ok_or("writer closed")?;
        let mut raw = store.raw.lock().map_err(|_| "raw lock poisoned")?;
        raw.refresh_budget(writer)?;
        assert!(raw.budget.diagnostics.is_empty());
        assert!(raw.budget.usage.is_empty());
        assert!(raw.budget.contexts.is_empty());

        for tenant in [1u8, 2] {
            writer.execute(
                "INSERT INTO traces VALUES (?, ?, ?, ?, '[]', ?, 1, 2, false, ?, 1, false, false)",
                params![
                    [tenant; 16].as_slice(),
                    [3u8; 16].as_slice(),
                    [1u8, 2, 3].as_slice(),
                    [0u8; 32].as_slice(),
                    [1u8, 2].as_slice(),
                    [0u8; 32].as_slice(),
                ],
            )?;
        }
        for (tenant, bytes) in [(1u8, 1000u64), (3, 3000), (4, 0)] {
            writer.execute(
                "INSERT INTO tenant_usage VALUES (?, ?, 0, 0, 0)",
                params![[tenant; 16].as_slice(), bytes],
            )?;
        }
        for tenant in [1u8, 5, 6] {
            writer.execute(
                "INSERT INTO context_versions VALUES (?, 'p', ?, ?, 1, 1, NULL,
                 'Tenant', ?, ?, 1)",
                params![
                    [tenant; 16].as_slice(),
                    [1u8].as_slice(),
                    [1u8].as_slice(),
                    [1u8, 2, 3].as_slice(),
                    [0u8; 32].as_slice(),
                ],
            )?;
        }
        for (tenant, reference) in [(1u8, "first"), (1, "second"), (5, "third")] {
            writer.execute(
                "INSERT INTO context_refs VALUES (?, ?, 'p', ?, ?, 1, ?)",
                params![
                    reference,
                    [tenant; 16].as_slice(),
                    [1u8].as_slice(),
                    [1u8].as_slice(),
                    [0u8; 32].as_slice(),
                ],
            )?;
        }
        raw.refresh_budget(writer)?;
        assert_eq!(
            raw.budget.diagnostics,
            BTreeMap::from([([1; 16], 263), ([2; 16], 263)])
        );
        assert_eq!(raw.budget.diagnostic_total, 526);
        assert_eq!(
            raw.budget.usage,
            BTreeMap::from([([1; 16], 1000), ([3; 16], 3000), ([4; 16], 0)])
        );
        assert_eq!(raw.budget.total, 4000);
        assert_eq!(
            raw.budget.contexts,
            BTreeMap::from([([1; 16], 262), ([5; 16], 262)])
        );

        writer.execute(
            "UPDATE tenant_usage SET logical_bytes = 2000 WHERE tenant_id = ?",
            params![[1u8; 16].as_slice()],
        )?;
        writer.execute(
            "DELETE FROM context_refs WHERE tenant_id = ?",
            params![[1u8; 16].as_slice()],
        )?;
        raw.refresh_budget(writer)?;
        assert_eq!(raw.budget.usage[&[1; 16]], 2000);
        assert_eq!(raw.budget.total, 5000);
        assert_eq!(raw.budget.contexts, BTreeMap::from([([5; 16], 262)]));
        Ok(())
    }

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
            assert_eq!(raw.sources[&source_key(&identity)].receipt.cursor(), 65);
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
    pub diagnostics: BTreeMap<[u8; 16], u64>,
    pub diagnostic_total: u64,
    pub trace_reserve: u64,
    pub trace_slots: usize,
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
        let mut raw = RawJournal::open(root, &committed)?;
        raw.restore_receipts(writer)?;
        for id in deleting {
            Self::remove_segment(writer, root, &raw, id)?;
            raw.forget_segment(id)?;
        }
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
            let mut statement = writer.prepare("SELECT segment_id, committed_end, identity_json, cpu_id, file_name, stream_kind FROM segments")
                .context(AnalysisDatabaseSnafu { operation: "prepare raw segment catalogue check" })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<u32>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
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
            let mut seen = BTreeSet::new();
            for row in rows {
                let (id, end, json, cpu, name, kind) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw segment catalogue check",
                })?;
                seen.insert(id);
                let entry = projected
                    .get(&id)
                    .ok_or_else(|| self.invalid("a catalogued raw segment is absent"))?;
                let identity = RawIdentity::parse(&kind, &json, &self.root)?;
                let path = self.segments.file_path(id)?;
                let current = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| self.invalid("the raw segment name is invalid"))?;
                let rotated = name.ends_with(".open")
                    && name.split('.').take(4).eq(current.split('.').take(4));
                if end != entry.reference.offset
                    || identity != entry.identity
                    || cpu != entry.commit.kind.cpu()
                    || (name != current && !rotated)
                {
                    return Err(
                        self.invalid("the raw segment catalogue differs from its durable file")
                    );
                }
            }
            if seen.len() != projected.len() {
                return Err(self.invalid("a committed raw segment has no metadata"));
            }
        }
        let mut statement = writer.prepare(
            "SELECT stream_key, identity_json, contiguous_cursor, retained_floor, 'records' FROM source_receipts
             UNION ALL SELECT stream_key, identity_json, last_sequence + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END,
             retained_floor, 'diagnostic' FROM trace_receipts"
        ).context(AnalysisDatabaseSnafu { operation: "prepare raw source validation" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read raw source validation",
            })?;
        for row in rows {
            let (key, json, accepted, floor, kind) = row.context(AnalysisDatabaseSnafu {
                operation: "decode raw source validation",
            })?;
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| self.invalid("the raw source key is invalid"))?;
            let identity = RawIdentity::parse(&kind, &json, &self.root)?;
            let expired: u64 = writer.query_row(
                "SELECT COALESCE(SUM(last_cursor::HUGEINT - first_cursor + 1), 0)::UBIGINT FROM expired_ranges WHERE stream_key = ?",
                params![key.as_slice()], |row| row.get(0)
            ).context(AnalysisDatabaseSnafu { operation: "count expired raw ranges" })?;
            if self
                .record_count(key, 1, accepted, revision)
                .checked_add(expired)
                != Some(accepted)
            {
                return Err(self.invalid("the acknowledged raw range is incomplete"));
            }
            let ranges = self.select_ranges(&identity, 1, accepted, revision, None, 1)?;
            let expected = ranges
                .first()
                .map_or(accepted, |range| range.first_cursor - 1);
            if floor != expected {
                return Err(self.invalid("the retained raw floor is invalid"));
            }
            for entry in self
                .entries
                .values()
                .filter(|entry| entry.identity.key() == key)
            {
                if entry.commit.spans.iter().any(|span| {
                    span.last > accepted.saturating_add(crate::MAX_PENDING_EVIDENCE_RECORDS)
                }) {
                    return Err(self.invalid("the raw pending range exceeds its bound"));
                }
            }
        }
        let mut statement = writer
            .prepare("SELECT stream_key, first_cursor, last_cursor FROM expired_ranges")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare expiry overlap validation",
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
                operation: "read expiry overlap validation",
            })?;
        for row in rows {
            let (key, first, last) = row.context(AnalysisDatabaseSnafu {
                operation: "decode expiry overlap validation",
            })?;
            let key = key
                .try_into()
                .map_err(|_| self.invalid("the expired source key is invalid"))?;
            if self.record_count(key, first, last, revision) != 0 {
                return Err(self.invalid("an expired raw range is still live"));
            }
        }
        let mut statement = writer
            .prepare("SELECT stream_key, durable_cursor, segment_id FROM evidence_refs")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare raw witness validation",
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
                operation: "read raw witness validation",
            })?;
        for row in rows {
            let (key, cursor, segment) = row.context(AnalysisDatabaseSnafu {
                operation: "decode raw witness validation",
            })?;
            let key = key
                .try_into()
                .map_err(|_| self.invalid("the raw witness key is invalid"))?;
            let (entry, index) = self.locate(key, cursor, revision)?;
            if entry.reference.id != segment {
                return Err(self.invalid("the retained witness segment differs"));
            }
            self.freeze(entry, index, cursor, cursor)?
                .read(&self.root)?;
        }
        Ok(())
    }

    pub(super) fn refresh_budget(&mut self, writer: &Connection) -> Result<()> {
        self.restore_receipts(writer)?;
        let mut budget = RawBudget::default();
        {
            let mut statement = writer
                .prepare(&format!(
                    "SELECT 0::UTINYINT AS kind, tenant_id, SUM(bytes)::UBIGINT AS bytes
                     FROM ({}) GROUP BY tenant_id
                     UNION ALL SELECT 1::UTINYINT, tenant_id, logical_bytes FROM tenant_usage
                     UNION ALL SELECT 2::UTINYINT, c.tenant_id,
                     SUM(256 + octet_length(c.body) + octet_length(encode(c.owner_id))
                     + octet_length(c.entity_key) + octet_length(c.lifetime_key))::UBIGINT
                     FROM context_versions c SEMI JOIN context_refs r USING
                     (tenant_id, owner_id, entity_key, lifetime_key, owner_revision)
                     GROUP BY c.tenant_id",
                    super::quota::TRACE_CHARGES
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare raw budget charges",
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u8>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw budget charges",
                })?;
            for row in rows {
                let (kind, tenant, bytes) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw budget charge",
                })?;
                let reason = match kind {
                    0 => "the diagnostic tenant is invalid",
                    1 => "the raw quota tenant is invalid",
                    2 => "the raw context tenant is invalid",
                    _ => return Err(self.invalid("the raw budget charge kind is invalid")),
                };
                let tenant = tenant.try_into().map_err(|_| self.invalid(reason))?;
                match kind {
                    0 => {
                        budget.diagnostics.insert(tenant, bytes);
                        budget.diagnostic_total = budget
                            .diagnostic_total
                            .checked_add(bytes)
                            .ok_or_else(|| self.invalid("the diagnostic budget is exhausted"))?;
                    }
                    1 => {
                        budget.usage.insert(tenant, bytes);
                        budget.total = budget
                            .total
                            .checked_add(bytes)
                            .ok_or_else(|| self.invalid("the raw quota total is exhausted"))?;
                    }
                    _ => {
                        budget.contexts.insert(tenant, bytes);
                    }
                }
            }
            let (unfinished, slots): (u64, u64) = writer.query_row(
                "SELECT COUNT(*)::UBIGINT, COALESCE(SUM(CASE WHEN EXISTS (SELECT 1 FROM segments s
                 WHERE s.stream_key = r.stream_key AND s.state = 'Live') THEN 1 ELSE 2 END), 0)::UBIGINT
                 FROM trace_receipts r WHERE terminal IS NULL", [], |row| Ok((row.get(0)?, row.get(1)?))
            ).context(AnalysisDatabaseSnafu { operation: "read diagnostic reservations" })?;
            budget.trace_reserve = unfinished
                .checked_mul(super::quota::TRACE_RESERVE)
                .ok_or_else(|| self.invalid("the diagnostic reserve is exhausted"))?;
            budget.trace_slots = usize::try_from(slots)
                .map_err(|_| self.invalid("the diagnostic slot reserve is exhausted"))?;
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
            let mut statement = writer.prepare(
                "SELECT segment_id, tenant_id, MAX(expires_utc_ns)::UBIGINT FROM evidence_refs GROUP BY segment_id, tenant_id"
            ).context(AnalysisDatabaseSnafu { operation: "prepare raw witness pins" })?;
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
            self.forget_segment(id)?;
        }
        for entry in self.entries.values() {
            let key = entry.identity.key();
            let Some(&floor) = budget.required.get(&key) else {
                continue;
            };
            let contiguous = self.sources[&key].receipt.cursor();
            for (index, span) in entry.commit.spans.iter().enumerate() {
                if span.last <= floor {
                    continue;
                }
                let consumed = if floor >= span.first {
                    self.read_entry(entry)?.spans[index].ends[(floor - span.first) as usize]
                } else {
                    0
                };
                *budget.protected.entry(entry.identity.tenant()).or_default() +=
                    u64::from(span.bytes - consumed);
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
                let count: usize = entry
                    .commit
                    .spans
                    .iter()
                    .map(|span| (span.last - span.first + 1) as usize)
                    .sum();
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
        for entry in &pending {
            let key = entry.identity.key();
            sources.entry(key).or_insert(entry.commit.revision);
            segments.insert(entry.reference.id, *entry);
        }
        for (id, entry) in segments {
            let key = entry.identity.key();
            let json = entry.identity.json(&self.root)?;
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
                *charges.entry(entry.identity.tenant()).or_default() +=
                    (entry.reference.offset - prior) as i64;
            } else {
                transaction
                    .execute(
                        "INSERT INTO segments VALUES (?, ?, ?, ?, ?, ?, 'Live', ?, ?, ?)",
                        params![
                            id,
                            key.as_slice(),
                            entry.identity.tenant().as_slice(),
                            json,
                            entry.commit.kind.cpu(),
                            entry.identity.kind(),
                            !name.ends_with(".open"),
                            entry.reference.offset,
                            name
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "publish raw segment",
                    })?;
                *charges.entry(entry.identity.tenant()).or_default() +=
                    256 + json.len() as i64 + entry.reference.offset as i64;
            }
        }
        for (key, first_revision) in sources {
            let source = &self.sources[&key];
            let RawReceipt::Evidence(receipt) = &source.receipt else {
                let entry = self
                    .entries
                    .range(..=group_revision)
                    .rev()
                    .map(|(_, entry)| entry)
                    .find(|entry| entry.identity.key() == key)
                    .ok_or_else(|| self.invalid("the diagnostic projection entry is absent"))?;
                let commit = self.read_entry(entry)?;
                let RawReceipt::Diagnostic(receipt) = self.commit_receipt(entry, &commit)? else {
                    return Err(self.invalid("the diagnostic projection receipt is invalid"));
                };
                let terminal = receipt
                    .terminal
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .context(JsonSnafu { path: &self.root })?;
                let prior: Option<String> = transaction
                    .query_row(
                        "SELECT terminal FROM trace_receipts WHERE stream_key = ?",
                        params![key.as_slice()],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read diagnostic terminal charge",
                    })?;
                if prior.is_none() {
                    if let Some(terminal) = &terminal {
                        *charges.entry(receipt.identity.tenant_id).or_default() +=
                            terminal.len() as i64 - super::quota::TRACE_RESERVE as i64;
                    }
                }
                transaction.execute(
                    "UPDATE trace_receipts SET last_sequence = ?, output_bytes = ?, terminal = ?, commit_revision = ? WHERE stream_key = ?",
                    params![receipt.last_sequence, receipt.output_bytes, terminal, receipt.commit_revision, key.as_slice()],
                ).context(AnalysisDatabaseSnafu { operation: "publish diagnostic receipt" })?;
                continue;
            };
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
        let evidence = pending
            .iter()
            .any(|entry| matches!(entry.identity, RawIdentity::Evidence(_)));
        let diagnostic = pending
            .iter()
            .any(|entry| matches!(entry.identity, RawIdentity::Diagnostic(_)));
        let mut relations = Vec::new();
        if evidence {
            relations.extend(["events", "source_receipts"]);
        }
        if diagnostic {
            relations.extend(["trace_output", "trace_receipts"]);
        }
        AnalysisStore::record_revision(&transaction, group_revision, &relations)?;
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
                let RawReceipt::Evidence(saved) = &mut source.receipt else {
                    return AnalysisStore::reject_path(
                        &self.root,
                        "the raw receipt kind conflicts",
                    );
                };
                if saved.identity != receipt.identity || saved.cpu_id != receipt.cpu_id {
                    return AnalysisStore::reject_path(
                        &self.root,
                        "the durable raw receipt conflicts with its segments",
                    );
                }
                saved.contiguous_cursor = saved.contiguous_cursor.max(receipt.contiguous_cursor);
                saved.coverage_revision = receipt.coverage_revision;
                saved.retained_floor = receipt.retained_floor;
            } else {
                self.sources.insert(key, receipt.into());
            }
        }
        let mut statement = writer.prepare("SELECT identity_json, last_sequence, output_bytes, terminal, retained_floor, commit_revision FROM trace_receipts")
            .context(AnalysisDatabaseSnafu { operation: "prepare diagnostic receipts" })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read diagnostic receipts",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read diagnostic receipt",
        })? {
            let json: String = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic identity",
            })?;
            let identity: crate::TraceIdentityV1 =
                serde_json::from_str(&json).context(JsonSnafu { path: &self.root })?;
            let terminal: Option<String> = row.get(3).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic terminal",
            })?;
            let receipt = TraceOutputReceiptV1 {
                identity: identity.clone(),
                last_sequence: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "read diagnostic sequence",
                })?,
                output_bytes: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "read diagnostic byte count",
                })?,
                terminal: terminal
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .context(JsonSnafu { path: &self.root })?,
                retained_floor: row.get(4).context(AnalysisDatabaseSnafu {
                    operation: "read diagnostic retained floor",
                })?,
                commit_revision: row.get(5).context(AnalysisDatabaseSnafu {
                    operation: "read diagnostic revision",
                })?,
            };
            let key = RawIdentity::Diagnostic(identity).key();
            if let Some(source) = self.sources.get_mut(&key) {
                let RawReceipt::Diagnostic(saved) = &mut source.receipt else {
                    return AnalysisStore::reject_path(
                        &self.root,
                        "the diagnostic receipt kind conflicts",
                    );
                };
                if saved.identity != receipt.identity
                    || (saved.commit_revision == receipt.commit_revision
                        && (saved.last_sequence != receipt.last_sequence
                            || saved.output_bytes != receipt.output_bytes
                            || saved.terminal != receipt.terminal))
                {
                    return AnalysisStore::reject_path(
                        &self.root,
                        "the diagnostic receipt conflicts with its segments",
                    );
                }
                if saved.commit_revision < receipt.commit_revision {
                    *saved = receipt;
                } else {
                    saved.retained_floor = receipt.retained_floor;
                }
            } else {
                self.sources.insert(
                    key,
                    RawSource {
                        receipt: RawReceipt::Diagnostic(receipt),
                        stream: 0,
                        sequence: 0,
                    },
                );
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
