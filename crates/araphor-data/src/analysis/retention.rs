use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use duckdb::params;
use snafu::ResultExt as _;

use super::{raw::RawIdentity, AnalysisStore, StorePositionV1};
#[cfg(any(test, feature = "test-fixtures"))]
use crate::EvidenceIntakeIdentityV1;
use crate::{AnalysisDatabaseSnafu, Result};

const RETENTION_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionLimitsV1 {
    pub raw_max_age_ns: Option<u64>,
    pub raw_max_bytes: Option<u64>,
}

#[cfg(test)]
impl RetentionLimitsV1 {
    pub(super) fn fixture() -> Self {
        Self {
            raw_max_age_ns: Some(24 * 60 * 60 * 1_000_000_000),
            raw_max_bytes: Some(2 * 1024 * 1024 * 1024),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionStepV1 {
    pub removed_records: u32,
    pub more: bool,
    pub next_deadline_utc_ns: Option<u64>,
    pub read_revision: u64,
}

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionResultV1 {
    pub removed_records: u32,
    pub retained_bytes: u64,
    pub retained_floor: u64,
    pub commit_revision: u64,
}

pub struct EvidenceRetentionOwner<'a> {
    store: &'a AnalysisStore,
}

impl<'a> EvidenceRetentionOwner<'a> {
    pub fn new(store: &'a AnalysisStore) -> Self {
        Self { store }
    }

    pub fn enabled(&self) -> bool {
        self.store.retention.raw_max_age_ns.is_some()
            || self.store.retention.raw_max_bytes.is_some()
            || self.store.storage.logical_max_bytes.is_some()
            || self.store.storage.tenant_max_bytes.is_some()
    }

    pub fn step(&self, now_utc_ns: u64) -> Result<RetentionStepV1> {
        self.run(
            now_utc_ns,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        )
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn retain(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        now_utc_ns: u64,
    ) -> Result<RetentionResultV1> {
        self.retain_source(&identity.clone().into(), now_utc_ns)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn retain_trace(
        &self,
        identity: &crate::TraceIdentityV1,
        now_utc_ns: u64,
    ) -> Result<RetentionResultV1> {
        self.retain_source(&identity.clone().into(), now_utc_ns)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn retain_source(&self, source: &RawIdentity, now: u64) -> Result<RetentionResultV1> {
        if !source.valid() {
            return self.store.reject("the retention source is invalid");
        }
        let mut target = RetentionResultV1 {
            removed_records: 0,
            retained_bytes: 0,
            retained_floor: 0,
            commit_revision: 0,
        };
        self.run(now, Some((source, &mut target)))?;
        Ok(target)
    }

    fn run(
        &self,
        now: u64,
        #[cfg(any(test, feature = "test-fixtures"))] target: Option<(
            &RawIdentity,
            &mut RetentionResultV1,
        )>,
    ) -> Result<RetentionStepV1> {
        if now == 0 {
            return self.store.reject("the retention time is invalid");
        }
        let result = self
            .run_batch(
                now,
                #[cfg(any(test, feature = "test-fixtures"))]
                target,
            )
            .and_then(|result| {
                if result.removed_records > 0 || !self.store.retention_healthy() {
                    self.store.checkpoint()?;
                }
                Ok(result)
            });
        if result.is_ok() {
            if !self.store.retention_healthy.swap(true, Ordering::AcqRel) {
                self.store.revision.send_modify(|_| {});
            }
        } else {
            self.store.retention_healthy.store(false, Ordering::Release);
        }
        result
    }

    fn selection(&self) -> String {
        let logical = if self.store.storage.logical_max_bytes.is_some()
            || self.store.storage.tenant_max_bytes.is_some()
        {
            AnalysisStore::usage_projection()
        } else {
            "SELECT NULL::BLOB AS tenant_id, 0::UBIGINT AS logical_bytes WHERE FALSE".to_owned()
        };
        #[cfg(any(test, feature = "test-fixtures"))]
        let (source, scope) = (
            ", ?::BLOB AS source_key",
            "AND (cfg.source_key IS NULL OR s.stream_key = cfg.source_key)",
        );
        #[cfg(not(any(test, feature = "test-fixtures")))]
        let (source, scope) = ("", "");
        let rules = format!(
            include_str!("retention.sql"),
            source = source,
            scope = scope
        );
        format!("WITH logical AS ({logical}), {rules}")
    }

    fn run_batch(
        &self,
        now: u64,
        #[cfg(any(test, feature = "test-fixtures"))] target: Option<(
            &RawIdentity,
            &mut RetentionResultV1,
        )>,
    ) -> Result<RetentionStepV1> {
        let enabled = self.enabled();
        let mut step = RetentionStepV1 {
            removed_records: 0,
            more: false,
            next_deadline_utc_ns: None,
            read_revision: *self.store.revision.borrow(),
        };
        let disabled = !enabled;
        #[cfg(any(test, feature = "test-fixtures"))]
        let disabled = disabled && target.is_none();
        if disabled {
            return Ok(step);
        }
        let mut guard = self.store.maintenance_writer()?;
        let _snapshot = self.store.maintenance.write().map_err(|_| {
            self.store
                .state_error("the analysis maintenance lock is poisoned")
        })?;
        let writer = guard.get_mut()?;
        let mut raw = self
            .store
            .raw
            .lock()
            .map_err(|_| self.store.state_error("the raw owner lock is poisoned"))?;
        #[cfg(any(test, feature = "test-fixtures"))]
        let key = target.as_ref().map(|(source, _)| source.key());
        #[cfg(any(test, feature = "test-fixtures"))]
        let binding = key.as_deref();
        let threshold = |limit: u64| {
            let allowance = limit - limit / 4;
            allowance - allowance / 10
        };
        let global = self.store.storage.logical_max_bytes.map(threshold);
        let tenant = self.store.storage.tenant_max_bytes.map(threshold);
        let selection = enabled.then(|| self.selection());
        let values = params![
            now,
            self.store.retention.raw_max_age_ns,
            self.store.retention.raw_max_bytes,
            global,
            tenant
        ];
        #[cfg(any(test, feature = "test-fixtures"))]
        let scoped = [values, params![binding]].concat();
        #[cfg(any(test, feature = "test-fixtures"))]
        let values = scoped.as_slice();
        let meta = AnalysisStore::read_meta_from(writer, &self.store.root)?;
        if let Some(selection) = &selection {
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin raw retention",
            })?;
            let chosen = transaction.prepare(&format!("{selection} SELECT segment_id, stream_key, tenant_id,
                    identity_json, stream_kind, first_cursor, last_cursor, last_intake_utc_ns, committed_end
                    FROM selected ORDER BY last_intake_utc_ns, segment_id LIMIT {RETENTION_SEGMENTS}"))
                .context(AnalysisDatabaseSnafu { operation: "prepare eligible retention segments" })?
                .query_map(values, |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, u64>(5)?, row.get::<_, u64>(6)?,
                    row.get::<_, u64>(7)?, row.get::<_, u64>(8)?)))
                .context(AnalysisDatabaseSnafu { operation: "read eligible retention segments" })?
                .collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu { operation: "decode eligible retention segments" })?;
            if !chosen.is_empty() {
                let revision = meta.commit_revision.checked_add(1).ok_or_else(|| {
                    self.store
                        .state_error("the analysis commit revision is exhausted")
                })?;
                let mut selected = BTreeSet::new();
                let mut floors = BTreeMap::<[u8; 16], StorePositionV1>::new();
                let mut sources = BTreeMap::new();
                raw.seal_all()?;
                raw.project_paths(&transaction)?;
                for (id, key, tenant, json, kind, first, last, intake, end) in chosen {
                    let identity = RawIdentity::parse(&kind, &json, &self.store.root)?;
                    if identity.key() != key || identity.tenant().as_slice() != tenant {
                        return self.store.reject("the retention segment identity differs");
                    }
                    let mut intervals = Vec::new();
                    for entry in raw.segment_entries(id, first, last, intake, end)? {
                        if entry.identity != identity {
                            return self.store.reject("the retention journal identity differs");
                        }
                        for span in &entry.commit.spans {
                            let count =
                                u32::try_from(span.last - span.first + 1).map_err(|_| {
                                    self.store
                                        .state_error("the expired record count is invalid")
                                })?;
                            step.removed_records =
                                step.removed_records.checked_add(count).ok_or_else(|| {
                                    self.store
                                        .state_error("the expired record count is invalid")
                                })?;
                            let position = StorePositionV1 {
                                commit_revision: entry.commit.revision,
                                ordinal: span.ordinal.checked_add(count - 1).ok_or_else(|| {
                                    self.store.state_error("the expired position is invalid")
                                })?,
                            };
                            floors
                                .entry(identity.tenant())
                                .and_modify(|floor| *floor = (*floor).max(position))
                                .or_insert(position);
                            intervals.push([span.first, span.last]);
                        }
                    }
                    let ranges = serde_json::to_string(&intervals).context(crate::JsonSnafu {
                        path: &self.store.root,
                    })?;
                    transaction.execute("INSERT INTO expired_ranges
                        WITH spans AS (SELECT span[1] AS first, span[2] AS last
                            FROM (SELECT unnest(CAST(? AS UBIGINT[][])) AS span)),
                        ordered AS (SELECT *, MAX(last) OVER (ORDER BY first ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prior FROM spans),
                        grouped AS (SELECT *, SUM(CASE WHEN prior::HUGEINT + 1 = first THEN 0 ELSE 1 END)
                            OVER (ORDER BY first) AS group_id FROM ordered)
                        SELECT ?, ?, ?, MIN(first), MAX(last), ? FROM grouped GROUP BY group_id",
                        params![ranges, id, key.as_slice(), tenant.as_slice(), revision])
                        .context(AnalysisDatabaseSnafu { operation: "record expired segment interval" })?;
                    transaction.execute("UPDATE segments SET state = 'Deleting', sealed = true WHERE segment_id = ? AND state = 'Live'", params![id])
                        .context(AnalysisDatabaseSnafu { operation: "mark eligible segment deletion" })?;
                    selected.insert(id);
                    sources.insert(key, identity);
                }
                let mut relations = vec!["expired_ranges", "evidence_refs"];
                for (tenant, floor) in floors {
                    let before = AnalysisStore::replay_floor_from(&transaction, tenant)?;
                    if before.is_none_or(|before| floor > before) {
                        transaction.execute("INSERT INTO replay_floors VALUES (?, ?, ?) ON CONFLICT (tenant_id)
                            DO UPDATE SET commit_revision = excluded.commit_revision, ordinal = excluded.ordinal",
                            params![tenant.as_slice(), floor.commit_revision, floor.ordinal])
                            .context(AnalysisDatabaseSnafu { operation: "advance tenant replay floor" })?;
                        relations.push("replay_floors");
                    }
                }
                let mut changed = Vec::new();
                for (key, identity) in sources {
                    let (relation, receipts, cursor) = if identity.evidence().is_some() {
                        ("events", "source_receipts", "contiguous_cursor")
                    } else {
                        (
                            "trace_output",
                            "trace_receipts",
                            "last_sequence + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END",
                        )
                    };
                    let before = raw
                        .sources
                        .get(&key)
                        .ok_or_else(|| self.store.state_error("the retention source is absent"))?
                        .receipt
                        .floor();
                    let floor: u64 = transaction.query_row(&format!("SELECT COALESCE(
                            (SELECT MIN(first_cursor) - 1 FROM segments WHERE stream_key = ? AND state = 'Live'
                                AND first_cursor <= ({cursor})), {cursor}) FROM {receipts} WHERE stream_key = ?"),
                        params![key.as_slice(), key.as_slice()], |row| row.get(0))
                        .context(AnalysisDatabaseSnafu { operation: "read remaining retention floor" })?;
                    transaction.execute("DELETE FROM evidence_refs WHERE stream_key = ? AND tenant_id = ? AND expires_utc_ns <= ?",
                        params![key.as_slice(), identity.tenant().as_slice(), now]).context(AnalysisDatabaseSnafu { operation: "remove expired witness references" })?;
                    if floor > before {
                        transaction
                            .execute(
                                &format!(
                                    "UPDATE {receipts} SET retained_floor = ? WHERE stream_key = ?"
                                ),
                                params![floor, key.as_slice()],
                            )
                            .context(AnalysisDatabaseSnafu {
                                operation: "advance retained segment floor",
                            })?;
                        relations.push(receipts);
                    }
                    relations.push(relation);
                    changed.push((key, floor));
                }
                relations.sort_unstable();
                relations.dedup();
                AnalysisStore::record_revision(&transaction, revision, &relations)?;
                #[cfg(test)]
                self.store.crash_at("retention.before");
                #[cfg(any(test, feature = "test-fixtures"))]
                self.store
                    .run_commit_hook(super::AnalysisCommitStage::BeforeRetentionCommit)?;
                self.store.write_ready.store(false, Ordering::Release);
                transaction.commit().context(AnalysisDatabaseSnafu {
                    operation: "commit segment deletion",
                })?;
                for (key, floor) in changed {
                    if let Some(source) = raw.sources.get_mut(&key) {
                        source.receipt.set_floor(floor);
                    }
                }
                #[cfg(test)]
                self.store.crash_at("retention.after");
                let cleanup =
                    AnalysisStore::remove_segments(writer, &self.store.root, &raw, &selected);
                raw.forget_segments(selected)?;
                cleanup?;
                raw.refresh_budget(writer, self.store.retention)?;
                self.store.write_ready.store(true, Ordering::Release);
                self.store.revision.send_replace(revision);
            } else {
                transaction.rollback().context(AnalysisDatabaseSnafu {
                    operation: "finish empty retention",
                })?;
            }
            let (more, deadline): (bool, Option<u64>) = writer.query_row(&format!("{selection}
                SELECT EXISTS(SELECT 1 FROM selected), CAST(MIN(due) FILTER (WHERE due > now_ns AND due <= 18446744073709551615) AS UBIGINT)
                FROM (SELECT now_ns, CASE WHEN over_bytes OR pressure THEN pin_until::HUGEINT
                    WHEN age_ns IS NOT NULL THEN GREATEST(last_intake_utc_ns::HUGEINT + age_ns, pin_until::HUGEINT)
                    ELSE NULL END AS due FROM base)"), values, |row| Ok((row.get(0)?, row.get(1)?)))
                .context(AnalysisDatabaseSnafu { operation: "read retention continuation" })?;
            step.more = more;
            step.next_deadline_utc_ns = deadline;
        }
        step.read_revision =
            AnalysisStore::read_meta_from(writer, &self.store.root)?.commit_revision;
        #[cfg(any(test, feature = "test-fixtures"))]
        if let Some((identity, target)) = target {
            target.removed_records = step.removed_records;
            target.commit_revision = step.read_revision;
            let key = identity.key();
            let receipt = raw
                .sources
                .get(&key)
                .filter(|source| source.receipt.matches(identity))
                .ok_or_else(|| self.store.state_error("the retention source is absent"))?;
            target.retained_floor = receipt.receipt.floor();
            target.retained_bytes = writer
                .query_row(
                    "SELECT COALESCE(SUM(committed_end), 0)::UBIGINT FROM segments
                WHERE stream_key = ? AND state = 'Live'",
                    params![key.as_slice()],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "count retained source bytes",
                })?;
        }
        Ok(step)
    }
}

#[cfg(test)]
impl AnalysisStore {
    pub(super) fn open_retention(root: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::open_with_limits(root, RetentionLimitsV1::fixture(), Default::default())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceStoreOutcomeV1, ProcessorClassV1,
        ProcessorScopeV1, ValidatedEvidenceBatchV1,
    };

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            ..crate::analysis::tests::identity()
        }
    }

    fn batch(first: u64, bytes: &'static [u8]) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + bytes.len() as u64 - 1,
            intake_utc_ns: 100,
            framed_records: prost::bytes::Bytes::from_static(bytes),
            frame_ends: (1..=bytes.len()).collect(),
        }
    }

    #[test]
    fn retention_is_optional() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits: RetentionLimitsV1 = serde_json::from_str("{}")?;
        assert_eq!(limits, RetentionLimitsV1::default());
        assert_eq!(limits.raw_max_age_ns, None);
        assert_eq!(limits.raw_max_bytes, None);
        let store = AnalysisStore::open(&root)?;
        let source = identity(1);
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let mut notice = store.subscribe_revision();
        notice.borrow_and_update();
        let owner = EvidenceRetentionOwner::new(&store);
        assert!(!owner.enabled());
        let step = owner.step(u64::MAX)?;
        assert_eq!(
            step,
            RetentionStepV1 {
                removed_records: 0,
                more: false,
                next_deadline_utc_ns: None,
                read_revision: 1
            }
        );
        assert!(store.raw_pending.load(Ordering::Acquire));
        assert!(!notice.has_changed()?);
        assert!(owner.step(0).is_err());
        assert!(store.retention_healthy());
        assert!(!notice.has_changed()?);
        let raw = store.raw.lock().map_err(|_| "raw lock")?;
        assert!(raw.budget.required.is_empty());
        assert!(raw.budget.protected.is_empty());
        assert!(raw.budget.oldest.is_empty());
        drop(raw);
        assert_eq!(store.read_page(&source, 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn retention_reports_deadlines() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_age_ns: Some(50),
                ..Default::default()
            },
            Default::default(),
        )?;
        let source = identity(1);
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let owner = EvidenceRetentionOwner::new(&store);
        assert_eq!(owner.step(149)?.next_deadline_utc_ns, Some(150));
        for (name, expiry) in [("first", 300), ("last", 400)] {
            let scope = ProcessorScopeV1 {
                processor_id: name.into(),
                method_version: 1,
                identity: source.clone(),
            };
            store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
            store.commit_result(&AnalysisResultCommitV1 {
                consumed_cursor: 1,
                created_utc_ns: 101,
                body: vec![1],
                witnesses: vec![AnalysisWitnessV1 {
                    identity: source.clone().into(),
                    cursor: 1,
                    expires_utc_ns: expiry,
                }],
                ..crate::analysis::tests::result(scope, name.into())
            })?;
        }
        assert_eq!(owner.step(150)?.next_deadline_utc_ns, Some(400));
        let pinned = owner.step(300)?;
        assert_eq!(pinned.removed_records, 0);
        assert_eq!(pinned.next_deadline_utc_ns, Some(400));
        let removed = owner.step(400)?;
        assert_eq!(removed.removed_records, 1);
        assert!(!removed.more);
        assert_eq!(removed.next_deadline_utc_ns, None);
        let required = ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&required, ProcessorClassV1::Required, 2)?;
        store.accept_validated_batch(source.clone(), batch(2, b"b"))?;
        let blocked = owner.step(500)?;
        assert_eq!(blocked.removed_records, 0);
        assert!(!blocked.more);
        assert_eq!(blocked.next_deadline_utc_ns, None);
        Ok(())
    }

    #[test]
    fn retention_age_overflow() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_age_ns: Some(10),
                ..Default::default()
            },
            Default::default(),
        )?;
        let source = identity(1);
        let mut input = batch(1, b"a");
        input.intake_utc_ns = u64::MAX - 5;
        store.accept_validated_batch(source.clone(), input)?;
        let step = EvidenceRetentionOwner::new(&store).step(u64::MAX)?;
        assert_eq!(step.removed_records, 0);
        assert_eq!(step.next_deadline_utc_ns, None);
        assert_eq!(store.read_page(&source, 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn retention_zero_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for limits in [
            RetentionLimitsV1 {
                raw_max_age_ns: Some(0),
                ..Default::default()
            },
            RetentionLimitsV1 {
                raw_max_bytes: Some(0),
                ..Default::default()
            },
        ] {
            let directory = tempfile::tempdir()?;
            let store = AnalysisStore::open_with_limits(
                directory.path().join("analysis"),
                limits,
                Default::default(),
            )?;
            let source = identity(1);
            store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
            let owner = EvidenceRetentionOwner::new(&store);
            assert!(owner.enabled());
            let step = owner.step(100)?;
            assert_eq!(step.removed_records, 1);
            assert!(!step.more);
            assert_eq!(step.next_deadline_utc_ns, None);
            assert_eq!(
                store
                    .source_receipt(&source)?
                    .ok_or("receipt absent")?
                    .retained_floor,
                1
            );
        }
        Ok(())
    }

    #[test]
    fn retention_repair_notices() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let before = store.meta()?;
        let mut notice = store.subscribe_revision();
        notice.borrow_and_update();
        store.retention_healthy.store(false, Ordering::Release);
        assert!(matches!(
            store.accept_validated_batch(identity(1), batch(1, b"a")),
            Err(crate::Error::RetentionUnavailable { .. })
        ));
        assert!(notice.has_changed()?);
        assert_eq!(*notice.borrow_and_update(), before.commit_revision);
        assert_eq!(store.meta()?, before);
        assert!(store.source_receipt(&identity(1))?.is_none());
        store.recover()?;
        assert!(notice.has_changed()?);
        assert_eq!(*notice.borrow_and_update(), before.commit_revision);
        assert_eq!(store.meta()?, before);
        assert!(store.write_ready.load(Ordering::Acquire));
        let owner = EvidenceRetentionOwner::new(&store);
        assert!(!owner.enabled());
        owner.step(100)?;
        assert!(store.retention_healthy());
        assert!(notice.has_changed()?);
        assert_eq!(*notice.borrow_and_update(), before.commit_revision);
        owner.step(100)?;
        assert!(!notice.has_changed()?);
        assert_eq!(store.meta()?, before);
        Ok(())
    }

    #[test]
    fn retention_checks_segment_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for mutation in [
            "UPDATE segments SET first_cursor = 2 WHERE segment_id = 1",
            "UPDATE segments SET last_intake_utc_ns = 101 WHERE segment_id = 1",
            "UPDATE segments AS s SET stream_key = other.stream_key, tenant_id = other.tenant_id,
                identity_json = other.identity_json FROM segments AS other
                WHERE s.segment_id = 1 AND other.segment_id = 2",
        ] {
            let directory = tempfile::tempdir()?;
            let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
            store.accept_validated_batch(identity(1), batch(1, b"a"))?;
            store.accept_validated_batch(identity(2), batch(1, b"b"))?;
            let before = store.meta()?;
            store.writer()?.get()?.execute_batch(mutation)?;
            assert!(matches!(
                EvidenceRetentionOwner::new(&store).step(u64::MAX),
                Err(crate::Error::AnalysisState { .. })
            ));
            assert_eq!(store.meta()?, before);
            let expired: u64 = store.writer()?.get()?.query_row(
                "SELECT COUNT(*) FROM expired_ranges",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(expired, 0);
            assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 2);
        }
        Ok(())
    }

    #[test]
    fn retention_bounds_segments() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(
            &root,
            RetentionLimitsV1 {
                raw_max_age_ns: Some(50),
                ..Default::default()
            },
            Default::default(),
        )?;
        let source = identity(1);
        let foreign = identity(2);
        for cursor in 1..=18 {
            store.accept_validated_batch(source.clone(), batch(cursor, b"x"))?;
            store.raw.lock().map_err(|_| "raw lock")?.seal_all()?;
        }
        store.accept_validated_batch(foreign.clone(), batch(1, b"z"))?;
        let scope = ProcessorScopeV1 {
            processor_id: "bounded-retention".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 18,
            body: vec![1],
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            ..crate::analysis::tests::result(scope, "bounded-pin".into())
        })?;
        let first = EvidenceRetentionOwner::new(&store).retain(&source, 200)?;
        assert_eq!(first.removed_records, RETENTION_SEGMENTS as u32);
        assert_eq!(first.retained_floor, 0);
        assert_eq!(store.read_page(&source, 1)?.records[0].framed_record, b"x");
        assert_eq!(store.read_page(&source, 18)?.records[0].cursor, 18);
        assert_eq!(store.read_page(&foreign, 1)?.records.len(), 1);
        drop(store);
        let store = AnalysisStore::open_with_limits(
            &root,
            RetentionLimitsV1 {
                raw_max_age_ns: Some(50),
                ..Default::default()
            },
            Default::default(),
        )?;
        let last = EvidenceRetentionOwner::new(&store).retain(&source, 300)?;
        assert_eq!(last.removed_records, 2);
        assert_eq!(last.retained_floor, 18);
        assert_eq!(store.read_page(&foreign, 1)?.records[0].framed_record, b"z");
        Ok(())
    }

    #[test]
    fn observability_retention_sweep() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        use crate::{AnalysisReadControl, TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(50),
            raw_max_bytes: Some(1024 * 1024),
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let evidence = identity(1);
        store.accept_validated_batch(evidence.clone(), batch(1, b"a"))?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let batch = TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"raw".to_vec(),
            }],
            terminal: Some(trace_terminal(1, 3)),
        };
        let mut expected = store.append_trace(identity, &batch, 100)?;
        store.checkpoint()?;
        let mut empty = intent.clone();
        empty.request_id = [5; 16];
        empty.bindings[0].identity.request_id = empty.request_id;
        empty.bindings[0].identity.execution_id = [6; 16];
        store.accept_trace(&empty)?;
        let owner = EvidenceRetentionOwner::new(&store);
        let result = owner.step(201)?;
        assert_eq!(result.removed_records, 3);
        assert!(!result.more);
        assert!(store.retention_healthy());
        expected.retained_floor = 2;
        assert_eq!(store.trace_receipt(identity)?, Some(expected.clone()));
        assert!(matches!(
            store.read_trace(identity, 1, &AnalysisReadControl::default()),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert!(matches!(
            store.append_trace(identity, &batch, 202),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(owner.retain_trace(identity, 202)?.removed_records, 0);
        let empty = &empty.bindings[0].identity;
        assert_eq!(owner.retain_trace(empty, 202)?.removed_records, 0);
        assert_eq!(
            store
                .trace_receipt(empty)?
                .ok_or("empty receipt absent")?
                .last_sequence,
            0
        );
        assert_eq!(
            store
                .source_receipt(&evidence)?
                .ok_or("evidence receipt absent")?
                .retained_floor,
            1
        );
        drop(store);
        let reopened = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        assert_eq!(reopened.trace_receipt(identity)?, Some(expected));
        assert!(matches!(
            reopened.read_trace(identity, 2, &AnalysisReadControl::default()),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert!(reopened
            .read_trace(identity, 3, &AnalysisReadControl::default())?
            .frames
            .is_empty());
        assert_eq!(
            EvidenceRetentionOwner::new(&reopened)
                .step(203)?
                .removed_records,
            0
        );
        Ok(())
    }

    #[test]
    fn query_follow_retention_commit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
        let source = identity(1);
        let older = EvidenceIntakeIdentityV1 {
            source_id: [4; 16],
            ..source.clone()
        };
        let foreign = identity(2);
        store.accept_validated_batch(older.clone(), batch(1, b"gh"))?;
        store.accept_validated_batch(source.clone(), batch(2, b"b"))?;
        store.accept_validated_batch(source.clone(), batch(4, b"d"))?;
        store.accept_validated_batch(source.clone(), batch(1, b"abcdef"))?;
        let expected = store.read_page(&source, 6)?.records[0].position;
        assert_eq!(expected.ordinal, 3);
        store.accept_validated_batch(foreign.clone(), batch(1, b"xy"))?;
        let foreign_position = store.read_page(&foreign, 2)?.records[0].position;
        assert_eq!(store.replay_floor(source.tenant_id)?, None);
        assert_eq!(store.replay_floor(foreign.tenant_id)?, None);
        assert!(store.replay_floor([0; 16]).is_err());
        let owner = EvidenceRetentionOwner::new(&store);
        let result = owner.retain(&source, u64::MAX)?;
        assert_eq!(result.removed_records, 6);
        assert!(expected.commit_revision < result.commit_revision);
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(expected));
        assert_eq!(owner.retain(&older, u64::MAX)?.removed_records, 2);
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(expected));
        assert_eq!(store.replay_floor(foreign.tenant_id)?, None);
        assert_eq!(owner.retain(&foreign, u64::MAX)?.removed_records, 2);
        assert_eq!(
            store.replay_floor(foreign.tenant_id)?,
            Some(foreign_position)
        );
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(expected));
        store.accept_validated_batch(source.clone(), batch(7, b"i"))?;
        let later = store.read_page(&source, 7)?.records[0].position;
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(expected));
        assert_eq!(owner.retain(&source, u64::MAX)?.removed_records, 1);
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(later));
        let before = store.meta()?;
        assert_eq!(owner.retain(&source, u64::MAX)?.removed_records, 0);
        assert_eq!(store.meta()?, before);
        store.read_snapshot(|snapshot| AnalysisStore::validate_state(snapshot, &store.root))?;
        Ok(())
    }

    #[test]
    fn query_follow_retention_restart() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let source = identity(1);
        if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
            let store = AnalysisStore::open_retention(std::path::PathBuf::from(root))?;
            EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
            return Err("the requested retention crash did not occur".into());
        }
        for point in [
            "retention.before",
            "retention.after",
            "retention.unlinked",
            "retention.cleaned",
        ] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open_retention(&root)?;
            store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
            let position = store.read_page(&source, 3)?.records[0].position;
            let before = store.meta()?;
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "analysis::retention::tests::query_follow_retention_restart",
                ])
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}");
            let committed = point != "retention.before";
            let expected = committed.then_some(position);
            {
                let snapshot = AnalysisStore::open_native(&root.join("analysis.duckdb"))?;
                assert_eq!(
                    AnalysisStore::replay_floor_from(&snapshot, source.tenant_id)?,
                    expected,
                    "{point}"
                );
                let deleting: bool = snapshot.query_row(
                    "SELECT EXISTS (SELECT 1 FROM segments WHERE state = 'Deleting')",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    deleting,
                    matches!(point, "retention.after" | "retention.unlinked"),
                    "{point}"
                );
            }
            let mut meta = before;
            meta.commit_revision += u64::from(committed);
            for _ in 0..2 {
                let reopened = AnalysisStore::open_retention(&root)?;
                assert_eq!(reopened.meta()?, meta, "{point}");
                assert_eq!(
                    reopened.replay_floor(source.tenant_id)?,
                    expected,
                    "{point}"
                );
                if committed {
                    assert!(matches!(
                        reopened.read_page(&source, 1),
                        Err(crate::Error::RetainedRangeExpired { .. })
                    ));
                } else {
                    assert_eq!(reopened.read_page(&source, 1)?.records.len(), 3);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn query_follow_retention_restore() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_retention(&root)?;
        let source = identity(1);
        store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
        let expected = store.read_page(&source, 3)?.records[0].position;
        EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
        store.accept_validated_batch(source.clone(), batch(4, b"d"))?;
        let before = store.meta()?;
        let backup = root.join("backups/floor");
        let manifest = store.backup(&backup)?;
        let restored_root = directory.path().join("restored");
        let restored = AnalysisStore::restore(&backup, &restored_root)?;
        let mut restored_meta = before.clone();
        restored_meta.recovery_epoch += 1;
        assert_eq!(restored.meta()?, restored_meta);
        assert_eq!(manifest.recovery_epoch, before.recovery_epoch);
        assert_eq!(restored.replay_floor(source.tenant_id)?, Some(expected));
        assert_eq!(restored.replay_floor(identity(2).tenant_id)?, None);
        assert_eq!(
            restored.read_page(&source, 4)?.records[0].framed_record,
            b"d"
        );
        assert_eq!(store.meta()?, before);
        drop(restored);
        let reopened = AnalysisStore::open_retention(&restored_root)?;
        assert_eq!(reopened.meta()?, restored_meta);
        assert_eq!(reopened.replay_floor(source.tenant_id)?, Some(expected));
        Ok(())
    }

    #[test]
    fn query_follow_retention_witness() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_retention(&root)?;
        let source = identity(1);
        let expires = 3 * 24 * 60 * 60 * 1_000_000_000;
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let witness_position = store.read_page(&source, 1)?.records[0].position;
        store.backup(&root.join("backups/sealed"))?;
        store.accept_validated_batch(source.clone(), batch(2, b"bc"))?;
        let floor = store.read_page(&source, 3)?.records[0].position;
        let scope = ProcessorScopeV1 {
            processor_id: "review".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 3,
            body: b"review".to_vec(),
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: expires,
            }],
            ..crate::analysis::tests::result(scope, "retained-witness".into())
        })?;
        let result = EvidenceRetentionOwner::new(&store).retain(&source, expires - 1)?;
        assert_eq!(result.removed_records, 2);
        assert_eq!(result.retained_floor, 0);
        assert_eq!(store.replay_floor(source.tenant_id)?, Some(floor));
        assert!(witness_position < floor);
        let page = store.read_page(&source, 1)?;
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].framed_record, b"a");
        assert_eq!(page.records[0].position, witness_position);
        assert_eq!(page.next_cursor, Some(2));
        assert!(matches!(
            store.read_page(&source, 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        let before = store.meta()?;
        drop(store);
        let reopened = AnalysisStore::open_retention(&root)?;
        assert_eq!(reopened.meta()?, before);
        assert_eq!(reopened.replay_floor(source.tenant_id)?, Some(floor));
        assert_eq!(
            reopened.read_page(&source, 1)?.records[0].position,
            witness_position
        );
        assert_eq!(
            EvidenceRetentionOwner::new(&reopened)
                .retain(&source, expires)?
                .removed_records,
            1
        );
        assert_eq!(reopened.replay_floor(source.tenant_id)?, Some(floor));
        reopened.read_snapshot(|snapshot| AnalysisStore::validate_state(snapshot, &root))?;
        Ok(())
    }

    #[test]
    fn query_follow_retention_validation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        const FRAMES: [u8; crate::MAX_EVIDENCE_BATCH_RECORDS] =
            [b'a'; crate::MAX_EVIDENCE_BATCH_RECORDS];
        for (index, mutation) in [
            format!(
                "UPDATE replay_floors SET ordinal = {}",
                crate::MAX_EVIDENCE_BATCH_RECORDS
            ),
            "UPDATE replay_floors SET commit_revision = 0".to_owned(),
            "UPDATE replay_floors SET commit_revision = (SELECT commit_revision FROM store_meta)"
                .to_owned(),
            "UPDATE replay_floors SET tenant_id = from_hex('01')".to_owned(),
            "DELETE FROM replay_floors".to_owned(),
            "UPDATE expired_ranges SET last_cursor = last_cursor + 1".to_owned(),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open_retention(&root)?;
            let source = identity(1);
            store.accept_validated_batch(source.clone(), batch(1, &FRAMES))?;
            let expected = StorePositionV1 {
                commit_revision: store.meta()?.commit_revision,
                ordinal: crate::MAX_EVIDENCE_BATCH_RECORDS as u32 - 1,
            };
            EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
            assert_eq!(store.replay_floor(source.tenant_id)?, Some(expected));
            store.read_snapshot(|snapshot| AnalysisStore::validate_state(snapshot, &root))?;
            store.writer()?.get()?.execute_batch(&mutation)?;
            assert!(
                matches!(
                    store.backup(&root.join("backups/invalid")),
                    Err(crate::Error::AnalysisState { .. })
                ),
                "case {index}"
            );
            drop(store);
            assert!(
                matches!(
                    AnalysisStore::open_retention(&root),
                    Err(crate::Error::AnalysisState { .. })
                ),
                "case {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn analysis_store_required_plan() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
        let source = identity(1);
        let scope = ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
        store.commit_result(&AnalysisResultCommitV1 {
            body: b"checked".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: 200,
            }],
            ..crate::analysis::tests::result(scope, "witness".into())
        })?;
        let writer = store.raw_access()?;
        {
            let raw = store.raw.lock().map_err(|_| "raw owner lock poisoned")?;
            assert_eq!(raw.budget.required.get(&source.key()), Some(&1));
            assert_eq!(raw.budget.protected.get(&source.tenant_id), Some(&2));
        }
        drop(writer);
        assert_eq!(
            EvidenceRetentionOwner::new(&store)
                .retain(&source, 101)?
                .removed_records,
            0
        );
        Ok(())
    }

    #[test]
    fn analysis_store_required_scopes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_bytes: Some(3),
                ..Default::default()
            },
            Default::default(),
        )?;
        let source = identity(1);
        let first = ProcessorScopeV1 {
            processor_id: "first".into(),
            method_version: 1,
            identity: source.clone(),
        };
        let second = ProcessorScopeV1 {
            processor_id: "second".into(),
            ..first.clone()
        };
        let optional = ProcessorScopeV1 {
            processor_id: "optional".into(),
            ..first.clone()
        };
        let foreign = ProcessorScopeV1 {
            identity: identity(2),
            ..first.clone()
        };
        for scope in [&first, &second, &foreign] {
            store.register_processor(scope, ProcessorClassV1::Required, 1)?;
        }
        store.register_processor(&optional, ProcessorClassV1::Optional, 1)?;
        store.accept_validated_batch(foreign.identity.clone(), batch(1, b"xyz"))?;
        store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
        for (scope, cursor) in [(&first, 2), (&second, 3)] {
            store.commit_result(&AnalysisResultCommitV1 {
                consumed_cursor: cursor,
                body: b"checked".to_vec(),
                created_utc_ns: 101,
                ..crate::analysis::tests::result(scope.clone(), scope.processor_id.clone())
            })?;
            if cursor == 2 {
                let before = store.meta()?;
                assert!(matches!(
                    store.accept_validated_batch(source.clone(), batch(4, b"d")),
                    Err(crate::Error::ProtectedInputCapacity {
                        resource: "bytes",
                        ..
                    })
                ));
                assert_eq!(store.meta()?, before);
            }
        }
        store.accept_validated_batch(source.clone(), batch(4, b"de"))?;
        store.retire_required(&crate::ProcessorRetirementV1 {
            scope: first,
            change_id: "retire-first".into(),
            reason: "test retirement".into(),
            expected_cursor: 2,
            cutoff_cursor: 5,
        })?;
        store.accept_validated_batch(source.clone(), batch(6, b"f"))?;
        let before = store.meta()?;
        assert!(matches!(
            store.accept_validated_batch(source, batch(7, b"g")),
            Err(crate::Error::ProtectedInputCapacity {
                resource: "bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        Ok(())
    }

    #[test]
    fn analysis_store_required_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let hour = 60 * 60 * 1_000_000_000;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_age_ns: Some(24 * hour),
                raw_max_bytes: Some(3),
            },
            Default::default(),
        )?;
        let source = identity(1);
        let scope = ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let mut later = batch(2, b"b");
        later.intake_utc_ns += hour;
        store.accept_validated_batch(source.clone(), later)?;
        let before = store.meta()?;
        let mut aged = batch(3, b"c");
        aged.intake_utc_ns += 24 * hour;
        assert!(matches!(
            store.accept_validated_batch(source.clone(), aged.clone()),
            Err(crate::Error::ProtectedInputCapacity {
                resource: "age",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        let mut retry = batch(1, b"ab");
        retry.intake_utc_ns = aged.intake_utc_ns;
        store.accept_validated_batch(source.clone(), retry)?;
        assert_eq!(store.meta()?, before);
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 2,
            body: b"checked".to_vec(),
            created_utc_ns: aged.intake_utc_ns,
            ..crate::analysis::tests::result(scope, "caught-up".into())
        })?;
        store.accept_validated_batch(source.clone(), aged)?;

        let mut other = source.clone();
        other.source_id = [4; 16];
        store.register_processor(
            &ProcessorScopeV1 {
                processor_id: "required".into(),
                method_version: 1,
                identity: other.clone(),
            },
            ProcessorClassV1::Required,
            1,
        )?;
        assert_eq!(
            store.accept_validated_batch(other.clone(), batch(2, b"y"))?,
            EvidenceStoreOutcomeV1::Pending
        );
        let mut repair = batch(1, b"x");
        repair.intake_utc_ns += 48 * hour;
        store.accept_validated_batch(other.clone(), repair)?;
        let before = store.meta()?;
        let mut excess = batch(3, b"z");
        assert!(matches!(
            store.accept_validated_batch(other.clone(), excess.clone()),
            Err(crate::Error::ProtectedInputCapacity {
                resource: "bytes",
                ..
            })
        ));
        excess.intake_utc_ns += 48 * hour;
        assert!(matches!(
            store.accept_validated_batch(other.clone(), excess),
            Err(crate::Error::ProtectedInputCapacity {
                resource: "age",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store
                .source_receipt(&other)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(
            store
                .source_status(&other)?
                .ok_or("status absent")?
                .retained_event_count,
            2
        );
        let optional = identity(2);
        store.register_processor(
            &ProcessorScopeV1 {
                processor_id: "optional".into(),
                method_version: 1,
                identity: optional.clone(),
            },
            ProcessorClassV1::Optional,
            1,
        )?;
        store.accept_validated_batch(optional, batch(1, b"abcd"))?;
        Ok(())
    }

    #[test]
    fn analysis_store_sweep_pages() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(50),
            raw_max_bytes: Some(100),
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let mut sources = Vec::new();
        for index in 1..=RETENTION_SEGMENTS + 2 {
            let mut source = identity(1);
            source.source_id = [index as u8; 16];
            store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
            sources.push(source);
        }
        store.register_processor(
            &ProcessorScopeV1 {
                processor_id: "required".into(),
                method_version: 1,
                identity: sources[0].clone(),
            },
            ProcessorClassV1::Required,
            1,
        )?;
        let owner = EvidenceRetentionOwner::new(&store);
        let first = owner.step(200)?;
        assert_eq!(first.removed_records, RETENTION_SEGMENTS as u32);
        assert!(first.more);
        let second = owner.step(200)?;
        assert_eq!(second.removed_records, 1);
        assert!(!second.more);
        assert_eq!(
            first.removed_records + second.removed_records,
            RETENTION_SEGMENTS as u32 + 1
        );
        assert_eq!(store.read_page(&sources[0], 1)?.records.len(), 1);
        for source in &sources[1..] {
            assert_eq!(
                store
                    .source_receipt(source)?
                    .ok_or("receipt absent")?
                    .retained_floor,
                1
            );
        }
        assert_eq!(owner.step(200)?.removed_records, 0);
        assert!(store.retention_healthy());
        Ok(())
    }

    #[test]
    fn retention_waits_for_maintenance() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
        let writer = store.maintenance_writer()?;
        let maintenance = store.maintenance.write().map_err(|_| "poisoned lock")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let (early, result) = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let result = EvidenceRetentionOwner::new(&store).step(100);
                let _sent = sender.send(());
                result
            });
            let early = receiver.recv_timeout(std::time::Duration::from_millis(1200));
            drop(maintenance);
            drop(writer);
            (early, worker.join())
        });
        assert!(matches!(
            early,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            result
                .map_err(|_| "retention thread panicked")??
                .removed_records,
            0
        );
        assert!(store.retention_healthy());
        Ok(())
    }

    #[test]
    fn analysis_store_sweep_failure() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
        let source = identity(1);
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let before = store.meta()?;
        let owner = EvidenceRetentionOwner::new(&store);
        store
            .writer()?
            .get()?
            .execute_batch("ALTER TABLE expired_ranges RENAME TO missing_expiry")?;
        assert!(owner.step(u64::MAX).is_err());
        assert!(!store.retention_healthy());
        assert!(matches!(
            store.accept_validated_batch(source.clone(), batch(2, b"b")),
            Err(crate::Error::RetentionUnavailable { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        store
            .writer()?
            .get()?
            .execute_batch("ALTER TABLE missing_expiry RENAME TO expired_ranges")?;
        assert_eq!(owner.step(100)?.removed_records, 0);
        assert!(store.retention_healthy());
        store.accept_validated_batch(source.clone(), batch(2, b"b"))?;
        assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 2);
        let reader = store.writer()?.get()?.try_clone()?;
        reader.execute_batch("BEGIN TRANSACTION; SELECT * FROM segments")?;
        let pending = store.meta()?;
        let failed = owner.step(u64::MAX);
        assert!(
            matches!(
                failed,
                Err(crate::Error::AnalysisDatabase {
                    operation: "checkpoint analysis database",
                    ..
                })
            ),
            "{failed:?}"
        );
        assert!(!store.retention_healthy());
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or("source status absent")?
                .retained_event_count,
            0
        );
        assert!(matches!(
            store.read_page(&source, 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert!(matches!(
            store.accept_validated_batch(source.clone(), batch(3, b"c")),
            Err(crate::Error::RetentionUnavailable { .. })
        ));
        let expired = store.meta()?;
        assert_eq!(expired.commit_revision, pending.commit_revision + 1);
        assert!(owner.step(u64::MAX).is_err());
        assert!(!store.retention_healthy());
        assert_eq!(store.meta()?, expired);
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or("source status absent")?
                .retained_event_count,
            0
        );
        reader.execute_batch("ROLLBACK")?;
        assert_eq!(owner.step(u64::MAX)?.removed_records, 0);
        assert!(store.retention_healthy());
        assert_eq!(store.meta()?, expired);
        drop(reader);
        drop(store);
        let store = AnalysisStore::open_retention(directory.path().join("analysis"))?;
        assert_eq!(store.meta()?, expired);
        assert!(matches!(
            store.read_page(&source, 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        Ok(())
    }

    #[test]
    fn analysis_store_retention_guards() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(50),
            raw_max_bytes: Some(10),
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let source = identity(1);
        let other = identity(2);
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(1, b"abc"))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        store.accept_validated_batch(other.clone(), batch(1, b"xyz"))?;
        let scope = ProcessorScopeV1 {
            processor_id: "security".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        let review = ProcessorScopeV1 {
            processor_id: "review".into(),
            ..scope.clone()
        };
        store.register_processor(&review, ProcessorClassV1::Required, 1)?;
        store.register_processor(
            &ProcessorScopeV1 {
                processor_id: "optional".into(),
                ..scope.clone()
            },
            ProcessorClassV1::Optional,
            1,
        )?;
        store.register_processor(
            &ProcessorScopeV1 {
                identity: other.clone(),
                ..scope.clone()
            },
            ProcessorClassV1::Required,
            1,
        )?;
        let owner = EvidenceRetentionOwner::new(&store);
        assert_eq!(owner.retain(&source, 200)?.removed_records, 0);
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 2,
            created_utc_ns: 150,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            ..crate::analysis::tests::result(scope.clone(), "finding-a".into())
        })?;
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 3,
            body: b"checked".to_vec(),
            created_utc_ns: 150,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: 200,
            }],
            ..crate::analysis::tests::result(review, "review".into())
        })?;
        let first = owner.retain(&source, 200)?;
        assert_eq!(first.removed_records, 0);
        assert_eq!(first.retained_floor, 0);
        assert!(first.retained_bytes > 3);
        assert_eq!(store.read_page(&source, 2)?.records.len(), 2);
        let witness = store.read_page(&source, 1)?;
        assert_eq!(witness.records.len(), 3);
        assert_eq!(witness.records[0].cursor, 1);
        assert_eq!(witness.next_cursor, None);
        assert_eq!(store.read_page(&source, 3)?.records[0].cursor, 3);
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2, b"b"))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2, b"bc"))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.read_page(&other, 1)?.records.len(), 3);
        let second = owner.retain(&source, 300)?;
        assert_eq!(second.removed_records, 0);
        assert_eq!(second.retained_floor, 0);
        assert!(store
            .accept_validated_batch(source.clone(), batch(2, b"bad"))
            .is_err());
        assert_eq!(
            store
                .source_receipt(&source)?
                .ok_or_else(|| std::io::Error::other("source receipt absent"))?
                .contiguous_cursor,
            3
        );
        store.commit_result(&AnalysisResultCommitV1 {
            expected_cursor: 2,
            consumed_cursor: 3,
            created_utc_ns: 300,
            ..crate::analysis::tests::result(scope, "finding-b".into())
        })?;
        let third = owner.retain(&source, 300)?;
        assert_eq!(third.removed_records, 3);
        assert_eq!(third.retained_floor, 3);
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2, b"b"))?,
            EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
        );
        assert!(store
            .accept_validated_batch(source.clone(), batch(2, b"bcd"))
            .is_err());
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or_else(|| std::io::Error::other("source status absent"))?
                .retained_event_count,
            0
        );
        Ok(())
    }

    #[test]
    fn analysis_store_physical_reuse() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest as _, Sha256};

        const ROWS: u64 = 512;
        const CYCLES: u64 = 5;
        const BATCH: u64 = 64;
        const FRAME_BYTES: usize = 16 * 1024;
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(100),
            raw_max_bytes: Some(1024 * 1024 * 1024),
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let source = identity(1);
        let owner = EvidenceRetentionOwner::new(&store);
        let mut first_peak = 0;
        let mut witness = Vec::new();
        for cycle in 0..CYCLES {
            let intake = 100 + cycle * 1000;
            for offset in (0..ROWS).step_by(BATCH as usize) {
                let first = cycle * ROWS + offset + 1;
                let mut frames = Vec::with_capacity(BATCH as usize * FRAME_BYTES);
                for cursor in first..first + BATCH {
                    for block in 0..FRAME_BYTES / 32 {
                        let mut hash = Sha256::new();
                        hash.update(cursor.to_be_bytes());
                        hash.update((block as u64).to_be_bytes());
                        frames.extend_from_slice(&hash.finalize());
                    }
                }
                assert_eq!(
                    store.accept_validated_batch(
                        source.clone(),
                        ValidatedEvidenceBatchV1 {
                            cpu_id: 0,
                            first_cursor: first,
                            last_cursor: first + BATCH - 1,
                            intake_utc_ns: intake,
                            framed_records: frames.into(),
                            frame_ends: (1..=BATCH as usize).map(|row| row * FRAME_BYTES).collect(),
                        }
                    )?,
                    EvidenceStoreOutcomeV1::Accepted
                );
            }
            if cycle == 0 {
                witness = store.read_page(&source, ROWS)?.records[0]
                    .framed_record
                    .clone();
                let scope = ProcessorScopeV1 {
                    processor_id: "review".into(),
                    method_version: 1,
                    identity: source.clone(),
                };
                store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
                store.commit_result(&AnalysisResultCommitV1 {
                    consumed_cursor: ROWS,
                    body: b"review".to_vec(),
                    created_utc_ns: intake,
                    witnesses: vec![AnalysisWitnessV1 {
                        identity: source.clone().into(),
                        cursor: ROWS,
                        expires_utc_ns: 10_000,
                    }],
                    ..crate::analysis::tests::result(scope, "retained-witness".into())
                })?;
            }
            store.checkpoint()?;
            let peak = store.storage_usage()?.allocated_bytes;
            assert!(peak >= ROWS * FRAME_BYTES as u64);
            if cycle < 2 {
                first_peak = first_peak.max(peak);
            } else {
                assert!(
                    peak <= first_peak + ROWS * FRAME_BYTES as u64 + 1024 * 1024,
                    "cycle {cycle} grew from {first_peak} to {peak} bytes"
                );
            }
            let expected = match cycle {
                0 => 0,
                1 => BATCH,
                _ => ROWS,
            };
            let sweep = owner.step(intake + 101)?;
            assert_eq!(sweep.removed_records as u64, expected);
            let retained = store.source_status(&source)?.ok_or("source is absent")?;
            assert_eq!(
                retained.retained_event_count,
                if cycle == 0 { ROWS } else { 15 * BATCH }
            );
            assert_eq!(retained.receipt.contiguous_cursor, (cycle + 1) * ROWS);
            assert_eq!(retained.receipt.retained_floor, 0);
            assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 1);
            assert_eq!(
                store.read_page(&source, ROWS)?.records[0].framed_record,
                witness
            );
            if cycle > 0 {
                assert!(matches!(
                    store.read_page(&source, (cycle + 1) * ROWS),
                    Err(crate::Error::RetainedRangeExpired { .. })
                ));
            }
            assert!(!root.join("analysis.duckdb.wal").exists());
        }
        let pinned = store.storage_usage()?.allocated_bytes;
        assert_eq!(owner.step(10_000)?.removed_records as u64, 15 * BATCH);
        let cleared = store.storage_usage()?.allocated_bytes;
        assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
        assert!(
            cleared + 14 * 1024 * 1024 < pinned,
            "segment deletion did not release blocks: {pinned} -> {cleared}"
        );
        let before = store.meta()?;
        drop(store);
        let reopened = AnalysisStore::open_with_limits(root, limits, Default::default())?;
        assert_eq!(reopened.meta()?, before);
        let receipt = reopened
            .source_receipt(&source)?
            .ok_or("source is absent")?;
        assert_eq!(
            (receipt.contiguous_cursor, receipt.retained_floor),
            (CYCLES * ROWS, CYCLES * ROWS)
        );
        Ok(())
    }

    #[test]
    fn analysis_store_retention_pressure() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let source = identity(1);
        let optional = ProcessorScopeV1 {
            processor_id: "discovery".into(),
            method_version: 1,
            identity: source.clone(),
        };
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(1_000),
            raw_max_bytes: Some(1),
        };
        {
            let store = AnalysisStore::open_with_limits(&path, limits, Default::default())?;
            store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
            store.register_processor(&optional, ProcessorClassV1::Optional, 1)?;
            let owner = EvidenceRetentionOwner::new(&store);
            let result = owner.retain(&source, 101)?;
            assert_eq!(result.removed_records, 3);
            assert_eq!(result.retained_bytes, 0);
            assert_eq!(result.retained_floor, 3);
            assert!(matches!(
                store.read_page(&source, 3),
                Err(crate::Error::RetainedRangeExpired { .. })
            ));
        }
        let reopened = AnalysisStore::open_with_limits(path, limits, Default::default())?;
        assert!(matches!(
            reopened.read_page(&source, 1),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert!(matches!(
            reopened.read_page(&source, 3),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        let gap = reopened
            .resume_optional(&optional)?
            .ok_or_else(|| std::io::Error::other("optional gap absent"))?;
        assert_eq!((gap.first_cursor, gap.last_cursor), (1, 3));
        assert_eq!(reopened.resume_optional(&optional)?, None);
        reopened.accept_validated_batch(source.clone(), batch(4, b"d"))?;
        reopened.commit_result(&AnalysisResultCommitV1 {
            expected_cursor: 3,
            consumed_cursor: 4,
            body: b"incomplete".to_vec(),
            created_utc_ns: 101,
            ..crate::analysis::tests::result(optional, "profile-after-gap".into())
        })?;
        let scope = ProcessorScopeV1 {
            processor_id: "late-security".into(),
            method_version: 1,
            identity: source,
        };
        assert!(reopened
            .register_processor(&scope, ProcessorClassV1::Required, 1)
            .is_err());
        reopened.register_processor(&scope, ProcessorClassV1::Required, 4)?;
        assert!(reopened
            .register_processor(&scope, ProcessorClassV1::Required, 2)
            .is_err());
        let backup_dir = reopened.root.join("backups");
        let backup = backup_dir.join("retained");
        let manifest = reopened.backup(&backup)?;
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
        assert_eq!(
            restored
                .source_receipt(&scope.identity)?
                .ok_or_else(|| { std::io::Error::other("restored source receipt absent") })?
                .retained_floor,
            3
        );
        assert_eq!(restored.read_page(&scope.identity, 4)?.records.len(), 1);
        Ok(())
    }
}
