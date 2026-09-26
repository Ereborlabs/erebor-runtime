use duckdb::{params, params_from_iter, types::Value};
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result};

const RETENTION_BATCH: usize = 256;
const SWEEP_SOURCES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionLimitsV1 {
    pub raw_max_age_ns: u64,
    pub raw_max_bytes: u64,
}

impl Default for RetentionLimitsV1 {
    fn default() -> Self {
        Self {
            raw_max_age_ns: 24 * 60 * 60 * 1_000_000_000,
            raw_max_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionSweepV1 {
    pub next_source: Option<[u8; 32]>,
    pub checked_sources: u32,
    pub removed_records: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionResultV1 {
    pub removed_records: u32,
    pub retained_bytes: u64,
    pub retained_floor: u64,
    pub commit_revision: u64,
}

pub struct EvidenceRetentionOwner<'a> {
    store: &'a AnalysisStore,
    limits: RetentionLimitsV1,
}

impl<'a> EvidenceRetentionOwner<'a> {
    pub fn new(store: &'a AnalysisStore, limits: RetentionLimitsV1) -> Result<Self> {
        if limits.raw_max_age_ns == 0 || limits.raw_max_bytes == 0 {
            return store.reject("the raw retention limits must be positive");
        }
        Ok(Self { store, limits })
    }

    pub fn sweep(&self, after: Option<[u8; 32]>, now_utc_ns: u64) -> Result<RetentionSweepV1> {
        if now_utc_ns == 0 {
            return self.store.reject("the retention time is invalid");
        }
        let result = self.sweep_page(after, now_utc_ns);
        self.store
            .retention_healthy
            .store(result.is_ok(), std::sync::atomic::Ordering::Release);
        result
    }

    fn sweep_page(&self, after: Option<[u8; 32]>, now_utc_ns: u64) -> Result<RetentionSweepV1> {
        let sources = {
            let reader = self.store.reader()?;
            let mut statement = reader
                .prepare(
                    "SELECT stream_key, identity_json FROM source_receipts
                     WHERE CAST(? AS BLOB) IS NULL OR stream_key > ?
                     ORDER BY stream_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare retention source page",
                })?;
            statement
                .query_map(
                    params![
                        after.as_ref().map(|key| key.as_slice()),
                        after.as_ref().map(|key| key.as_slice()),
                        SWEEP_SOURCES as u32
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read retention source page",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode retention source page",
                })?
        };
        let mut result = RetentionSweepV1 {
            next_source: None,
            checked_sources: sources.len() as u32,
            removed_records: 0,
        };
        for (key, json) in &sources {
            let identity: EvidenceIntakeIdentityV1 =
                serde_json::from_str(json).context(crate::JsonSnafu {
                    path: &self.store.root,
                })?;
            if !valid_source_identity(&identity) || source_key(&identity).as_slice() != key {
                return self
                    .store
                    .reject("the retention source identity is invalid");
            }
            result.removed_records += self.retain(&identity, now_utc_ns)?.removed_records;
            if sources.len() == SWEEP_SOURCES {
                result.next_source = Some(source_key(&identity));
            }
        }
        if result.removed_records > 0 || !self.store.retention_healthy() {
            self.store.checkpoint()?;
        }
        Ok(result)
    }

    pub fn retain(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        now_utc_ns: u64,
    ) -> Result<RetentionResultV1> {
        if !valid_source_identity(identity) || now_utc_ns == 0 {
            return self.store.reject("the retention source or time is invalid");
        }
        let key = source_key(identity);
        let mut writer = self.store.maintenance_writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin evidence retention",
        })?;
        let receipt =
            AnalysisStore::read_receipt_from(&transaction, &self.store.root, identity, &key)?
                .ok_or_else(|| self.store.state_error("the retention source is absent"))?;
        let mut retained_bytes: u64 = transaction
            .query_row(
                "SELECT CAST(COALESCE(SUM(octet_length(framed_record)), 0) AS UBIGINT)
                 FROM events WHERE stream_key = ? AND tenant_id = ?",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count retained raw bytes",
            })?;
        let cutoff = now_utc_ns.saturating_sub(self.limits.raw_max_age_ns);
        let mut tenant_bytes: u64 = transaction
            .query_row(
                "SELECT CAST(COALESCE(SUM(octet_length(framed_record)), 0) AS UBIGINT)
             FROM events WHERE tenant_id = ?",
                params![identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count tenant raw bytes",
            })?;
        let logical_pressure = self
            .store
            .logical_pressure(&transaction, identity.tenant_id)?;
        let mut selected = Vec::new();
        {
            let mut statement = transaction
                .prepare(
                    "SELECT e.durable_cursor, octet_length(e.framed_record), e.intake_utc_ns
                     FROM events e WHERE e.stream_key = ? AND e.tenant_id = ?
                     AND e.durable_cursor <= ?
                     AND NOT EXISTS (
                         SELECT 1 FROM processor_progress p
                         WHERE p.stream_key = e.stream_key AND p.tenant_id = e.tenant_id
                         AND p.class = 'required' AND p.retired = false
                         AND p.consumed_cursor < e.durable_cursor
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM evidence_refs r
                         WHERE r.stream_key = e.stream_key AND r.tenant_id = e.tenant_id
                         AND r.durable_cursor = e.durable_cursor AND r.expires_utc_ns > ?
                     )
                     AND (e.intake_utc_ns <= ? OR ?)
                     ORDER BY e.durable_cursor LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare eligible raw evidence",
                })?;
            let rows = statement
                .query_map(
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        receipt.contiguous_cursor,
                        now_utc_ns,
                        cutoff,
                        tenant_bytes > self.limits.raw_max_bytes || logical_pressure,
                        RETENTION_BATCH as u32,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, Option<u64>>(2)?,
                        ))
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "scan eligible raw evidence",
                })?;
            for row in rows {
                let (cursor, bytes, intake) = row.context(AnalysisDatabaseSnafu {
                    operation: "read eligible raw evidence",
                })?;
                if intake.is_some_and(|time| time <= cutoff)
                    || tenant_bytes > self.limits.raw_max_bytes
                    || logical_pressure
                {
                    tenant_bytes = tenant_bytes
                        .checked_sub(bytes)
                        .ok_or_else(|| self.store.state_error("tenant raw bytes underflow"))?;
                    retained_bytes = retained_bytes
                        .checked_sub(bytes)
                        .ok_or_else(|| self.store.state_error("retained raw bytes underflow"))?;
                    selected.push(cursor);
                }
            }
        }
        let meta =
            AnalysisStore::read_meta_from(&transaction, &self.store.root.join("analysis.duckdb"))?;
        if selected.is_empty() {
            return Ok(RetentionResultV1 {
                removed_records: 0,
                retained_bytes,
                retained_floor: receipt.retained_floor,
                commit_revision: meta.commit_revision,
            });
        }
        let revision = meta.commit_revision.checked_add(1).ok_or_else(|| {
            self.store
                .state_error("the analysis commit revision is exhausted")
        })?;
        let marks = vec!["?"; selected.len()].join(",");
        let mut values = vec![
            Value::Blob(key.to_vec()),
            Value::Blob(identity.tenant_id.to_vec()),
        ];
        values.extend(selected.iter().copied().map(Value::UBigInt));
        let deleted = transaction
            .execute(
                &format!(
                    "DELETE FROM events WHERE stream_key = ? AND tenant_id = ?
                    AND durable_cursor IN ({marks})"
                ),
                params_from_iter(values),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "expire eligible raw evidence",
            })?;
        if deleted != selected.len() {
            return self
                .store
                .reject("eligible raw evidence changed during retention");
        }
        let mut first = selected[0];
        let mut last = first;
        for cursor in selected.iter().copied().skip(1) {
            if last.checked_add(1) == Some(cursor) {
                last = cursor;
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO expired_ranges VALUES (?, ?, ?, ?, ?)",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        first,
                        last,
                        revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "record expired raw range",
                })?;
            first = cursor;
            last = cursor;
        }
        transaction
            .execute(
                "INSERT INTO expired_ranges VALUES (?, ?, ?, ?, ?)",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    first,
                    last,
                    revision
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "record expired raw range",
            })?;
        let next_retained: Option<u64> = transaction
            .query_row(
                "SELECT MIN(durable_cursor) FROM events
                 WHERE stream_key = ? AND tenant_id = ? AND durable_cursor <= ?",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    receipt.contiguous_cursor
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "find retained raw floor",
            })?;
        let retained_floor = next_retained.map_or(receipt.contiguous_cursor, |cursor| cursor - 1);
        if retained_floor > receipt.retained_floor {
            transaction
                .execute(
                    "UPDATE source_receipts SET retained_floor = ? WHERE stream_key = ?",
                    params![retained_floor, key.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance retained raw floor",
                })?;
        }
        transaction
            .execute(
                "DELETE FROM evidence_refs WHERE stream_key = ? AND tenant_id = ? AND expires_utc_ns <= ?",
                params![key.as_slice(), identity.tenant_id.as_slice(), now_utc_ns],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "remove expired witness references",
            })?;
        let mut relations = vec!["events", "expired_ranges", "evidence_refs"];
        if retained_floor > receipt.retained_floor {
            relations.push("source_receipts");
        }
        AnalysisStore::record_revision(&transaction, revision, &relations)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit evidence retention",
        })?;
        self.store.revision.send_replace(revision);
        Ok(RetentionResultV1 {
            removed_records: selected.len() as u32,
            retained_bytes,
            retained_floor,
            commit_revision: revision,
        })
    }
}

impl AnalysisStore {
    pub(super) fn check_required(
        &self,
        transaction: &duckdb::Transaction<'_>,
        identity: &EvidenceIntakeIdentityV1,
        now: u64,
    ) -> Result<()> {
        let key = source_key(identity);
        let required: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM processor_progress
             WHERE tenant_id = ? AND stream_key = ? AND class = 'required' AND retired = false)",
                params![identity.tenant_id.as_slice(), key.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check required source scope",
            })?;
        if !required {
            return Ok(());
        }
        let (oldest, bytes): (Option<u64>, u64) = transaction
            .query_row(
                "SELECT MIN(CASE WHEN e.stream_key = ? AND e.durable_cursor <= r.contiguous_cursor
                        THEN e.intake_utc_ns END),
                    CAST(COALESCE(SUM(octet_length(e.framed_record)), 0) AS UBIGINT)
             FROM events e LEFT JOIN source_receipts r ON e.stream_key = r.stream_key
                AND e.tenant_id = r.tenant_id
             WHERE e.tenant_id = ? AND EXISTS (
                 SELECT 1 FROM processor_progress p WHERE p.stream_key = e.stream_key
                 AND p.tenant_id = e.tenant_id AND p.class = 'required' AND p.retired = false
                 AND p.consumed_cursor < e.durable_cursor)",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read required input budget",
            })?;
        if oldest.is_some_and(|time| now.saturating_sub(time) >= self.retention.raw_max_age_ns) {
            return crate::ProtectedInputCapacitySnafu { resource: "age" }.fail();
        }
        if bytes > self.retention.raw_max_bytes {
            return crate::ProtectedInputCapacitySnafu { resource: "bytes" }.fail();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt as _;

    use super::*;
    use crate::{
        AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceStoreOutcomeV1, ProcessorClassV1,
        ProcessorScopeV1, ValidatedEvidenceBatchV1,
    };

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
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
    fn analysis_store_required_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let hour = 60 * 60 * 1_000_000_000;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_age_ns: 24 * hour,
                raw_max_bytes: 3,
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
            scope,
            expected_cursor: 0,
            consumed_cursor: 2,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "caught-up".into(),
            body: b"checked".to_vec(),
            created_utc_ns: aged.intake_utc_ns,
            witnesses: vec![],
            context_refs: vec![],
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
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut sources = Vec::new();
        for index in 1..=SWEEP_SOURCES + 1 {
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
        let owner = EvidenceRetentionOwner::new(
            &store,
            RetentionLimitsV1 {
                raw_max_age_ns: 50,
                raw_max_bytes: 100,
            },
        )?;
        let first = owner.sweep(None, 200)?;
        assert_eq!(first.checked_sources, SWEEP_SOURCES as u32);
        assert!(first.next_source.is_some());
        let second = owner.sweep(first.next_source, 200)?;
        assert_eq!(second.checked_sources, 1);
        assert_eq!(second.next_source, None);
        assert_eq!(
            first.removed_records + second.removed_records,
            SWEEP_SOURCES as u32
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
        assert_eq!(owner.sweep(None, 200)?.removed_records, 0);
        assert!(store.retention_healthy());
        Ok(())
    }

    #[test]
    fn analysis_store_sweep_failure() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let source = identity(1);
        store.accept_validated_batch(source.clone(), batch(1, b"a"))?;
        let before = store.meta()?;
        let owner = EvidenceRetentionOwner::new(&store, Default::default())?;
        store
            .writer()?
            .execute_batch("ALTER TABLE expired_ranges RENAME TO missing_expiry")?;
        assert!(owner.sweep(None, u64::MAX).is_err());
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
            .execute_batch("ALTER TABLE missing_expiry RENAME TO expired_ranges")?;
        assert_eq!(owner.sweep(None, 100)?.removed_records, 0);
        assert!(store.retention_healthy());
        store.accept_validated_batch(source.clone(), batch(2, b"b"))?;
        let reader = store.writer()?.try_clone()?;
        reader.execute_batch("BEGIN TRANSACTION; SELECT * FROM events")?;
        assert!(owner.sweep(None, u64::MAX).is_err());
        assert!(!store.retention_healthy());
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or("source status absent")?
                .retained_event_count,
            0
        );
        assert!(owner.sweep(None, u64::MAX).is_err());
        assert!(!store.retention_healthy());
        reader.execute_batch("ROLLBACK")?;
        assert_eq!(owner.sweep(None, u64::MAX)?.removed_records, 0);
        assert!(store.retention_healthy());
        Ok(())
    }

    #[test]
    fn analysis_store_retention_respects_progress_and_witnesses(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
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
        let owner = EvidenceRetentionOwner::new(
            &store,
            RetentionLimitsV1 {
                raw_max_age_ns: 50,
                raw_max_bytes: 10,
            },
        )?;
        assert_eq!(owner.retain(&source, 200)?.removed_records, 0);
        store.commit_result(&AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 2,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "finding-a".into(),
            body: b"finding".to_vec(),
            created_utc_ns: 150,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone(),
                cursor: 1,
                expires_utc_ns: 300,
            }],
            context_refs: vec![],
        })?;
        let first = owner.retain(&source, 200)?;
        assert_eq!(first.removed_records, 1);
        assert_eq!(first.retained_floor, 0);
        assert_eq!(first.retained_bytes, 2);
        assert!(matches!(
            store.read_page(&source, 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert!(matches!(
            store.read_page(&source, 1),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2, b"b"))?,
            EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
        );
        assert!(store
            .accept_validated_batch(source.clone(), batch(2, b"bc"))
            .is_err());
        assert_eq!(store.read_page(&other, 1)?.records.len(), 3);
        let second = owner.retain(&source, 300)?;
        assert_eq!(second.removed_records, 1);
        assert_eq!(second.retained_floor, 2);
        assert!(store
            .accept_validated_batch(source.clone(), batch(2, b"bcd"))
            .is_err());
        assert_eq!(
            store
                .source_receipt(&source)?
                .ok_or_else(|| std::io::Error::other("source receipt absent"))?
                .contiguous_cursor,
            3
        );
        store.commit_result(&AnalysisResultCommitV1 {
            scope,
            expected_cursor: 2,
            consumed_cursor: 3,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "finding-b".into(),
            body: b"finding".to_vec(),
            created_utc_ns: 300,
            witnesses: vec![],
            context_refs: vec![],
        })?;
        let third = owner.retain(&source, 300)?;
        assert_eq!(third.removed_records, 1);
        assert_eq!(third.retained_floor, 3);
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
    fn analysis_store_retention_reclaims_byte_pressure(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let source = identity(1);
        let optional = ProcessorScopeV1 {
            processor_id: "discovery".into(),
            method_version: 1,
            identity: source.clone(),
        };
        {
            let store = AnalysisStore::open(&path)?;
            store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
            store.register_processor(&optional, ProcessorClassV1::Optional, 1)?;
            let owner = EvidenceRetentionOwner::new(
                &store,
                RetentionLimitsV1 {
                    raw_max_age_ns: 1_000,
                    raw_max_bytes: 1,
                },
            )?;
            let result = owner.retain(&source, 101)?;
            assert_eq!(result.removed_records, 2);
            assert_eq!(result.retained_bytes, 1);
            assert_eq!(result.retained_floor, 2);
            assert_eq!(store.read_page(&source, 3)?.records.len(), 1);
        }
        let reopened = AnalysisStore::open(path)?;
        assert!(matches!(
            reopened.read_page(&source, 1),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(reopened.read_page(&source, 3)?.records.len(), 1);
        let gap = reopened
            .resume_optional(&optional)?
            .ok_or_else(|| std::io::Error::other("optional gap absent"))?;
        assert_eq!((gap.first_cursor, gap.last_cursor), (1, 2));
        assert_eq!(reopened.resume_optional(&optional)?, None);
        reopened.commit_result(&AnalysisResultCommitV1 {
            scope: optional,
            expected_cursor: 2,
            consumed_cursor: 3,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "profile-after-gap".into(),
            body: b"incomplete".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![],
            context_refs: vec![],
        })?;
        let scope = ProcessorScopeV1 {
            processor_id: "late-security".into(),
            method_version: 1,
            identity: source,
        };
        assert!(reopened
            .register_processor(&scope, ProcessorClassV1::Required, 1)
            .is_err());
        reopened.register_processor(&scope, ProcessorClassV1::Required, 3)?;
        assert!(reopened
            .register_processor(&scope, ProcessorClassV1::Required, 2)
            .is_err());
        let backup_dir = directory.path().join("backups");
        std::fs::DirBuilder::new().mode(0o700).create(&backup_dir)?;
        let backup = backup_dir.join("retained.backup.duckdb");
        let manifest = reopened.backup(&backup)?;
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
        assert_eq!(
            restored
                .source_receipt(&scope.identity)?
                .ok_or_else(|| { std::io::Error::other("restored source receipt absent") })?
                .retained_floor,
            2
        );
        assert_eq!(restored.read_page(&scope.identity, 3)?.records.len(), 1);
        Ok(())
    }
}
