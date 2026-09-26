use duckdb::params;
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result};

const RETENTION_BATCH: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionLimitsV1 {
    pub raw_max_age_ns: u64,
    pub raw_max_bytes: u64,
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

    pub fn retain(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        now_utc_ns: u64,
    ) -> Result<RetentionResultV1> {
        if !valid_source_identity(identity) || now_utc_ns == 0 {
            return self.store.reject("the retention source or time is invalid");
        }
        let key = source_key(identity);
        let mut writer = self.store.writer()?;
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
                        retained_bytes > self.limits.raw_max_bytes,
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
                    || retained_bytes > self.limits.raw_max_bytes
                {
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
        for cursor in &selected {
            let deleted = transaction
                .execute(
                    "DELETE FROM events WHERE stream_key = ? AND tenant_id = ? AND durable_cursor = ?",
                    params![key.as_slice(), identity.tenant_id.as_slice(), cursor],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "expire eligible raw evidence",
                })?;
            if deleted != 1 {
                return self
                    .store
                    .reject("eligible raw evidence changed during retention");
            }
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
