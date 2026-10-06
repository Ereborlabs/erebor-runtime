use duckdb::params;
use snafu::ResultExt as _;

use super::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, AnalysisStoreMetaV1};
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    /// Read the last relevant commit and current metadata without decoding event payloads.
    pub fn dependency_revision(
        &self,
        selection: &AnalysisSelectionV1,
        control: &AnalysisReadControl,
    ) -> Result<(AnalysisStoreMetaV1, u64)> {
        control.check()?;
        if !selection.valid() || !selection.results.is_empty() {
            return self
                .reject("the dependency selection is invalid or includes unsupported results");
        }
        let coordinator = self.read_coordinator(control)?;
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            drop(coordinator);
            let mut revision = self.selected_revision(selection, meta.commit_revision, control)?;
            let mut sources = snapshot
                .prepare(
                    "SELECT MAX(commit_revision) FROM (
                        SELECT MAX(commit_revision) AS commit_revision FROM coverage
                        WHERE tenant_id = ? AND stream_key = ? AND commit_revision <= ?
                        UNION ALL
                        SELECT MAX(commit_revision) AS commit_revision FROM expired_ranges
                        WHERE tenant_id = ? AND stream_key = ? AND commit_revision <= ?
                        UNION ALL
                        SELECT MAX(commit_revision) AS commit_revision FROM recovery_gaps
                        WHERE tenant_id = ? AND stream_key = ? AND commit_revision <= ?
                    )",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare source dependencies",
                })?;
            for identity in &selection.sources {
                control.check()?;
                let key = identity.key();
                let changed: Option<u64> = sources
                    .query_row(
                        params![
                            identity.tenant_id.as_slice(),
                            key.as_slice(),
                            meta.commit_revision,
                            identity.tenant_id.as_slice(),
                            key.as_slice(),
                            meta.commit_revision,
                            identity.tenant_id.as_slice(),
                            key.as_slice(),
                            meta.commit_revision,
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read source dependencies",
                    })?;
                revision = revision.max(changed.unwrap_or(0));
            }
            let mut contexts = snapshot
                .prepare(
                    "SELECT MAX(commit_revision) FROM context_versions
                     WHERE tenant_id = ? AND owner_id = ? AND entity_key = ?
                     AND lifetime_key = ? AND owner_revision = ? AND commit_revision <= ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare context dependencies",
                })?;
            for key in &selection.contexts {
                control.check()?;
                let changed: Option<u64> = contexts
                    .query_row(
                        params![
                            key.tenant_id.as_slice(),
                            key.owner_id,
                            key.entity_key.as_slice(),
                            key.lifetime_key.as_slice(),
                            key.owner_revision,
                            meta.commit_revision,
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read context dependencies",
                    })?;
                revision = revision.max(changed.unwrap_or(0));
            }
            control.check()?;
            Ok((meta, revision))
        })
    }

    fn selected_revision(
        &self,
        selection: &AnalysisSelectionV1,
        revision: u64,
        control: &AnalysisReadControl,
    ) -> Result<u64> {
        control
            .lock(|| self.raw.try_lock())?
            .selection_revision(selection, revision, control)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use prost::Message as _;

    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, CoverageReport,
        EvidenceIntakeIdentityV1, EvidenceRecord, ValidatedCoverageV1, ValidatedEvidenceBatchV1,
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn identity(tenant: u8, source: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: format!("node-{tenant}"),
            node_boot_id: [tenant; 16],
            label_epoch: 1,
            source_id: [source; 16],
            source_epoch: 1,
        }
    }

    fn batch(first_cursor: u64, intake: u64) -> ValidatedEvidenceBatchV1 {
        let payload = EvidenceRecord {
            operation: 1,
            ..Default::default()
        }
        .encode_to_vec();
        let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
        framed.extend(payload);
        framed.extend(crc32c::crc32c(&framed).to_be_bytes());
        let length = framed.len();
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor,
            last_cursor: first_cursor,
            intake_utc_ns: intake,
            framed_records: framed.into(),
            frame_ends: vec![length],
        }
    }

    fn read(store: &AnalysisStore, selection: &AnalysisSelectionV1) -> Result<(u64, u64)> {
        store
            .dependency_revision(selection, &AnalysisReadControl::default())
            .map(|(meta, revision)| (meta.commit_revision, revision))
    }

    #[test]
    fn query_follow_scoped_dependencies() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = AnalysisStore::open(&path)?;
        let selected = identity(1, 1);
        let foreign = identity(2, 2);
        let unrelated = identity(1, 3);
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: selected.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        };
        let mut selection = AnalysisSelectionV1::new(selected.tenant_id, vec![selected.clone()]);
        selection.received_from = Bound::Included(10);
        selection.received_until = Bound::Excluded(20);
        selection.contexts.push(context.key.clone());
        assert_eq!(read(&store, &selection)?, (0, 0));
        store.accept_validated_batch(foreign, batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (1, 0));
        store.accept_validated_batch(unrelated, batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (2, 0));
        store.accept_validated_batch(selected.clone(), batch(11, 9))?;
        assert_eq!(read(&store, &selection)?, (3, 0));
        store.accept_validated_batch(selected.clone(), batch(12, 10))?;
        assert_eq!(read(&store, &selection)?, (4, 4));
        assert_eq!(
            store
                .source_receipt(&selected)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            0
        );
        store.accept_validated_batch(selected.clone(), batch(13, 20))?;
        assert_eq!(read(&store, &selection)?, (5, 4));
        let mut other = context.clone();
        other.key.owner_revision = 2;
        store.commit_context(&other)?;
        assert_eq!(read(&store, &selection)?, (6, 4));
        store.commit_context(&context)?;
        assert_eq!(read(&store, &selection)?, (7, 7));
        other.key = context.key.clone();
        other.key.lifetime_key = vec![3];
        store.commit_context(&other)?;
        assert_eq!(read(&store, &selection)?, (8, 7));
        for report_revision in 1..=2 {
            let report = CoverageReport {
                source_id: selected.source_id.to_vec(),
                cpu_id: 0,
                source_epoch: selected.source_epoch,
                revision: report_revision,
                intervals: Vec::new(),
            };
            store.accept_validated_coverage(ValidatedCoverageV1 {
                identity: selected.clone(),
                cpu_id: 0,
                revision: report_revision,
                encoded_report: report.encode_to_vec(),
            })?;
            assert_eq!(
                read(&store, &selection)?,
                (8 + report_revision, 8 + report_revision)
            );
        }
        store.record_recovery_floor(&selected, 5)?;
        assert_eq!(read(&store, &selection)?, (11, 11));
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.dependency_revision(&selection, &cancelled),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        let mut invalid = selection.clone();
        invalid.sources.push(identity(2, 2));
        assert!(store
            .dependency_revision(&invalid, &AnalysisReadControl::default())
            .is_err());
        drop(store);
        let reopened = AnalysisStore::open(path)?;
        assert_eq!(read(&reopened, &selection)?, (11, 11));
        Ok(())
    }
}
