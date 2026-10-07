use duckdb::params;
use snafu::ResultExt as _;

use super::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, AnalysisStoreMetaV1, ProcessorScopeV1,
};
use crate::{AnalysisDatabaseSnafu, Result, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION};

impl AnalysisStore {
    pub(crate) fn profile_notices(
        &self,
        scope: &ProcessorScopeV1,
        facts_revision: u64,
        coverage_revision: u64,
    ) -> Result<Vec<(String, u64)>> {
        if !scope.valid()
            || scope.processor_id != DISCOVERY_PROCESSOR
            || scope.method_version != DISCOVERY_SCHEMA_VERSION as u64
        {
            return self.reject("the discovery notice scope is invalid");
        }
        self.read_snapshot(|reader| {
            let Some(receipt) = Self::read_receipt_from(
                reader,
                &self.root,
                &scope.identity,
                &scope.identity.key(),
            )?
            else {
                return Ok(Vec::new());
            };
            let mut statement = reader
                .prepare(
                    "WITH profiles AS (
                        SELECT result_id, commit_revision, interval_id,
                            facts_revision, coverage_revision, first_cursor,
                            ROW_NUMBER() OVER (
                                PARTITION BY interval_id
                                ORDER BY profile_revision DESC, commit_revision DESC, result_id DESC
                            ) AS rank
                        FROM analysis_results
                        WHERE tenant_id = ? AND processor_id = ?
                          AND method_version = ? AND stream_key = ?
                    )
                    SELECT result_id, commit_revision FROM profiles
                    WHERE rank = 1 AND (facts_revision < ? OR coverage_revision < ?)
                      AND (first_cursor = 0 OR first_cursor > ?)
                    ORDER BY interval_id LIMIT 16",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare discovery notices",
                })?;
            let rows = statement
                .query_map(
                    params![
                        scope.identity.tenant_id.as_slice(),
                        scope.processor_id,
                        scope.method_version,
                        scope.identity.key().as_slice(),
                        facts_revision,
                        coverage_revision,
                        receipt.retained_floor,
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read discovery notices",
                })?;
            let mut notices = Vec::with_capacity(16);
            for row in rows {
                let notice = row.context(AnalysisDatabaseSnafu {
                    operation: "decode discovery notice",
                })?;
                if notice.0.is_empty() || notice.0.len() > 256 || notice.1 == 0 {
                    return self.reject("the discovery notice result is invalid");
                }
                notices.push(notice);
            }
            Ok(notices)
        })
    }

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
        let all_traces = selection.all_traces;
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            let (selection, _) =
                self.resolve_selection(snapshot, selection, control, 64 * 1024 * 1024)?;
            let selection = selection.as_ref();
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
            let mut profiles = snapshot
                .prepare(
                    "SELECT MAX(commit_revision) FROM analysis_results
                 WHERE tenant_id = ? AND processor_id = 'discovery' AND result_id = ?
                   AND commit_revision <= ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare discovery dependencies",
                })?;
            for id in &selection.profiles {
                control.check()?;
                let changed: Option<u64> = profiles
                    .query_row(
                        params![selection.tenant_id.as_slice(), id, meta.commit_revision],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read discovery dependencies",
                    })?;
                revision = revision.max(changed.unwrap_or(0));
            }
            let mut traces = snapshot
                .prepare(
                    "SELECT MAX(revision) FROM traces WHERE tenant_id = ?
                 AND (CAST(? AS BLOB) IS NULL OR request_id = ?)",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare trace dependencies",
                })?;
            if all_traces {
                let changed: Option<u64> = traces
                    .query_row(
                        params![
                            selection.tenant_id.as_slice(),
                            Option::<&[u8]>::None,
                            Option::<&[u8]>::None
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read tenant trace dependencies",
                    })?;
                revision = revision.max(changed.unwrap_or(0));
            } else {
                for identity in &selection.traces {
                    control.check()?;
                    let changed: Option<u64> = traces
                        .query_row(
                            params![
                                selection.tenant_id.as_slice(),
                                identity.request_id.as_slice(),
                                identity.request_id.as_slice()
                            ],
                            |row| row.get(0),
                        )
                        .context(AnalysisDatabaseSnafu {
                            operation: "read trace dependencies",
                        })?;
                    revision = revision.max(changed.unwrap_or(0));
                }
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
    use std::sync::Arc;

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

    fn result_row(store: &AnalysisStore, id: &str) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        store.read_snapshot(|reader| {
            reader.query_row(
                "SELECT body, request_meta, commit_revision FROM analysis_results WHERE result_id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).context(AnalysisDatabaseSnafu { operation: "read frozen result test" })
        })
    }

    struct NoContext;

    impl crate::DiscoveryContextProvider for NoContext {
        fn context(&self, _: &crate::DiscoveryRecordV1) -> Result<crate::DiscoveryContextJoinV1> {
            Ok(crate::DiscoveryContextJoinV1::Unresolved(
                crate::DiscoveryContextUnavailableV1::MissingDecisionCatalog,
            ))
        }
    }

    #[test]
    fn discovery_notice_cache() -> TestResult {
        let input = crate::DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = Arc::new(AnalysisStore::open(&root)?);
        let record = &input.records[0];
        store.accept_validated_batch(
            record.id.stream.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                intake_utc_ns: 1,
                framed_records: record.wire_record.clone().into(),
                frame_ends: vec![record.wire_record.len()],
            },
        )?;
        let owner = crate::DiscoveryOwner::new(
            store.clone(),
            Arc::new(NoContext),
            crate::DiscoveryConfigV1 {
                interval_records: 1,
                ..Default::default()
            },
        )?;
        owner.process(10)?;
        let profile = owner.profile(&record.id.stream)?.ok_or("profile absent")?;
        assert!(profile.sealed);
        let head = store.processor_result(&profile.scope)?;
        let health = store.processor_health(&profile.scope)?;
        let meta = store.meta()?;
        let frozen = result_row(&store, &profile.profile_id)?;
        let notices = vec![(profile.profile_id.clone(), frozen.2)];
        assert_eq!(store.profile_notices(&profile.scope, 2, 2)?, notices);
        store.mark_notice(&profile, frozen.2, 2, 2)?;
        assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
        store.mark_notice(&profile, frozen.2, 1, 1)?;
        assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
        assert!(store.mark_notice(&profile, frozen.2 + 1, 3, 3).is_err());
        assert_eq!(result_row(&store, &profile.profile_id)?, frozen);
        assert_eq!(store.processor_result(&profile.scope)?, head);
        assert_eq!(store.processor_health(&profile.scope)?, health);
        assert_eq!(store.meta()?, meta);
        drop(owner);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(result_row(&store, &profile.profile_id)?, frozen);
        assert_eq!(store.processor_result(&profile.scope)?, head);
        assert_eq!(store.processor_health(&profile.scope)?, health);
        assert_eq!(store.meta()?, meta);
        assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
        assert_eq!(store.profile_notices(&profile.scope, 3, 2)?, notices);
        Ok(())
    }

    #[test]
    fn query_tenant_dependencies() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1, 1);
        let mut selection = AnalysisSelectionV1::tenant(first.tenant_id);
        assert_eq!(read(&store, &selection)?, (0, 0));
        store.accept_validated_batch(first.clone(), batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (1, 1));
        store.accept_validated_batch(identity(2, 2), batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (2, 1));
        let mut next = identity(1, 3);
        next.node_boot_id = [3; 16];
        next.node_id = "next-node".into();
        store.accept_validated_batch(next, batch(1, 20))?;
        assert_eq!(read(&store, &selection)?, (3, 3));
        selection.nodes.push(first.node_id.clone());
        assert_eq!(read(&store, &selection)?, (3, 1));
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: first.tenant_id,
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
        store.commit_context(&context)?;
        assert_eq!(read(&store, &selection)?, (4, 4));
        selection.all_contexts = false;
        assert_eq!(read(&store, &selection)?, (4, 1));
        selection.received_from = Bound::Included(11);
        assert_eq!(read(&store, &selection)?, (4, 0));
        let empty = AnalysisSelectionV1::new(first.tenant_id, vec![]);
        assert_eq!(read(&store, &empty)?, (4, 0));
        Ok(())
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
