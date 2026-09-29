use duckdb::params;
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result};

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
            let writer = self.store.maintenance_writer()?;
            let reader = writer.get()?;
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
                })
        }?;
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
        let mut writer_guard = self.store.maintenance_writer()?;
        let _snapshot = self.store.maintenance.write().map_err(|_| {
            self.store
                .state_error("the analysis maintenance lock is poisoned")
        })?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin evidence retention",
        })?;
        let receipt =
            AnalysisStore::read_receipt_from(&transaction, &self.store.root, identity, &key)?
                .ok_or_else(|| self.store.state_error("the retention source is absent"))?;
        let consumed: u64 = transaction
            .query_row(
                "SELECT COALESCE(MIN(consumed_cursor), ?) FROM processor_progress
             WHERE stream_key = ? AND tenant_id = ? AND class = 'required' AND NOT retired",
                params![
                    receipt.contiguous_cursor,
                    key.as_slice(),
                    identity.tenant_id.as_slice()
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read required retention cutoff",
            })?;
        let retained_bytes: u64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(committed_end), 0)::UBIGINT FROM segments
             WHERE stream_key = ? AND tenant_id = ? AND state = 'Live'",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count retained segment bytes",
            })?;
        let tenant_bytes: u64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(committed_end), 0)::UBIGINT FROM segments
             WHERE tenant_id = ? AND state = 'Live'",
                params![identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count tenant segment bytes",
            })?;
        let pressure = self
            .store
            .logical_pressure(&transaction, identity.tenant_id)?;
        let meta = AnalysisStore::read_meta_from(&transaction, &self.store.root)?;
        // Read current pins. Cached intake totals cannot authorize deletion.
        let pins = {
            let mut statement = transaction
                .prepare(
                    "SELECT DISTINCT segment_id FROM evidence_refs WHERE stream_key = ?
                 AND tenant_id = ? AND expires_utc_ns > ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare retention pins",
                })?;
            statement
                .query_map(
                    params![key.as_slice(), identity.tenant_id.as_slice(), now_utc_ns],
                    |row| row.get::<_, u64>(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read retention pins",
                })?
                .collect::<duckdb::Result<std::collections::BTreeSet<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode retention pins",
                })?
        };
        let mut raw = self
            .store
            .raw
            .lock()
            .map_err(|_| self.store.state_error("the raw owner lock is poisoned"))?;
        let mut candidates = std::collections::BTreeMap::<u64, (u64, u64, u64, u64)>::new();
        for entry in raw
            .entries
            .values()
            .filter(|entry| entry.identity == *identity)
        {
            let candidate = candidates
                .entry(entry.reference.id)
                .or_insert((u64::MAX, 0, 0, 0));
            for span in &entry.commit.spans {
                candidate.0 = candidate.0.min(span.first);
                candidate.1 = candidate.1.max(span.last);
            }
            candidate.2 = candidate.2.max(entry.commit.intake);
            candidate.3 = entry.reference.offset;
        }
        let selected = candidates
            .into_iter()
            .filter(|(id, (_, last, intake, _))| {
                *last <= consumed.min(receipt.contiguous_cursor)
                    && (*intake <= now_utc_ns.saturating_sub(self.limits.raw_max_age_ns)
                        || tenant_bytes > self.limits.raw_max_bytes
                        || pressure)
                    && !pins.contains(id)
            })
            .min_by_key(|(_, (first, _, _, _))| *first)
            .map(|(id, (_, _, _, bytes))| (id, bytes));
        let Some((segment_id, segment_bytes)) = selected else {
            return Ok(RetentionResultV1 {
                removed_records: 0,
                retained_bytes,
                retained_floor: receipt.retained_floor,
                commit_revision: meta.commit_revision,
            });
        };
        let revision = meta.commit_revision.checked_add(1).ok_or_else(|| {
            self.store
                .state_error("the analysis commit revision is exhausted")
        })?;
        let mut intervals: Vec<(u64, u64)> = raw
            .entries
            .values()
            .filter(|entry| entry.reference.id == segment_id)
            .flat_map(|entry| {
                entry
                    .commit
                    .spans
                    .iter()
                    .map(|span| (span.first, span.last))
            })
            .collect();
        intervals.sort_unstable();
        let removed_records = intervals
            .iter()
            .try_fold(0_u32, |count, (first, last)| {
                u32::try_from(last - first + 1)
                    .ok()
                    .and_then(|added| count.checked_add(added))
            })
            .ok_or_else(|| {
                self.store
                    .state_error("the expired record count is invalid")
            })?;
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (first, last) in intervals {
            if let Some(prior) = merged
                .last_mut()
                .filter(|prior| prior.1.checked_add(1) == Some(first))
            {
                prior.1 = last;
            } else {
                merged.push((first, last));
            }
        }
        let retained_bytes = retained_bytes
            .checked_sub(segment_bytes)
            .ok_or_else(|| self.store.state_error("retained segment bytes underflow"))?;
        raw.segments.seal_all()?;
        raw.project_paths(&transaction)?;
        transaction.execute(
            "UPDATE segments SET state = 'Deleting', sealed = true WHERE segment_id = ? AND state = 'Live'",
            params![segment_id],
        ).context(AnalysisDatabaseSnafu { operation: "mark eligible segment deletion" })?;
        for (first, last) in &merged {
            transaction
                .execute(
                    "INSERT INTO expired_ranges VALUES (?, ?, ?, ?, ?, ?)",
                    params![
                        segment_id,
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        first,
                        last,
                        revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "record expired segment interval",
                })?;
        }
        let expired = merged.len();
        let released: i64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(256 + octet_length(encode(ref_id))), 0)::BIGINT
                FROM evidence_refs WHERE stream_key = ? AND tenant_id = ? AND expires_utc_ns <= ?",
                params![key.as_slice(), identity.tenant_id.as_slice(), now_utc_ns],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read expired witness charge",
            })?;
        transaction.execute(
            "DELETE FROM evidence_refs WHERE stream_key = ? AND tenant_id = ? AND expires_utc_ns <= ?",
            params![key.as_slice(), identity.tenant_id.as_slice(), now_utc_ns],
        ).context(AnalysisDatabaseSnafu { operation: "remove expired witness references" })?;
        super::quota::UsageChange::from(256 * expired as i64 - released)
            .apply(&transaction, &identity.tenant_id)?;
        let next_retained = raw
            .entries
            .values()
            .filter(|entry| entry.identity == *identity && entry.reference.id != segment_id)
            .flat_map(|entry| &entry.commit.spans)
            .filter(|span| span.first <= receipt.contiguous_cursor)
            .map(|span| span.first)
            .min();
        let retained_floor = next_retained.map_or(receipt.contiguous_cursor, |cursor| cursor - 1);
        let mut relations = vec!["events", "expired_ranges", "evidence_refs"];
        if retained_floor > receipt.retained_floor {
            transaction
                .execute(
                    "UPDATE source_receipts SET retained_floor = ? WHERE stream_key = ?",
                    params![retained_floor, key.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance retained segment floor",
                })?;
            relations.push("source_receipts");
        }
        AnalysisStore::record_revision(&transaction, revision, &relations)?;
        #[cfg(test)]
        self.store.crash_at("retention.before");
        self.store
            .write_ready
            .store(false, std::sync::atomic::Ordering::Release);
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit segment deletion",
        })?;
        if let Some(source) = raw.sources.get_mut(&key) {
            source.receipt.retained_floor = retained_floor;
        }
        #[cfg(test)]
        self.store.crash_at("retention.after");
        let cleanup = AnalysisStore::remove_segment(writer, &self.store.root, &raw, segment_id);
        raw.forget_segment(segment_id)?;
        cleanup?;
        raw.refresh_budget(writer)?;
        self.store
            .write_ready
            .store(true, std::sync::atomic::Ordering::Release);
        self.store.revision.send_replace(revision);
        Ok(RetentionResultV1 {
            removed_records,
            retained_bytes,
            retained_floor,
            commit_revision: revision,
        })
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
    fn analysis_store_required_plan() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let source = identity(1);
        let scope = ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(source.clone(), batch(1, b"abc"))?;
        store.commit_result(&AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "witness".into(),
            body: b"checked".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone(),
                cursor: 1,
                expires_utc_ns: 200,
            }],
            context_refs: vec![],
        })?;
        let writer = store.raw_access()?;
        {
            let raw = store.raw.lock().map_err(|_| "raw owner lock poisoned")?;
            assert_eq!(raw.budget.required.get(&source_key(&source)), Some(&1));
            assert_eq!(raw.budget.protected.get(&source.tenant_id), Some(&2));
        }
        drop(writer);
        assert_eq!(
            EvidenceRetentionOwner::new(&store, Default::default())?
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
                raw_max_bytes: 3,
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
                scope: scope.clone(),
                expected_cursor: 0,
                consumed_cursor: cursor,
                coverage_revision: 0,
                context_revision: 0,
                result_id: scope.processor_id.clone(),
                body: b"checked".to_vec(),
                created_utc_ns: 101,
                witnesses: vec![],
                context_refs: vec![],
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
    fn retention_waits_for_maintenance() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let writer = store.maintenance_writer()?;
        let maintenance = store.maintenance.write().map_err(|_| "poisoned lock")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let (early, result) = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let result = EvidenceRetentionOwner::new(&store, Default::default())
                    .and_then(|owner| owner.sweep(None, 100));
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
                .checked_sources,
            0
        );
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
            .get()?
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
            .get()?
            .execute_batch("ALTER TABLE missing_expiry RENAME TO expired_ranges")?;
        assert_eq!(owner.sweep(None, 100)?.removed_records, 0);
        assert!(store.retention_healthy());
        store.accept_validated_batch(source.clone(), batch(2, b"b"))?;
        assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 2);
        let reader = store.writer()?.get()?.try_clone()?;
        reader.execute_batch("BEGIN TRANSACTION; SELECT * FROM segments")?;
        let failed = owner.sweep(None, u64::MAX);
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
            1
        );
        assert_eq!(store.read_page(&source, 2)?.records[0].framed_record, b"b");
        assert!(owner.sweep(None, u64::MAX).is_err());
        assert!(!store.retention_healthy());
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or("source status absent")?
                .retained_event_count,
            0
        );
        reader.execute_batch("ROLLBACK")?;
        assert_eq!(owner.sweep(None, u64::MAX)?.removed_records, 0);
        assert!(store.retention_healthy());
        Ok(())
    }

    #[test]
    fn analysis_store_retention_guards() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        store.commit_result(&AnalysisResultCommitV1 {
            scope: review,
            expected_cursor: 0,
            consumed_cursor: 3,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "review".into(),
            body: b"checked".to_vec(),
            created_utc_ns: 150,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone(),
                cursor: 1,
                expires_utc_ns: 200,
            }],
            context_refs: vec![],
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
        let store = AnalysisStore::open(&root)?;
        let source = identity(1);
        let owner = EvidenceRetentionOwner::new(
            &store,
            RetentionLimitsV1 {
                raw_max_age_ns: 100,
                raw_max_bytes: 1024 * 1024 * 1024,
            },
        )?;
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
                    scope,
                    expected_cursor: 0,
                    consumed_cursor: ROWS,
                    coverage_revision: 0,
                    context_revision: 0,
                    result_id: "retained-witness".into(),
                    body: b"review".to_vec(),
                    created_utc_ns: intake,
                    witnesses: vec![AnalysisWitnessV1 {
                        identity: source.clone(),
                        cursor: ROWS,
                        expires_utc_ns: 10_000,
                    }],
                    context_refs: vec![],
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
            let sweep = owner.sweep(None, intake + 101)?;
            assert_eq!(sweep.checked_sources, 1);
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
        assert_eq!(
            owner.sweep(None, 10_000)?.removed_records as u64,
            15 * BATCH
        );
        let cleared = store.storage_usage()?.allocated_bytes;
        assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
        assert!(
            cleared + 14 * 1024 * 1024 < pinned,
            "segment deletion did not release blocks: {pinned} -> {cleared}"
        );
        let before = store.meta()?;
        drop(store);
        let reopened = AnalysisStore::open(root)?;
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
            assert_eq!(result.removed_records, 3);
            assert_eq!(result.retained_bytes, 0);
            assert_eq!(result.retained_floor, 3);
            assert!(matches!(
                store.read_page(&source, 3),
                Err(crate::Error::RetainedRangeExpired { .. })
            ));
        }
        let reopened = AnalysisStore::open(path)?;
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
            scope: optional,
            expected_cursor: 3,
            consumed_cursor: 4,
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
