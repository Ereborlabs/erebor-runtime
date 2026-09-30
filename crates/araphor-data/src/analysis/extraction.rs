use std::collections::BTreeSet;
use std::mem::size_of;
use std::ops::Bound;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::segments::SegmentRange;
use super::{
    source_key, AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisGapV1, AnalysisReadControl,
    AnalysisRecordV1, AnalysisSourceReceiptV1, AnalysisStore, AnalysisStoreMetaV1,
    MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, EvidenceIntakeIdentityV1, Result};

const MAX_EXTRACT_KEYS: usize = 1024;
const MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Trusted selection after authorization. An empty source list selects no events.
#[derive(Clone, Debug)]
pub struct AnalysisSelectionV1 {
    pub tenant_id: [u8; 16],
    pub sources: Vec<EvidenceIntakeIdentityV1>,
    pub received_from: Bound<u64>,
    pub received_until: Bound<u64>,
    pub contexts: Vec<AnalysisContextKeyV1>,
    pub results: Vec<String>,
}

impl AnalysisSelectionV1 {
    pub fn new(tenant_id: [u8; 16], sources: Vec<EvidenceIntakeIdentityV1>) -> Self {
        Self {
            tenant_id,
            sources,
            received_from: Bound::Unbounded,
            received_until: Bound::Unbounded,
            contexts: Vec::new(),
            results: Vec::new(),
        }
    }

    fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && self.sources.len() <= MAX_EXTRACT_KEYS
            && self.contexts.len() <= MAX_EXTRACT_KEYS - self.sources.len()
            && self.results.len() <= MAX_EXTRACT_KEYS - self.sources.len() - self.contexts.len()
            && self
                .sources
                .iter()
                .all(|source| source.tenant_id == self.tenant_id && source.valid())
            && self
                .contexts
                .iter()
                .all(|key| key.tenant_id == self.tenant_id && key.valid())
            && self
                .results
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
            && self.sources.iter().collect::<BTreeSet<_>>().len() == self.sources.len()
            && self.contexts.iter().collect::<BTreeSet<_>>().len() == self.contexts.len()
            && self.results.iter().collect::<BTreeSet<_>>().len() == self.results.len()
    }

    fn time_range(&self) -> Option<(u64, u64)> {
        let first = match self.received_from {
            Bound::Unbounded => 0,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_add(1)?,
        };
        let last = match self.received_until {
            Bound::Unbounded => u64::MAX,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_sub(1)?,
        };
        (first <= last).then_some((first, last))
    }
}

/// Input for trusted row and field projection. This callback is not a client API.
pub enum AnalysisInputV1<'a> {
    Event {
        identity: &'a EvidenceIntakeIdentityV1,
        cpu_id: u32,
        received_utc_ns: u64,
        record: &'a AnalysisRecordV1,
    },
    Context(&'a AnalysisContextVersionV1),
    Result {
        result_id: &'a str,
        body: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisRelationV1 {
    Events,
    Context,
    Results,
}

#[derive(Debug)]
pub struct AnalysisInputPageV1 {
    pub relation: AnalysisRelationV1,
    pub rows: Vec<Box<[u8]>>,
    pub input_bytes: usize,
}

#[derive(Debug)]
pub struct AnalysisSourceSnapshotV1 {
    pub receipt: AnalysisSourceReceiptV1,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
}

#[derive(Debug)]
pub struct AnalysisExtractionV1 {
    pub meta: AnalysisStoreMetaV1,
    pub sources: Vec<AnalysisSourceSnapshotV1>,
    pub missing_contexts: Vec<AnalysisContextKeyV1>,
    pub missing_results: Vec<String>,
    pub pages: Vec<AnalysisInputPageV1>,
    pub scanned_bytes: usize,
    pub projected_bytes: usize,
    /// Includes projected bytes, row descriptors, page headers, and coverage metadata.
    pub input_bytes: usize,
}

impl AnalysisExtractionV1 {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.input_bytes = self
            .input_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_INPUT_BYTES)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "selected input bytes",
                }
                .build()
            })?;
        Ok(())
    }

    fn scan(&mut self, bytes: usize) -> Result<()> {
        self.scanned_bytes = self
            .scanned_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_SCAN_BYTES)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "scanned segment bytes",
                }
                .build()
            })?;
        Ok(())
    }

    fn push(&mut self, relation: AnalysisRelationV1, row: Vec<u8>) -> Result<()> {
        let bytes = row
            .len()
            .checked_add(size_of::<Box<[u8]>>())
            .filter(|bytes| *bytes <= MAX_ANALYSIS_PAGE_BYTES)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "projected row bytes",
                }
                .build()
            })?;
        let new_page = self.pages.last().is_none_or(|page| {
            page.relation != relation
                || page.rows.len() == MAX_ANALYSIS_PAGE_RECORDS
                || page.input_bytes + bytes > MAX_ANALYSIS_PAGE_BYTES
        });
        self.charge(
            bytes
                + if new_page {
                    size_of::<AnalysisInputPageV1>()
                } else {
                    0
                },
        )?;
        self.projected_bytes += row.len();
        if new_page {
            self.pages.push(AnalysisInputPageV1 {
                relation,
                rows: Vec::new(),
                input_bytes: 0,
            });
        }
        let page = self.pages.last_mut().ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: std::path::Path::new("<extraction>"),
                reason: "the charged input page is absent",
            }
            .build()
        })?;
        page.input_bytes += bytes;
        page.rows.push(row.into_boxed_slice());
        Ok(())
    }
}

impl AnalysisStore {
    /// Project permitted rows and fields without caller I/O. No partial input escapes an error.
    pub fn extract(
        &self,
        selection: &AnalysisSelectionV1,
        control: &AnalysisReadControl,
        mut project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<Vec<u8>>>,
    ) -> Result<AnalysisExtractionV1> {
        control.check()?;
        if !selection.valid() {
            return self.reject("the extraction selection has invalid, duplicate, or foreign keys");
        }
        let coordinator = self.read_coordinator(control)?;
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            // The revision fixes raw selection. The lease prevents segment deletion.
            drop(coordinator);
            let mut output = AnalysisExtractionV1 {
                meta,
                sources: Vec::new(),
                missing_contexts: Vec::new(),
                missing_results: Vec::new(),
                pages: Vec::new(),
                scanned_bytes: 0,
                projected_bytes: 0,
                input_bytes: size_of::<AnalysisExtractionV1>(),
            };
            for identity in &selection.sources {
                control.check()?;
                let key = source_key(identity);
                let receipt = Self::read_receipt_from(snapshot, &self.root, identity, &key)?
                    .ok_or_else(|| self.state_error("the selected source is absent"))?;
                output.charge(size_of::<AnalysisSourceSnapshotV1>() + identity.node_id.len())?;
                let expired = self.extract_gaps(snapshot, identity, false, control, &mut output)?;
                let recovery = self.extract_gaps(snapshot, identity, true, control, &mut output)?;
                self.check_selected_source(snapshot, &receipt, &expired)?;
                if let Some((first, last)) = selection.time_range() {
                    let mut cursor = 0;
                    while cursor < receipt.contiguous_cursor {
                        control.check()?;
                        let ranges = self.selected_ranges(
                            snapshot,
                            identity,
                            cursor,
                            receipt.contiguous_cursor,
                            (first, last),
                        )?;
                        if ranges.is_empty() {
                            break;
                        }
                        for (range, received) in ranges {
                            control.check()?;
                            output.scan(range.scan_bytes)?;
                            for record in range.read(&self.root)? {
                                control.check()?;
                                if record.cursor > receipt.contiguous_cursor {
                                    continue;
                                }
                                if let Some(row) = project(AnalysisInputV1::Event {
                                    identity,
                                    cpu_id: receipt.cpu_id,
                                    received_utc_ns: received,
                                    record: &record,
                                })? {
                                    output.push(AnalysisRelationV1::Events, row)?;
                                }
                            }
                            cursor = range.last_cursor;
                        }
                    }
                }
                output.sources.push(AnalysisSourceSnapshotV1 {
                    receipt,
                    expired,
                    recovery,
                });
            }
            for key in &selection.contexts {
                control.check()?;
                match Self::read_context_from(snapshot, &self.root, key)? {
                    Some((context, _)) => {
                        if let Some(row) = project(AnalysisInputV1::Context(&context))? {
                            output.push(AnalysisRelationV1::Context, row)?;
                        }
                    }
                    None => {
                        output.charge(
                            size_of::<AnalysisContextKeyV1>()
                                + key.owner_id.len()
                                + key.entity_key.len()
                                + key.lifetime_key.len(),
                        )?;
                        output.missing_contexts.push(key.clone());
                    }
                }
            }
            for id in &selection.results {
                control.check()?;
                match self.read_result_from(snapshot, selection.tenant_id, id)? {
                    Some(body) => {
                        if let Some(row) = project(AnalysisInputV1::Result {
                            result_id: id,
                            body: &body,
                        })? {
                            output.push(AnalysisRelationV1::Results, row)?;
                        }
                    }
                    None => {
                        output.charge(size_of::<String>() + id.len())?;
                        output.missing_results.push(id.clone());
                    }
                }
            }
            control.check()?;
            Ok(output)
        })
    }

    fn selected_ranges(
        &self,
        snapshot: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        after: u64,
        accepted: u64,
        time: (u64, u64),
    ) -> Result<Vec<(SegmentRange, u64)>> {
        let revision = Self::read_meta_from(snapshot, &self.root)?.commit_revision;
        let raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        Ok(raw
            .select_ranges(
                identity,
                after.saturating_add(1),
                accepted,
                revision,
                Some(time),
                MAX_ANALYSIS_PAGE_RECORDS,
            )?
            .into_iter()
            .map(|range| {
                let intake = range.intake;
                (range, intake)
            })
            .collect())
    }

    fn check_selected_source(
        &self,
        snapshot: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        expired: &[AnalysisGapV1],
    ) -> Result<()> {
        let identity = &receipt.identity;
        let revision = Self::read_meta_from(snapshot, &self.root)?.commit_revision;
        let retained = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?
            .record_count(source_key(identity), 1, receipt.contiguous_cursor, revision);
        let covered = expired.iter().try_fold(retained, |count, gap| {
            gap.last_cursor
                .checked_sub(gap.first_cursor)
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| count.checked_add(bytes))
        });
        if covered != Some(receipt.contiguous_cursor) {
            return self.reject("the selected source has an unrecorded input gap");
        }
        Ok(())
    }

    fn extract_gaps(
        &self,
        snapshot: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        recovery: bool,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Vec<AnalysisGapV1>> {
        // Expired ranges have no time proof. A time filter cannot hide these gaps.
        let sql = if recovery {
            "SELECT first_cursor, last_cursor, commit_revision FROM recovery_gaps
             WHERE stream_key = ? AND tenant_id = ? ORDER BY first_cursor"
        } else {
            "SELECT first_cursor, last_cursor, commit_revision FROM expired_ranges
             WHERE stream_key = ? AND tenant_id = ? ORDER BY first_cursor"
        };
        let mut statement = snapshot.prepare(sql).context(AnalysisDatabaseSnafu {
            operation: "prepare selected coverage gaps",
        })?;
        let rows = statement
            .query_map(
                params![
                    source_key(identity).as_slice(),
                    identity.tenant_id.as_slice()
                ],
                |row| {
                    Ok(AnalysisGapV1 {
                        first_cursor: row.get(0)?,
                        last_cursor: row.get(1)?,
                        commit_revision: row.get(2)?,
                    })
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read selected coverage gaps",
            })?;
        let mut gaps = Vec::new();
        for row in rows {
            control.check()?;
            output.charge(size_of::<AnalysisGapV1>())?;
            gaps.push(row.context(AnalysisDatabaseSnafu {
                operation: "decode selected coverage gap",
            })?);
        }
        Ok(gaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisResultCommitV1, ContextSensitivityV1, EvidenceRetentionOwner, ProcessorClassV1,
        ProcessorScopeV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: "n".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
    }

    fn batch(first: u64, count: usize, received: u64) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + count as u64 - 1,
            intake_utc_ns: received,
            framed_records: vec![7; count].into(),
            frame_ends: (1..=count).collect(),
        }
    }

    #[test]
    fn analysis_extract_selection() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for (cursor, received) in [(1, 10), (2, 30), (3, 20)] {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, received))?;
        }
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..identity.clone()
        };
        store.accept_validated_batch(foreign.clone(), batch(1, 1, 20))?;
        let before = store.meta()?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        selection.received_until = Bound::Excluded(30);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event {
                identity: source,
                cpu_id,
                record,
                received_utc_ns,
            } = input
            else {
                return store.reject("unexpected relation");
            };
            assert_eq!(source, &identity);
            assert_eq!(cpu_id, 0);
            assert_eq!(received_utc_ns, 20);
            Ok(Some(record.cursor.to_be_bytes().to_vec()))
        })?;
        assert_eq!(output.meta, before);
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.identity == identity && entry.commit.intake == 20)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(output.projected_bytes, 8);
        assert_eq!(output.pages[0].rows[0].as_ref(), &3_u64.to_be_bytes());
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 3);
        assert_eq!(store.meta()?, before);
        for (from, until) in [
            (Bound::Excluded(u64::MAX), Bound::Unbounded),
            (Bound::Unbounded, Bound::Excluded(0)),
            (Bound::Included(31), Bound::Included(30)),
        ] {
            selection.received_from = from;
            selection.received_until = until;
            let empty = store.extract(&selection, &AnalysisReadControl::default(), |_| {
                store.reject("empty range decoded input")
            })?;
            assert!(empty.pages.is_empty());
            assert_eq!(empty.scanned_bytes, 0);
        }
        selection.sources.clear();
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| store
                .reject("empty source scope is not a wildcard"))?
            .pages
            .is_empty());
        selection.sources.push(foreign);
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
            .is_err());
        selection.sources = vec![identity.clone(), identity];
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_snapshot() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 10))?;
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: identity.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 0,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![42],
        };
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.contexts.push(context.key.clone());
        selection.results.push("late".into());
        let before = store.meta()?;
        let mut calls = 0;
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event { record, .. } = input else {
                return store.reject("late metadata entered snapshot");
            };
            assert_eq!(record.cursor, 1);
            calls += 1;
            store.accept_validated_batch(identity.clone(), batch(2, 1, 5))?;
            store.commit_context(&context)?;
            store.commit_result(&AnalysisResultCommitV1 {
                scope: scope.clone(),
                expected_cursor: 0,
                consumed_cursor: 1,
                coverage_revision: 0,
                context_revision: 0,
                result_id: "late".into(),
                body: vec![43],
                created_utc_ns: 20,
                witnesses: vec![],
                context_refs: vec![],
            })?;
            Ok(Some(vec![1]))
        })?;
        assert_eq!(calls, 1);
        assert_eq!(output.meta, before);
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(output.missing_contexts, vec![context.key]);
        assert_eq!(output.missing_results, vec!["late"]);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            Ok(Some(match input {
                AnalysisInputV1::Event { record, .. } => vec![record.cursor as u8],
                AnalysisInputV1::Context(context) => context.body.clone(),
                AnalysisInputV1::Result { body, .. } => body.to_vec(),
            }))
        })?;
        assert!(output.missing_contexts.is_empty() && output.missing_results.is_empty());
        assert_eq!(output.meta, store.meta()?);
        assert_eq!(output.pages.len(), 3);
        assert_eq!(output.pages[0].rows.len(), 2);
        assert_eq!(output.pages[1].rows[0].as_ref(), &[42]);
        assert_eq!(output.pages[2].rows[0].as_ref(), &[43]);
        selection.received_from = Bound::Included(100);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            Ok(Some(match input {
                AnalysisInputV1::Context(context) => context.body.clone(),
                AnalysisInputV1::Result { body, .. } => body.to_vec(),
                _ => return store.reject("old event entered a new window"),
            }))
        })?;
        assert_eq!(output.scanned_bytes, 0);
        assert_eq!(output.pages.len(), 2);
        assert_eq!(output.pages[0].relation, AnalysisRelationV1::Context);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_range_pages() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for cursor in 1..=257 {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, 10))?;
        }
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let output = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert!(matches!(
            store.extract(&selection, &AnalysisReadControl::default(), |_| {
                Ok(Some(vec![0; 512 * 1024]))
            }),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ));
        let rows: Vec<_> = output.pages.iter().flat_map(|page| &page.rows).collect();
        assert_eq!(rows.len(), 257);
        for (index, row) in rows.into_iter().enumerate() {
            assert_eq!(row.as_ref(), &(index as u64 + 1).to_be_bytes());
        }
        let mut selection = AnalysisSelectionV1::new(
            identity.tenant_id,
            (1..=MAX_EXTRACT_KEYS)
                .map(|epoch| EvidenceIntakeIdentityV1 {
                    source_epoch: epoch as u64,
                    ..identity.clone()
                })
                .collect(),
        );
        assert!(selection.valid());
        selection.sources.push(EvidenceIntakeIdentityV1 {
            source_epoch: MAX_EXTRACT_KEYS as u64 + 1,
            ..identity
        });
        assert!(!selection.valid());
        Ok(())
    }

    #[test]
    fn analysis_extract_file_faults() -> TestResult {
        use std::os::unix::fs::FileExt as _;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1))?;
        let (path, offset) = {
            let reader = store.reader()?;
            let ranges = store.raw_ranges(reader.get()?, &identity, 1, 1, 1)?;
            let range = ranges.first().ok_or("batch absent")?;
            (
                SegmentRange::path(&store.root, range.segment_id),
                range.byte_start,
            )
        };
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
        let hidden = directory.path().join("hidden.seg");
        std::fs::rename(&path, &hidden)?;
        assert!(matches!(
            store.extract(&selection, &AnalysisReadControl::default(), |_| Ok(None)),
            Err(crate::Error::Io { .. })
        ));
        std::fs::rename(&hidden, &path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.write_all_at(&[8], offset)?;
        assert!(matches!(
            store.extract(&selection, &AnalysisReadControl::default(), |_| Ok(None)),
            Err(crate::Error::AnalysisState { .. })
        ));
        file.write_all_at(&[7], offset)?;
        let result = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![7]))
        })?;
        assert_eq!(result.pages[0].rows[0].as_ref(), &[7]);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_gaps() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1024,
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1))?;
        store.backup(&store.root.join("backups/sealed"))?;
        store.accept_validated_batch(identity.clone(), batch(2, 1, 100))?;
        EvidenceRetentionOwner::new(&store).retain(&identity, 3)?;
        store.record_recovery_floor(&identity, 4)?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(99);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![2]))
        })?;
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.commit.intake == 20 || entry.commit.intake == 100)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(output.sources[0].expired.len(), 1);
        assert_eq!(
            (
                output.sources[0].expired[0].first_cursor,
                output.sources[0].expired[0].last_cursor
            ),
            (1, 1)
        );
        assert_eq!(
            (
                output.sources[0].recovery[0].first_cursor,
                output.sources[0].recovery[0].last_cursor
            ),
            (3, 4)
        );
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .ranges
            .remove(&(source_key(&identity), 2));
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 257, 1))?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let before = store.meta()?;
        let output = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![1]))
        })?;
        assert_eq!(
            output
                .pages
                .iter()
                .map(|page| page.rows.len())
                .collect::<Vec<_>>(),
            vec![256, 1]
        );
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        let control = AnalysisReadControl::default();
        let mut calls = 0;
        assert!(matches!(
            store.extract(&selection, &control, |_| {
                calls += 1;
                control.cancel()?;
                Ok(Some(vec![1]))
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(calls, 1);
        let mut output = store.extract(
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            &AnalysisReadControl::default(),
            |_| store.reject("empty selection"),
        )?;
        output.scan(MAX_SCAN_BYTES)?;
        assert!(matches!(
            output.scan(1),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "scanned segment bytes",
                ..
            })
        ));
        output.charge(MAX_INPUT_BYTES - output.input_bytes)?;
        assert!(matches!(
            output.charge(1),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ));
        assert!(output.charge(usize::MAX).is_err());
        assert!(output.scan(usize::MAX).is_err());
        let mut output = store.extract(
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            &AnalysisReadControl::default(),
            |_| store.reject("empty selection"),
        )?;
        output.push(
            AnalysisRelationV1::Events,
            vec![0; MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>()],
        )?;
        assert_eq!(output.pages[0].input_bytes, MAX_ANALYSIS_PAGE_BYTES);
        output.push(AnalysisRelationV1::Events, vec![])?;
        assert_eq!(output.pages.len(), 2);
        assert!(matches!(
            output.push(
                AnalysisRelationV1::Events,
                vec![0; MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>() + 1]
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "projected row bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.maintenance.try_write().is_ok());
        store.checkpoint()?;
        Ok(())
    }

    #[test]
    #[ignore = "release history scan qualification"]
    fn analysis_extract_history() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1,
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let identity = identity(1);
        let frame_bytes = 128 * 1024;
        for group in 0..18 {
            store.accept_validated_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: group * 32 + 1,
                    last_cursor: (group + 1) * 32,
                    intake_utc_ns: if group == 17 { 20 } else { 10 },
                    framed_records: vec![7; 32 * frame_bytes].into(),
                    frame_ends: (1..=32).map(|index| index * frame_bytes).collect(),
                },
            )?;
        }
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        let started = std::time::Instant::now();
        let recent = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
        let recent_us = started.elapsed().as_micros();
        assert_eq!(
            recent.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.commit.intake == 20)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(recent.projected_bytes, 32 * 8);
        selection.received_from = Bound::Unbounded;
        let started = std::time::Instant::now();
        let sparse = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok((record.cursor % 32 == 1).then(|| record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
        let sparse_us = started.elapsed().as_micros();
        assert_eq!(
            sparse.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(sparse.projected_bytes, 18 * 8);
        let full = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => Ok(Some(record.framed_record.clone())),
                _ => store.reject("unexpected relation"),
            },
        );
        assert!(
            matches!(
                full,
                Err(crate::Error::AnalysisInputTooLarge {
                    resource: "selected input bytes",
                    ..
                })
            ),
            "{full:?}"
        );
        assert!(store.maintenance.try_write().is_ok());
        let scope = ProcessorScopeV1 {
            processor_id: "history".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let started = std::time::Instant::now();
        store.commit_result(&AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 18 * 32,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "sparse-history".into(),
            body: vec![1],
            created_utc_ns: 21,
            witnesses: (0..18)
                .map(|group| crate::AnalysisWitnessV1 {
                    identity: identity.clone(),
                    cursor: group * 32 + 1,
                    expires_utc_ns: 100,
                })
                .collect(),
            context_refs: vec![],
        })?;
        let pin_commit_us = started.elapsed().as_micros();
        let started = std::time::Instant::now();
        let usage = store.witness_usage(identity.tenant_id, 22)?;
        let usage_us = started.elapsed().as_micros();
        let header_bytes = super::super::SegmentFile::encode_identity(&identity)?.len() as u64;
        assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 6);
        assert_eq!(
            usage.segment_bytes,
            sparse.scanned_bytes as u64 + 6 * header_bytes
        );
        assert_eq!(usage.referenced_bytes, 18 * frame_bytes as u64);
        assert_eq!(
            usage.extra_segment_bytes,
            usage.segment_bytes - usage.referenced_bytes
        );
        assert_eq!(usage.charged_bytes, usage.segment_bytes);
        assert_eq!(
            EvidenceRetentionOwner::new(&store)
                .retain(&identity, 50)?
                .removed_records,
            0
        );
        eprintln!(
            "witness_bytes={} segment_bytes={} extra_bytes={} pin_commit_us={} usage_us={}",
            usage.referenced_bytes,
            usage.segment_bytes,
            usage.extra_segment_bytes,
            pin_commit_us,
            usage_us
        );
        eprintln!("history_bytes={} recent_scan={} recent_input={} recent_us={} sparse_scan={} sparse_input={} sparse_us={} debug={}",
            72 * 1024 * 1024, recent.scanned_bytes, recent.input_bytes, recent_us,
            sparse.scanned_bytes, sparse.input_bytes, sparse_us, cfg!(debug_assertions));
        Ok(())
    }
}
