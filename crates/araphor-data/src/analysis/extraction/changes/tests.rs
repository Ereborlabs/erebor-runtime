use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk::arrow_array::{UInt32Array, UInt64Array};
use snafu::ResultExt as _;

use super::*;
use crate::{
    AnalysisContextVersionV1, AnalysisReadModeV1, AnalysisTableRead, ContextSensitivityV1,
    EvidenceRetentionOwner, TraceBatchV1, TraceFrameKindV1, TraceFrameV1, TraceStateV1,
    ValidatedEvidenceBatchV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type Row = (u8, u64, u64, StorePositionV1);

fn batch(first: u64, count: usize, received: u64) -> Result<ValidatedEvidenceBatchV1> {
    let mut framed = Vec::new();
    let mut ends = Vec::new();
    for cursor in first..first + count as u64 {
        framed.extend(Vec::<u8>::try_from(&EvidenceRecord {
            observed_boottime_ns: cursor,
            ..Default::default()
        })?);
        ends.push(framed.len());
    }
    Ok(ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: first,
        last_cursor: first + count as u64 - 1,
        intake_utc_ns: received,
        framed_records: framed.into(),
        frame_ends: ends,
    })
}

fn read(
    store: &AnalysisStore,
    selection: &AnalysisSelectionV1,
    mode: AnalysisReadModeV1,
    limits: AnalysisExtractLimits,
    control: &AnalysisReadControl,
) -> Result<AnalysisPositionPageV1> {
    let relations = BTreeSet::from(["events".to_owned(), "trace_output".to_owned()]);
    let columns = [
        (
            "events",
            &[
                "source_cursor",
                "source_epoch",
                "commit_revision",
                "ordinal",
            ][..],
        ),
        (
            "trace_output",
            &["sequence", "commit_revision", "ordinal"][..],
        ),
    ]
    .into_iter()
    .map(|(name, fields)| {
        let schema = &AnalysisStore::table_schemas()[name];
        let indices = fields
            .iter()
            .map(|field| {
                schema
                    .index_of(field)
                    .map_err(araphor_analysis_sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        Ok((name.to_owned(), indices))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;
    store.read_tables(
        selection,
        AnalysisTableRead {
            relations: &relations,
            columns: &columns,
            event_ranges: None,
            inputs: None,
            mode,
            now: 0,
        },
        limits,
        control,
    )
}

fn rows(page: &AnalysisPositionPageV1) -> TestResult<Vec<Row>> {
    let mut rows = Vec::new();
    for (name, kind, cursor) in [
        ("events", 0, "source_cursor"),
        ("trace_output", 2, "sequence"),
    ] {
        let mut selected = Vec::new();
        for batch in page.tables.get(name).into_iter().flatten() {
            let cursors = batch
                .column_by_name(cursor)
                .ok_or("cursor column absent")?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("cursor is not UInt64")?;
            let revisions = batch
                .column_by_name("commit_revision")
                .ok_or("commit revision absent")?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("commit revision is not UInt64")?;
            let ordinals = batch
                .column_by_name("ordinal")
                .ok_or("ordinal absent")?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("ordinal is not UInt32")?;
            for index in 0..batch.num_rows() {
                selected.push((
                    kind,
                    cursors.value(index),
                    cursors.value(index),
                    StorePositionV1 {
                        commit_revision: revisions.value(index),
                        ordinal: ordinals.value(index),
                    },
                ));
            }
        }
        assert!(selected.windows(2).all(|pair| pair[0].3 < pair[1].3));
        rows.extend(selected);
    }
    for ranges in page.removals.values() {
        for range in ranges {
            rows.push((
                1,
                range.first_cursor,
                range.last_cursor,
                StorePositionV1 {
                    commit_revision: range.commit_revision,
                    ordinal: u32::MAX,
                },
            ));
        }
    }
    rows.sort_by_key(|row| row.3);
    Ok(rows)
}

#[test]
fn raw_changes_snapshot() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let source = crate::analysis::tests::identity();
    store.accept_validated_batch(source.clone(), batch(1, 1, 10)?)?;
    let selection = AnalysisSelectionV1::tenant(source.tenant_id);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let seed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    store.accept_validated_batch(source.clone(), batch(11, 10, 10)?)?;
    store.commit_context(&AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "change-proof".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![42],
    })?;
    let before = store.meta()?;
    let late = EvidenceIntakeIdentityV1 {
        source_epoch: 2,
        ..source.clone()
    };
    let writer = Arc::clone(&store);
    let repairing = source.clone();
    control.on_read_step(move || {
        writer.accept_validated_batch(repairing, batch(2, 9, 20)?)?;
        writer.accept_validated_batch(late, batch(1, 1, 30)?)?;
        Ok(())
    })?;
    let first = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        Default::default(),
        &control,
    )?;
    let first_rows = rows(&first)?;
    assert_eq!(first.extraction.meta, before);
    assert_eq!(
        first.scanned_through,
        StorePositionV1 {
            commit_revision: before.commit_revision,
            ordinal: u32::MAX
        }
    );
    assert!(first.exhausted);
    assert_eq!(
        first_rows.iter().map(|row| row.1).collect::<Vec<_>>(),
        (11..=20).collect::<Vec<_>>()
    );
    assert_eq!(first.extraction.sources.len(), 1);
    assert_eq!(first.extraction.sources[0].receipt.contiguous_cursor, 1);
    assert_eq!(first.extraction.sources[0].pending.len(), 1);
    assert_eq!(
        (
            first.extraction.sources[0].pending[0].first_cursor,
            first.extraction.sources[0].pending[0].last_cursor
        ),
        (2, 10)
    );
    assert!(first
        .extraction
        .references
        .iter()
        .all(|entry| entry.context().is_none()));
    let next = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(first.scanned_through),
        Default::default(),
        &control,
    )?;
    let next_rows = rows(&next)?;
    assert_eq!(next.extraction.sources.len(), 2);
    assert_eq!(
        next_rows.iter().map(|row| row.1).collect::<Vec<_>>(),
        (2..=10).chain([1]).collect::<Vec<_>>()
    );
    assert!(next_rows.iter().all(|row| row.3 > first.scanned_through));
    assert!(next_rows.windows(2).all(|pair| pair[0].3 < pair[1].3));
    assert_eq!(
        next.scanned_through.commit_revision,
        store.meta()?.commit_revision
    );
    assert_eq!(next.scanned_through.ordinal, u32::MAX);
    let unchanged = store.meta()?;
    store.accept_validated_batch(source, batch(11, 10, 10)?)?;
    assert_eq!(store.meta()?, unchanged);
    let empty = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(next.scanned_through),
        Default::default(),
        &control,
    )?;
    assert!(rows(&empty)?.is_empty());
    assert!(empty.exhausted);
    assert_eq!(empty.scanned_through, next.scanned_through);
    Ok(())
}

#[test]
fn raw_changes_retirement() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let source = crate::analysis::tests::identity();
    let next = EvidenceIntakeIdentityV1 {
        source_epoch: 2,
        ..source.clone()
    };
    let excluded = EvidenceIntakeIdentityV1 {
        node_id: "node-b".into(),
        source_epoch: 3,
        ..source.clone()
    };
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [2; 16],
        ..source.clone()
    };
    store.accept_validated_batch(source.clone(), batch(1, 2, 10)?)?;
    store.accept_validated_batch(next.clone(), batch(1, 1, 10)?)?;
    store.accept_validated_batch(excluded.clone(), batch(1, 1, 10)?)?;
    store.accept_validated_batch(foreign.clone(), batch(1, 1, 10)?)?;
    let mut selection = AnalysisSelectionV1::tenant(source.tenant_id);
    selection.nodes.push(source.node_id.clone());
    selection.received_until = Bound::Included(30);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let seed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    store.accept_validated_batch(next.clone(), batch(2, 1, 20)?)?;
    let first = StorePositionV1 {
        commit_revision: store.meta()?.commit_revision,
        ordinal: 0,
    };
    let retired = EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
    assert_eq!(retired.removed_records, 2);
    EvidenceRetentionOwner::new(&store).retain(&excluded, u64::MAX)?;
    EvidenceRetentionOwner::new(&store).retain(&foreign, u64::MAX)?;
    store.accept_validated_batch(next.clone(), batch(3, 1, 30)?)?;
    let last = StorePositionV1 {
        commit_revision: store.meta()?.commit_revision,
        ordinal: 0,
    };
    store.accept_validated_batch(next.clone(), batch(4, 1, 40)?)?;
    let before = store.meta()?;
    let changes = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        Default::default(),
        &control,
    )?;
    let expected = vec![
        (0, 2, 2, first),
        (
            1,
            1,
            2,
            StorePositionV1 {
                commit_revision: retired.commit_revision,
                ordinal: u32::MAX,
            },
        ),
        (0, 3, 3, last),
    ];
    assert_eq!(rows(&changes)?, expected);
    assert_eq!(
        changes.removals.keys().collect::<Vec<_>>(),
        [&RawIdentity::Evidence(source.clone())]
    );
    for batch in changes.tables.get("events").into_iter().flatten() {
        let epochs = batch
            .column_by_name("source_epoch")
            .ok_or("source epoch absent")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("source epoch is not UInt64")?;
        assert!(epochs
            .values()
            .iter()
            .all(|epoch| *epoch == next.source_epoch));
    }
    assert_eq!(changes.extraction.meta, before);
    assert_eq!(changes.extraction.sources.len(), 2);
    assert_eq!(
        changes.scanned_through,
        StorePositionV1 {
            commit_revision: before.commit_revision,
            ordinal: u32::MAX
        }
    );
    let backup = root.join("backups/changes");
    store.backup(&backup)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    for store in [&reopened, &restored] {
        let page = read(
            store,
            &selection,
            AnalysisReadModeV1::Changes(seed.scanned_through),
            Default::default(),
            &control,
        )?;
        assert_eq!(rows(&page)?, expected);
        assert_eq!(page.scanned_through, changes.scanned_through);
        let position = StorePositionV1 {
            commit_revision: 0,
            ordinal: u32::MAX,
        };
        assert!(
            matches!(read(store, &selection, AnalysisReadModeV1::Changes(position), Default::default(), &control),
            Err(crate::Error::AnalysisReplayExpired { position: actual, floor, .. })
                if actual == position && Some(floor) == store.replay_floor(source.tenant_id)?)
        );
        let empty = read(
            store,
            &selection,
            AnalysisReadModeV1::Changes(page.scanned_through),
            Default::default(),
            &control,
        )?;
        assert!(rows(&empty)?.is_empty());
        assert!(empty.exhausted);
        assert_eq!(empty.scanned_through, page.scanned_through);
    }
    Ok(())
}

#[test]
fn raw_changes_binding() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let source = crate::analysis::tests::identity();
    let mut selection = AnalysisSelectionV1::tenant(source.tenant_id);
    selection.binding_ids.push([9; 16]);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let seed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for binding in [Some(9), Some(8), None] {
        let record = EvidenceRecord {
            observed_boottime_ns: 1,
            decision_context: binding.map(|value| crate::EvidenceDecisionContext {
                binding_id: vec![value; 16],
                ..Default::default()
            }),
            ..Default::default()
        };
        bytes.extend(Vec::<u8>::try_from(&record)?);
        ends.push(bytes.len());
    }
    store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            framed_records: bytes.into(),
            frame_ends: ends,
            ..batch(1, 3, 10)?
        },
    )?;
    let page = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        Default::default(),
        &control,
    )?;
    assert_eq!(
        rows(&page)?.iter().map(|row| row.1).collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 3);
    EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
    let removed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(page.scanned_through),
        Default::default(),
        &control,
    )?;
    assert!(removed.exhausted);
    assert_eq!(removed.scanned_through.ordinal, u32::MAX);
    assert!(removed.scanned_through > page.scanned_through);
    assert_eq!(
        rows(&removed)?
            .iter()
            .map(|row| (row.0, row.1, row.2))
            .collect::<Vec<_>>(),
        [(1, 1, 3)]
    );
    Ok(())
}

#[test]
fn raw_changes_bounds() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let source = crate::analysis::tests::identity();
    store.accept_validated_batch(source.clone(), batch(1, 1, 10)?)?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let seed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    store.accept_validated_batch(source, batch(2, 3, 20)?)?;
    let complete = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        AnalysisExtractLimits {
            page_rows: 1,
            page_bytes: 1,
            ..Default::default()
        },
        &control,
    )?;
    let complete_rows = rows(&complete)?;
    assert_eq!(
        complete_rows.iter().map(|row| row.1).collect::<Vec<_>>(),
        [2, 3, 4]
    );
    assert_eq!(complete_rows.len(), 3);
    assert_eq!(complete.scanned_through.ordinal, u32::MAX);
    assert!(complete.exhausted);
    assert!(matches!(
        read(
            &store,
            &selection,
            AnalysisReadModeV1::Changes(StorePositionV1 {
                ordinal: 0,
                ..seed.scanned_through
            }),
            Default::default(),
            &control
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    for limits in [
        AnalysisExtractLimits {
            scan_bytes: 1,
            ..Default::default()
        },
        AnalysisExtractLimits {
            input_bytes: 1,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            read(
                &store,
                &selection,
                AnalysisReadModeV1::Changes(seed.scanned_through),
                limits,
                &control
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
    }
    let interrupted = Arc::new(AnalysisReadControl::default());
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mark = Arc::clone(&observed);
    let cancel = Arc::clone(&interrupted);
    interrupted.on_read_step(move || {
        mark.store(true, std::sync::atomic::Ordering::Release);
        cancel.cancel()
    })?;
    assert!(matches!(
        read(
            &store,
            &selection,
            AnalysisReadModeV1::Changes(seed.scanned_through),
            Default::default(),
            &interrupted
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    let recovered = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        Default::default(),
        &control,
    )?;
    assert_eq!(rows(&recovered)?, complete_rows);
    assert_eq!(recovered.scanned_through, complete.scanned_through);
    assert!(recovered.exhausted);
    assert!(store.maintenance.try_write().is_ok());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        read(
            &store,
            &selection,
            AnalysisReadModeV1::Changes(seed.scanned_through),
            Default::default(),
            &cancelled
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(StorePositionV1 {
            commit_revision: complete.scanned_through.commit_revision + 1,
            ordinal: u32::MAX
        }),
        Default::default(),
        &control
    )
    .is_err());
    Ok(())
}

#[test]
fn trace_changes_retirement() -> TestResult {
    use crate::analysis::raw::tests::{trace_intent, trace_terminal};

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    let state = store.accept_trace(&intent)?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, Vec::new());
    selection.traces = Selection::Exact(vec![identity.clone()]);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let seed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Complete,
        Default::default(),
        &control,
    )?;
    assert!(rows(&seed)?.is_empty());
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1],
            }],
            terminal: None,
        },
        100,
    )?;
    let data = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(seed.scanned_through),
        Default::default(),
        &control,
    )?;
    assert_eq!(
        rows(&data)?
            .iter()
            .map(|row| (row.0, row.1))
            .collect::<Vec<_>>(),
        [(2, 1)]
    );
    assert_eq!(data.extraction.trace_reads(), &[identity.request_id]);
    let state = store.update_trace(&TraceStateV1 {
        cancel_requested: true,
        ..state
    })?;
    let flags = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(data.scanned_through),
        Default::default(),
        &control,
    )?;
    assert!(rows(&flags)?.is_empty());
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: Vec::new(),
            terminal: Some(trace_terminal(1, 1)),
        },
        101,
    )?;
    let terminal = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(flags.scanned_through),
        Default::default(),
        &control,
    )?;
    assert_eq!(
        rows(&terminal)?
            .iter()
            .map(|row| (row.0, row.1))
            .collect::<Vec<_>>(),
        [(2, 2)]
    );
    let retired = EvidenceRetentionOwner::new(&store).retain_trace(identity, u64::MAX)?;
    assert_eq!(retired.removed_records, 2);
    let removed = read(
        &store,
        &selection,
        AnalysisReadModeV1::Changes(terminal.scanned_through),
        Default::default(),
        &control,
    )?;
    assert_eq!(
        removed.removals.keys().collect::<Vec<_>>(),
        [&RawIdentity::Diagnostic(identity.clone())]
    );
    assert_eq!(
        rows(&removed)?,
        [(
            1,
            1,
            2,
            StorePositionV1 {
                commit_revision: retired.commit_revision,
                ordinal: u32::MAX
            }
        )]
    );
    let mut excluded = selection.clone();
    excluded.binding_ids.push([8; 16]);
    let empty = read(
        &store,
        &excluded,
        AnalysisReadModeV1::Changes(terminal.scanned_through),
        Default::default(),
        &control,
    )?;
    assert!(rows(&empty)?.is_empty());
    assert!(empty.extraction.trace_reads().is_empty());
    store.update_trace(&TraceStateV1 {
        read_revoked: true,
        ..state
    })?;
    assert!(matches!(
        read(
            &store,
            &selection,
            AnalysisReadModeV1::Changes(removed.scanned_through),
            Default::default(),
            &control
        ),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    Ok(())
}
