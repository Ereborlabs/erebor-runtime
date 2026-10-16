use super::*;
use crate::{
    ContextSensitivityV1, EvidenceRetentionOwner, TraceBatchV1, TraceFrameKindV1, TraceFrameV1,
    ValidatedEvidenceBatchV1,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
type Row = (u8, u64, u64, StorePositionV1);

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

fn row(input: AnalysisInputV1<'_>) -> Result<Option<(Row, usize)>> {
    Ok(Some((
        match input {
            AnalysisInputV1::Event { record, .. } => {
                (0, record.cursor, record.cursor, record.position)
            }
            AnalysisInputV1::RawRemoval {
                first_cursor,
                last_cursor,
                position,
                ..
            } => (1, first_cursor, last_cursor, position),
            AnalysisInputV1::TraceOutput {
                sequence, position, ..
            } => (2, sequence, sequence, position),
            _ => {
                return AnalysisStore::reject_path(
                    std::path::Path::new("<test>"),
                    "metadata entered raw changes",
                )
            }
        },
        0,
    )))
}

struct Rows<F> {
    project: F,
    rows: Vec<Row>,
    page_bytes: usize,
}

impl<F> Rows<F> {
    fn new(project: F) -> Self {
        Self {
            project,
            rows: Vec::new(),
            page_bytes: MAX_ANALYSIS_PAGE_BYTES,
        }
    }
}

impl<F> AnalysisProjection for Rows<F>
where
    F: FnMut(AnalysisInputV1<'_>) -> Result<Option<(Row, usize)>>,
{
    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> Result<bool> {
        let Some((row, heap)) = (self.project)(input)? else {
            return Ok(true);
        };
        let bytes = heap
            .checked_add(size_of::<Row>())
            .filter(|bytes| *bytes <= self.page_bytes)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "projected row bytes",
                }
                .build()
            })?;
        if !sink.admit(bytes)? {
            return Ok(false);
        }
        sink.charge(heap)?;
        sink.grow(&mut self.rows)?;
        sink.projected(heap);
        self.rows.push(row);
        Ok(true)
    }
}

#[test]
fn raw_changes_snapshot() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let source = crate::analysis::tests::identity();
    store.accept_validated_batch(source.clone(), batch(1, 1, 10))?;
    let selection = AnalysisSelectionV1::tenant(source.tenant_id);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let (seed, _) = store.extract_rows(&selection, Default::default(), &control, Rows::new(row))?;
    store.accept_validated_batch(source.clone(), batch(11, 10, 10))?;
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
    let (
        first,
        Rows {
            rows: first_rows, ..
        },
    ) = store.change_rows(
        &selection,
        seed.scanned_through,
        Default::default(),
        &control,
        Rows::new(|input: AnalysisInputV1<'_>| {
            if let AnalysisInputV1::Event { record, .. } = &input {
                if record.cursor == 11 {
                    store.accept_validated_batch(source.clone(), batch(2, 9, 20))?;
                    store.accept_validated_batch(late.clone(), batch(1, 1, 30))?;
                }
            }
            row(input)
        }),
    )?;
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
    assert!(first.extraction.context_refs.is_empty());
    let (
        next,
        Rows {
            rows: next_rows, ..
        },
    ) = store.change_rows(
        &selection,
        first.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
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
    store.accept_validated_batch(source, batch(11, 10, 10))?;
    assert_eq!(store.meta()?, unchanged);
    let (
        empty,
        Rows {
            rows: empty_rows, ..
        },
    ) = store.change_rows(
        &selection,
        next.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert!(empty_rows.is_empty());
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
    store.accept_validated_batch(source.clone(), batch(1, 2, 10))?;
    store.accept_validated_batch(next.clone(), batch(1, 1, 10))?;
    store.accept_validated_batch(excluded.clone(), batch(1, 1, 10))?;
    store.accept_validated_batch(foreign.clone(), batch(1, 1, 10))?;
    let mut selection = AnalysisSelectionV1::tenant(source.tenant_id);
    selection.nodes.push(source.node_id.clone());
    selection.received_until = Bound::Included(30);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let (seed, _) = store.extract_rows(&selection, Default::default(), &control, Rows::new(row))?;
    store.accept_validated_batch(next.clone(), batch(2, 1, 20))?;
    let first = StorePositionV1 {
        commit_revision: store.meta()?.commit_revision,
        ordinal: 0,
    };
    let retired = EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
    assert_eq!(retired.removed_records, 2);
    EvidenceRetentionOwner::new(&store).retain(&excluded, u64::MAX)?;
    EvidenceRetentionOwner::new(&store).retain(&foreign, u64::MAX)?;
    store.accept_validated_batch(next.clone(), batch(3, 1, 30))?;
    let last = StorePositionV1 {
        commit_revision: store.meta()?.commit_revision,
        ordinal: 0,
    };
    store.accept_validated_batch(next.clone(), batch(4, 1, 40))?;
    let before = store.meta()?;
    let (
        changes,
        Rows {
            rows: changes_rows, ..
        },
    ) = store.change_rows(
        &selection,
        seed.scanned_through,
        Default::default(),
        &control,
        Rows::new(|input: AnalysisInputV1<'_>| {
            match &input {
                AnalysisInputV1::Event { identity, .. } => assert_eq!(*identity, &next),
                AnalysisInputV1::RawRemoval { identity, .. } => {
                    assert_eq!(*identity, &RawIdentity::Evidence(source.clone()))
                }
                _ => {}
            }
            row(input)
        }),
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
    assert_eq!(changes_rows, expected);
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
        let (
            page,
            Rows {
                rows: page_rows, ..
            },
        ) = store.change_rows(
            &selection,
            seed.scanned_through,
            Default::default(),
            &control,
            Rows::new(row),
        )?;
        assert_eq!(page_rows, expected);
        assert_eq!(page.scanned_through, changes.scanned_through);
        let position = StorePositionV1 {
            commit_revision: 0,
            ordinal: u32::MAX,
        };
        assert!(matches!(
            store.change_rows(&selection, position, Default::default(), &control, Rows::new(row)),
            Err(crate::Error::AnalysisReplayExpired { position: actual, floor, .. })
                if actual == position && Some(floor) == store.replay_floor(source.tenant_id)?
        ));
        let (
            empty,
            Rows {
                rows: empty_rows, ..
            },
        ) = store.change_rows(
            &selection,
            page.scanned_through,
            Default::default(),
            &control,
            Rows::new(row),
        )?;
        assert!(empty_rows.is_empty());
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
    let (seed, _) = store.extract_rows(&selection, Default::default(), &control, Rows::new(row))?;
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
            ..batch(1, 3, 10)
        },
    )?;
    let (
        page,
        Rows {
            rows: page_rows, ..
        },
    ) = store.change_rows(
        &selection,
        seed.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert_eq!(page_rows.iter().map(|row| row.1).collect::<Vec<_>>(), [1]);
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 3);
    EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
    let (
        removed,
        Rows {
            rows: removed_rows, ..
        },
    ) = store.change_rows(
        &selection,
        page.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert!(removed.exhausted);
    assert_eq!(removed.scanned_through.ordinal, u32::MAX);
    assert!(removed.scanned_through > page.scanned_through);
    assert_eq!(
        removed_rows
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
    store.accept_validated_batch(source.clone(), batch(1, 1, 10))?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let (seed, _) = store.extract_rows(&selection, Default::default(), &control, Rows::new(row))?;
    store.accept_validated_batch(source, batch(2, 3, 20))?;
    let (
        complete,
        Rows {
            rows: complete_rows,
            ..
        },
    ) = store.change_rows(
        &selection,
        seed.scanned_through,
        AnalysisExtractLimits {
            page_rows: 1,
            ..Default::default()
        },
        &control,
        Rows::new(row),
    )?;
    assert_eq!(
        complete_rows.iter().map(|row| row.1).collect::<Vec<_>>(),
        [2, 3, 4]
    );
    assert_eq!(complete_rows.len(), 3);
    assert_eq!(complete.scanned_through.ordinal, u32::MAX);
    assert!(complete.exhausted);
    assert!(matches!(
        store.change_rows(
            &selection,
            StorePositionV1 {
                ordinal: 0,
                ..seed.scanned_through
            },
            Default::default(),
            &control,
            Rows::new(row)
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    for limits in [
        AnalysisExtractLimits {
            scan_bytes: 1,
            ..Default::default()
        },
        AnalysisExtractLimits {
            page_bytes: 1,
            ..Default::default()
        },
        AnalysisExtractLimits {
            input_bytes: 1,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            store.change_rows(
                &selection,
                seed.scanned_through,
                limits,
                &control,
                Rows {
                    page_bytes: limits.page_bytes,
                    ..Rows::new(row)
                }
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
    }
    struct Stop;
    impl AnalysisProjection for Stop {
        fn project(&mut self, _: AnalysisInputV1<'_>, _: &mut ProjectionSink<'_>) -> Result<bool> {
            Ok(false)
        }
    }
    assert!(matches!(
        store.change_rows(
            &selection,
            seed.scanned_through,
            Default::default(),
            &control,
            Stop
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "complete change input",
            ..
        })
    ));
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.change_rows(
            &selection,
            seed.scanned_through,
            Default::default(),
            &cancelled,
            Rows::new(row)
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(store
        .change_rows(
            &selection,
            StorePositionV1 {
                commit_revision: complete.scanned_through.commit_revision + 1,
                ordinal: u32::MAX
            },
            Default::default(),
            &control,
            Rows::new(row)
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
    let (seed, _) = store.extract_rows(
        &selection,
        Default::default(),
        &control,
        Rows::new(|input: AnalysisInputV1<'_>| match input {
            AnalysisInputV1::Trace { .. } => Ok(None::<(Row, usize)>),
            input => row(input),
        }),
    )?;
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
    let (
        data,
        Rows {
            rows: data_rows, ..
        },
    ) = store.change_rows(
        &selection,
        seed.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert_eq!(
        data_rows
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
    let (
        flags,
        Rows {
            rows: flags_rows, ..
        },
    ) = store.change_rows(
        &selection,
        data.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert!(flags_rows.is_empty());
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: Vec::new(),
            terminal: Some(trace_terminal(1, 1)),
        },
        101,
    )?;
    let (
        terminal,
        Rows {
            rows: terminal_rows,
            ..
        },
    ) = store.change_rows(
        &selection,
        flags.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert_eq!(
        terminal_rows
            .iter()
            .map(|row| (row.0, row.1))
            .collect::<Vec<_>>(),
        [(2, 2)]
    );
    let retired = EvidenceRetentionOwner::new(&store).retain_trace(identity, u64::MAX)?;
    assert_eq!(retired.removed_records, 2);
    let (
        removed,
        Rows {
            rows: removed_rows, ..
        },
    ) = store.change_rows(
        &selection,
        terminal.scanned_through,
        Default::default(),
        &control,
        Rows::new(|input: AnalysisInputV1<'_>| {
            if let AnalysisInputV1::RawRemoval {
                identity: actual, ..
            } = &input
            {
                assert_eq!(*actual, &RawIdentity::Diagnostic(identity.clone()));
            }
            row(input)
        }),
    )?;
    assert_eq!(
        removed_rows,
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
    let (
        empty,
        Rows {
            rows: empty_rows, ..
        },
    ) = store.change_rows(
        &excluded,
        terminal.scanned_through,
        Default::default(),
        &control,
        Rows::new(row),
    )?;
    assert!(empty_rows.is_empty());
    assert!(empty.extraction.trace_reads().is_empty());
    store.update_trace(&TraceStateV1 {
        read_revoked: true,
        ..state
    })?;
    assert!(matches!(
        store.change_rows(
            &selection,
            removed.scanned_through,
            Default::default(),
            &control,
            Rows::new(row)
        ),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    Ok(())
}
