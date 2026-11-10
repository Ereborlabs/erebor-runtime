use super::*;

use crate :: { AnalysisPositionPageV1 , AnalysisStreamIdentityV1 , EvidenceRecord , EvidenceRetentionOwner , StorePositionV1 , ValidatedEvidenceBatchV1 } ;
use sdk::arrow_array::{UInt32Array, UInt64Array};

mod contexts;

struct Journal {
    fixture: Fixture,
    selection: AnalysisSelectionV1,
    requests: AnalysisTableRequests,
    limits: AnalysisExtractLimits,
    owners: Option<BTreeSet<String>>,
}

impl Journal {
    fn new(store: &AnalysisStore) -> TestResult<Self> {
        let source = crate::analysis::tests::identity();
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
        selection.contexts = crate::Selection::All;
        let schema = &crate::AnalysisStore::table_schemas()["events"];
        let columns = ["source_cursor", "commit_revision", "ordinal"]
            .into_iter()
            .map(|name| schema.index_of(name))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            fixture: Fixture::admit_scope(store, false, selection.clone())?,
            selection,
            requests: BTreeMap::from([
                ("events".into(), Some(columns)),
                ("coverage".into(), Some(BTreeSet::new())),
                ("context_versions".into(), None),
            ]),
            limits: AnalysisExtractLimits::default(),
            owners: None,
        })
    }

    fn append(store: &AnalysisStore, first: u64, count: usize) -> crate::Result<()> {
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..first + count as u64 {
            bytes.extend(Vec::<u8>::try_from(&EvidenceRecord {
                observed_boottime_ns: cursor,
                ..Default::default()
            })?);
            ends.push(bytes.len());
        }
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: first + count as u64 - 1,
                intake_utc_ns: first,
                framed_records: bytes.into(),
                frame_ends: ends,
            },
        )?;
        Ok(())
    }

    fn request(&self, store: &AnalysisStore) -> TestResult<ManagedRead> {
        Ok(ManagedRead {
            source: None,
            instance: self.fixture.current(store)?,
            execution: None,
            expected: None,
            rebuild: false,
            follow: false,
            completed: None,
        })
    }

    fn read(
        &self,
        store: &AnalysisStore,
        after: StorePositionV1,
        control: &AnalysisReadControl,
    ) -> TestResult<ManagedPage> {
        Ok(self.read_as(store, &self.request(store)?, after, control)?)
    }

    fn read_as(
        &self,
        store: &AnalysisStore,
        request: &ManagedRead,
        after: StorePositionV1,
        control: &AnalysisReadControl,
    ) -> crate::Result<ManagedPage> {
        store.read_managed_tables_filtered(
            &self.selection,
            request,
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Changes(after),
                now: 10,
            },
            self.limits,
            control,
            self.owners.as_ref(),
        )
    }

    fn rows(page: &AnalysisPositionPageV1) -> TestResult<Vec<(u64, StorePositionV1)>> {
        let mut rows = Vec::new();
        for batch in page.tables.get("events").into_iter().flatten() {
            let cursors = batch
                .column_by_name("source_cursor")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or("change cursor absent")?;
            let revisions = batch
                .column_by_name("commit_revision")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or("change revision absent")?;
            let ordinals = batch
                .column_by_name("ordinal")
                .and_then(|column| column.as_any().downcast_ref::<UInt32Array>())
                .ok_or("change ordinal absent")?;
            for row in 0..batch.num_rows() {
                rows.push((
                    cursors.value(row),
                    StorePositionV1 {
                        commit_revision: revisions.value(row),
                        ordinal: ordinals.value(row),
                    },
                ));
            }
        }
        Ok(rows)
    }

    fn frontier(store: &AnalysisStore) -> crate::Result<StorePositionV1> {
        Ok(StorePositionV1 {
            commit_revision: store.meta()?.commit_revision,
            ordinal: u32::MAX,
        })
    }
}

#[test]
fn managed_changes_skip_contexts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    let seed = Journal::frontier(&store)?;
    for revision in 1..=3 {
        store.commit_context(&crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "unselected-context".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: vec![42],
        })?;
    }
    Journal::append(&store, 2, 1)?;
    journal.limits.keys = Some(1);
    let before = store.meta()?;
    let changes = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::rows(&changes.page)?
            .iter()
            .map(|(cursor, _)| *cursor)
            .collect::<Vec<_>>(),
        [2]
    );
    assert!(changes.page.extraction.references.is_empty());
    assert_eq!(
        changes.state.contract.sources,
        journal.selection.source_revisions(before.commit_revision)
    );
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn managed_changes_keep_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("store"))?);
    Journal::append(&store, 1, 4)?;
    let journal = Journal::new(&store)?;
    let seed = Journal::frontier(&store)?;
    let instance = journal.fixture.current(&store)?;
    Journal::append(&store, 11, 10)?;
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&store);
    control.on_read_step(move || Journal::append(&writer, 5, 6))?;
    let first = journal.read(&store, seed, &control)?;
    let rows = Journal::rows(&first.page)?;
    assert_eq!(
        rows.iter().map(|(cursor, _)| *cursor).collect::<Vec<_>>(),
        (11..=20).collect::<Vec<_>>()
    );
    assert!(rows.windows(2).all(|pair| pair[0].1 < pair[1].1));
    assert_eq!(first.page.extraction.meta, before);
    assert_eq!(
        first.page.scanned_through.commit_revision,
        before.commit_revision
    );
    assert_eq!(first.page.scanned_through.ordinal, u32::MAX);
    assert!(first.page.exhausted);
    assert!(first.page.tables.contains_key("coverage"));
    assert!(!first.page.tables.contains_key("context_versions"));
    assert_eq!(first.state.revision(), before.commit_revision);
    assert_eq!(
        first.state.contract.witnesses,
        first.page.extraction.witnesses
    );
    assert_eq!(
        first.state.contract.sources,
        journal.selection.source_revisions(before.commit_revision)
    );
    assert_eq!(first.state.instance(), &instance);
    assert_eq!(journal.fixture.current(&store)?, instance);
    let next = journal.read(
        &store,
        first.page.scanned_through,
        &AnalysisReadControl::default(),
    )?;
    let rows = Journal::rows(&next.page)?;
    assert_eq!(
        rows.iter().map(|(cursor, _)| *cursor).collect::<Vec<_>>(),
        (5..=10).collect::<Vec<_>>()
    );
    assert!(rows
        .iter()
        .all(|(_, position)| *position > first.page.scanned_through));
    assert_eq!(
        next.page.extraction.sources[0].receipt.contiguous_cursor,
        20
    );
    let before = store.meta()?;
    let empty = journal.read(
        &store,
        next.page.scanned_through,
        &AnalysisReadControl::default(),
    )?;
    assert!(Journal::rows(&empty.page)?.is_empty());
    assert_eq!(empty.page.scanned_through, next.page.scanned_through);
    assert_eq!(store.meta()?, before);
    assert_eq!(journal.fixture.current(&store)?, instance);
    assert!(empty.state.prior(10).is_none());
    Ok(())
}

#[test]
fn managed_changes_reject_reads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    let seed = Journal::frontier(&store)?;
    Journal::append(&store, 2, 1)?;
    let before = store.meta()?;
    let request = journal.request(&store)?;
    let control = AnalysisReadControl::default();
    for name in [
        "context",
        "graph_manifest",
        "graph_coverage",
        "findings",
        "notifications",
        "trace_measurements",
    ] {
        journal.requests.insert(name.into(), Some(BTreeSet::new()));
        assert!(matches!(
            journal.read_as(&store, &request, seed, &control),
            Err(crate::Error::Package { .. })
        ));
        journal.requests.remove(name);
    }
    for case in 0..7 {
        let mut invalid = journal.request(&store)?;
        match case {
            0 => invalid.instance.generation += 1,
            1 => invalid.instance.progress += 1,
            2 => invalid.instance.grant.revision += 1,
            3 => invalid.instance.running = !invalid.instance.running,
            4 => invalid.instance.lifecycle += 1,
            5 => invalid.instance.spec.tenant = [2; 16],
            _ => invalid.instance.spec.id.push_str("-absent"),
        }
        assert!(
            journal.read_as(&store, &invalid, seed, &control).is_err(),
            "owner case {case}"
        );
    }
    for after in [
        StorePositionV1 { ordinal: 0, ..seed },
        StorePositionV1 {
            commit_revision: before.commit_revision + 1,
            ordinal: u32::MAX,
        },
    ] {
        assert!(journal.read_as(&store, &request, after, &control).is_err());
    }
    let original = journal.selection.clone();
    for case in 0..4 {
        journal.selection = original.clone();
        match case {
            0 => journal.selection.results.push("not-read".into()),
            1 => journal.selection.graphs = crate::Selection::All,
            2 => journal.selection.profiles = crate::Selection::All,
            _ => {
                journal.selection.contexts =
                    crate::Selection::Exact(vec![crate::AnalysisContextKeyV1 {
                        tenant_id: [1; 16],
                        owner_id: "not-read".into(),
                        entity_key: vec![1],
                        lifetime_key: vec![2],
                        owner_revision: 1,
                    }])
            }
        }
        assert!(
            journal.read_as(&store, &request, seed, &control).is_err(),
            "selection case {case}"
        );
    }
    journal.selection = original;
    let control = Arc::new(AnalysisReadControl::default());
    let cancelled = Arc::clone(&control);
    control.on_read_step(move || cancelled.cancel())?;
    assert!(matches!(
        journal.read_as(&store, &request, seed, &control),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(journal.fixture.current(&store)?, request.instance);
    let retry = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::rows(&retry.page)?
            .iter()
            .map(|(cursor, _)| *cursor)
            .collect::<Vec<_>>(),
        [2]
    );
    Ok(())
}

#[test]
fn managed_changes_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open_retention(&root)?;
    Journal::append(&store, 1, 2)?;
    let journal = Journal::new(&store)?;
    let seed = Journal::frontier(&store)?;
    let source = crate::analysis::tests::identity();
    let retired = EvidenceRetentionOwner::new(&store).retain(&source, u64::MAX)?;
    assert_eq!(retired.removed_records, 2);
    let removals = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert!(Journal::rows(&removals.page)?.is_empty());
    let identity = AnalysisStreamIdentityV1::Evidence(source);
    let gaps = removals
        .page
        .removals
        .get(&identity)
        .ok_or("managed removals absent")?;
    assert_eq!(
        gaps.iter()
            .map(|gap| (gap.first_cursor, gap.last_cursor, gap.commit_revision))
            .collect::<Vec<_>>(),
        [(1, 2, retired.commit_revision)]
    );
    Journal::append(&store, 3, 1)?;
    let before = store.meta()?;
    let changes = journal.read(&store, seed, &AnalysisReadControl::default())?;
    let rows = Journal::rows(&changes.page)?;
    assert_eq!(
        rows.iter().map(|(cursor, _)| *cursor).collect::<Vec<_>>(),
        [3]
    );
    assert_eq!(changes.page.removals, removals.page.removals);
    assert_eq!(
        changes.state.contract.witnesses,
        changes.page.extraction.witnesses
    );
    assert_eq!(store.meta()?, before);
    let instance = journal.fixture.current(&store)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let replay = journal.read(&reopened, seed, &AnalysisReadControl::default())?;
    assert_eq!(Journal::rows(&replay.page)?, rows);
    assert_eq!(replay.page.removals, changes.page.removals);
    assert_eq!(replay.page.scanned_through, changes.page.scanned_through);
    assert_eq!(
        replay.page.extraction.witnesses,
        changes.page.extraction.witnesses
    );
    assert_eq!(journal.fixture.current(&reopened)?, instance);
    assert!(matches!(
        journal.read_as(
            &reopened,
            &journal.request(&reopened)?,
            StorePositionV1 {
                commit_revision: 0,
                ordinal: u32::MAX
            },
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisReplayExpired { .. })
    ));
    Ok(())
}
