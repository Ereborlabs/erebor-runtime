use super::*;
use araphor_data::{
    AnalysisResultCommitV1, AnalysisStore, AnalysisWitnessV1, CoverageCounters, CoverageInterval,
    CoverageReport, EvidenceIntakeIdentityV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1,
};
use prost::Message as _;

struct WindowFixture {
    store: AnalysisStore,
    first: GraphSnapshotV1,
    first_request: AnalysisResultCommitV1,
    second: GraphSnapshotV1,
    request: AnalysisResultCommitV1,
    _directory: tempfile::TempDir,
}

impl WindowFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let source = fixture::source();
        store.enable_graph_owner()?;
        store.register_graph(&source)?;
        let mut windows = Vec::new();
        for cursor in 1..=2 {
            let wire = fixture::wire(
                cursor,
                EffectPhysicalResultV1::DeniedBeforeEffect,
                2,
                2,
                [19 + cursor as u8; 16],
            );
            let frame = Vec::<u8>::try_from(&wire)?;
            store.accept_validated_batch(
                source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: cursor,
                    frame_ends: vec![frame.len()],
                    framed_records: frame.into(),
                },
            )?;
            let report = CoverageReport {
                source_id: source.source_id.to_vec(),
                cpu_id: 0,
                source_epoch: source.source_epoch,
                revision: cursor,
                intervals: vec![CoverageInterval {
                    interval_id: vec![4; 16],
                    source_epoch: source.source_epoch,
                    revision: cursor,
                    state: "HEALTHY".into(),
                    first_sequence: 1,
                    last_sequence: Some(cursor),
                    opening_counters: Some(Default::default()),
                    closing_counters: Some(CoverageCounters {
                        attempted: cursor,
                        requested: cursor,
                        emitted: cursor,
                        next_sequence: cursor + 1,
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
            };
            store.accept_validated_coverage(ValidatedCoverageV1 {
                identity: source.clone(),
                cpu_id: 0,
                revision: cursor,
                encoded_report: report.encode_to_vec(),
            })?;
            let mut input = fixture::input(vec![fixture::record(cursor, &wire)?]);
            input.coverage[0].coverage_revision = cursor;
            input.coverage_keys[0].report_revision = cursor;
            input.coverage_keys[0].interval_revision = cursor;
            let mut snapshot = derive(&input)?;
            snapshot.witness_deadline_utc_ns = 10 + GRAPH_WITNESS_TTL_NS;
            let request = AnalysisResultCommitV1 {
                scope: snapshot.scope.clone(),
                expected_cursor: cursor - 1,
                consumed_cursor: cursor,
                coverage_revision: cursor,
                context_revision: 0,
                result_id: if cursor == 1 {
                    "graph:native-storage".into()
                } else {
                    "graph:notice-second-window".into()
                },
                body: serde_json::to_vec(&snapshot)?,
                created_utc_ns: cursor + 9,
                witnesses: vec![AnalysisWitnessV1 {
                    identity: source.clone().into(),
                    cursor,
                    expires_utc_ns: snapshot.witness_deadline_utc_ns,
                }],
                context_refs: Vec::new(),
            };
            store.commit_graph(&request, true, || Ok(()))?;
            windows.push((snapshot, request));
        }
        let [first, second]: [_; 2] = windows.try_into().map_err(|_| "two windows")?;
        Ok(Self {
            store,
            first: first.0,
            first_request: first.1,
            second: second.0,
            request: second.1,
            _directory: directory,
        })
    }

    fn source(&self) -> &EvidenceIntakeIdentityV1 {
        &self.first.scope.identity
    }

    fn bounds(&self, after: Option<u64>) -> TestResult<Vec<(u64, u64)>> {
        Ok(self
            .store
            .graph_window_headers(self.source(), after)?
            .into_iter()
            .map(|(_, header, _)| {
                assert!(header.graph.subjects.is_empty());
                assert!(header.graph.edges.is_empty());
                assert!(header.findings.is_empty());
                (header.first_cursor, header.last_cursor)
            })
            .collect())
    }

    fn windows(&self, first: u64, last: u64) -> TestResult<Vec<(String, GraphSnapshotV1, u64)>> {
        let mut values = Vec::new();
        let mut after = None;
        loop {
            let (page, next) =
                self.store
                    .graph_window_page(self.source(), first, last, after.as_deref())?;
            let Some(next) = next else {
                assert!(page.is_empty());
                break;
            };
            assert!(after.as_ref().is_none_or(|after| after < &next));
            after = Some(next);
            values.extend(page);
        }
        Ok(values)
    }

    fn replace(&self, id: &str, last: u64, previous: &str) -> TestResult<GraphSnapshotV1> {
        let mut snapshot = self.first.clone();
        snapshot.last_cursor = last;
        snapshot.previous_result_id = Some(previous.into());
        snapshot.validate()?;
        let mut request = self.first_request.clone();
        request.expected_cursor = 2;
        request.consumed_cursor = 2;
        request.coverage_revision = 2;
        request.result_id = id.into();
        request.created_utc_ns = 12;
        request.body = serde_json::to_vec(&snapshot)?;
        self.store.commit_graph(&request, false, || Ok(()))?;
        Ok(snapshot)
    }
}

#[test]
fn graph_window_selection() -> TestResult {
    let fixture = WindowFixture::new()?;
    let store = &fixture.store;
    assert_eq!(fixture.bounds(None)?, [(1, 1), (2, 2)]);
    assert_eq!(fixture.bounds(Some(1))?, [(2, 2)]);
    assert!(fixture.bounds(Some(2))?.is_empty());
    let selected = fixture.windows(1, 1)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, fixture.first_request.result_id);
    assert_eq!(selected[0].1, fixture.first);
    let overlapping = fixture.windows(1, 2)?;
    assert_eq!(overlapping.len(), 2);
    assert_eq!(overlapping[0].1, fixture.first);
    assert_eq!(overlapping[1].1, fixture.second);

    let (page, next) = store.graph_window_page(fixture.source(), 2, 2, None)?;
    assert!(page.is_empty());
    assert_eq!(
        next.as_deref(),
        Some(fixture.first_request.result_id.as_str())
    );
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, fixture.request.result_id);
    assert_eq!(selected[0].1, fixture.second);
    let mut foreign = fixture.source().clone();
    foreign.tenant_id = [99; 16];
    assert!(store.graph_window_headers(&foreign, None)?.is_empty());
    assert_eq!(
        store.graph_window_page(&foreign, 1, 2, None)?,
        (Vec::new(), None)
    );
    for (first, last) in [(0, 1), (2, 1)] {
        assert!(store
            .graph_window_page(fixture.source(), first, last, None)
            .is_err());
    }
    Ok(())
}

#[test]
fn graph_window_replacement() -> TestResult {
    let fixture = WindowFixture::new()?;
    let wide = fixture.replace("graph:a-wide", 2, &fixture.first_request.result_id)?;
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].0, "graph:a-wide");
    assert_eq!(selected[0].1, wide);
    let short = fixture.replace("graph:z-short", 1, "graph:a-wide")?;
    let store = &fixture.store;
    assert_eq!(fixture.bounds(None)?, [(1, 1), (2, 2)]);
    assert_eq!(fixture.bounds(Some(1))?, [(2, 2)]);
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, fixture.request.result_id);
    assert_eq!(selected[0].1, fixture.second);
    assert_eq!(
        store.graph_result(fixture.source().tenant_id, "graph:a-wide")?,
        Some(wide)
    );
    assert_eq!(
        store.graph_result(fixture.source().tenant_id, "graph:z-short")?,
        Some(short)
    );
    let mut after = None;
    let mut ids = Vec::new();
    loop {
        let page = store.graph_snapshots(
            fixture.source().tenant_id,
            Some(fixture.source()),
            after.as_deref(),
            false,
        )?;
        if page.is_empty() {
            break;
        }
        after = page.last().map(|row| row.0.clone());
        ids.extend(page.into_iter().map(|row| row.0));
    }
    assert_eq!(
        ids,
        [
            "graph:a-wide",
            fixture.first_request.result_id.as_str(),
            fixture.request.result_id.as_str(),
            "graph:z-short"
        ]
    );
    assert_eq!(
        store.graph_snapshot(fixture.source())?,
        Some(fixture.second)
    );
    Ok(())
}

#[test]
fn graph_window_metadata() -> TestResult {
    let fixture = WindowFixture::new()?;
    let store = &fixture.store;
    store.fault_write(
        "UPDATE graph_subjects SET subject_kind = repeat('X', length(subject_kind))
         WHERE result_id = ?",
        &[&fixture.first_request.result_id],
    )?;
    assert_eq!(fixture.bounds(None)?, [(1, 1), (2, 2)]);
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1, fixture.second);
    assert!(fixture.windows(1, 1).is_err());
    store.fault_write(
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?",
        &[&fixture.first_request.result_id],
    )?;
    assert!(matches!(
        store.graph_window_headers(fixture.source(), None),
        Err(araphor_data::Error::GraphInvalid { .. })
    ));
    assert!(matches!(
        store.graph_window_page(fixture.source(), 1, 1, None),
        Err(araphor_data::Error::GraphInvalid { .. })
    ));
    Ok(())
}
