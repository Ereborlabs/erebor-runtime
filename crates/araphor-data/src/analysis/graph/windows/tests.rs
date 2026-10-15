use duckdb::params;

use super::*;
use crate::graph::tests::native_storage::CommitFixture;
use crate::AnalysisResultCommitV1;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct WindowFixture {
    native: CommitFixture,
    second: GraphSnapshotV1,
    request: AnalysisResultCommitV1,
}

impl WindowFixture {
    fn new() -> TestResult<Self> {
        let native = CommitFixture::new()?;
        native.store.commit_graph(&native.request, true)?;
        let (second, request) = native.next_window()?;
        native.store.commit_graph(&request, true)?;
        Ok(Self {
            native,
            second,
            request,
        })
    }

    fn source(&self) -> &EvidenceIntakeIdentityV1 {
        &self.native.snapshot.scope.identity
    }

    fn bounds(&self, after: Option<u64>) -> TestResult<Vec<(u64, u64)>> {
        Ok(self
            .native
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
            let (page, next) = self.native.store.graph_window_page(
                self.source(),
                first,
                last,
                after.as_deref(),
            )?;
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
        let mut snapshot = self.native.snapshot.clone();
        snapshot.last_cursor = last;
        snapshot.previous_result_id = Some(previous.into());
        snapshot.validate()?;
        let mut request = self.native.request.clone();
        request.expected_cursor = 2;
        request.consumed_cursor = 2;
        request.coverage_revision = 2;
        request.result_id = id.into();
        request.created_utc_ns = 12;
        request.body = serde_json::to_vec(&snapshot)?;
        self.native.store.commit_graph(&request, false)?;
        Ok(snapshot)
    }
}

#[test]
fn graph_window_selection() -> TestResult {
    let fixture = WindowFixture::new()?;
    let store = &fixture.native.store;
    assert_eq!(fixture.bounds(None)?, [(1, 1), (2, 2)]);
    assert_eq!(fixture.bounds(Some(1))?, [(2, 2)]);
    assert!(fixture.bounds(Some(2))?.is_empty());
    let selected = fixture.windows(1, 1)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, fixture.native.request.result_id);
    assert_eq!(selected[0].1, fixture.native.snapshot);
    let overlapping = fixture.windows(1, 2)?;
    assert_eq!(overlapping.len(), 2);
    assert_eq!(overlapping[0].1, fixture.native.snapshot);
    assert_eq!(overlapping[1].1, fixture.second);

    let (page, next) = store.graph_window_page(fixture.source(), 2, 2, None)?;
    assert!(page.is_empty());
    assert_eq!(
        next.as_deref(),
        Some(fixture.native.request.result_id.as_str())
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
    for (first, last) in [(0, 1), (2, 1), (1, GRAPH_WINDOW_RECORDS + 1)] {
        assert!(store
            .graph_window_page(fixture.source(), first, last, None)
            .is_err());
    }
    Ok(())
}

#[test]
fn graph_window_replacement() -> TestResult {
    let fixture = WindowFixture::new()?;
    let wide = fixture.replace("graph:a-wide", 2, &fixture.native.request.result_id)?;
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].0, "graph:a-wide");
    assert_eq!(selected[0].1, wide);
    let short = fixture.replace("graph:z-short", 1, "graph:a-wide")?;
    let store = &fixture.native.store;
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
            fixture.native.request.result_id.as_str(),
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
    let store = &fixture.native.store;
    store.writer_access()?.get_mut()?.execute(
        "UPDATE graph_subjects SET subject_kind = repeat('X', length(subject_kind))
         WHERE result_id = ?",
        params![fixture.native.request.result_id],
    )?;
    assert_eq!(fixture.bounds(None)?, [(1, 1), (2, 2)]);
    let selected = fixture.windows(2, 2)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1, fixture.second);
    assert!(fixture.windows(1, 1).is_err());
    store.writer_access()?.get_mut()?.execute(
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?",
        params![fixture.native.request.result_id],
    )?;
    assert!(matches!(
        store.graph_window_headers(fixture.source(), None),
        Err(crate::Error::GraphInvalid { .. })
    ));
    assert!(matches!(
        store.graph_window_page(fixture.source(), 1, 1, None),
        Err(crate::Error::GraphInvalid { .. })
    ));
    Ok(())
}
