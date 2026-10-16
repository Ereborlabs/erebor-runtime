use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
};
use datafusion::common::ScalarValue;
use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;

use super::SourceSnapshot;
use crate::execution::{Engine, Limits};
use crate::parser::Parser;
use crate::planner::Planner;

struct Fixture {
    engine: Arc<Engine>,
    state: SessionState,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(store, Limits::default()).unwrap();
        let state = engine.catalog(BTreeMap::new()).unwrap();
        Self {
            engine,
            state,
            _directory: directory,
        }
    }

    async fn plan(&self, capture: &Arc<SourceSnapshot>, sql: &str, parameters: Vec<ScalarValue>) {
        let mut state = self.state.clone();
        state.config_mut().set_extension(Arc::clone(capture));
        let plan = Planner::new(&state)
            .build(Parser::parse(sql).unwrap(), parameters)
            .await
            .unwrap();
        state.create_physical_plan(&plan).await.unwrap();
    }

    fn capture(&self, selection: AnalysisSelectionV1) -> Arc<SourceSnapshot> {
        SourceSnapshot::new(
            Arc::clone(self.engine.store()),
            selection,
            AnalysisExtractLimits::default(),
            AnalysisReadControl::default(),
            Duration::from_secs(5),
            0,
            Arc::clone(self.engine.memory()),
        )
    }
}

#[tokio::test]
async fn native_fixed_time_bounds() {
    let fixture = Fixture::new();
    for (field, first, last) in [
        (
            "received_utc_ns",
            ScalarValue::UInt64(Some(1000)),
            ScalarValue::UInt64(Some(3000)),
        ),
        (
            "received_at",
            ScalarValue::TimestampMicrosecond(Some(1), None),
            ScalarValue::TimestampMicrosecond(Some(3), None),
        ),
    ] {
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        let capture = fixture.capture(selection.clone());
        fixture
            .plan(
                &capture,
                &format!("SELECT count(*) FROM events e WHERE e.{field} >= $1 AND e.{field} < $2"),
                vec![first, last],
            )
            .await;
        let (requests, bounds) = capture.requests().unwrap();
        assert!(requests.contains_key("events"));
        let bounds = bounds.unwrap();
        assert_eq!(bounds.lower(), &ScalarValue::UInt64(Some(1000)));
        assert_eq!(bounds.upper(), &ScalarValue::UInt64(Some(2999)));
        let selected = capture.prune_selection(selection).unwrap();
        assert_eq!(selected.received_from, Bound::Included(1000));
        assert_eq!(selected.received_until, Bound::Included(2999));
    }
}

#[tokio::test]
async fn native_bounds_keep_scope() {
    let fixture = Fixture::new();
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.received_from = Bound::Excluded(1500);
    selection.received_until = Bound::Excluded(2500);
    let capture = fixture.capture(selection.clone());
    let sql = "SELECT count(*) FROM events WHERE received_utc_ns >= $1 AND received_utc_ns < $2";
    let parameters = vec![
        ScalarValue::UInt64(Some(1000)),
        ScalarValue::UInt64(Some(3000)),
    ];
    fixture.plan(&capture, sql, parameters.clone()).await;
    let selected = capture.prune_selection(selection).unwrap();
    assert_eq!(selected.received_from, Bound::Excluded(1500));
    assert_eq!(selected.received_until, Bound::Excluded(2500));
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let capture = fixture.capture(selection.clone());
    fixture.plan(&capture, sql, parameters).await;
    fixture
        .plan(&capture, "SELECT count(*) FROM events", vec![])
        .await;
    let selected = capture.prune_selection(selection).unwrap();
    assert_eq!(selected.received_from, Bound::Unbounded);
    assert_eq!(selected.received_until, Bound::Unbounded);
}

#[tokio::test]
async fn local_source_has_no_bounds() {
    let fixture = Fixture::new();
    let options = &fixture.state.config_options().catalog;
    let schema = fixture
        .state
        .catalog_list()
        .catalog(&options.default_catalog)
        .unwrap()
        .schema(&options.default_schema)
        .unwrap();
    let table =
        MemTable::try_new(SourceSnapshot::providers()["events"].schema(), vec![vec![]]).unwrap();
    assert!(schema.deregister_table("events").unwrap().is_some());
    schema
        .register_table("events".into(), Arc::new(table))
        .unwrap();
    let capture = fixture.capture(AnalysisSelectionV1::tenant([1; 16]));
    fixture
        .plan(
            &capture,
            "SELECT count(*) FROM events WHERE received_utc_ns >= $1",
            vec![ScalarValue::UInt64(Some(1000))],
        )
        .await;
    let (requests, bounds) = capture.requests().unwrap();
    assert!(requests.is_empty());
    assert!(bounds.is_none());
}
