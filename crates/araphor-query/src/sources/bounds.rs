use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use araphor_data::{AnalysisSelectionV1, AnalysisStore, AnalysisTableRequests};
use datafusion::common::ScalarValue;
use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;
use datafusion::physical_plan::union::UnionExec;
use datafusion::physical_plan::ExecutionPlan;

use super::{ScanBounds, SourceSnapshot};
use crate::execution::{Engine, Limits};
use crate::parser::Parser;
use crate::planner::Planner;

struct Fixture {
    _engine: Arc<Engine>,
    state: SessionState,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(store, Limits::default()).unwrap();
        let state = engine.catalog(SourceSnapshot::providers()).unwrap();
        Self {
            _engine: engine,
            state,
            _directory: directory,
        }
    }

    fn requests(plans: &[Arc<dyn ExecutionPlan>]) -> (AnalysisTableRequests, ScanBounds) {
        let mut requests = BTreeMap::from([("events".to_owned(), None)]);
        let bounds = SourceSnapshot::requests(&mut requests, plans, None).unwrap();
        (requests, bounds)
    }

    async fn plan(&self, sql: &str, parameters: Vec<ScalarValue>) -> Arc<dyn ExecutionPlan> {
        assert!(self
            .state
            .config()
            .get_extension::<SourceSnapshot>()
            .is_none());
        let plan = Planner::new(&self.state)
            .build(Parser::default().parse(sql).unwrap(), parameters)
            .await
            .unwrap();
        self.state.create_physical_plan(&plan).await.unwrap()
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
        let physical = fixture
            .plan(
                &format!("SELECT count(*) FROM events e WHERE e.{field} >= $1 AND e.{field} < $2"),
                vec![first, last],
            )
            .await;
        let (requests, bounds) = Fixture::requests(std::slice::from_ref(&physical));
        assert!(requests.contains_key("events"));
        let interval = &bounds.fields["received_utc_ns"];
        assert_eq!(interval.lower(), &ScalarValue::UInt64(Some(1000)));
        assert_eq!(interval.upper(), &ScalarValue::UInt64(Some(2999)));
        let selected = SourceSnapshot::prune_selection(selection, &bounds);
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
    let sql = "SELECT count(*) FROM events WHERE received_utc_ns >= $1 AND received_utc_ns < $2";
    let parameters = vec![
        ScalarValue::UInt64(Some(1000)),
        ScalarValue::UInt64(Some(3000)),
    ];
    let bounded = fixture.plan(sql, parameters).await;
    let (_, bounds) = Fixture::requests(std::slice::from_ref(&bounded));
    let selected = SourceSnapshot::prune_selection(selection, &bounds);
    assert_eq!(selected.received_from, Bound::Excluded(1500));
    assert_eq!(selected.received_until, Bound::Excluded(2500));
    let unbounded = fixture.plan("SELECT count(*) FROM events", vec![]).await;
    assert_eq!(Fixture::requests(std::slice::from_ref(&bounded)).1, bounds);
    let (_, shared) = Fixture::requests(&[Arc::clone(&bounded), Arc::clone(&unbounded)]);
    assert_eq!(
        SourceSnapshot::prune_selection(AnalysisSelectionV1::tenant([1; 16]), &shared).time_range(),
        Some((0, u64::MAX))
    );
    let physical: Arc<dyn ExecutionPlan> = UnionExec::try_new(vec![bounded, unbounded]).unwrap();
    let (_, bounds) = Fixture::requests(std::slice::from_ref(&physical));
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let selected = SourceSnapshot::prune_selection(selection, &bounds);
    assert_eq!(selected.received_from, Bound::Unbounded);
    assert_eq!(selected.received_until, Bound::Unbounded);
}

#[tokio::test]
async fn cursor_bounds_keep_scope() {
    let fixture = Fixture::new();
    let filtered = fixture
        .plan(
            "SELECT framed_record FROM events WHERE source_cursor >= $1 AND source_cursor < $2",
            vec![ScalarValue::UInt64(Some(3)), ScalarValue::UInt64(Some(7))],
        )
        .await;
    let (_, bounds) = Fixture::requests(std::slice::from_ref(&filtered));
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.cursor_from = Bound::Excluded(3);
    selection.cursor_until = Bound::Excluded(6);
    let selected = SourceSnapshot::prune_selection(selection.clone(), &bounds);
    assert_eq!(selected.cursor_range(), Some((4, 5)));
    assert_eq!(selected.cursor_from, selection.cursor_from);
    assert_eq!(selected.cursor_until, selection.cursor_until);
    assert_eq!(selected.time_range(), selection.time_range());

    let unfiltered = fixture
        .plan("SELECT framed_record FROM events", vec![])
        .await;
    let (_, bounds) = Fixture::requests(&[filtered, unfiltered]);
    let selected = SourceSnapshot::prune_selection(AnalysisSelectionV1::tenant([1; 16]), &bounds);
    assert_eq!(selected.cursor_range(), Some((0, u64::MAX)));
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
    let table = MemTable::try_new(
        Arc::clone(&SourceSnapshot::schemas()["events"]),
        vec![vec![]],
    )
    .unwrap();
    assert!(schema.deregister_table("events").unwrap().is_some());
    schema
        .register_table("events".into(), Arc::new(table))
        .unwrap();
    let physical = fixture
        .plan(
            "SELECT count(*) FROM events WHERE received_utc_ns >= $1",
            vec![ScalarValue::UInt64(Some(1000))],
        )
        .await;
    let mut requests = AnalysisTableRequests::new();
    let bounds =
        SourceSnapshot::requests(&mut requests, std::slice::from_ref(&physical), None).unwrap();
    assert!(requests.is_empty());
    assert!(bounds.fields.is_empty());
}

#[tokio::test]
async fn physical_projection_requests() {
    let fixture = Fixture::new();
    let first = fixture.plan("SELECT operation FROM events", vec![]).await;
    let second = fixture
        .plan("SELECT source_cursor FROM events", vec![])
        .await;
    let canonical = &SourceSnapshot::schemas()["events"];
    let operation = canonical.index_of("operation").unwrap();
    let cursor = canonical.index_of("source_cursor").unwrap();
    assert_eq!(
        Fixture::requests(std::slice::from_ref(&first)).0["events"],
        Some(BTreeSet::from([operation]))
    );
    assert_eq!(
        Fixture::requests(std::slice::from_ref(&second)).0["events"],
        Some(BTreeSet::from([cursor]))
    );
    assert_eq!(
        Fixture::requests(&[first, second]).0["events"],
        Some(BTreeSet::from([operation, cursor]))
    );
    let physical = fixture.plan(
        "SELECT CAST(operation AS BIGINT UNSIGNED) AS value FROM events UNION ALL SELECT source_cursor AS value FROM events",
        vec![],
    ).await;
    assert_eq!(
        Fixture::requests(std::slice::from_ref(&physical)).0["events"],
        Some(BTreeSet::from([operation, cursor]))
    );
}
