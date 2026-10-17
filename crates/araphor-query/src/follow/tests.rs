use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    AnalysisStore, ContextSensitivityV1, EvidenceIntakeIdentityV1, EvidenceRecord,
    GraphSubjectKeyV1, GraphSubjectKindV1, GraphTraversalV1, NotificationKeyV1,
    NotificationObligationV1, NotificationPriorityV1, NotificationSinkHealthV1, Selection,
    TraceIdentityV1, UnconfirmedNotificationConcernV1, ValidatedEvidenceBatchV1,
    NOTIFICATION_STATE_OWNER,
};
use datafusion::arrow::array::{RecordBatch, StringViewArray};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, ScalarValue};
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder};
use futures_util::StreamExt as _;
use prost::Message as _;
use tokio::sync::watch;

use super::{Clock, Cursor, Fingerprint, Operation, Subscription, Update, Window};
use crate::execution::{Engine, Limits};
use crate::parser::Parser;

mod trace;

struct TestClock {
    now: AtomicU64,
    reads: AtomicU64,
    changes: watch::Sender<u64>,
}

impl TestClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            reads: AtomicU64::new(0),
            changes: watch::channel(0).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_replace(now);
    }
}

impl Clock for TestClock {
    fn now_ns(&self) -> crate::Result<u64> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.now.load(Ordering::SeqCst))
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Fixture {
    engine: Arc<Engine>,
    store: Arc<AnalysisStore>,
    source: EvidenceIntakeIdentityV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(mut limits: Limits) -> Self {
        limits.extract_timeout = Duration::from_secs(5);
        limits.evaluate_timeout = Duration::from_secs(5);
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(Arc::clone(&store), limits).unwrap();
        Self {
            engine,
            store,
            _directory: directory,
            source: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "follow-test".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        }
    }

    fn commit(&self, source: &EvidenceIntakeIdentityV1, first: u64, count: usize, received: u64) {
        let mut frames = Vec::new();
        let mut ends = Vec::new();
        for _ in 0..count {
            let payload = EvidenceRecord {
                operation: 7,
                ..Default::default()
            }
            .encode_to_vec();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&payload);
            frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
            frames.extend_from_slice(&frame);
            ends.push(frames.len());
        }
        self.store
            .accept_validated_batch(
                source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: first,
                    last_cursor: first + count as u64 - 1,
                    intake_utc_ns: received,
                    frame_ends: ends,
                    framed_records: frames.into(),
                },
            )
            .unwrap();
    }

    fn selection(&self) -> AnalysisSelectionV1 {
        AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()])
    }

    fn notification(&self, deadline: u64) {
        self.store.enable_notification_owner().unwrap();
        let value = NotificationObligationV1 {
            schema_version: 1,
            key: NotificationKeyV1 {
                tenant_id: self.source.tenant_id,
                notification_id: [7; 16],
            },
            revision: 1,
            finding: None,
            unconfirmed_concern: Some(UnconfirmedNotificationConcernV1 {
                concern_id: [9; 16],
                model_label: "follow".into(),
                summary: "Review this concern".into(),
                context: Vec::new(),
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Info,
            }),
            finding_revision: 1,
            package_id: "follow".into(),
            required_action: None,
            sensitivity: ContextSensitivityV1::Tenant,
            source_priority: NotificationPriorityV1::Info,
            minimum_priority: NotificationPriorityV1::Info,
            route: None,
            escalation: None,
            first_seen_utc_ns: 1,
            deadline_utc_ns: Some(deadline),
            overdue_since_utc_ns: None,
            attempt_sequence: 0,
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
            agent_receipt: None,
            advisory: None,
        };
        value.validate().unwrap();
        self.store
            .commit_context(&AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: value.key.tenant_id,
                    owner_id: NOTIFICATION_STATE_OWNER.into(),
                    entity_key: value.key.notification_id.to_vec(),
                    lifetime_key: b"obligation".to_vec(),
                    owner_revision: value.revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: value.sensitivity,
                body: serde_json::to_vec(&value).unwrap(),
            })
            .unwrap();
    }

    fn plan(
        &self,
        sql: &str,
        parameters: Vec<ScalarValue>,
    ) -> (Arc<LogicalPlan>, BTreeSet<String>) {
        let state = self.engine.catalog(BTreeMap::new()).unwrap();
        let statement = Parser::parse(sql).unwrap();
        let sources = state
            .resolve_table_references(&statement)
            .unwrap()
            .into_iter()
            .map(|reference| reference.table().to_owned())
            .collect();
        (
            Arc::new(self.engine.plan(&state, statement, parameters).unwrap()),
            sources,
        )
    }

    fn subscribe(
        &self,
        sql: &str,
        clock: Arc<dyn Clock>,
        resume: Option<Cursor>,
        follow: bool,
    ) -> Subscription {
        let (plan, sources) = self.plan(sql, vec![]);
        Subscription::new(
            Arc::clone(&self.engine),
            plan,
            sources,
            self.selection(),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"authorized principal",
            resume,
            clock,
            follow,
        )
        .unwrap()
    }
}

fn values(update: &Update, column: usize) -> Vec<ScalarValue> {
    update
        .batches
        .as_ref()
        .unwrap()
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows())
                .map(move |row| ScalarValue::try_from_array(batch.column(column), row).unwrap())
        })
        .collect()
}

async fn next(subscription: &mut Subscription) -> Update {
    tokio::time::timeout(Duration::from_secs(8), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[test]
fn lazy_native_shape() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(2_000_000_000);
    let held = fixture
        .engine
        .reserve_evaluation(fixture.source.tenant_id)
        .unwrap();
    for (sql, expected) in [
        ("SELECT source_cursor FROM events", Operation::Append),
        (
            "SELECT e.source_cursor FROM events e WHERE e.operation = 7",
            Operation::Append,
        ),
        ("SELECT DISTINCT operation FROM events", Operation::Replace),
        (
            "SELECT operation FROM events GROUP BY operation",
            Operation::Replace,
        ),
        (
            "SELECT source_cursor FROM events ORDER BY source_cursor",
            Operation::Replace,
        ),
        (
            "SELECT source_cursor FROM events LIMIT 1",
            Operation::Replace,
        ),
        ("SELECT count(*) FROM events", Operation::Replace),
        ("SELECT sequence FROM trace_output", Operation::Append),
        ("SELECT sequence FROM trace_measurements", Operation::Replace),
        (
            "SELECT a.source_cursor FROM events a JOIN events b ON a.source_cursor = b.source_cursor",
            Operation::Replace,
        ),
        (
            "SELECT source_cursor FROM events UNION ALL SELECT source_cursor FROM events",
            Operation::Replace,
        ),
    ] {
        let (plan, sources) = fixture.plan(sql, vec![]);
        assert_eq!(
            crate::planner::subscription::Subscribe::appendable(&plan).unwrap(),
            expected == Operation::Append
        );
        let subscription = Subscription::new(
            Arc::clone(&fixture.engine),
            plan,
            sources,
            fixture.selection(),
            Arc::new(AnalysisReadControl::default()),
            b"authority",
            None,
            clock.clone(),
            true,
        )
        .unwrap();
        assert_eq!(clock.reads.load(Ordering::SeqCst), 0);
        drop(subscription);
    }
    drop(held);
}

#[test]
fn native_graph_admission() {
    let fixture = Fixture::new(Limits::default());
    let mut selection = fixture.selection();
    selection
        .select_graphs(
            Selection::Exact(vec!["graph-result".into()]),
            Some(GraphTraversalV1 {
                seeds: vec![GraphSubjectKeyV1::native(
                    &fixture.source,
                    GraphSubjectKindV1::Task,
                    1u64.to_be_bytes().to_vec(),
                )],
                result_ids: vec!["graph-result".into()],
                ..Default::default()
            }),
        )
        .unwrap();
    assert!(selection.valid());
    let sql = "SELECT subject_id FROM graph_subjects";
    let create = |sql: &str, follow, resume| {
        let (plan, sources) = fixture.plan(sql, vec![]);
        Subscription::new(
            Arc::clone(&fixture.engine),
            plan,
            sources,
            selection.clone(),
            Arc::new(AnalysisReadControl::default()),
            b"graph-authority",
            resume,
            TestClock::new(0),
            follow,
        )
    };
    drop(create(sql, false, None).unwrap());
    for (sql, follow) in [
        ("SELECT source_cursor FROM events", false),
        (
            "WITH unused AS (SELECT * FROM events) SELECT subject_id FROM graph_subjects",
            false,
        ),
        (sql, true),
    ] {
        assert!(matches!(
            create(sql, follow, None),
            Err(crate::Error::Sql {
                source: DataFusionError::NotImplemented(_),
            })
        ));
    }
    let (plan, sources) = fixture.plan(sql, vec![]);
    let binding = Fingerprint::binding(
        &plan,
        &sources,
        &selection,
        Operation::Replace,
        b"graph-authority",
    )
    .unwrap();
    let cursor = Cursor::new(
        &fixture.store.meta().unwrap(),
        Operation::Replace,
        binding,
        araphor_data::StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        0,
    );
    assert!(matches!(
        create(sql, true, Some(cursor.clone())),
        Err(crate::Error::Sql {
            source: DataFusionError::NotImplemented(_),
        })
    ));
    assert!(matches!(
        create(sql, false, Some(cursor)),
        Err(crate::Error::Invalid {
            field: "cursor request",
            ..
        })
    ));
}

#[test]
fn local_cursor_denied() {
    let fixture = Fixture::new(Limits::default());
    let schema = crate::sources::SourceSnapshot::schemas()
        .get("events")
        .cloned()
        .unwrap();
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("events".into(), schema)]))
        .unwrap();
    let statement = Parser::parse("SELECT source_cursor FROM events").unwrap();
    let plan = fixture.engine.plan(&state, statement, vec![]).unwrap();
    assert!(!crate::planner::subscription::Subscribe::appendable(&plan).unwrap());
    let statement = Parser::parse(
        "SELECT operation FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 second'",
    )
    .unwrap();
    let plan = fixture.engine.plan(&state, statement, vec![]).unwrap();
    assert!(Window::from_plan(&plan).is_err());
    let subscription = Subscription::new(
        Arc::clone(&fixture.engine),
        Arc::new(plan),
        BTreeSet::new(),
        fixture.selection(),
        Arc::new(AnalysisReadControl::default()),
        b"authority",
        None,
        TestClock::new(0),
        false,
    )
    .unwrap();
    assert_eq!(subscription.moving_resolution_ns(), None);
}

#[tokio::test]
async fn subqueries_use_replace() {
    let sql =
        "SELECT source_cursor FROM events WHERE source_cursor <= (SELECT count(*) FROM events)";
    for retained in [false, true] {
        let fixture = Fixture::new(Limits::default());
        fixture.commit(&fixture.source, 2, 1, 1_000_000_000);
        let (plan, sources) = fixture.engine.prepare(sql, vec![]).await.unwrap();
        let plan = Arc::new(plan);
        let clock = TestClock::new(2_000_000_000);
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
        let mut subscription = if retained {
            let state = fixture.engine.catalog(BTreeMap::new()).unwrap();
            let native = Arc::new(
                state
                    .statement_to_plan(Parser::parse(sql).unwrap())
                    .await
                    .unwrap(),
            );
            Subscription::new(
                Arc::clone(&fixture.engine),
                native,
                sources.clone(),
                fixture.selection(),
                control,
                b"subquery principal",
                None,
                clock.clone(),
                true,
            )
            .unwrap()
        } else {
            fixture
                .engine
                .subscribe(
                    sql,
                    vec![],
                    fixture.selection(),
                    control,
                    b"subquery principal",
                    None,
                    clock.clone(),
                    true,
                )
                .await
                .unwrap()
        };
        let first = next(&mut subscription).await;
        assert_eq!(first.operation, Operation::Replace);
        assert!(values(&first, 0).is_empty());
        assert_eq!(first.snapshot.witnesses.len(), 1);
        drop(first);
        fixture.commit(&fixture.source, 1, 1, 1_500_000_000);
        let second = next(&mut subscription).await;
        assert_eq!(second.operation, Operation::Replace);
        assert_eq!(second.snapshot.witnesses.len(), 2);
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap();
        let (snapshot, batches) = fixture
            .engine
            .session(fixture.selection(), &control, second.evaluated_utc_ns)
            .unwrap()
            .execute(Arc::clone(&plan), &sources)
            .unwrap();
        assert_eq!(
            snapshot.page.extraction.meta,
            second.snapshot.page.extraction.meta
        );
        for batch in &batches {
            assert_eq!(batch.schema(), subscription.schema());
        }
        let mut expected = batches
            .iter()
            .flat_map(|batch| {
                (0..batch.num_rows())
                    .map(move |row| ScalarValue::try_from_array(batch.column(0), row).unwrap())
            })
            .collect::<Vec<_>>();
        let mut actual = values(&second, 0);
        expected.sort_by(|first, second| first.partial_cmp(second).unwrap());
        actual.sort_by(|first, second| first.partial_cmp(second).unwrap());
        assert_eq!(actual, expected);
        assert_eq!(
            actual,
            vec![ScalarValue::UInt64(Some(1)), ScalarValue::UInt64(Some(2))]
        );
        subscription.cancel().unwrap();
    }
}

#[tokio::test]
async fn subqueries_keep_policy() {
    let fixture = Fixture::new(Limits::default());
    for (sql, expected) in [
        (
            "SELECT (SELECT count(*) FROM events) AS total FROM events",
            BTreeSet::from(["events".to_owned()]),
        ),
        (
            "SELECT e.source_cursor FROM events e WHERE EXISTS (SELECT 1 FROM coverage c WHERE c.first_cursor < e.source_cursor)",
            BTreeSet::from(["coverage".to_owned(), "events".to_owned()]),
        ),
        (
            "SELECT source_cursor FROM events WHERE source_cursor IN (SELECT first_cursor FROM coverage)",
            BTreeSet::from(["coverage".to_owned(), "events".to_owned()]),
        ),
        (
            "SELECT source_cursor FROM events WHERE source_cursor <= (SELECT 2)",
            BTreeSet::from(["events".to_owned()]),
        ),
    ] {
        let (plan, sources) = fixture.engine.prepare(sql, vec![]).await.unwrap();
        assert_eq!(sources, expected);
        let subscription = Subscription::new(
            Arc::clone(&fixture.engine),
            Arc::new(plan),
            sources,
            fixture.selection(),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"subquery principal",
            None,
            TestClock::new(2_000_000_000),
            true,
        )
        .unwrap();
        assert_eq!(subscription.operation, Operation::Replace);
    }
    let (plan, sources) = fixture
        .engine
        .prepare(
            "SELECT source_cursor FROM events WHERE source_cursor IN (SELECT $1)",
            vec![ScalarValue::UInt64(Some(2))],
        )
        .await
        .unwrap();
    assert!(plan.get_parameter_names().unwrap().is_empty());
    assert_eq!(sources, BTreeSet::from(["events".to_owned()]));
    for sql in [
        "SELECT source_cursor FROM events WHERE EXISTS (SELECT 1 FROM missing_source)",
        "SELECT source_cursor FROM events WHERE EXISTS (SELECT random() FROM events)",
        "SELECT source_cursor FROM events WHERE EXISTS (SELECT 1 FROM events e JOIN coverage c ON e.source_cursor = e.source_cursor)",
        "SELECT source_cursor FROM events WHERE source_cursor IN (SELECT lag(source_cursor, 201) OVER (ORDER BY source_cursor) FROM events)",
    ] {
        assert!(fixture.engine.prepare(sql, vec![]).await.is_err(), "{sql}");
    }
    let wide = (0..257)
        .map(|index| format!("1 AS column_{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT source_cursor FROM events WHERE EXISTS (SELECT {wide} FROM events)");
    assert!(fixture.engine.prepare(&sql, vec![]).await.is_err());
}

#[tokio::test]
async fn page_keeps_lookahead() {
    let fixture = Fixture::new(Limits {
        output_rows: 2,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let sql = "SELECT source_cursor AS \"__follow_revision\", source_cursor AS \"__follow_ordinal\" FROM events";
    let mut subscription = fixture.subscribe(sql, clock.clone(), None, true);
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Append);
    assert_eq!(
        first.batches.as_ref().unwrap()[0].schema(),
        subscription.schema()
    );
    assert_eq!(first.batches.as_ref().unwrap()[0].num_columns(), 2);
    assert_eq!(
        values(&first, 0),
        vec![ScalarValue::UInt64(Some(1)), ScalarValue::UInt64(Some(2))]
    );
    assert_eq!(first.positions.len(), 2);
    assert!(first.positions[0] < first.positions[1]);
    assert_eq!(first.cursor.position(), first.positions[1]);
    assert!(!first.exhausted);
    assert!(first.limited);
    let cursor = Cursor::decode(&first.cursor.encode().unwrap()).unwrap();
    drop(first);
    subscription.cancel().unwrap();
    let mut resumed = fixture.subscribe(sql, clock, Some(cursor), true);
    let second = next(&mut resumed).await;
    assert_eq!(values(&second, 0), vec![ScalarValue::UInt64(Some(3))]);
    assert_eq!(
        second.cursor.position(),
        second.snapshot.page.scanned_through
    );
    assert_eq!(
        second.cursor.position(),
        araphor_data::StorePositionV1 {
            commit_revision: second.snapshot.page.extraction.meta.commit_revision,
            ordinal: u32::MAX,
        }
    );
    assert!(second.cursor.position() > second.positions[0]);
    assert_eq!(second.positions[0].ordinal, 2);
    assert!(second.exhausted);
    assert!(!second.limited);
    fixture.commit(&fixture.source, 4, 1, 1_500_000_000);
    let third = next(&mut resumed).await;
    assert_eq!(values(&third, 0), vec![ScalarValue::UInt64(Some(4))]);
    assert_eq!(third.positions[0].ordinal, 0);
    assert!(third.positions[0] > second.cursor.position());
    assert!(third.exhausted);
}

#[tokio::test]
async fn filtered_page_progress() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 257, 1_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT source_cursor FROM events WHERE source_cursor > 256",
        TestClock::new(2_000_000_000),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert!(values(&first, 0).is_empty());
    assert!(first.cursor.position().commit_revision > 0);
    assert_eq!(first.cursor.position().ordinal, 255);
    assert!(!first.exhausted);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), vec![ScalarValue::UInt64(Some(257))]);
    assert_eq!(second.positions[0].ordinal, 256);
    assert_eq!(
        second.cursor.position(),
        second.snapshot.page.scanned_through
    );
    assert_eq!(
        second.cursor.position(),
        araphor_data::StorePositionV1 {
            commit_revision: second.snapshot.page.extraction.meta.commit_revision,
            ordinal: u32::MAX,
        }
    );
    assert!(second.exhausted);
}

#[tokio::test]
async fn append_preserves_expressions() {
    let fixture = Fixture::new(Limits {
        output_rows: 2,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 5, 1_000_000_000);
    let positions = fixture
        .store
        .read_page(&fixture.source, 1)
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.position)
        .collect::<Vec<_>>();
    let sql = "SELECT CAST(e.source_cursor AS BIGINT) + $1 AS \"MiXeD\", CASE WHEN e.source_cursor % 2 = 0 THEN CAST(NULL AS BIGINT) ELSE CAST(e.source_cursor AS BIGINT) END AS nullable, e.kernel_sequence AS \"Missing\" FROM events AS e WHERE e.source_cursor > $2 AND e.source_cursor < $3 AND e.kernel_sequence IS NULL";
    let parameters = vec![
        ScalarValue::Int32(Some(2)),
        ScalarValue::UInt64(Some(1)),
        ScalarValue::UInt64(Some(5)),
    ];
    let (plan, sources) = fixture
        .engine
        .prepare(sql, parameters.clone())
        .await
        .unwrap();
    let schema = Arc::clone(plan.schema().inner());
    assert!(plan.get_parameter_names().unwrap().is_empty());
    assert_eq!(schema.field(0).name(), "MiXeD");
    assert_eq!(schema.field(2).name(), "Missing");
    assert_eq!(
        schema.field(2).metadata(),
        crate::sources::SourceSnapshot::schemas()["events"]
            .field_with_name("kernel_sequence")
            .unwrap()
            .metadata()
    );
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .engine
        .session(fixture.selection(), &control, 2_000_000_000)
        .unwrap();
    session
        .set_output(5, fixture.engine.limits().output_bytes)
        .unwrap();
    let (snapshot, expected) = session.execute(Arc::new(plan), &sources).unwrap();
    let mut subscription = fixture
        .engine
        .subscribe(
            sql,
            parameters,
            fixture.selection(),
            Arc::new(AnalysisReadControl::default()),
            b"expression principal",
            None,
            TestClock::new(2_000_000_000),
            true,
        )
        .await
        .unwrap();
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Append);
    assert_eq!(first.positions.as_slice(), &positions[1..3]);
    assert_eq!(first.cursor.position(), positions[2]);
    assert_eq!(
        values(&first, 0),
        [ScalarValue::Int64(Some(4)), ScalarValue::Int64(Some(5))]
    );
    assert_eq!(
        values(&first, 1),
        [ScalarValue::Int64(None), ScalarValue::Int64(Some(3))]
    );
    assert_eq!(values(&first, 2), vec![ScalarValue::UInt64(None); 2]);
    assert!(first.limited && !first.exhausted);
    assert_eq!(first.snapshot.witnesses.len(), 5);
    let second = next(&mut subscription).await;
    assert_eq!(second.positions, vec![positions[3]]);
    assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(6))]);
    assert_eq!(values(&second, 1), [ScalarValue::Int64(None)]);
    assert_eq!(values(&second, 2), [ScalarValue::UInt64(None)]);
    assert!(second.exhausted && !second.limited);
    assert_eq!(
        second.cursor.position(),
        second.snapshot.page.scanned_through
    );
    assert_eq!(second.cursor.position().ordinal, u32::MAX);
    assert_eq!(
        snapshot.page.extraction.meta,
        second.snapshot.page.extraction.meta
    );
    for column in 0..schema.fields().len() {
        let actual = [values(&first, column), values(&second, column)].concat();
        let expected = expected
            .iter()
            .flat_map(|batch| {
                (0..batch.num_rows())
                    .map(move |row| ScalarValue::try_from_array(batch.column(column), row).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
    for update in [&first, &second] {
        assert!(update
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.schema() == schema));
    }
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn append_positions_ignore_aliases() {
    let sql = "SELECT CAST(91 AS BIGINT UNSIGNED) AS commit_revision, CAST(NULL AS INT UNSIGNED) AS ordinal, CAST(73 AS BIGINT UNSIGNED) AS \"__follow_revision\", CAST(29 AS BIGINT UNSIGNED) AS \"__follow_ordinal\", source_cursor FROM events";
    for count in [2, 3] {
        let fixture = Fixture::new(Limits {
            output_rows: 2,
            ..Default::default()
        });
        fixture.commit(&fixture.source, 1, count, 1_000_000_000);
        let positions = fixture
            .store
            .read_page(&fixture.source, 1)
            .unwrap()
            .records
            .into_iter()
            .map(|record| record.position)
            .collect::<Vec<_>>();
        let (plan, _) = fixture.plan(sql, vec![]);
        let schema = Arc::clone(plan.schema().inner());
        let clock = TestClock::new(2_000_000_000);
        let mut subscription = fixture.subscribe(sql, clock.clone(), None, true);
        let first = next(&mut subscription).await;
        assert_eq!(first.operation, Operation::Append);
        assert_eq!(first.positions.as_slice(), &positions[..2]);
        assert_eq!(values(&first, 0), vec![ScalarValue::UInt64(Some(91)); 2]);
        assert_eq!(values(&first, 1), vec![ScalarValue::UInt32(None); 2]);
        assert_eq!(values(&first, 2), vec![ScalarValue::UInt64(Some(73)); 2]);
        assert_eq!(values(&first, 3), vec![ScalarValue::UInt64(Some(29)); 2]);
        assert_eq!(
            values(&first, 4),
            [ScalarValue::UInt64(Some(1)), ScalarValue::UInt64(Some(2))]
        );
        assert!(first
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.schema() == schema));
        if count == 2 {
            assert!(first.exhausted && !first.limited);
            assert_eq!(first.cursor.position(), first.snapshot.page.scanned_through);
            assert_eq!(first.cursor.position().ordinal, u32::MAX);
            subscription.cancel().unwrap();
            continue;
        }
        assert!(!first.exhausted && first.limited);
        assert_eq!(first.cursor.position(), positions[1]);
        let cursor = Cursor::decode(&first.cursor.encode().unwrap()).unwrap();
        drop(first);
        subscription.cancel().unwrap();
        drop(subscription);
        let mut resumed = fixture.subscribe(sql, clock, Some(cursor), true);
        let second = next(&mut resumed).await;
        assert_eq!(second.positions, vec![positions[2]]);
        assert_eq!(values(&second, 0), [ScalarValue::UInt64(Some(91))]);
        assert_eq!(values(&second, 1), [ScalarValue::UInt32(None)]);
        assert_eq!(values(&second, 2), [ScalarValue::UInt64(Some(73))]);
        assert_eq!(values(&second, 3), [ScalarValue::UInt64(Some(29))]);
        assert_eq!(values(&second, 4), [ScalarValue::UInt64(Some(3))]);
        assert!(second.exhausted && !second.limited);
        assert_eq!(
            second.cursor.position(),
            second.snapshot.page.scanned_through
        );
        assert_eq!(second.cursor.position().ordinal, u32::MAX);
        assert!(second
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.schema() == schema));
        resumed.cancel().unwrap();
    }
}

#[tokio::test]
async fn append_constants_and_empty() {
    let fixture = Fixture::new(Limits {
        output_rows: 2,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let positions = fixture
        .store
        .read_page(&fixture.source, 1)
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.position)
        .collect::<Vec<_>>();
    for (sql, empty) in [
        ("SELECT 7 AS value FROM events", false),
        (
            "SELECT source_cursor AS \"__follow_ordinal\" FROM events WHERE FALSE",
            true,
        ),
    ] {
        let (plan, _) = fixture.plan(sql, vec![]);
        let schema = Arc::clone(plan.schema().inner());
        let state = fixture.engine.catalog(BTreeMap::new()).unwrap();
        let physical = state.create_physical_plan(&plan).await.unwrap();
        let mut widths = Vec::new();
        physical
            .apply(|node| {
                if crate::sources::SourceData::from_plan(node.as_ref()).is_some() {
                    widths.push(node.schema().fields().len());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
        assert_eq!(widths, if empty { vec![] } else { vec![0] });
        let mut subscription = fixture.subscribe(sql, TestClock::new(2_000_000_000), None, true);
        assert_eq!(subscription.schema(), schema);
        let first = next(&mut subscription).await;
        assert_eq!(first.operation, Operation::Append);
        assert_eq!(first.snapshot.page.extraction.sources.len(), 1);
        assert_eq!(
            first.snapshot.page.extraction.sources[0]
                .receipt
                .contiguous_cursor,
            3
        );
        assert_eq!(first.snapshot.witnesses.len(), 3);
        if empty {
            assert!(first.positions.is_empty());
            assert!(values(&first, 0).is_empty());
            assert!(first.exhausted && !first.limited);
            assert_eq!(first.cursor.position(), first.snapshot.page.scanned_through);
            assert_eq!(first.cursor.position().ordinal, u32::MAX);
        } else {
            assert_eq!(first.positions.as_slice(), &positions[..2]);
            assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(7)); 2]);
            assert_eq!(first.cursor.position(), positions[1]);
            assert!(!first.exhausted && first.limited);
            let second = next(&mut subscription).await;
            assert_eq!(second.positions, vec![positions[2]]);
            assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(7))]);
            assert!(second.exhausted && !second.limited);
            assert_eq!(
                second.cursor.position(),
                second.snapshot.page.scanned_through
            );
            assert_eq!(second.cursor.position().ordinal, u32::MAX);
            assert!(second
                .batches
                .as_ref()
                .unwrap()
                .iter()
                .all(|batch| batch.schema() == schema));
        }
        assert!(first
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.schema() == schema));
        subscription.cancel().unwrap();
    }
}

#[tokio::test]
async fn append_zero_columns() {
    let fixture = Fixture::new(Limits {
        output_rows: 2,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let positions = fixture
        .store
        .read_page(&fixture.source, 1)
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.position)
        .collect::<Vec<_>>();
    let (plan, sources) = fixture
        .engine
        .prepare("SELECT source_cursor FROM events", vec![])
        .await
        .unwrap();
    let LogicalPlan::Projection(projection) = plan else {
        panic!("the native projection is absent");
    };
    let plan = LogicalPlanBuilder::from(projection.input.as_ref().clone())
        .project(Vec::<Expr>::new())
        .unwrap()
        .build()
        .unwrap();
    assert!(plan.schema().fields().is_empty());
    let mut subscription = Subscription::new(
        Arc::clone(&fixture.engine),
        Arc::new(plan),
        sources,
        fixture.selection(),
        Arc::new(AnalysisReadControl::default()),
        b"zero-column principal",
        None,
        TestClock::new(2_000_000_000),
        true,
    )
    .unwrap();
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Append);
    assert_eq!(first.positions.as_slice(), &positions[..2]);
    assert!(first.positions[0] < first.positions[1]);
    assert_eq!(first.cursor.position(), positions[1]);
    assert!(!first.exhausted && first.limited);
    let batches = first.batches.as_ref().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].schema(), subscription.schema());
    assert_eq!(batches[0].num_columns(), 0);
    assert_eq!(batches[0].num_rows(), 2);
    let second = next(&mut subscription).await;
    assert_eq!(second.positions, vec![positions[2]]);
    assert!(second.positions[0] > first.cursor.position());
    assert!(second.exhausted && !second.limited);
    assert_eq!(
        second.cursor.position(),
        second.snapshot.page.scanned_through
    );
    assert_eq!(
        second.cursor.position(),
        araphor_data::StorePositionV1 {
            commit_revision: second.snapshot.page.extraction.meta.commit_revision,
            ordinal: u32::MAX,
        }
    );
    let batches = second.batches.as_ref().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].schema(), subscription.schema());
    assert_eq!(batches[0].num_columns(), 0);
    assert_eq!(batches[0].num_rows(), 1);
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn append_view_byte_limit() {
    let fixture = Fixture::new(Limits {
        output_bytes: 1024,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let positions = fixture
        .store
        .read_page(&fixture.source, 1)
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.position)
        .collect::<Vec<_>>();
    let large = "x".repeat(4096);
    let sql = format!(
        "SELECT CAST(CASE WHEN source_cursor = 2 THEN '{large}' ELSE 'tiny' END AS VARCHAR) AS value FROM events"
    );
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(&sql, clock.clone(), None, true);
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Append);
    assert_eq!(first.positions, vec![positions[0]]);
    assert_eq!(first.cursor.position(), positions[0]);
    assert!(first.limited && !first.exhausted);
    let batches = first.batches.as_ref().unwrap();
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(batch.schema(), subscription.schema());
    assert_eq!(batch.num_columns(), 1);
    assert_eq!(batch.num_rows(), 1);
    assert!(batch.get_array_memory_size() <= fixture.engine.limits().output_bytes);
    let view = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringViewArray>()
        .unwrap();
    assert_eq!(view.value(0), "tiny");
    assert!(view.data_buffers().is_empty());
    let borrowed = Arc::clone(batch.column(0));
    let cursor = Cursor::decode(&first.cursor.encode().unwrap()).unwrap();
    drop(first);
    subscription.cancel().unwrap();
    drop(subscription);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_err());
    assert_eq!(
        borrowed
            .as_any()
            .downcast_ref::<StringViewArray>()
            .unwrap()
            .value(0),
        "tiny"
    );
    let mut resumed = fixture.subscribe(&sql, clock.clone(), Some(cursor), true);
    let error = tokio::time::timeout(Duration::from_secs(8), resumed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(crate::Failure::from(&error), crate::Failure::ResultTooLarge);
    assert!(resumed.next().await.is_none());
    resumed.cancel().unwrap();
    drop(resumed);
    drop(borrowed);
    assert!(fixture
        .engine
        .reserve_evaluation(fixture.source.tenant_id)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
    let mut recovered = fixture.subscribe("SELECT source_cursor FROM events", clock, None, true);
    let output = next(&mut recovered).await;
    assert_eq!(output.positions, positions);
    assert_eq!(
        values(&output, 0),
        [
            ScalarValue::UInt64(Some(1)),
            ScalarValue::UInt64(Some(2)),
            ScalarValue::UInt64(Some(3)),
        ]
    );
    assert!(output.exhausted && !output.limited);
    assert_eq!(
        output.cursor.position(),
        output.snapshot.page.scanned_through
    );
    drop(output);
    recovered.cancel().unwrap();
    drop(recovered);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[tokio::test]
async fn native_append_execution() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let control = Arc::new(AnalysisReadControl::default());
    let (plan, sources) = fixture
        .engine
        .prepare(
            "SELECT source_cursor + source_cursor AS \"Value\", CAST(NULL AS BIGINT) AS nullable FROM events WHERE source_cursor > 1",
            vec![],
        )
        .await
        .unwrap();
    let schema = Arc::clone(plan.schema().inner());
    let mut state = fixture.engine.catalog(BTreeMap::new()).unwrap();
    state
        .config_mut()
        .set_extension(Arc::new(crate::stream::Run {
            engine: Arc::clone(&fixture.engine),
            selection: fixture.selection(),
            sources,
            control: Arc::clone(&control),
            now: 2_000_000_000,
            after: None,
        }));
    state.config_mut().set_extension(Arc::new(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    ));
    let logical = crate::planner::subscription::Subscribe::page(plan).unwrap();
    let physical = state.create_physical_plan(&logical).await.unwrap();
    assert!(physical
        .as_any()
        .is::<crate::stream::physical::SubscribeExec>());
    assert_eq!(physical.schema(), schema);
    let context = state.task_ctx();
    drop(state);
    let mut stream = datafusion::physical_plan::execute_stream(physical, context).unwrap();
    let batch = stream.next().await.unwrap().unwrap();
    assert_eq!(batch.schema(), schema);
    assert_eq!(batch.num_columns(), 2);
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(
        (0..2)
            .map(|row| ScalarValue::try_from_array(batch.column(0), row).unwrap())
            .collect::<Vec<_>>(),
        [ScalarValue::UInt64(Some(4)), ScalarValue::UInt64(Some(6))]
    );
    assert_eq!(
        (0..2)
            .map(|row| ScalarValue::try_from_array(batch.column(1), row).unwrap())
            .collect::<Vec<_>>(),
        vec![ScalarValue::Int64(None); 2]
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
    let borrowed = Arc::clone(batch.column(0));
    drop(batch);
    assert!(stream.next().await.is_none());
    drop(stream);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_err());
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0).unwrap(),
        ScalarValue::UInt64(Some(4))
    );
    drop(borrowed);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[tokio::test]
async fn evaluation_wait_and_cancel() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let held = fixture
        .engine
        .reserve_evaluation(fixture.source.tenant_id)
        .unwrap();
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT source_cursor FROM events",
        clock.clone(),
        None,
        true,
    );
    {
        let pending = subscription.next();
        futures_util::pin_mut!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        assert_eq!(clock.reads.load(Ordering::SeqCst), 0);
        drop(held);
        let update = tokio::time::timeout(Duration::from_secs(8), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(values(&update, 0), vec![ScalarValue::UInt64(Some(1))]);
        let available = fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap();
        drop(available);
    }
    subscription.cancel().unwrap();
    assert!(subscription.next().await.is_none());
    assert!(fixture
        .engine
        .reserve_evaluation(fixture.source.tenant_id)
        .is_ok());
}

#[tokio::test]
async fn health_keeps_cursor() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(1))]);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&other, 1, 1, 1_500_000_000);
    clock.set(3_000_000_000);
    let health = next(&mut subscription).await;
    assert!(health.batches.is_none());
    assert!(health.clock_changed);
    assert_eq!(health.cursor, first.cursor);
    assert_eq!(health.evaluated_utc_ns, first.evaluated_utc_ns);
    assert!(health.snapshot.page.extraction.meta.commit_revision > first.cursor.read_revision());
    fixture.commit(&fixture.source, 2, 1, 2_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), vec![ScalarValue::Int64(Some(2))]);
    assert!(second.cursor.read_revision() > health.cursor.read_revision());
}

#[tokio::test]
async fn native_subscribe_execution() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let control = Arc::new(AnalysisReadControl::default());
    let (plan, sources) = fixture
        .engine
        .prepare("SELECT count(*) AS total FROM events", vec![])
        .await
        .unwrap();
    let mut state = fixture.engine.catalog(Default::default()).unwrap();
    let defaults = datafusion::physical_optimizer::optimizer::PhysicalOptimizer::new();
    let native = defaults
        .rules
        .iter()
        .map(|rule| rule.name())
        .collect::<Vec<_>>();
    let actual = state
        .physical_optimizers()
        .iter()
        .map(|rule| rule.name())
        .collect::<Vec<_>>();
    assert_eq!(actual.len(), native.len() + 1);
    assert_eq!(
        &actual[actual.len() - 2..],
        &["PageLineage", "SanityCheckPlan"]
    );
    assert_eq!(
        actual.iter().filter(|name| **name == "PageLineage").count(),
        1
    );
    assert_eq!(
        actual
            .into_iter()
            .filter(|name| *name != "PageLineage")
            .collect::<Vec<_>>(),
        native
    );
    state
        .config_mut()
        .set_extension(Arc::new(crate::stream::Run {
            engine: Arc::clone(&fixture.engine),
            selection: fixture.selection(),
            sources,
            control: Arc::clone(&control),
            now: 2_000_000_000,
            after: None,
        }));
    assert!(state
        .physical_optimizers()
        .iter()
        .any(|rule| rule.name() == "SanityCheckPlan"));
    assert!(state
        .physical_optimizers()
        .iter()
        .any(|rule| rule.name() == "EnsureCooperative"));
    let logical = crate::planner::subscription::Subscribe::plan(plan).unwrap();
    let physical = state.create_physical_plan(&logical).await.unwrap();
    assert!(physical
        .as_any()
        .is::<crate::stream::physical::SubscribeExec>());
    {
        use datafusion::physical_plan::execution_plan::{
            Boundedness, EmissionType, SchedulingType,
        };

        let children = physical.children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].properties().boundedness, Boundedness::Bounded);
        let mut scans = 0;
        let mut scan_schema = None;
        children[0]
            .apply(|node| {
                if crate::sources::SourceData::from_plan(node.as_ref()).is_some() {
                    scans += 1;
                    scan_schema = Some(node.schema());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
        assert_eq!(scans, 1);
        assert!(children[1].as_any().is::<crate::sources::JournalExec>());
        assert_eq!(children[1].schema(), scan_schema.unwrap());
        assert_eq!(
            children[1].properties().boundedness,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            }
        );
        assert_eq!(
            children[1].properties().emission_type,
            EmissionType::Incremental
        );
        assert_eq!(
            children[1].properties().scheduling_type,
            SchedulingType::Cooperative
        );
        match children[1].execute(0, state.task_ctx()) {
            Err(DataFusionError::NotImplemented(_)) => {}
            Err(error) => panic!("journal returned {error:?}"),
            Ok(_) => panic!("signed changes became unsigned rows"),
        }
        let journal = Arc::clone(children[1]);
        let context = state.task_ctx();
        tokio::spawn(async move {
            use crate::stream::Message;

            let mut input = journal
                .as_any()
                .downcast_ref::<crate::sources::JournalExec>()
                .unwrap()
                .execute_committed(0, context)
                .unwrap();
            assert!(matches!(input.next().await, Some(Ok(Message::Begin(_)))));
            for _ in 0..128 {
                if !tokio::task::coop::has_budget_remaining() {
                    break;
                }
                tokio::task::consume_budget().await;
            }
            assert!(!tokio::task::coop::has_budget_remaining());
            let mut pending = Box::pin(input.next());
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            assert!(matches!(pending.await, Some(Ok(Message::Insert(_)))));
        })
        .await
        .unwrap();
    }
    let mut stream = datafusion::physical_plan::execute_stream(physical, state.task_ctx()).unwrap();
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(
        ScalarValue::try_from_array(first.column(0), 0).unwrap(),
        ScalarValue::Int64(Some(1))
    );
    let capacity = fixture.engine.limits().output_capacity;
    let buffers = first.column(0).get_buffer_memory_size();
    let held = capacity
        - fixture
            .engine
            .memory()
            .prepare_output(capacity)
            .unwrap()
            .size();
    assert!(held >= buffers + std::mem::size_of::<RecordBatch>());
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
    let borrowed = Arc::clone(first.column(0));
    drop(first);
    let second = {
        let waiting = stream.next();
        futures_util::pin_mut!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let retained = capacity
            - fixture
                .engine
                .memory()
                .prepare_output(capacity)
                .unwrap()
                .size();
        assert_eq!(retained, buffers);
        assert_eq!(
            ScalarValue::try_from_array(&borrowed, 0).unwrap(),
            ScalarValue::Int64(Some(1))
        );
        drop(
            fixture
                .engine
                .reserve_evaluation(fixture.source.tenant_id)
                .unwrap(),
        );
        fixture.commit(&fixture.source, 2, 1, 1_500_000_000);
        tokio::time::timeout(Duration::from_secs(8), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        ScalarValue::try_from_array(second.column(0), 0).unwrap(),
        ScalarValue::Int64(Some(2))
    );
    drop(second);
    control.cancel().unwrap();
    let error = crate::Error::Sql {
        source: stream.next().await.unwrap().unwrap_err(),
    };
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_err());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_err());
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0).unwrap(),
        ScalarValue::Int64(Some(1))
    );
    drop(borrowed);
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(fixture.engine.limits().output_capacity)
            .unwrap(),
    );
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn count_consumes_committed_changes() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 128, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total, count(source_cursor) FILTER (WHERE operation = 7) AS selected, count(*) + 1 AS adjusted FROM events",
        clock, None, true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(128))]);
    assert_eq!(values(&first, 1), vec![ScalarValue::Int64(Some(128))]);
    assert_eq!(values(&first, 2), vec![ScalarValue::Int64(Some(129))]);
    let scanned = first.snapshot.page.extraction.scanned_bytes;
    fixture.commit(&fixture.source, 129, 1, 1_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), vec![ScalarValue::Int64(Some(129))]);
    assert_eq!(values(&second, 1), vec![ScalarValue::Int64(Some(129))]);
    assert_eq!(values(&second, 2), vec![ScalarValue::Int64(Some(130))]);
    assert_eq!(second.snapshot.witnesses.len(), 129);
    assert!(second.snapshot.page.extraction.scanned_bytes < scanned / 2);
    let cursor = second.cursor.clone();
    drop(first);
    drop(second);
    let pressure = fixture
        .engine
        .memory()
        .reserve_input(
            fixture.engine.limits().input_capacity - fixture.engine.limits().input_bytes / 2,
        )
        .unwrap();
    araphor_data::EvidenceRetentionOwner::new(fixture.store.as_ref())
        .retain(&fixture.source, u64::MAX)
        .unwrap();
    let removed = next(&mut subscription).await;
    assert_eq!(values(&removed, 0), vec![ScalarValue::Int64(Some(0))]);
    assert_eq!(values(&removed, 1), vec![ScalarValue::Int64(Some(0))]);
    assert_eq!(values(&removed, 2), vec![ScalarValue::Int64(Some(1))]);
    assert_eq!(removed.snapshot.page.extraction.scanned_bytes, 0);
    assert!(removed.snapshot.witnesses.is_empty());
    assert!(removed.cursor.read_revision() > cursor.read_revision());
    drop(removed);
    drop(pressure);
    subscription.cancel().unwrap();
    drop(subscription);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[tokio::test]
async fn journal_keeps_residual_filter() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events WHERE source_cursor > 1",
        clock,
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(2))]);
    assert_eq!(first.snapshot.witnesses.len(), 3);
    fixture.commit(&fixture.source, 4, 1, 1_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), vec![ScalarValue::Int64(Some(3))]);
    assert_eq!(second.snapshot.witnesses.len(), 4);
    assert!(second.cursor.read_revision() > first.cursor.read_revision());
    drop(first);
    drop(second);
    araphor_data::EvidenceRetentionOwner::new(fixture.store.as_ref())
        .retain(&fixture.source, u64::MAX)
        .unwrap();
    let removed = next(&mut subscription).await;
    assert_eq!(values(&removed, 0), vec![ScalarValue::Int64(Some(0))]);
    assert_eq!(removed.snapshot.page.extraction.scanned_bytes, 0);
    assert!(removed.snapshot.witnesses.is_empty());
}

#[tokio::test]
async fn empty_scan_keeps_receipts() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 3, 1_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events WHERE false",
        TestClock::new(2_000_000_000),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(0))]);
    assert_eq!(first.snapshot.witnesses.len(), 3);
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(
        first.cursor.read_revision(),
        first.snapshot.page.extraction.meta.commit_revision
    );
    assert_eq!(first.snapshot.page.scanned_through.ordinal, u32::MAX);
}

#[tokio::test]
async fn moving_window_nanoseconds() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_123);
    let clock = TestClock::new(2_000_000_000);
    let sql = "SELECT count(*) AS total FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 second'";
    let mut subscription = fixture.subscribe(sql, clock.clone(), None, true);
    assert_eq!(subscription.moving_resolution_ns(), Some(500_000_000));
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(1))]);
    assert_eq!(
        first.snapshot.selection.received_from,
        Bound::Included(1_000_000_000)
    );
    clock.set(2_000_000_001);
    let expired = next(&mut subscription).await;
    assert!(expired.clock_changed);
    assert_eq!(values(&expired, 0), vec![ScalarValue::Int64(Some(0))]);
    assert_eq!(
        expired.snapshot.selection.received_from,
        Bound::Included(1_000_001_000)
    );
    let (strict, _) = fixture.plan(
        "SELECT operation FROM events WHERE received_at > CURRENT_TIMESTAMP - INTERVAL '1 second'",
        vec![],
    );
    let window = Window::from_plan(&strict).unwrap().unwrap();
    assert_eq!(
        window
            .selection(&fixture.selection(), 1_999_999_999)
            .received_from,
        Bound::Included(1_000_000_000)
    );
    assert_eq!(window.expiry(Some(1_000_000_123)), Some(2_000_000_000));
    let (inclusive, _) = fixture.plan(sql, vec![]);
    assert_eq!(
        Window::from_plan(&inclusive)
            .unwrap()
            .unwrap()
            .expiry(Some(1_000_000_123)),
        Some(2_000_000_001)
    );
}

#[tokio::test]
async fn notification_follow_deadline() {
    let fixture = Fixture::new(Limits::default());
    fixture.notification(100);
    let (plan, sources) = fixture.plan("SELECT overdue FROM notifications", vec![]);
    let clock = TestClock::new(99);
    let mut subscription = Subscription::new(
        Arc::clone(&fixture.engine),
        plan,
        sources,
        AnalysisSelectionV1::tenant(fixture.source.tenant_id),
        Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
        b"notification principal",
        None,
        clock.clone(),
        true,
    )
    .unwrap();
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), vec![ScalarValue::Boolean(Some(false))]);
    assert_eq!(first.snapshot.next_change, Some(100));
    let before = fixture.store.meta().unwrap();
    clock.set(100);
    let overdue = next(&mut subscription).await;
    assert!(overdue.clock_changed);
    assert_eq!(overdue.evaluated_utc_ns, 100);
    assert_eq!(values(&overdue, 0), vec![ScalarValue::Boolean(Some(true))]);
    assert_eq!(overdue.snapshot.next_change, None);
    assert_eq!(fixture.store.meta().unwrap(), before);
}

#[tokio::test]
async fn unused_notification_deadline() {
    let fixture = Fixture::new(Limits::default());
    fixture.notification(100);
    let (plan, sources) = fixture.plan(
        "WITH unused AS (SELECT overdue FROM notifications) SELECT 7 AS value",
        vec![],
    );
    assert_eq!(sources, BTreeSet::from(["notifications".to_owned()]));
    let clock = TestClock::new(99);
    let mut subscription = Subscription::new(
        Arc::clone(&fixture.engine),
        plan,
        sources,
        AnalysisSelectionV1::tenant(fixture.source.tenant_id),
        Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
        b"notification principal",
        None,
        clock.clone(),
        true,
    )
    .unwrap();
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(7))]);
    assert_eq!(first.snapshot.next_change, Some(100));
    assert_eq!(first.evaluated_utc_ns, 99);
    let before = fixture.store.meta().unwrap();
    clock.set(100);
    let completed = next(&mut subscription).await;
    assert!(completed.clock_changed);
    assert!(completed.batches.is_none());
    assert_eq!(completed.evaluated_utc_ns, 100);
    assert_eq!(completed.snapshot.next_change, None);
    assert_eq!(fixture.store.meta().unwrap(), before);
}

#[test]
fn cursor_admission_bindings() {
    let fixture = Fixture::new(Limits::default());
    let (plan, sources) = fixture.plan(
        "SELECT operation FROM events WHERE source_cursor = $1",
        vec![ScalarValue::UInt64(Some(1))],
    );
    let scope = fixture.selection();
    let operation = Operation::Append;
    let binding = Fingerprint::binding(&plan, &sources, &scope, operation, b"authority").unwrap();
    let cursor = Cursor::new(
        &fixture.store.meta().unwrap(),
        operation,
        binding,
        araphor_data::StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        0,
    );
    let (other, _) = fixture.plan(
        "SELECT operation FROM events WHERE source_cursor = $1",
        vec![ScalarValue::UInt64(Some(2))],
    );
    let attempt = |plan, scope, binding: &[u8], cursor| {
        Subscription::new(
            Arc::clone(&fixture.engine),
            plan,
            sources.clone(),
            scope,
            Arc::new(AnalysisReadControl::default()),
            binding,
            Some(cursor),
            TestClock::new(0),
            true,
        )
    };
    assert!(attempt(other, scope.clone(), b"authority", cursor.clone()).is_err());
    assert!(attempt(
        plan.clone(),
        scope.clone(),
        b"different authority",
        cursor.clone()
    )
    .is_err());
    assert!(attempt(plan.clone(), scope.clone(), b"authority", cursor).is_ok());
    let mut first = scope;
    first.traces = Selection::Exact(vec![TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "trace-test".into(),
        node_boot_id: [2; 16],
        request_id: [3; 16],
        execution_id: [4; 16],
        source_sha256: [5; 32],
    }]);
    let binding =
        Fingerprint::binding(&plan, &sources, &first, operation, b"same principal").unwrap();
    let cursor = Cursor::new(
        &fixture.store.meta().unwrap(),
        operation,
        binding,
        araphor_data::StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        0,
    );
    let mut second = first.clone();
    second.traces.exact_mut().unwrap()[0].execution_id = [9; 16];
    assert!(attempt(plan.clone(), second, b"same principal", cursor.clone()).is_err());
    assert!(attempt(plan, first, b"same principal", cursor).is_ok());
}

#[test]
fn clock_requires_time_filter() {
    let fixture = Fixture::new(Limits::default());
    for sql in [
        "SELECT CURRENT_TIMESTAMP FROM events",
        "SELECT CURRENT_TIMESTAMP - INTERVAL '1 second' FROM events",
        "SELECT operation FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 second' OR operation = 7",
    ] {
        let (plan, sources) = fixture.plan(sql, vec![]);
        assert!(Subscription::new(Arc::clone(&fixture.engine), plan, sources, fixture.selection(),
            Arc::new(AnalysisReadControl::default()), b"authority", None, TestClock::new(0), true).is_err());
    }
}
