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
use datafusion::common::{DataFusionError, ScalarValue};
use datafusion::logical_expr::LogicalPlan;
use futures_util::StreamExt as _;
use prost::Message as _;
use tokio::sync::watch;

use super::{Clock, Cursor, Fingerprint, Operation, State, Subscription, Update, Window};
use crate::execution::{Engine, Limits};
use crate::parser::Parser;

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
            State::page_plan(&plan).unwrap().is_some(),
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
    assert!(State::page_plan(&plan).unwrap().is_none());
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
    let snapshot = crate::sources::SourceSnapshot::new(
        Arc::clone(&fixture.store),
        fixture.selection(),
        Default::default(),
        AnalysisReadControl::default(),
        Duration::from_secs(5),
        2_000_000_000,
        Arc::clone(fixture.engine.memory()),
    );
    let mut state = fixture.engine.catalog(Default::default()).unwrap();
    state.config_mut().set_extension(snapshot);
    state
        .config_mut()
        .set_extension(Arc::new(crate::stream::Run {
            engine: Arc::clone(&fixture.engine),
            selection: fixture.selection(),
            sources,
            control: Arc::clone(&control),
            now: 2_000_000_000,
        }));
    let logical = crate::planner::subscription::Subscribe::plan(plan).unwrap();
    let physical = state.create_physical_plan(&logical).await.unwrap();
    assert!(physical
        .as_any()
        .is::<crate::stream::physical::SubscribeExec>());
    let mut stream = datafusion::physical_plan::execute_stream(physical, state.task_ctx()).unwrap();
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(
        ScalarValue::try_from_array(first.column(0), 0).unwrap(),
        ScalarValue::Int64(Some(1))
    );
    drop(first);
    let second = {
        let waiting = stream.next();
        futures_util::pin_mut!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
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
