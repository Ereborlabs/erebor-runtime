use std::{
    fs,
    ops::Bound,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

use araphor_data::{
    AnalysisReadControl, AnalysisResultCommitV1, AnalysisSelectionV1, AnalysisStore,
    AnalysisStreamIdentityV1, AnalysisWitnessV1, EvidenceDecisionContext, EvidenceIntakeIdentityV1,
    EvidenceRecord, EvidenceRetentionOwner, EvidenceStoreOutcomeV1, ProcessorClassV1,
    ProcessorScopeV1, ValidatedEvidenceBatchV1,
};
use araphor_query::datafusion::arrow::array::RecordBatch;
use araphor_query::datafusion::logical_expr::LogicalPlan;
use araphor_query::execution::{Engine, Limits};
use araphor_query::follow::{Clock as FollowClock, Cursor, Operation, Subscription, Update};
use araphor_query::sources::ArrowSnapshot;
use datafusion_common::ScalarValue;
use erebor_runtime_error::ErrorExt as _;
use futures_util::StreamExt as _;
use mithril_control::ControlStore;
use prost::Message as _;
use serde_json::json;
use tokio::sync::watch;

use crate::control_fixture::{OutagePolicyFixture, OUTAGE_NAMESPACE_UID};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MINUTE: u64 = 60_000_000_000;
const EVENTS: &str = "SELECT source_cursor, operation, received_utc_ns, ingested_utc_ns, observed_boottime_ns FROM events";
const COUNTS: &str =
    "SELECT operation, COUNT(*) AS count FROM events GROUP BY operation ORDER BY operation";
const MOVING: &str = "SELECT COUNT(*) AS count FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds'";
const BUCKETS: &str = "SELECT date_bin(INTERVAL '300 seconds', received_at, TIMESTAMP '1970-01-01 00:00:00') AS bucket_start, COUNT(*) AS count FROM events GROUP BY bucket_start ORDER BY bucket_start";

struct Clock {
    now: AtomicU64,
    changes: watch::Sender<u64>,
}

impl Clock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            changes: watch::channel(0).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_replace(now);
    }
}

impl FollowClock for Clock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        Ok(self.now.load(Ordering::SeqCst))
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct GateClock {
    gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    now: AtomicU64,
    reads: AtomicU64,
    pause: u64,
    changes: watch::Sender<u64>,
}

impl GateClock {
    fn new(now: u64) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        Self::on_read(now, 0)
    }

    fn on_read(now: u64, pause: u64) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        (
            Arc::new(Self {
                gate: Mutex::new(Some((entered, released))),
                now: AtomicU64::new(now),
                reads: AtomicU64::new(0),
                pause,
                changes: watch::channel(0).0,
            }),
            entering,
            release,
        )
    }
}

impl FollowClock for GateClock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        let now = self.now.load(Ordering::SeqCst);
        if self.reads.fetch_add(1, Ordering::SeqCst) != self.pause {
            return Ok(now);
        }
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, released)) = gate {
            let invalid = || araphor_query::Error::Invalid {
                field: "qualification clock gate",
                location: snafu::Location::default(),
            };
            entered.send(()).map_err(|_| invalid())?;
            released
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| invalid())?;
        }
        Ok(now)
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Cycle {
    results: Vec<Update>,
    cursor: Cursor,
    clock_changed: bool,
}

pub struct QueryFollowQualification {
    output: PathBuf,
}

impl QueryFollowQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn run(&self) -> Result<()> {
        self.check(!self.output.exists(), "the output directory already exists")?;
        let directory = tempfile::tempdir()?;
        let cases = [
            self.pending(&directory.path().join("pending"))
                .await
                .map_err(|error| format!("query-follow pending: {error}"))?,
            self.counts(&directory.path().join("counts"))
                .await
                .map_err(|error| format!("query-follow counts: {error}"))?,
            self.windows(&directory.path().join("windows"))
                .await
                .map_err(|error| format!("query-follow windows: {error}"))?,
            self.bounded_window(&directory.path().join("bounded"))
                .await
                .map_err(|error| format!("query-follow bounded window: {error:?}"))?,
            self.retention(&directory.path().join("retention"))
                .await
                .map_err(|error| format!("query-follow retention: {error}"))?,
            self.policy_continuity(&directory.path().join("policy"))
                .await
                .map_err(|error| format!("query-follow policy continuity: {error}"))?,
            self.snapshot_and_coalescing(&directory.path().join("snapshot"))
                .await
                .map_err(|error| format!("query-follow snapshot and coalescing: {error}"))?,
            self.paused_stream(&directory.path().join("paused"))
                .await
                .map_err(|error| format!("query-follow paused stream: {error}"))?,
        ];
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &json!({
                "schema_version": 1,
                "case": "query-follow",
                "result": "PASS",
                "native_sql": true,
                "production_owners": ["AnalysisStore", "Engine", "EvidenceRetentionOwner", "ControlStore", "PolicyDesiredStateOwner"],
                "cases": cases,
                "limits": limits_receipt(&Limits::default()),
                "input_rows_meaning": "Event evidence witnesses captured before SQL filters.",
                "input_bytes_meaning": "Data capture charge and separately retained native Arrow allocations.",
                "received_time_meaning": "Controlled durable intake UTC nanoseconds, not source action time.",
                "proof_boundary": "Internal production-owner qualification with synthetic evidence and a controlled clock.",
                "not_covered": ["pin-delete-race", "concurrent-rotation"],
                "separate_component_proof": "Pin/delete and snapshot rotation use component barriers. This case does not claim those simultaneous races.",
                "public_sql": false,
                "authenticated_cursor": false,
                "os_worker_isolation": false,
                "performance_claim": false
            }),
        )?;
        Ok(())
    }

    async fn pending(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let owner = Engine::new(
            store.clone(),
            Limits {
                output_rows: 4,
                ..Default::default()
            },
        )?;
        let clock = Clock::new(100 * MINUTE);
        let plan = prepare(&owner, &source, EVENTS).await?;
        self.check(
            commit(&store, &source, 11, MINUTE, records(11, 10, 7))?
                == EvidenceStoreOutcomeV1::Pending,
            "pending evidence advanced its ACK",
        )?;
        let mut stream = plan.subscribe(Arc::clone(&owner), None, clock.clone())?;
        let initial = self.cycle(&mut stream, Operation::Append).await?;
        self.check(
            cursors(&initial)? == (11..=20).collect::<Vec<_>>(),
            "pending rows differ",
        )?;
        self.check(
            initial.results.len() == 3,
            "append did not page complete output frames",
        )?;
        let coverage = &initial
            .results
            .last()
            .ok_or("initial result absent")?
            .snapshot
            .page
            .extraction
            .sources;
        self.check(
            coverage.len() == 1
                && coverage[0].receipt.contiguous_cursor == 0
                && coverage[0].pending.len() == 1
                && coverage[0].pending[0].first_cursor == 1
                && coverage[0].pending[0].last_cursor == 10,
            "pending source coverage differs",
        )?;
        commit(&store, &source, 1, 2 * MINUTE, records(1, 10, 7))?;
        let repaired = self.cycle(&mut stream, Operation::Append).await?;
        self.check(
            cursors(&repaired)? == (1..=10).collect::<Vec<_>>(),
            "gap repair duplicated rows",
        )?;
        let coverage = &repaired
            .results
            .last()
            .ok_or("repair result absent")?
            .snapshot
            .page
            .extraction
            .sources;
        self.check(
            coverage[0].receipt.contiguous_cursor == 20 && coverage[0].pending.is_empty(),
            "gap repair did not correct ACK and coverage",
        )?;
        let mut replay = plan.subscribe(
            Arc::clone(&owner),
            Some(initial.cursor.clone()),
            clock.clone(),
        )?;
        let replayed = self.cycle(&mut replay, Operation::Append).await?;
        self.check(
            cursors(&replayed)? == (1..=10).collect::<Vec<_>>(),
            "checkpoint replay differs",
        )?;
        self.cancel(&mut replay, Operation::Append).await?;
        let before = store.meta()?;
        commit(&store, &source, 1, 2 * MINUTE, records(1, 10, 7))?;
        self.check(
            store.meta()? == before,
            "exact retry changed the durable revision",
        )?;
        let unrelated = evidence_source(1, 4);
        let foreign = evidence_source(2, 3);
        commit(&store, &unrelated, 1, 3 * MINUTE, records(1, 1, 9))?;
        commit(&store, &foreign, 1, 3 * MINUTE, records(1, 1, 9))?;
        self.check(
            owner
                .session(
                    AnalysisSelectionV1::new(source.tenant_id, vec![foreign]),
                    &AnalysisReadControl::default(),
                    clock.now_ns()?,
                )
                .is_err(),
            "cross-tenant source selection was accepted",
        )?;
        let unrelated_revision = store.meta()?.commit_revision;
        clock.set(100 * MINUTE + 1);
        let evaluation = owner.reserve_evaluation(source.tenant_id)?;
        let health = self
            .health(&mut stream, Operation::Append, unrelated_revision)
            .await?;
        drop(evaluation);
        self.check(
            health.cursor == repaired.cursor
                && health.evaluated_utc_ns
                    == repaired
                        .results
                        .last()
                        .ok_or("repair update")?
                        .evaluated_utc_ns,
            "unrelated sources or a fixed clock change reran the selected query",
        )?;
        commit(&store, &source, 21, 4 * MINUTE, records(21, 1, 7))?;
        commit(&store, &source, 22, 4 * MINUTE, records(22, 1, 7))?;
        let mut appended = Vec::new();
        let mut notices = Vec::new();
        while appended.len() < 2 {
            let cycle = self.cycle(&mut stream, Operation::Append).await?;
            appended.extend(cursors(&cycle)?);
            notices.extend(
                cycle
                    .results
                    .iter()
                    .map(|result| result_receipt(&plan, result)),
            );
        }
        self.check(
            appended == [21, 22],
            "retry or unrelated input produced duplicate rows",
        )?;
        self.cancel(&mut stream, Operation::Append).await?;
        commit(&store, &source, 23, 5 * MINUTE, records(23, 1, 7))?;
        self.check(
            store
                .source_receipt(&source)?
                .ok_or("source absent")?
                .contiguous_cursor
                == 23,
            "cancelled follow blocked subsequent intake",
        )?;
        let empty = prepare(
            &owner,
            &source,
            "SELECT source_cursor FROM events WHERE operation = 99",
        )
        .await?;
        let mut empty_stream = empty.subscribe(Arc::clone(&owner), None, clock)?;
        let empty_cycle = self.cycle(&mut empty_stream, Operation::Append).await?;
        self.check(
            cursors(&empty_cycle)?.is_empty(),
            "empty filter returned rows",
        )?;
        self.check(
            empty_cycle.cursor.position().commit_revision > 0,
            "empty filter has no scan checkpoint",
        )?;
        self.cancel(&mut empty_stream, Operation::Append).await?;
        Ok(json!({
            "name": "pending-replay-and-scope", "result": "PASS", "output_rows_limit": 4,
            "initial": cycle_receipt(&plan, &initial), "repair": cycle_receipt(&plan, &repaired),
            "replay": cycle_receipt(&plan, &replayed), "later_commits": notices,
            "empty_filter": cycle_receipt(&empty, &empty_cycle),
            "unrelated_revision": unrelated_revision, "final_ack": 23,
            "cancellation": "Native subscription cancelled and closed"
        }))
    }

    async fn counts(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let owner = Engine::new(store.clone(), Limits::default())?;
        let plan = prepare(&owner, &source, COUNTS).await?;
        let clock = Clock::new(100 * MINUTE);
        let mut input = records(1, 2, 7);
        input.extend(records(3, 1, 8));
        commit(&store, &source, 1, MINUTE, input)?;
        let mut stream = plan.subscribe(Arc::clone(&owner), None, clock)?;
        let first = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &plan,
            &first,
            &[
                vec![ScalarValue::UInt32(Some(7)), ScalarValue::Int64(Some(2))],
                vec![ScalarValue::UInt32(Some(8)), ScalarValue::Int64(Some(1))],
            ],
        )?;
        commit(&store, &source, 4, 2 * MINUTE, records(4, 2, 7))?;
        let second = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &plan,
            &second,
            &[
                vec![ScalarValue::UInt32(Some(7)), ScalarValue::Int64(Some(4))],
                vec![ScalarValue::UInt32(Some(8)), ScalarValue::Int64(Some(1))],
            ],
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        Ok(
            json!({"name": "complete-operation-counts", "result": "PASS",
            "initial": cycle_receipt(&plan, &first), "replacement": cycle_receipt(&plan, &second)}),
        )
    }

    async fn windows(&self, root: &Path) -> Result<serde_json::Value> {
        fs::create_dir(root)?;
        let timer = self.timer_expiry(&root.join("timer")).await?;
        let store = Arc::new(AnalysisStore::open(root.join("history"))?);
        let source = evidence_source(1, 3);
        for (cursor, minute) in [(1, 601), (2, 604), (3, 607)] {
            commit(
                &store,
                &source,
                cursor,
                minute * MINUTE,
                records(cursor, 1, 7),
            )?;
        }
        let owner = Engine::new(store.clone(), Limits::default())?;
        let clock = Clock::new(608 * MINUTE);
        let moving = prepare(&owner, &source, MOVING).await?;
        let mut stream = moving.subscribe(Arc::clone(&owner), None, clock.clone())?;
        let first = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &moving,
            &first,
            &[vec![ScalarValue::Int64(Some(2))]],
        )?;
        let before = store.meta()?;
        clock.set(610 * MINUTE);
        let quiet = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &moving,
            &quiet,
            &[vec![ScalarValue::Int64(Some(1))]],
        )?;
        self.check(
            store.meta()? == before && quiet.clock_changed,
            "quiet expiry changed storage or hid its clock change",
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.received_from = Bound::Included(600 * MINUTE);
        selection.received_until = Bound::Excluded(610 * MINUTE);
        let fixed = Prepared::new(&owner, selection, BUCKETS).await?;
        let mut stream = fixed.subscribe(Arc::clone(&owner), None, clock.clone())?;
        let buckets = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(&owner, &fixed, &buckets, &[bucket(600, 2), bucket(605, 1)])?;
        commit(&store, &source, 4, 605 * MINUTE, records(4, 1, 7))?;
        let boundary = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(&owner, &fixed, &boundary, &[bucket(600, 2), bucket(605, 2)])?;
        let mut late = records(5, 1, 7);
        late[0].ingested_utc_ns = (604 * MINUTE) as i64;
        late[0].observed_boottime_ns = 123;
        commit(&store, &source, 5, 620 * MINUTE, late)?;
        let late_revision = store.meta()?.commit_revision;
        clock.set(620 * MINUTE);
        self.health(&mut stream, Operation::Replace, late_revision)
            .await?;
        self.check(
            batch_rows(&fixed.snapshot(&owner, 620 * MINUTE)?.1)?
                == [bucket(600, 2), bucket(605, 2)],
            "late input changed fixed input bounds",
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        let all = prepare(&owner, &source, BUCKETS).await?;
        let mut stream = all.subscribe(Arc::clone(&owner), None, clock)?;
        let late_buckets = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &all,
            &late_buckets,
            &[bucket(600, 2), bucket(605, 2), bucket(620, 1)],
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        let event_plan = prepare(&owner, &source, EVENTS).await?;
        let events = event_plan.snapshot(&owner, 620 * MINUTE)?;
        let event_rows = batch_rows(&events.1)?;
        let row = event_rows.last().ok_or("late row absent")?;
        self.check(
            row[event_plan
                .plan
                .schema()
                .as_arrow()
                .index_of("received_utc_ns")?]
                == ScalarValue::UInt64(Some(620 * MINUTE))
                && row[event_plan
                    .plan
                    .schema()
                    .as_arrow()
                    .index_of("ingested_utc_ns")?]
                    == ScalarValue::Int64(Some((604 * MINUTE) as i64))
                && row[event_plan
                    .plan
                    .schema()
                    .as_arrow()
                    .index_of("observed_boottime_ns")?]
                    == ScalarValue::UInt64(Some(123)),
            "late input lost its intake or source clock domain",
        )?;
        Ok(json!({"name": "moving-and-fixed-windows", "result": "PASS",
            "timer_only": timer,
            "at_1008": cycle_receipt(&moving, &first), "quiet_1010": cycle_receipt(&moving, &quiet),
            "fixed": cycle_receipt(&fixed, &buckets), "boundary_1005": cycle_receipt(&fixed, &boundary),
            "late_1020": cycle_receipt(&all, &late_buckets), "source_times": snapshot_receipt(&events)}))
    }

    async fn timer_expiry(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, 2_000_000_000, records(1, 1, 7))?;
        let owner = Engine::new(store.clone(), Limits::default())?;
        let plan = prepare(
            &owner,
            &source,
            "SELECT COUNT(*) AS count FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 second'",
        ).await?;
        let (clock, sampled, release) = GateClock::on_read(3_000_000_000, 1);
        let advancing = clock.clone();
        let advance = tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            sampled
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            advancing.now.store(4_000_000_000, Ordering::SeqCst);
            release.send(()).map_err(|error| error.to_string())
        });
        let mut stream = plan.subscribe(Arc::clone(&owner), None, clock)?;
        let initial = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &plan,
            &initial,
            &[vec![ScalarValue::Int64(Some(1))]],
        )?;
        let before = store.meta()?;
        let expired = tokio::time::timeout(
            Duration::from_secs(5),
            self.cycle(&mut stream, Operation::Replace),
        )
        .await??;
        advance.await??;
        self.replacement(
            &owner,
            &plan,
            &expired,
            &[vec![ScalarValue::Int64(Some(0))]],
        )?;
        self.check(
            store.meta()? == before
                && expired.cursor.read_revision() == initial.cursor.read_revision(),
            "timer-only expiry changed the store revision",
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        Ok(json!({"initial": cycle_receipt(&plan, &initial),
            "expired": cycle_receipt(&plan, &expired), "clock_notifications": false,
            "store_unchanged": true, "deadline_ms": 5000, "heartbeat_ms": 15000}))
    }

    async fn bounded_window(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let limits = Limits {
            scan_bytes: 32 * 1024,
            input_bytes: 64 * 1024,
            ..Default::default()
        };
        let mut history = records(1, 64, 7);
        for record in &mut history {
            record
                .decision_context
                .as_mut()
                .ok_or("context absent")?
                .catalog_json = vec![b' '; 2048];
        }
        let history_bytes: usize = history.iter().map(|record| record.encoded_len() + 8).sum();
        self.check(
            history_bytes > limits.scan_bytes,
            "history does not exceed the configured scan bound",
        )?;
        commit(&store, &source, 1, 500 * MINUTE, history)?;
        commit(&store, &source, 65, 604 * MINUTE, records(65, 1, 7))?;
        commit(&store, &source, 66, 607 * MINUTE, records(66, 1, 7))?;
        let owner = Engine::new(store.clone(), limits.clone())?;
        let moving = prepare(&owner, &source, MOVING).await?;
        let all = prepare(&owner, &source, COUNTS).await?;
        self.check(
            matches!(
                all.snapshot(&owner, 608 * MINUTE),
                Err(error) if failure(&error, "input")
            ),
            "over-budget complete input was accepted",
        )?;
        let mut stream = moving.subscribe(Arc::clone(&owner), None, Clock::new(608 * MINUTE))?;
        let initial = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &moving,
            &initial,
            &[vec![ScalarValue::Int64(Some(2))]],
        )?;
        self.check(
            event_inputs(&initial.results[0]) == 2
                && initial.results[0].snapshot.witnesses.iter().all(|witness| {
                    matches!(&witness.identity, AnalysisStreamIdentityV1::Evidence(identity) if identity == &source)
                })
                && initial.results[0].snapshot.witnesses.iter().map(|witness| witness.cursor).eq([65, 66])
                && initial.results[0].snapshot.page.extraction.scanned_bytes <= limits.scan_bytes,
            "time selection extracted unrelated history",
        )?;
        commit(&store, &source, 67, 608 * MINUTE, records(67, 1, 7))?;
        let added = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &moving,
            &added,
            &[vec![ScalarValue::Int64(Some(3))]],
        )?;
        self.check(
            event_inputs(&added.results[0]) == 3
                && added.results[0].snapshot.witnesses.iter().all(|witness| {
                    matches!(&witness.identity, AnalysisStreamIdentityV1::Evidence(identity) if identity == &source)
                })
                && added.results[0].snapshot.witnesses.iter().map(|witness| witness.cursor).eq([65, 66, 67]),
            "replacement omitted matching input",
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        let output_owner = Engine::new(
            store.clone(),
            Limits {
                output_rows: 1,
                ..limits.clone()
            },
        )?;
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.received_from = Bound::Included(603 * MINUTE);
        let counts = Prepared::new(&owner, selection, COUNTS).await?;
        let mut output_stream =
            counts.subscribe(Arc::clone(&output_owner), None, Clock::new(608 * MINUTE))?;
        let output_before = self.cycle(&mut output_stream, Operation::Replace).await?;
        self.replacement(
            &output_owner,
            &counts,
            &output_before,
            &[vec![
                ScalarValue::UInt32(Some(7)),
                ScalarValue::Int64(Some(3)),
            ]],
        )?;
        commit(&store, &source, 68, 608 * MINUTE, records(68, 1, 8))?;
        let output_error = self
            .stream_error(
                &mut output_stream,
                Operation::Replace,
                &output_before.cursor,
                "output",
            )
            .await?;
        self.check(
            matches!(
                counts.snapshot(&output_owner, 608 * MINUTE),
                Err(error) if failure(&error, "output")
            ),
            "over-budget replacement returned a partial aggregate",
        )?;
        commit(&store, &source, 69, 608 * MINUTE, records(69, 1, 7))?;
        let recovered = moving.snapshot(&output_owner, 608 * MINUTE)?;
        self.check(
            batch_rows(&recovered.1)? == [vec![ScalarValue::Int64(Some(5))]],
            "failed evaluation blocked later reads or intake",
        )?;
        let mut input_stream =
            counts.subscribe(Arc::clone(&owner), None, Clock::new(608 * MINUTE))?;
        let input_before = self.cycle(&mut input_stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &counts,
            &input_before,
            &[
                vec![ScalarValue::UInt32(Some(7)), ScalarValue::Int64(Some(4))],
                vec![ScalarValue::UInt32(Some(8)), ScalarValue::Int64(Some(1))],
            ],
        )?;
        let mut large = records(70, 1, 7);
        large[0]
            .decision_context
            .as_mut()
            .ok_or("context absent")?
            .catalog_json = vec![b' '; limits.scan_bytes];
        commit(&store, &source, 70, 608 * MINUTE, large)?;
        let input_error = self
            .stream_error(
                &mut input_stream,
                Operation::Replace,
                &input_before.cursor,
                "input",
            )
            .await?;
        commit(&store, &source, 71, 620 * MINUTE, records(71, 1, 7))?;
        let subsequent = moving.snapshot(&owner, 620 * MINUTE)?;
        self.check(
            batch_rows(&subsequent.1)? == [vec![ScalarValue::Int64(Some(1))]],
            "input overflow blocked later intake or a bounded query",
        )?;
        Ok(
            json!({"name": "bounded-window-and-recovery", "result": "PASS", "limits": limits_receipt(&limits),
            "historical_frame_bytes": history_bytes, "initial": cycle_receipt(&moving, &initial),
            "replacement": cycle_receipt(&moving, &added), "after_error": snapshot_receipt(&recovered),
            "output_before": cycle_receipt(&counts, &output_before), "output_error": output_error,
            "input_before": cycle_receipt(&counts, &input_before), "input_error": input_error,
            "after_input_error": snapshot_receipt(&subsequent)}),
        )
    }

    async fn retention(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let expires = 3 * 24 * 60 * MINUTE;
        let now = expires - 1;
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let witness_position = store.read_page(&source, 1)?.records[0].position;
        let owner = Engine::new(store.clone(), Limits::default())?;
        let plan = prepare(&owner, &source, EVENTS).await?;
        let mut stream = plan.subscribe(Arc::clone(&owner), None, Clock::new(now))?;
        let initial = self.cycle(&mut stream, Operation::Append).await?;
        self.check(cursors(&initial)? == [1], "initial witness row differs")?;
        self.cancel(&mut stream, Operation::Append).await?;
        drop(stream);
        let changed_sql = prepare(
            &owner,
            &source,
            "SELECT source_cursor FROM events WHERE operation = 8",
        )
        .await?;
        self.check(matches!(changed_sql.subscribe(Arc::clone(&owner), Some(initial.cursor.clone()), Clock::new(now)),
            Err(ref error) if failure(error, "binding")), "changed SQL accepted an unrelated cursor")?;
        let mut selection = plan.selection.clone();
        selection.received_from = Bound::Excluded(0);
        let changed_scope = Prepared::new(&owner, selection, EVENTS).await?;
        self.check(matches!(changed_scope.subscribe(Arc::clone(&owner), Some(initial.cursor.clone()), Clock::new(now)),
            Err(ref error) if failure(error, "binding")), "changed scope accepted an unrelated cursor")?;
        store.backup(&root.join("backups/sealed"))?;
        commit(&store, &source, 2, 2 * MINUTE, records(2, 2, 7))?;
        let floor = store.read_page(&source, 3)?.records[0].position;
        let counts = prepare(&owner, &source, COUNTS).await?;
        let mut stream = counts.subscribe(Arc::clone(&owner), None, Clock::new(now))?;
        let before = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &counts,
            &before,
            &[vec![
                ScalarValue::UInt32(Some(7)),
                ScalarValue::Int64(Some(3)),
            ]],
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        drop(stream);
        let scope = ProcessorScopeV1 {
            processor_id: "query-witness".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 3,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "query-retained-witness".into(),
            body: b"query witness".to_vec(),
            created_utc_ns: 3 * MINUTE,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor: 1,
                expires_utc_ns: expires,
            }],
            context_refs: Vec::new(),
        })?;
        let retained = EvidenceRetentionOwner::new(&store).retain(&source, now)?;
        self.check(
            retained.removed_records == 2
                && store.replay_floor(source.tenant_id)? == Some(floor)
                && witness_position < floor
                && initial.cursor.position() < floor,
            "retention did not persist the expected raw replay floor",
        )?;
        let expired = self
            .follow_error(&owner, &plan, &initial.cursor, now, "expired")
            .await?;
        let witness = self.witness_query(&owner, &plan, now)?;
        let mut stream = counts.subscribe(
            Arc::clone(&owner),
            Some(before.cursor.clone()),
            Clock::new(now),
        )?;
        let replacement = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &counts,
            &replacement,
            &[vec![
                ScalarValue::UInt32(Some(7)),
                ScalarValue::Int64(Some(1)),
            ]],
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        drop(stream);
        let backup = root.join("backups/retained");
        store.backup(&backup)?;
        let saved_meta = store.meta()?;
        drop(owner);
        drop(store);
        let reopened = Arc::new(AnalysisStore::open(root)?);
        self.check(
            reopened.meta()? == saved_meta
                && reopened.replay_floor(source.tenant_id)? == Some(floor),
            "restart changed the store identity or replay floor",
        )?;
        let owner = Engine::new(reopened.clone(), Limits::default())?;
        let restart_error = self
            .follow_error(&owner, &plan, &initial.cursor, now, "expired")
            .await?;
        let restart_witness = self.witness_query(&owner, &plan, now)?;
        let restored = Arc::new(AnalysisStore::restore(
            &backup,
            &root.with_file_name("retention-restored"),
        )?);
        let mut restored_meta = saved_meta.clone();
        restored_meta.recovery_epoch += 1;
        self.check(
            restored.meta()? == restored_meta
                && restored.replay_floor(source.tenant_id)? == Some(floor),
            "restore lost the replay floor or did not change the recovery epoch",
        )?;
        let restored_owner = Engine::new(restored, Limits::default())?;
        let restore_error = self
            .follow_error(&restored_owner, &plan, &initial.cursor, now, "binding")
            .await?;
        let restore_witness = self.witness_query(&restored_owner, &plan, now)?;
        let mut stream = plan.subscribe(Arc::clone(&restored_owner), None, Clock::new(now))?;
        let fresh = self.cycle(&mut stream, Operation::Append).await?;
        self.check(
            cursors(&fresh)? == [1],
            "fresh restored follow lost its retained witness",
        )?;
        self.cancel(&mut stream, Operation::Append).await?;
        Ok(json!({
            "name": "retention-restart-restore-and-witness", "result": "PASS",
            "initial": cycle_receipt(&plan, &initial), "replay_floor": floor,
            "changed_sql_cursor_rejected": true, "changed_scope_cursor_rejected": true,
            "witness_position": witness_position, "removed_records": retained.removed_records,
            "expired": expired, "witness": witness,
            "replacement_before": cycle_receipt(&counts, &before),
            "replacement_after": cycle_receipt(&counts, &replacement),
            "restart_error": restart_error, "restart_witness": restart_witness,
            "restore_error": restore_error, "restore_witness": restore_witness,
            "fresh_restore": cycle_receipt(&plan, &fresh),
            "store_uuid": saved_meta.store_uuid.to_string(),
            "recovery_epoch_before": saved_meta.recovery_epoch,
            "recovery_epoch_restored": restored_meta.recovery_epoch
        }))
    }

    fn witness_query(
        &self,
        owner: &Arc<Engine>,
        plan: &Prepared,
        now: u64,
    ) -> Result<serde_json::Value> {
        let result = plan.snapshot(owner, now)?;
        let sources = &result.0.page.extraction.sources;
        self.check(
            batch_rows(&result.1)?.len() == 1
                && batch_rows(&result.1)?[0]
                    [plan.plan.schema().as_arrow().index_of("source_cursor")?]
                    == ScalarValue::UInt64(Some(1))
                && sources.len() == 1
                && sources[0].receipt.contiguous_cursor == 3
                && sources[0].expired.len() == 1
                && sources[0].expired[0].first_cursor == 2
                && sources[0].expired[0].last_cursor == 3,
            "retained witness or explicit expired coverage differs",
        )?;
        Ok(snapshot_receipt(&result))
    }

    async fn follow_error(
        &self,
        owner: &Arc<Engine>,
        plan: &Prepared,
        cursor: &Cursor,
        now: u64,
        expected: &str,
    ) -> Result<serde_json::Value> {
        let mut stream =
            plan.subscribe(Arc::clone(owner), Some(cursor.clone()), Clock::new(now))?;
        self.stream_error(&mut stream, Operation::Append, cursor, expected)
            .await
    }

    async fn stream_error(
        &self,
        stream: &mut Subscription,
        operation: Operation,
        cursor: &Cursor,
        expected: &str,
    ) -> Result<serde_json::Value> {
        let error = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match stream
                    .next()
                    .await
                    .ok_or("subscription closed before its error")?
                {
                    Ok(update) if update.batches.is_none() && update.operation == operation => {}
                    Ok(_) => return Err("failed native evaluation emitted a partial result".into()),
                    Err(error) => return Result::Ok(error),
                }
            }
        })
        .await??;
        self.check(
            failure(&error, expected),
            &format!("native query error category differs: {error:?}"),
        )?;
        self.check(
            tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await?
                .is_none(),
            "failed native subscription did not close",
        )?;
        Ok(
            json!({"failure": expected, "status": format!("{:?}", error.status_code()),
            "last_delivered_cursor": cursor, "stream_closed": true, "partial_result": false}),
        )
    }

    async fn policy_continuity(&self, root: &Path) -> Result<serde_json::Value> {
        const POLICY_TIME: i64 = 1_800_000_000_000_000_000;
        let control = ControlStore::open(root.join("control"))?;
        let fixture = OutagePolicyFixture::new(control.clone());
        let first = fixture.resource(1)?;
        let first = fixture.owner.reconcile(
            &first,
            OUTAGE_NAMESPACE_UID,
            &fixture.inventory(&first)?,
            POLICY_TIME,
        )?;
        let first_id = first.source_revision.policy_source_revision_id;
        let first_policy = control
            .policy_document(&first_id)?
            .ok_or("initial policy absent")?;
        let control_before = control.health()?.commit_index;
        let store = Arc::new(AnalysisStore::open(root.join("analysis"))?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let owner = Engine::new(store.clone(), Limits::default())?;
        let plan = prepare(&owner, &source, COUNTS).await?;
        let mut stream = plan.subscribe(Arc::clone(&owner), None, Clock::new(2 * MINUTE))?;
        let initial = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &plan,
            &initial,
            &[vec![
                ScalarValue::UInt32(Some(7)),
                ScalarValue::Int64(Some(1)),
            ]],
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        let second = fixture.resource(2)?;
        let second = fixture.owner.reconcile(
            &second,
            OUTAGE_NAMESPACE_UID,
            &fixture.inventory(&second)?,
            POLICY_TIME + 1,
        )?;
        let second_id = second.source_revision.policy_source_revision_id;
        let control_after = control.health()?.commit_index;
        self.check(
            second_id != first_id
                && control_after > control_before
                && control.policy_document(&second_id)?.is_some()
                && control.policy_document(&first_id)?.as_ref() == Some(&first_policy),
            "query cancellation blocked policy work or changed the prior policy",
        )?;
        commit(&store, &source, 2, 2 * MINUTE, records(2, 1, 7))?;
        let subsequent = plan.snapshot(&owner, 2 * MINUTE)?;
        self.check(
            batch_rows(&subsequent.1)?
                == [vec![
                    ScalarValue::UInt32(Some(7)),
                    ScalarValue::Int64(Some(2)),
                ]],
            "query cancellation blocked subsequent intake or reads",
        )?;
        Ok(
            json!({"name": "cancellation-policy-and-intake", "result": "PASS",
            "initial": cycle_receipt(&plan, &initial), "subsequent": snapshot_receipt(&subsequent),
            "cancellation": "Native subscription cancelled and closed",
            "policy_operation": "PolicyDesiredStateOwner::reconcile",
            "policy_source_before": first_id, "policy_source_after": second_id,
            "control_revision_before": control_before, "control_revision_after": control_after,
            "concurrency_claim": false}),
        )
    }

    async fn snapshot_and_coalescing(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let now = 100 * MINUTE;
        let owner = Engine::new(store.clone(), Limits::default())?;
        let plan = prepare(&owner, &source, EVENTS).await?;
        let (clock, entered, release) = GateClock::new(now);
        let writing = store.clone();
        let writer_source = source.clone();
        let writer = tokio::task::spawn_blocking(move || -> std::result::Result<u64, String> {
            entered
                .recv_timeout(Duration::from_secs(10))
                .map_err(|error| error.to_string())?;
            for cursor in [2, 3] {
                commit(
                    &writing,
                    &writer_source,
                    cursor,
                    2 * MINUTE,
                    records(cursor, 1, 7),
                )
                .map_err(|error| error.to_string())?;
            }
            let revision = writing
                .meta()
                .map_err(|error| error.to_string())?
                .commit_revision;
            release.send(()).map_err(|error| error.to_string())?;
            Ok(revision)
        });
        let mut stream = plan.subscribe(Arc::clone(&owner), None, clock)?;
        let initial = self.cycle(&mut stream, Operation::Append).await?;
        let captured = tokio::time::timeout(Duration::from_secs(10), writer).await???;
        self.check(
            cursors(&initial)? == [1, 2, 3]
                && initial.results.len() == 1
                && initial.results[0]
                    .snapshot
                    .page
                    .extraction
                    .meta
                    .commit_revision
                    == captured
                && initial.results[0].snapshot.page.extraction.sources[0]
                    .receipt
                    .contiguous_cursor
                    == 3,
            "initial snapshot lost or duplicated commits made inside its clock barrier",
        )?;
        self.cancel(&mut stream, Operation::Append).await?;
        let counts = prepare(&owner, &source, COUNTS).await?;
        let mut stream = counts.subscribe(Arc::clone(&owner), None, Clock::new(now))?;
        let held = self.next(&mut stream, Operation::Replace).await?;
        self.check(
            held.batches.is_some()
                && held.snapshot.page.extraction.meta.commit_revision == captured,
            "native replacement did not capture its initial snapshot",
        )?;
        let baseline = counts.snapshot(&owner, now)?;
        for (cursor, operation) in [(4, 7), (5, 9), (6, 7)] {
            commit(
                &store,
                &source,
                cursor,
                3 * MINUTE,
                records(cursor, 1, operation),
            )?;
        }
        let coalesced_revision = store.meta()?.commit_revision;
        let before = Cycle {
            cursor: held.cursor.clone(),
            clock_changed: held.clock_changed,
            results: vec![held],
        };
        self.check(
            before.results.len() == 1
                && before.results[0].snapshot.page.extraction.meta
                    == baseline.0.page.extraction.meta
                && rows(&before.results[0])? == batch_rows(&baseline.1)?
                && batch_rows(&baseline.1)?
                    == [vec![
                        ScalarValue::UInt32(Some(7)),
                        ScalarValue::Int64(Some(3)),
                    ]],
            "retained native replacement changed after later commits",
        )?;
        let after = self.cycle(&mut stream, Operation::Replace).await?;
        self.replacement(
            &owner,
            &counts,
            &after,
            &[
                vec![ScalarValue::UInt32(Some(7)), ScalarValue::Int64(Some(5))],
                vec![ScalarValue::UInt32(Some(9)), ScalarValue::Int64(Some(1))],
            ],
        )?;
        self.check(
            after.results[0]
                .snapshot
                .page
                .extraction
                .meta
                .commit_revision
                == coalesced_revision,
            "coalesced wake did not include the complete commit batch",
        )?;
        self.cancel(&mut stream, Operation::Replace).await?;
        Ok(
            json!({"name": "initial-snapshot-and-coalesced-wake", "result": "PASS",
            "barrier": "Two commits complete after follow registration and before the first query snapshot.",
            "initial": cycle_receipt(&plan, &initial), "captured_revision": captured,
            "coalesced_commits": 3, "coalesced_revision": coalesced_revision,
            "before": cycle_receipt(&counts, &before), "after": cycle_receipt(&counts, &after)}),
        )
    }

    async fn paused_stream(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let limits = Limits {
            global_streams: 1,
            tenant_streams: 1,
            ..Default::default()
        };
        let owner = Engine::new(store.clone(), limits.clone())?;
        let plan = prepare(&owner, &source, EVENTS).await?;
        let (clock, _, _) = GateClock::on_read(2 * MINUTE, u64::MAX);
        let mut stream = plan.subscribe(Arc::clone(&owner), None, clock.clone())?;
        self.check(
            matches!(
                plan.subscribe(Arc::clone(&owner), None, Clock::new(2 * MINUTE)),
                Err(error) if failure(&error, "busy")
            ),
            "active stream did not consume its admission slot",
        )?;
        let retaining = store.clone();
        let retained_source = source.clone();
        let retained = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                EvidenceRetentionOwner::new(&retaining)
                    .retain(&retained_source, 3 * 24 * 60 * MINUTE)
            }),
        )
        .await???;
        self.check(
            retained.removed_records == 1,
            "unpolled stream retained a raw segment lease",
        )?;
        commit(&store, &source, 2, 2 * MINUTE, records(2, 1, 7))?;
        self.check(
            clock.reads.load(Ordering::SeqCst) == 0,
            "unpolled stream started query work",
        )?;
        let initial = self.cycle(&mut stream, Operation::Append).await?;
        self.check(
            cursors(&initial)? == [2],
            "first demand did not read current retained input",
        )?;
        let initial_receipt = cycle_receipt(&plan, &initial);
        let alias = initial.results[0]
            .batches
            .as_ref()
            .and_then(|batches| batches.first())
            .ok_or("paused native batch")?
            .column(0)
            .clone();
        let memory = Arc::clone(owner.memory());
        drop(initial);
        let reads = clock.reads.load(Ordering::SeqCst);
        commit(&store, &source, 3, 3 * MINUTE, records(3, 1, 7))?;
        self.check(
            clock.reads.load(Ordering::SeqCst) == reads,
            "paused stream started another evaluation",
        )?;
        let running = Arc::downgrade(&owner);
        drop(owner);
        drop(stream);
        self.check(
            running.upgrade().is_none(),
            "stream drop retained its query owner",
        )?;
        self.check(
            memory.reserve_output(limits.output_capacity).is_err()
                && ScalarValue::try_from_array(&alias, 0)? == ScalarValue::UInt64(Some(2)),
            "borrowed native output lost its allocation or value after producer drop",
        )?;
        self.check(
            memory.reserve_input(limits.input_capacity).is_ok(),
            "borrowed output retained unrelated source input capacity",
        )?;
        drop(alias);
        self.check(
            memory.reserve_output(limits.output_capacity).is_ok(),
            "final native buffer drop did not release output capacity",
        )?;
        let owner = Engine::new(store, limits.clone())?;
        let mut recovered = plan.subscribe(Arc::clone(&owner), None, Clock::new(3 * MINUTE))?;
        let subsequent = self.cycle(&mut recovered, Operation::Append).await?;
        self.check(
            cursors(&subsequent)? == [2, 3],
            "paused stream blocked later intake or follow",
        )?;
        self.cancel(&mut recovered, Operation::Append).await?;
        Ok(json!({"name": "lazy-demand-and-drop", "result": "PASS",
            "limits": limits_receipt(&limits), "owner_released_on_drop": true,
            "retention_removed_before_first_poll": retained.removed_records,
            "no_unpolled_evaluation": true,
            "initial": initial_receipt,
            "borrowed_output_capacity_until_final_drop": true,
            "subsequent": cycle_receipt(&plan, &subsequent)}))
    }

    async fn next(&self, stream: &mut Subscription, operation: Operation) -> Result<Update> {
        let update = tokio::time::timeout(Duration::from_secs(20), stream.next())
            .await?
            .ok_or("subscription closed before its expected update")??;
        self.check(
            update.operation == operation
                && !update.snapshot.page.extraction.meta.store_uuid.is_nil()
                && update.snapshot.page.extraction.meta.recovery_epoch > 0,
            "native update receipt is invalid",
        )?;
        Ok(update)
    }

    async fn cycle(&self, stream: &mut Subscription, operation: Operation) -> Result<Cycle> {
        self.check(
            !stream.schema().fields().is_empty(),
            "native subscription schema is empty",
        )?;
        let mut results = Vec::new();
        let mut clock_changed = false;
        for _ in 0..128 {
            let update = self.next(stream, operation).await?;
            if update.batches.is_none() {
                continue;
            }
            clock_changed |= update.clock_changed;
            self.check(
                update.cursor.read_revision()
                    == update.snapshot.page.extraction.meta.commit_revision,
                "native cursor differs from captured receipt",
            )?;
            let encoded = update.cursor.encode()?;
            self.check(
                Cursor::decode(&encoded)? == update.cursor,
                "native cursor encoding differs",
            )?;
            let exhausted = update.exhausted;
            let cursor = update.cursor.clone();
            results.push(update);
            if exhausted || operation == Operation::Replace {
                return Ok(Cycle {
                    results,
                    cursor,
                    clock_changed,
                });
            }
        }
        Err("native paging did not finish within its update bound".into())
    }

    async fn health(
        &self,
        stream: &mut Subscription,
        operation: Operation,
        revision: u64,
    ) -> Result<Update> {
        for _ in 0..4 {
            let update = self.next(stream, operation).await?;
            self.check(
                update.batches.is_none()
                    && update.snapshot.page.extraction.meta.commit_revision == revision
                    && update.cursor.read_revision() <= revision
                    && update.snapshot.page.extraction.scanned_bytes == 0,
                "health emitted rows, decoded raw input, or lost the current metadata receipt",
            )?;
            if update.clock_changed {
                return Ok(update);
            }
        }
        Err("native clock health update was not delivered".into())
    }

    async fn cancel(&self, stream: &mut Subscription, _operation: Operation) -> Result<()> {
        stream.cancel()?;
        self.check(
            tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await?
                .is_none(),
            "cancelled native subscription did not close",
        )
    }

    fn replacement(
        &self,
        owner: &Arc<Engine>,
        plan: &Prepared,
        cycle: &Cycle,
        expected: &[Vec<ScalarValue>],
    ) -> Result<()> {
        self.check(
            cycle.results.len() == 1,
            "replacement was split across updates",
        )?;
        let result = &cycle.results[0];
        let normal = plan.snapshot(owner, result.evaluated_utc_ns)?;
        let schema = plan.plan.schema().as_arrow();
        self.check(
            !result.limited
                && rows(result)? == expected
                && rows(result)? == batch_rows(&normal.1)?
                && result.batches.as_ref().is_none_or(|batches| {
                    batches
                        .iter()
                        .all(|batch| batch.schema().as_ref() == schema)
                })
                && normal
                    .1
                    .iter()
                    .all(|batch| batch.schema().as_ref() == schema)
                && result.snapshot.page.extraction.meta == normal.0.page.extraction.meta,
            "replacement differs from a complete native query at the same revision and instant",
        )
    }

    fn check(&self, passed: bool, reason: &str) -> Result<()> {
        if !passed {
            return Err(crate::error::InvalidInputSnafu {
                path: &self.output,
                reason,
            }
            .build()
            .into());
        }
        Ok(())
    }
}

fn evidence_source(tenant: u8, source_id: u8) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [tenant; 16],
        node_id: "query-node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [source_id; 16],
        source_epoch: 1,
    }
}

fn records(first: u64, count: usize, operation: u32) -> Vec<EvidenceRecord> {
    (first..first + count as u64)
        .map(|cursor| EvidenceRecord {
            operation,
            task_cookie: 1,
            observed_boottime_ns: cursor * 100,
            ingested_utc_ns: cursor as i64,
            temporal_coverage: 1,
            decision_context: Some(EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: cursor,
                ..Default::default()
            }),
            ..Default::default()
        })
        .collect()
}

fn commit(
    store: &AnalysisStore,
    source: &EvidenceIntakeIdentityV1,
    first: u64,
    received: u64,
    records: Vec<EvidenceRecord>,
) -> Result<EvidenceStoreOutcomeV1> {
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for record in records {
        let payload = record.encode_to_vec();
        let mut frame = u32::try_from(payload.len())?.to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        bytes.extend_from_slice(&frame);
        ends.push(bytes.len());
    }
    Ok(store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + ends.len() as u64 - 1,
            intake_utc_ns: received,
            framed_records: bytes.into(),
            frame_ends: ends,
        },
    )?)
}

struct Prepared {
    plan: Arc<LogicalPlan>,
    sources: araphor_data::AnalysisTableRequests,
    selection: AnalysisSelectionV1,
}

impl Prepared {
    async fn new(engine: &Engine, selection: AnalysisSelectionV1, sql: &str) -> Result<Self> {
        let (plan, sources) = engine.prepare(sql, vec![]).await?;
        Ok(Self {
            plan: Arc::new(plan),
            sources,
            selection,
        })
    }

    fn subscribe(
        &self,
        engine: Arc<Engine>,
        resume: Option<Cursor>,
        clock: Arc<dyn FollowClock>,
    ) -> araphor_query::Result<Subscription> {
        (engine)
            .session(
                self.selection.clone(),
                &(Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(120))?)),
                0,
            )
            .and_then(|session| {
                Subscription::new(
                    session,
                    Arc::clone(&self.plan),
                    self.sources.clone(),
                    b"mithril-e2e.query-follow",
                    resume,
                    clock,
                    true,
                )
            })
    }

    fn snapshot(
        &self,
        engine: &Arc<Engine>,
        now: u64,
    ) -> araphor_query::Result<(Arc<ArrowSnapshot>, Vec<RecordBatch>)> {
        engine
            .session(
                self.selection.clone(),
                &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
                now,
            )?
            .execute(Arc::clone(&self.plan), &self.sources)
    }
}

async fn prepare(
    engine: &Engine,
    source: &EvidenceIntakeIdentityV1,
    sql: &str,
) -> Result<Prepared> {
    Prepared::new(
        engine,
        AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]),
        sql,
    )
    .await
}

fn batch_rows(batches: &[RecordBatch]) -> Result<Vec<Vec<ScalarValue>>> {
    let mut rows = Vec::new();
    for batch in batches {
        for row in 0..batch.num_rows() {
            rows.push(
                batch
                    .columns()
                    .iter()
                    .map(|array| ScalarValue::try_from_array(array, row))
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            );
        }
    }
    Ok(rows)
}

fn rows(update: &Update) -> Result<Vec<Vec<ScalarValue>>> {
    batch_rows(update.batches.as_deref().unwrap_or_default())
}

fn column(result: &Update, name: &str) -> Result<usize> {
    result
        .batches
        .as_ref()
        .and_then(|batches| batches.first())
        .ok_or("native batch absent")?
        .schema()
        .index_of(name)
        .map_err(Into::into)
}

fn cursors(cycle: &Cycle) -> Result<Vec<u64>> {
    let mut values = Vec::new();
    for result in &cycle.results {
        if rows(result)?.is_empty() {
            continue;
        }
        let index = column(result, "source_cursor")?;
        for row in rows(result)? {
            let ScalarValue::UInt64(Some(cursor)) = &row[index] else {
                return Err("source cursor is not UInt64".into());
            };
            values.push(*cursor);
        }
    }
    Ok(values)
}

fn failure(error: &araphor_query::Error, expected: &str) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisInputTooLarge { .. })
        ) && expected == "input"
        {
            return true;
        }
        if matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisReplayExpired { .. })
        ) && expected == "expired"
        {
            return true;
        }
        if matches!(
            error.downcast_ref::<araphor_query::Error>(),
            Some(araphor_query::Error::Invalid {
                field: "cursor binding" | "cursor store",
                ..
            })
        ) && expected == "binding"
        {
            return true;
        }
        if matches!(
            error.downcast_ref::<araphor_query::Error>(),
            Some(araphor_query::Error::Busy { .. } | araphor_query::Error::Capacity { .. })
        ) && expected == "busy"
        {
            return true;
        }
        if matches!(
            error.downcast_ref::<araphor_query::datafusion::error::DataFusionError>(),
            Some(araphor_query::datafusion::error::DataFusionError::ResourcesExhausted(_))
        ) && expected == "output"
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn bucket(minute: u64, count: i64) -> Vec<ScalarValue> {
    vec![
        ScalarValue::TimestampMicrosecond(Some((minute * MINUTE / 1_000) as i64), None),
        ScalarValue::Int64(Some(count)),
    ]
}

fn event_inputs(update: &Update) -> usize {
    update
        .snapshot
        .witnesses
        .iter()
        .filter(|witness| matches!(witness.identity, AnalysisStreamIdentityV1::Evidence(_)))
        .count()
}

fn result_receipt(plan: &Prepared, update: &Update) -> serde_json::Value {
    let snapshot = &update.snapshot;
    let captured = &snapshot.page.extraction;
    let batches = update.batches.as_deref().unwrap_or_default();
    json!({"native_plan": plan.plan.display_indent().to_string(),
        "read_revision": captured.meta.commit_revision,
        "store_uuid": captured.meta.store_uuid.to_string(), "recovery_epoch": captured.meta.recovery_epoch,
        "evaluated_utc_ns": update.evaluated_utc_ns, "scanned_bytes": captured.scanned_bytes,
        "input_rows": event_inputs(update),
        "input_bytes": captured.input_bytes,
        "output_bytes": batches.iter().map(RecordBatch::get_array_memory_size).sum::<usize>(),
        "returned_rows": batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        "columns": plan.plan.schema().fields().iter().map(|field| field.name()).collect::<Vec<_>>(),
        "types": plan.plan.schema().fields().iter().map(|field| format!("{:?}", field.data_type())).collect::<Vec<_>>(),
        "rows": rows(update).map(|rows| rows.iter().map(|row| row.iter().map(|value| format!("{value:?}")).collect::<Vec<_>>()).collect::<Vec<_>>()).unwrap_or_else(|error| vec![vec![format!("Arrow receipt failed: {error}")]]),
        "limited": update.limited, "exhausted": update.exhausted,
        "coverage": captured.sources.iter().map(|source| json!({"source": source.receipt.identity,
            "ack": source.receipt.contiguous_cursor, "pending": source.pending,
            "expired": source.expired, "recovery": source.recovery})).collect::<Vec<_>>()})
}

fn snapshot_receipt(snapshot: &(Arc<ArrowSnapshot>, Vec<RecordBatch>)) -> serde_json::Value {
    json!({"read_revision": snapshot.0.page.extraction.meta.commit_revision,
        "rows": batch_rows(&snapshot.1).map(|rows| format!("{rows:?}")).unwrap_or_else(|error| error.to_string())})
}

fn cycle_receipt(plan: &Prepared, cycle: &Cycle) -> serde_json::Value {
    json!({"updates": cycle.results.iter().map(|result| result_receipt(plan, result)).collect::<Vec<_>>(),
        "cursor": cycle.cursor, "clock_changed": cycle.clock_changed})
}

fn limits_receipt(limits: &Limits) -> serde_json::Value {
    json!({"scan_bytes": limits.scan_bytes, "input_bytes": limits.input_bytes, "output_rows": limits.output_rows,
        "output_bytes": limits.output_bytes, "extract_timeout_ms": limits.extract_timeout.as_millis(),
        "evaluate_timeout_ms": limits.evaluate_timeout.as_millis(), "global_evaluations": limits.global_evaluations,
        "tenant_evaluations": limits.tenant_evaluations, "global_streams": limits.global_streams,
        "tenant_streams": limits.tenant_streams, "input_capacity": limits.input_capacity,
        "output_capacity": limits.output_capacity, "replace_interval_ms": 500,
        "heartbeat_ms": 15000})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_follow_contract() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        let runner = QueryFollowQualification::new(output.clone());
        runner.run().await?;
        let before = fs::read(output.join("result.json"))?;
        let result: serde_json::Value = serde_json::from_slice(&before)?;
        assert_eq!(result["case"], "query-follow");
        assert_eq!(result["result"], "PASS");
        assert_eq!(result["cases"].as_array().ok_or("cases absent")?.len(), 8);
        assert!(runner.run().await.is_err());
        assert_eq!(fs::read(output.join("result.json"))?, before);
        Ok(())
    }
}
