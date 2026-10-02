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
    AnalysisResultCommitV1, AnalysisSelectionV1, AnalysisStore, AnalysisWitnessV1,
    EvidenceDecisionContext, EvidenceIntakeIdentityV1, EvidenceRecord, EvidenceRetentionOwner,
    EvidenceStoreOutcomeV1, ProcessorClassV1, ProcessorScopeV1, QueryCheckpoint, QueryClock,
    QueryCoverageState, QueryErrorCode, QueryFrame, QueryLimits, QueryOperation, QueryOwner,
    QueryPayload, QueryPlan, QueryResult, QueryStream, QueryTemplate, QueryTerminalReason,
    ValidatedEvidenceBatchV1, QUERY_SCHEMA_VERSION,
};
use duckdb::types::{TimeUnit, Value};
use mithril_control::ControlStore;
use prost::Message as _;
use serde_json::json;
use tokio::sync::watch;

use crate::control_fixture::{OutagePolicyFixture, OUTAGE_NAMESPACE_UID};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MINUTE: u64 = 60_000_000_000;

struct Clock {
    now: AtomicU64,
    changes: watch::Sender<()>,
}

impl Clock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            changes: watch::channel(()).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_replace(());
    }
}

impl QueryClock for Clock {
    fn now_ns(&self) -> araphor_data::Result<u64> {
        Ok(self.now.load(Ordering::SeqCst))
    }

    fn changes(&self) -> Option<watch::Receiver<()>> {
        Some(self.changes.subscribe())
    }
}

struct GateClock {
    gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    now: AtomicU64,
    reads: AtomicU64,
    pause: u64,
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
            }),
            entering,
            release,
        )
    }
}

impl QueryClock for GateClock {
    fn now_ns(&self) -> araphor_data::Result<u64> {
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
            let invalid = || araphor_data::Error::QueryInvalid {
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
}

struct Cycle {
    results: Vec<QueryResult>,
    checkpoint: QueryCheckpoint,
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
                .map_err(|error| format!("query-follow bounded window: {error}"))?,
            self.retention(&directory.path().join("retention"))
                .await
                .map_err(|error| format!("query-follow retention: {error}"))?,
            self.policy_continuity(&directory.path().join("policy"))
                .await
                .map_err(|error| format!("query-follow policy continuity: {error}"))?,
            self.snapshot_and_coalescing(&directory.path().join("snapshot"))
                .await
                .map_err(|error| format!("query-follow snapshot and coalescing: {error}"))?,
            self.blocked_output(&directory.path().join("blocked"))
                .await
                .map_err(|error| format!("query-follow blocked output: {error}"))?,
        ];
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &json!({
                "schema_version": 1,
                "case": "query-follow",
                "result": "PASS",
                "query_schema_version": QUERY_SCHEMA_VERSION,
                "production_owners": ["AnalysisStore", "QueryOwner", "EvidenceRetentionOwner", "ControlStore", "PolicyDesiredStateOwner"],
                "cases": cases,
                "limits": limits_receipt(&QueryLimits::default()),
                "input_rows_meaning": "Admitted event and context rows before generated coverage and catalog rows.",
                "input_bytes_meaning": "Complete admitted allocation, including generated relations.",
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
        let owner = Arc::new(QueryOwner::new(
            store.clone(),
            QueryLimits {
                output_rows: 4,
                ..Default::default()
            },
        )?);
        let clock = Clock::new(100 * MINUTE);
        let plan = query_plan(&source, QueryTemplate::Events { operation: None })?;
        self.check(
            commit(&store, &source, 11, MINUTE, records(11, 10, 7))?
                == EvidenceStoreOutcomeV1::Pending,
            "pending evidence advanced its ACK",
        )?;
        let mut stream = owner.follow_clock(plan.clone(), None, clock.clone())?;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Append)
            .await?;
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
            .sources;
        self.check(
            coverage.len() == 1
                && coverage[0].receipt.contiguous_cursor == 0
                && coverage[0].state == QueryCoverageState::Gapped
                && coverage[0].pending.len() == 1
                && coverage[0].pending[0].first_cursor == 1
                && coverage[0].pending[0].last_cursor == 10,
            "pending source coverage differs",
        )?;
        commit(&store, &source, 1, 2 * MINUTE, records(1, 10, 7))?;
        let repaired = self
            .cycle(&mut stream, false, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&repaired)? == (1..=10).collect::<Vec<_>>(),
            "gap repair duplicated rows",
        )?;
        let coverage = &repaired
            .results
            .last()
            .ok_or("repair result absent")?
            .sources;
        self.check(
            coverage[0].receipt.contiguous_cursor == 20 && coverage[0].pending.is_empty(),
            "gap repair did not correct ACK and coverage",
        )?;
        let mut replay = owner.follow_clock(
            plan.clone(),
            Some(initial.checkpoint.clone()),
            clock.clone(),
        )?;
        let replayed = self
            .cycle(&mut replay, true, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&replayed)? == (1..=10).collect::<Vec<_>>(),
            "checkpoint replay differs",
        )?;
        self.cancel(&mut replay, QueryOperation::Append).await?;
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
            QueryPlan::new(
                AnalysisSelectionV1::new(source.tenant_id, vec![foreign]),
                QueryTemplate::Events { operation: None },
            )
            .is_err(),
            "cross-tenant source selection was accepted",
        )?;
        let unrelated_revision = store.meta()?.commit_revision;
        clock.set(100 * MINUTE + 1);
        self.health(&mut stream, QueryOperation::Append, unrelated_revision)
            .await?;
        commit(&store, &source, 21, 4 * MINUTE, records(21, 1, 7))?;
        commit(&store, &source, 22, 4 * MINUTE, records(22, 1, 7))?;
        let mut appended = Vec::new();
        let mut notices = Vec::new();
        while appended.len() < 2 {
            let cycle = self
                .cycle(&mut stream, false, QueryOperation::Append)
                .await?;
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
        self.cancel(&mut stream, QueryOperation::Append).await?;
        commit(&store, &source, 23, 5 * MINUTE, records(23, 1, 7))?;
        self.check(
            store
                .source_receipt(&source)?
                .ok_or("source absent")?
                .contiguous_cursor
                == 23,
            "cancelled follow blocked subsequent intake",
        )?;
        let empty = query_plan(
            &source,
            QueryTemplate::Events {
                operation: Some(99),
            },
        )?;
        let mut empty_stream = owner.follow_clock(empty.clone(), None, clock)?;
        let empty_cycle = self
            .cycle(&mut empty_stream, true, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&empty_cycle)?.is_empty(),
            "empty filter returned rows",
        )?;
        self.check(
            empty_cycle.checkpoint.position().is_some(),
            "empty filter has no scan checkpoint",
        )?;
        self.cancel(&mut empty_stream, QueryOperation::Append)
            .await?;
        Ok(json!({
            "name": "pending-replay-and-scope", "result": "PASS", "output_rows_limit": 4,
            "initial": cycle_receipt(&plan, &initial), "repair": cycle_receipt(&plan, &repaired),
            "replay": cycle_receipt(&plan, &replayed), "later_commits": notices,
            "empty_filter": cycle_receipt(&empty, &empty_cycle),
            "unrelated_revision": unrelated_revision, "final_ack": 23,
            "cancellation": "Terminal(Cancelled), then closed"
        }))
    }

    async fn counts(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let plan = query_plan(&source, QueryTemplate::OperationCounts)?;
        let clock = Clock::new(100 * MINUTE);
        let mut input = records(1, 2, 7);
        input.extend(records(3, 1, 8));
        commit(&store, &source, 1, MINUTE, input)?;
        let mut stream = owner.follow_clock(plan.clone(), None, clock)?;
        let first = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &plan,
            &first,
            &[
                vec![Value::UInt(7), Value::BigInt(2)],
                vec![Value::UInt(8), Value::BigInt(1)],
            ],
        )?;
        commit(&store, &source, 4, 2 * MINUTE, records(4, 2, 7))?;
        let second = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &plan,
            &second,
            &[
                vec![Value::UInt(7), Value::BigInt(4)],
                vec![Value::UInt(8), Value::BigInt(1)],
            ],
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
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
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let clock = Clock::new(608 * MINUTE);
        let moving = query_plan(&source, QueryTemplate::MovingCount { seconds: 300 })?;
        let mut stream = owner.follow_clock(moving.clone(), None, clock.clone())?;
        let first = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &moving, &first, &[vec![Value::BigInt(2)]])?;
        let before = store.meta()?;
        clock.set(610 * MINUTE);
        let quiet = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &moving, &quiet, &[vec![Value::BigInt(1)]])?;
        self.check(
            store.meta()? == before && quiet.clock_changed,
            "quiet expiry changed storage or hid its clock change",
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.received_from = Bound::Included(600 * MINUTE);
        selection.received_until = Bound::Excluded(610 * MINUTE);
        let fixed = QueryPlan::new(selection, QueryTemplate::FixedBuckets { seconds: 300 })?;
        let mut stream = owner.follow_clock(fixed.clone(), None, clock.clone())?;
        let buckets = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &fixed, &buckets, &[bucket(600, 2), bucket(605, 1)])?;
        commit(&store, &source, 4, 605 * MINUTE, records(4, 1, 7))?;
        let boundary = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &fixed, &boundary, &[bucket(600, 2), bucket(605, 2)])?;
        let mut late = records(5, 1, 7);
        late[0].ingested_utc_ns = (604 * MINUTE) as i64;
        late[0].observed_boottime_ns = 123;
        commit(&store, &source, 5, 620 * MINUTE, late)?;
        let late_revision = store.meta()?.commit_revision;
        clock.set(620 * MINUTE);
        self.health(&mut stream, QueryOperation::Replace, late_revision)
            .await?;
        self.check(
            owner.query_at(&fixed, 620 * MINUTE)?.rows == [bucket(600, 2), bucket(605, 2)],
            "late input changed fixed input bounds",
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        let all = query_plan(&source, QueryTemplate::FixedBuckets { seconds: 300 })?;
        let mut stream = owner.follow_clock(all.clone(), None, clock)?;
        let late_buckets = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &all,
            &late_buckets,
            &[bucket(600, 2), bucket(605, 2), bucket(620, 1)],
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        let event_plan = query_plan(&source, QueryTemplate::Events { operation: None })?;
        let events = owner.query_at(&event_plan, 620 * MINUTE)?;
        let row = events.rows.last().ok_or("late row absent")?;
        self.check(
            row[column(&events, "received_utc_ns")?] == Value::UBigInt(620 * MINUTE)
                && row[column(&events, "ingested_utc_ns")?] == Value::BigInt((604 * MINUTE) as i64)
                && row[column(&events, "observed_boottime_ns")?] == Value::UBigInt(123),
            "late input lost its intake or source clock domain",
        )?;
        Ok(json!({"name": "moving-and-fixed-windows", "result": "PASS",
            "timer_only": timer,
            "at_1008": cycle_receipt(&moving, &first), "quiet_1010": cycle_receipt(&moving, &quiet),
            "fixed": cycle_receipt(&fixed, &buckets), "boundary_1005": cycle_receipt(&fixed, &boundary),
            "late_1020": cycle_receipt(&all, &late_buckets), "source_times": result_receipt(&event_plan, &events)}))
    }

    async fn timer_expiry(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, 2_000_000_000, records(1, 1, 7))?;
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let plan = query_plan(&source, QueryTemplate::MovingCount { seconds: 1 })?;
        let (clock, sampled, release) = GateClock::on_read(3_000_000_000, 1);
        let advancing = clock.clone();
        let advance = tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            sampled
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            advancing.now.store(4_000_000_000, Ordering::SeqCst);
            release.send(()).map_err(|error| error.to_string())
        });
        let mut stream = owner.follow_clock(plan.clone(), None, clock)?;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &plan, &initial, &[vec![Value::BigInt(1)]])?;
        let before = store.meta()?;
        advance.await??;
        let expired = tokio::time::timeout(
            Duration::from_secs(5),
            self.cycle(&mut stream, false, QueryOperation::Replace),
        )
        .await??;
        self.replacement(&owner, &plan, &expired, &[vec![Value::BigInt(0)]])?;
        self.check(
            store.meta()? == before
                && expired.checkpoint.read_revision() == initial.checkpoint.read_revision(),
            "timer-only expiry changed the store revision",
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        Ok(json!({"initial": cycle_receipt(&plan, &initial),
            "expired": cycle_receipt(&plan, &expired), "clock_notifications": false,
            "store_unchanged": true, "deadline_ms": 5000, "heartbeat_ms": 15000}))
    }

    async fn bounded_window(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let limits = QueryLimits {
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
        let owner = Arc::new(QueryOwner::new(store.clone(), limits.clone())?);
        let moving = query_plan(&source, QueryTemplate::MovingCount { seconds: 300 })?;
        let all = query_plan(&source, QueryTemplate::OperationCounts)?;
        self.check(
            matches!(
                owner.query_at(&all, 608 * MINUTE),
                Err(araphor_data::Error::AnalysisInputTooLarge { .. })
            ),
            "over-budget complete input was accepted",
        )?;
        let mut stream = owner.follow_clock(moving.clone(), None, Clock::new(608 * MINUTE))?;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &moving, &initial, &[vec![Value::BigInt(2)]])?;
        self.check(
            initial.results[0].input_rows == 2
                && initial.results[0].scanned_bytes <= limits.scan_bytes,
            "time selection extracted unrelated history",
        )?;
        commit(&store, &source, 67, 608 * MINUTE, records(67, 1, 7))?;
        let added = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.replacement(&owner, &moving, &added, &[vec![Value::BigInt(3)]])?;
        self.check(
            added.results[0].input_rows == 3,
            "replacement omitted matching input",
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        let output_owner = Arc::new(QueryOwner::new(
            store.clone(),
            QueryLimits {
                output_rows: 1,
                ..limits.clone()
            },
        )?);
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.received_from = Bound::Included(603 * MINUTE);
        let counts = QueryPlan::new(selection, QueryTemplate::OperationCounts)?;
        let mut output_stream =
            output_owner.follow_clock(counts.clone(), None, Clock::new(608 * MINUTE))?;
        let output_before = self
            .cycle(&mut output_stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &output_owner,
            &counts,
            &output_before,
            &[vec![Value::UInt(7), Value::BigInt(3)]],
        )?;
        commit(&store, &source, 68, 608 * MINUTE, records(68, 1, 8))?;
        let output_error = self
            .stream_error(
                &mut output_stream,
                QueryOperation::Replace,
                &output_before.checkpoint,
                QueryErrorCode::ResultTooLarge,
            )
            .await?;
        self.check(
            matches!(
                output_owner.query_at(&counts, 608 * MINUTE),
                Err(araphor_data::Error::QueryLimit { .. })
            ),
            "over-budget replacement returned a partial aggregate",
        )?;
        commit(&store, &source, 69, 608 * MINUTE, records(69, 1, 7))?;
        let recovered = output_owner.query_at(&moving, 608 * MINUTE)?;
        self.check(
            recovered.rows == [vec![Value::BigInt(5)]],
            "failed evaluation blocked later reads or intake",
        )?;
        let mut input_stream =
            owner.follow_clock(counts.clone(), None, Clock::new(608 * MINUTE))?;
        let input_before = self
            .cycle(&mut input_stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &counts,
            &input_before,
            &[
                vec![Value::UInt(7), Value::BigInt(4)],
                vec![Value::UInt(8), Value::BigInt(1)],
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
                QueryOperation::Replace,
                &input_before.checkpoint,
                QueryErrorCode::InputTooLarge,
            )
            .await?;
        commit(&store, &source, 71, 620 * MINUTE, records(71, 1, 7))?;
        let subsequent = owner.query_at(&moving, 620 * MINUTE)?;
        self.check(
            subsequent.rows == [vec![Value::BigInt(1)]],
            "input overflow blocked later intake or a bounded query",
        )?;
        Ok(
            json!({"name": "bounded-window-and-recovery", "result": "PASS", "limits": limits_receipt(&limits),
            "historical_frame_bytes": history_bytes, "initial": cycle_receipt(&moving, &initial),
            "replacement": cycle_receipt(&moving, &added), "after_error": result_receipt(&moving, &recovered),
            "output_before": cycle_receipt(&counts, &output_before), "output_error": output_error,
            "input_before": cycle_receipt(&counts, &input_before), "input_error": input_error,
            "after_input_error": result_receipt(&moving, &subsequent)}),
        )
    }

    async fn retention(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        let expires = 3 * 24 * 60 * MINUTE;
        let now = expires - 1;
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let witness_position = store.read_page(&source, 1)?.records[0].position;
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let plan = query_plan(&source, QueryTemplate::Events { operation: None })?;
        let mut stream = owner.follow_clock(plan.clone(), None, Clock::new(now))?;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Append)
            .await?;
        self.check(cursors(&initial)? == [1], "initial witness row differs")?;
        self.cancel(&mut stream, QueryOperation::Append).await?;
        drop(stream);
        store.backup(&root.join("backups/sealed"))?;
        commit(&store, &source, 2, 2 * MINUTE, records(2, 2, 7))?;
        let floor = store.read_page(&source, 3)?.records[0].position;
        let counts = query_plan(&source, QueryTemplate::OperationCounts)?;
        let mut stream = owner.follow_clock(counts.clone(), None, Clock::new(now))?;
        let before = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &counts,
            &before,
            &[vec![Value::UInt(7), Value::BigInt(3)]],
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
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
                identity: source.clone(),
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
                && initial
                    .checkpoint
                    .position()
                    .is_some_and(|position| position < floor),
            "retention did not persist the expected raw replay floor",
        )?;
        let expired = self
            .follow_error(
                &owner,
                &plan,
                &initial.checkpoint,
                now,
                QueryErrorCode::CursorExpired,
            )
            .await?;
        let witness = self.witness_query(&owner, &plan, now)?;
        let mut stream = owner.follow_clock(
            counts.clone(),
            Some(before.checkpoint.clone()),
            Clock::new(now),
        )?;
        let replacement = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &counts,
            &replacement,
            &[vec![Value::UInt(7), Value::BigInt(1)]],
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
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
        let owner = Arc::new(QueryOwner::new(reopened.clone(), QueryLimits::default())?);
        let restart_error = self
            .follow_error(
                &owner,
                &plan,
                &initial.checkpoint,
                now,
                QueryErrorCode::CursorExpired,
            )
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
        let restored_owner = Arc::new(QueryOwner::new(restored, QueryLimits::default())?);
        let restore_error = self
            .follow_error(
                &restored_owner,
                &plan,
                &initial.checkpoint,
                now,
                QueryErrorCode::InvalidCheckpoint,
            )
            .await?;
        let restore_witness = self.witness_query(&restored_owner, &plan, now)?;
        let mut stream = restored_owner.follow_clock(plan.clone(), None, Clock::new(now))?;
        let fresh = self
            .cycle(&mut stream, true, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&fresh)? == [1],
            "fresh restored follow lost its retained witness",
        )?;
        self.cancel(&mut stream, QueryOperation::Append).await?;
        Ok(json!({
            "name": "retention-restart-restore-and-witness", "result": "PASS",
            "initial": cycle_receipt(&plan, &initial), "replay_floor": floor,
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
        owner: &QueryOwner,
        plan: &QueryPlan,
        now: u64,
    ) -> Result<serde_json::Value> {
        let result = owner.query_at(plan, now)?;
        self.check(
            result.rows.len() == 1
                && result.rows[0][column(&result, "source_cursor")?] == Value::UBigInt(1)
                && result.sources.len() == 1
                && result.sources[0].receipt.contiguous_cursor == 3
                && result.sources[0].state == QueryCoverageState::Gapped
                && result.sources[0].expired.len() == 1
                && result.sources[0].expired[0].first_cursor == 2
                && result.sources[0].expired[0].last_cursor == 3,
            "retained witness or explicit expired coverage differs",
        )?;
        Ok(result_receipt(plan, &result))
    }

    async fn follow_error(
        &self,
        owner: &Arc<QueryOwner>,
        plan: &QueryPlan,
        checkpoint: &QueryCheckpoint,
        now: u64,
        expected: QueryErrorCode,
    ) -> Result<serde_json::Value> {
        let mut stream =
            owner.follow_clock(plan.clone(), Some(checkpoint.clone()), Clock::new(now))?;
        self.stream_error(&mut stream, plan.operation(), checkpoint, expected)
            .await
    }

    async fn stream_error(
        &self,
        stream: &mut QueryStream,
        operation: QueryOperation,
        checkpoint: &QueryCheckpoint,
        expected: QueryErrorCode,
    ) -> Result<serde_json::Value> {
        let frame = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let frame = self.next(stream, operation).await?;
                if !matches!(frame.payload, QueryPayload::Health { .. }) {
                    return Result::<QueryFrame>::Ok(frame);
                }
            }
        })
        .await??;
        self.check(
            matches!(&frame.payload, QueryPayload::Error { code, last_checkpoint, .. }
                if *code == expected && last_checkpoint.as_ref() == Some(checkpoint)),
            "query failure did not preserve its checkpoint or emitted a partial result",
        )?;
        self.check(
            tokio::time::timeout(Duration::from_secs(10), stream.next())
                .await?
                .is_none(),
            "failed query stream did not close",
        )?;
        Ok(
            json!({"code": format!("{expected:?}"), "read_revision": frame.read_revision,
            "store_uuid": frame.store_uuid, "recovery_epoch": frame.recovery_epoch,
            "checkpoint": checkpoint, "stream_closed": true}),
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
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let plan = query_plan(&source, QueryTemplate::OperationCounts)?;
        let mut stream = owner.follow_clock(plan.clone(), None, Clock::new(2 * MINUTE))?;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &plan,
            &initial,
            &[vec![Value::UInt(7), Value::BigInt(1)]],
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
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
        let subsequent = owner.query_at(&plan, 2 * MINUTE)?;
        self.check(
            subsequent.rows == [vec![Value::UInt(7), Value::BigInt(2)]],
            "query cancellation blocked subsequent intake or reads",
        )?;
        Ok(
            json!({"name": "cancellation-policy-and-intake", "result": "PASS",
            "initial": cycle_receipt(&plan, &initial), "subsequent": result_receipt(&plan, &subsequent),
            "cancellation": "Terminal(Cancelled), then closed",
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
        let owner = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
        let plan = query_plan(&source, QueryTemplate::Events { operation: None })?;
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
        let mut stream = owner.follow_clock(plan.clone(), None, clock)?;
        let captured = tokio::time::timeout(Duration::from_secs(10), writer).await???;
        let initial = self
            .cycle(&mut stream, true, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&initial)? == [1, 2, 3]
                && initial.results.len() == 1
                && initial.results[0].meta.commit_revision == captured
                && initial.results[0].sources[0].receipt.contiguous_cursor == 3,
            "initial snapshot lost or duplicated commits made inside its clock barrier",
        )?;
        self.cancel(&mut stream, QueryOperation::Append).await?;
        let counts = query_plan(&source, QueryTemplate::OperationCounts)?;
        let mut stream = owner.follow_clock(counts.clone(), None, Clock::new(now))?;
        let metadata = self.next(&mut stream, QueryOperation::Replace).await?;
        self.check(
            matches!(metadata.payload, QueryPayload::Metadata(_))
                && metadata.read_revision == captured,
            "coalesced query did not capture its initial metadata",
        )?;
        drop(metadata);
        let baseline = owner.query_at(&counts, now)?;
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
        let before = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.check(
            before.results.len() == 1
                && before.results[0].meta == baseline.meta
                && before.results[0].columns == baseline.columns
                && before.results[0].rows == baseline.rows
                && baseline.rows == [vec![Value::UInt(7), Value::BigInt(3)]],
            "blocked initial output changed after later commits",
        )?;
        let after = self
            .cycle(&mut stream, false, QueryOperation::Replace)
            .await?;
        self.replacement(
            &owner,
            &counts,
            &after,
            &[
                vec![Value::UInt(7), Value::BigInt(5)],
                vec![Value::UInt(9), Value::BigInt(1)],
            ],
        )?;
        self.check(
            after.results[0].meta.commit_revision == coalesced_revision,
            "coalesced wake did not include the complete commit batch",
        )?;
        self.cancel(&mut stream, QueryOperation::Replace).await?;
        Ok(
            json!({"name": "initial-snapshot-and-coalesced-wake", "result": "PASS",
            "barrier": "Two commits complete after follow registration and before the first query snapshot.",
            "initial": cycle_receipt(&plan, &initial), "captured_revision": captured,
            "coalesced_commits": 3, "coalesced_revision": coalesced_revision,
            "before": cycle_receipt(&counts, &before), "after": cycle_receipt(&counts, &after)}),
        )
    }

    async fn blocked_output(&self, root: &Path) -> Result<serde_json::Value> {
        let store = Arc::new(AnalysisStore::open(root)?);
        let source = evidence_source(1, 3);
        commit(&store, &source, 1, MINUTE, records(1, 1, 7))?;
        let limits = QueryLimits {
            global_streams: 1,
            tenant_streams: 1,
            output_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let owner = Arc::new(QueryOwner::new(store.clone(), limits.clone())?);
        let plan = query_plan(&source, QueryTemplate::Events { operation: None })?;
        let mut stream = owner.follow_clock(plan.clone(), None, Clock::new(2 * MINUTE))?;
        self.check(
            matches!(
                owner.follow_clock(plan.clone(), None, Clock::new(2 * MINUTE)),
                Err(araphor_data::Error::AnalysisBusy { .. })
            ),
            "active blocked stream did not consume its admission slot",
        )?;
        let running = Arc::downgrade(&owner);
        drop(owner);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if running.upgrade().is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
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
            "blocked output retained a raw segment lease",
        )?;
        let metadata = self.next(&mut stream, QueryOperation::Append).await?;
        self.check(
            matches!(metadata.payload, QueryPayload::Metadata(_)) && metadata.read_revision == 1,
            "blocked query did not leave only its initial metadata queued",
        )?;
        drop(metadata);
        self.check(
            tokio::time::timeout(Duration::from_secs(10), stream.next())
                .await?
                .is_none(),
            "output-timeout stream did not close after its queued metadata",
        )?;
        commit(&store, &source, 2, 2 * MINUTE, records(2, 1, 7))?;
        let owner = Arc::new(QueryOwner::new(store, limits.clone())?);
        let mut recovered = owner.follow_clock(plan.clone(), None, Clock::new(3 * MINUTE))?;
        let subsequent = self
            .cycle(&mut recovered, true, QueryOperation::Append)
            .await?;
        self.check(
            cursors(&subsequent)? == [2],
            "output timeout blocked later intake or follow",
        )?;
        self.cancel(&mut recovered, QueryOperation::Append).await?;
        Ok(json!({"name": "blocked-output-cleanup", "result": "PASS",
            "limits": limits_receipt(&limits), "worker_released_before_drain": true,
            "retention_removed_before_drain": retained.removed_records,
            "drained_frames": ["Metadata"], "then_closed": true,
            "last_complete_checkpoint": null,
            "terminal_frame": "The full output queue cannot accept a terminal frame.",
            "subsequent": cycle_receipt(&plan, &subsequent)}))
    }

    async fn next(
        &self,
        stream: &mut QueryStream,
        operation: QueryOperation,
    ) -> Result<QueryFrame> {
        let frame = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await?
            .ok_or("query stream closed before its expected frame")?;
        self.check(
            frame.schema_version == QUERY_SCHEMA_VERSION
                && frame.operation == operation
                && frame.store_uuid != [0; 16]
                && frame.recovery_epoch > 0
                && frame.frame_id != [0; 32],
            "query frame header is invalid",
        )?;
        Ok(frame)
    }

    async fn cycle(
        &self,
        stream: &mut QueryStream,
        initial: bool,
        operation: QueryOperation,
    ) -> Result<Cycle> {
        if initial {
            let frame = self.next(stream, operation).await?;
            let QueryPayload::Metadata(metadata) = frame.payload else {
                return Err(format!(
                    "expected initial query metadata, received {:?}",
                    frame.payload
                )
                .into());
            };
            self.check(
                !metadata.columns.is_empty(),
                "initial metadata has no columns",
            )?;
        }
        let mut results = Vec::new();
        let mut clock_changed = false;
        for _ in 0..32 {
            let frame = self.next(stream, operation).await?;
            clock_changed |= frame.clock_changed;
            let result = match frame.payload {
                QueryPayload::Append { result, .. } if operation == QueryOperation::Append => {
                    result
                }
                QueryPayload::Replace { result, .. } if operation == QueryOperation::Replace => {
                    result
                }
                QueryPayload::Health { .. } => continue,
                payload => return Err(format!("unexpected query data frame: {payload:?}").into()),
            };
            self.check(
                result.meta.commit_revision == frame.read_revision,
                "result frame revision differs",
            )?;
            let exhausted = result.exhausted;
            let next = self.next(stream, operation).await?;
            let coverage_matches = next.coverage() == &result.sources[..];
            let QueryPayload::Checkpoint { checkpoint, .. } = next.payload else {
                return Err("query data has no following checkpoint".into());
            };
            self.check(
                checkpoint.read_revision() == result.meta.commit_revision
                    && next.read_revision == result.meta.commit_revision
                    && coverage_matches,
                "checkpoint differs from its result",
            )?;
            let encoded = checkpoint.encode()?;
            self.check(
                QueryCheckpoint::try_from(encoded.as_slice())? == checkpoint,
                "checkpoint encoding differs",
            )?;
            results.push(result);
            if exhausted || operation == QueryOperation::Replace {
                return Ok(Cycle {
                    results,
                    checkpoint,
                    clock_changed,
                });
            }
        }
        Err("query cycle did not finish within its frame bound".into())
    }

    async fn health(
        &self,
        stream: &mut QueryStream,
        operation: QueryOperation,
        revision: u64,
    ) -> Result<()> {
        let frame = self.next(stream, operation).await?;
        self.check(
            matches!(frame.payload, QueryPayload::Health { .. })
                && frame.clock_changed
                && frame.read_revision == revision,
            "unrelated commit reran the query or lost its clock health frame",
        )
    }

    async fn cancel(&self, stream: &mut QueryStream, operation: QueryOperation) -> Result<()> {
        stream.cancel()?;
        for _ in 0..4 {
            match self.next(stream, operation).await?.payload {
                QueryPayload::Health { .. } => {}
                QueryPayload::Terminal {
                    reason: QueryTerminalReason::Cancelled,
                    ..
                } => {
                    return self.check(
                        tokio::time::timeout(Duration::from_secs(10), stream.next())
                            .await?
                            .is_none(),
                        "cancelled stream did not close",
                    );
                }
                payload => return Err(format!("unexpected cancellation frame: {payload:?}").into()),
            }
        }
        Err("query cancellation has no terminal frame".into())
    }

    fn replacement(
        &self,
        owner: &QueryOwner,
        plan: &QueryPlan,
        cycle: &Cycle,
        expected: &[Vec<Value>],
    ) -> Result<()> {
        self.check(
            cycle.results.len() == 1,
            "replacement was split across data frames",
        )?;
        let result = &cycle.results[0];
        let normal = owner.query_at(plan, result.evaluated_utc_ns)?;
        self.check(
            !result.limited
                && result.rows == expected
                && result.rows == normal.rows
                && result.columns == normal.columns
                && result.meta == normal.meta,
            "replacement differs from a complete query at the same revision and instant",
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

fn query_plan(
    source: &EvidenceIntakeIdentityV1,
    template: QueryTemplate,
) -> araphor_data::Result<QueryPlan> {
    QueryPlan::new(
        AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]),
        template,
    )
}

fn column(result: &QueryResult, name: &str) -> Result<usize> {
    result
        .columns
        .iter()
        .position(|column| column == name)
        .ok_or_else(|| format!("query column {name} is absent").into())
}

fn cursors(cycle: &Cycle) -> Result<Vec<u64>> {
    let mut values = Vec::new();
    for result in &cycle.results {
        let index = column(result, "source_cursor")?;
        for row in &result.rows {
            let Value::UBigInt(cursor) = &row[index] else {
                return Err("source cursor is not UBIGINT".into());
            };
            values.push(*cursor);
        }
    }
    Ok(values)
}

fn bucket(minute: u64, count: i64) -> Vec<Value> {
    vec![
        Value::Timestamp(TimeUnit::Microsecond, (minute * MINUTE / 1_000) as i64),
        Value::BigInt(count),
    ]
}

fn result_receipt(plan: &QueryPlan, result: &QueryResult) -> serde_json::Value {
    json!({"template": format!("{:?}", plan.template()), "read_revision": result.meta.commit_revision,
        "store_uuid": result.meta.store_uuid.to_string(), "recovery_epoch": result.meta.recovery_epoch,
        "evaluated_utc_ns": result.evaluated_utc_ns, "scanned_bytes": result.scanned_bytes,
        "input_rows": result.input_rows, "input_bytes": result.input_bytes, "output_bytes": result.output_bytes,
        "returned_rows": result.rows.len(), "columns": result.columns, "types": result.types,
        "rows": result.rows.iter().map(|row| row.iter().map(|value| format!("{value:?}")).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "limited": result.limited, "exhausted": result.exhausted,
        "coverage": result.sources.iter().map(|source| json!({"source": source.receipt.identity,
            "ack": source.receipt.contiguous_cursor, "state": format!("{:?}", source.state),
            "pending": source.pending, "expired": source.expired, "recovery": source.recovery})).collect::<Vec<_>>()})
}

fn cycle_receipt(plan: &QueryPlan, cycle: &Cycle) -> serde_json::Value {
    json!({"results": cycle.results.iter().map(|result| result_receipt(plan, result)).collect::<Vec<_>>(),
        "checkpoint": cycle.checkpoint, "clock_changed": cycle.clock_changed})
}

fn limits_receipt(limits: &QueryLimits) -> serde_json::Value {
    json!({"scan_bytes": limits.scan_bytes, "input_bytes": limits.input_bytes, "output_rows": limits.output_rows,
        "output_bytes": limits.output_bytes, "extract_timeout_ms": limits.extract_timeout.as_millis(),
        "evaluate_timeout_ms": limits.evaluate_timeout.as_millis(), "global_evaluations": limits.global_evaluations,
        "tenant_evaluations": limits.tenant_evaluations, "global_streams": limits.global_streams,
        "tenant_streams": limits.tenant_streams, "input_capacity": limits.input_capacity,
        "output_capacity": limits.output_capacity, "replace_interval_ms": limits.replace_interval.as_millis(),
        "heartbeat_ms": limits.heartbeat.as_millis(), "output_timeout_ms": limits.output_timeout.as_millis()})
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
