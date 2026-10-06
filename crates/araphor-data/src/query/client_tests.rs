use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use duckdb::types::{TimeUnit, Value};
use futures_core::stream::FusedStream;
use futures_util::StreamExt;
use tokio::sync::{oneshot, watch};

use super::tests::QueryFixture;
use super::{
    QueryAuthorization, QueryCheckpoint, QueryClock, QueryErrorCode, QueryFrame, QueryGrant,
    QueryLimits, QueryOperation, QueryOwner, QueryPayload, QueryPlan, QueryResult, QuerySql,
    QueryStream, QueryTerminalReason,
};
use crate::{AnalysisReadControl, AnalysisSelectionV1, EvidenceRecord, Result, StorePositionV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ClockGate = (oneshot::Sender<()>, mpsc::Receiver<()>);
const WAIT: Duration = Duration::from_secs(5);

struct Clock {
    now: Arc<AtomicU64>,
    reads: AtomicUsize,
    gate: Mutex<Option<ClockGate>>,
}

impl Clock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
            reads: AtomicUsize::new(0),
            gate: Mutex::new(None),
        }
    }

    fn arm(&self) -> TestResult<(oneshot::Receiver<()>, mpsc::Sender<()>)> {
        let (entered, entering) = oneshot::channel();
        let (release, released) = mpsc::channel();
        *self.gate.lock().map_err(|_| "clock gate lock failed")? = Some((entered, released));
        Ok((entering, release))
    }
}

impl QueryClock for Clock {
    fn now_ns(&self) -> Result<u64> {
        let now = self.now.load(Ordering::SeqCst);
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            let gate = self
                .gate
                .lock()
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test clock",
                    }
                    .build()
                })?
                .take();
            if let Some((entered, released)) = gate {
                let _entered = entered.send(());
                released.recv_timeout(WAIT).map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test clock gate",
                    }
                    .build()
                })?;
            }
        }
        Ok(now)
    }
}

struct Authority {
    grant: QueryGrant,
    now: Arc<AtomicU64>,
    changes: watch::Sender<u64>,
    until: u64,
}

impl Authority {
    fn new(grant: QueryGrant, now: Arc<AtomicU64>) -> Self {
        let (changes, _) = watch::channel(grant.revision);
        Self {
            grant,
            now,
            changes,
            until: 10_000_000_000_000,
        }
    }

    fn revoke(&self) {
        self.changes.send_replace(self.grant.revision + 1);
    }
}

impl QueryAuthorization for Authority {
    fn check(&self, grant: &QueryGrant) -> Result<()> {
        let expected = &self.grant;
        if *self.changes.borrow() != expected.revision
            || self.now.load(Ordering::SeqCst) >= self.until
            || grant.principal != expected.principal
            || grant.revision != expected.revision
            || grant.selection.tenant_id != expected.selection.tenant_id
        {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn expires_ns(&self) -> Option<u64> {
        Some(self.until)
    }
}

struct ClientFixture {
    data: QueryFixture,
    owner: Arc<QueryOwner>,
    grant: QueryGrant,
    authority: Arc<Authority>,
    clock: Arc<Clock>,
}

impl ClientFixture {
    fn local() -> TestResult<Self> {
        Self::new(200, 100)
    }

    fn new(rows: usize, now: u64) -> TestResult<Self> {
        let data = QueryFixture::new()?;
        let owner = Arc::new(QueryOwner::new(
            data.store.clone(),
            QueryLimits {
                output_rows: rows,
                ..Default::default()
            },
        )?);
        let grant = QueryGrant {
            principal: "client-operator".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new(data.source.tenant_id, vec![data.source.clone()]),
        };
        let clock = Arc::new(Clock::new(now));
        let authority = Arc::new(Authority::new(grant.clone(), clock.now.clone()));
        Ok(Self {
            data,
            owner,
            grant,
            authority,
            clock,
        })
    }

    fn bounded() -> TestResult<Self> {
        let mut fixture = Self::new(200, 100)?;
        let capacity = 64 * 1024;
        fixture.owner = Arc::new(QueryOwner::new(
            fixture.data.store.clone(),
            QueryLimits {
                input_bytes: capacity,
                output_bytes: capacity,
                input_capacity: capacity,
                output_capacity: capacity,
                global_evaluations: 1,
                extract_timeout: Duration::from_secs(30),
                evaluate_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        )?);
        Ok(fixture)
    }

    fn gate(&self) -> TestResult<(mpsc::Receiver<()>, mpsc::Sender<()>)> {
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *self
            .owner
            .scan_gate
            .lock()
            .map_err(|_| "scan gate lock failed")? = Some((entered, released));
        Ok((entering, release))
    }

    async fn entered(entering: &mpsc::Receiver<()>) -> TestResult {
        tokio::time::timeout(WAIT, async {
            loop {
                match entering.try_recv() {
                    Ok(()) => return Ok(()),
                    Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(mpsc::TryRecvError::Disconnected) => return Err("scan gate closed".into()),
                }
            }
        })
        .await?
    }

    fn inputs(&self, alive: bool) -> TestResult {
        let inputs = self
            .owner
            .input_refs
            .lock()
            .map_err(|_| "input reference lock failed")?;
        assert!(!inputs.is_empty());
        assert!(inputs
            .iter()
            .all(|input| input.upgrade().is_some() == alive));
        Ok(())
    }

    fn commit(&self, cursor: u64, now: u64, operation: u32, target: u8) -> TestResult {
        self.data.commit(
            cursor,
            now,
            EvidenceRecord {
                operation,
                policy_rule_id: 42,
                execution_set_id: vec![target; 16].into(),
                ..Default::default()
            },
        )
    }

    fn plan(&self, sql: &str, parameters: Vec<Value>, follow: bool) -> Result<QueryPlan> {
        QueryPlan::client(
            self.grant.clone(),
            QuerySql::admit(sql, parameters, follow)?,
        )
    }

    async fn query(&self, plan: &QueryPlan) -> Result<QueryResult> {
        self.owner
            .query_client(
                plan.clone(),
                self.authority.clone(),
                self.clock.now.load(Ordering::SeqCst),
                Arc::new(AnalysisReadControl::default()),
            )
            .await
    }

    fn follow(&self, plan: QueryPlan, checkpoint: Option<QueryCheckpoint>) -> Result<QueryStream> {
        self.owner
            .follow_client_clock(plan, checkpoint, self.authority.clone(), self.clock.clone())
    }

    async fn next(stream: &mut QueryStream) -> TestResult<QueryFrame> {
        let frame = tokio::time::timeout(WAIT, stream.next())
            .await?
            .ok_or("client stream closed before its expected frame")??;
        Ok(frame)
    }

    fn checkpoint(frame: &QueryFrame) -> TestResult<QueryCheckpoint> {
        match &frame.payload {
            QueryPayload::Checkpoint { checkpoint, .. } => Ok(checkpoint.clone()),
            payload => Err(format!("expected checkpoint, received {payload:?}").into()),
        }
    }

    fn result(frame: &QueryFrame, operation: QueryOperation) -> TestResult<&QueryResult> {
        match (&frame.payload, operation) {
            (QueryPayload::Append { result, .. }, QueryOperation::Append)
            | (QueryPayload::Replace { result, .. }, QueryOperation::Replace) => Ok(result),
            (payload, _) => Err(format!("expected {operation:?}, received {payload:?}").into()),
        }
    }

    async fn cancel(stream: &mut QueryStream) -> TestResult {
        stream.cancel()?;
        for _ in 0..4 {
            let frame = Self::next(stream).await?;
            if matches!(
                frame.payload,
                QueryPayload::Terminal {
                    reason: QueryTerminalReason::Cancelled,
                    ..
                }
            ) {
                drop(frame);
                assert!(tokio::time::timeout(WAIT, stream.next())
                    .await?
                    .transpose()?
                    .is_none());
                tokio::time::timeout(WAIT, &mut stream.task).await??;
                return Ok(());
            }
            if !matches!(
                frame.payload,
                QueryPayload::Append { .. } | QueryPayload::Checkpoint { .. }
            ) {
                return Err(format!("unexpected cancellation frame: {:?}", frame.payload).into());
            }
        }
        Err("client cancellation did not close within four frames".into())
    }

    async fn current_query(&self) -> TestResult {
        let mut grant = self.grant.clone();
        grant.revision += 1;
        let sql = QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?;
        let authority = Arc::new(Authority::new(grant.clone(), self.clock.now.clone()));
        let plan = QueryPlan::client(grant, sql)?;
        let result = self
            .owner
            .query_client(
                plan,
                authority,
                self.clock.now.load(Ordering::SeqCst),
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
        assert_eq!(result.sources.len(), 1);
        Ok(())
    }
}

#[test]
fn query_client_trusted_entry() -> TestResult {
    let fixture = ClientFixture::local()?;
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    assert!(matches!(
        fixture.owner.query_at(&plan, 100),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture
            .owner
            .query_cancel(&plan, 100, &AnalysisReadControl::default()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.owner.follow(plan.clone(), None),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture
            .owner
            .follow_clock(plan.clone(), None, fixture.clock.clone()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        QueryPlan::new(fixture.grant.selection.clone(), plan.template().clone()),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_in_process() -> TestResult {
    let fixture = ClientFixture::local()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    fixture.authority.check(&fixture.grant)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(1)]]);
    drop(result);
    let inputs = fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?;
    assert!(!inputs.is_empty());
    assert!(inputs.iter().all(|input| input.upgrade().is_none()));
    drop(inputs);
    let trusted = fixture.data.plan(super::QueryTemplate::OperationCounts)?;
    let result = fixture.owner.query_at(&trusted, 100)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(1)]]);
    Ok(())
}

#[tokio::test]
async fn query_client_scheduler() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let (entering, release) = fixture.gate()?;
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task = tokio::spawn(async move {
        owner
            .query_client(
                request,
                authority,
                100,
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
            )
            .await
    });
    ClientFixture::entered(&entering).await?;
    fixture.inputs(true)?;
    tokio::time::timeout(WAIT, tokio::time::sleep(Duration::from_millis(1))).await?;
    assert!(!task.is_finished());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    let result = tokio::time::timeout(WAIT, task).await???;
    assert_eq!(result.rows, vec![vec![Value::BigInt(1)]]);
    drop(result);
    fixture.inputs(false)?;
    drop(
        fixture
            .owner
            .budget
            .evaluate(fixture.grant.selection.tenant_id)?,
    );
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    Ok(())
}

#[tokio::test]
async fn query_client_cancel() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let before = fixture.data.store.meta()?;
    let (entering, release) = fixture.gate()?;
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let query = control.clone();
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task =
        tokio::spawn(async move { owner.query_client(request, authority, 100, query).await });
    ClientFixture::entered(&entering).await?;
    control.cancel()?;
    assert!(!task.is_finished());
    fixture.inputs(true)?;
    assert!(fixture
        .owner
        .budget
        .evaluate(fixture.grant.selection.tenant_id)
        .is_err());
    assert!(fixture.owner.budget.output(1).is_err());
    release.send(())?;
    ClientFixture::entered(&entering).await?;
    let result = tokio::time::timeout(WAIT, task).await??;
    assert!(
        matches!(result, Err(crate::Error::AnalysisReadCancelled { .. })),
        "{result:?}"
    );
    assert!(fixture.owner.native_failed.load(Ordering::Acquire));
    fixture.inputs(false)?;
    assert_eq!(fixture.data.store.meta()?, before);
    fixture.commit(2, 2, 8, 4)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
    drop(result);
    drop(
        fixture
            .owner
            .budget
            .evaluate(fixture.grant.selection.tenant_id)?,
    );
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    Ok(())
}

#[tokio::test]
async fn query_client_drop() -> TestResult {
    let fixture = ClientFixture::bounded()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    let before = fixture.data.store.meta()?;
    let (entering, release) = fixture.gate()?;
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let query = control.clone();
    let owner = fixture.owner.clone();
    let authority = fixture.authority.clone();
    let request = plan.clone();
    let task =
        tokio::spawn(async move { owner.query_client(request, authority, 100, query).await });
    ClientFixture::entered(&entering).await?;
    task.abort();
    assert!(matches!(
        tokio::time::timeout(WAIT, task).await?,
        Err(error) if error.is_cancelled()
    ));
    assert!(matches!(
        control.check(),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    fixture.inputs(true)?;
    assert!(fixture
        .owner
        .budget
        .evaluate(fixture.grant.selection.tenant_id)
        .is_err());
    assert!(fixture.owner.budget.output(1).is_err());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::AnalysisBusy { .. })
    ));
    release.send(())?;
    ClientFixture::entered(&entering).await?;
    tokio::time::timeout(WAIT, async {
        loop {
            match fixture
                .owner
                .budget
                .evaluate(fixture.grant.selection.tenant_id)
            {
                Ok(lease) => {
                    drop(lease);
                    return Ok::<_, crate::Error>(());
                }
                Err(crate::Error::AnalysisBusy { .. }) => tokio::task::yield_now().await,
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    assert!(fixture.owner.native_failed.load(Ordering::Acquire));
    fixture.inputs(false)?;
    drop(
        fixture
            .owner
            .budget
            .output(fixture.owner.limits.output_bytes)?,
    );
    assert_eq!(fixture.data.store.meta()?, before);
    fixture.commit(2, 2, 8, 4)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(2)]]);
    Ok(())
}

#[test]
fn query_client_follow_admission() -> TestResult {
    let fixture = ClientFixture::local()?;
    for sql in [
        "SELECT operation FROM events",
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds' OR operation = 7",
        "SELECT COUNT(*) FROM events WHERE received_at <= CURRENT_TIMESTAMP - INTERVAL '300 seconds'",
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        assert!(matches!(
            fixture.owner.follow_client(plan.clone(), None, fixture.authority.clone()),
            Err(crate::Error::QueryDenied { .. })
        ), "{sql}");
        assert!(matches!(
            fixture.follow(plan, None),
            Err(crate::Error::QueryDenied { .. })
        ), "{sql}");
    }
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_capacity() -> TestResult {
    let fixture = ClientFixture::local()?;
    let limits = QueryLimits {
        input_bytes: 1_024,
        output_bytes: 4_096,
        input_capacity: 1_024,
        output_capacity: 4_096,
        ..Default::default()
    };
    let owner = QueryOwner::new(fixture.data.store.clone(), limits.clone())?;
    drop(owner);
    for changed in [
        QueryLimits {
            input_capacity: 1_023,
            ..limits.clone()
        },
        QueryLimits {
            output_capacity: 4_095,
            ..limits.clone()
        },
    ] {
        assert!(matches!(
            QueryOwner::new(fixture.data.store.clone(), changed),
            Err(crate::Error::QueryInvalid { .. })
        ));
    }
    for changed in [
        QueryLimits {
            output_rows: 201,
            ..Default::default()
        },
        QueryLimits {
            output_bytes: 1024 * 1024 + 1,
            ..Default::default()
        },
    ] {
        let owner = Arc::new(QueryOwner::new(fixture.data.store.clone(), changed)?);
        let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
        assert!(matches!(
            owner
                .query_client(
                    plan,
                    fixture.authority.clone(),
                    100,
                    Arc::new(AnalysisReadControl::default())
                )
                .await,
            Err(crate::Error::QueryInvalid { .. })
        ));
        let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], true)?;
        assert!(matches!(
            owner.follow_client(plan, None, fixture.authority.clone()),
            Err(crate::Error::QueryInvalid { .. })
        ));
        assert!(owner
            .input_refs
            .lock()
            .map_err(|_| "input reference lock failed")?
            .is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn query_client_expired_authority() -> TestResult {
    let fixture = ClientFixture::local()?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?;
    fixture
        .clock
        .now
        .store(fixture.authority.until - 1, Ordering::SeqCst);
    fixture.authority.check(&fixture.grant)?;
    fixture
        .clock
        .now
        .store(fixture.authority.until, Ordering::SeqCst);
    let control = Arc::new(AnalysisReadControl::default());
    control.cancel()?;
    assert!(matches!(
        fixture
            .owner
            .query_client(plan.clone(), fixture.authority.clone(), 100, control)
            .await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(fixture
        .owner
        .input_refs
        .lock()
        .map_err(|_| "input reference lock failed")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn query_client_bounds() -> TestResult {
    let fixture = ClientFixture::new(200, 10_000)?;
    for (index, now) in [1, 999, 1_000, 1_001, 1_999, 2_000, 3_000]
        .into_iter()
        .enumerate()
    {
        fixture.commit(index as u64 + 1, now, (index % 3) as u32, 4)?;
    }
    for predicate in [
        "received_at >= TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at > TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at <= TIMESTAMP '1970-01-01 00:00:00.000001'",
        "received_at BETWEEN TIMESTAMP '1970-01-01 00:00:00.000001' AND TIMESTAMP '1970-01-01 00:00:00.000002'",
    ] {
        let direct = fixture.plan(
            &format!("SELECT source_cursor FROM events WHERE {predicate} ORDER BY source_cursor"),
            vec![],
            false,
        )?;
        let complete = fixture.plan(
            &format!("SELECT source_cursor FROM events WHERE ({predicate}) OR FALSE ORDER BY source_cursor"),
            vec![],
            false,
        )?;
        let actual = fixture.query(&direct).await?;
        let expected = fixture.query(&complete).await?;
        assert_eq!(actual.scanned_bytes, None);
        assert_eq!(actual.input_bytes, None);
        assert_eq!(expected.scanned_bytes, None);
        assert_eq!(expected.input_bytes, None);
        assert_eq!(actual.rows, expected.rows, "{predicate}");
        assert_eq!(expected.input_rows, 7);
        assert!(actual.input_rows < expected.input_rows, "{predicate}");
        assert!(!actual.limited && !expected.limited);
    }
    let direct = fixture.plan(
        "SELECT source_cursor FROM events WHERE received_at >= $1 AND received_at <= $2 ORDER BY source_cursor",
        vec![Value::Timestamp(TimeUnit::Microsecond, 1), Value::Timestamp(TimeUnit::Microsecond, 2)],
        false,
    )?;
    assert_eq!(
        fixture.query(&direct).await?.rows,
        vec![
            vec![Value::UBigInt(3)],
            vec![Value::UBigInt(4)],
            vec![Value::UBigInt(5)],
            vec![Value::UBigInt(6)]
        ]
    );
    for sql in [
        "SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' OR operation = 0 ORDER BY source_cursor",
        "WITH chosen AS (SELECT source_cursor FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002') SELECT source_cursor FROM chosen ORDER BY source_cursor",
        "SELECT a.source_cursor FROM events a LEFT JOIN events b ON a.source_cursor = b.source_cursor WHERE a.received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' ORDER BY a.source_cursor",
    ] {
        let plan = fixture.plan(sql, vec![], false)?;
        let result = fixture.query(&plan).await?;
        assert_eq!(result.input_rows, 7, "{sql}");
        assert!(!result.rows.is_empty());
        assert!(!result.limited);
    }
    Ok(())
}

#[tokio::test]
async fn query_client_tenant_scope() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    for (cursor, operation, target) in [(1, 7, 4), (2, 99, 5), (3, 8, 4), (4, 99, 5), (5, 99, 0)] {
        fixture.commit(cursor, cursor, operation, target)?;
    }
    let mut other = fixture.data.source.clone();
    other.source_id = [6; 16];
    fixture.data.commit_as(
        &other,
        0,
        1,
        6,
        EvidenceRecord {
            operation: 99,
            policy_rule_id: 42,
            execution_set_id: vec![5; 16].into(),
            ..Default::default()
        },
    )?;
    let mut foreign = other.clone();
    foreign.tenant_id = [9; 16];
    foreign.source_id = [7; 16];
    fixture.data.commit_as(
        &foreign,
        0,
        1,
        7,
        EvidenceRecord {
            operation: 99,
            policy_rule_id: 42,
            execution_set_id: vec![5; 16].into(),
            ..Default::default()
        },
    )?;
    let count = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE policy_rule_id = 42",
        vec![],
        false,
    )?;
    let result = fixture.query(&count).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(5)]]);
    assert_eq!(result.input_rows, 5);
    assert_eq!(result.scanned_bytes, None);
    assert_eq!(result.input_bytes, None);
    assert_eq!(result.sources.len(), 1);
    assert_eq!(result.sources[0].receipt.identity, fixture.data.source);
    drop(result);
    let rows = fixture
        .query(&fixture.plan("SELECT * FROM events", vec![], false)?)
        .await?;
    let schema = super::input::SCHEMAS
        .iter()
        .find(|schema| schema.name == "events")
        .ok_or("event schema is absent")?;
    assert_eq!(
        rows.columns,
        schema
            .columns
            .iter()
            .map(|field| field.0)
            .collect::<Vec<_>>()
    );
    assert_eq!(rows.types.len(), schema.columns.len());
    assert_eq!(rows.rows.len(), 5);
    assert_eq!(rows.positions.len(), 5);
    assert!(!rows
        .columns
        .iter()
        .any(|name| name.starts_with("__araphor_")));
    let target = rows
        .columns
        .iter()
        .position(|name| name == "execution_set_id")
        .ok_or("target column is absent")?;
    assert_eq!(
        rows.rows
            .iter()
            .map(|row| row[target].clone())
            .collect::<Vec<_>>(),
        [4, 5, 4, 5, 0].map(|target| Value::Blob(vec![target; 16]))
    );
    drop(rows);
    let selected = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE execution_set_id = $1 AND policy_rule_id = 42",
        vec![Value::Blob(vec![4; 16])],
        false,
    )?;
    assert_eq!(
        fixture.query(&selected).await?.rows,
        vec![vec![Value::BigInt(2)]]
    );
    for sql in [
        "SELECT COUNT(execution_set_id) FROM events",
        "SELECT COUNT(*) FROM events WHERE execution_set_id IS NULL",
        "SELECT e.operation FROM events e JOIN events f ON e.execution_set_id = f.execution_set_id",
        "SELECT operation FROM events ORDER BY execution_set_id",
        "SELECT * FROM coverage",
    ] {
        fixture.plan(sql, vec![], false)?;
    }
    assert!(fixture
        .plan(
            "SELECT __araphor_commit_revision FROM events",
            vec![],
            false
        )
        .is_err());
    let mut grant = fixture.grant.clone();
    grant.selection.sources.push(other);
    let plan = QueryPlan::client(
        grant.clone(),
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(6)]]);
    assert_eq!(result.sources.len(), 2);
    assert!(result
        .sources
        .iter()
        .all(|source| source.receipt.identity.tenant_id == fixture.grant.selection.tenant_id));
    drop(result);
    grant.selection.sources.clear();
    let plan = QueryPlan::client(
        grant.clone(),
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    assert_eq!(
        fixture.query(&plan).await?.rows,
        vec![vec![Value::BigInt(0)]]
    );
    grant.selection.sources.push(foreign.clone());
    assert!(matches!(
        QueryPlan::client(
            grant.clone(),
            QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?
        ),
        Err(crate::Error::QueryDenied { .. })
    ));
    grant.selection.tenant_id = foreign.tenant_id;
    let plan = QueryPlan::client(
        grant,
        QuerySql::admit("SELECT COUNT(*) FROM events", vec![], false)?,
    )?;
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        fixture.owner.query_at(&count, 100),
        Err(crate::Error::QueryDenied { .. })
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_append_resume() -> TestResult {
    let fixture = ClientFixture::new(2, 100)?;
    for (cursor, operation) in [(1, 9), (2, 7), (3, 9), (4, 7), (5, 7), (6, 9)] {
        fixture.commit(cursor, cursor, operation, 4)?;
    }
    let plan = fixture.plan(
        "SELECT operation FROM events WHERE operation = 7",
        vec![],
        true,
    )?;
    let mut stream = fixture.follow(plan.clone(), None)?;
    let metadata = ClientFixture::next(&mut stream).await?;
    let QueryPayload::Metadata(metadata) = &metadata.payload else {
        return Err("client metadata is absent".into());
    };
    assert_eq!(metadata.columns.len(), 1);
    assert_eq!(metadata.columns[0].name, "operation");
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.columns, ["operation"]);
    assert_eq!(
        result.rows,
        vec![vec![Value::UInt(7)], vec![Value::UInt(7)]]
    );
    assert_eq!(
        result
            .positions
            .iter()
            .map(|position| position.commit_revision)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
    assert!(result.limited && !result.exhausted);
    drop(frame);
    let first = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    assert_eq!(
        first.position(),
        Some(StorePositionV1 {
            commit_revision: 4,
            ordinal: u32::MAX
        })
    );
    ClientFixture::cancel(&mut stream).await?;

    let mut resumed = fixture.follow(plan.clone(), Some(first))?;
    assert!(matches!(
        ClientFixture::next(&mut resumed).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut resumed).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.columns, ["operation"]);
    assert_eq!(result.rows, vec![vec![Value::UInt(7)]]);
    assert_eq!(
        result.positions,
        vec![StorePositionV1 {
            commit_revision: 5,
            ordinal: 0
        }]
    );
    assert!(!result.limited && result.exhausted);
    drop(frame);
    let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut resumed).await?)?;
    assert_eq!(
        complete.position(),
        Some(StorePositionV1 {
            commit_revision: 6,
            ordinal: u32::MAX
        })
    );
    ClientFixture::cancel(&mut resumed).await?;

    fixture.commit(7, 7, 7, 4)?;
    let mut resumed = fixture.follow(plan, Some(complete))?;
    assert!(matches!(
        ClientFixture::next(&mut resumed).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut resumed).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Append)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7)]]);
    assert_eq!(
        result.positions,
        vec![StorePositionV1 {
            commit_revision: 7,
            ordinal: 0
        }]
    );
    drop(frame);
    let _complete = ClientFixture::checkpoint(&ClientFixture::next(&mut resumed).await?)?;
    ClientFixture::cancel(&mut resumed).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_timer_replace() -> TestResult {
    let fixture = ClientFixture::new(200, 3_000_000_000)?;
    fixture.commit(1, 2_000_000_000, 7, 4)?;
    let meta = fixture.data.store.meta()?;
    let plan = fixture.plan(
        "SELECT COUNT(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '1 seconds'",
        vec![],
        true,
    )?;
    let (entering, release) = fixture.clock.arm()?;
    assert!(fixture.clock.changes().is_none());
    assert!(WAIT < QueryLimits::default().heartbeat);
    let mut stream = fixture.follow(plan, None)?;
    let proof: TestResult<_> = match tokio::time::timeout(WAIT, async {
        let metadata = ClientFixture::next(&mut stream).await?;
        assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
        let initial = ClientFixture::next(&mut stream).await?;
        let first = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
        entering.await?;
        // Keep the idle loop's old sample. Only its expiry timer can wake it.
        fixture.clock.now.store(4_000_000_000, Ordering::SeqCst);
        release.send(())?;
        let expired = ClientFixture::next(&mut stream).await?;
        let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
        Ok((initial, first, expired, complete))
    })
    .await
    {
        Ok(proof) => proof,
        Err(error) => Err(error.into()),
    };
    let _released = release.send(());
    let cleanup = ClientFixture::cancel(&mut stream).await;
    let (initial, first, expired, complete) = proof?;
    cleanup?;
    for (frame, count, now, expiry) in [
        (&initial, 1, 3_000_000_000, Some(4_000_000_000)),
        (&expired, 0, 4_000_000_000, None),
    ] {
        let result = ClientFixture::result(frame, QueryOperation::Replace)?;
        assert_eq!(result.rows, vec![vec![Value::BigInt(count)]]);
        assert_eq!(result.evaluated_utc_ns, now);
        assert_eq!(result.next_expiry_ns, expiry);
        assert_eq!(result.meta, meta);
        assert!(!frame.clock_changed);
    }
    assert_eq!(first, complete);
    assert_eq!(fixture.data.store.meta()?, meta);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_quiet_revoke() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT COUNT(*) FROM events", vec![], true)?;
    let mut stream = fixture.follow(plan.clone(), None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut stream).await?;
    assert_eq!(
        ClientFixture::result(&frame, QueryOperation::Replace)?.rows,
        vec![vec![Value::BigInt(1)]]
    );
    drop(frame);
    let _checkpoint = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    fixture.authority.revoke();
    assert!(WAIT < QueryLimits::default().heartbeat);
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    assert!(matches!(
        stream.next().await,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(stream.is_terminated());
    assert!(stream.next().await.is_none());
    assert!(matches!(
        fixture.query(&plan).await,
        Err(crate::Error::QueryDenied { .. })
    ));
    drop(stream);
    fixture.commit(2, 2, 8, 4)?;
    fixture.current_query().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_buffered_revoke() -> TestResult {
    let fixture = ClientFixture::new(200, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    let plan = fixture.plan("SELECT operation FROM events", vec![], true)?;
    let mut stream = fixture.follow(plan, None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    tokio::time::timeout(WAIT, async {
        while stream.queued() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(stream.queued(), 1);
    fixture.authority.revoke();
    assert!(matches!(
        stream.next().await,
        Some(Err(crate::Error::QueryDenied { .. }))
    ));
    assert!(stream.is_terminated());
    assert!(stream.next().await.is_none());
    drop(stream);
    tokio::time::timeout(WAIT, async {
        while Arc::strong_count(&fixture.owner) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    fixture.commit(2, 2, 8, 4)?;
    fixture.current_query().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_client_output_limit() -> TestResult {
    let fixture = ClientFixture::new(2, 100)?;
    fixture.commit(1, 1, 7, 4)?;
    fixture.commit(2, 2, 8, 4)?;
    let sql = "SELECT operation, COUNT(*) FROM events GROUP BY operation ORDER BY operation";
    let plan = fixture.plan(sql, vec![], false)?;
    let result = fixture.query(&plan).await?;
    assert_eq!(
        result.rows,
        vec![
            vec![Value::UInt(7), Value::BigInt(1)],
            vec![Value::UInt(8), Value::BigInt(1)]
        ]
    );
    assert!(!result.limited);
    drop(result);
    let mut stream = fixture.follow(fixture.plan(sql, vec![], true)?, None)?;
    assert!(matches!(
        ClientFixture::next(&mut stream).await?.payload,
        QueryPayload::Metadata(_)
    ));
    let frame = ClientFixture::next(&mut stream).await?;
    let result = ClientFixture::result(&frame, QueryOperation::Replace)?;
    assert_eq!(result.rows.len(), 2);
    assert!(!result.limited);
    drop(frame);
    let complete = ClientFixture::checkpoint(&ClientFixture::next(&mut stream).await?)?;
    fixture.commit(3, 3, 9, 4)?;
    let frame = ClientFixture::next(&mut stream).await?;
    let QueryPayload::Error {
        code,
        last_checkpoint,
        ..
    } = &frame.payload
    else {
        return Err(format!(
            "expected complete-output failure, received {:?}",
            frame.payload
        )
        .into());
    };
    assert_eq!(*code, QueryErrorCode::ResultTooLarge);
    assert_eq!(last_checkpoint.as_ref(), Some(&complete));
    drop(frame);
    assert!(tokio::time::timeout(WAIT, stream.next())
        .await?
        .transpose()?
        .is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    let result = fixture.query(&plan).await?;
    assert_eq!(result.rows.len(), 2);
    assert!(result.limited);
    drop(result);
    let count = fixture
        .query(&fixture.plan("SELECT COUNT(*) FROM events", vec![], false)?)
        .await?;
    assert_eq!(count.rows, vec![vec![Value::BigInt(3)]]);
    assert!(!count.limited);
    Ok(())
}
