use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use duckdb::types::Value;
use tokio::sync::oneshot;

use super::tests::QueryFixture;
use super::{
    QueryCheckpoint, QueryClock, QueryFrame, QueryLimits, QueryOperation, QueryOwner, QueryPayload,
    QueryStream, QueryTemplate, QueryTerminalReason, QUERY_SCHEMA_VERSION,
};
use crate::{AnalysisReadControl, Result, StorePositionV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(5);

struct GateClock {
    first: Mutex<Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>>,
    origin: Instant,
}

impl GateClock {
    fn new() -> (Arc<Self>, oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entering) = oneshot::channel();
        let (release, released) = mpsc::channel();
        (
            Arc::new(Self {
                first: Mutex::new(Some((entered, released))),
                origin: Instant::now(),
            }),
            entering,
            release,
        )
    }
}

impl QueryClock for GateClock {
    fn now_ns(&self) -> Result<u64> {
        let first = self
            .first
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, released)) = first {
            let _entered = entered.send(());
            released.recv_timeout(WAIT).map_err(|_| {
                crate::QueryInvalidSnafu {
                    field: "test clock gate",
                }
                .build()
            })?;
        }
        Ok(1_000_000_000_000 + self.origin.elapsed().as_nanos() as u64)
    }
}

async fn next(stream: &mut QueryStream) -> TestResult<QueryFrame> {
    tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or_else(|| "query stream closed before its expected frame".into())
}

fn checkpoint(frame: &QueryFrame) -> TestResult<QueryCheckpoint> {
    match &frame.payload {
        QueryPayload::Checkpoint { checkpoint, .. } => Ok(checkpoint.clone()),
        payload => Err(format!("expected checkpoint, received {payload:?}").into()),
    }
}

fn cursors(frame: &QueryFrame) -> TestResult<Vec<u64>> {
    let QueryPayload::Append { result, .. } = &frame.payload else {
        return Err(format!("expected append, received {:?}", frame.payload).into());
    };
    let cursor = result
        .columns
        .iter()
        .position(|column| column == "source_cursor")
        .ok_or("source cursor column absent")?;
    result
        .rows
        .iter()
        .map(|row| match row.get(cursor) {
            Some(Value::UBigInt(cursor)) => Ok(*cursor),
            _ => Err("source cursor value absent".into()),
        })
        .collect()
}

fn inputs_released(owner: &QueryOwner) {
    let inputs = owner
        .input_refs
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(!inputs.is_empty());
    assert!(inputs.iter().all(|input| input.upgrade().is_none()));
}

async fn cancelled(stream: &mut QueryStream, last: Option<&QueryCheckpoint>) -> TestResult {
    stream.cancel()?;
    let frame = next(stream).await?;
    match &frame.payload {
        QueryPayload::Terminal {
            reason: QueryTerminalReason::Cancelled,
            last_checkpoint,
            ..
        } => assert_eq!(last_checkpoint.as_ref(), last),
        payload => {
            return Err(format!("expected cancellation terminal, received {payload:?}").into())
        }
    }
    drop(frame);
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_follow_snapshot_race() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1, 7)?;
    let owner = Arc::new(fixture.owner(QueryLimits::default())?);
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let (clock, entered, release) = GateClock::new();
    let mut stream = owner.follow_clock(plan.clone(), None, clock)?;
    tokio::time::timeout(WAIT, entered).await??;
    fixture.event(2, 2, 7)?;
    let captured = fixture.store.meta()?;
    release.send(())?;

    let metadata = next(&mut stream).await?;
    assert_eq!(metadata.schema_version, QUERY_SCHEMA_VERSION);
    assert_eq!(metadata.operation, QueryOperation::Append);
    assert_eq!(metadata.read_revision, captured.commit_revision);
    assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
    assert_eq!(metadata.coverage()[0].receipt.contiguous_cursor, 2);
    drop(metadata);
    let data = next(&mut stream).await?;
    assert_eq!(cursors(&data)?, vec![1, 2]);
    assert_eq!(data.read_revision, captured.commit_revision);
    inputs_released(&owner);
    drop(data);
    let initial = checkpoint(&next(&mut stream).await?)?;
    assert_eq!(
        initial.position(),
        Some(StorePositionV1 {
            commit_revision: captured.commit_revision,
            ordinal: u32::MAX,
        })
    );

    fixture.event(3, 3, 7)?;
    let data = next(&mut stream).await?;
    assert_eq!(cursors(&data)?, vec![3]);
    drop(data);
    let complete = checkpoint(&next(&mut stream).await?)?;
    assert!(complete.position() > initial.position());
    cancelled(&mut stream, Some(&complete)).await?;
    inputs_released(&owner);
    fixture.event(4, 4, 7)?;
    assert_eq!(owner.query_at(&plan, 4)?.rows.len(), 4);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_follow_empty_progress() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1, 9)?;
    let owner = Arc::new(fixture.owner(QueryLimits::default())?);
    let plan = fixture.plan(QueryTemplate::Events { operation: Some(7) })?;
    let mut stream = owner.follow(plan.clone(), None)?;
    let metadata = next(&mut stream).await?;
    assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
    drop(metadata);

    // The initial result cannot pass its checkpoint while output is not read.
    fixture.event(2, 2, 9)?;
    fixture.event(3, 3, 7)?;
    fixture.event(4, 4, 9)?;
    let end = fixture.store.meta()?.commit_revision;
    let empty = next(&mut stream).await?;
    assert!(cursors(&empty)?.is_empty());
    drop(empty);
    let first = checkpoint(&next(&mut stream).await?)?;
    assert_eq!(
        first.position(),
        Some(StorePositionV1 {
            commit_revision: 1,
            ordinal: u32::MAX
        })
    );
    let data = next(&mut stream).await?;
    assert_eq!(cursors(&data)?, vec![3]);
    assert_eq!(data.read_revision, end);
    drop(data);
    let complete = checkpoint(&next(&mut stream).await?)?;
    assert_eq!(
        complete.position(),
        Some(StorePositionV1 {
            commit_revision: end,
            ordinal: u32::MAX
        })
    );
    cancelled(&mut stream, Some(&complete)).await?;

    let mut resumed = owner.follow(plan, Some(complete.clone()))?;
    let metadata = next(&mut resumed).await?;
    assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
    drop(metadata);
    let data = next(&mut resumed).await?;
    assert!(cursors(&data)?.is_empty());
    drop(data);
    let replayed = checkpoint(&next(&mut resumed).await?)?;
    assert_eq!(replayed, complete);
    cancelled(&mut resumed, Some(&replayed)).await?;
    inputs_released(&owner);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_follow_coalesced_output() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1, 7)?;
    let owner = Arc::new(fixture.owner(QueryLimits::default())?);
    let plan = fixture.plan(QueryTemplate::OperationCounts)?;
    let mut stream = owner.follow(plan.clone(), None)?;
    let metadata = next(&mut stream).await?;
    assert_eq!(metadata.operation, QueryOperation::Replace);
    assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
    drop(metadata);
    fixture.event(2, 2, 7)?;
    fixture.event(3, 3, 9)?;
    fixture.event(4, 4, 7)?;
    let end = fixture.store.meta()?.commit_revision;

    let initial = next(&mut stream).await?;
    let QueryPayload::Replace { result, .. } = &initial.payload else {
        return Err("initial replacement absent".into());
    };
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(1)]]);
    assert_eq!(initial.read_revision, 1);
    drop(initial);
    let _first = checkpoint(&next(&mut stream).await?)?;
    let updated = next(&mut stream).await?;
    let QueryPayload::Replace { result, .. } = &updated.payload else {
        return Err(format!("coalesced replacement absent: {:?}", updated.payload).into());
    };
    assert_eq!(
        result.rows,
        vec![
            vec![Value::UInt(7), Value::BigInt(3)],
            vec![Value::UInt(9), Value::BigInt(1)],
        ]
    );
    assert_eq!(updated.read_revision, end);
    let normal = owner.query_at(&plan, result.evaluated_utc_ns)?;
    assert_eq!(result.meta, normal.meta);
    assert_eq!(result.rows, normal.rows);
    drop(normal);
    drop(updated);
    let complete = checkpoint(&next(&mut stream).await?)?;
    assert_eq!(complete.read_revision(), end);
    assert_eq!(complete.position(), None);
    cancelled(&mut stream, Some(&complete)).await?;
    inputs_released(&owner);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_follow_output_stall() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1, 7)?;
    let limits = QueryLimits {
        global_streams: 1,
        tenant_streams: 1,
        output_capacity: QueryLimits::default().output_bytes,
        output_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let owner = Arc::new(fixture.owner(limits)?);
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let (clock, entered, release) = GateClock::new();
    let mut stream = owner.follow_clock(plan.clone(), None, clock)?;
    tokio::time::timeout(WAIT, entered).await??;
    assert!(matches!(
        owner.follow(plan.clone(), None),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    release.send(())?;

    // Leave the one-slot output queue full until its owner reaches the deadline.
    tokio::time::timeout(WAIT, &mut stream.task).await??;
    inputs_released(&owner);
    let metadata = next(&mut stream).await?;
    assert!(matches!(metadata.payload, QueryPayload::Metadata(_)));
    drop(metadata);
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    fixture.event(2, 2, 7)?;
    let result = owner.query_cancel(&plan, 2, &AnalysisReadControl::default())?;
    assert_eq!(result.rows.len(), 2);
    drop(result);

    let (clock, entered, release) = GateClock::new();
    let mut recovered = owner.follow_clock(plan, None, clock)?;
    tokio::time::timeout(WAIT, entered).await??;
    recovered.cancel()?;
    release.send(())?;
    cancelled(&mut recovered, None).await?;
    inputs_released(&owner);
    assert_eq!(Arc::strong_count(&owner), 1);
    Ok(())
}
