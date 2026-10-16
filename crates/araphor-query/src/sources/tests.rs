use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, EvidenceIntakeIdentityV1,
    EvidenceRecord, ValidatedEvidenceBatchV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::common::ScalarValue;
use datafusion::logical_expr::LogicalPlan;
use futures_util::TryStreamExt as _;
use prost::Message as _;

use crate::execution::{Engine, Limits, Read};
use crate::parser::Parser;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    engine: Arc<Engine>,
    store: Arc<AnalysisStore>,
    source: EvidenceIntakeIdentityV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::new_with_limits(Limits {
            extract_timeout: Duration::from_secs(5),
            evaluate_timeout: Duration::from_secs(5),
            ..Default::default()
        })
    }

    fn new_with_limits(limits: Limits) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let engine = Engine::new(Arc::clone(&store), limits)?;
        Ok(Self {
            engine,
            store,
            source: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "source-test".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            _directory: directory,
        })
    }

    fn commit(&self, source: &EvidenceIntakeIdentityV1, cursor: u64, received: u64) -> TestResult {
        self.commit_records(
            source,
            cursor,
            received,
            &[EvidenceRecord {
                operation: 7,
                ..Default::default()
            }],
        )
    }

    fn commit_records(
        &self,
        source: &EvidenceIntakeIdentityV1,
        cursor: u64,
        received: u64,
        records: &[EvidenceRecord],
    ) -> TestResult {
        let mut frame = Vec::new();
        let mut ends = Vec::new();
        for record in records {
            let payload = record.encode_to_vec();
            let start = frame.len();
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            frame.extend_from_slice(&crc32c::crc32c(&frame[start..]).to_be_bytes());
            ends.push(frame.len());
        }
        self.store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor + records.len() as u64 - 1,
                intake_utc_ns: received,
                frame_ends: ends,
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    fn plan(&self, sql: &str) -> TestResult<(Arc<LogicalPlan>, BTreeSet<String>)> {
        let state = self.engine.catalog(BTreeMap::new())?;
        let statement = Parser::parse(sql)?;
        let sources = state
            .resolve_table_references(&statement)?
            .into_iter()
            .map(|reference| reference.table().to_owned())
            .collect();
        Ok((
            Arc::new(self.engine.plan(&state, statement, vec![])?),
            sources,
        ))
    }

    fn selection(&self) -> AnalysisSelectionV1 {
        AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()])
    }

    fn control(&self) -> TestResult<AnalysisReadControl> {
        Ok(AnalysisReadControl::with_timeout(Duration::from_secs(10))?)
    }
}

fn cell(batches: &[RecordBatch], column: usize) -> ScalarValue {
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    ScalarValue::try_from_array(batches[0].column(column), 0).unwrap()
}

#[test]
fn source_scope_and_time() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit(&fixture.source, 1, 1_234_567)?;
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&foreign, 1, 2_345_678)?;
    let unrelated = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&unrelated, 1, 3_456_789)?;
    let (plan, sources) = fixture
        .plan("SELECT source_cursor, received_utc_ns, received_at, operation FROM events")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 9_000_000)?;
    let (snapshot, batches) = session.execute(plan, &sources)?;
    assert_eq!(cell(&batches, 0), ScalarValue::UInt64(Some(1)));
    assert_eq!(cell(&batches, 1), ScalarValue::UInt64(Some(1_234_567)));
    assert_eq!(
        cell(&batches, 2),
        ScalarValue::TimestampMicrosecond(Some(1_234), None)
    );
    assert_eq!(cell(&batches, 3), ScalarValue::UInt32(Some(7)));
    assert_eq!(snapshot.witnesses.len(), 1);
    assert_eq!(snapshot.witnesses[0].identity, fixture.source);
    assert_eq!(snapshot.page.extraction.sources.len(), 1);
    assert_eq!(
        snapshot.page.extraction.sources[0].receipt.identity,
        fixture.source
    );
    Ok(())
}

#[test]
fn unused_source_receipts() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit(&fixture.source, 1, 10_001)?;
    let (plan, sources) =
        fixture.plan("WITH unused AS (SELECT source_cursor FROM events) SELECT 7 AS value")?;
    assert_eq!(sources, BTreeSet::from(["events".into()]));
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 20_000)?;
    let (first, rows) = session.execute(Arc::clone(&plan), &sources)?;
    assert_eq!(cell(&rows, 0), ScalarValue::Int64(Some(7)));
    assert_eq!(first.witnesses.len(), 1);
    fixture.commit(&fixture.source, 2, 10_002)?;
    let (second, rows) = session.execute(plan, &sources)?;
    assert_eq!(cell(&rows, 0), ScalarValue::Int64(Some(7)));
    assert_eq!(first.witnesses.len(), 1);
    assert_eq!(second.witnesses.len(), 2);
    assert!(
        second.page.extraction.meta.commit_revision > first.page.extraction.meta.commit_revision
    );
    Ok(())
}

#[tokio::test]
async fn empty_filter_progress() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit(&fixture.source, 1, 10_001)?;
    let (plan, sources) = fixture.plan("SELECT source_cursor FROM events WHERE operation = 999")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 20_000)?;
    let (snapshot, stream) = session.stream(&plan, &sources, Read::Page(None)).await?;
    let batches: Vec<RecordBatch> = stream.try_collect().await?;
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 0);
    assert_eq!(snapshot.witnesses.len(), 1);
    assert!(snapshot.page.scanned_through.commit_revision > 0);
    assert!(snapshot.page.exhausted);
    Ok(())
}

#[test]
fn zero_column_counts() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit(&fixture.source, 1, 10_001)?;
    fixture.commit(&fixture.source, 2, 10_002)?;
    let (plan, sources) = fixture.plan("SELECT count(*) AS count FROM events")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 20_000)?;
    let (snapshot, batches) = session.execute(plan, &sources)?;
    assert_eq!(cell(&batches, 0), ScalarValue::Int64(Some(2)));
    assert_eq!(snapshot.witnesses.len(), 2);
    Ok(())
}

#[test]
fn clock_prunes_history() -> TestResult {
    const MINUTE: u64 = 60_000_000_000;
    let fixture = Fixture::new_with_limits(Limits {
        scan_bytes: 32 * 1024,
        input_bytes: 64 * 1024,
        extract_timeout: Duration::from_secs(5),
        evaluate_timeout: Duration::from_secs(5),
        ..Default::default()
    })?;
    let history = vec![
        EvidenceRecord {
            operation: 7,
            exact_object_id: vec![1; 2048].into(),
            ..Default::default()
        };
        64
    ];
    assert!(
        history
            .iter()
            .map(|record| record.encoded_len() + 8)
            .sum::<usize>()
            > fixture.engine.limits().scan_bytes
    );
    fixture.commit_records(&fixture.source, 1, 500 * MINUTE, &history)?;
    fixture.commit(&fixture.source, 65, 604 * MINUTE)?;
    fixture.commit(&fixture.source, 66, 607 * MINUTE)?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 608 * MINUTE)?;
    let (all, sources) = fixture.plan("SELECT count(*) FROM events")?;
    assert!(session.execute(all, &sources).is_err());
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 608 * MINUTE)?;
    let (plan, sources) = fixture.plan(
        "SELECT count(*) FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '5 minutes'",
    )?;
    let (snapshot, batches) = session.execute(plan, &sources)?;
    assert_eq!(cell(&batches, 0), ScalarValue::Int64(Some(2)));
    assert_eq!(snapshot.witnesses.len(), 2);
    assert_eq!(snapshot.page.extraction.sources.len(), 1);
    assert_eq!(
        snapshot.page.extraction.sources[0].receipt.identity,
        fixture.source
    );
    Ok(())
}

#[test]
fn scan_bounds_union() -> TestResult {
    let fixture = Fixture::new()?;
    for (cursor, received) in [(1, 1001), (2, 2001), (3, 3001)] {
        fixture.commit(&fixture.source, cursor, received)?;
    }
    for (sql, rows) in [
        (
            "SELECT source_cursor FROM events WHERE received_utc_ns >= 3000 UNION ALL SELECT source_cursor FROM events WHERE received_utc_ns < 2000",
            2,
        ),
        (
            "SELECT source_cursor FROM events WHERE received_utc_ns >= 3000 UNION ALL SELECT source_cursor FROM events",
            4,
        ),
        (
            "SELECT a.source_cursor FROM events a JOIN events b ON a.source_cursor = b.source_cursor WHERE a.received_utc_ns >= 2000 AND b.received_utc_ns <= 3000",
            1,
        ),
    ] {
        let (plan, sources) = fixture.plan(sql)?;
        let session = fixture
            .engine
            .session(fixture.selection(), &fixture.control()?, 4000)?;
        let (snapshot, batches) = session.execute(plan, &sources)?;
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            rows,
            "{sql}"
        );
        assert_eq!(snapshot.witnesses.len(), 3, "{sql}");
    }
    Ok(())
}

#[test]
fn unsupported_filter_capture() -> TestResult {
    let fixture = Fixture::new()?;
    for (cursor, received) in [(1, 1001), (2, 2001), (3, 3001)] {
        fixture.commit(&fixture.source, cursor, received)?;
    }
    for (sql, rows) in [
        (
            "SELECT source_cursor FROM events WHERE received_utc_ns >= 3000 OR operation = 7",
            3,
        ),
        (
            "SELECT source_cursor FROM events WHERE source_cursor >= 3",
            1,
        ),
        (
            "SELECT source_cursor FROM events WHERE ingested_utc_ns >= 3000",
            0,
        ),
    ] {
        let (plan, sources) = fixture.plan(sql)?;
        let session = fixture
            .engine
            .session(fixture.selection(), &fixture.control()?, 4000)?;
        let (snapshot, batches) = session.execute(plan, &sources)?;
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            rows,
            "{sql}"
        );
        assert_eq!(snapshot.witnesses.len(), 3, "{sql}");
    }
    let (plan, sources) = fixture.plan("SELECT source_cursor FROM events WHERE received_utc_ns >= 3000 AND CAST(node_id AS BIGINT) > 0")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 4000)?;
    assert!(session.execute(plan, &sources).is_err());
    Ok(())
}

#[test]
fn time_bounds_preserve_precision() -> TestResult {
    let fixture = Fixture::new()?;
    for (cursor, received) in [(1, 1999), (2, 2000), (3, 2999), (4, 3000)] {
        fixture.commit(&fixture.source, cursor, received)?;
    }
    let (plan, sources) = fixture.plan("SELECT source_cursor FROM events WHERE received_at > TIMESTAMP '1970-01-01 00:00:00.000001' AND received_at <= TIMESTAMP '1970-01-01 00:00:00.000002'")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, 4000)?;
    let (snapshot, batches) = session.execute(plan, &sources)?;
    let values = batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows())
                .map(move |row| ScalarValue::try_from_array(batch.column(0), row).unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        [ScalarValue::UInt64(Some(2)), ScalarValue::UInt64(Some(3))]
    );
    assert_eq!(snapshot.selection.time_range(), Some((2000, 2999)));
    assert_eq!(snapshot.witnesses.len(), 2);
    Ok(())
}

#[test]
fn native_intake_keeps_uint64_range() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.commit(&fixture.source, 1, u64::MAX - 1)?;
    fixture.commit(&fixture.source, 2, u64::MAX)?;
    let (plan, sources) = fixture.plan("SELECT received_utc_ns FROM events WHERE received_utc_ns >= CAST('18446744073709551615' AS BIGINT UNSIGNED)")?;
    let session = fixture
        .engine
        .session(fixture.selection(), &fixture.control()?, u64::MAX)?;
    let (snapshot, batches) = session.execute(plan, &sources)?;
    assert_eq!(cell(&batches, 0), ScalarValue::UInt64(Some(u64::MAX)));
    assert_eq!(snapshot.selection.time_range(), Some((u64::MAX, u64::MAX)));
    assert_eq!(snapshot.witnesses.len(), 1);
    Ok(())
}
