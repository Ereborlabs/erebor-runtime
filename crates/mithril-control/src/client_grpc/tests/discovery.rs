use araphor_data::{EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};
use prost::Message as _;

use super::*;

const SQL: &str = "SELECT tenant_id, source_id, event_count, first_cursor, last_cursor,
        effect_family, operation, binding_id
    FROM discovery.observed_effects((SELECT * FROM events))";

fn source(tenant_id: [u8; 16]) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id,
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn retain(
    fixture: &Fixture,
    source: &EvidenceIntakeIdentityV1,
    first: u64,
    count: usize,
) -> TestResult {
    let batch = crate::evidence::EvidenceBatchInputV1::encode(
        first,
        (0..count)
            .map(|_| crate::EvidenceRecord {
                effect_family: 1,
                operation: 7,
                coverage_interval_id: vec![4; 16].into(),
                ..Default::default()
            })
            .collect(),
    )?;
    fixture.service.data()?.store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: batch.cpu_id,
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            intake_utc_ns: 1_000_000_000,
            framed_records: batch.framed_records,
            frame_ends: batch.frame_ends,
        },
    )?;
    Ok(())
}

async fn next_rows(stream: &mut ClientStream<proto::QueryFrame>) -> TestResult<proto::QueryFrame> {
    loop {
        let frame = Fixture::next(stream).await?;
        match &frame.payload {
            Some(proto::query_frame::Payload::Rows(_)) => return Ok(frame),
            Some(proto::query_frame::Payload::Error(error)) => {
                return Err(format!("query failed: {}", error.code).into());
            }
            Some(proto::query_frame::Payload::Terminal(_)) => {
                return Err("query completed before its rows".into());
            }
            _ => {}
        }
    }
}

fn assert_rows(
    frame: &proto::QueryFrame,
    source: &EvidenceIntakeIdentityV1,
    count: u64,
) -> TestResult {
    use proto::query_value::Kind;

    assert_eq!(frame.operation, proto::QueryOperation::Replace as i32);
    assert_eq!(frame.coverage.len(), 1);
    let receipt = &frame.coverage[0];
    assert_eq!(
        receipt.source,
        Some(proto::SourceIdentity {
            tenant_id: source.tenant_id.to_vec(),
            node_id: source.node_id.clone(),
            node_boot_id: source.node_boot_id.to_vec(),
            label_epoch: source.label_epoch,
            source_id: source.source_id.to_vec(),
            source_epoch: source.source_epoch,
        })
    );
    assert_eq!(receipt.cpu_id, 0);
    assert_eq!(receipt.contiguous_cursor, count);
    let Some(proto::query_frame::Payload::Rows(rows)) = &frame.payload else {
        return Err("query rows are absent".into());
    };
    assert!(!rows.limited);
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(
        rows.rows[0]
            .values
            .iter()
            .map(|value| value.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(Kind::Binary(source.tenant_id.to_vec())),
            Some(Kind::Binary(source.source_id.to_vec())),
            Some(Kind::Signed(count as i64)),
            Some(Kind::Unsigned(1)),
            Some(Kind::Unsigned(count)),
            Some(Kind::Unsigned(1)),
            Some(Kind::Unsigned(7)),
            Some(Kind::Null(true)),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn discovery_rpc_finite() -> TestResult {
    let fixture = Fixture::new()?;
    let source = source([1; 16]);
    retain(&fixture, &source, 1, 2)?;
    retain(
        &fixture,
        &EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..source.clone()
        },
        1,
        5,
    )?;
    let meta = fixture.service.data()?.store.meta()?;
    let mut stream = fixture
        .service
        .query(fixture.request(
            proto::QueryRequest {
                sql: SQL.into(),
                ..Default::default()
            },
            false,
        )?)
        .await?
        .into_inner();
    let frame = Fixture::next(&mut stream).await?;
    let Some(proto::query_frame::Payload::Metadata(metadata)) = frame.payload else {
        return Err("query metadata is absent".into());
    };
    assert_eq!(metadata.columns[2].name, "event_count");
    let rows = next_rows(&mut stream).await?;
    assert_rows(&rows, &source, 2)?;
    assert_eq!(rows.store_uuid, meta.store_uuid.as_bytes());
    assert_eq!(rows.recovery_epoch, meta.recovery_epoch);
    assert_eq!(rows.read_revision, meta.commit_revision);
    let mut completed = false;
    while let Some(frame) = tokio::time::timeout(WAIT, stream.next()).await? {
        match frame?.payload {
            Some(proto::query_frame::Payload::Terminal(terminal)) => {
                assert_eq!(terminal.reason, "Completed");
                assert!(!terminal.last_checkpoint.is_empty());
                completed = true;
            }
            Some(proto::query_frame::Payload::Error(error)) => {
                return Err(format!("query failed: {}", error.code).into());
            }
            Some(proto::query_frame::Payload::Rows(_)) => {
                return Err("finite query repeated its rows".into());
            }
            _ => {}
        }
    }
    assert!(completed);
    Ok(())
}

#[tokio::test]
async fn discovery_rpc_follow() -> TestResult {
    let fixture = Fixture::new()?;
    let source = source([1; 16]);
    retain(&fixture, &source, 1, 1)?;
    let mut stream = fixture
        .service
        .query(fixture.request(
            proto::QueryRequest {
                sql: SQL.into(),
                follow: true,
                ..Default::default()
            },
            false,
        )?)
        .await?
        .into_inner();
    let first = next_rows(&mut stream).await?;
    assert_rows(&first, &source, 1)?;
    retain(&fixture, &source, 2, 2)?;
    let next = next_rows(&mut stream).await?;
    assert_rows(&next, &source, 3)?;
    assert!(next.read_revision > first.read_revision);
    assert_eq!(next.store_uuid, first.store_uuid);
    assert_eq!(next.recovery_epoch, first.recovery_epoch);
    Ok(())
}

#[tokio::test]
async fn discovery_rpc_coverage() -> TestResult {
    use proto::query_value::Kind;

    let fixture = Fixture::new()?;
    let source = source([1; 16]);
    retain(&fixture, &source, 1, 2)?;
    let mut stream = fixture
        .service
        .query(
            fixture.request(
                proto::QueryRequest {
                    sql: "SELECT state, expected_records, coverage_revision,
                        array_to_string(gap_reasons, ',') AS reasons
                    FROM discovery.coverage_ranges(
                        (SELECT * FROM events), (SELECT * FROM coverage))"
                        .into(),
                    follow: true,
                    ..Default::default()
                },
                false,
            )?,
        )
        .await?
        .into_inner();
    let mut revision = 0;
    for (coverage, state, reason) in [
        (0, "UNKNOWN", "MISSING_COVERAGE_REPORT"),
        (1, "GAPPED", "SOURCE_COVERAGE_GAPPED"),
    ] {
        if coverage != 0 {
            fixture.service.data()?.store.accept_validated_coverage(
                araphor_data::ValidatedCoverageV1 {
                    identity: source.clone(),
                    cpu_id: 0,
                    revision: coverage,
                    encoded_report: araphor_data::CoverageReport {
                        source_id: source.source_id.to_vec(),
                        source_epoch: source.source_epoch,
                        cpu_id: 0,
                        revision: coverage,
                        intervals: vec![araphor_data::CoverageInterval {
                            interval_id: vec![4; 16],
                            source_epoch: source.source_epoch,
                            revision: coverage,
                            state: state.into(),
                            ..Default::default()
                        }],
                    }
                    .encode_to_vec(),
                },
            )?;
        }
        let frame = next_rows(&mut stream).await?;
        assert_eq!(frame.operation, proto::QueryOperation::Replace as i32);
        assert!(frame.read_revision > revision);
        revision = frame.read_revision;
        assert_eq!(frame.coverage.len(), 1);
        assert_eq!(frame.coverage[0].contiguous_cursor, 2);
        assert_eq!(frame.coverage[0].coverage_revision, coverage);
        let Some(proto::query_frame::Payload::Rows(rows)) = &frame.payload else {
            return Err("coverage rows are absent".into());
        };
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(
            rows.rows[0]
                .values
                .iter()
                .map(|value| value.kind.clone())
                .collect::<Vec<_>>(),
            [
                Some(Kind::Text(state.into())),
                Some(Kind::Unsigned(2)),
                Some(Kind::Unsigned(coverage)),
                Some(Kind::Text(reason.into())),
            ]
        );
    }
    Ok(())
}
