use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use mithril_control as control;
use mithril_node::{NodeControlMessage, TrustCache};
use prost::Message as _;

use super::{batch_source_id, registration, transfer::GrpcTransfer};
use crate::{control_fixture::MtlsFixture, platform::TestResult};

#[tokio::test]
#[ignore = "requires release optimization"]
async fn backlog_beats_previous_budget() -> TestResult<()> {
    const RECORDS: u64 = 4_096;
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&target)?;
    let tls = MtlsFixture::in_directory(tempfile::tempdir_in(target)?, false)?;
    let path = tls.path().display();
    let store = control::ControlStore::open(tls.path().join("control-evidence"))?;
    let intake = control::EvidenceIntakeOwner::try_from(store.clone())?;
    let server = tls
        .start(tls.control_from_intake(intake.clone(), 1)?)
        .await?;
    let template = tls.effect_batch(RECORDS as usize)?;
    assert_eq!(template.record_count() as u64, RECORDS);
    let bytes = control::EvidenceBatch::from(template.clone()).encoded_len() as u64;
    assert!(bytes <= control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES as u64);
    let count = (512 * 1_024 * 1_024_u64).div_ceil(bytes);
    let total = count * bytes;
    let limit = (control::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES as u64 / bytes)
        .min(control::MAX_EVIDENCE_BATCH_RECORDS as u64 / RECORDS)
        .max(1);
    for path in [None, Some(tls.path().join("grpc-received.bin"))] {
        let (elapsed, rate) = GrpcTransfer::new(path.clone())
            .measure(&tls.files, total)
            .await?;
        eprintln!("raw transfer {path:?}: {total} bytes, {elapsed:?}, {rate:.1} MiB/s");
    }
    let connector = tls.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(&tls.path().join("trust"))?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let (mut prep, mut enqueue, mut ack) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut receipts = 0;
    let started = Instant::now();
    for first in (0..count).step_by(limit as usize) {
        let end = (first + limit).min(count);
        let cursor = end * RECORDS;
        let phase = Instant::now();
        let group = (first..end)
            .map(|index| {
                let mut batch = template.clone();
                batch.first_cursor = index * RECORDS + 1;
                batch.last_cursor = (index + 1) * RECORDS;
                batch
            })
            .collect();
        prep += phase.elapsed();
        let phase = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(30),
            connection.send_evidence_group(group),
        )
        .await
        .map_err(|error| format!("{path}: send through cursor {cursor}: {error}"))??;
        enqueue += phase.elapsed();
        let phase = Instant::now();
        let message = tokio::time::timeout(Duration::from_secs(30), connection.next_message())
            .await
            .map_err(|error| format!("{path}: wait for cursor {cursor}: {error}"))??;
        let NodeControlMessage::EvidenceAck(receipt) = message else {
            return Err("Control did not acknowledge the throughput group".into());
        };
        assert_eq!(receipt.contiguous_cursor, cursor);
        ack += phase.elapsed();
        receipts += 1;
    }
    let elapsed = started.elapsed();
    let rate = total as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    eprintln!("acknowledged {total} bytes: {elapsed:?}, {rate:.1} MiB/s (target 300.0); receipts={receipts} prepare={prep:?} enqueue={enqueue:?} control_ack={ack:?}");
    assert_eq!(receipts, count.div_ceil(limit));
    assert_eq!(
        intake.contiguous_cursor(&tls.identity(batch_source_id(&template)?))?,
        count * RECORDS
    );
    assert_eq!(
        intake
            .analysis_store()
            .source_status(&tls.identity(batch_source_id(&template)?))?
            .ok_or("source absent")?
            .retained_event_count,
        count * RECORDS
    );
    assert!(!store.root().join("evidence/segments-v2").exists());
    drop(connection);
    server.shutdown().await?;
    assert!(rate > 107.1, "{rate:.1} MiB/s <= 107.1 MiB/s");
    Ok(())
}
