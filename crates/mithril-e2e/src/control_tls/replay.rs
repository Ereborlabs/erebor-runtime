use std::time::Duration;

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{ControlStore, EvidenceIntakeOwner};
use mithril_node::{EvidenceWalLimits, NodeControlMessage, TrustCache};
use snafu::ResultExt as _;
use zerocopy::IntoBytes as _;

use super::{batch_source_id, registration};
use crate::control_fixture::MtlsFixture;
use crate::error::PolicySnafu;
use crate::physical::wait_for_async;
use crate::platform::TestResult;

#[tokio::test]
async fn evidence_replays_once() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let store = ControlStore::open(&path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = fixture.control_with_store(store, 1)?;
    let server = fixture.start(control.clone()).await?;
    let wal = fixture.wal(EvidenceWalLimits {
        maximum_retained_records: 10,
        maximum_batch_records: 10,
        ..EvidenceWalLimits::default()
    })?;
    let mut event = EffectObservationV1 {
        reason: 9,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        ..EffectObservationV1::default()
    };
    for (sequence, cpu, cookie) in [(1, 0, 7), (1, 1, 8), (2, 0, 9)] {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.source_cpu_id = cpu;
        event.task_cookie = cookie;
        wal.record_bytes(event.as_bytes());
    }
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;
    let mut first = connector.connect(registration(), false, &mut trust).await?;
    let batch = wal.next_evidence_batch().ok_or("missing WAL batch")?;
    let source = batch_source_id(&batch)?;
    let identity = fixture.identity(source);
    first.send_evidence_batch(batch.clone()).await?;
    wait_for_async(
        &path,
        "Control to persist the first batch",
        Duration::from_secs(2),
        || {
            let cursor = intake.contiguous_cursor(&identity).context(PolicySnafu)?;
            Ok((cursor == batch.last_cursor).then_some(()))
        },
        || format!("last cursor: {:?}", intake.contiguous_cursor(&identity)),
    )
    .await?;
    drop(first);
    assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));

    let mut second = connector.connect(registration(), false, &mut trust).await?;
    assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));
    let mut sources = Vec::new();
    let mut count = 0;
    for _ in 0..2 {
        let batch = wal.next_evidence_batch().ok_or("missing source batch")?;
        let source = batch_source_id(&batch)?;
        second.send_evidence_batch(batch.clone()).await?;
        let message = tokio::time::timeout(Duration::from_secs(2), second.next_message())
            .await
            .map_err(|error| {
                format!("evidence acknowledgement for {source:?} at {path:?}: {error}")
            })??;
        let NodeControlMessage::EvidenceAck(ack) = message else {
            return Err("Control did not acknowledge the source batch".into());
        };
        wal.acknowledge_evidence(ack)?;
        let identity = fixture.identity(source);
        assert_eq!(intake.contiguous_cursor(&identity)?, batch.last_cursor);
        let records = intake.store().accepted_evidence_records(&identity)?;
        assert_eq!(records.len(), batch.record_count());
        assert_eq!(records, batch.decode_records()?);
        count += records.len();
        sources.push(source);
    }
    assert_eq!(sources[0], source);
    assert_ne!(sources[0], sources[1]);
    assert_eq!(count, 3);
    assert_eq!(control.registered_nonce_count(), 2);
    assert!(wal.next_evidence_batch().is_none());
    drop(second);
    server.shutdown().await?;
    Ok(())
}
