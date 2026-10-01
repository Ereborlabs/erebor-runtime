use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{ControlStore, EvidenceIntakeOwner};
use mithril_node::{
    EvidenceWalCapacityPolicyV1, EvidenceWalLimits, NodeControlMessage, TrustCache,
};
use tokio::time::{timeout, Duration};
use zerocopy::IntoBytes as _;

use super::{batch_source_id, registration};
use crate::control_fixture::MtlsFixture;
use crate::platform::TestResult;

#[tokio::test]
async fn retained_wal_survives_restart() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let store = ControlStore::open(&path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = fixture.control_with_store(store, 1)?;
    let server = fixture.start(control.clone()).await?;
    let limits = EvidenceWalLimits {
        maximum_retained_records: 3,
        maximum_batch_records: 4_096,
        capacity_policy: EvidenceWalCapacityPolicyV1::Retain,
        ..EvidenceWalLimits::default()
    };
    let wal = fixture.wal(limits)?;
    let mut event = EffectObservationV1 {
        reason: 9,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        ..EffectObservationV1::default()
    };
    for sequence in 1..=2 {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.task_cookie = sequence;
        wal.record_bytes(event.as_bytes());
    }
    let retained = wal
        .next_evidence_batch()
        .ok_or("missing retained WAL batch")?;
    assert_eq!(retained.record_count(), 2);
    assert_eq!(wal.pending_evidence_records(), 2);
    drop(wal);

    let wal = fixture.wal(limits)?;
    assert_eq!(wal.pending_evidence_records(), 2);
    for sequence in 3..=303 {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.task_cookie = sequence;
        wal.record_bytes(event.as_bytes());
    }
    assert_eq!(wal.pending_evidence_records(), 303);
    let batches = wal.next_evidence_batches();
    let [batch] = batches.as_slice() else {
        return Err("retained records must form one complete batch".into());
    };
    assert_eq!(batch.record_count(), 303);
    assert_eq!(batch.first_cursor, 1);
    assert_eq!(batch.last_cursor, 303);
    let records = batch.decode_records()?;
    assert_eq!(&records[..2], retained.decode_records()?.as_slice());
    let source = batch_source_id(batch)?;
    assert_eq!(source, batch_source_id(&retained)?);
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    connection.send_evidence_group(batches.clone()).await?;
    let message = timeout(Duration::from_secs(2), connection.next_message())
        .await
        .map_err(|error| {
            format!("retained group acknowledgement for {source:?} at {path:?}: {error}")
        })??;
    let NodeControlMessage::EvidenceAck(ack) = message else {
        return Err("Control returned no retained-group acknowledgement".into());
    };
    assert_eq!(ack.contiguous_cursor, 303);
    assert!(wal.acknowledge_evidence(ack)?);
    assert_eq!(wal.pending_evidence_records(), 0);
    assert!(wal.next_evidence_batch().is_none());
    assert_eq!(control.registered_nonce_count(), 1);
    let identity = fixture.identity(source);
    assert_eq!(intake.contiguous_cursor(&identity)?, 303);
    let accepted = intake.store().accepted_evidence_records(&identity)?;
    assert_eq!(accepted.len(), 303);
    assert_eq!(accepted, records);
    drop(connection);
    server.shutdown().await?;
    Ok(())
}
