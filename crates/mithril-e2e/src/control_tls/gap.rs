use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{ControlStore, EvidenceIntakeOwner};
use mithril_node::{EvidenceWalLimits, NodeControlMessage, TrustCache};
use tokio::time::{timeout, Duration};
use zerocopy::IntoBytes as _;

use super::{batch_source_id, control_store_lease_ready, registration};
use crate::control_fixture::MtlsFixture;
use crate::physical::wait_for_async;
use crate::platform::TestResult;

#[tokio::test]
async fn evidence_gap_survives_restart() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let wait = Duration::from_secs(2);
    let wal = fixture.wal(EvidenceWalLimits {
        maximum_retained_records: 10,
        maximum_batch_records: 1,
        ..EvidenceWalLimits::default()
    })?;
    let mut event = EffectObservationV1 {
        reason: 9,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        ..EffectObservationV1::default()
    };
    for sequence in 1..=3 {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.task_cookie = sequence;
        wal.record_bytes(event.as_bytes());
    }
    let batches = wal.next_evidence_batches();
    let cursors: Vec<_> = batches
        .iter()
        .map(|batch| (batch.first_cursor, batch.last_cursor))
        .collect();
    assert_eq!(cursors, [(1, 1), (2, 2), (3, 3)]);
    let identity = fixture.identity(batch_source_id(&batches[0])?);
    let mut trust = TrustCache::load(fixture.path())?;
    {
        let store = ControlStore::open(&path)?;
        let intake = EvidenceIntakeOwner::from_store(store.clone());
        let control = fixture.control_with_store(store.clone(), 1)?;
        let server = fixture.start(control).await?;
        let connector = fixture.connector(&server, "node-a", [7; 16]);
        let mut connection = connector.connect(registration(), false, &mut trust).await?;
        connection.send_evidence_batch(batches[2].clone()).await?;
        let message = timeout(wait, connection.next_message())
            .await
            .map_err(|error| format!("gap rejection at {path:?}: {error}"))?;
        assert!(message.is_err(), "Control acknowledged a cursor gap");
        assert_eq!(intake.contiguous_cursor(&identity)?, 0);
        assert_eq!(store.health()?.pending_evidence_records, 1);
        assert_eq!(wal.pending_evidence_records(), 3);
        drop(connection);
        server.shutdown().await?;
    }
    let store = wait_for_async(
        &path,
        "the stopped Control server to release its evidence-store lease",
        Duration::from_secs(5),
        || control_store_lease_ready(ControlStore::open(&path)),
        || "the stopped server still owns the evidence store `owner.lock`".to_owned(),
    )
    .await?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    assert_eq!(intake.contiguous_cursor(&identity)?, 0);
    assert_eq!(store.health()?.pending_evidence_records, 1);
    let control = fixture.control_with_store(store.clone(), 1)?;
    let server = fixture.start(control).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let mut ack = None;
    for group in [batches[..2].to_vec(), batches.clone()] {
        connection.send_evidence_group(group).await?;
        let message = timeout(wait, connection.next_message())
            .await
            .map_err(|error| format!("cumulative acknowledgement at {path:?}: {error}"))??;
        let NodeControlMessage::EvidenceAck(received) = message else {
            return Err("Control returned no cumulative acknowledgement".into());
        };
        assert_eq!(received.contiguous_cursor, 3);
        assert_eq!(intake.contiguous_cursor(&identity)?, 3);
        assert_eq!(store.health()?.pending_evidence_records, 0);
        if let Some(previous) = ack {
            assert_eq!(received, previous);
        }
        ack = Some(received);
    }
    assert!(wal.acknowledge_evidence(ack.ok_or("missing acknowledgement")?)?);
    assert_eq!(wal.pending_evidence_records(), 0);
    assert_eq!(store.accepted_evidence_records(&identity)?.len(), 3);
    drop(connection);
    server.shutdown().await?;
    Ok(())
}
