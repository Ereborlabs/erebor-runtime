use std::fs;

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{ControlStore, EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1};
use mithril_node::{EvidenceWalLimits, NodeControlMessage, TrustCache};
use tokio::time::{timeout, Duration};
use zerocopy::IntoBytes as _;

use super::{batch_source_id, control_store_lease_ready, registration};
use crate::control_fixture::MtlsFixture;
use crate::physical::wait_for_async;
use crate::platform::TestResult;

#[tokio::test]
async fn storage_failure_keeps_evidence() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let wait = Duration::from_secs(2);
    let mut limits = EvidenceStoreLimitsV1 {
        maximum_retained_bytes: mithril_control::MAX_EVIDENCE_SEGMENT_BYTES as u64,
        maximum_retained_records: 10,
        capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
    };
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
    for sequence in 1..=2 {
        event.observed_boottime_ns = sequence;
        event.source_sequence = sequence;
        event.task_cookie = sequence;
        wal.record_bytes(event.as_bytes());
    }
    let batch = wal.next_evidence_batch().ok_or("missing WAL batch")?;
    assert_eq!(batch.record_count(), 2);
    let identity = fixture.identity(batch_source_id(&batch)?);

    drop(ControlStore::open_with_evidence_limits(&path, limits)?);
    let retained = fixture.path().join("retained-control-evidence");
    fs::rename(&path, &retained)?;
    fs::write(&path, [])?;
    assert!(ControlStore::open_with_evidence_limits(&path, limits).is_err());
    assert_eq!(wal.pending_evidence_records(), 2);
    assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));
    fs::remove_file(&path)?;
    fs::rename(retained, &path)?;
    let mut trust = TrustCache::load(fixture.path())?;
    for capacity in [1, 10] {
        limits.maximum_retained_records = capacity;
        let store = wait_for_async(
            &path,
            "the stopped Control server to release its store lease",
            Duration::from_secs(5),
            || control_store_lease_ready(ControlStore::open_with_evidence_limits(&path, limits)),
            || "the stopped server still owns `owner.lock`".to_owned(),
        )
        .await?;
        let control = fixture.control_with_store(store.clone(), 1)?;
        let server = fixture.start(control).await?;
        let connector = fixture.connector(&server, "node-a", [7; 16]);
        let mut connection = connector.connect(registration(), false, &mut trust).await?;
        connection.send_evidence_group(vec![batch.clone()]).await?;
        let message = timeout(wait, connection.next_message())
            .await
            .map_err(|error| format!("capacity {capacity} response at {path:?}: {error}"))?;
        if capacity == 1 {
            assert!(message.is_err(), "Control acknowledged beyond capacity");
            assert_eq!(store.health()?.evidence_cursors, 0);
            assert_eq!(wal.pending_evidence_records(), 2);
            assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));
        } else {
            let NodeControlMessage::EvidenceAck(ack) = message? else {
                return Err("restored Control returned no acknowledgement".into());
            };
            assert_eq!(ack.contiguous_cursor, 2);
            assert_eq!(store.health()?.evidence_cursors, 1);
            let accepted = store.accepted_evidence_records(&identity)?;
            assert_eq!(accepted.len(), 2);
            assert_eq!(accepted, batch.decode_records()?);
            assert!(wal.acknowledge_evidence(ack)?);
            assert_eq!(wal.pending_evidence_records(), 0);
        }
        drop(connection);
        server.shutdown().await?;
    }
    Ok(())
}
