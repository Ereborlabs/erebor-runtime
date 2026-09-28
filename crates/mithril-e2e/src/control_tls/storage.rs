use std::{fs, sync::Arc};

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{ControlStore, EvidenceIntakeOwner, SystemIntakeClock};
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

    drop(ControlStore::open(&path)?);
    let retained = fixture.path().join("retained-control-evidence");
    fs::rename(&path, &retained)?;
    fs::write(&path, [])?;
    assert!(ControlStore::open(&path).is_err());
    assert_eq!(wal.pending_evidence_records(), 2);
    assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));
    fs::remove_file(&path)?;
    fs::rename(retained, &path)?;
    let mut trust = TrustCache::load(fixture.path())?;
    for capacity in [1, araphor_data::StorageLimitsV1::default().tenant_max_bytes] {
        let store = wait_for_async(
            &path,
            "the stopped Control server to release its store lease",
            Duration::from_secs(5),
            || control_store_lease_ready(ControlStore::open(&path)),
            || "the stopped server still owns `owner.lock`".to_owned(),
        )
        .await?;
        let data = Arc::new(araphor_data::AnalysisStore::open_with_limits(
            store.root().join("analysis"),
            Default::default(),
            araphor_data::StorageLimitsV1 {
                tenant_max_bytes: capacity,
                ..Default::default()
            },
        )?);
        let intake =
            EvidenceIntakeOwner::new(store.clone(), data.clone(), Arc::new(SystemIntakeClock))?;
        let control = fixture.control_from_intake(intake.clone(), 1)?;
        let server = fixture.start(control).await?;
        let connector = fixture.connector(&server, "node-a", [7; 16]);
        let mut connection = connector.connect(registration(), false, &mut trust).await?;
        connection.send_evidence_group(vec![batch.clone()]).await?;
        let message = timeout(wait, connection.next_message())
            .await
            .map_err(|error| format!("capacity {capacity} response at {path:?}: {error}"))?;
        if capacity == 1 {
            assert!(message.is_err(), "Control acknowledged beyond capacity");
            assert_eq!(intake.contiguous_cursor(&identity)?, 0);
            assert!(data.source_receipt(&identity)?.is_none());
            assert_eq!(wal.pending_evidence_records(), 2);
            assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));
        } else {
            let NodeControlMessage::EvidenceAck(ack) = message? else {
                return Err("restored Control returned no acknowledgement".into());
            };
            assert_eq!(ack.contiguous_cursor, 2);
            assert_eq!(intake.contiguous_cursor(&identity)?, 2);
            let accepted = data.read_page(&identity, 1)?;
            assert_eq!(accepted.records.len(), 2);
            assert_eq!(
                accepted
                    .records
                    .iter()
                    .flat_map(|record| record.framed_record.iter().copied())
                    .collect::<Vec<_>>(),
                mithril_control::EvidenceBatch::from(batch.clone())
                    .framed_records
                    .to_vec()
            );
            assert!(wal.acknowledge_evidence(ack)?);
            assert_eq!(wal.pending_evidence_records(), 0);
        }
        assert!(!store.root().join("evidence/segments-v2").exists());
        drop(connection);
        server.shutdown().await?;
    }
    Ok(())
}
