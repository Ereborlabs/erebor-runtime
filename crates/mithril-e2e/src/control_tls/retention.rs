use std::fs;
use std::time::Duration;

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{
    AuthenticatedEvidenceNodeV1, ControlStore, EvidenceConsumptionWatermarkV1, EvidenceIntakeOwner,
    EvidenceRetentionOwner, EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1,
};
use mithril_node::EvidenceWalLimits;
use zerocopy::IntoBytes as _;

use super::{batch_source_id, control_store_lease_ready};
use crate::control_fixture::MtlsFixture;
use crate::physical::wait_for;
use crate::platform::TestResult;

#[test]
fn consumption_reclaims_segments() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path().join("control-evidence");
    let segments = path.join("evidence/segments-v2");
    let limits = EvidenceStoreLimitsV1 {
        maximum_retained_bytes: mithril_control::MAX_EVIDENCE_SEGMENT_BYTES as u64,
        maximum_retained_records: 2,
        capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
    };
    let wal = fixture.wal(EvidenceWalLimits {
        maximum_batch_records: 1,
        ..EvidenceWalLimits::default()
    })?;
    let mut event = EffectObservationV1 {
        composite_atom_id: 1,
        reason: 1,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        configured_errno: -13,
        kernel_result: -13,
        ..EffectObservationV1::default()
    };
    for cursor in 1..=3 {
        event.observed_boottime_ns = cursor;
        event.source_sequence = cursor;
        event.task_cookie = cursor;
        wal.record_bytes(event.as_bytes());
    }
    let batches = wal.next_evidence_batches();
    assert_eq!(batches.len(), 3);
    let identity = fixture.identity(batch_source_id(&batches[0])?);
    let authenticated = AuthenticatedEvidenceNodeV1 {
        tenant_id: identity.tenant_id,
        node_id: identity.node_id.clone(),
        node_boot_id: identity.node_boot_id,
        label_epoch: identity.label_epoch,
    };
    let expected = batches[2].decode_records()?;
    let third: mithril_control::EvidenceBatch = batches[2].clone().into();
    {
        let store = ControlStore::open_with_evidence_limits(&path, limits)?;
        let intake = EvidenceIntakeOwner::from_store(store.clone());
        for batch in &batches[..2] {
            let ack = intake.receive(&authenticated, batch.clone().into())?;
            assert_eq!(ack.contiguous_cursor, batch.last_cursor);
        }
        assert!(intake.receive(&authenticated, third.clone()).is_err());
        assert_eq!(fs::read_dir(&segments)?.count(), 1);
        let retention = EvidenceRetentionOwner::from_store(store.clone());
        for (cursor, remaining) in [(1, 1), (2, 0)] {
            retention.acknowledge(EvidenceConsumptionWatermarkV1 {
                identity: identity.clone(),
                evidence_cursor: cursor,
                coverage_revision: 0,
            })?;
            assert_eq!(fs::read_dir(&segments)?.count(), remaining);
            assert_eq!(retention.watermark(&identity)?.evidence_cursor, cursor);
            if cursor == 1 {
                assert!(intake.receive(&authenticated, third.clone()).is_err());
            }
        }
        assert_eq!(intake.receive(&authenticated, third)?.contiguous_cursor, 3);
        assert_eq!(store.accepted_evidence_records(&identity)?, expected);
        assert_eq!(store.accepted_evidence_records(&identity)?.len(), 1);
        assert_eq!(fs::read_dir(&segments)?.count(), 1);
    }
    let store = wait_for(
        &path,
        "the compact evidence owners to release the store lease",
        Duration::from_secs(5),
        || control_store_lease_ready(ControlStore::open_with_evidence_limits(&path, limits)),
        || "a compact evidence owner still owns `owner.lock`".to_owned(),
    )?;
    let retention = EvidenceRetentionOwner::from_store(store.clone());
    assert_eq!(retention.watermark(&identity)?.evidence_cursor, 2);
    assert_eq!(store.evidence_cursor(&identity)?, 3);
    assert_eq!(store.accepted_evidence_records(&identity)?.len(), 1);
    assert_eq!(store.accepted_evidence_records(&identity)?, expected);
    Ok(())
}
