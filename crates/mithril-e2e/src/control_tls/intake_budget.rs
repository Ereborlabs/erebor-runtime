use std::{fs, path::Path, time::Instant};

use mithril_control::{
    AuthenticatedEvidenceNodeV1, ControlStore, EvidenceBatch, EvidenceIntakeOwner,
    EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1,
};
use mithril_node::EvidenceIdV1;
use prost::Message as _;

use crate::{control_fixture::MtlsFixture, platform::TestResult};

#[test]
#[ignore = "requires release optimization"]
fn direct_intake_commits_group() -> TestResult<()> {
    const RECORDS: u64 = 4_096;
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&target)?;
    let tls = MtlsFixture::in_directory(tempfile::tempdir_in(target)?, false)?;
    let store = ControlStore::open_with_evidence_limits(
        tls.path().join("control-evidence"),
        EvidenceStoreLimitsV1 {
            capacity_policy: EvidenceStoreCapacityPolicyV1::Retain,
            ..Default::default()
        },
    )?;
    let template = tls.effect_batch(RECORDS as usize)?;
    assert_eq!(template.record_count() as u64, RECORDS);
    let bytes = EvidenceBatch::from(template.clone()).encoded_len() as u64;
    assert!(bytes <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES as u64);
    let count = (mithril_control::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES as u64 / bytes).max(1);
    let identity = AuthenticatedEvidenceNodeV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
    };
    let mut batches = Vec::new();
    for index in 0..count {
        let mut batch = template.clone();
        batch.first_cursor = index * RECORDS + 1;
        batch.last_cursor = (index + 1) * RECORDS;
        let mut batch = EvidenceBatch::from(batch);
        batch.source_id = vec![9; 16];
        batches.push((identity.clone(), batch));
    }
    let intake = EvidenceIntakeOwner::from_store(store.clone());

    let started = Instant::now();
    let receipt = intake.receive_group(batches)?;
    let elapsed = started.elapsed();
    let rate = bytes as f64 * count as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    eprintln!("direct Control intake completed in {elapsed:?}: {rate:.1} MiB/s");
    assert_eq!(receipt.contiguous_cursor, count * RECORDS);
    let source = tls.identity([9; 16]);
    assert_eq!(store.evidence_cursor(&source)?, count * RECORDS);
    assert_eq!(store.health()?.pending_evidence_records, 0);
    let records = template.decode_records()?;
    assert_eq!(
        store.accepted_evidence_records(&source)?,
        (0..count)
            .flat_map(|_| records.iter().cloned())
            .collect::<Vec<_>>()
    );
    Ok(())
}
