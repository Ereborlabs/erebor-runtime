use std::{fs, path::Path, time::Instant};

use mithril_control::{
    AuthenticatedEvidenceNodeV1, ControlStore, EvidenceBatch, EvidenceIntakeOwner,
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
    let store = ControlStore::open(tls.path().join("control-evidence"))?;
    let template = tls.effect_batch(RECORDS as usize)?;
    assert_eq!(template.record_count() as u64, RECORDS);
    let bytes = EvidenceBatch::from(template.clone()).encoded_len() as u64;
    assert!(bytes <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES as u64);
    let count = (mithril_control::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES as u64 / bytes)
        .min(mithril_control::MAX_EVIDENCE_BATCH_RECORDS as u64 / RECORDS)
        .max(1);
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
    let intake = EvidenceIntakeOwner::try_from(store.clone())?;

    let started = Instant::now();
    let receipt = intake.receive_group(batches)?;
    let elapsed = started.elapsed();
    let rate = bytes as f64 * count as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    eprintln!("direct Control intake completed in {elapsed:?}: {rate:.1} MiB/s");
    assert_eq!(receipt.contiguous_cursor, count * RECORDS);
    let source = tls.identity([9; 16]);
    let data = intake.analysis_store();
    assert_eq!(
        data.source_receipt(&source)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        count * RECORDS
    );
    assert_eq!(
        data.source_status(&source)?
            .ok_or("source absent")?
            .retained_event_count,
        count * RECORDS
    );
    assert!(!store.root().join("evidence/segments-v2").exists());
    let mut accepted = Vec::new();
    let mut cursor = 1;
    loop {
        let page = data.read_page(&source, cursor)?;
        accepted.extend(
            page.records
                .iter()
                .flat_map(|record| record.framed_record.iter().copied()),
        );
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(
        accepted,
        EvidenceBatch::from(template)
            .framed_records
            .repeat(usize::try_from(count)?)
    );
    Ok(())
}
