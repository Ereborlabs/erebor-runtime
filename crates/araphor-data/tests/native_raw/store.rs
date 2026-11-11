#![cfg(feature = "test-fixtures")]

use super::*;
use araphor_data::{
    analysis::{AnalysisStore, MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS},
    CoverageRecord, EVIDENCE_BATCH_RECORDS,
};
use std::path::PathBuf;

fn batch(first_cursor: u64, records: &[&[u8]]) -> ValidatedEvidenceBatchV1 {
    let mut framed_records = Vec::new();
    let mut frame_ends = Vec::new();
    for record in records {
        framed_records.extend_from_slice(record);
        frame_ends.push(framed_records.len());
    }
    ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor,
        last_cursor: first_cursor + records.len() as u64 - 1,
        intake_utc_ns: 1_000_000_000,
        framed_records: framed_records.into(),
        frame_ends,
    }
}

fn coverage(
    identity: &EvidenceIntakeIdentityV1,
    revision: u64,
    bytes: &[u8],
) -> ValidatedCoverageV1 {
    ValidatedCoverageV1 {
        identity: identity.clone(),
        cpu_id: 0,
        revision,
        encoded_report: bytes.to_vec(),
    }
}

fn reports(
    store: &AnalysisStore,
    identity: &EvidenceIntakeIdentityV1,
) -> Result<Vec<CoverageRecord>, Box<dyn std::error::Error>> {
    Ok(store.view()?.coverage_changes(
        &selection(identity),
        StorePositionV1 {
            commit_revision: 0,
            ordinal: u32::MAX,
        },
        &AnalysisReadControl::default(),
    )?)
}

fn relation_heads(store: &AnalysisStore) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    let prefix = b"\0data/relation/";
    store
        .view()?
        .snapshot()
        .prefix(prefix)
        .map(|row| {
            let (key, value) = row?;
            Ok((
                String::from_utf8(key[prefix.len()..].to_vec())?,
                u64::from_be_bytes(value.as_ref().try_into()?),
            ))
        })
        .collect()
}

#[test]
fn analysis_store_batch_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let identity = identity();
    let first = b"first".as_slice();
    let second = b"second".as_slice();
    let third = b"third".as_slice();

    let pending = batch(2, &[second]);
    assert_eq!(
        store.accept_validated_batch(identity.clone(), pending.clone())?,
        EvidenceStoreOutcomeV1::Pending
    );
    assert_eq!(
        store
            .source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        0
    );
    assert_eq!(
        store.accept_validated_batch(identity.clone(), batch(1, &[first]))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(
        store
            .source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        2
    );
    assert_eq!(store.meta()?.commit_revision, 2);
    assert_eq!(store.raw_index_fixture()?.counts(), (2, 2, 2));
    assert_eq!(
        store
            .source_status(&identity)?
            .ok_or("source status")?
            .retained_event_count,
        2
    );
    let records = store.read_page(&identity, 1)?.records;
    assert_eq!(
        records
            .iter()
            .map(|record| record.framed_record.as_slice())
            .collect::<Vec<_>>(),
        [first, second]
    );
    assert_eq!(
        records[0].position,
        StorePositionV1 {
            commit_revision: 2,
            ordinal: 0
        }
    );
    assert_eq!(
        store.read_page(&identity, 2)?.records[0].position,
        StorePositionV1 {
            commit_revision: 1,
            ordinal: 0
        }
    );
    assert_eq!(
        store.accept_validated_batch(identity.clone(), pending)?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(store.meta()?.commit_revision, 2);

    assert!(store
        .accept_validated_batch(identity.clone(), batch(2, &[b"changed"]))
        .is_err());
    assert_eq!(store.meta()?.commit_revision, 2);

    assert_eq!(
        store.accept_validated_batch(identity.clone(), batch(4, &[third]))?,
        EvidenceStoreOutcomeV1::Pending
    );
    assert!(store
        .accept_validated_batch(identity.clone(), batch(3, &[third, b"changed"]))
        .is_err());
    assert_eq!(store.meta()?.commit_revision, 3);
    assert_eq!(
        store
            .source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        2
    );
    assert_eq!(
        store
            .source_status(&identity)?
            .ok_or("source absent")?
            .retained_event_count,
        3
    );
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(
        reopened
            .source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        2
    );
    assert_eq!(
        reopened.accept_validated_batch(identity.clone(), batch(3, &[third]))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(
        reopened
            .source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        4
    );
    let mut relabeled = identity.clone();
    relabeled.label_epoch += 1;
    assert!(reopened
        .accept_validated_batch(relabeled, batch(1, &[b"first"]))
        .is_err());
    let mut rebooted = identity.clone();
    rebooted.node_boot_id = [9; 16];
    assert!(reopened
        .accept_validated_batch(rebooted, batch(1, &[first]))
        .is_err());
    let mut changed_cpu = batch(5, &[first]);
    changed_cpu.cpu_id = 1;
    assert!(reopened
        .accept_validated_batch(identity.clone(), changed_cpu)
        .is_err());
    reopened.accept_validated_batch(identity.clone(), batch(5, &[first, second, third]))?;
    assert_eq!(
        reopened
            .source_status(&identity)?
            .ok_or("source absent")?
            .retained_event_count,
        7
    );
    assert_eq!(reopened.raw_index_fixture()?.range_count(&identity), 5);

    let revision = reopened.meta()?.commit_revision;
    reopened.accept_validated_coverage(coverage(&identity, 1, b"coverage"))?;
    assert_eq!(*reopened.subscribe_revision().borrow(), revision + 1);
    reopened.recover()?;
    reopened.accept_validated_batch(identity.clone(), batch(8, &[first]))?;
    assert_eq!(reopened.meta()?.commit_revision, revision + 2);
    assert_eq!(*reopened.subscribe_revision().borrow(), revision + 2);
    assert_eq!(
        reopened.read_page(&identity, 8)?.records[0]
            .position
            .commit_revision,
        revision + 2
    );
    let raw_revision = reopened.meta()?.commit_revision;
    let mut probe = reopened.write()?;
    probe.native().insert(b"core-relation-probe", b"published");
    probe.commit([])?;
    assert_eq!(reopened.meta()?.commit_revision, raw_revision + 1);
    let changes = relation_heads(&reopened)?;
    assert_eq!(
        changes,
        vec![
            ("coverage".into(), revision + 1),
            ("events".into(), revision + 2),
            ("source_bindings".into(), 1),
            ("source_receipts".into(), revision + 2),
        ]
    );
    Ok(())
}

#[test]
fn analysis_store_bulk_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let identity = identity();
    let maximum = EVIDENCE_BATCH_RECORDS + 1;
    store.accept_validated_batch(identity.clone(), batch(maximum as u64, &[b"frame"]))?;
    let before = store.meta()?;
    let mut changes = store.subscribe_revision();
    let _revision = *changes.borrow_and_update();
    let mut records = vec![b"frame".as_slice(); maximum];
    records[maximum - 1] = b"conflict";
    assert!(store
        .accept_validated_batch(identity.clone(), batch(1, &records))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(!changes.has_changed()?);
    assert_eq!(
        store
            .source_status(&identity)?
            .ok_or("source absent")?
            .retained_event_count,
        1
    );
    records[maximum - 1] = b"frame";
    assert_eq!(
        store.accept_validated_batch(identity.clone(), batch(1, &records))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
    let revision = store.meta()?.commit_revision;
    store.accept_validated_batch(identity.clone(), batch(1, &records))?;
    assert_eq!(store.meta()?.commit_revision, revision);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let status = reopened.source_status(&identity)?.ok_or("source absent")?;
    assert_eq!(status.retained_event_count, maximum as u64);
    assert_eq!(status.receipt.contiguous_cursor, maximum as u64);
    Ok(())
}

#[test]
fn analysis_store_bounded_read() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let identity = identity();
    let mut changed = store.subscribe_revision();
    assert_eq!(*changed.borrow_and_update(), 0);
    let records = vec![b"one".as_slice(); 2 * MAX_ANALYSIS_PAGE_RECORDS + 1];
    assert_eq!(
        store.accept_validated_batch(identity.clone(), batch(1, &records))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert!(changed.has_changed()?);
    assert_eq!(*changed.borrow_and_update(), 1);
    let page = store.read_page(&identity, 1)?;
    assert_eq!(page.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
    assert_eq!(page.encoded_bytes, 3 * MAX_ANALYSIS_PAGE_RECORDS);
    assert_eq!(page.next_cursor, Some(257));
    assert_eq!(page.read_revision, 1);
    assert_eq!(page.records[0].position.commit_revision, 1);
    assert_eq!(page.records[0].position.ordinal, 0);
    assert_eq!(page.records[255].position.ordinal, 255);
    let middle = store.read_page(&identity, 257)?;
    assert_eq!(middle.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
    assert_eq!(middle.records[0].cursor, 257);
    assert_eq!(middle.records[255].cursor, 512);
    assert_eq!(middle.next_cursor, Some(513));
    let last = store.read_page(&identity, 513)?;
    assert_eq!(last.records.len(), 1);
    assert_eq!(last.next_cursor, None);
    let empty = store.read_page(&identity, 514)?;
    assert!(empty.records.is_empty());
    assert_eq!(empty.next_cursor, None);
    assert!(store.read_page(&identity, 0).is_err());
    assert!(store.read_page(&identity, 515).is_err());
    let mut foreign = identity.clone();
    foreign.tenant_id = [4; 16];
    assert!(store.read_page(&foreign, 1).is_err());
    assert_eq!(
        store.accept_validated_batch(identity.clone(), batch(1, &records))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert!(!changed.has_changed()?);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(*reopened.subscribe_revision().borrow(), 1);
    assert_eq!(reopened.read_page(&identity, 257)?, middle);
    assert_eq!(reopened.read_page(&identity, 513)?, last);
    let mut large = identity.clone();
    large.source_epoch = 2;
    let frame = vec![42; MAX_ANALYSIS_PAGE_BYTES / 8];
    let frames = vec![frame.as_slice(); 9];
    reopened.accept_validated_batch(large.clone(), batch(1, &frames))?;
    let page = reopened.read_page(&large, 1)?;
    assert_eq!(page.records.len(), 8);
    assert_eq!(page.encoded_bytes, MAX_ANALYSIS_PAGE_BYTES);
    assert_eq!(page.next_cursor, Some(9));
    assert_eq!(
        reopened.read_page(&large, 9)?.records[0].framed_record,
        frame
    );
    let cached = reopened.read_page(&identity, 1)?;
    let mut anchor = reopened.write()?;
    anchor.native().insert(b"core-page-anchor", b"published");
    anchor.commit([])?;
    let view = reopened.view()?;
    let ends = view
        .snapshot()
        .prefix(b"\0data/raw/end/")
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<fjall::Result<Vec<_>>>()?;
    assert_eq!(ends.len(), 2);
    drop(view);
    let mut transaction = reopened.write()?;
    transaction.native().remove(ends[0].clone());
    transaction.commit([])?;
    let page = reopened.read_page(&identity, 1)?;
    assert_eq!(page.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
    assert_eq!(page.records, cached.records);
    assert_eq!(page.encoded_bytes, cached.encoded_bytes);
    assert_eq!(page.next_cursor, cached.next_cursor);
    assert!(matches!(
        reopened.recover(),
        Err(araphor_data::Error::NativeState {
            field: "raw segment baseline",
            ..
        })
    ));
    drop(reopened);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(araphor_data::Error::NativeState {
            field: "raw segment baseline",
            ..
        })
    ));
    Ok(())
}

#[test]
fn analysis_store_coverage_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let mut identity = identity();
    identity.node_id = "n".repeat(128);
    assert_eq!(store.source_status(&identity)?, None);
    let accepted = coverage(&identity, 1, b"coverage-1");
    assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
    assert_eq!(store.meta()?.commit_revision, 1);
    assert_eq!(reports(&store, &identity)?.len(), 1);
    let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
    assert_eq!(receipt.contiguous_cursor, 0);
    assert_eq!(receipt.coverage_revision, 1);
    let status = store.source_status(&identity)?.ok_or("status absent")?;
    assert_eq!(status.receipt, receipt);
    assert_eq!(status.retained_event_count, 0);
    assert_eq!(status.latest_coverage_report, Some(b"coverage-1".to_vec()));
    assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
    assert_eq!(store.meta()?.commit_revision, 1);
    assert_eq!(reports(&store, &identity)?.len(), 1);

    let conflicting = coverage(&identity, 1, b"changed");
    assert!(store.accept_validated_coverage(conflicting).is_err());
    assert_eq!(store.meta()?.commit_revision, 1);

    let newer = coverage(&identity, 3, b"coverage-3");
    assert_eq!(store.accept_validated_coverage(newer)?, 3);
    assert_eq!(store.meta()?.commit_revision, 2);
    let stale = coverage(&identity, 2, b"coverage-2");
    assert!(store.accept_validated_coverage(stale).is_err());
    assert_eq!(store.meta()?.commit_revision, 2);
    assert_eq!(reports(&store, &identity)?.len(), 2);
    store.recover()?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.meta()?.commit_revision, 2);
    let receipt = reopened
        .source_receipt(&identity)?
        .ok_or("receipt absent")?;
    assert_eq!(receipt.coverage_revision, 3);
    assert_eq!(receipt.contiguous_cursor, 0);
    let status = reopened.source_status(&identity)?.ok_or("status absent")?;
    assert_eq!(status.receipt, receipt);
    assert_eq!(status.latest_coverage_report, Some(b"coverage-3".to_vec()));
    let records = reports(&reopened, &identity)?;
    assert_eq!(records.len(), 2);
    reopened.recover()?;
    assert_eq!(
        relation_heads(&reopened)?
            .into_iter()
            .filter(|(_, revision)| *revision == 2)
            .collect::<Vec<_>>(),
        vec![("coverage".into(), 2), ("source_receipts".into(), 2)]
    );
    let reference = &records[1].reference;
    assert_eq!(reference.revision, 3);
    let key = [
        b"\0data/coverage/report/".as_slice(),
        &identity.key(),
        &3u64.to_be_bytes(),
    ]
    .concat();
    let mut bytes = vec![0];
    bytes.extend(rmp_serde::to_vec(&(reference, Vec::<u8>::new()))?);
    let mut transaction = reopened.write()?;
    assert!(transaction.native().get(&key)?.is_some());
    transaction.native().insert(key, bytes);
    transaction.commit([])?;
    assert!(reopened.source_status(&identity).is_err());
    Ok(())
}

#[test]
fn analysis_store_limit_edges() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let mut source = identity();
    source.node_id = "n".repeat(araphor_data::MAX_NODE_ID_BYTES);
    let mut max_batch = ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: 1,
        last_cursor: EVIDENCE_BATCH_RECORDS as u64,
        intake_utc_ns: 1_000_000_000,
        framed_records: vec![1; EVIDENCE_BATCH_RECORDS].into(),
        frame_ends: (1..=EVIDENCE_BATCH_RECORDS).collect(),
    };
    {
        let check = AnalysisStore::open(
            directory
                .path()
                .join(format!("validate-{}", max_batch.last_cursor)),
        )?;
        assert_eq!(
            check.accept_validated_batch(source.clone(), max_batch.clone())?,
            EvidenceStoreOutcomeV1::Accepted
        );
    }
    max_batch.last_cursor += 1;
    max_batch.framed_records = vec![1; EVIDENCE_BATCH_RECORDS + 1].into();
    max_batch.frame_ends.push(EVIDENCE_BATCH_RECORDS + 1);
    {
        let check = AnalysisStore::open(
            directory
                .path()
                .join(format!("validate-{}", max_batch.last_cursor)),
        )?;
        assert_eq!(
            check.accept_validated_batch(source.clone(), max_batch.clone())?,
            EvidenceStoreOutcomeV1::Accepted
        );
    }
    source.node_id.push('n');
    assert!(store
        .accept_validated_batch(source.clone(), batch(1, &[b"first"]))
        .is_err());
    assert_eq!(store.meta()?.commit_revision, 0);
    source.node_id.pop();

    let pending = EVIDENCE_BATCH_RECORDS as u64 + 2;
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(pending, &[b"gap"]))?,
        EvidenceStoreOutcomeV1::Pending
    );
    let revision = store.meta()?.commit_revision;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?.commit_revision, revision);
    assert_eq!(
        store.accept_validated_batch(
            source.clone(),
            batch(1, &vec![b"frame".as_slice(); pending as usize - 1])
        )?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(
        store
            .source_receipt(&source)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        pending
    );
    let report = vec![1; 4 * 1_024 * 1_024 + 1];
    store.accept_validated_coverage(coverage(&source, 1, &report))?;
    assert_eq!(
        store
            .source_status(&source)?
            .ok_or("source absent")?
            .latest_coverage_report,
        Some(report)
    );
    Ok(())
}

#[test]
fn analysis_store_crash_replay() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let identity = identity();
    if let Some(root) = std::env::var_os("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT") {
        let store = AnalysisStore::open(PathBuf::from(root))?;
        assert_eq!(
            store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        std::process::exit(73);
    }

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let status = std::process::Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("store::analysis_store_crash_replay")
        .env("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT", &root)
        .status()?;
    assert_eq!(status.code(), Some(73));
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?.commit_revision, 1);
    assert_eq!(
        store
            .source_receipt(&identity)?
            .ok_or("receipt absent after crash")?
            .contiguous_cursor,
        1
    );
    assert_eq!(
        store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(store.meta()?.commit_revision, 1);
    Ok(())
}
