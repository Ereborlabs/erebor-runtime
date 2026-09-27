use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Instant;

use prost::Message as _;

use super::{ControlStore, EvidenceBatchInputV1, EvidenceIntakeIdentityV1, EvidenceRecord};

fn sizes_in(path: &Path) -> std::io::Result<(u64, u64)> {
    let mut logical = 0;
    let mut allocated = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let (file_bytes, disk_bytes) = if metadata.is_dir() {
            sizes_in(&entry.path())?
        } else {
            (metadata.len(), metadata.blocks() * 512)
        };
        logical += file_bytes;
        allocated += disk_bytes;
    }
    Ok((logical, allocated))
}

#[test]
#[ignore = "run alone in release mode with ARAPHOR_STORE_BENCH_MODE and ARAPHOR_STORE_BENCH_BATCHES"]
fn raw_event_store_comparison() -> Result<(), Box<dyn std::error::Error>> {
    const RECORDS_PER_BATCH: u64 = 256;

    let mode = std::env::var("ARAPHOR_STORE_BENCH_MODE")?;
    let batch_count: u64 = std::env::var("ARAPHOR_STORE_BENCH_BATCHES")?.parse()?;
    if !matches!(mode.as_str(), "segments" | "duckdb") || batch_count == 0 {
        return Err("invalid raw event benchmark configuration".into());
    }
    let total = batch_count * RECORDS_PER_BATCH;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".to_owned(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let mut batches = Vec::new();
    let mut input_bytes = 0_u64;
    for index in 0..batch_count {
        let first = index * RECORDS_PER_BATCH + 1;
        let records = (first..first + RECORDS_PER_BATCH)
            .map(|cursor| EvidenceRecord {
                observed_boottime_ns: cursor,
                ingested_utc_ns: cursor as i64,
                coverage_interval_id: vec![4; 16].into(),
                task_cookie: cursor,
                process_lineage_id: vec![cursor as u8; 16].into(),
                authority_domain_id: vec![5; 16].into(),
                execution_set_id: vec![6; 16].into(),
                exact_object_id: vec![cursor.rotate_left(11) as u8; 32].into(),
                reason: 1,
                decision: 1,
                effect_family: 1,
                operation: 1,
                configured_errno: -13,
                kernel_result: -13,
                temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                ..EvidenceRecord::default()
            })
            .collect();
        let batch = EvidenceBatchInputV1::encode(first, records)?;
        input_bytes += batch.framed_records.len() as u64;
        batches.push(batch);
    }

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let open_start = Instant::now();
    let mut latency = Vec::new();
    let (open, write, reopen, read, empty, written, closed) = if mode == "segments" {
        let store = ControlStore::open(&root)?;
        let open = open_start.elapsed();
        let empty = sizes_in(&root)?;
        let write_start = Instant::now();
        for batch in &batches {
            let start = Instant::now();
            assert_eq!(
                store.accept_evidence_batch(identity.clone(), batch.clone())?,
                crate::EvidenceStoreOutcomeV1::Accepted
            );
            latency.push(start.elapsed());
        }
        let write = write_start.elapsed();
        assert_eq!(store.evidence_cursor(&identity)?, total);
        let written = sizes_in(&root)?;
        drop(store);
        let reopen_start = Instant::now();
        let store = ControlStore::open(&root)?;
        let reopen = reopen_start.elapsed();
        let closed = sizes_in(&root)?;
        let read_start = Instant::now();
        let handle = store.begin_evidence_read(&identity, 1)?;
        let mut next = 1;
        while next <= total {
            let page = store.read_evidence_page(&handle, next)?;
            assert!(!page.records.is_empty());
            for (offset, record) in page.records.iter().enumerate() {
                assert_eq!(record.observed_boottime_ns, next + offset as u64);
            }
            next += page.records.len() as u64;
        }
        (
            open,
            write,
            reopen,
            read_start.elapsed(),
            empty,
            written,
            closed,
        )
    } else {
        let store = araphor_data::AnalysisStore::open(&root)?;
        let open = open_start.elapsed();
        let empty = sizes_in(&root)?;
        let write_start = Instant::now();
        for batch in &batches {
            let start = Instant::now();
            assert_eq!(
                store.accept_validated_batch(
                    identity.clone(),
                    araphor_data::ValidatedEvidenceBatchV1 {
                        cpu_id: batch.cpu_id,
                        first_cursor: batch.first_cursor,
                        last_cursor: batch.last_cursor,
                        intake_utc_ns: 1_000_000_000,
                        framed_records: batch.framed_records.clone(),
                        frame_ends: batch.frame_ends.clone(),
                    },
                )?,
                araphor_data::EvidenceStoreOutcomeV1::Accepted
            );
            latency.push(start.elapsed());
        }
        let write = write_start.elapsed();
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("missing benchmark source")?
                .receipt
                .contiguous_cursor,
            total
        );
        let written = sizes_in(&root)?;
        drop(store);
        let reopen_start = Instant::now();
        let store = araphor_data::AnalysisStore::open(&root)?;
        let reopen = reopen_start.elapsed();
        let closed = sizes_in(&root)?;
        let read_start = Instant::now();
        let mut next = 1;
        while next <= total {
            let page = store.read_page(&identity, next)?;
            assert!(!page.records.is_empty());
            for (offset, record) in page.records.iter().enumerate() {
                let frame = &record.framed_record;
                let length = u32::from_be_bytes(frame[..4].try_into()?) as usize;
                assert_eq!(length + 8, frame.len());
                let decoded = EvidenceRecord::decode(&frame[4..4 + length])?;
                assert_eq!(decoded.observed_boottime_ns, next + offset as u64);
            }
            next += page.records.len() as u64;
        }
        (
            open,
            write,
            reopen,
            read_start.elapsed(),
            empty,
            written,
            closed,
        )
    };
    latency.sort_unstable();
    let p50 = latency[latency.len() / 2];
    let p95 = latency[latency.len() * 95 / 100];
    println!(
        "RAW_EVENT_BENCH mode={mode} records={total} batches={batch_count} input_bytes={input_bytes} \
         open_s={:.6} write_s={:.6} write_records_s={:.1} p50_ms={:.3} p95_ms={:.3} \
         reopen_s={:.6} read_s={:.6} read_records_s={:.1} empty_bytes={} \
         written_bytes={} closed_bytes={} written_allocated={} closed_allocated={}",
        open.as_secs_f64(),
        write.as_secs_f64(),
        total as f64 / write.as_secs_f64(),
        p50.as_secs_f64() * 1000.0,
        p95.as_secs_f64() * 1000.0,
        reopen.as_secs_f64(),
        read.as_secs_f64(),
        total as f64 / read.as_secs_f64(),
        empty.0,
        written.0,
        closed.0,
        written.1,
        closed.1,
    );
    Ok(())
}
