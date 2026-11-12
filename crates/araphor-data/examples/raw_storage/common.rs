use std::{fs, os::unix::fs::MetadataExt as _, path::Path};

use araphor_data::{
    analysis::raw_benchmark::Result, EvidenceIntakeIdentityV1, EvidenceRecord,
    EvidenceTemporalCoverage, ValidatedEvidenceBatchV1,
};
use serde_json::json;

pub fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

pub fn inputs(count: u64) -> Result<(Vec<ValidatedEvidenceBatchV1>, Vec<Vec<u8>>)> {
    let mut batches = Vec::new();
    let mut frames = Vec::new();
    for first in (1..=count).step_by(256) {
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..first + 256 {
            let record = EvidenceRecord {
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
                temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
                ..Default::default()
            };
            let frame = Vec::<u8>::try_from(&record)?;
            bytes.extend_from_slice(&frame);
            ends.push(bytes.len());
            frames.push(frame);
        }
        batches.push(ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + 255,
            intake_utc_ns: 1_000_000_000,
            framed_records: bytes.into(),
            frame_ends: ends,
        });
    }
    Ok((batches, frames))
}

pub fn distribution(samples: &[u64]) -> serde_json::Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    json!({"count":sorted.len(),"median_ms":sorted[sorted.len()/2] as f64/1e6,
        "p95_ms":sorted[sorted.len()*95/100] as f64/1e6,
        "p99_ms":sorted[sorted.len()*99/100] as f64/1e6,
        "max_ms":sorted[sorted.len()-1] as f64/1e6})
}

pub fn size(path: &Path) -> Result<(u64, u64)> {
    let mut bytes = (0, 0);
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let child = if metadata.is_dir() {
            size(&entry.path())?
        } else {
            (metadata.len(), metadata.blocks() * 512)
        };
        bytes.0 += child.0;
        bytes.1 += child.1;
    }
    Ok(bytes)
}
