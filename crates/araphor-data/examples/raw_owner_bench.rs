use std::{fs, time::Instant};

use araphor_data::{
    analysis::{
        native::benchmark::{Cut, Store},
        raw_benchmark::Result,
    },
    AnalysisRecordV1,
};
use serde_json::json;

#[path = "raw_storage/common.rs"]
mod common;
use common::{distribution, inputs, size, source};

#[derive(serde::Serialize)]
struct Sample {
    accept_ns: u64,
    capture_ns: u64,
    progress_ns: u64,
    total_ns: u64,
}

fn verify(records: &[AnalysisRecordV1], frames: &[Vec<u8>], first: u64) {
    for (offset, record) in records.iter().enumerate() {
        let cursor = first + offset as u64;
        assert_eq!(record.cursor, cursor);
        assert_eq!(record.framed_record, frames[cursor as usize - 1]);
        assert_eq!(record.position.commit_revision, (cursor - 1) / 256 * 2 + 1);
        assert_eq!(record.position.ordinal, ((cursor - 1) % 256) as u32);
    }
}

fn scan(store: &Store, frames: &[Vec<u8>], total: u64) -> Result<serde_json::Value> {
    let started = Instant::now();
    let mut samples = Vec::new();
    for first in (1..=total).step_by(256) {
        let read = Instant::now();
        let page = store.read(first, None)?;
        samples.push(read.elapsed().as_nanos() as u64);
        assert_eq!(page.len(), 256);
        verify(&page, frames, first);
    }
    Ok(
        json!({"elapsed_s":started.elapsed().as_secs_f64(),"read":distribution(&samples),"samples_ns":samples}),
    )
}

fn replay(store: &Store, cut: &Cut, frames: &[Vec<u8>], last: u64) -> Result<f64> {
    let started = Instant::now();
    let mut expected = cut.accepted + 1;
    let count = store.replay(cut, |cursor, bytes, position| {
        assert_eq!(cursor, expected);
        assert_eq!(bytes, frames[cursor as usize - 1]);
        assert_eq!(position.commit_revision, (cursor - 1) / 256 * 2 + 1);
        assert_eq!(position.ordinal, ((cursor - 1) % 256) as u32);
        expected += 1;
        Ok(())
    })?;
    assert_eq!(count, last - cut.accepted);
    assert_eq!(expected, last + 1);
    Ok(started.elapsed().as_secs_f64())
}

fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("use a release build".into());
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: raw_owner_bench hybrid|fjall RECORDS REPORT.json".into());
    }
    let total: u64 = args[1].parse()?;
    if total < 512 || total % 512 != 0 {
        return Err("records must be a multiple of 512 and at least 512".into());
    }
    let (batches, frames) = inputs(total + 256)?;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let started = Instant::now();
    let mut store = Store::open(&root, &args[0], source())?;
    let open_s = started.elapsed().as_secs_f64();
    rustix::fs::syncfs(&fs::File::open(&root)?)?;
    let mut samples = Vec::new();
    let mut middle = None;
    let started = Instant::now();
    for (index, batch) in batches.iter().take((total / 256) as usize).enumerate() {
        let cycle = Instant::now();
        let accept = Instant::now();
        store.append(batch.clone())?;
        let accept_ns = accept.elapsed().as_nanos() as u64;
        let capture = Instant::now();
        let input = store.cut()?;
        let capture_ns = capture.elapsed().as_nanos() as u64;
        assert_eq!(input.accepted, batch.last_cursor);
        let progress = Instant::now();
        store.consume(batch.first_cursor, &input)?;
        let progress_ns = progress.elapsed().as_nanos() as u64;
        samples.push(Sample {
            accept_ns,
            capture_ns,
            progress_ns,
            total_ns: cycle.elapsed().as_nanos() as u64,
        });
        if index + 1 == (total / 512) as usize {
            middle = Some(store.cut()?);
        }
    }
    let write_s = started.elapsed().as_secs_f64();
    let middle = middle.ok_or("missing middle cut")?;
    let end = store.cut()?;
    assert_eq!(end.accepted, total);
    assert_eq!(end.revision, total / 256 * 2);
    assert_eq!(store.saved(None)?.accepted, total);
    let written = size(&root)?;
    let warm_scan = scan(&store, &frames, total)?;
    let historical = store.read(total / 2 - 255, Some(&middle))?;
    assert_eq!(historical.len(), 256);
    verify(&historical, &frames, total / 2 - 255);
    assert!(store.read(total / 2 + 1, Some(&middle))?.is_empty());
    let middle = store.saved(Some(total / 2))?;
    let replay_s = replay(&store, &middle, &frames, total)?;
    let maintenance = store.maintain()?;
    let maintained = size(&root)?;
    let table_scan = scan(&store, &frames, total)?;
    drop(store);
    let started = Instant::now();
    let mut store = Store::open(&root, &args[0], source())?;
    let reopen_s = started.elapsed().as_secs_f64();
    assert_eq!(store.cut()?.accepted, total);
    let reopened_scan = scan(&store, &frames, total)?;
    let middle = store.saved(Some(total / 2))?;
    let retained = store.read(1, Some(&middle))?;
    assert_eq!(retained.len(), 256);
    verify(&retained, &frames, 1);
    assert!(store.read(total / 2 + 1, Some(&middle))?.is_empty());
    let resume_s = replay(&store, &middle, &frames, total)?;
    let end = store.saved(None)?;
    replay(&store, &end, &frames, total)?;
    store.append(batches[(total / 256) as usize].clone())?;
    let continue_s = replay(&store, &end, &frames, total + 256)?;
    let input = store.cut()?;
    store.consume(total + 1, &input)?;
    assert_eq!(store.saved(None)?.accepted, total + 256);
    let continued = store.read(total + 1, None)?;
    assert_eq!(continued.len(), 256);
    verify(&continued, &frames, total + 1);
    let distribution_for =
        |field: fn(&Sample) -> u64| distribution(&samples.iter().map(field).collect::<Vec<_>>());
    let report = json!({"backend":args[0],"records":total,"batch_records":256,
        "input_bytes":frames.iter().take(total as usize).map(|frame| frame.len() as u64).sum::<u64>(),
        "scope":"production NativeStore segment append plus real DataWrite metadata commit versus all-Fjall candidate; two durable stages; identical benchmark result/reference/progress records",
        "durability":{"hybrid":"raw syncfs ACK, then DataWrite SyncAll metadata commit including stage_raw",
            "fjall":"SyncAll payload+receipt ACK, then SyncAll result/reference/progress commit"},
        "cache":"OS page cache retained; new engine cache on same-process reopen",
        "candidate_layout":"source+first_cursor batch key; source/cursor result reference; no segment files, offsets, RawEntry, or RAM range index",
        "progress_scope":"common benchmark-owned result and consumed-cut record; no ManagedCommit/commit_result/processor or witness-pin qualification",
        "read_scope":"256-record production pages versus native predecessor/range pages; includes frame validation and exact-byte verification; no Arrow conversion",
        "open_s":open_s,"write_s":write_s,"write_records_s":total as f64/write_s,
        "append":distribution_for(|sample|sample.total_ns),"accept":distribution_for(|sample|sample.accept_ns),
        "capture":distribution_for(|sample|sample.capture_ns),"progress":distribution_for(|sample|sample.progress_ns),
        "append_samples":samples,"written_bytes":written,"maintained_bytes":maintained,
        "warm_scan":warm_scan,"after_maintenance_scan":table_scan,"reopened_scan":reopened_scan,
        "maintenance":maintenance,"reopen_s":reopen_s,"replay_s":replay_s,
        "resume_s":resume_s,"continue_s":continue_s,
        "checks":{"exact_bytes":true,"logical_positions":true,"retained_cut":true,"reopen":true,
            "durable_result_reference":true,"saved_log_resume":true,"continued_log_resume":true},
        "limits":["not a production replacement or notification benchmark","no overlapping retries, gaps, expiry, branches, or witness reclamation",
            "same-process reopen, not killed-process or power-loss recovery","forced flush/major compaction, not sustained natural compaction",
            "point-read latency and Arrow conversion are not measured"]});
    fs::write(&args[2], serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{} records={} cycle_records_s={:.1} reopen_ms={:.3}",
        args[0],
        total,
        total as f64 / write_s,
        reopen_s * 1000.0
    );
    Ok(())
}
