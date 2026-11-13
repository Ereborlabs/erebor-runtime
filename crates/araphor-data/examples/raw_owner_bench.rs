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

fn scan(store: &Store, frames: &[Vec<u8>], total: u64, mode: &str) -> Result<serde_json::Value> {
    let started = Instant::now();
    let mut samples = Vec::new();
    if mode == "stream" {
        let mut first = 1;
        let mut read = Instant::now();
        store.scan(None, |page| {
            samples.push(read.elapsed().as_nanos() as u64);
            assert_eq!(page.len(), 256);
            verify(&page, frames, first);
            first += page.len() as u64;
            read = Instant::now();
            Ok(())
        })?;
        assert_eq!(first, total + 1);
    } else {
        for first in (1..=total).step_by(256) {
            let read = Instant::now();
            let page = store.read(first, None)?;
            samples.push(read.elapsed().as_nanos() as u64);
            assert_eq!(page.len(), 256);
            verify(&page, frames, first);
        }
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
    if !(3..=4).contains(&args.len()) {
        return Err(
            "usage: raw_owner_bench production|fjall RECORDS REPORT.json [pages|stream]".into(),
        );
    }
    let mode = args.get(3).map_or("pages", String::as_str);
    if !["pages", "stream"].contains(&mode) {
        return Err("expected pages or stream".into());
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
    let warm_scan = scan(&store, &frames, total, mode)?;
    let historical = store.read(total / 2 - 255, Some(&middle))?;
    assert_eq!(historical.len(), 256);
    verify(&historical, &frames, total / 2 - 255);
    assert!(store.read(total / 2 + 1, Some(&middle))?.is_empty());
    let middle = store.saved(Some(total / 2))?;
    let replay_s = replay(&store, &middle, &frames, total)?;
    let maintenance = store.maintain()?;
    let maintained = size(&root)?;
    let table_scan = scan(&store, &frames, total, mode)?;
    drop(store);
    let started = Instant::now();
    let mut store = Store::open(&root, &args[0], source())?;
    let reopen_s = started.elapsed().as_secs_f64();
    assert_eq!(store.cut()?.accepted, total);
    let reopened_scan = scan(&store, &frames, total, mode)?;
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
    let crossing = store.read(17, None)?;
    assert_eq!(crossing.len(), 256);
    verify(&crossing, &frames, 17);
    let tail = store.read(total + 256 - 16, None)?;
    assert_eq!(tail.len(), 17);
    verify(&tail, &frames, total + 256 - 16);
    let historical = store.read(17, Some(&middle))?;
    assert_eq!(historical.len(), (total / 2 - 16).min(256) as usize);
    verify(&historical, &frames, 17);
    let mut historical_rows = 0;
    store.scan(Some(&middle), |page| {
        assert_eq!(page.len(), 256);
        verify(&page, &frames, historical_rows + 1);
        historical_rows += page.len() as u64;
        Ok(())
    })?;
    assert_eq!(historical_rows, total / 2);
    let distribution_for =
        |field: fn(&Sample) -> u64| distribution(&samples.iter().map(field).collect::<Vec<_>>());
    let report = json!({"backend":args[0],"records":total,"batch_records":256,
        "input_bytes":frames.iter().take(total as usize).map(|frame| frame.len() as u64).sum::<u64>(),
        "scope":"production NativeStore native Evidence versus all-Fjall candidate; two durable stages; identical benchmark result/reference/progress records",
        "durability":{"production":"SyncAll payload+indexes+receipt ACK, then DataWrite SyncAll result/reference/progress commit",
            "fjall":"SyncAll payload+receipt ACK, then SyncAll result/reference/progress commit"},
        "cache":"OS page cache retained; new engine cache on same-process reopen",
        "candidate_layout":"source+first_cursor batch key; source/cursor result reference; no segment files, offsets, RawEntry, or RAM range index",
        "progress_scope":"common benchmark-owned result and consumed-cut record; no ManagedCommit/commit_result/processor or witness-pin qualification",
        "read_scope":"256-record pages; pages mode captures each read separately; stream mode uses one fixed view and native forward scan; includes frame validation and exact-byte verification; no Arrow conversion",
        "scan_mode":mode,
        "open_s":open_s,"write_s":write_s,"write_records_s":total as f64/write_s,
        "append":distribution_for(|sample|sample.total_ns),"accept":distribution_for(|sample|sample.accept_ns),
        "capture":distribution_for(|sample|sample.capture_ns),"progress":distribution_for(|sample|sample.progress_ns),
        "append_samples":samples,"written_bytes":written,"maintained_bytes":maintained,
        "warm_scan":warm_scan,"after_maintenance_scan":table_scan,"reopened_scan":reopened_scan,
        "maintenance":maintenance,"reopen_s":reopen_s,"replay_s":replay_s,
        "resume_s":resume_s,"continue_s":continue_s,
        "checks":{"exact_bytes":true,"logical_positions":true,"retained_cut":true,"reopen":true,
            "durable_result_reference":true,"saved_log_resume":true,"continued_log_resume":true,
            "unaligned_page":true,"partial_tail":true,"unaligned_history":true,"historical_stream":true},
        "limits":["not a notification benchmark","no overlapping retries, gaps, expiry, branches, or witness reclamation",
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

#[test]
fn stream_partial_history() -> Result<()> {
    for backend in ["production", "fjall"] {
        let (batches, frames) = inputs(512)?;
        let mut first = batches[0].clone();
        let mut rest = first.clone();
        let boundary = first.frame_ends[16];
        first.last_cursor = 17;
        first.framed_records = first.framed_records.slice(..boundary);
        first.frame_ends.truncate(17);
        rest.first_cursor = 18;
        rest.framed_records = rest.framed_records.slice(boundary..);
        rest.frame_ends = rest.frame_ends[17..]
            .iter()
            .map(|end| end - boundary)
            .collect();
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("store");
        let mut store = Store::open(&root, backend, source())?;
        store.append(first)?;
        let cut = store.cut()?;
        store.append(rest)?;
        for phase in 0..3 {
            if phase == 1 {
                store.maintain()?;
            }
            if phase == 2 {
                drop(store);
                store = Store::open(&root, backend, source())?;
            }
            for (at, total) in [(None, 256), (Some(&cut), 17)] {
                let mut count = 0;
                store.scan(at, |page| {
                    assert_eq!(page.len(), total);
                    for record in page {
                        count += 1;
                        assert_eq!(record.cursor, count);
                        assert_eq!(record.framed_record, frames[count as usize - 1]);
                        assert_eq!(
                            record.position.commit_revision,
                            if count <= 17 { 1 } else { 2 }
                        );
                        assert_eq!(
                            record.position.ordinal,
                            if count <= 17 { count - 1 } else { count - 18 } as u32
                        );
                    }
                    Ok(())
                })?;
                assert_eq!(count, total as u64);
            }
        }
    }
    Ok(())
}
