use std::{fs, path::Path, time::Instant};

use araphor_data::{
    analysis::raw_benchmark::{Append, Cut, Result, Store},
    AnalysisRecordV1,
};
use serde_json::json;

#[path = "raw_storage/common.rs"]
mod common;
use common::{distribution, inputs, size, source};

fn verify(records: &[AnalysisRecordV1], frames: &[Vec<u8>], first: u64) {
    for (offset, record) in records.iter().enumerate() {
        let cursor = first + offset as u64;
        assert_eq!(record.cursor, cursor);
        assert_eq!(record.framed_record, frames[cursor as usize - 1]);
        assert_eq!(record.position.commit_revision, (cursor - 1) / 256 + 1);
        assert_eq!(record.position.ordinal, ((cursor - 1) % 256) as u32);
    }
}

fn scan(store: &Store, frames: &[Vec<u8>], total: u64) -> Result<serde_json::Value> {
    let start = Instant::now();
    let mut samples = Vec::new();
    for first in (1..=total).step_by(256) {
        let read = Instant::now();
        let page = store.read(first, 256, None)?;
        samples.push(read.elapsed().as_nanos() as u64);
        assert_eq!(page.len(), 256);
        verify(&page, frames, first);
    }
    Ok(
        json!({"elapsed_s":start.elapsed().as_secs_f64(),"read":distribution(&samples),"samples_ns":samples}),
    )
}

fn points(store: &Store, frames: &[Vec<u8>], total: u64) -> Result<serde_json::Value> {
    let mut samples = Vec::new();
    for index in 0..total / 256 {
        let cursor = index * 256 + (index * 37) % 256 + 1;
        let started = Instant::now();
        let rows = store.read(cursor, 1, None)?;
        samples.push(started.elapsed().as_nanos() as u64);
        assert_eq!(rows.len(), 1);
        verify(&rows, frames, cursor);
    }
    Ok(json!({"read":distribution(&samples),"samples_ns":samples}))
}

fn replay(store: &Store, cut: &Cut, frames: &[Vec<u8>], first: u64, last: u64) -> Result<f64> {
    let started = Instant::now();
    let mut expected = first;
    let count = store.replay(cut, |cursor, bytes, position| {
        assert_eq!(cursor, expected);
        assert_eq!(bytes, frames[cursor as usize - 1]);
        assert_eq!(position.commit_revision, (cursor - 1) / 256 + 1);
        assert_eq!(position.ordinal, ((cursor - 1) % 256) as u32);
        expected += 1;
        Ok(())
    })?;
    assert_eq!(expected, last + 1);
    assert_eq!(count, last + 1 - first);
    Ok(started.elapsed().as_secs_f64())
}

fn save_cut(path: &Path, cut: &Cut) -> Result<()> {
    fs::write(path, cut.encode()?)?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("use a release build".into());
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: raw_storage_bench segments|fjall RECORDS REPORT.json".into());
    }
    let total: u64 = args[1].parse()?;
    if total < 512 || total % 512 != 0 {
        return Err("records must be a multiple of512 and at least512".into());
    }
    let (batches, frames) = inputs(total + 256)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store");
    let started = Instant::now();
    let mut store = Store::open(&path, &args[0], source())?;
    let open_s = started.elapsed().as_secs_f64();
    rustix::fs::syncfs(&fs::File::open(&path)?)?;
    let mut appends: Vec<Append> = Vec::new();
    let mut middle = None;
    let started = Instant::now();
    for (index, batch) in batches.iter().take((total / 256) as usize).enumerate() {
        appends.push(store.append(batch.clone())?);
        if index + 1 == (total / 512) as usize {
            middle = Some(store.cut()?);
        }
    }
    let write_s = started.elapsed().as_secs_f64();
    assert_eq!(store.accepted(), total);
    let middle = middle.ok_or("benchmark needs at least512records")?;
    let end = store.cut()?;
    let written = size(&path)?;
    let warm_scan = scan(&store, &frames, total)?;
    let warm_points = points(&store, &frames, total)?;
    let historical = store.read(total / 2 - 255, 256, Some(&middle))?;
    assert_eq!(historical.len(), 256);
    verify(&historical, &frames, total / 2 - 255);
    assert!(store.read(total / 2 + 1, 1, Some(&middle))?.is_empty());
    let replay_s = replay(&store, &middle, &frames, total / 2 + 1, total)?;
    save_cut(&directory.path().join("middle.cut"), &middle)?;
    save_cut(&directory.path().join("end.cut"), &end)?;
    fs::File::open(directory.path())?.sync_all()?;
    let maintenance = store.maintain()?;
    let maintained = size(&path)?;
    let table_scan = scan(&store, &frames, total)?;
    let table_points = points(&store, &frames, total)?;
    drop(store);
    let started = Instant::now();
    let mut store = Store::open(&path, &args[0], source())?;
    let reopen_s = started.elapsed().as_secs_f64();
    assert_eq!(store.accepted(), total);
    let middle = Cut::decode(&fs::read(directory.path().join("middle.cut"))?)?;
    let end = Cut::decode(&fs::read(directory.path().join("end.cut"))?)?;
    let reopened_scan = scan(&store, &frames, total)?;
    let reopened_points = points(&store, &frames, total)?;
    let retained = store.read(1, 256, Some(&middle))?;
    assert_eq!(retained.len(), 256);
    verify(&retained, &frames, 1);
    assert!(store.read(total / 2 + 1, 1, Some(&middle))?.is_empty());
    replay(&store, &middle, &frames, total / 2 + 1, total)?;
    replay(&store, &end, &frames, total + 1, total)?;
    store.append(batches[(total / 256) as usize].clone())?;
    replay(&store, &end, &frames, total + 1, total + 256)?;
    let continued = store.read(total + 1, 256, None)?;
    assert_eq!(continued.len(), 256);
    verify(&continued, &frames, total + 1);
    let totals = appends
        .iter()
        .map(|sample| sample.total_ns)
        .collect::<Vec<_>>();
    let prepares = appends
        .iter()
        .map(|sample| sample.prepare_ns)
        .collect::<Vec<_>>();
    let commits = appends
        .iter()
        .map(|sample| sample.commit_ns)
        .collect::<Vec<_>>();
    let report = json!({"backend":args[0],"records":total,"batch_records":256,
        "input_bytes":frames.iter().take(total as usize).map(|frame|frame.len() as u64).sum::<u64>(),
        "scope":"RawJournal versus versioned Fjall, identical RawCommit codec, common in-memory range index; single source; disjoint appends",
        "durability":{"segments":"positional write then filesystem syncfs","fjall":"versioned branch SyncAll journal commit; receipt and entry index atomic"},
        "cache":"OS page cache is not dropped; reopened engine caches are new; syncfs drains setup writes before timed append",
        "preparation_note":"Fjall candidate calls existing prepare_append without active segment state; it prepares an unused segment identity header per batch. Do not attribute prepare differences to Fjall commit cost.",
        "history_policy":"all native history and original journals retained for historical/resume probes",
        "recovery_scope":"saved cuts are synced to files; same-process store close/reopen, not a killed-process or power-loss test",
        "open_s":open_s,"write_s":write_s,"write_records_s":total as f64/write_s,
        "append":distribution(&totals),"prepare":distribution(&prepares),"commit":distribution(&commits),
        "append_samples":appends,"written_bytes":written,"maintained_bytes":maintained,
        "warm_scan":warm_scan,"warm_points":warm_points,"maintenance":maintenance,
        "after_maintenance_scan":table_scan,"after_maintenance_points":table_points,
        "reopen_s":reopen_s,"reopened_scan":reopened_scan,"reopened_points":reopened_points,
        "replay_s":replay_s,"checks":{"exact_bytes":true,"logical_positions":true,
        "retained_cut":true,"reopen":true,"saved_log_resume":true,"continued_log_resume":true},
        "limits":["not the full Data owner or notification pipeline","no expiry or witness reclamation parity",
        "no overlapping retries or gap filling","forced flush/major compaction is not steady natural compaction"]});
    fs::write(&args[2], serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{} records={} write_records_s={:.1} reopen_ms={:.3}",
        args[0],
        total,
        total as f64 / write_s,
        reopen_s * 1000.0
    );
    Ok(())
}
