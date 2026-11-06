use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde::Serialize;

use super::fixture::{Fixture, Spec};
use super::incident::Incident;
use super::native::Native;
use super::{Oracle, Reference, Result, Sample, check_findings, materialize, package, usage};

#[derive(Clone, Serialize)]
struct Event {
    at_s: f64,
    thread: String,
    target: String,
    level: String,
    message: String,
}
struct Trace {
    started: OnceLock<Instant>,
    events: Mutex<Vec<Event>>,
}
static TRACE: Trace = Trace {
    started: OnceLock::new(),
    events: Mutex::new(Vec::new()),
};
impl Trace {
    fn elapsed(&self) -> f64 {
        self.started
            .get_or_init(Instant::now)
            .elapsed()
            .as_secs_f64()
    }
    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
impl log::Log for Trace {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target() == "lsm_tree::compaction::worker"
            || (metadata.level() <= log::Level::Warn
                && (metadata.target().starts_with("fjall")
                    || metadata.target().starts_with("lsm_tree")))
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        if message == "Compaction successful"
            || message.starts_with("Compaction choice:")
            || record.level() <= log::Level::Warn
        {
            let event = Event {
                at_s: self.elapsed(),
                thread: format!("{:?}", std::thread::current().id()),
                target: record.target().into(),
                level: record.level().to_string(),
                message,
            };
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
        }
    }
    fn flush(&self) {}
}

#[derive(Serialize)]
struct Cycle {
    epoch: usize,
    started_s: f64,
    ended_s: f64,
    before: Option<super::kv::Maintenance>,
    after: Option<super::kv::Maintenance>,
    #[serde(flatten)]
    sample: Sample,
}
#[derive(Serialize)]
struct Pass {
    engine: String,
    round: usize,
    epochs: usize,
    started_s: f64,
    ended_s: f64,
    reopen_s: f64,
    file_bytes: u64,
    allocated_bytes: u64,
    files: usize,
    cycles: Vec<Cycle>,
    events: Vec<Event>,
}

pub fn run(output: &Path) -> Result<()> {
    std::fs::create_dir_all(output.parent().unwrap_or(Path::new(".")))?;
    log::set_logger(&TRACE).map_err(|_| "compaction logger already set")?;
    log::set_max_level(log::LevelFilter::Trace);
    let mut references = BTreeMap::new();
    let first = pass("fjall", 0, None, output, &mut references)?;
    let epochs = first.epochs;
    let mut passes = vec![first];
    for (engine, round) in [("redb", 0), ("redb", 1), ("fjall", 1)] {
        passes.push(pass(engine, round, Some(epochs), output, &mut references)?);
    }
    let report = serde_json::json!({
        "source": option_env!("POC_SOURCE_REVISION").unwrap_or("working-tree"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "workload": {
            "scope": "same eight actual Causal package steps repeated in one growing database",
            "history": "same identities; advancing revisions; reset and rebuild at each epoch start; all historical keys retained",
            "stop": "first Fjall pass: two successful physical background merges, finish epoch, then one additional epoch; other passes: same epoch count",
            "fjall": "default 64MiB memtable and leveled L0 threshold4; no manual rotation or major compaction",
            "durability": {"redb": "Immediate", "fjall": "transaction SyncAll"},
            "merge_proof": "lsm_tree::compaction::worker Trace Compaction successful after merge manifest installation; native attempt counters can include no-ops",
            "history_checks": "all8 early, middle, latest cuts after writes and after reopen; exact cross-engine rows/calls/frontiers at these cuts; Oracle at every cycle",
            "logger": "native compaction choices, successful merges, and storage warnings/errors retained; trace-level log dispatch enabled on both engines",
            "excludes": ["raw ingestion", "DataFusion input execution", "production Data authority", "notification creation", "power loss", "history retention deletion"]
        },
        "passes": passes,
    });
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
    Ok(())
}

fn pass(
    kind: &str,
    round: usize,
    fixed: Option<usize>,
    output: &Path,
    references: &mut BTreeMap<u64, Reference>,
) -> Result<Pass> {
    let directory = tempfile::Builder::new()
        .prefix("araphor-compaction-poc-")
        .tempdir_in(output.parent().unwrap_or(Path::new(".")))?;
    let mut fixture = Fixture::new()?;
    let base = fixture.steps.clone();
    fixture.steps.clear();
    let mut incident = Incident::new()?;
    let mut engine = Native::open(kind, directory.path())?;
    let mut oracle = Oracle::default();
    let mut cycles = Vec::new();
    let mut calls = BTreeMap::new();
    let mut epoch = 0;
    let mut stop = fixed;
    let started_s = TRACE.elapsed();
    loop {
        let offset = u64::try_from(epoch)?
            .checked_mul(87)
            .ok_or("revision overflow")?;
        let steps = base
            .iter()
            .map(|base| Spec {
                revision: base.revision + offset,
                captured: base.captured + offset,
                previous: if epoch > 0 && base.previous == 1 {
                    offset
                } else {
                    base.previous + offset
                },
                ..*base
            })
            .collect::<Vec<_>>();
        fixture.steps.extend_from_slice(&steps);
        for (i, spec) in steps.into_iter().enumerate() {
            let input = incident.index_input(i, spec)?;
            let before = engine.maintenance();
            let started_s = TRACE.elapsed();
            let started = Instant::now();
            let (prepared, capture_s) = engine.capture(&fixture, spec.captured, |view, time| {
                Ok((
                    package::evaluate(view, &fixture, &incident, spec, &input)?,
                    time,
                ))
            })?;
            let write = engine.apply(&fixture, &prepared.step, true)?;
            let scenario_s = started.elapsed().as_secs_f64();
            let ended_s = TRACE.elapsed();
            let after = engine.maintenance();
            let mut out = engine.inspect(&fixture, spec.revision, true)?;
            let materialized = Instant::now();
            out.rows = materialize(out.rows, &fixture)?;
            out.read_s += materialized.elapsed().as_secs_f64();
            let counts = oracle.apply(&prepared.step);
            assert_eq!((write.added, write.closed), counts);
            assert_eq!(write.added, [50, 12, 1, 1, 1, 63, 2, 64][i]);
            assert_eq!(
                write.closed,
                if i == 0 && epoch > 0 {
                    186
                } else {
                    [0, 0, 1, 1, 1, 1, 2, 2][i]
                }
            );
            oracle.check(&mut out, &fixture, spec.revision)?;
            check_findings(&out.rows, spec.expected_findings)?;
            engine.verify_metadata(&fixture, spec.revision, spec.revision)?;
            let signatures = prepared
                .calls
                .iter()
                .map(|call| {
                    let (w, op, r, k, n) = call.signature();
                    (w, op.to_string(), r, k.to_vec(), n)
                })
                .collect::<Vec<_>>();
            if let Some(reference) = references.get(&spec.revision) {
                Fixture::assert_rows(&reference.rows, &mut out.rows)?;
                assert_eq!(reference.calls, signatures);
                assert_eq!(reference.frontier, prepared.frontier);
            }
            calls.insert(spec.revision, (signatures, prepared.frontier.clone()));
            cycles.push(Cycle {
                epoch,
                started_s,
                ended_s,
                before,
                after,
                sample: Sample {
                    engine: kind.into(),
                    round,
                    write,
                    scenario_s,
                    capture_s,
                    index_s: prepared.index_s,
                    resolve_s: prepared.resolve_s,
                    detect_s: prepared.detect_s,
                    normalize_s: prepared.normalize_s,
                    verification_read_s: out.capture_s + out.read_s + out.cdc_s,
                    frontier_records: prepared.frontier,
                    calls: prepared.calls,
                },
            });
        }
        epoch += 1;
        let merges = TRACE
            .events()
            .iter()
            .filter(|e| e.at_s >= started_s && e.message == "Compaction successful")
            .count();
        if stop.is_none() && merges >= 2 {
            stop = Some(epoch + 1);
        }
        if epoch % 16 == 0 || stop == Some(epoch) {
            eprintln!(
                "engine={kind} round={} epochs={epoch} merges={merges}",
                round + 1
            );
        }
        if stop == Some(epoch) {
            break;
        }
        incident.shift(87);
    }
    let current = fixture.steps.last().ok_or("no completed steps")?.revision;
    let cuts = [0, epoch / 2, epoch - 1];
    let retained = fixture
        .steps
        .iter()
        .enumerate()
        .filter(|(i, _)| cuts.contains(&(i / 8)))
        .map(|(_, spec)| *spec)
        .collect::<Vec<_>>();
    for spec in &retained {
        let mut out = engine.inspect(&fixture, spec.revision, true)?;
        out.rows = materialize(out.rows, &fixture)?;
        oracle.check(&mut out, &fixture, spec.revision)?;
        engine.verify_metadata(&fixture, spec.revision, current)?;
        if kind == "fjall" && round == 0 {
            let (calls, frontier) = calls
                .remove(&spec.revision)
                .ok_or("call reference absent")?;
            references.insert(
                spec.revision,
                Reference {
                    rows: out.rows,
                    calls,
                    frontier,
                },
            );
        }
    }
    let rollback = Spec {
        revision: current + 1,
        captured: current,
        previous: current,
        expected_findings: 3,
        expected_frontier: 18,
    };
    let input = incident.index_input(8, rollback)?;
    let prepared = engine.capture(&fixture, current, |view, _| {
        package::evaluate(view, &fixture, &incident, rollback, &input)
    })?;
    engine.apply(&fixture, &prepared.step, false)?;
    engine.verify_metadata(&fixture, current + 1, current)?;
    engine.shutdown()?;
    drop(engine);
    let started = Instant::now();
    let engine = Native::open(kind, directory.path())?;
    let reopen_s = started.elapsed().as_secs_f64();
    for spec in &retained {
        let mut out = engine.inspect(&fixture, spec.revision, true)?;
        out.rows = materialize(out.rows, &fixture)?;
        oracle.check(&mut out, &fixture, spec.revision)?;
        engine.verify_metadata(&fixture, spec.revision, current)?;
        Fixture::assert_rows(&references[&spec.revision].rows, &mut out.rows)?;
    }
    let mut out = engine.inspect(&fixture, current + 1, true)?;
    out.rows = materialize(out.rows, &fixture)?;
    oracle.check(&mut out, &fixture, current + 1)?;
    engine.verify_metadata(&fixture, current + 1, current)?;
    engine.shutdown()?;
    drop(engine);
    let ended_s = TRACE.elapsed();
    let events = TRACE
        .events()
        .into_iter()
        .filter(|event| event.at_s >= started_s && event.at_s <= ended_s)
        .collect();
    let (file_bytes, allocated_bytes, files) = usage(directory.path())?;
    Ok(Pass {
        engine: kind.into(),
        round,
        epochs: epoch,
        started_s,
        ended_s,
        reopen_s,
        file_bytes,
        allocated_bytes,
        files,
        cycles,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_package_history() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("unused.json");
        let mut references = BTreeMap::new();
        let first = pass("fjall", 0, Some(2), &output, &mut references)?;
        let second = pass("redb", 0, Some(2), &output, &mut references)?;
        assert_eq!(references.len(), 16);
        for pass in [first, second] {
            assert_eq!(pass.cycles.len(), 16);
            assert_eq!(
                pass.cycles
                    .iter()
                    .map(|c| c.sample.write.added)
                    .sum::<usize>(),
                388
            );
            assert_eq!(
                pass.cycles
                    .iter()
                    .map(|c| c.sample.write.closed)
                    .sum::<usize>(),
                202
            );
        }
        Ok(())
    }
}
