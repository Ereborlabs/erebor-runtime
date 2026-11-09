use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use super::{
    fixture::Fixture, history::History, incident::Incident, package, Engine, Oracle, Reference,
    Result,
};

#[derive(Serialize)]
struct Run {
    engine: String,
    round: usize,
    samples: Vec<super::Sample>,
    history: Vec<super::history::Sample>,
    historical_views: usize,
    compactions: usize,
    reopen_s: f64,
    member_keys: usize,
    unsupported_after_reopen: usize,
}

fn native(engine: &Engine) -> &super::native::Native {
    match engine {
        Engine::Native(db) => db,
        _ => unreachable!(),
    }
}

fn flush(engine: &Engine, compact: bool) -> Result<()> {
    if let super::kv::Database::Fjall(_, table) = native(engine).database() {
        table.as_ref().flush(true)?;
        if compact {
            table.as_ref().major_compact()?;
        }
    }
    #[cfg(feature = "cdc-poc")]
    if let super::kv::Database::FjallBranch(store) = native(engine).database() {
        store.database().inner().flush_memtables()?;
        if compact {
            store.database().inner().major_compact()?;
        }
    }
    Ok(())
}

fn keys(engine: &Engine, stable: bool) -> Result<usize> {
    native(engine).database().read(|tx| {
        if matches!(
            native(engine).database(),
            super::kv::Database::FjallBranch(..)
        ) {
            super::live::Live::assert_stable(match native(engine).database() {
                super::kv::Database::FjallBranch(store) => store,
                _ => unreachable!(),
            })?;
            return Ok(tx.prefix(b"\0graph/M")?.len());
        }
        let members = tx.prefix(b"M")?;
        if stable {
            for (kind, fields) in [
                (b'M', 4),
                (b'R', 4),
                (b'K', 4),
                (b'O', 5),
                (b'I', 5),
                (b'B', 5),
                (b'H', 1),
                (b'S', 1),
                (b'T', 1),
                (b'J', 0),
                (b'C', 0),
            ] {
                for (key, _) in tx.prefix(&[kind])? {
                    assert_eq!(key.len(), 1 + fields * 8);
                }
            }
            assert_eq!(tx.prefix(b"H")?.len(), 2);
            assert_eq!(tx.prefix(b"J")?.len(), 1);
            assert_eq!(tx.prefix(b"C")?.len(), 1);
            assert_eq!(members.len(), 186);
        } else {
            assert_eq!(members.len(), 194);
            assert!(members.iter().all(|(key, _)| key.len() == 41));
        }
        Ok(members.len())
    })
}

fn views(engine: &Engine, oracle: &Oracle, fixture: &Fixture) -> Result<usize> {
    for spec in &fixture.steps {
        oracle.check(
            &mut engine.inspect(fixture, spec.revision)?,
            fixture,
            spec.revision,
        )?;
        engine.verify_metadata(fixture, spec.revision, 87)?;
    }
    Ok(fixture.steps.len())
}

fn scenario(
    kind: &str,
    round: usize,
    references: &mut BTreeMap<u64, Reference>,
    history: &mut History,
) -> Result<Run> {
    let directory = tempfile::tempdir()?;
    let fixture = Fixture::new()?;
    let incident = Incident::new()?;
    let inputs = fixture
        .steps
        .iter()
        .enumerate()
        .map(|(i, spec)| incident.index_input(i, *spec))
        .collect::<Result<Vec<_>>>()?;
    let stable = kind.ends_with("stable");
    let mut engine = Engine::open(kind, directory.path(), &fixture)?;
    let mut oracle = Oracle::default();
    let mut run = Run {
        engine: kind.into(),
        round,
        samples: Vec::new(),
        history: Vec::new(),
        historical_views: 0,
        compactions: 0,
        reopen_s: 0.0,
        member_keys: 0,
        unsupported_after_reopen: 0,
    };
    for (i, spec) in fixture.steps.iter().copied().enumerate() {
        let started = Instant::now();
        let (prepared, capture_s) =
            engine.capture(&fixture, spec.captured, |view, capture_s| {
                Ok((
                    package::evaluate(view, &fixture, &incident, spec, &inputs[i])?,
                    capture_s,
                ))
            })?;
        let write = engine.apply(&fixture, &prepared.step, true)?;
        let scenario_s = started.elapsed().as_secs_f64();
        let counts = oracle.apply(&prepared.step);
        assert_eq!(counts, (write.added, write.closed));
        assert_eq!(
            counts,
            [
                (50, 0),
                (12, 0),
                (1, 1),
                (1, 1),
                (1, 1),
                (63, 1),
                (2, 2),
                (64, 2)
            ][i]
        );
        let mut out = engine.inspect(&fixture, spec.revision)?;
        oracle.check(&mut out, &fixture, spec.revision)?;
        super::check_findings(&out.rows, spec.expected_findings)?;
        engine.verify_metadata(&fixture, spec.revision, spec.revision)?;
        let calls = prepared
            .calls
            .iter()
            .map(|c| {
                let (w, o, r, k, n) = c.signature();
                (w, o.to_string(), r, k.to_vec(), n)
            })
            .collect();
        if let Some(reference) = references.get(&spec.revision) {
            Fixture::assert_rows(&reference.rows, &mut out.rows)?;
            assert_eq!(reference.calls, calls);
            assert_eq!(reference.frontier, prepared.frontier);
        } else {
            references.insert(
                spec.revision,
                Reference {
                    rows: out.rows,
                    calls,
                    frontier: prepared.frontier.clone(),
                },
            );
        }
        history.remember(spec.revision, &prepared)?;
        run.samples.push(super::Sample {
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
        });
        if i < 4 {
            flush(&engine, false)?;
        }
    }
    run.member_keys = keys(&engine, stable)?;
    run.historical_views += views(&engine, &oracle, &fixture)?;
    run.history.extend(history.replay(
        &engine,
        &fixture,
        &incident,
        &inputs,
        kind,
        round,
        "after-writes",
    )?);
    if kind.starts_with("fjall") {
        let before = super::compaction::Trace::completed();
        flush(&engine, true)?;
        run.compactions = super::compaction::Trace::completed() - before;
        assert!(run.compactions > 0);
        run.historical_views += views(&engine, &oracle, &fixture)?;
        run.history.extend(history.replay(
            &engine,
            &fixture,
            &incident,
            &inputs,
            kind,
            round,
            "after-compaction",
        )?);
    }
    let rollback = super::fixture::Spec {
        revision: 88,
        captured: 87,
        previous: 87,
        expected_findings: 3,
        expected_frontier: 18,
    };
    let input = incident.index_input(8, rollback)?;
    let prepared = engine.capture(&fixture, 87, |view, _| {
        package::evaluate(view, &fixture, &incident, rollback, &input)
    })?;
    engine.apply(&fixture, &prepared.step, false)?;
    engine.verify_metadata(&fixture, 88, 87)?;
    oracle.check(&mut engine.inspect(&fixture, 88)?, &fixture, 88)?;
    let Engine::Native(db) = &mut engine else {
        unreachable!()
    };
    let revisions = db.take_revisions();
    engine.close()?;
    drop(engine);
    let reopened = Instant::now();
    engine = Engine::open(kind, directory.path(), &fixture)?;
    run.reopen_s = reopened.elapsed().as_secs_f64();
    let Engine::Native(db) = &mut engine else {
        unreachable!()
    };
    db.restore_revisions(revisions);
    if kind == "fjall-stable" {
        flush(&engine, true)?;
    }
    if kind == "fjall-stable" && !cfg!(feature = "cdc-poc") {
        for revision in fixture
            .steps
            .iter()
            .map(|s| s.captured)
            .chain(fixture.steps.iter().map(|s| s.revision).filter(|r| *r < 87))
        {
            let result = engine.capture(&fixture, revision, |_, _| Ok(()));
            assert_eq!(
                result
                    .err()
                    .ok_or("unexpected reopened Fjall historical handle")?
                    .to_string(),
                "Fjall historical snapshot is not open"
            );
            run.unsupported_after_reopen += 1;
        }
        oracle.check(&mut engine.inspect(&fixture, 87)?, &fixture, 87)?;
        engine.verify_metadata(&fixture, 87, 87)?;
    } else {
        run.historical_views += views(&engine, &oracle, &fixture)?;
        run.history.extend(history.replay(
            &engine,
            &fixture,
            &incident,
            &inputs,
            kind,
            round,
            "after-reopen",
        )?);
    }
    if kind == "fjall-stable" {
        engine.verify_metadata(&fixture, 88, 87)?;
    }
    assert_eq!(keys(&engine, stable)?, run.member_keys);
    engine.close()?;
    Ok(run)
}

pub fn run(output: &Path) -> Result<()> {
    super::compaction::Trace::install()?;
    let engines = ["fjall", "fjall-stable", "neon-layers", "neon-stable"];
    let mut references = BTreeMap::new();
    let mut history = History::default();
    let mut runs = Vec::new();
    for round in 0..4 {
        for slot in [0, 1, 3, 2] {
            runs.push(scenario(
                engines[(slot + round) % 4],
                round,
                &mut references,
                &mut history,
            )?);
        }
    }
    let report = serde_json::json!({
        "source": option_env!("POC_SOURCE_REVISION").unwrap_or("unrecorded"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "versioned_fjall": cfg!(feature = "cdc-poc"),
        "change_verification": "native Graph target reconstructs semantic changes from before/after native views; no copied change log",
        "workload": "original eight Causal Graph cycles; revision-key controls versus stable mutable keys; exact package and retained-view comparisons",
        "native_history": { "fjall-stable": if cfg!(feature = "cdc-poc") { "araphor_graph::native; durable retained branch history and stamped Data cut index" } else { "live public Snapshot handles; old handles after reopen Unsupported" }, "neon-stable": "stable native keys with separate layer LSN; history after reopen" },
        "limits": ["Fjall branch reads durable stamped Data cuts; Neon controls keep caller-owned Graph revision references", "Neon adapter has no original WAL CDC, native branches or background compaction", "immutable property chunks and dictionary IDs remain; no property reclamation", "prepared source Arrow; no production DataFusion input or notification path", "no steady compaction, large-history, cold-cache or power-loss qualification"],
        "runs": runs
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "128 package cycles and exact historical replay checks passed: {}",
        output.display()
    );
    Ok(())
}
