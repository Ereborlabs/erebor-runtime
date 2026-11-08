use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{
    Oracle, Result, fixture::Fixture, incident::Incident, kv::Database, native::Native, package,
};
use serde::{Deserialize, Serialize};

const SOURCE: &[u8] = b"input/frontier";
const PACKAGE_ACK: &[u8] = b"cursor/package";
const GRAPH_ACK: &[u8] = b"cursor/graph";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Cursor {
    pub journal: u64,
    pub offset: u64,
    pub sequence: u64,
}
impl Cursor {
    fn bytes(self) -> Vec<u8> {
        [
            self.journal.to_be_bytes(),
            self.offset.to_be_bytes(),
            self.sequence.to_be_bytes(),
        ]
        .concat()
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 24 {
            return Err("invalid saved journal cursor".into());
        }
        Ok(Self {
            journal: u64::from_be_bytes(bytes[..8].try_into()?),
            offset: u64::from_be_bytes(bytes[8..16].try_into()?),
            sequence: u64::from_be_bytes(bytes[16..].try_into()?),
        })
    }
}
impl From<fjall::cdc::Cursor> for Cursor {
    fn from(c: fjall::cdc::Cursor) -> Self {
        Self {
            journal: c.journal,
            offset: c.offset,
            sequence: c.sequence,
        }
    }
}
impl From<Cursor> for fjall::cdc::Cursor {
    fn from(c: Cursor) -> Self {
        Self {
            journal: c.journal,
            offset: c.offset,
            sequence: c.sequence,
        }
    }
}
pub struct Item {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}
pub struct Batch {
    pub cursor: Cursor,
    pub items: Vec<Item>,
}
enum Feed {
    Fjall(fjall::cdc::Feed, u64),
    Home(super::home::Feed),
}
enum Cancel {
    Fjall(fjall::cdc::Cancel),
    Home(super::home::Cancel),
}
impl Cancel {
    fn stop(&self) {
        match self {
            Self::Fjall(c) => c.stop(),
            Self::Home(c) => c.stop(),
        }
    }
}
impl Feed {
    fn read(&mut self) -> Result<Vec<Batch>> {
        Ok(match self {
            Self::Fjall(feed, id) => feed
                .read()?
                .into_iter()
                .map(|batch| {
                    assert!(
                        !batch.clears.contains(id),
                        "source keyspace cleared outside this fixture"
                    );
                    Batch {
                        cursor: batch.cursor.into(),
                        items: batch
                            .items
                            .into_iter()
                            .filter(|i| i.keyspace == *id)
                            .map(|i| Item {
                                key: i.key.to_vec(),
                                value: i.value.map(|v| v.to_vec()),
                            })
                            .collect(),
                    }
                })
                .collect(),
            Self::Home(feed) => feed.read()?,
        })
    }
    fn wait(&mut self) -> Result<bool> {
        match self {
            Self::Fjall(f, _) => Ok(f.wait()?),
            Self::Home(f) => f.wait(),
        }
    }
    fn cancellation(&self) -> Cancel {
        match self {
            Self::Fjall(f, _) => Cancel::Fjall(f.cancellation()),
            Self::Home(f) => Cancel::Home(f.cancellation()),
        }
    }
}

struct Event {
    cursor: Cursor,
    value: u64,
    seen: Instant,
    members: usize,
}
#[derive(Default, Serialize)]
struct Walk {
    batches: usize,
    items: usize,
    journal_bytes: u64,
    source_wakes: usize,
    graph_wakes: usize,
    read_s: f64,
}
struct Walker {
    source: Receiver<Event>,
    graph: Receiver<Event>,
    progress: Receiver<Cursor>,
    cancel: Cancel,
    join: Option<JoinHandle<std::result::Result<Walk, String>>>,
}
impl Walker {
    fn start(native: &Native, path: &Path, source: Cursor, graph: Cursor) -> Result<Self> {
        let cursor = source.min(graph);
        let mut feed = match native.database() {
            Database::Fjall(db, table) => Feed::Fjall(
                db.inner().journal_feed(Some(cursor.into()))?,
                table.as_ref().id(),
            ),
            Database::Home(db) => Feed::Home(db.journal_feed(path, cursor)?),
            _ => return Err("engine has no supported native journal feed".into()),
        };
        let cancel = feed.cancellation();
        let (source_tx, source_rx) = mpsc::channel();
        let (graph_tx, graph_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let result = (|| -> Result<Walk> {
                let mut totals = Walk::default();
                let mut previous = cursor;
                loop {
                    let started = Instant::now();
                    let batches = feed.read()?;
                    totals.read_s += started.elapsed().as_secs_f64();
                    for batch in batches {
                        totals.batches += 1;
                        totals.items += batch.items.len();
                        totals.journal_bytes += if previous.journal == batch.cursor.journal {
                            batch.cursor.offset - previous.offset
                        } else {
                            batch.cursor.offset
                        };
                        previous = batch.cursor;
                        let head = batch
                            .items
                            .iter()
                            .find(|i| i.key == b"head")
                            .and_then(|i| i.value.as_deref());
                        let members = batch
                            .items
                            .iter()
                            .filter(|i| i.key.first() == Some(&b'M'))
                            .count();
                        for item in &batch.items {
                            if item.key == SOURCE && batch.cursor > source {
                                let bytes =
                                    item.value.as_deref().ok_or("source frontier deleted")?;
                                let value = u64::from_be_bytes(bytes.try_into()?);
                                source_tx.send(Event {
                                    cursor: batch.cursor,
                                    value,
                                    seen: Instant::now(),
                                    members: 0,
                                })?;
                                totals.source_wakes += 1;
                            }
                        }
                        if members > 0 && batch.cursor > graph {
                            let value = u64::from_be_bytes(
                                head.ok_or("Graph batch head absent")?.try_into()?,
                            );
                            graph_tx.send(Event {
                                cursor: batch.cursor,
                                value,
                                seen: Instant::now(),
                                members,
                            })?;
                            totals.graph_wakes += 1;
                        }
                        progress_tx.send(batch.cursor)?;
                    }
                    if !feed.wait()? {
                        break;
                    }
                }
                Ok(totals)
            })();
            result.map_err(|error| error.to_string())
        });
        Ok(Self {
            source: source_rx,
            graph: graph_rx,
            progress: progress_rx,
            cancel,
            join: Some(join),
        })
    }
    fn receive(receiver: &Receiver<Event>) -> Result<Event> {
        receiver
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| format!("journal subscription did not advance: {error}").into())
    }
    fn scanned(&self, cursor: Cursor) -> Result<()> {
        loop {
            if self.progress.recv_timeout(Duration::from_secs(5))? >= cursor {
                return Ok(());
            }
        }
    }
    fn quiet(&self) {
        assert!(matches!(
            self.source.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            self.graph.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    fn stop(mut self) -> Result<Walk> {
        self.cancel.stop();
        self.join
            .take()
            .unwrap()
            .join()
            .map_err(|_| "journal walker panicked")?
            .map_err(Into::into)
    }
}
impl Drop for Walker {
    fn drop(&mut self) {
        self.cancel.stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Serialize)]
struct Sample {
    engine: String,
    round: usize,
    revision: u64,
    captured: u64,
    restarted: bool,
    source_commit_s: f64,
    source_wake_s: f64,
    source_ready_s: f64,
    package_s: f64,
    output_commit_s: f64,
    output_wake_s: f64,
    output_ready_s: f64,
    total_s: f64,
    source_cursor: Cursor,
    graph_cursor: Cursor,
    members: usize,
    findings: usize,
}
#[derive(Serialize)]
struct Run {
    engine: String,
    round: usize,
    walks: Vec<Walk>,
    samples: Vec<Sample>,
    reopen_s: f64,
    compactions: usize,
    rotation: bool,
    historical_views: usize,
}

fn head(native: &Native) -> Result<Cursor> {
    match native.database() {
        Database::Fjall(db, _) => Ok(db
            .inner()
            .journal_head()?
            .ok_or("journal head absent")?
            .into()),
        Database::Home(db) => db.journal_head(),
        _ => Err("native journal feed unavailable".into()),
    }
}
fn saved(native: &Native, key: &[u8], default: Cursor) -> Result<Cursor> {
    native
        .database()
        .read(|view| view.get(key)?.map_or(Ok(default), |v| Cursor::decode(&v)))
}
fn acknowledge(native: &Native, cursor: Cursor) -> Result<()> {
    if let Database::Fjall(db, _) = native.database() {
        db.inner().retain_after(cursor.into())?;
    }
    Ok(())
}
fn write(native: &Native, key: &[u8], value: &[u8], commit: bool) -> Result<()> {
    native.database().write(commit, |tx| tx.put(key, value))?;
    Ok(())
}
fn maintain(native: &Native, rotate: bool) -> Result<()> {
    if let Database::Fjall(db, table) = native.database() {
        table.as_ref().flush(true)?;
        if rotate {
            db.inner().rotate_journal()?;
            table.as_ref().major_compact()?;
            db.inner().collect_journals()?;
        }
    }
    Ok(())
}

fn scenario(
    kind: &str,
    round: usize,
    references: &mut std::collections::BTreeMap<u64, super::Reference>,
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
    let before = super::compaction::Trace::completed();
    let mut native = Native::open(kind, directory.path())?;
    let mut initial = head(&native)?;
    let mut walker = Some(Walker::start(&native, directory.path(), initial, initial)?);
    let mut oracle = Oracle::default();
    let mut run = Run {
        engine: kind.into(),
        round,
        walks: Vec::new(),
        samples: Vec::new(),
        reopen_s: 0.0,
        compactions: 0,
        rotation: false,
        historical_views: 0,
    };
    for (i, spec) in fixture.steps.iter().copied().enumerate() {
        let restarted = i == 4;
        if restarted {
            run.walks.push(walker.take().unwrap().stop()?);
        }
        let started = Instant::now();
        write(&native, SOURCE, &spec.captured.to_be_bytes(), true)?;
        let source_commit_s = started.elapsed().as_secs_f64();
        if restarted {
            maintain(&native, true)?;
            run.rotation = kind == "fjall";
            let package_cursor = saved(&native, PACKAGE_ACK, initial)?;
            let graph_cursor = saved(&native, GRAPH_ACK, initial)?;
            acknowledge(&native, package_cursor.min(graph_cursor))?;
            native.shutdown()?;
            drop(native);
            let reopened = Instant::now();
            native = Native::open(kind, directory.path())?;
            run.reopen_s = reopened.elapsed().as_secs_f64();
            assert_eq!(saved(&native, PACKAGE_ACK, initial)?, package_cursor);
            assert_eq!(saved(&native, GRAPH_ACK, initial)?, graph_cursor);
            walker = Some(Walker::start(
                &native,
                directory.path(),
                package_cursor,
                graph_cursor,
            )?);
            acknowledge(&native, package_cursor.min(graph_cursor))?;
        }
        let active = walker.as_ref().unwrap();
        let source = Walker::receive(&active.source)?;
        let source_ready_s = started.elapsed().as_secs_f64();
        assert_eq!(source.value, spec.captured);
        let capture = Instant::now();
        let prepared = native.capture(&fixture, source.value, |view, _| {
            package::evaluate(view, &fixture, &incident, spec, &inputs[i])
        })?;
        let package_s = capture.elapsed().as_secs_f64();
        let output = Instant::now();
        let applied = native.apply_checkpoint(&prepared.step, &source.cursor.bytes(), true)?;
        let output_commit_s = output.elapsed().as_secs_f64();
        let graph = Walker::receive(&active.graph)?;
        let output_ready_s = output.elapsed().as_secs_f64();
        let total_s = started.elapsed().as_secs_f64();
        let counts = oracle.apply(&prepared.step);
        assert_eq!(counts, (applied.added, applied.closed));
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
        assert_eq!(graph.value, spec.revision);
        assert_eq!(graph.members, applied.added + applied.closed);
        assert_eq!(saved(&native, PACKAGE_ACK, initial)?, source.cursor);
        let mut state = native.inspect(&fixture, graph.value, true)?;
        oracle.check(&mut state, &fixture, graph.value)?;
        super::check_findings(&state.rows, spec.expected_findings)?;
        native.verify_metadata(&fixture, spec.revision, spec.revision)?;
        write(&native, GRAPH_ACK, &graph.cursor.bytes(), true)?;
        acknowledge(&native, source.cursor.min(graph.cursor))?;
        let calls = prepared
            .calls
            .iter()
            .map(|call| {
                let (w, op, relation, keys, count) = call.signature();
                (w, op.to_string(), relation, keys.to_vec(), count)
            })
            .collect::<Vec<_>>();
        if let Some(reference) = references.get(&spec.revision) {
            Fixture::assert_rows(&reference.rows, &mut state.rows)?;
            assert_eq!(reference.calls, calls);
            assert_eq!(reference.frontier, prepared.frontier);
        } else {
            references.insert(
                spec.revision,
                super::Reference {
                    rows: state.rows,
                    calls,
                    frontier: prepared.frontier.clone(),
                },
            );
        }
        run.samples.push(Sample {
            engine: kind.into(),
            round,
            revision: spec.revision,
            captured: spec.captured,
            restarted,
            source_commit_s,
            source_wake_s: source.seen.duration_since(started).as_secs_f64(),
            source_ready_s,
            package_s,
            output_commit_s,
            output_wake_s: graph.seen.duration_since(output).as_secs_f64(),
            output_ready_s,
            total_s,
            source_cursor: source.cursor,
            graph_cursor: graph.cursor,
            members: graph.members,
            findings: spec.expected_findings,
        });
        if i < 4 {
            maintain(&native, false)?;
        }
    }
    let active = walker.as_ref().unwrap();
    write(&native, SOURCE, &999u64.to_be_bytes(), false)?;
    let rollback = super::fixture::Spec {
        revision: 88,
        captured: 87,
        previous: 87,
        expected_findings: 3,
        expected_frontier: 18,
    };
    let input = incident.index_input(8, rollback)?;
    let prepared = native.capture(&fixture, 87, |view, _| {
        package::evaluate(view, &fixture, &incident, rollback, &input)
    })?;
    let package_cursor = saved(&native, PACKAGE_ACK, initial)?;
    native.apply_checkpoint(
        &prepared.step,
        &Cursor {
            journal: u64::MAX,
            offset: u64::MAX,
            sequence: u64::MAX,
        }
        .bytes(),
        false,
    )?;
    assert_eq!(saved(&native, PACKAGE_ACK, initial)?, package_cursor);
    native.verify_metadata(&fixture, 88, 87)?;
    oracle.check(&mut native.inspect(&fixture, 88, true)?, &fixture, 88)?;
    write(&native, b"unrelated/value", b"unrelated", true)?;
    let last = head(&native)?;
    active.scanned(last)?;
    active.quiet();
    run.walks.push(walker.take().unwrap().stop()?);
    for spec in &fixture.steps {
        oracle.check(
            &mut native.inspect(&fixture, spec.revision, true)?,
            &fixture,
            spec.revision,
        )?;
        native.verify_metadata(&fixture, spec.revision, 87)?;
        run.historical_views += 1;
    }
    native.shutdown()?;
    drop(native);
    native = Native::open(kind, directory.path())?;
    for spec in &fixture.steps {
        oracle.check(
            &mut native.inspect(&fixture, spec.revision, true)?,
            &fixture,
            spec.revision,
        )?;
        native.verify_metadata(&fixture, spec.revision, 87)?;
        run.historical_views += 1;
    }
    run.compactions = super::compaction::Trace::completed() - before;
    if kind == "fjall" {
        assert!(run.compactions > 0, "no physical compaction completed");
    }
    assert_eq!(run.walks.iter().map(|w| w.source_wakes).sum::<usize>(), 8);
    assert_eq!(run.walks.iter().map(|w| w.graph_wakes).sum::<usize>(), 8);
    initial = saved(&native, PACKAGE_ACK, initial)?;
    assert_eq!(initial, run.samples.last().unwrap().source_cursor);
    Ok(run)
}

pub fn run(output: &Path) -> Result<()> {
    super::compaction::Trace::install()?;
    let mut runs = Vec::new();
    let mut reference = std::collections::BTreeMap::new();
    for (round, order) in [
        ["fjall", "home"],
        ["home", "fjall"],
        ["home", "fjall"],
        ["fjall", "home"],
    ]
    .iter()
    .enumerate()
    {
        for kind in order {
            runs.push(scenario(kind, round, &mut reference)?);
        }
    }
    let report = serde_json::json!({
        "source": option_env!("POC_SOURCE_REVISION").unwrap_or("unrecorded"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "workload": "original eight Causal cycles, synthetic source-frontier metadata, original engine-journal reader drives both subscription wakes",
        "supported": { "fjall": "provided clone with opt-in journal-cdc patch", "home": "original durable transaction frames" },
        "unsupported": {
            "fjall-stock": "no public retained journal feed or event-driven CDC API",
            "redb": "copy-on-write pages; no original WAL feed",
            "duckdb": "no supported retained original-WAL CDC API",
            "surrealkv": "private WAL reader; no retained CDC API; value-log references also need retention",
            "neon-layers": "the layer adapter does not produce or stream PostgreSQL WAL"
        },
        "limits": ["prepared input Arrow, no DataFusion source query", "synthetic source metadata, no event capture", "no production notification delivery", "no branch qualification", "Fjall bulk ingestion and keyspace catalog changes are not CDC supported", "explicit flush/rotation/major compaction is correctness proof, not sustained compaction timing"],
        "runs": runs
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{} journal-driven runs, {} package cycles passed: {}",
        report["runs"].as_array().unwrap().len(),
        64,
        output.display()
    );
    Ok(())
}
