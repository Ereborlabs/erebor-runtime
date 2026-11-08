#![allow(unexpected_cfgs)]

#[cfg(feature = "cdc-poc")]
mod cdc;
mod compaction;
mod duck;
mod fixture;
mod history;
mod home;
mod incident;
mod kv;
mod native;
#[cfg(feature = "neon-poc")]
mod neon;
mod package;
#[cfg(all(feature = "neon-poc", feature = "cdc-poc"))]
mod stable;
mod surreal;

use araphor_graph::Read;
use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::Schema;
use fixture::{Fixture, Row, Step};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

trait GraphRead {
    fn query(&self, relation: u64, read: Read, keys: &RecordBatch) -> Result<Vec<RecordBatch>>;
    fn presence(&self, writer: u64, relation: u64, batch: &RecordBatch) -> Result<Vec<bool>>;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
struct Change {
    writer: u64,
    relation: u64,
    owner: Vec<u8>,
    key: Vec<u8>,
    opened: u64,
    added: bool,
}
impl Change {
    fn new(row: &Row, opened: u64, added: bool) -> Self {
        Self {
            writer: row.writer,
            relation: row.relation,
            owner: row.owner.clone(),
            key: row.key.clone(),
            opened,
            added,
        }
    }
}

#[derive(Default, Serialize)]
struct Timing {
    revision: u64,
    prepare_s: f64,
    work_s: f64,
    commit_s: f64,
    total_s: f64,
    added: usize,
    closed: usize,
    encoded_bytes: usize,
}
struct Readout {
    rows: Vec<Row>,
    states: Vec<Option<Vec<u8>>>,
    changes: Vec<Change>,
    capture_s: f64,
    read_s: f64,
    cdc_s: f64,
}

#[derive(Default)]
struct Oracle {
    current: BTreeMap<(u64, u64, Vec<u8>, Vec<u8>), Row>,
    views: BTreeMap<u64, Vec<Row>>,
    changes: BTreeMap<u64, Vec<Change>>,
}
impl Oracle {
    fn apply(&mut self, step: &Step) -> (usize, usize) {
        let mut changes = Vec::new();
        for (writer, owner) in &step.clears {
            let keys = self
                .current
                .iter()
                .filter(|(_, r)| {
                    r.writer == *writer && owner.as_ref().is_none_or(|o| o == &r.owner)
                })
                .map(|(k, _)| k.clone())
                .collect::<Vec<_>>();
            for key in keys {
                let old = self.current.remove(&key).unwrap();
                changes.push(Change::new(&old, old.opened, false));
            }
        }
        for row in step.groups.iter().flat_map(|g| &g.rows) {
            if let Some(old) = self.current.insert(row.identity(), row.clone()) {
                changes.push(Change::new(&old, old.opened, false));
            }
            changes.push(Change::new(row, step.revision, true));
        }
        let added = changes.iter().filter(|c| c.added).count();
        let closed = changes.len() - added;
        changes.sort();
        self.changes.insert(step.revision, changes);
        self.views
            .insert(step.revision, self.current.values().cloned().collect());
        (added, closed)
    }
    fn check(&self, out: &mut Readout, fixture: &Fixture, revision: u64) -> Result<()> {
        let expected = self
            .views
            .range(..=revision)
            .next_back()
            .map(|(_, r)| r.as_slice())
            .unwrap_or(&[]);
        Fixture::assert_rows(expected, &mut out.rows)?;
        let last = fixture
            .steps
            .iter()
            .filter(|s| s.revision <= revision)
            .next_back();
        let mut states = Vec::new();
        for writer in [1u64, 2] {
            states.push(last.map(|s| {
                [
                    writer.to_be_bytes().as_slice(),
                    s.captured.to_be_bytes().as_slice(),
                    &[0x7f; 64],
                ]
                .concat()
            }));
            states.push(last.map(|s| s.captured.to_be_bytes().to_vec()));
        }
        assert_eq!(out.states, states);
        assert_eq!(
            out.changes,
            self.changes.get(&revision).cloned().unwrap_or_default()
        );
        Ok(())
    }
}

enum Engine {
    Duck(duck::Duck),
    Native(native::Native),
}
impl Engine {
    fn close(&self) -> Result<()> {
        match self {
            Self::Duck(_) => Ok(()),
            Self::Native(db) => db.shutdown(),
        }
    }

    fn open(kind: &str, path: &Path, fixture: &Fixture) -> Result<Self> {
        if kind == "duckdb" {
            Ok(Self::Duck(duck::Duck::open(path, fixture)?))
        } else {
            Ok(Self::Native(native::Native::open(kind, path)?))
        }
    }
    fn apply(&mut self, fixture: &Fixture, step: &Step, commit: bool) -> Result<Timing> {
        match self {
            Self::Duck(db) => db.apply(fixture, step, commit),
            Self::Native(db) => db.apply(fixture, step, commit),
        }
    }
    fn capture<T>(
        &self,
        fixture: &Fixture,
        revision: u64,
        action: impl FnOnce(&dyn GraphRead, f64) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Duck(db) => db.capture(fixture, revision, action),
            Self::Native(db) => db.capture(fixture, revision, action),
        }
    }
    fn inspect(&self, fixture: &Fixture, revision: u64) -> Result<Readout> {
        match self {
            Self::Duck(db) => db.inspect(fixture, revision, true),
            Self::Native(db) => {
                let mut out = db.inspect(fixture, revision, true)?;
                let started = Instant::now();
                out.rows = materialize(out.rows, fixture)?;
                out.read_s += started.elapsed().as_secs_f64();
                Ok(out)
            }
        }
    }
    fn verify_metadata(&self, fixture: &Fixture, revision: u64, current: u64) -> Result<()> {
        match self {
            Self::Duck(db) => db.verify_metadata(fixture, revision, current),
            Self::Native(db) => db.verify_metadata(fixture, revision, current),
        }
    }
}

#[derive(Serialize)]
struct Sample {
    engine: String,
    round: usize,
    write: Timing,
    scenario_s: f64,
    capture_s: f64,
    index_s: f64,
    resolve_s: f64,
    detect_s: f64,
    normalize_s: f64,
    verification_read_s: f64,
    frontier_records: Vec<usize>,
    calls: Vec<package::Call>,
}
#[derive(Serialize)]
struct Run {
    engine: String,
    round: usize,
    open_s: f64,
    reopen_s: f64,
    scenario_s: f64,
    write_s: f64,
    warm_read_s: f64,
    historical_read_s: f64,
    reopened_read_s: f64,
    file_bytes: u64,
    allocated_bytes: u64,
    files: usize,
}
#[derive(Serialize)]
struct Report {
    profile: &'static str,
    source: &'static str,
    rounds: usize,
    workload: serde_json::Value,
    runs: Vec<Run>,
    samples: Vec<Sample>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    history: Vec<history::Sample>,
}
struct Reference {
    rows: Vec<Row>,
    calls: Vec<(u64, String, u64, Vec<Vec<u8>>, usize)>,
    frontier: Vec<usize>,
}

fn main() -> Result<()> {
    #[cfg(feature = "cdc-poc")]
    if std::env::args().nth(2).as_deref() == Some("combined") {
        return cdc::combined(Path::new(
            &std::env::args().nth(1).ok_or("output path required")?,
        ));
    }
    #[cfg(all(feature = "neon-poc", feature = "cdc-poc"))]
    if std::env::args().nth(2).as_deref() == Some("stable") {
        return stable::run(Path::new(
            &std::env::args().nth(1).ok_or("output path required")?,
        ));
    }
    #[cfg(feature = "cdc-poc")]
    if std::env::args().nth(2).as_deref() == Some("cdc") {
        return cdc::run(Path::new(
            &std::env::args().nth(1).ok_or("output path required")?,
        ));
    }

    let mut arguments = std::env::args_os().skip(1);
    let output = arguments
        .next()
        .ok_or("usage: storage_poc OUTPUT.json [compaction|surrealkv|versioned]")?;
    let mode = arguments.next();
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = Path::new(&output);
    if mode.as_deref() == Some(std::ffi::OsStr::new("compaction")) {
        return compaction::run(output);
    }
    let versioned = mode.as_deref() == Some(std::ffi::OsStr::new("versioned"));
    let orders: Vec<Vec<&str>> = match mode.as_deref() {
        None => vec![
            vec!["duckdb", "redb", "home", "fjall"],
            vec!["redb", "fjall", "duckdb", "home"],
            vec!["fjall", "home", "redb", "duckdb"],
            vec!["home", "duckdb", "fjall", "redb"],
            vec!["home", "duckdb", "fjall", "redb"],
            vec!["fjall", "home", "redb", "duckdb"],
            vec!["redb", "fjall", "duckdb", "home"],
            vec!["duckdb", "redb", "home", "fjall"],
        ],
        Some(mode) if mode == "surrealkv" => vec![
            vec!["redb", "fjall", "surrealkv"],
            vec!["fjall", "surrealkv", "redb"],
            vec!["surrealkv", "redb", "fjall"],
            vec!["surrealkv", "fjall", "redb"],
            vec!["fjall", "redb", "surrealkv"],
            vec!["redb", "surrealkv", "fjall"],
        ],
        Some(mode) if mode == "versioned" => history::History::orders(),
        _ => return Err("unknown scenario".into()),
    };
    let parent = output.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let fixture = Fixture::new()?;
    let incident = incident::Incident::new()?;
    let inputs = fixture
        .steps
        .iter()
        .enumerate()
        .map(|(i, s)| incident.index_input(i, *s))
        .collect::<Result<Vec<_>>>()?;
    let mut references = BTreeMap::<u64, Reference>::new();
    let mut history = history::History::default();
    let mut report = Report {
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        source: option_env!("POC_SOURCE_REVISION").unwrap_or("working-tree"),
        rounds: orders.len(),
        workload: serde_json::json!({"scope":"actual Causal package Graph scenario through SDK InvocationHost",
            "case":"discovery::packages::required::incident::incremental::follows_incremental_sources",
            "package":"HF-CAUSAL-001","exports":["index","detect"],"steps":8,"source_streams":4,"nodes":2,"episodes":3,
            "scenario_interval":"capture -> actual index traversal/staging -> resolved detect inputs -> actual detection/staging -> durable atomic Graph/state commit",
            "traversal":"actual package iterative neighbors(Either); next keys depend on returned edges",
            "source_inputs":"typed incident audit and observation fixture; same6-action scenario; prepared index inputs",
            "durability":{"redb":"Immediate","fjall":"transaction SyncAll","duckdb":"normal on-disk COMMIT","home":"one append-only frame and sync_all per transaction; immutable RAM index","surrealkv":"transaction Immediate; native transactions; engine versioning off; same explicit Graph history keys"},
            "excludes":["Control/raw ingestion","native DataFusion input execution","Data authority/evidence pins","notification creation","steady compaction/power loss"],
            "qualification_reads":"8 post-commit finite all-member reads; historical snapshots, rollback and reopen outside primary interval"}),
        runs: Vec::new(),
        samples: Vec::new(),
        history: Vec::new(),
    };
    if versioned {
        report.workload["history"] = serde_json::json!({"scope":"actual package replay at original Graph input cuts", "order":"backward then forward", "stages":["after-writes", "after-reopen"], "writes":false, "surrealkv-native":"set_at, soft tombstones, get_at, timestamp-filtered native history; unlimited retention", "neon-layers":"native durable delta per transaction; exact-key RAM catalog; no quorum WAL or compaction"});
    }
    for (round, order) in orders.into_iter().enumerate() {
        for kind in order {
            let directory = tempfile::Builder::new()
                .prefix("araphor-causal-poc-")
                .tempdir_in(parent)?;
            let started = Instant::now();
            let mut engine = Engine::open(kind, directory.path(), &fixture)?;
            let open_s = started.elapsed().as_secs_f64();
            let (mut write_s, mut scenario_s, mut warm_read_s) = (0.0, 0.0, 0.0);
            let mut oracle = Oracle::default();
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
                let elapsed = started.elapsed().as_secs_f64();
                scenario_s += elapsed;
                write_s += write.total_s;
                let mut out = engine.inspect(&fixture, spec.revision)?;
                let verification_read_s = out.capture_s + out.read_s + out.cdc_s;
                warm_read_s += verification_read_s;
                let counts = oracle.apply(&prepared.step);
                assert_eq!((write.added, write.closed), counts);
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
                oracle.check(&mut out, &fixture, spec.revision)?;
                check_findings(&out.rows, spec.expected_findings)?;
                engine.verify_metadata(&fixture, spec.revision, spec.revision)?;
                let calls = prepared
                    .calls
                    .iter()
                    .map(|c| {
                        let (w, op, r, k, n) = c.signature();
                        (w, op.to_string(), r, k.to_vec(), n)
                    })
                    .collect::<Vec<_>>();
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
                if versioned {
                    history.remember(spec.revision, &prepared)?;
                }
                report.samples.push(Sample {
                    engine: kind.into(),
                    round,
                    write,
                    scenario_s: elapsed,
                    capture_s,
                    index_s: prepared.index_s,
                    resolve_s: prepared.resolve_s,
                    detect_s: prepared.detect_s,
                    normalize_s: prepared.normalize_s,
                    verification_read_s,
                    frontier_records: prepared.frontier,
                    calls: prepared.calls,
                });
            }
            let mut historical_read_s = 0.0;
            for spec in &fixture.steps {
                let mut out = engine.inspect(&fixture, spec.revision)?;
                historical_read_s += out.capture_s + out.read_s + out.cdc_s;
                oracle.check(&mut out, &fixture, spec.revision)?;
                engine.verify_metadata(&fixture, spec.revision, 87)?;
            }
            if versioned {
                report.history.extend(history.replay(
                    &engine,
                    &fixture,
                    &incident,
                    &inputs,
                    kind,
                    round,
                    "after-writes",
                )?);
            }
            let rollback = fixture::Spec {
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
            oracle.check(&mut engine.inspect(&fixture, 87)?, &fixture, 87)?;
            engine.verify_metadata(&fixture, 88, 87)?;
            engine.close()?;
            drop(engine);
            let started = Instant::now();
            let engine = Engine::open(kind, directory.path(), &fixture)?;
            let reopen_s = started.elapsed().as_secs_f64();
            let mut reopened_read_s = 0.0;
            for spec in &fixture.steps {
                let mut out = engine.inspect(&fixture, spec.revision)?;
                reopened_read_s += out.capture_s + out.read_s + out.cdc_s;
                oracle.check(&mut out, &fixture, spec.revision)?;
                engine.verify_metadata(&fixture, spec.revision, 87)?;
            }
            if versioned {
                report.history.extend(history.replay(
                    &engine,
                    &fixture,
                    &incident,
                    &inputs,
                    kind,
                    round,
                    "after-reopen",
                )?);
            }
            oracle.check(&mut engine.inspect(&fixture, 88)?, &fixture, 88)?;
            engine.verify_metadata(&fixture, 88, 87)?;
            engine.close()?;
            drop(engine);
            let (file_bytes, allocated_bytes, files) = usage(directory.path())?;
            eprintln!(
                "round={} engine={} scenario_ms={:.3} writes_ms={:.3}",
                round + 1,
                kind,
                scenario_s * 1000.0,
                write_s * 1000.0
            );
            report.runs.push(Run {
                engine: kind.into(),
                round,
                open_s,
                reopen_s,
                scenario_s,
                write_s,
                warm_read_s,
                historical_read_s,
                reopened_read_s,
                file_bytes,
                allocated_bytes,
                files,
            });
        }
    }
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
    Ok(())
}

fn check_findings(rows: &[Row], expected: usize) -> Result<()> {
    use araphor_analysis_types::{FindingMember, values::FindingStateV1};
    let findings = rows.iter().filter(|r| r.relation == 1).collect::<Vec<_>>();
    assert_eq!(findings.len(), expected);
    for row in findings {
        let members = FindingMember::decode(&araphor_analysis_sdk::Dataset {
            name: FindingMember::port().name,
            batches: vec![row.value()?],
        })?;
        assert_eq!(members.len(), 1);
        let value = &members[0].value;
        assert_eq!(value.state, FindingStateV1::Confirmed);
        assert_eq!(value.evidence.len(), 6);
        assert_eq!(
            value
                .evidence
                .iter()
                .map(|e| &e.stream.node_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        assert_eq!(
            value
                .evidence
                .iter()
                .map(|e| &e.stream)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
    }
    Ok(())
}

fn rows_from_batch(relation: u64, batch: RecordBatch, opened: &[u64]) -> Result<Vec<Row>> {
    let uint = batch
        .column_by_name("writer")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let binary = |name: &str| {
        batch
            .column_by_name(name)
            .unwrap()
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap()
    };
    let props = batch
        .column_by_name("properties")
        .unwrap()
        .as_any()
        .downcast_ref::<StructArray>()
        .unwrap();
    let properties = Arc::new(RecordBatch::try_new(
        Arc::new(Schema::new(props.fields().clone())),
        props.columns().to_vec(),
    )?);
    assert_eq!(batch.num_rows(), opened.len());
    Ok((0..batch.num_rows())
        .map(|row| Row {
            writer: uint.value(row),
            relation,
            owner: binary("owner").value(row).to_vec(),
            key: binary("key").value(row).to_vec(),
            endpoints: (relation == 3)
                .then(|| ["from", "to", "label"].map(|name| binary(name).value(row).to_vec())),
            properties: Arc::clone(&properties),
            row,
            opened: opened[row],
        })
        .collect())
}

fn batches_from_rows(rows: Vec<Row>, fixture: &Fixture) -> Result<Vec<RecordBatch>> {
    let mut groups = BTreeMap::<(u64, usize), Vec<Row>>::new();
    for row in rows {
        groups
            .entry((row.relation, Arc::as_ptr(&row.properties) as usize))
            .or_default()
            .push(row);
    }
    let mut result = Vec::new();
    for ((relation, _), rows) in groups {
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.writer))),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|r| r.owner.as_slice()),
            )),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|r| r.key.as_slice()),
            )),
        ];
        if relation == 3 {
            for i in 0..3 {
                columns.push(Arc::new(BinaryArray::from_iter_values(
                    rows.iter()
                        .map(|r| r.endpoints.as_ref().unwrap()[i].as_slice()),
                )));
            }
        }
        let props = arrow_select::take::take_record_batch(
            &rows[0].properties,
            &UInt64Array::from_iter_values(rows.iter().map(|r| r.row as u64)),
        )?;
        columns.push(Arc::new(StructArray::from(props)));
        let batch =
            RecordBatch::try_new(Arc::new(fixture.shapes[&relation].read_schema()), columns)?;
        result.push(batch);
    }
    Ok(result)
}

fn materialize(rows: Vec<Row>, fixture: &Fixture) -> Result<Vec<Row>> {
    let opened = rows
        .iter()
        .map(|r| {
            (
                (r.writer, r.relation, r.owner.clone(), r.key.clone()),
                r.opened,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for batch in batches_from_rows(rows, fixture)? {
        let relation = if batch.column_by_name("from").is_some() {
            3
        } else if batch
            .column_by_name("properties")
            .ok_or("properties absent")?
            .as_any()
            .downcast_ref::<StructArray>()
            .ok_or("properties type")?
            .fields()
            .iter()
            .any(|f| f.name() == "kind")
        {
            2
        } else {
            1
        };
        let writers = batch
            .column_by_name("writer")
            .ok_or("writer absent")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("writer type")?;
        let owners = binary(&batch, "owner")?;
        let keys = binary(&batch, "key")?;
        let revisions = (0..batch.num_rows())
            .map(|i| {
                opened[&(
                    writers.value(i),
                    relation,
                    owners.value(i).to_vec(),
                    keys.value(i).to_vec(),
                )]
            })
            .collect::<Vec<_>>();
        result.extend(rows_from_batch(relation, batch, &revisions)?);
    }
    Ok(result)
}

fn binary<'a>(batch: &'a RecordBatch, name: &str) -> Result<&'a BinaryArray> {
    batch
        .column_by_name(name)
        .and_then(|a| a.as_any().downcast_ref::<BinaryArray>())
        .ok_or_else(|| format!("binary column {name} absent").into())
}

fn usage(path: &Path) -> Result<(u64, u64, usize)> {
    use std::os::unix::fs::MetadataExt;
    let (mut size, mut allocated, mut count) = (0, 0, 0);
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let bytes = if meta.is_dir() {
            usage(&entry.path())?
        } else {
            (meta.len(), meta.blocks() * 512, 1)
        };
        size += bytes.0;
        allocated += bytes.1;
        count += bytes.2;
    }
    Ok((size, allocated, count))
}
