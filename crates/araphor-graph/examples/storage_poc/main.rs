mod duck;
mod fixture;
mod kv;
mod native;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::Schema;
use serde::{Deserialize, Serialize};

use fixture::{Fixture, Row, Step};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

impl Readout {
    fn check(&mut self, fixture: &Fixture, revision: u64) -> Result<()> {
        Fixture::assert_rows(&fixture.expected(revision), &mut self.rows)?;
        let last = fixture
            .steps
            .iter()
            .filter(|s| s.revision <= revision)
            .next_back();
        let mut states = Vec::new();
        for writer in [1, 2] {
            states.push(last.map(|s| s.state(writer)));
            states.push(last.map(|s| s.captured.to_be_bytes().to_vec()));
        }
        assert_eq!(self.states, states);
        let mut changes = Vec::new();
        if let Some(step) = fixture.steps.iter().find(|s| s.revision == revision) {
            let prior = fixture.expected(step.previous);
            for row in step.groups.iter().flat_map(|g| &g.rows) {
                if step.is_update(row) {
                    let before = prior
                        .iter()
                        .find(|b| b.identity() == row.identity())
                        .unwrap();
                    changes.push(Change::new(row, before.opened, false));
                }
                changes.push(Change::new(row, step.revision, true));
            }
        }
        changes.sort();
        assert_eq!(self.changes, changes);
        Ok(())
    }
}

enum Engine {
    Duck(duck::Duck),
    Native(native::Native),
}
impl Engine {
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
    fn inspect(&self, fixture: &Fixture, revision: u64, all: bool) -> Result<Readout> {
        match self {
            Self::Duck(db) => db.inspect(fixture, revision, all),
            Self::Native(db) => {
                let mut out = db.inspect(fixture, revision, all)?;
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
    input_capture_s: f64,
    input_read_s: f64,
    input_cdc_s: f64,
    output_capture_s: f64,
    output_read_s: f64,
    output_cdc_s: f64,
}

#[derive(Serialize)]
struct Run {
    engine: String,
    round: usize,
    open_s: f64,
    reopen_s: f64,
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
}

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().ok_or("usage: storage_poc OUTPUT.json")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = Path::new(&output);
    let parent = output.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let fixture = Fixture::new()?;
    let mut report = Report {
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        source: option_env!("POC_SOURCE_REVISION").unwrap_or("working-tree"),
        rounds: 6,
        workload: serde_json::json!({"scope":"Graph storage and synthetic atomic state/progress only",
            "source_case":"discovery::packages::required::incident::incremental::follows_incremental_sources",
            "writers":2,"relations":3,"steps":8,"inserted_versions":194,"closed_versions":8,
            "final_live_members":186,"probe_keys":fixture.probes.len(),
            "fixture_properties":"production schemas, generated typed values; not a production input replay",
            "durability":{"redb":"Immediate","fjall":"transaction SyncAll","duckdb":"normal on-disk COMMIT"},
            "excludes":["raw upload","Control","DataFusion execution","package algorithms",
                "Data authority and evidence pins","full finding projection","notification creation"],
            "limits":"small cached fixture; no steady-state compaction or power-loss proof"}),
        runs: Vec::new(),
        samples: Vec::new(),
    };
    let orders = [
        ["duckdb", "redb", "fjall"],
        ["redb", "fjall", "duckdb"],
        ["fjall", "duckdb", "redb"],
        ["fjall", "redb", "duckdb"],
        ["redb", "duckdb", "fjall"],
        ["duckdb", "fjall", "redb"],
    ];
    for (round, order) in orders.into_iter().enumerate() {
        for kind in order {
            let directory = tempfile::Builder::new()
                .prefix("araphor-storage-poc-")
                .tempdir_in(parent)?;
            let started = Instant::now();
            let mut engine = Engine::open(kind, directory.path(), &fixture)?;
            let open_s = started.elapsed().as_secs_f64();
            let (mut write_s, mut warm_read_s) = (0.0, 0.0);
            for step in &fixture.steps {
                let mut input = engine.inspect(&fixture, step.previous, false)?;
                input.check(&fixture, step.previous)?;
                engine.verify_metadata(&fixture, step.previous, step.previous)?;
                let write = engine.apply(&fixture, step, true)?;
                write_s += write.total_s;
                let mut out = engine.inspect(&fixture, step.revision, false)?;
                out.check(&fixture, step.revision)?;
                engine.verify_metadata(&fixture, step.revision, step.revision)?;
                warm_read_s += input.capture_s
                    + input.read_s
                    + input.cdc_s
                    + out.capture_s
                    + out.read_s
                    + out.cdc_s;
                report.samples.push(Sample {
                    engine: kind.into(),
                    round,
                    write,
                    input_capture_s: input.capture_s,
                    input_read_s: input.read_s,
                    input_cdc_s: input.cdc_s,
                    output_capture_s: out.capture_s,
                    output_read_s: out.read_s,
                    output_cdc_s: out.cdc_s,
                });
            }
            let mut historical_read_s = 0.0;
            for step in &fixture.steps {
                let mut read = engine.inspect(&fixture, step.revision, true)?;
                historical_read_s += read.capture_s + read.read_s + read.cdc_s;
                read.check(&fixture, step.revision)?;
                engine.verify_metadata(&fixture, step.revision, 87)?;
            }
            let mut rollback = Fixture::new()?;
            let mut step = rollback.steps.remove(2);
            step.previous = 87;
            step.revision = 88;
            step.captured = 87;
            for row in step.groups.iter_mut().flat_map(|g| &mut g.rows) {
                row.opened = 88;
            }
            engine.apply(&fixture, &step, false)?;
            engine.inspect(&fixture, 87, true)?.check(&fixture, 87)?;
            engine.verify_metadata(&fixture, 88, 87)?;
            drop(engine);
            let started = Instant::now();
            let engine = Engine::open(kind, directory.path(), &fixture)?;
            let reopen_s = started.elapsed().as_secs_f64();
            let mut reopened_read_s = 0.0;
            for step in &fixture.steps {
                let mut read = engine.inspect(&fixture, step.revision, true)?;
                reopened_read_s += read.capture_s + read.read_s + read.cdc_s;
                read.check(&fixture, step.revision)?;
                engine.verify_metadata(&fixture, step.revision, 87)?;
            }
            engine.inspect(&fixture, 88, true)?.check(&fixture, 88)?;
            engine.verify_metadata(&fixture, 88, 87)?;
            drop(engine);
            let (file_bytes, allocated_bytes, files) = usage(directory.path())?;
            report.runs.push(Run {
                engine: kind.into(),
                round,
                open_s,
                reopen_s,
                write_s,
                warm_read_s,
                historical_read_s,
                reopened_read_s,
                file_bytes,
                allocated_bytes,
                files,
            });
            eprintln!(
                "round={} engine={} writes_ms={:.3} warm_reads_ms={:.3}",
                round + 1,
                kind,
                write_s * 1000.0,
                warm_read_s * 1000.0
            );
        }
    }
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
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

fn materialize(rows: Vec<Row>, fixture: &Fixture) -> Result<Vec<Row>> {
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
        result.extend(rows_from_batch(
            relation,
            batch,
            &rows.iter().map(|r| r.opened).collect::<Vec<_>>(),
        )?);
    }
    Ok(result)
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
