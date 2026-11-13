use std::{
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use araphor_data::analysis::{
    native::benchmark::columnar::{Counts, Layout, Table},
    raw_benchmark::Result,
};
use datafusion::{
    arrow::{
        array::{Array, BinaryArray, Int32Array, UInt32Array, UInt64Array},
        record_batch::RecordBatch,
    },
    physical_plan::{collect, ExecutionPlan},
    prelude::{SessionConfig, SessionContext},
};
use serde_json::json;

#[allow(dead_code)]
#[path = "raw_storage/common.rs"]
mod common;
#[path = "table_storage/provider.rs"]
mod provider;
use provider::{Binding, Provider};

const QUERIES: [(&str, &str); 6] = [
    ("full", "SELECT * FROM events"),
    ("raw", "SELECT source_cursor, framed_record FROM events"),
    ("projected", "SELECT source_cursor, task_cookie FROM events"),
    (
        "cpu",
        "SELECT source_cursor, task_cookie FROM events WHERE cpu_id = 2",
    ),
    (
        "residual",
        "SELECT source_cursor, task_cookie FROM events WHERE cpu_id = 2 AND task_cookie % 7 = 0",
    ),
    (
        "late_raw",
        "SELECT source_cursor, framed_record FROM events WHERE cpu_id = 2 AND task_cookie % 7 = 0",
    ),
];

struct Queries {
    context: SessionContext,
    binding: Arc<RwLock<Binding>>,
    counts: Arc<Mutex<Counts>>,
    plans: Vec<Arc<dyn ExecutionPlan>>,
    planning_s: f64,
}

impl Queries {
    async fn new(table: Arc<Table>) -> Result<Self> {
        let context =
            SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1));
        let binding = Arc::new(RwLock::new(Binding {
            view: table.database.read_tx(),
            table: Arc::clone(&table),
            only: None,
        }));
        let counts = Arc::new(Mutex::new(Counts::default()));
        context.register_table(
            "events",
            Arc::new(Provider {
                binding: Arc::clone(&binding),
                counts: Arc::clone(&counts),
                schema: Arc::clone(&table.schema),
            }),
        )?;
        let started = Instant::now();
        let mut plans = Vec::new();
        for (_, sql) in QUERIES {
            plans.push(context.sql(sql).await?.create_physical_plan().await?);
        }
        Ok(Self {
            context,
            binding,
            counts,
            plans,
            planning_s: started.elapsed().as_secs_f64(),
        })
    }

    async fn run(
        &self,
        index: usize,
        only: Option<Vec<u8>>,
    ) -> Result<(Vec<RecordBatch>, serde_json::Value)> {
        *self.counts.lock().unwrap() = Counts::default();
        let started = Instant::now();
        {
            let mut binding = self.binding.write().unwrap();
            binding.view = binding.table.database.read_tx();
            binding.only = only;
        }
        let batches = collect(Arc::clone(&self.plans[index]), self.context.task_ctx()).await?;
        let elapsed_s = started.elapsed().as_secs_f64();
        let rows = batches.iter().map(RecordBatch::num_rows).sum::<usize>();
        Ok((
            batches,
            json!({"elapsed_s":elapsed_s,"rows":rows,"reads":*self.counts.lock().unwrap()}),
        ))
    }

    async fn suite(&self, frames: &[Vec<u8>], total: u64) -> Result<serde_json::Value> {
        let mut reports = serde_json::Map::new();
        for (index, (name, _)) in QUERIES.iter().enumerate() {
            let (batches, report) = self.run(index, None).await?;
            Self::verify(&batches, name, frames, total);
            reports.insert((*name).into(), report);
        }
        Ok(reports.into())
    }

    fn verify(batches: &[RecordBatch], name: &str, frames: &[Vec<u8>], total: u64) {
        let mut seen = Self::verify_values(batches, frames);
        seen.sort_unstable();
        let expected = (1..=total)
            .filter(|cursor| {
                (!matches!(name, "cpu" | "residual" | "late_raw") || (cursor - 1) / 256 % 4 == 2)
                    && (!matches!(name, "residual" | "late_raw") || cursor % 7 == 0)
            })
            .collect::<Vec<_>>();
        assert_eq!(seen, expected);
    }

    fn verify_values(batches: &[RecordBatch], frames: &[Vec<u8>]) -> Vec<u64> {
        let mut seen = Vec::new();
        for batch in batches {
            let cursors = batch
                .column_by_name("source_cursor")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            for row in 0..batch.num_rows() {
                let cursor = cursors.value(row);
                seen.push(cursor);
                if let Some(array) = batch.column_by_name("framed_record") {
                    assert_eq!(
                        array
                            .as_any()
                            .downcast_ref::<BinaryArray>()
                            .unwrap()
                            .value(row),
                        frames[cursor as usize - 1]
                    );
                }
                if let Some(array) = batch.column_by_name("task_cookie") {
                    assert_eq!(
                        array
                            .as_any()
                            .downcast_ref::<UInt64Array>()
                            .unwrap()
                            .value(row),
                        cursor
                    );
                }
                if let Some(array) = batch.column_by_name("cpu_id") {
                    assert_eq!(
                        array
                            .as_any()
                            .downcast_ref::<UInt32Array>()
                            .unwrap()
                            .value(row),
                        ((cursor - 1) / 256 % 4) as u32
                    );
                }
                if let Some(array) = batch.column_by_name("operation") {
                    assert_eq!(
                        array
                            .as_any()
                            .downcast_ref::<UInt32Array>()
                            .unwrap()
                            .value(row),
                        1
                    );
                }
                if let Some(array) = batch.column_by_name("kernel_result") {
                    assert_eq!(
                        array
                            .as_any()
                            .downcast_ref::<Int32Array>()
                            .unwrap()
                            .value(row),
                        -13
                    );
                }
            }
        }
        seen
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("use a release build".into());
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: table_storage_bench frames|packed|columns RECORDS REPORT.json".into());
    }
    let layout = match args[0].as_str() {
        "frames" => Layout::Frames,
        "packed" => Layout::Packed,
        "columns" => Layout::Columns,
        _ => return Err("unknown layout".into()),
    };
    let total: u64 = args[1].parse()?;
    if total < 1024 || total % 1024 != 0 {
        return Err("records must be a multiple of 1024".into());
    }
    let (mut batches, frames) = common::inputs(total + 256)?;
    for (index, batch) in batches.iter_mut().enumerate() {
        batch.cpu_id = (index % 4) as u32;
    }
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let mut table = Arc::new(Table::open(&root, layout, Table::schema())?);
    let start = table
        .database
        .inner()
        .journal_head()?
        .ok_or("missing initial cursor")?;
    let mut queries = Queries::new(Arc::clone(&table)).await?;
    let mut changes = table.database.inner().journal_feed(Some(start))?;
    rustix::fs::syncfs(&std::fs::File::open(&root)?)?;
    let mut samples = Vec::new();
    let mut middle = None;
    let mut held = None;
    let mut input = start;
    let mut output = start;
    let started = Instant::now();
    for (index, batch) in batches.iter().take((total / 256) as usize).enumerate() {
        let cycle = Instant::now();
        let accept = Instant::now();
        input = table.append(batch)?.cursor;
        let accept_ns = accept.elapsed().as_nanos() as u64;
        let read = Instant::now();
        let (key, observed) = loop {
            let publication = changes.next_batch()?.ok_or("missing committed input")?;
            if let Some(item) = publication.items.iter().find(|item| {
                item.keyspace == table.events.inner().id() && item.key.first() == Some(&b'H')
            }) {
                assert_eq!(
                    publication
                        .items
                        .iter()
                        .filter(|item| item.keyspace == table.events.inner().id()
                            && item.key.first() == Some(&b'H'))
                        .count(),
                    1
                );
                break (item.key[1..].to_vec(), publication.cursor);
            }
        };
        assert_eq!(observed, input);
        input = observed;
        assert_eq!(key, Table::batch_key(batch.first_cursor, batch.cpu_id));
        let (selected, _) = queries.run(2, Some(key)).await?;
        let read_ns = read.elapsed().as_nanos() as u64;
        assert_eq!(
            selected.iter().map(RecordBatch::num_rows).sum::<usize>(),
            256
        );
        let progress = Instant::now();
        output = table.complete(input)?.cursor;
        let progress_ns = progress.elapsed().as_nanos() as u64;
        samples.push(json!({"accept_ns":accept_ns,"read_ns":read_ns,"progress_ns":progress_ns,"total_ns":cycle.elapsed().as_nanos() as u64}));
        if index + 1 == (total / 512) as usize {
            middle = Some(table.saved()?);
            held = Some(table.database.read_tx());
        }
    }
    let cycle_s = started.elapsed().as_secs_f64();
    assert_eq!(table.saved()?, input);
    assert_ne!(input, output);
    let middle = middle.ok_or("missing saved cut")?;
    let replay = table.replay(middle, output)?;
    let expected = batches
        .iter()
        .skip((total / 512) as usize)
        .take((total / 512) as usize)
        .map(|batch| Table::batch_key(batch.first_cursor, batch.cpu_id))
        .collect::<Vec<_>>();
    assert_eq!(replay, expected);
    let view = table.database.read_tx();
    for key in &replay {
        let mut counts = Counts::default();
        for (key, header) in table.headers(&view, Some(key), &mut counts)? {
            let batch = araphor_data::analysis::native::benchmark::columnar::Page::new(
                &table, &view, &key, &header,
            )
            .read(&[0, 1, 2, 3, 4, 5])?;
            assert_eq!(
                Queries::verify_values(&[batch], &frames),
                (header.first..header.first + header.rows as u64).collect::<Vec<_>>()
            );
        }
    }
    drop(view);
    let mut counts = Counts::default();
    assert_eq!(
        table
            .headers(held.as_ref().unwrap(), None, &mut counts)?
            .len(),
        (total / 512) as usize
    );
    let view = held.as_ref().unwrap();
    let retained = table
        .headers(view, None, &mut counts)?
        .into_iter()
        .map(|(key, header)| {
            araphor_data::analysis::native::benchmark::columnar::Page::new(
                &table, view, &key, &header,
            )
            .read(&[0, 1, 2, 3, 4, 5])
        })
        .collect::<Result<Vec<_>>>()?;
    Queries::verify(&retained, "full", &frames, total / 2);
    drop(retained);
    let warm = queries.suite(&frames, total).await?;
    let maintenance = Instant::now();
    table.database.inner().flush_memtables()?;
    table.database.inner().major_compact()?;
    let maintenance_s = maintenance.elapsed().as_secs_f64();
    let maintained = common::size(&root)?;
    let after_flush = queries.suite(&frames, total).await?;
    let statistics = table.statistics()?;
    let planning_s = queries.planning_s;
    drop(changes);
    drop(held);
    drop(queries);
    drop(table);
    let reopen = Instant::now();
    table = Arc::new(Table::open(&root, layout, Table::schema())?);
    let reopen_s = reopen.elapsed().as_secs_f64();
    assert_eq!(table.saved()?, input);
    assert_eq!(table.replay(middle, output)?, replay);
    assert!(table.replay(input, output)?.is_empty());
    queries = Queries::new(Arc::clone(&table)).await?;
    let reopened = queries.suite(&frames, total).await?;
    let mut feed = table.database.inner().journal_feed(Some(output))?;
    assert!(feed.next_batch()?.is_none());
    let next = table.append(&batches[(total / 256) as usize])?.cursor;
    assert!(feed.wait()?);
    let publication = feed.next_batch()?.ok_or("missing continued publication")?;
    assert_eq!(publication.cursor, next);
    let changed = table.replay(input, next)?;
    assert_eq!(
        changed,
        vec![Table::batch_key(
            total + 1,
            batches[(total / 256) as usize].cpu_id
        )]
    );
    let (continued, _) = queries.run(0, Some(changed[0].clone())).await?;
    assert_eq!(
        continued.iter().map(RecordBatch::num_rows).sum::<usize>(),
        256
    );
    assert_eq!(
        Queries::verify_values(&continued, &frames),
        (total + 1..=total + 256).collect::<Vec<_>>()
    );
    table.complete(next)?;
    assert_eq!(table.saved()?, next);
    let report = json!({"layout":args[0],"records":total,"batch_records":256,"input_bytes":frames.iter().take(total as usize).map(Vec::len).sum::<usize>(),
        "cycle_s":cycle_s,"cycle_events_s":total as f64/cycle_s,"samples":samples,"planning_s":planning_s,"reopen_planning_s":queries.planning_s,
        "warm":warm,"after_flush":after_flush,"reopened":reopened,"maintenance_s":maintenance_s,"maintained_bytes":maintained,"statistics":statistics,"reopen_s":reopen_s,
        "checks":{"original_bytes":true,"all_query_rows":true,"held_snapshot":true,"original_log_resume":true,"durable_input_progress":true,"continued_wake":true}});
    std::fs::write(Path::new(&args[2]), serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{}",
        json!({"layout":args[0],"records":total,"cycle_events_s":total as f64/cycle_s})
    );
    Ok(())
}

#[cfg(test)]
#[path = "table_storage/tests.rs"]
mod tests;
