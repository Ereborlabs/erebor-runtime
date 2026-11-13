use super::*;
use araphor_data::analysis::native::benchmark::columnar::{Header, Page};
use datafusion::arrow::{
    array::{ArrayRef, StringArray},
    datatypes::{DataType, Field, Schema},
};
use fjall::Readable;

#[test]
fn frame_bytes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let table = Table::open(directory.path(), Layout::Frames, Table::schema())?;
    let (batches, frames) = common::inputs(256)?;
    table.append(&batches[0])?;
    let view = table.database.read_tx();
    let mut counts = Counts::default();
    for (key, header) in table.headers(&view, None, &mut counts)? {
        let mut page = Page::new(&table, &view, &key, &header);
        let batch = page.read(&[1, 5])?;
        assert_eq!(batch.num_rows(), 256);
        assert_eq!(page.counts.raw_decodes, 0);
        let raw = batch
            .column(1)
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap();
        for (row, frame) in frames.iter().enumerate() {
            assert_eq!(raw.value(row), frame);
        }
    }
    Ok(())
}

#[tokio::test]
async fn mixed_cpu_and_projection() -> Result<()> {
    for layout in [Layout::Packed, Layout::Columns] {
        let directory = tempfile::tempdir()?;
        let table = Arc::new(Table::open(directory.path(), layout, Table::schema())?);
        let (batches, _) = common::inputs(256)?;
        let mut batch = Table::build(&batches[0])?;
        let mut arrays = batch.columns().to_vec();
        arrays[0] = Arc::new(UInt32Array::from_iter_values(
            (0..256).map(|index| (index % 4) as u32),
        ));
        batch = RecordBatch::try_new(batch.schema(), arrays)?;
        let key = Table::batch_key(1, 0);
        table.append_arrow(
            &key,
            &Header {
                first: 1,
                rows: 256,
                cpu: None,
            },
            &batch,
        )?;
        let queries = Queries::new(Arc::clone(&table)).await?;
        let (selected, _) = queries.run(3, None).await?;
        let cursors = selected
            .iter()
            .flat_map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            cursors,
            (1..=256)
                .filter(|cursor| (cursor - 1) % 4 == 2)
                .collect::<Vec<_>>()
        );
        let (_, report) = queries.run(2, None).await?;
        assert_eq!(report["reads"]["ipc_columns"].as_u64().unwrap(), 2);
    }
    Ok(())
}

#[tokio::test]
async fn schema_and_abort() -> Result<()> {
    for layout in [Layout::Packed, Layout::Columns] {
        let directory = tempfile::tempdir()?;
        let schema = Arc::new(Schema::new(vec![
            Field::new("received_at", DataType::UInt64, false),
            Field::new("severity", DataType::Utf8, true),
        ]));
        let table = Table::open(directory.path(), layout, Arc::clone(&schema))?;
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(UInt64Array::from(vec![1, 2, 3])) as ArrayRef,
                Arc::new(StringArray::from(vec![Some("info"), None, Some("error")])),
            ],
        )?;
        let key = Table::batch_key(1, 0);
        let header = Header {
            first: 1,
            rows: 3,
            cpu: None,
        };
        let before = table.database.read_tx();
        {
            let mut tx = table.database.write_tx();
            tx.insert(
                &table.events,
                Table::key(b'H', None, &key),
                rmp_serde::to_vec(&header)?,
            );
        }
        assert!(table
            .database
            .read_tx()
            .get(&table.events, Table::key(b'H', None, &key))?
            .is_none());
        table.append_arrow(&key, &header, &batch)?;
        assert!(before
            .get(&table.events, Table::key(b'H', None, &key))?
            .is_none());
        let view = table.database.read_tx();
        assert_eq!(
            Page::new(&table, &view, &key, &header).read(&[0, 1])?,
            batch
        );
        let table = Arc::new(table);
        let context = SessionContext::new();
        context.register_table(
            "events",
            Arc::new(Provider {
                schema: Arc::clone(&table.schema),
                counts: Arc::new(Mutex::new(Counts::default())),
                binding: Arc::new(RwLock::new(Binding {
                    view: table.database.read_tx(),
                    table,
                    only: None,
                })),
            }),
        )?;
        for (predicate, expected) in [("severity IS NULL", 2), ("severity = 'error'", 3)] {
            let rows = context
                .sql(&format!("SELECT received_at FROM events WHERE {predicate}"))
                .await?
                .collect()
                .await?;
            assert_eq!(rows.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
            assert_eq!(
                rows[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .unwrap()
                    .value(0),
                expected
            );
        }
    }
    Ok(())
}
