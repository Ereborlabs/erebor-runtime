use super::*;
use araphor_data::analysis::native::benchmark::columnar::{Header, Page};
use datafusion::arrow::{
    array::{ArrayRef, StringArray},
    datatypes::{DataType, Field, Schema},
};
use fjall::Readable;

#[test]
fn production_held_sources() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let owner = Owner::open(&directory.path().join("store"), Layout::Frames, true)?;
    let (mut batches, frames) = common::inputs(1024)?;
    let sender = Sender {
        layout: Layout::Frames,
        arrow: false,
    };
    let mut held = None;
    for (index, batch) in batches.iter_mut().enumerate() {
        batch.cpu_id = index as u32;
        batch.first_cursor = 1;
        batch.last_cursor = 256;
        owner.receive(&sender.encode(batch, index as u64 * 256 + 1)?)?;
        if index == 1 {
            held = Some(owner.view()?);
        }
    }
    let mut counts = Counts::default();
    let rows = owner.capture(&held.unwrap(), None, &[0, 1, 2, 3, 4, 5], &mut counts)?;
    Queries::verify(&rows, "full", &frames, 512, true);
    let rows = owner.capture(&owner.view()?, None, &[0, 1, 2, 3, 4, 5], &mut counts)?;
    Queries::verify(&rows, "full", &frames, 1024, true);
    Ok(())
}

#[test]
fn sender_roundtrip() -> Result<()> {
    use araphor_data::analysis::native::benchmark::columnar::{Packet, Payload};
    let (batches, _) = common::inputs(256)?;
    let expected = Table::build(&batches[0])?;
    for layout in [Layout::Packed, Layout::Columns] {
        for arrow in [false, true] {
            let directory = tempfile::tempdir()?;
            let table = Table::open(directory.path(), layout, Table::schema())?;
            let bytes = Sender { layout, arrow }.encode(&batches[0], 1)?;
            let packet: Packet = rmp_serde::from_slice(&bytes)?;
            table.receive(&bytes)?;
            let view = table.database.read_tx();
            assert_eq!(
                Page::new(&table, &view, &packet.key, &packet.header).read(&[0, 1, 2, 3, 4, 5])?,
                expected
            );
            match packet.payload {
                Payload::Packed(bytes) => assert_eq!(
                    view.get(&table.events, Table::key(b'P', None, &packet.key))?
                        .unwrap()
                        .as_ref(),
                    bytes.as_ref()
                ),
                Payload::Columns(values) => {
                    for (index, bytes) in values {
                        assert_eq!(
                            view.get(&table.events, Table::key(b'C', Some(index), &packet.key))?
                                .unwrap()
                                .as_ref(),
                            bytes.as_ref()
                        );
                    }
                }
                Payload::Frames { .. } => (),
            }
        }
    }
    Ok(())
}

#[test]
fn reject_wire_before_commit() -> Result<()> {
    use araphor_data::analysis::native::benchmark::columnar::{Packet, Payload};
    let (batches, _) = common::inputs(256)?;
    for layout in [Layout::Packed, Layout::Columns] {
        let directory = tempfile::tempdir()?;
        let table = Table::open(directory.path(), layout, Table::schema())?;
        let bytes = Sender {
            layout,
            arrow: true,
        }
        .encode(&batches[0], 1)?;
        let packet: Packet = rmp_serde::from_slice(&bytes)?;
        let head = table.database.inner().journal_head()?;
        let state = table.statistics()?;
        let mut invalid = Vec::new();
        let mut zero = packet.clone();
        zero.header.first = 0;
        invalid.push(zero);
        let mut key = packet.clone();
        key.key = Table::batch_key(2, 0).into();
        invalid.push(key);
        let mut cpu = packet.clone();
        cpu.header.cpu = Some(1);
        invalid.push(cpu);
        let mut count = packet.clone();
        count.header.rows += 1;
        invalid.push(count);
        let mut cursor = packet.clone();
        cursor.header.first += 1;
        invalid.push(cursor);
        let mut truncated = packet.clone();
        match &mut truncated.payload {
            Payload::Packed(bytes) => *bytes = vec![1, 2, 3].into(),
            Payload::Columns(values) => values[0].1 = vec![1, 2, 3].into(),
            Payload::Frames { .. } => unreachable!(),
        }
        invalid.push(truncated);
        if let Payload::Columns(values) = &packet.payload {
            let mut duplicate = packet.clone();
            if let Payload::Columns(parts) = &mut duplicate.payload {
                parts.push(values[0].clone());
            }
            invalid.push(duplicate);
            let mut missing = packet.clone();
            if let Payload::Columns(parts) = &mut missing.payload {
                parts.pop();
            }
            invalid.push(missing);
        } else {
            let mut schema = packet.clone();
            schema.payload =
                Payload::Packed(Table::encode(&Table::build(&batches[0])?.project(&[1])?)?.into());
            invalid.push(schema);
        }
        for packet in invalid {
            assert!(table.receive(&packet.encode()?).is_err());
            assert_eq!(table.database.inner().journal_head()?, head);
            assert_eq!(table.statistics()?, state);
        }
    }
    Ok(())
}

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
        let packet = araphor_data::analysis::native::benchmark::columnar::Packet::arrow(
            key.clone(),
            Header {
                first: 1,
                rows: 256,
                cpu: None,
            },
            &batch,
            layout,
        )?;
        table.receive(&packet.encode()?)?;
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
        let mut invalid = header.clone();
        invalid.cpu = Some(0);
        let packet = araphor_data::analysis::native::benchmark::columnar::Packet::arrow(
            key.clone(),
            invalid,
            &batch,
            layout,
        )?;
        let head = table.database.inner().journal_head()?;
        assert!(table.receive(&packet.encode()?).is_err());
        assert_eq!(table.database.inner().journal_head()?, head);
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
        table.receive(
            &araphor_data::analysis::native::benchmark::columnar::Packet::arrow(
                key.clone(),
                header.clone(),
                &batch,
                layout,
            )?
            .encode()?,
        )?;
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
                    view: araphor_data::analysis::native::benchmark::columnar::View::Candidate(
                        table.database.read_tx(),
                    ),
                    table: Arc::new(Owner::Candidate(table)),
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
