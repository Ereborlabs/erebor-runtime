use std::{collections::BTreeMap, io::Cursor, path::Path, sync::Arc};

use araphor_analysis_sdk::{arrow_array::*, DataType, Field, Schema};
use fjall::{Readable, SingleWriterTxDatabase, SingleWriterTxKeyspace, Snapshot};
use serde::{Deserialize, Serialize};

use super::Result;
use crate::{
    analysis::raw::{RawCommit, RawKind, RawSpan},
    EvidenceRecord, ValidatedEvidenceBatchV1,
};

mod wire;
pub use wire::{Packet, Payload};
mod owner;
pub use owner::{Owner, View};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    Frames,
    Packed,
    Columns,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Header {
    pub first: u64,
    pub rows: usize,
    pub cpu: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Counts {
    pub gets: u64,
    pub value_bytes: u64,
    pub ipc_columns: u64,
    pub raw_decodes: u64,
    pub production_scan_bytes: u64,
    pub production_input_bytes: u64,
}

impl Counts {
    pub fn add(&mut self, other: Self) {
        self.gets += other.gets;
        self.value_bytes += other.value_bytes;
        self.ipc_columns += other.ipc_columns;
        self.raw_decodes += other.raw_decodes;
        self.production_scan_bytes += other.production_scan_bytes;
        self.production_input_bytes += other.production_input_bytes;
    }
}

pub struct Table {
    pub database: SingleWriterTxDatabase,
    pub events: SingleWriterTxKeyspace,
    progress: SingleWriterTxKeyspace,
    output: SingleWriterTxKeyspace,
    pub schema: Arc<Schema>,
    pub layout: Layout,
}

impl Table {
    pub fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("cpu_id", DataType::UInt32, false),
            Field::new("source_cursor", DataType::UInt64, false),
            Field::new("task_cookie", DataType::UInt64, false),
            Field::new("operation", DataType::UInt32, false),
            Field::new("kernel_result", DataType::Int32, false),
            Field::new("framed_record", DataType::Binary, false),
        ]))
    }

    pub fn open(root: &Path, layout: Layout, schema: Arc<Schema>) -> Result<Self> {
        let database = SingleWriterTxDatabase::builder(root).journal_cdc().open()?;
        let catalog = database.keyspace("catalog", fjall::KeyspaceCreateOptions::default)?;
        let bytes = Self::encode(&RecordBatch::new_empty(Arc::clone(&schema)))?;
        if let Some(saved) = database.read_tx().get(&catalog, b"kernel_events")? {
            if saved.as_ref() != bytes {
                return Err("table schema mismatch".into());
            }
        } else {
            let mut tx = database.write_tx();
            tx.insert(&catalog, b"kernel_events", bytes);
            tx.commit_receipt()?;
        }
        Ok(Self {
            events: database.keyspace("kernel_events", fjall::KeyspaceCreateOptions::default)?,
            progress: database
                .keyspace("benchmark_progress", fjall::KeyspaceCreateOptions::default)?,
            output: database.keyspace("benchmark_output", fjall::KeyspaceCreateOptions::default)?,
            database,
            schema,
            layout,
        })
    }

    pub fn encode(batch: &RecordBatch) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut bytes, &batch.schema())?;
            writer.write(batch)?;
            writer.finish()?;
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<RecordBatch> {
        Self::decode_columns(bytes, None)
    }

    fn decode_columns(bytes: &[u8], projection: Option<Vec<usize>>) -> Result<RecordBatch> {
        let mut reader = arrow_ipc::reader::StreamReader::try_new(Cursor::new(bytes), projection)?;
        let batch = reader.next().transpose()?.ok_or("missing IPC batch")?;
        if reader.next().is_some() {
            return Err("multiple IPC batches".into());
        }
        Ok(batch)
    }

    pub fn build(batch: &ValidatedEvidenceBatchV1) -> Result<RecordBatch> {
        let mut cursor = Vec::new();
        let mut cookies = Vec::new();
        let mut operations = Vec::new();
        let mut results = Vec::new();
        let mut frames = Vec::new();
        let mut start = 0;
        for (slot, &end) in batch.frame_ends.iter().enumerate() {
            let bytes = &batch.framed_records[start..end];
            let record = EvidenceRecord::try_from(bytes)?;
            cursor.push(batch.first_cursor + slot as u64);
            cookies.push(record.task_cookie);
            operations.push(record.operation);
            results.push(record.kernel_result);
            frames.push(bytes);
            start = end;
        }
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(UInt32Array::from(vec![batch.cpu_id; cursor.len()])),
                Arc::new(UInt64Array::from(cursor)),
                Arc::new(UInt64Array::from(cookies)),
                Arc::new(UInt32Array::from(operations)),
                Arc::new(Int32Array::from(results)),
                Arc::new(BinaryArray::from_iter_values(frames)),
            ],
        )?)
    }

    pub fn from_records(
        batch: &ValidatedEvidenceBatchV1,
        records: &[EvidenceRecord],
    ) -> Result<RecordBatch> {
        if records.len() != batch.frame_ends.len() {
            return Err("native record count mismatch".into());
        }
        let mut start = 0;
        let frames = batch
            .frame_ends
            .iter()
            .map(|&end| {
                let bytes = &batch.framed_records[start..end];
                start = end;
                bytes
            })
            .collect::<Vec<_>>();
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(UInt32Array::from(vec![batch.cpu_id; records.len()])),
                Arc::new(UInt64Array::from_iter_values(
                    (0..records.len()).map(|row| batch.first_cursor + row as u64),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    records.iter().map(|record| record.task_cookie),
                )),
                Arc::new(UInt32Array::from_iter_values(
                    records.iter().map(|record| record.operation),
                )),
                Arc::new(Int32Array::from_iter_values(
                    records.iter().map(|record| record.kernel_result),
                )),
                Arc::new(BinaryArray::from_iter_values(frames)),
            ],
        )?)
    }

    pub fn batch_key(first: u64, cpu: u32) -> Vec<u8> {
        let mut key = vec![0, 6];
        key.extend_from_slice(b"node-a");
        let mut source = [3; 16];
        source[0] = cpu as u8;
        key.extend_from_slice(&source);
        key.extend_from_slice(&1u64.to_be_bytes());
        key.extend_from_slice(&first.to_be_bytes());
        key
    }

    pub fn key(tag: u8, column: Option<usize>, batch: &[u8]) -> Vec<u8> {
        let mut key = vec![tag];
        if let Some(column) = column {
            key.extend_from_slice(&(column as u16).to_be_bytes());
        }
        key.extend_from_slice(batch);
        key
    }

    pub fn append(&self, batch: &ValidatedEvidenceBatchV1) -> Result<fjall::Commit> {
        let header = Header {
            first: batch.first_cursor,
            rows: batch.frame_ends.len(),
            cpu: Some(batch.cpu_id),
        };
        let key = Self::batch_key(batch.first_cursor, batch.cpu_id);
        if self.layout == Layout::Frames {
            let commit = RawCommit {
                revision: 1,
                kind: Some(RawKind::Evidence(batch.cpu_id)),
                intake: batch.intake_utc_ns,
                spans: vec![RawSpan {
                    first: batch.first_cursor,
                    last: batch.last_cursor,
                    start: 0,
                    ordinal: 0,
                    ends: batch
                        .frame_ends
                        .iter()
                        .map(|&end| u32::try_from(end))
                        .collect::<std::result::Result<_, _>>()?,
                }],
                body: batch.framed_records.clone(),
            };
            let value = commit.frame(Path::new("table_storage_bench"))?;
            let mut tx = self.database.write_tx();
            tx.insert(
                &self.events,
                Self::key(b'H', None, &key),
                rmp_serde::to_vec(&header)?,
            );
            tx.insert(&self.events, Self::key(b'P', None, &key), value);
            return tx
                .commit_receipt()?
                .ok_or_else(|| "missing input commit".into());
        }
        self.append_arrow(&key, &header, &Self::build(batch)?)
    }

    pub fn append_arrow(
        &self,
        key: &[u8],
        header: &Header,
        batch: &RecordBatch,
    ) -> Result<fjall::Commit> {
        if batch.schema() != self.schema || batch.num_rows() != header.rows {
            return Err("batch schema or row count mismatch".into());
        }
        let mut tx = self.database.write_tx();
        tx.insert(
            &self.events,
            Self::key(b'H', None, key),
            rmp_serde::to_vec(header)?,
        );
        let indices = (0..batch.num_columns())
            .filter(|&index| index != 0 || header.cpu.is_none())
            .collect::<Vec<_>>();
        match self.layout {
            Layout::Packed => tx.insert(
                &self.events,
                Self::key(b'P', None, key),
                Self::encode(&batch.project(&indices)?)?,
            ),
            Layout::Columns => {
                for index in indices {
                    tx.insert(
                        &self.events,
                        Self::key(b'C', Some(index), key),
                        Self::encode(&batch.project(&[index])?)?,
                    );
                }
            }
            Layout::Frames => return Err("generic Arrow append requires an Arrow layout".into()),
        }
        tx.commit_receipt()?
            .ok_or_else(|| "missing input commit".into())
    }

    pub fn complete(&self, input: fjall::Cursor) -> Result<fjall::Commit> {
        let mut tx = self.database.write_tx();
        tx.insert(&self.output, input.sequence.to_be_bytes(), [0; 32]);
        tx.insert(
            &self.progress,
            b"subscription-1",
            rmp_serde::to_vec(&(input.journal, input.offset, input.sequence))?,
        );
        tx.commit_receipt()?
            .ok_or_else(|| "missing output commit".into())
    }

    pub fn saved(&self) -> Result<fjall::Cursor> {
        let bytes = self
            .database
            .read_tx()
            .get(&self.progress, b"subscription-1")?
            .ok_or("missing progress")?;
        let (journal, offset, sequence) = rmp_serde::from_slice(&bytes)?;
        Ok(fjall::Cursor {
            journal,
            offset,
            sequence,
        })
    }

    pub fn headers(
        &self,
        view: &Snapshot,
        only: Option<&[u8]>,
        counts: &mut Counts,
    ) -> Result<Vec<(Vec<u8>, Header)>> {
        let rows = if let Some(key) = only {
            vec![(
                key.to_vec(),
                self.get(view, &Self::key(b'H', None, key), counts)?
                    .to_vec(),
            )]
        } else {
            view.prefix(&self.events, b"H")
                .map(|row| {
                    let (key, value) = row.into_inner()?;
                    counts.gets += 1;
                    counts.value_bytes += value.len() as u64;
                    Ok((key[1..].to_vec(), value.to_vec()))
                })
                .collect::<Result<Vec<_>>>()?
        };
        rows.into_iter()
            .map(|(key, value)| Ok((key, rmp_serde::from_slice(&value)?)))
            .collect()
    }

    pub fn get(&self, view: &Snapshot, key: &[u8], counts: &mut Counts) -> Result<fjall::Slice> {
        let value = view
            .get(&self.events, key)?
            .ok_or("missing column or header")?;
        counts.gets += 1;
        counts.value_bytes += value.len() as u64;
        Ok(value)
    }

    pub fn replay(&self, after: fjall::Cursor, through: fjall::Cursor) -> Result<Vec<Vec<u8>>> {
        let mut feed = self.database.inner().journal_feed(Some(after))?;
        let mut keys = Vec::new();
        while let Some(batch) = feed.next_batch()? {
            if batch.cursor.sequence > through.sequence {
                break;
            }
            for item in batch.items {
                if item.keyspace == self.events.inner().id() && item.key.first() == Some(&b'H') {
                    keys.push(item.key[1..].to_vec());
                }
            }
        }
        Ok(keys)
    }

    pub fn statistics(&self) -> Result<BTreeMap<String, [u64; 3]>> {
        let view = self.database.read_tx();
        let mut result = BTreeMap::new();
        for name in [
            "catalog",
            "kernel_events",
            "benchmark_progress",
            "benchmark_output",
        ] {
            let table = self
                .database
                .keyspace(name, fjall::KeyspaceCreateOptions::default)?;
            let mut count = [0; 3];
            for row in view.iter(&table) {
                let (key, value) = row.into_inner()?;
                count[0] += 1;
                count[1] += key.len() as u64;
                count[2] += value.len() as u64;
            }
            result.insert(name.into(), count);
        }
        Ok(result)
    }
}

pub struct Page<'a> {
    table: &'a Table,
    view: &'a Snapshot,
    key: &'a [u8],
    pub header: &'a Header,
    columns: BTreeMap<usize, ArrayRef>,
    packed: Option<fjall::Slice>,
    pub counts: Counts,
}

impl<'a> Page<'a> {
    pub fn new(table: &'a Table, view: &'a Snapshot, key: &'a [u8], header: &'a Header) -> Self {
        let mut columns = BTreeMap::new();
        if let Some(cpu) = header.cpu {
            columns.insert(
                0,
                Arc::new(UInt32Array::from(vec![cpu; header.rows])) as ArrayRef,
            );
        }
        Self {
            table,
            view,
            key,
            header,
            columns,
            packed: None,
            counts: Counts::default(),
        }
    }

    pub fn read(&mut self, indices: &[usize]) -> Result<RecordBatch> {
        for &index in indices {
            if self.columns.contains_key(&index) {
                continue;
            }
            match self.table.layout {
                Layout::Columns => {
                    let bytes = self.table.get(
                        self.view,
                        &Table::key(b'C', Some(index), self.key),
                        &mut self.counts,
                    )?;
                    let batch = Table::decode(&bytes)?;
                    self.counts.ipc_columns += batch.num_columns() as u64;
                    self.columns.insert(index, Arc::clone(batch.column(0)));
                }
                Layout::Packed => {
                    if self.packed.is_none() {
                        self.packed = Some(self.table.get(
                            self.view,
                            &Table::key(b'P', None, self.key),
                            &mut self.counts,
                        )?);
                    }
                    let projection = indices
                        .iter()
                        .filter(|index| !self.columns.contains_key(index))
                        .map(|&index| index - usize::from(self.header.cpu.is_some()))
                        .collect();
                    let batch =
                        Table::decode_columns(self.packed.as_ref().unwrap(), Some(projection))?;
                    self.counts.ipc_columns += batch.num_columns() as u64;
                    for (slot, field) in batch.schema().fields().iter().enumerate() {
                        self.columns.insert(
                            self.table.schema.index_of(field.name())?,
                            Arc::clone(batch.column(slot)),
                        );
                    }
                }
                Layout::Frames => {
                    let bytes = self.table.get(
                        self.view,
                        &Table::key(b'P', None, self.key),
                        &mut self.counts,
                    )?;
                    let frame = RawCommit::from_frame(&bytes, Path::new("table_storage_bench"))?;
                    if !indices.iter().any(|index| (2..=4).contains(index)) {
                        self.columns.insert(
                            1,
                            Arc::new(UInt64Array::from_iter_values(
                                frame.records().map(|(cursor, _)| cursor),
                            )),
                        );
                        self.columns.insert(
                            5,
                            Arc::new(BinaryArray::from_iter_values(
                                frame.records().map(|(_, bytes)| bytes).collect::<Vec<_>>(),
                            )),
                        );
                        continue;
                    }
                    let batch = ValidatedEvidenceBatchV1 {
                        cpu_id: self.header.cpu.ok_or("missing frame CPU")?,
                        first_cursor: self.header.first,
                        last_cursor: self.header.first + self.header.rows as u64 - 1,
                        intake_utc_ns: frame.intake,
                        framed_records: frame.body,
                        frame_ends: frame.spans[0]
                            .ends
                            .iter()
                            .map(|&end| end as usize)
                            .collect(),
                    };
                    let batch = Table::build(&batch)?;
                    self.counts.raw_decodes += batch.num_rows() as u64;
                    for (slot, array) in batch.columns().iter().enumerate() {
                        self.columns.insert(slot, Arc::clone(array));
                    }
                }
            }
        }
        Ok(RecordBatch::try_new(
            Arc::new(self.table.schema.project(indices)?),
            indices
                .iter()
                .map(|index| Arc::clone(&self.columns[index]))
                .collect(),
        )?)
    }

    pub fn predicate(&mut self, indices: &[usize]) -> Result<RecordBatch> {
        self.read(indices)?;
        Ok(RecordBatch::try_new(
            Arc::new(Schema::new(
                self.table
                    .schema
                    .fields()
                    .iter()
                    .map(|field| field.as_ref().clone().with_nullable(true))
                    .collect::<Vec<_>>(),
            )),
            (0..self.table.schema.fields().len())
                .map(|index| {
                    self.columns.get(&index).cloned().unwrap_or_else(|| {
                        new_null_array(self.table.schema.field(index).data_type(), self.header.rows)
                    })
                })
                .collect(),
        )?)
    }
}
