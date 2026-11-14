use super::*;
use crate::analysis::native::{events::Events, DataView, NativeStore};
use crate::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisTableRead, EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, StorePositionV1,
};

pub enum Owner {
    Candidate(Arc<Table>),
    Production(Arc<NativeStore>),
}

#[derive(Clone)]
pub enum View {
    Candidate(Snapshot),
    Production(Arc<DataView>),
}

impl Owner {
    const PROGRESS: &'static [u8] = b"\0benchmark/input-cursor";
    const OUTPUT: &'static [u8] = b"\0benchmark/output/";

    pub fn open(root: &Path, layout: Layout, production: bool) -> Result<Self> {
        Ok(if production {
            Self::Production(Arc::new(NativeStore::open(root)?))
        } else {
            Self::Candidate(Arc::new(Table::open(root, layout, Table::schema())?))
        })
    }

    pub fn source(cpu: u32) -> EvidenceIntakeIdentityV1 {
        let mut source_id = [3; 16];
        source_id[0] = cpu as u8;
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id,
            source_epoch: 1,
        }
    }

    pub fn database(&self) -> &SingleWriterTxDatabase {
        match self {
            Self::Candidate(table) => &table.database,
            Self::Production(store) => store.database(),
        }
    }

    pub fn schema(&self) -> Arc<Schema> {
        match self {
            Self::Candidate(table) => Arc::clone(&table.schema),
            Self::Production(_) => Table::schema(),
        }
    }

    pub fn view(&self) -> Result<View> {
        Ok(match self {
            Self::Candidate(table) => View::Candidate(table.database.read_tx()),
            Self::Production(store) => View::Production(store.view()?),
        })
    }

    pub fn append(&self, batch: &ValidatedEvidenceBatchV1) -> Result<fjall::Commit> {
        match self {
            Self::Candidate(table) => table.append(batch),
            Self::Production(store) => {
                if store.accept_validated_batch(Self::source(batch.cpu_id), batch.clone())?
                    != EvidenceStoreOutcomeV1::Accepted
                {
                    return Err("production input did not receive an Accepted ACK".into());
                }
                let cursor = store
                    .view()?
                    .snapshot()
                    .cursor()?
                    .ok_or("missing production input cursor")?;
                Ok(fjall::Commit {
                    revision: cursor.revision(),
                    cursor,
                })
            }
        }
    }

    pub fn receive(&self, bytes: &[u8]) -> Result<fjall::Commit> {
        match self {
            Self::Candidate(table) => table.receive(bytes),
            Self::Production(_) => {
                let packet: Packet = rmp_serde::from_slice(bytes)?;
                let Payload::Frames {
                    bytes,
                    ends,
                    intake,
                } = packet.payload
                else {
                    return Err("production control requires original frame packets".into());
                };
                if ends.len() != packet.header.rows
                    || ends.last().copied() != Some(bytes.len())
                    || ends.windows(2).any(|pair| pair[0] >= pair[1])
                    || ends.first() == Some(&0)
                {
                    return Err("invalid production frame boundaries".into());
                }
                let last = packet
                    .header
                    .first
                    .checked_add(
                        packet
                            .header
                            .rows
                            .checked_sub(1)
                            .ok_or("empty frame packet")? as u64,
                    )
                    .ok_or("wire cursor overflow")?;
                let cpu = packet.header.cpu.ok_or("missing production CPU")?;
                if packet.key.as_ref() != Table::batch_key(packet.header.first, cpu) {
                    return Err("production wire key mismatch".into());
                }
                self.append(&ValidatedEvidenceBatchV1 {
                    cpu_id: cpu,
                    first_cursor: packet.header.first,
                    last_cursor: last,
                    intake_utc_ns: intake,
                    framed_records: bytes.into_vec().into(),
                    frame_ends: ends,
                })
            }
        }
    }

    pub fn complete(&self, input: fjall::Cursor) -> Result<fjall::Commit> {
        match self {
            Self::Candidate(table) => table.complete(input),
            Self::Production(store) => {
                let mut tx = store.write()?;
                tx.native().insert(
                    [Self::OUTPUT, &input.sequence.to_be_bytes()].concat(),
                    [0; 32],
                );
                tx.native().insert(
                    Self::PROGRESS,
                    rmp_serde::to_vec(&(input.journal, input.offset, input.sequence))?,
                );
                tx.commit([])?
                    .ok_or_else(|| "missing production output commit".into())
            }
        }
    }

    pub fn saved(&self) -> Result<fjall::Cursor> {
        match self {
            Self::Candidate(table) => table.saved(),
            Self::Production(store) => {
                let bytes = store
                    .view()?
                    .snapshot()
                    .get(Self::PROGRESS)?
                    .ok_or("missing production progress")?;
                let (journal, offset, sequence) = rmp_serde::from_slice(&bytes)?;
                Ok(fjall::Cursor {
                    journal,
                    offset,
                    sequence,
                })
            }
        }
    }

    fn header(batch: &crate::analysis::native::events::EventBatch) -> Result<Header> {
        let RawKind::Evidence(cpu) = &batch.meta.kind else {
            return Err("unexpected production event kind".into());
        };
        Ok(Header {
            first: batch.first,
            rows: batch
                .meta
                .spans
                .iter()
                .map(|span| (span.last - span.first + 1) as usize)
                .sum(),
            cpu: Some(*cpu),
        })
    }

    pub fn descriptors(&self, batch: &fjall::cdc::Batch) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Candidate(table) => Ok(batch
                .items
                .iter()
                .filter(|item| {
                    item.keyspace == table.events.inner().id() && item.key.first() == Some(&b'H')
                })
                .map(|item| item.key[1..].to_vec())
                .collect()),
            Self::Production(store) => {
                let view = store.view()?;
                let events = Events::new(&view);
                batch
                    .items
                    .iter()
                    .filter(|item| {
                        item.branch == Some(store.branch().id())
                            && item.key.starts_with(Events::POSITION)
                    })
                    .map(|item| {
                        let event = events.decode_batch(
                            &item.key,
                            item.value
                                .as_deref()
                                .ok_or("missing production event metadata")?,
                        )?;
                        let header = Self::header(&event)?;
                        Ok(Table::batch_key(header.first, header.cpu.unwrap()))
                    })
                    .collect()
            }
        }
    }

    pub fn headers(
        &self,
        view: &View,
        only: Option<&[u8]>,
        counts: &mut Counts,
    ) -> Result<Vec<(Vec<u8>, Header)>> {
        match (self, view) {
            (Self::Candidate(table), View::Candidate(view)) => table.headers(view, only, counts),
            (Self::Production(_), View::Production(view)) => {
                let events = Events::new(view);
                if let Some(key) = only {
                    let cpu = u32::from(key[8]);
                    let first = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
                    let (batch, _) = events
                        .lookup(&Self::source(cpu), first)?
                        .ok_or("missing production input")?;
                    return Ok(vec![(key.to_vec(), Self::header(&batch)?)]);
                }
                events
                    .batches(0)
                    .map(|row| {
                        let (key, value) = row?;
                        let batch = events.decode_batch(&key, &value)?;
                        let header = Self::header(&batch)?;
                        Ok((Table::batch_key(header.first, header.cpu.unwrap()), header))
                    })
                    .collect()
            }
            _ => Err("view owner mismatch".into()),
        }
    }

    pub fn capture(
        &self,
        view: &View,
        only: Option<&[u8]>,
        indices: &[usize],
        counts: &mut Counts,
    ) -> Result<Vec<RecordBatch>> {
        match (self, view) {
            (Self::Candidate(table), View::Candidate(view)) => table
                .headers(view, only, counts)?
                .into_iter()
                .map(|(key, header)| {
                    let mut page = Page::new(table, view, &key, &header);
                    let batch = page.read(indices)?;
                    counts.add(page.counts);
                    Ok(batch)
                })
                .collect(),
            (Self::Production(store), View::Production(view)) => {
                let schema = &NativeStore::table_schemas()["events"];
                let columns = indices
                    .iter()
                    .map(|&index| schema.index_of(Table::schema().field(index).name()))
                    .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
                let requests = BTreeMap::from([("events".to_string(), Some(columns))]);
                let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
                selection.sources = crate::Selection::All;
                let mode = if let Some(key) = only {
                    let cpu = u32::from(key[8]);
                    let first = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
                    let (batch, _) = Events::new(view)
                        .lookup(&Self::source(cpu), first)?
                        .ok_or("missing production capture")?;
                    let header = Self::header(&batch)?;
                    selection.sources = crate::Selection::Exact(vec![Self::source(cpu)]);
                    selection.cursor_from = std::ops::Bound::Included(first);
                    selection.cursor_until =
                        std::ops::Bound::Included(first + header.rows as u64 - 1);
                    AnalysisReadModeV1::Changes(StorePositionV1 {
                        commit_revision: batch.meta.revision - 1,
                        ordinal: u32::MAX,
                    })
                } else {
                    AnalysisReadModeV1::Complete
                };
                let mut page = store.read_tables_at(
                    view,
                    &selection,
                    AnalysisTableRead {
                        requests: &requests,
                        event_ranges: None,
                        mode,
                        now: 2_000_000_000,
                    },
                    AnalysisExtractLimits::default(),
                    &AnalysisReadControl::default(),
                    None,
                )?;
                counts.production_scan_bytes += page.extraction.scanned_bytes as u64;
                counts.production_input_bytes += page.extraction.input_bytes as u64;
                page.tables
                    .remove("events")
                    .unwrap_or_default()
                    .into_iter()
                    .map(|batch| {
                        let arrays = indices
                            .iter()
                            .map(|&index| {
                                batch
                                    .column_by_name(Table::schema().field(index).name())
                                    .cloned()
                                    .ok_or_else(|| "missing production projected column".into())
                            })
                            .collect::<Result<Vec<_>>>()?;
                        Ok(RecordBatch::try_new(
                            Arc::new(Table::schema().project(indices)?),
                            arrays,
                        )?)
                    })
                    .collect()
            }
            _ => Err("capture owner mismatch".into()),
        }
    }

    pub fn replay(&self, after: fjall::Cursor, through: fjall::Cursor) -> Result<Vec<Vec<u8>>> {
        let mut feed = self.database().inner().journal_feed(Some(after))?;
        let mut keys = Vec::new();
        while let Some(batch) = feed.next_batch()? {
            if batch.cursor.sequence > through.sequence {
                break;
            }
            keys.extend(self.descriptors(&batch)?);
        }
        Ok(keys)
    }

    pub fn statistics(&self) -> Result<BTreeMap<String, [u64; 3]>> {
        match self {
            Self::Candidate(table) => table.statistics(),
            Self::Production(store) => {
                let mut counts = [0; 3];
                for row in store.view()?.snapshot().iter() {
                    let (key, value) = row?;
                    counts[0] += 1;
                    counts[1] += key.len() as u64;
                    counts[2] += value.len() as u64;
                }
                Ok(BTreeMap::from([("production".into(), counts)]))
            }
        }
    }
}
