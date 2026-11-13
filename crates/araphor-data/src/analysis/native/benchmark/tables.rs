use std::path::{Path, PathBuf};

use fjall::{Readable, SingleWriterTxKeyspace};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{Cut, Progress, Result};
use crate::analysis::raw::{RawCommit, RawKind, RawSpan};
use crate::{
    AnalysisRecordV1, AnalysisSourceReceiptV1, EvidenceIntakeIdentityV1, StorePositionV1,
    ValidatedEvidenceBatchV1,
};

mod metadata;
use metadata::{Receipt, State};

#[derive(Clone, Copy, Deserialize, Serialize)]
struct Header {
    revision: u64,
    ordinal: u32,
    intake: u64,
    cpu: u32,
}

#[derive(Deserialize, Serialize)]
struct Batch(Header, Vec<u32>, serde_bytes::ByteBuf);

#[derive(Deserialize, Serialize)]
struct Record(Header, serde_bytes::ByteBuf);

pub(super) struct Tables {
    pub database: fjall::SingleWriterTxDatabase,
    events: SingleWriterTxKeyspace,
    receipts: SingleWriterTxKeyspace,
    epochs: SingleWriterTxKeyspace,
    state: SingleWriterTxKeyspace,
    results: SingleWriterTxKeyspace,
    source: EvidenceIntakeIdentityV1,
    source_ids: SingleWriterTxKeyspace,
    sources: SingleWriterTxKeyspace,
    prefix: Option<Vec<u8>>,
    root: PathBuf,
    records: bool,
    compact: bool,
    metadata: bool,
    framed: bool,
}

impl Tables {
    pub fn open(root: &Path, source: EvidenceIntakeIdentityV1, backend: &str) -> Result<Self> {
        let records = backend.ends_with("-record");
        let compact = backend.starts_with("compact-");
        let compressed = backend.contains("-lz4-");
        std::fs::create_dir_all(root)?;
        let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
            .journal_cdc()
            .open()?;
        let create = || {
            let options = fjall::KeyspaceCreateOptions::default();
            if compressed {
                options
                    .data_block_compression_policy(fjall::config::CompressionPolicy::all(
                        fjall::CompressionType::Lz4,
                    ))
                    .index_block_compression_policy(fjall::config::CompressionPolicy::all(
                        fjall::CompressionType::Lz4,
                    ))
            } else {
                options
            }
        };
        let source_ids = database.keyspace("source_ids", create)?;
        let sources = database.keyspace("sources", create)?;
        let prefix = if compact {
            let snapshot = database.read_tx();
            match snapshot.get(&source_ids, source.key())? {
                Some(id) => {
                    if Self::number(Some(id.clone()))? == 0 {
                        return Err("zero compact source ID".into());
                    }
                    let value = snapshot
                        .get(&sources, &id)?
                        .ok_or("missing compact source identity")?;
                    if rmp_serde::from_slice::<EvidenceIntakeIdentityV1>(&value)? != source {
                        return Err("compact source identity conflict".into());
                    }
                    Some(id.to_vec())
                }
                None => None,
            }
        } else {
            Some(source.key())
        };
        Ok(Self {
            events: database.keyspace("events", create)?,
            receipts: database.keyspace("source_receipts", create)?,
            epochs: database.keyspace("source_epochs", create)?,
            state: database.keyspace("benchmark_state", create)?,
            results: database.keyspace("benchmark_results", create)?,
            database,
            source_ids,
            sources,
            prefix,
            source,
            root: root.to_path_buf(),
            records,
            compact,
            metadata: backend.contains("-meta-") || backend.contains("-frame-"),
            framed: backend.contains("-frame-"),
        })
    }

    fn number(bytes: Option<fjall::Slice>) -> Result<u64> {
        Ok(bytes
            .map(|bytes| bytes.as_ref().try_into().map(u64::from_be_bytes))
            .transpose()?
            .unwrap_or(0))
    }

    fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = rmp_serde::to_vec(value)?;
        bytes.extend(crc32c::crc32c(&bytes).to_be_bytes());
        Ok(bytes)
    }

    fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
        let end = bytes.len().checked_sub(4).ok_or("short table value")?;
        let checksum = u32::from_be_bytes(bytes[end..].try_into()?);
        if checksum != crc32c::crc32c(&bytes[..end]) {
            return Err("table value checksum".into());
        }
        let value: T = rmp_serde::from_slice(&bytes[..end])?;
        if rmp_serde::to_vec(&value)? != bytes[..end] {
            return Err("noncanonical table value".into());
        }
        Ok(value)
    }

    fn key(prefix: &[u8], cursor: u64) -> Vec<u8> {
        [prefix, &cursor.to_be_bytes()].concat()
    }

    fn cursor(&self, key: &[u8]) -> Result<u64> {
        let prefix = self.prefix.as_deref().ok_or("unbound compact source")?;
        let suffix = key.strip_prefix(prefix).ok_or("table source key")?;
        let cursor = u64::from_be_bytes(suffix.try_into()?);
        if cursor == 0 {
            return Err("zero table cursor".into());
        }
        Ok(cursor)
    }

    pub fn cut(&self) -> Result<Cut> {
        let snapshot = self.database.read_tx();
        let revision = if self.metadata {
            self.state(&snapshot)?.head
        } else {
            Self::number(snapshot.get(&self.state, b"head")?)?
        };
        let receipt = self.receipt(&snapshot)?;
        let cursor = self.database.inner().journal_head()?;
        Ok(Cut {
            revision,
            accepted: receipt.map_or(0, |receipt| receipt.contiguous_cursor),
            native: cursor.map_or([0; 8], |cursor| cursor.revision().to_bytes()),
            cursor: cursor.map(|cursor| (cursor.journal, cursor.offset, cursor.sequence)),
        })
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<()> {
        batch.validate_identity(&self.source, &self.root)?;
        if batch.intake_utc_ns == 0 {
            return Err("table intake time".into());
        }
        let mut tx = self.database.write_tx();
        let receipt = self.receipt(&tx)?;
        let mut state = if self.metadata {
            self.state(&tx)?
        } else {
            State::default()
        };
        if receipt.as_ref().is_some_and(|receipt| {
            receipt.identity != self.source || receipt.cpu_id != batch.cpu_id
        }) || batch.first_cursor
            != receipt
                .as_ref()
                .map_or(0, |receipt| receipt.contiguous_cursor)
                + 1
        {
            return Err("table benchmark requires contiguous source and CPU".into());
        }
        let epoch = self.source.epoch_key();
        if let Some(bytes) = tx.get(&self.epochs, &epoch)? {
            if rmp_serde::from_slice::<EvidenceIntakeIdentityV1>(&bytes)? != self.source {
                return Err("table source epoch conflict".into());
            }
        } else {
            tx.insert(&self.epochs, epoch, rmp_serde::to_vec(&self.source)?);
        }
        let prefix = if let Some(prefix) = &self.prefix {
            prefix.clone()
        } else {
            if !self.compact
                || receipt.is_some()
                || tx.get(&self.source_ids, self.source.key())?.is_some()
            {
                return Err("unbound compact source metadata".into());
            }
            let id = if self.metadata {
                state.next_source
            } else {
                match tx.get(&self.state, b"next_source")? {
                    Some(value) => Self::number(Some(value))?,
                    None => 1,
                }
            };
            if id == 0 || tx.get(&self.sources, id.to_be_bytes())?.is_some() {
                return Err("compact source allocator conflict".into());
            }
            let next = id.checked_add(1).ok_or("compact source ID exhausted")?;
            tx.insert(&self.source_ids, self.source.key(), id.to_be_bytes());
            tx.insert(
                &self.sources,
                id.to_be_bytes(),
                rmp_serde::to_vec(&self.source)?,
            );
            if self.metadata {
                state.next_source = next;
            } else {
                tx.insert(&self.state, b"next_source", next.to_be_bytes());
            }
            id.to_be_bytes().to_vec()
        };
        let revision = (if self.metadata {
            state.head
        } else {
            Self::number(tx.get(&self.state, b"head")?)?
        }) + 1;
        let header = Header {
            revision,
            ordinal: 0,
            intake: batch.intake_utc_ns,
            cpu: batch.cpu_id,
        };
        if self.records {
            let mut start = 0;
            for (ordinal, end) in batch.frame_ends.iter().copied().enumerate() {
                let value = (
                    Header {
                        ordinal: u32::try_from(ordinal)?,
                        ..header
                    },
                    serde_bytes::Bytes::new(&batch.framed_records[start..end]),
                );
                tx.insert(
                    &self.events,
                    Self::key(&prefix, batch.first_cursor + ordinal as u64),
                    Self::encode(&value)?,
                );
                start = end;
            }
        } else {
            let ends = batch
                .frame_ends
                .iter()
                .map(|end| u32::try_from(*end))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let value = if self.framed {
                RawCommit {
                    revision,
                    kind: Some(RawKind::Evidence(batch.cpu_id)),
                    intake: batch.intake_utc_ns,
                    spans: vec![RawSpan {
                        first: batch.first_cursor,
                        last: batch.last_cursor,
                        start: 0,
                        ordinal: 0,
                        ends,
                    }],
                    body: batch.framed_records.clone(),
                }
                .frame(&self.root)?
            } else {
                Self::encode(&(
                    header,
                    &ends,
                    serde_bytes::Bytes::new(&batch.framed_records),
                ))?
            };
            tx.insert(&self.events, Self::key(&prefix, batch.first_cursor), value);
        }
        if self.metadata {
            tx.insert(
                &self.receipts,
                &prefix,
                rmp_serde::to_vec(&Receipt {
                    cpu_id: batch.cpu_id,
                    contiguous_cursor: batch.last_cursor,
                    coverage_revision: 0,
                    retained_floor: 0,
                })?,
            );
            state.head = revision;
            state.events = revision;
            state.receipts = revision;
            if receipt.is_none() {
                state.bindings = revision;
            }
            tx.insert(&self.state, b"head", rmp_serde::to_vec(&state)?);
        } else {
            tx.insert(
                &self.receipts,
                self.source.key(),
                rmp_serde::to_vec(&AnalysisSourceReceiptV1 {
                    identity: self.source.clone(),
                    cpu_id: batch.cpu_id,
                    contiguous_cursor: batch.last_cursor,
                    coverage_revision: 0,
                    retained_floor: 0,
                })?,
            );
            for key in [b"head".as_slice(), b"events", b"source_receipts"] {
                tx.insert(&self.state, key, revision.to_be_bytes());
            }
            if receipt.is_none() {
                tx.insert(&self.state, b"source_bindings", revision.to_be_bytes());
            }
        }
        tx.commit_receipt()?.ok_or("missing table input commit")?;
        self.prefix = Some(prefix);
        Ok(())
    }

    fn rows(
        &self,
        key: &[u8],
        bytes: &[u8],
        minimum: u64,
        mut visit: impl FnMut(AnalysisRecordV1) -> Result<bool>,
    ) -> Result<bool> {
        let first = self.cursor(key)?;
        if self.framed {
            let commit = RawCommit::from_frame(bytes, &self.root)?;
            if !matches!(commit.kind, Some(RawKind::Evidence(_)))
                || commit.intake == 0
                || commit.spans.len() != 1
                || commit.spans[0].first != first
            {
                return Err("table frame source or span mismatch".into());
            }
            for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                if cursor < minimum {
                    continue;
                }
                if !visit(AnalysisRecordV1 {
                    cursor,
                    framed_record: bytes.to_vec(),
                    position: StorePositionV1 {
                        commit_revision: commit.revision,
                        ordinal: u32::try_from(ordinal)?,
                    },
                })? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        if self.records {
            let Record(header, body) = Self::decode(bytes)?;
            if header.revision == 0 || header.intake == 0 || body.is_empty() {
                return Err("table record metadata".into());
            }
            return visit(AnalysisRecordV1 {
                cursor: first,
                framed_record: body.into_vec(),
                position: StorePositionV1 {
                    commit_revision: header.revision,
                    ordinal: header.ordinal,
                },
            });
        }
        let Batch(header, ends, body) = Self::decode(bytes)?;
        if header.revision == 0
            || header.intake == 0
            || header.ordinal != 0
            || ends.is_empty()
            || ends.last().copied() != Some(u32::try_from(body.len())?)
            || ends
                .iter()
                .scan(0, |previous, end| {
                    let valid = *end > *previous;
                    *previous = *end;
                    Some(valid)
                })
                .any(|valid| !valid)
        {
            return Err("table batch metadata or boundaries".into());
        }
        let mut start = 0;
        for (index, end) in ends.into_iter().enumerate() {
            let end = end as usize;
            let cursor = first
                .checked_add(index as u64)
                .ok_or("table cursor overflow")?;
            if cursor < minimum {
                start = end;
                continue;
            }
            let record = AnalysisRecordV1 {
                cursor,
                framed_record: body[start..end].to_vec(),
                position: StorePositionV1 {
                    commit_revision: header.revision,
                    ordinal: u32::try_from(index)?,
                },
            };
            start = end;
            if !visit(record)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn point(&self, cursor: u64) -> Result<Vec<AnalysisRecordV1>> {
        let Some(prefix) = self.prefix.as_deref() else {
            return Ok(Vec::new());
        };
        let snapshot = self.database.read_tx();
        let target = Self::key(prefix, cursor);
        let row = if self.records {
            snapshot
                .get(&self.events, &target)?
                .map(|value| (target, value))
        } else {
            snapshot
                .range(&self.events, Self::key(prefix, 0)..=target)
                .next_back()
                .map(|row| row.into_inner().map(|(key, value)| (key.to_vec(), value)))
                .transpose()?
        };
        let mut output = Vec::new();
        if let Some((key, bytes)) = row {
            self.rows(&key, &bytes, cursor, |record| {
                if record.cursor == cursor {
                    output.push(record);
                }
                Ok(false)
            })?;
        }
        Ok(output)
    }

    pub fn read(&self, first: u64, cut: Option<&Cut>) -> Result<Vec<AnalysisRecordV1>> {
        use std::ops::Bound::{Excluded, Included};
        let Some(prefix) = self.prefix.as_deref() else {
            return Ok(Vec::new());
        };
        let snapshot = self.database.read_tx();
        let target = Self::key(prefix, first);
        let predecessor = if self.records {
            None
        } else {
            snapshot
                .range(&self.events, Self::key(prefix, 0)..=target.clone())
                .next_back()
                .map(|row| row.into_inner())
                .transpose()?
        };
        let lower = predecessor
            .as_ref()
            .map_or(Included(target), |(key, _)| Excluded(key.to_vec()));
        let remaining = std::iter::once_with(|| {
            snapshot.range(&self.events, (lower, Included(Self::key(prefix, u64::MAX))))
        })
        .flatten();
        let mut output = Vec::new();
        for row in predecessor
            .into_iter()
            .map(Ok)
            .chain(remaining.map(|row| row.into_inner()))
        {
            let (key, bytes) = row?;
            if !self.rows(&key, &bytes, first, |record| {
                if cut.is_some_and(|cut| record.position.commit_revision > cut.revision) {
                    return Ok(false);
                }
                output.push(record);
                Ok(output.len() < crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
            })? {
                break;
            }
        }
        Ok(output)
    }

    pub fn scan(
        &self,
        cut: Option<&Cut>,
        mut visit: impl FnMut(Vec<AnalysisRecordV1>) -> Result<()>,
    ) -> Result<()> {
        let Some(prefix) = self.prefix.as_deref() else {
            return Ok(());
        };
        let snapshot = self.database.read_tx();
        let mut output = Vec::new();
        for row in snapshot.prefix(&self.events, prefix) {
            let (key, bytes) = row.into_inner()?;
            if !self.rows(&key, &bytes, 1, |record| {
                if cut.is_some_and(|cut| record.position.commit_revision > cut.revision) {
                    return Ok(false);
                }
                output.push(record);
                if output.len() == crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                    visit(std::mem::take(&mut output))?;
                }
                Ok(true)
            })? {
                break;
            }
        }
        if !output.is_empty() {
            visit(output)?;
        }
        Ok(())
    }

    pub fn consume(&self, progress: &Progress) -> Result<()> {
        let mut tx = self.database.write_tx();
        let mut state = if self.metadata {
            self.state(&tx)?
        } else {
            State::default()
        };
        let consumed = if self.metadata {
            state.consumed
        } else {
            Self::number(tx.get(&self.state, b"consumed")?)?
        };
        if consumed != progress.first - 1 {
            return Err("table consumed cursor conflict".into());
        }
        tx.insert(
            &self.results,
            progress.cut.accepted.to_be_bytes(),
            rmp_serde::to_vec(progress)?,
        );
        if self.metadata {
            state.consumed = progress.cut.accepted;
            state.head = progress.cut.revision + 1;
            tx.insert(&self.state, b"head", rmp_serde::to_vec(&state)?);
        } else {
            tx.insert(
                &self.state,
                b"consumed",
                progress.cut.accepted.to_be_bytes(),
            );
            tx.insert(
                &self.state,
                b"head",
                (progress.cut.revision + 1).to_be_bytes(),
            );
        }
        tx.commit_receipt()?.ok_or("missing table result commit")?;
        Ok(())
    }

    pub fn saved(&self, last: Option<u64>) -> Result<Cut> {
        let snapshot = self.database.read_tx();
        let last = match last {
            Some(last) => last,
            None if self.metadata => self.state(&snapshot)?.consumed,
            None => Self::number(snapshot.get(&self.state, b"consumed")?)?,
        };
        let bytes = snapshot
            .get(&self.results, last.to_be_bytes())?
            .ok_or("missing table result")?;
        let progress: Progress = rmp_serde::from_slice(&bytes)?;
        if progress.source != self.source
            || progress.cut.accepted != last
            || progress.body != [0x44; 32]
        {
            return Err("table saved result mismatch".into());
        }
        let page = self.read(progress.first, Some(&progress.cut))?;
        if page.first().map(|row| row.cursor) != Some(progress.first)
            || page.last().map(|row| row.cursor) != Some(last)
        {
            return Err("table saved reference does not resolve".into());
        }
        Ok(progress.cut)
    }

    pub fn replay(
        &self,
        cut: &Cut,
        mut visit: impl FnMut(u64, &[u8], StorePositionV1) -> Result<()>,
    ) -> Result<u64> {
        let Some(prefix) = self.prefix.as_deref() else {
            return Ok(0);
        };
        let mut feed = self.database.inner().journal_feed(cut.journal())?;
        let mut count = 0;
        while let Some(batch) = feed.next_batch()? {
            let revision = batch
                .items
                .iter()
                .find(|item| {
                    item.keyspace == self.state.inner().id() && item.key.as_ref() == b"head"
                })
                .and_then(|item| item.value.as_deref())
                .map(|bytes| -> Result<u64> {
                    if self.metadata {
                        Ok(rmp_serde::from_slice::<State>(bytes)?.head)
                    } else {
                        Ok(u64::from_be_bytes(bytes.try_into()?))
                    }
                })
                .transpose()?;
            for item in batch.items {
                if item.keyspace != self.events.inner().id() || !item.key.starts_with(prefix) {
                    continue;
                }
                let bytes = item.value.ok_or("unexpected table deletion")?;
                self.rows(&item.key, &bytes, 1, |record| {
                    if Some(record.position.commit_revision) != revision {
                        return Err("table input differs from committed head".into());
                    }
                    visit(record.cursor, &record.framed_record, record.position)?;
                    count += 1;
                    Ok(true)
                })?;
            }
        }
        Ok(count)
    }

    pub fn journal_usage(&self) -> Result<[u64; 3]> {
        use std::os::unix::fs::MetadataExt as _;
        let mut usage = [0; 3];
        for entry in std::fs::read_dir(self.root.join("fjall"))? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jnl")
            {
                let metadata = entry.metadata()?;
                usage[0] += 1;
                usage[1] += metadata.len();
                usage[2] += metadata.blocks() * 512;
            }
        }
        Ok(usage)
    }

    pub fn statistics(&self) -> Result<std::collections::BTreeMap<String, [u64; 3]>> {
        let snapshot = self.database.read_tx();
        let mut output = std::collections::BTreeMap::new();
        for (name, table) in [
            ("events", &self.events),
            ("source_receipts", &self.receipts),
            ("source_epochs", &self.epochs),
            ("source_ids", &self.source_ids),
            ("sources", &self.sources),
            ("benchmark_state", &self.state),
            ("benchmark_results", &self.results),
        ] {
            let mut counts = [0; 3];
            for row in snapshot.iter(table) {
                let (key, value) = row.into_inner()?;
                counts[0] += 1;
                counts[1] += key.len() as u64;
                counts[2] += value.len() as u64;
            }
            output.insert(name.into(), counts);
        }
        Ok(output)
    }

    pub fn journal_statistics(&self) -> Result<std::collections::BTreeMap<String, [u64; 3]>> {
        let mut output = std::collections::BTreeMap::<String, [u64; 3]>::new();
        let mut feed = self.database.inner().journal_feed(None)?;
        while let Some(batch) = feed.next_batch()? {
            for item in batch.items {
                let name = [
                    ("events", &self.events),
                    ("source_receipts", &self.receipts),
                    ("source_epochs", &self.epochs),
                    ("source_ids", &self.source_ids),
                    ("sources", &self.sources),
                    ("benchmark_state", &self.state),
                    ("benchmark_results", &self.results),
                ]
                .into_iter()
                .find(|(_, table)| table.inner().id() == item.keyspace)
                .map_or("engine", |(name, _)| name);
                let counts = output.entry(name.into()).or_default();
                counts[0] += 1;
                counts[1] += item.key.len() as u64;
                counts[2] += item.value.as_ref().map_or(0, |value| value.len() as u64);
            }
        }
        Ok(output)
    }
}
