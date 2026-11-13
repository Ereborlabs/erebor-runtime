use std::path::{Path, PathBuf};

use fjall::{Readable, SingleWriterTxKeyspace};
use serde::{Deserialize, Serialize};

use super::{Cut, Progress, Result};
use crate::analysis::raw::{RawCommit, RawKind, RawSpan};
use crate::{
    AnalysisRecordV1, AnalysisSourceReceiptV1, EvidenceIntakeIdentityV1, StorePositionV1,
    ValidatedEvidenceBatchV1,
};

#[derive(Default, Deserialize, Serialize)]
struct State {
    head: u64,
    events: u64,
    receipts: u64,
    bindings: u64,
}

pub(super) struct Natural {
    pub database: fjall::SingleWriterTxDatabase,
    pub root: PathBuf,
    events: SingleWriterTxKeyspace,
    sources: SingleWriterTxKeyspace,
    results: SingleWriterTxKeyspace,
    state: SingleWriterTxKeyspace,
    source: EvidenceIntakeIdentityV1,
    prefix: Vec<u8>,
    bound: bool,
}

impl Natural {
    pub fn open(root: &Path, source: EvidenceIntakeIdentityV1) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
            .journal_cdc()
            .open()?;
        let mut store = Self {
            events: database.keyspace("events", fjall::KeyspaceCreateOptions::default)?,
            sources: database.keyspace("sources", fjall::KeyspaceCreateOptions::default)?,
            results: database
                .keyspace("benchmark_results", fjall::KeyspaceCreateOptions::default)?,
            state: database.keyspace("benchmark_state", fjall::KeyspaceCreateOptions::default)?,
            database,
            prefix: source.epoch_key(),
            source,
            root: root.to_path_buf(),
            bound: false,
        };
        store.bound = store.receipt(&store.database.read_tx())?.is_some();
        Ok(store)
    }

    fn key(&self, cursor: u64) -> Vec<u8> {
        [&self.prefix[..], &cursor.to_be_bytes()].concat()
    }

    fn cursor(&self, key: &[u8]) -> Result<u64> {
        Ok(u64::from_be_bytes(
            key.strip_prefix(self.prefix.as_slice())
                .ok_or("natural source key mismatch")?
                .try_into()?,
        ))
    }

    fn receipt(&self, tx: &impl Readable) -> Result<Option<AnalysisSourceReceiptV1>> {
        let receipt = tx
            .get(&self.sources, &self.prefix)?
            .map(|bytes| rmp_serde::from_slice::<AnalysisSourceReceiptV1>(&bytes))
            .transpose()?;
        if receipt
            .as_ref()
            .is_some_and(|row| row.identity != self.source)
        {
            return Err("natural source epoch conflict".into());
        }
        Ok(receipt)
    }

    fn state(&self, tx: &impl Readable) -> Result<State> {
        Ok(tx
            .get(&self.state, b"head")?
            .map(|bytes| rmp_serde::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default())
    }

    pub fn cut(&self) -> Result<Cut> {
        let tx = self.database.read_tx();
        let revision = self.state(&tx)?.head;
        let accepted = if self.bound {
            self.receipt(&tx)?.map_or(0, |row| row.contiguous_cursor)
        } else {
            0
        };
        let cursor = self.database.inner().journal_head()?;
        Ok(Cut {
            revision,
            accepted,
            native: cursor.map_or([0; 8], |cursor| cursor.revision().to_bytes()),
            cursor: cursor.map(|cursor| (cursor.journal, cursor.offset, cursor.sequence)),
        })
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<()> {
        batch.validate_identity(&self.source, &self.root)?;
        if batch.intake_utc_ns == 0 {
            return Err("natural intake time".into());
        }
        let mut tx = self.database.write_tx();
        let previous = self.receipt(&tx)?;
        if previous
            .as_ref()
            .is_some_and(|row| row.cpu_id != batch.cpu_id)
            || batch.first_cursor != previous.as_ref().map_or(0, |row| row.contiguous_cursor) + 1
        {
            return Err("natural benchmark requires contiguous source and CPU".into());
        }
        let mut state = self.state(&tx)?;
        state.head += 1;
        state.events = state.head;
        state.receipts = state.head;
        if previous.is_none() {
            state.bindings = state.head;
        }
        let commit = RawCommit {
            revision: state.head,
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
                    .map(|end| u32::try_from(*end))
                    .collect::<std::result::Result<_, _>>()?,
            }],
            body: batch.framed_records,
        };
        tx.insert(
            &self.events,
            self.key(batch.first_cursor),
            commit.frame(&self.root)?,
        );
        tx.insert(
            &self.sources,
            &self.prefix,
            rmp_serde::to_vec(&AnalysisSourceReceiptV1 {
                identity: self.source.clone(),
                cpu_id: batch.cpu_id,
                contiguous_cursor: batch.last_cursor,
                coverage_revision: previous.as_ref().map_or(0, |row| row.coverage_revision),
                retained_floor: previous.as_ref().map_or(0, |row| row.retained_floor),
            })?,
        );
        tx.insert(&self.state, b"head", rmp_serde::to_vec(&state)?);
        tx.commit_receipt()?.ok_or("missing natural input commit")?;
        self.bound = true;
        Ok(())
    }

    fn decode(&self, key: &[u8], bytes: &[u8]) -> Result<RawCommit> {
        let first = self.cursor(key)?;
        let commit = RawCommit::from_frame(bytes, &self.root)?;
        if first == 0
            || !matches!(commit.kind, Some(RawKind::Evidence(_)))
            || commit.intake == 0
            || commit.spans.len() != 1
            || commit.spans[0].first != first
        {
            return Err("natural batch source or span mismatch".into());
        }
        Ok(commit)
    }

    fn rows(
        &self,
        key: &[u8],
        bytes: &[u8],
        first: u64,
        cut: Option<&Cut>,
        mut visit: impl FnMut(AnalysisRecordV1) -> Result<bool>,
    ) -> Result<bool> {
        let commit = self.decode(key, bytes)?;
        if cut.is_some_and(|cut| commit.revision > cut.revision) {
            return Ok(false);
        }
        for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
            if cursor < first {
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
        Ok(true)
    }

    pub fn read(&self, first: u64, cut: Option<&Cut>) -> Result<Vec<AnalysisRecordV1>> {
        if !self.bound {
            return Ok(Vec::new());
        }
        let tx = self.database.read_tx();
        let target = self.key(first);
        let predecessor = tx
            .range(&self.events, self.key(0)..=target.clone())
            .next_back()
            .map(|row| row.into_inner())
            .transpose()?;
        let lower = predecessor
            .as_ref()
            .map_or(std::ops::Bound::Included(target), |(key, _)| {
                std::ops::Bound::Excluded(key.to_vec())
            });
        let mut output = Vec::new();
        let remaining = std::iter::once_with(|| {
            tx.range(
                &self.events,
                (lower, std::ops::Bound::Included(self.key(u64::MAX))),
            )
        })
        .flatten();
        for row in predecessor
            .into_iter()
            .map(Ok)
            .chain(remaining.map(|row| row.into_inner()))
        {
            let (key, bytes) = row?;
            if !self.rows(&key, &bytes, first, cut, |record| {
                output.push(record);
                Ok(output.len() < crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
            })? {
                break;
            }
        }
        Ok(output)
    }

    pub fn point(&self, cursor: u64) -> Result<Vec<AnalysisRecordV1>> {
        if !self.bound {
            return Ok(Vec::new());
        }
        let tx = self.database.read_tx();
        let mut output = Vec::new();
        if let Some(row) = tx
            .range(&self.events, self.key(0)..=self.key(cursor))
            .next_back()
        {
            let (key, bytes) = row.into_inner()?;
            self.rows(&key, &bytes, cursor, None, |record| {
                if record.cursor == cursor {
                    output.push(record);
                }
                Ok(false)
            })?;
        }
        Ok(output)
    }

    pub fn scan(
        &self,
        cut: Option<&Cut>,
        mut visit: impl FnMut(Vec<AnalysisRecordV1>) -> Result<()>,
    ) -> Result<()> {
        if !self.bound {
            return Ok(());
        }
        let tx = self.database.read_tx();
        let mut output = Vec::new();
        for row in tx.prefix(&self.events, &self.prefix) {
            let (key, bytes) = row.into_inner()?;
            if !self.rows(&key, &bytes, 1, cut, |record| {
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

    fn progress(&self, tx: &impl Readable, last: Option<u64>) -> Result<Option<Progress>> {
        let row = match last {
            Some(last) => tx
                .get(&self.results, self.key(last))?
                .map(|value| (self.key(last), value)),
            None => tx
                .prefix(&self.results, &self.prefix)
                .next_back()
                .map(|row| row.into_inner().map(|(key, value)| (key.to_vec(), value)))
                .transpose()?,
        };
        row.map(|(key, bytes)| {
            let progress: Progress = rmp_serde::from_slice(&bytes)?;
            if self.cursor(&key)? != progress.cut.accepted
                || progress.source != self.source
                || progress.body != [0x44; 32]
            {
                return Err("natural saved result mismatch".into());
            }
            Ok(progress)
        })
        .transpose()
    }

    pub fn consume(&self, progress: &Progress) -> Result<()> {
        let mut tx = self.database.write_tx();
        if self.progress(&tx, None)?.map_or(0, |row| row.cut.accepted) != progress.first - 1 {
            return Err("natural consumed cursor conflict".into());
        }
        let mut state = self.state(&tx)?;
        state.head = state.head.checked_add(1).ok_or("natural head exhausted")?;
        tx.insert(
            &self.results,
            self.key(progress.cut.accepted),
            rmp_serde::to_vec(progress)?,
        );
        tx.insert(&self.state, b"head", rmp_serde::to_vec(&state)?);
        tx.commit_receipt()?
            .ok_or("missing natural result commit")?;
        Ok(())
    }

    pub fn saved(&self, last: Option<u64>) -> Result<Cut> {
        let progress = self
            .progress(&self.database.read_tx(), last)?
            .ok_or("missing natural saved result")?;
        let page = self.read(progress.first, Some(&progress.cut))?;
        if page.first().map(|row| row.cursor) != Some(progress.first)
            || page.last().map(|row| row.cursor) != Some(progress.cut.accepted)
        {
            return Err("natural saved reference does not resolve".into());
        }
        Ok(progress.cut)
    }

    pub fn replay(
        &self,
        cut: &Cut,
        mut visit: impl FnMut(u64, &[u8], StorePositionV1) -> Result<()>,
    ) -> Result<u64> {
        if !self.bound {
            return Ok(0);
        }
        let mut feed = self.database.inner().journal_feed(cut.journal())?;
        let mut count = 0;
        while let Some(batch) = feed.next_batch()? {
            let head = batch
                .items
                .iter()
                .find(|item| {
                    item.keyspace == self.state.inner().id() && item.key.as_ref() == b"head"
                })
                .and_then(|item| item.value.as_deref())
                .map(|bytes| rmp_serde::from_slice::<State>(bytes))
                .transpose()?;
            for item in batch.items {
                if item.keyspace != self.events.inner().id() || !item.key.starts_with(&self.prefix)
                {
                    continue;
                }
                let commit = self.decode(
                    &item.key,
                    &item.value.ok_or("unexpected natural event deletion")?,
                )?;
                if Some(commit.revision) != head.as_ref().map(|state| state.head) {
                    return Err("natural input differs from committed head".into());
                }
                for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                    visit(
                        cursor,
                        bytes,
                        StorePositionV1 {
                            commit_revision: commit.revision,
                            ordinal: u32::try_from(ordinal)?,
                        },
                    )?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    pub fn statistics(&self) -> Result<serde_json::Value> {
        let tables = [
            ("events", &self.events),
            ("sources", &self.sources),
            ("benchmark_results", &self.results),
            ("benchmark_state", &self.state),
        ];
        let mut live = std::collections::BTreeMap::<String, [u64; 3]>::new();
        let tx = self.database.read_tx();
        for (name, table) in tables {
            let counts = live.entry(name.into()).or_default();
            for row in tx.iter(table) {
                let (key, bytes) = row.into_inner()?;
                counts[0] += 1;
                counts[1] += key.len() as u64;
                counts[2] += bytes.len() as u64;
            }
        }
        let mut journal = std::collections::BTreeMap::<String, [u64; 3]>::new();
        let mut feed = self.database.inner().journal_feed(None)?;
        while let Some(batch) = feed.next_batch()? {
            for item in batch.items {
                let name = tables
                    .iter()
                    .find(|(_, table)| table.inner().id() == item.keyspace)
                    .map_or("engine", |(name, _)| *name);
                let counts = journal.entry(name.into()).or_default();
                counts[0] += 1;
                counts[1] += item.key.len() as u64;
                counts[2] += item.value.as_ref().map_or(0, |value| value.len() as u64);
            }
        }
        Ok(
            serde_json::json!({"logical_counts":live,"journal_logical_counts":journal,
            "count_fields":["entries","key_bytes","value_bytes"],"journal_bytes":self.database.inner().journal_disk_space()?}),
        )
    }
}
