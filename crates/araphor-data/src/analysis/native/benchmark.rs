use std::{path::Path, time::Instant};

use serde::{Deserialize, Serialize};

use super::NativeStore;
use crate::analysis::{raw::RawCommit, raw_benchmark::Result};
use crate::{
    AnalysisReadControl, AnalysisRecordV1, EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1,
    StorePositionV1, ValidatedEvidenceBatchV1,
};

mod candidate;
mod tables;
use candidate::Candidate;
use tables::Tables;

const PROGRESS: &[u8] = b"benchmark/consumed";
const RESULTS: &[u8] = b"benchmark/result/";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Cut {
    pub revision: u64,
    pub accepted: u64,
    native: [u8; 8],
    cursor: Option<(u64, u64, u64)>,
}

impl Cut {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(rmp_serde::from_slice(bytes)?)
    }

    fn journal(&self) -> Option<fjall::Cursor> {
        self.cursor
            .map(|(journal, offset, sequence)| fjall::Cursor {
                journal,
                offset,
                sequence,
            })
    }
}

#[derive(Deserialize, Serialize)]
struct Progress {
    source: EvidenceIntakeIdentityV1,
    first: u64,
    cut: Cut,
    body: [u8; 32],
}

impl Progress {
    fn key(last: u64) -> Vec<u8> {
        [RESULTS, &last.to_be_bytes()].concat()
    }

    fn stage(&self, tx: &mut fjall::BranchWriteTransaction<'_>) -> Result<()> {
        let previous = tx
            .get(PROGRESS)?
            .map(|bytes| bytes.as_ref().try_into().map(u64::from_be_bytes))
            .transpose()?;
        if previous.unwrap_or(0) != self.first - 1 {
            return Err("benchmark consumed cursor conflict".into());
        }
        tx.insert(Self::key(self.cut.accepted), rmp_serde::to_vec(self)?);
        tx.insert(PROGRESS, self.cut.accepted.to_be_bytes());
        Ok(())
    }
}

enum Backend {
    Production(Box<NativeStore>),
    Fjall(Candidate),
    Tables(Tables),
}

pub struct Store {
    backend: Backend,
    source: EvidenceIntakeIdentityV1,
}

impl Store {
    pub fn open(root: &Path, backend: &str, source: EvidenceIntakeIdentityV1) -> Result<Self> {
        let backend = match backend {
            "production" => Backend::Production(Box::new(NativeStore::open(root)?)),
            "fjall" => Backend::Fjall(Candidate::open(root, source.clone())?),
            "table-batch" | "table-record" | "compact-batch" | "compact-record" => Backend::Tables(Tables::open(
                root,
                source.clone(),
                backend.ends_with("-record"),
                backend.starts_with("compact-"),
            )?),
            _ => return Err("expected production, fjall, table-batch, table-record, compact-batch, or compact-record".into()),
        };
        Ok(Self { backend, source })
    }

    fn database(&self) -> &fjall::SingleWriterTxDatabase {
        match &self.backend {
            Backend::Production(store) => store.database(),
            Backend::Fjall(store) => &store.database,
            Backend::Tables(store) => &store.database,
        }
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<()> {
        match &mut self.backend {
            Backend::Production(store) => {
                if store.accept_validated_batch(self.source.clone(), batch)?
                    != EvidenceStoreOutcomeV1::Accepted
                {
                    return Err("benchmark batch was not accepted".into());
                }
                Ok(())
            }
            Backend::Fjall(store) => store.append(batch),
            Backend::Tables(store) => store.append(batch),
        }
    }

    pub fn cut(&self) -> Result<Cut> {
        let (revision, accepted, snapshot) = match &self.backend {
            Backend::Production(store) => {
                let view = store.view()?;
                let accepted = view
                    .source_receipt(&self.source)?
                    .map_or(0, |receipt| receipt.contiguous_cursor);
                (view.revision(), accepted, view.snapshot().clone())
            }
            Backend::Fjall(store) => store.cut()?,
            Backend::Tables(store) => return store.cut(),
        };
        Ok(Cut {
            revision,
            accepted,
            native: snapshot.revision().to_bytes(),
            cursor: snapshot
                .cursor()?
                .map(|cursor| (cursor.journal, cursor.offset, cursor.sequence)),
        })
    }

    pub fn read(&self, first: u64, cut: Option<&Cut>) -> Result<Vec<AnalysisRecordV1>> {
        match &self.backend {
            Backend::Production(store) => {
                let view = match cut {
                    Some(cut) => store.read_at(cut.revision)?,
                    None => store.view()?.as_ref().clone(),
                };
                Ok(store
                    .read_page_at(&view, &self.source, first, &AnalysisReadControl::default())?
                    .records)
            }
            Backend::Fjall(store) => store.read(first, cut),
            Backend::Tables(store) => store.read(first, cut),
        }
    }

    pub fn point(&self, cursor: u64) -> Result<Vec<AnalysisRecordV1>> {
        match &self.backend {
            Backend::Tables(store) => store.point(cursor),
            _ => Err("point comparison requires the table PoC".into()),
        }
    }

    pub fn statistics(&self) -> Result<serde_json::Value> {
        let counts = match &self.backend {
            Backend::Tables(store) => store.statistics()?,
            Backend::Production(store) => {
                let mut counts = std::collections::BTreeMap::<String, [u64; 3]>::new();
                for row in store.view()?.snapshot().iter() {
                    let (key, value) = row?;
                    let name = [
                        (super::events::Events::PAYLOAD, "payload"),
                        (super::events::Events::SPANS, "span"),
                        (super::events::Events::POSITION, "position"),
                        (super::events::Events::EXPIRED, "expiry"),
                        (super::source::Sources::RECEIPTS, "source_receipts"),
                        (super::source::Sources::EPOCHS, "source_epochs"),
                    ]
                    .into_iter()
                    .find(|(prefix, _)| key.starts_with(prefix))
                    .map_or("other_metadata", |(_, name)| name);
                    let entry = counts.entry(name.into()).or_default();
                    entry[0] += 1;
                    entry[1] += key.len() as u64;
                    entry[2] += value.len() as u64;
                }
                counts
            }
            Backend::Fjall(_) => return Err("statistics require production or table PoC".into()),
        };
        Ok(serde_json::json!({"logical_counts":counts,
            "count_fields":["entries","key_bytes","value_bytes"],
            "journal_bytes":self.database().inner().journal_disk_space()?}))
    }

    pub fn scan(
        &self,
        cut: Option<&Cut>,
        mut visit: impl FnMut(Vec<AnalysisRecordV1>) -> Result<()>,
    ) -> Result<()> {
        match &self.backend {
            Backend::Production(store) => {
                let view = match cut {
                    Some(cut) => store.read_at(cut.revision)?,
                    None => store.view()?.as_ref().clone(),
                };
                let control = AnalysisReadControl::default();
                let mut first = 1;
                loop {
                    let page = store.read_page_at(&view, &self.source, first, &control)?;
                    if !page.records.is_empty() {
                        visit(page.records)?;
                    }
                    let Some(next) = page.next_cursor else {
                        break;
                    };
                    first = next;
                }
                Ok(())
            }
            Backend::Fjall(store) => store.scan(cut, visit),
            Backend::Tables(store) => store.scan(cut, visit),
        }
    }

    pub fn consume(&self, first: u64, cut: &Cut) -> Result<()> {
        let page = self.read(first, None)?;
        if page.first().map(|row| row.cursor) != Some(first)
            || page.last().map(|row| row.cursor) != Some(cut.accepted)
        {
            return Err("benchmark result references an absent input batch".into());
        }
        let progress = Progress {
            source: self.source.clone(),
            first,
            cut: cut.clone(),
            body: [0x44; 32],
        };
        match &self.backend {
            Backend::Production(store) => {
                let mut tx = store.write()?;
                progress.stage(tx.native())?;
                tx.commit([])?.ok_or("missing production metadata commit")?;
            }
            Backend::Fjall(store) => {
                let mut tx = store.branch.write_tx()?;
                progress.stage(&mut tx)?;
                tx.insert(super::HEAD, (cut.revision + 1).to_be_bytes());
                tx.commit()?.ok_or("missing native progress commit")?;
            }
            Backend::Tables(store) => store.consume(&progress)?,
        }
        Ok(())
    }

    pub fn saved(&self, last: Option<u64>) -> Result<Cut> {
        let snapshot = match &self.backend {
            Backend::Production(store) => store.branch().snapshot()?,
            Backend::Fjall(store) => store.branch.snapshot()?,
            Backend::Tables(store) => return store.saved(last),
        };
        let last = match last {
            Some(last) => last,
            None => u64::from_be_bytes(
                snapshot
                    .get(PROGRESS)?
                    .ok_or("missing saved consumed cursor")?
                    .as_ref()
                    .try_into()?,
            ),
        };
        let bytes = snapshot
            .get(Progress::key(last))?
            .ok_or("missing saved result")?;
        let progress: Progress = rmp_serde::from_slice(&bytes)?;
        if progress.source != self.source
            || progress.cut.accepted != last
            || progress.body != [0x44; 32]
        {
            return Err("benchmark saved result mismatch".into());
        }
        let page = self.read(progress.first, Some(&progress.cut))?;
        if page.first().map(|row| row.cursor) != Some(progress.first)
            || page.last().map(|row| row.cursor) != Some(last)
        {
            return Err("benchmark saved reference does not resolve".into());
        }
        Ok(progress.cut)
    }

    pub fn replay(
        &self,
        cut: &Cut,
        mut visit: impl FnMut(u64, &[u8], StorePositionV1) -> Result<()>,
    ) -> Result<u64> {
        let mut count = 0;
        let mut consume = |commit: RawCommit| -> Result<()> {
            for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                visit(
                    cursor,
                    bytes,
                    StorePositionV1 {
                        commit_revision: commit.revision,
                        ordinal: ordinal as u32,
                    },
                )?;
                count += 1;
            }
            Ok(())
        };
        match &self.backend {
            Backend::Production(store) => {
                let mut feed = store.database.inner().journal_feed(cut.journal())?;
                while let Some(batch) = feed.next_batch()? {
                    for item in &batch.items {
                        if item.branch != Some(store.branch.id())
                            || !item.key.starts_with(super::events::Events::PAYLOAD)
                        {
                            continue;
                        }
                        let Some(bytes) = &item.value else {
                            continue;
                        };
                        let head = batch
                            .items
                            .iter()
                            .find(|item| {
                                item.branch == Some(store.branch.id())
                                    && item.key.as_ref() == super::HEAD
                            })
                            .and_then(|item| item.value.as_deref())
                            .ok_or("benchmark payload Data head")?;
                        let revision = NativeStore::number(head)?;
                        let key = super::events::Events::position(
                            super::events::Events::POSITION,
                            revision,
                        );
                        let header = batch
                            .items
                            .iter()
                            .find(|item| {
                                item.branch == Some(store.branch.id())
                                    && item.key.as_ref() == key.as_slice()
                            })
                            .and_then(|item| item.value.as_deref())
                            .and_then(|value| value.strip_prefix(&[0]))
                            .ok_or("benchmark payload position")?;
                        let header: super::events::EventBatch =
                            super::records::Records::decode(header)?;
                        header.check(revision)?;
                        let commit = RawCommit::from_frame(bytes, &store.root)?;
                        header.check_commit(&commit, bytes.len())?;
                        if commit.revision != revision
                            || header.source != self.source
                            || item.key.as_ref()
                                != super::events::Events::key(
                                    super::events::Events::PAYLOAD,
                                    &header.source,
                                    header.first,
                                )
                        {
                            return Err("benchmark payload source or position".into());
                        }
                        consume(commit)?;
                    }
                }
            }
            Backend::Fjall(store) => {
                let mut feed = store.database.inner().journal_feed(cut.journal())?;
                let prefix = store.key(None);
                while let Some(batch) = feed.next_batch()? {
                    for item in batch.items {
                        if item.branch == Some(store.branch.id()) && item.key.starts_with(&prefix) {
                            let bytes =
                                item.value.ok_or("benchmark unexpected payload deletion")?;
                            consume(store.decode(&item.key, &bytes)?)?;
                        }
                    }
                }
            }
            Backend::Tables(store) => return store.replay(cut, visit),
        }
        Ok(count)
    }

    pub fn maintain(&self) -> Result<serde_json::Value> {
        let started = Instant::now();
        if let Backend::Production(store) = &self.backend {
            store.checkpoint()?;
        }
        let checkpoint = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let database = self.database().inner();
        let before = database.compactions_completed();
        database.flush_memtables()?;
        let flush = started.elapsed().as_secs_f64();
        let started = Instant::now();
        database.major_compact()?;
        Ok(
            serde_json::json!({"checkpoint_s":checkpoint,"flush_s":flush,
            "major_compact_s":started.elapsed().as_secs_f64(),
            "background_compactions":database.compactions_completed()-before}),
        )
    }
}
