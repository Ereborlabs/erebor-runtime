use std::{ops::Bound::Excluded, path::Path, time::Instant};

use serde::{Deserialize, Serialize};

use super::NativeStore;
use crate::analysis::{raw::RawCommit, raw_benchmark::Result};
use crate::{
    AnalysisReadControl, AnalysisRecordV1, EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1,
    StorePositionV1, ValidatedEvidenceBatchV1,
};

mod candidate;
use candidate::Candidate;

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
    Hybrid(Box<NativeStore>),
    Fjall(Candidate),
}

pub struct Store {
    backend: Backend,
    source: EvidenceIntakeIdentityV1,
}

impl Store {
    pub fn open(root: &Path, backend: &str, source: EvidenceIntakeIdentityV1) -> Result<Self> {
        let backend = match backend {
            "hybrid" => Backend::Hybrid(Box::new(NativeStore::open(root)?)),
            "fjall" => Backend::Fjall(Candidate::open(root, source.clone())?),
            _ => return Err("expected hybrid or fjall".into()),
        };
        Ok(Self { backend, source })
    }

    fn branch(&self) -> &fjall::Branch {
        match &self.backend {
            Backend::Hybrid(store) => store.branch(),
            Backend::Fjall(store) => &store.branch,
        }
    }

    fn database(&self) -> &fjall::SingleWriterTxDatabase {
        match &self.backend {
            Backend::Hybrid(store) => store.database(),
            Backend::Fjall(store) => &store.database,
        }
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<()> {
        match &mut self.backend {
            Backend::Hybrid(store) => {
                if store.accept_validated_batch(self.source.clone(), batch)?
                    != EvidenceStoreOutcomeV1::Accepted
                {
                    return Err("benchmark batch was not accepted".into());
                }
                Ok(())
            }
            Backend::Fjall(store) => store.append(batch),
        }
    }

    pub fn cut(&self) -> Result<Cut> {
        let (revision, accepted, snapshot) = match &self.backend {
            Backend::Hybrid(store) => {
                let view = store.view()?;
                let accepted = view
                    .source_receipt(&self.source)?
                    .map_or(0, |receipt| receipt.contiguous_cursor);
                (view.revision(), accepted, view.snapshot().clone())
            }
            Backend::Fjall(store) => store.cut()?,
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
            Backend::Hybrid(store) => {
                let view = match cut {
                    Some(cut) => store.read_at(cut.revision)?,
                    None => store.view()?.as_ref().clone(),
                };
                Ok(store
                    .read_page_at(&view, &self.source, first, &AnalysisReadControl::default())?
                    .records)
            }
            Backend::Fjall(store) => store.read(first, cut),
        }
    }

    pub fn scan(
        &self,
        cut: Option<&Cut>,
        mut visit: impl FnMut(Vec<AnalysisRecordV1>) -> Result<()>,
    ) -> Result<()> {
        match &self.backend {
            Backend::Hybrid(store) => {
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
            Backend::Hybrid(store) => {
                let mut tx = store.write()?;
                progress.stage(tx.native())?;
                tx.commit([])?.ok_or("missing hybrid metadata commit")?;
            }
            Backend::Fjall(store) => {
                let mut tx = store.branch.write_tx()?;
                progress.stage(&mut tx)?;
                tx.insert(super::HEAD, (cut.revision + 1).to_be_bytes());
                tx.commit()?.ok_or("missing native progress commit")?;
            }
        }
        Ok(())
    }

    pub fn saved(&self, last: Option<u64>) -> Result<Cut> {
        let snapshot = self.branch().snapshot()?;
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
            Backend::Hybrid(store) => {
                let view = store.view()?;
                let raw = store.raw.lock().map_err(|_| "raw benchmark lock")?;
                for (_, entry) in view
                    .raw
                    .entries
                    .range((Excluded(cut.revision), std::ops::Bound::Unbounded))
                {
                    consume(raw.read_entry(entry)?)?;
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
        }
        Ok(count)
    }

    pub fn maintain(&self) -> Result<serde_json::Value> {
        let started = Instant::now();
        if let Backend::Hybrid(store) = &self.backend {
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
