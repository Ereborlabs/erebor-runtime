use std::{collections::BTreeMap, path::Path, time::Instant};

use super::raw::{RawCommit, RawEntry, RawIdentity, RawJournal, RawLocation, RawMeta, RawReceipt};
use super::{AnalysisRecordV1, EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct Cut {
    revision: u64,
    native: Option<fjall::Revision>,
    cursor: Option<fjall::Cursor>,
}

impl Cut {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(&(
            self.revision,
            self.native.map(|revision| revision.to_bytes()),
            self.cursor
                .map(|cursor| (cursor.journal, cursor.offset, cursor.sequence)),
        ))?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (revision, native, cursor): (u64, Option<[u8; 8]>, Option<(u64, u64, u64)>) =
            rmp_serde::from_slice(bytes)?;
        Ok(Self {
            revision,
            native: native.map(fjall::Revision::from_bytes),
            cursor: cursor.map(|(journal, offset, sequence)| fjall::Cursor {
                journal,
                offset,
                sequence,
            }),
        })
    }
}

#[derive(serde::Serialize)]
pub struct Append {
    pub prepare_ns: u64,
    pub commit_ns: u64,
    pub total_ns: u64,
}

struct Native {
    branch: fjall::Branch,
    database: fjall::SingleWriterTxDatabase,
}

pub struct Store {
    journal: RawJournal,
    identity: RawIdentity,
    native: Option<Native>,
}

impl Store {
    pub fn open(root: &Path, backend: &str, identity: EvidenceIntakeIdentityV1) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let mut journal = RawJournal::open(root, &BTreeMap::new())?;
        let identity = RawIdentity::Evidence(identity);
        let native = match backend {
            "segments" => None,
            "fjall" => {
                let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
                    .versioned()
                    .open()?;
                let branch = match database.branch("raw-benchmark")? {
                    Some(branch) => branch,
                    None => {
                        let branch = database.create_branch("raw-benchmark")?;
                        branch.retain_history(branch.info()?.head..)?;
                        branch
                    }
                };
                let snapshot = branch.snapshot()?;
                let receipt = snapshot.get(Self::key(&identity, b'r', None))?;
                if let Some(receipt) = receipt {
                    let receipt = RawReceipt::Evidence(rmp_serde::from_slice(&receipt)?);
                    for row in snapshot.prefix(Self::key(&identity, b'i', None)) {
                        let (_, bytes) = row?;
                        let entry: RawEntry = rmp_serde::from_slice(&bytes)?;
                        if entry.identity != identity {
                            return Err("benchmark source identity".into());
                        }
                        journal.index = journal.index.prepare(entry, receipt.clone(), root)?;
                    }
                    journal.index.refresh_source(&identity.key())?;
                }
                drop(snapshot);
                Some(Native { branch, database })
            }
            _ => return Err("unknown raw benchmark backend".into()),
        };
        Ok(Self {
            journal,
            identity,
            native,
        })
    }

    fn key(identity: &RawIdentity, tag: u8, cursor: Option<u64>) -> Vec<u8> {
        let mut key = vec![tag];
        key.extend(identity.key());
        if let Some(cursor) = cursor {
            key.extend(cursor.to_be_bytes());
        }
        key
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<Append> {
        let started = Instant::now();
        let source = self
            .identity
            .evidence()
            .ok_or("benchmark evidence source")?;
        batch.validate_identity(source, &self.journal.root)?;
        let revision = self.journal.index.revision + 1;
        if batch.first_cursor != self.accepted() + 1 {
            return Err("benchmark append requires disjoint contiguous input".into());
        }
        let commit = self
            .journal
            .prepare(&self.identity, &batch.into(), revision)?;
        let append = self.journal.prepare_append(&self.identity, commit)?;
        let prepared = started.elapsed();
        let durable = Instant::now();
        if let Some(native) = &self.native {
            let first = append
                .commit
                .spans
                .first()
                .ok_or("empty accepted commit")?
                .first;
            let entry = RawEntry {
                identity: self.identity.clone(),
                commit: RawMeta::try_from(&append.commit)?,
                reference: RawLocation {
                    id: revision,
                    offset: append.frame.len() as u64,
                },
                body_start: (append.frame.len() - 4 - append.commit.body.len()) as u64,
                body_bytes: append.commit.body.len(),
                frame_bytes: append.frame.len(),
            };
            let mut index = self.journal.prepare_index(entry.clone(), &append.commit)?;
            index.refresh_source(&self.identity.key())?;
            let receipt = index.sources[&self.identity.key()]
                .receipt
                .evidence()
                .ok_or("benchmark receipt")?;
            let mut transaction = native.branch.write_tx()?;
            transaction.insert(Self::key(&self.identity, b'p', Some(first)), append.frame);
            transaction.insert(
                Self::key(&self.identity, b'i', Some(first)),
                rmp_serde::to_vec(&entry)?,
            );
            transaction.insert(
                Self::key(&self.identity, b'r', None),
                rmp_serde::to_vec(receipt)?,
            );
            transaction.commit()?.ok_or("missing native commit")?;
            self.journal.index = index;
        } else {
            self.journal.append(&self.identity, append)?;
        }
        let committed = durable.elapsed();
        Ok(Append {
            prepare_ns: prepared.as_nanos().try_into()?,
            commit_ns: committed.as_nanos().try_into()?,
            total_ns: started.elapsed().as_nanos().try_into()?,
        })
    }

    pub fn accepted(&self) -> u64 {
        self.journal
            .index
            .sources
            .get(&self.identity.key())
            .map_or(0, |source| source.receipt.cursor())
    }

    pub fn cut(&self) -> Result<Cut> {
        let native = self
            .native
            .as_ref()
            .map(|native| native.branch.snapshot())
            .transpose()?;
        Ok(Cut {
            revision: self.journal.index.revision,
            native: native.as_ref().map(|snapshot| snapshot.revision()),
            cursor: native
                .as_ref()
                .map(|snapshot| snapshot.cursor())
                .transpose()?
                .flatten(),
        })
    }

    fn commit(
        &self,
        entry: &RawEntry,
        snapshot: Option<&fjall::BranchSnapshot>,
    ) -> Result<RawCommit> {
        if let Some(snapshot) = snapshot {
            let first = entry.commit.spans.first().ok_or("benchmark span")?.first;
            let frame = snapshot
                .get(Self::key(&self.identity, b'p', Some(first)))?
                .ok_or("benchmark payload missing at cut")?;
            let commit = RawCommit::from_frame(&frame, &self.journal.root)?;
            if commit.revision != entry.commit.revision
                || commit.kind.as_ref() != Some(&entry.commit.kind)
                || commit.intake != entry.commit.intake
                || RawMeta::try_from(&commit)?.spans != entry.commit.spans
                || commit.body.len() != entry.body_bytes
            {
                return Err("benchmark native commit metadata mismatch".into());
            }
            Ok(commit)
        } else {
            Ok(self.journal.read_entry(entry)?)
        }
    }

    pub fn read(
        &self,
        first: u64,
        limit: usize,
        cut: Option<&Cut>,
    ) -> Result<Vec<AnalysisRecordV1>> {
        let revision = cut.map_or(self.journal.index.revision, |cut| cut.revision);
        let snapshot = self
            .native
            .as_ref()
            .map(|native| match cut.and_then(|cut| cut.native) {
                Some(revision) => native.branch.read_at(revision),
                None => native.branch.snapshot(),
            })
            .transpose()?;
        let key = self.identity.key();
        let start = self
            .journal
            .index
            .ranges
            .range((key.clone(), 0)..=(key.clone(), first))
            .next_back()
            .map_or(first, |((_, cursor), _)| *cursor);
        let mut records = Vec::new();
        for (_, &(id, _)) in self
            .journal
            .index
            .ranges
            .range((key.clone(), start)..=(key, u64::MAX))
        {
            let entry = &self.journal.index.entries[&id];
            if entry.commit.revision > revision {
                continue;
            }
            let commit = self.commit(entry, snapshot.as_ref())?;
            for span in &commit.spans {
                let first = first.max(span.first);
                for cursor in first..=span.last {
                    if records.len() == limit {
                        return Ok(records);
                    }
                    let index = (cursor - span.first) as usize;
                    let start = span.start as usize
                        + if index == 0 {
                            0
                        } else {
                            span.ends[index - 1] as usize
                        };
                    let end = span.start as usize + span.ends[index] as usize;
                    records.push(AnalysisRecordV1 {
                        cursor,
                        framed_record: commit.body[start..end].to_vec(),
                        position: super::StorePositionV1 {
                            commit_revision: commit.revision,
                            ordinal: span.ordinal + index as u32,
                        },
                    });
                    if records.len() == limit {
                        return Ok(records);
                    }
                }
            }
        }
        Ok(records)
    }

    pub fn replay(
        &self,
        cut: &Cut,
        mut visit: impl FnMut(u64, &[u8], super::StorePositionV1) -> Result<()>,
    ) -> Result<u64> {
        let mut records = 0;
        let mut consume = |commit: RawCommit| -> Result<()> {
            for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                visit(
                    cursor,
                    bytes,
                    super::StorePositionV1 {
                        commit_revision: commit.revision,
                        ordinal: ordinal as u32,
                    },
                )?;
                records += 1;
            }
            Ok(())
        };
        if let Some(native) = &self.native {
            let mut feed = native.database.inner().journal_feed(cut.cursor)?;
            let prefix = Self::key(&self.identity, b'p', None);
            while let Some(batch) = feed.next_batch()? {
                for item in batch.items {
                    if item.branch == Some(native.branch.id()) && item.key.starts_with(&prefix) {
                        let value = item.value.ok_or("benchmark journal deletion")?;
                        consume(RawCommit::from_frame(&value, &self.journal.root)?)?;
                    }
                }
            }
        } else {
            for (_, entry) in self.journal.index.entries.range((
                std::ops::Bound::Excluded(cut.revision),
                std::ops::Bound::Unbounded,
            )) {
                consume(self.journal.read_entry(entry)?)?;
            }
        }
        Ok(records)
    }

    pub fn maintain(&mut self) -> Result<serde_json::Value> {
        let started = Instant::now();
        if let Some(native) = &self.native {
            let before = native.database.inner().compactions_completed();
            native.database.inner().flush_memtables()?;
            let flush = started.elapsed().as_secs_f64();
            let compact = Instant::now();
            native.database.inner().major_compact()?;
            Ok(
                serde_json::json!({"flush_s":flush,"major_compact_s":compact.elapsed().as_secs_f64(),
                "background_compactions":native.database.inner().compactions_completed()-before}),
            )
        } else {
            self.journal.seal_all()?;
            Ok(serde_json::json!({"seal_s":started.elapsed().as_secs_f64()}))
        }
    }
}
