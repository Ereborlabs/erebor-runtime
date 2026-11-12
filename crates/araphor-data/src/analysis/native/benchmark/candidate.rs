use std::path::{Path, PathBuf};

use prost::Message as _;

use super::{Cut, Result};
use crate::analysis::raw::{RawCommit, RawKind, RawSpan};
use crate::{
    AnalysisRecordV1, AnalysisSourceReceiptV1, EvidenceIntakeIdentityV1, StorePositionV1,
    ValidatedEvidenceBatchV1,
};

const RECEIPT: &[u8] = b"input/receipt/";
const EPOCH: &[u8] = b"input/epoch/";
const PAYLOAD: &[u8] = b"input/events/";

pub(super) struct Candidate {
    pub branch: fjall::Branch,
    pub database: fjall::SingleWriterTxDatabase,
    source: EvidenceIntakeIdentityV1,
    root: PathBuf,
}

impl Candidate {
    pub fn open(root: &Path, source: EvidenceIntakeIdentityV1) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
            .versioned()
            .open()?;
        let branch = match database.branch("data")? {
            Some(branch) => branch,
            None => {
                let branch = database.create_branch("data")?;
                branch.retain_history(branch.info()?.head..)?;
                branch
            }
        };
        Ok(Self {
            branch,
            database,
            source,
            root: root.to_path_buf(),
        })
    }

    pub fn key(&self, cursor: Option<u64>) -> Vec<u8> {
        let mut key = [PAYLOAD, &self.source.key()].concat();
        if let Some(cursor) = cursor {
            key.extend(cursor.to_be_bytes());
        }
        key
    }

    fn receipt_key(&self) -> Vec<u8> {
        [RECEIPT, &self.source.key()].concat()
    }

    fn head(bytes: Option<fjall::Slice>) -> Result<u64> {
        Ok(bytes
            .map(|bytes| bytes.as_ref().try_into().map(u64::from_be_bytes))
            .transpose()?
            .unwrap_or(0))
    }

    pub fn cut(&self) -> Result<(u64, u64, fjall::BranchSnapshot)> {
        let snapshot = self.branch.snapshot()?;
        let revision = Self::head(snapshot.get(super::super::HEAD)?)?;
        let receipt = snapshot
            .get(self.receipt_key())?
            .map(|bytes| rmp_serde::from_slice::<AnalysisSourceReceiptV1>(&bytes))
            .transpose()?;
        Ok((
            revision,
            receipt.map_or(0, |receipt| receipt.contiguous_cursor),
            snapshot,
        ))
    }

    pub fn append(&mut self, batch: ValidatedEvidenceBatchV1) -> Result<()> {
        batch.validate_identity(&self.source, &self.root)?;
        let mut tx = self.branch.write_tx()?;
        let receipt = tx
            .get(self.receipt_key())?
            .map(|bytes| rmp_serde::from_slice::<AnalysisSourceReceiptV1>(&bytes))
            .transpose()?;
        if receipt.as_ref().is_some_and(|receipt| {
            receipt.identity != self.source || receipt.cpu_id != batch.cpu_id
        }) || batch.first_cursor
            != receipt
                .as_ref()
                .map_or(0, |receipt| receipt.contiguous_cursor)
                + 1
        {
            return Err(
                "native benchmark requires contiguous input from the same source and CPU".into(),
            );
        }
        let epoch = [EPOCH, &self.source.epoch_key()].concat();
        if let Some(bytes) = tx.get(&epoch)? {
            if rmp_serde::from_slice::<EvidenceIntakeIdentityV1>(&bytes)? != self.source {
                return Err("native benchmark source epoch conflict".into());
            }
        }
        let revision = Self::head(tx.get(super::super::HEAD)?)? + 1;
        let commit = RawCommit {
            revision,
            kind: Some(RawKind::Evidence(batch.cpu_id)),
            intake: batch.intake_utc_ns,
            spans: vec![RawSpan {
                first: batch.first_cursor,
                last: batch.last_cursor,
                start: 0,
                ends: batch
                    .frame_ends
                    .iter()
                    .map(|end| u32::try_from(*end))
                    .collect::<std::result::Result<_, _>>()?,
                ordinal: 0,
            }],
            body: batch.framed_records,
        };
        commit.validate(&self.root)?;
        let mut frame = Vec::with_capacity(commit.encoded_len() + 8);
        frame.extend(u32::try_from(commit.encoded_len())?.to_be_bytes());
        commit.encode(&mut frame)?;
        frame.extend(crc32c::crc32c(&frame).to_be_bytes());
        tx.insert(self.key(Some(batch.first_cursor)), frame);
        tx.insert(
            self.receipt_key(),
            rmp_serde::to_vec(&AnalysisSourceReceiptV1 {
                identity: self.source.clone(),
                cpu_id: batch.cpu_id,
                contiguous_cursor: batch.last_cursor,
                coverage_revision: 0,
                retained_floor: 0,
            })?,
        );
        tx.insert(epoch, rmp_serde::to_vec(&self.source)?);
        for key in [
            super::super::HEAD,
            b"input/heads/events",
            b"input/heads/source_receipts",
        ] {
            tx.insert(key, revision.to_be_bytes());
        }
        if receipt.is_none() {
            tx.insert(b"input/heads/source_bindings", revision.to_be_bytes());
        }
        tx.commit()?.ok_or("missing native input commit")?;
        Ok(())
    }

    pub fn decode(&self, key: &[u8], bytes: &[u8]) -> Result<RawCommit> {
        let commit = RawCommit::from_frame(bytes, &self.root)?;
        if key != self.key(Some(commit.spans[0].first)) {
            return Err("native benchmark source/cursor reference mismatch".into());
        }
        Ok(commit)
    }

    pub fn read(&self, first: u64, cut: Option<&Cut>) -> Result<Vec<AnalysisRecordV1>> {
        let snapshot = match cut {
            Some(cut) => self
                .branch
                .read_at(fjall::Revision::from_bytes(cut.native))?,
            None => self.branch.snapshot()?,
        };
        let lower = self.key(Some(0));
        let target = self.key(Some(first));
        let upper = self.key(Some(u64::MAX));
        let predecessor = snapshot
            .range(lower.clone()..=target.clone())
            .next_back()
            .transpose()?;
        let start = predecessor.as_ref().map_or(target, |(key, _)| key.to_vec());
        let mut records = Vec::new();
        let remaining = snapshot.range((
            std::ops::Bound::Excluded(start),
            std::ops::Bound::Included(upper),
        ));
        for row in predecessor.into_iter().map(Ok).chain(remaining) {
            let (key, value) = row?;
            let commit = self.decode(&key, &value)?;
            for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                if cursor < first {
                    continue;
                }
                records.push(AnalysisRecordV1 {
                    cursor,
                    framed_record: bytes.to_vec(),
                    position: StorePositionV1 {
                        commit_revision: commit.revision,
                        ordinal: ordinal as u32,
                    },
                });
                if records.len() == crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                    return Ok(records);
                }
            }
        }
        Ok(records)
    }

    pub fn scan(
        &self,
        cut: Option<&Cut>,
        mut visit: impl FnMut(Vec<AnalysisRecordV1>) -> Result<()>,
    ) -> Result<()> {
        let snapshot = match cut {
            Some(cut) => self
                .branch
                .read_at(fjall::Revision::from_bytes(cut.native))?,
            None => self.branch.snapshot()?,
        };
        let mut records = Vec::new();
        for row in snapshot.prefix(self.key(None)) {
            let (key, bytes) = row?;
            let commit = self.decode(&key, &bytes)?;
            for (ordinal, (cursor, bytes)) in commit.records().enumerate() {
                records.push(AnalysisRecordV1 {
                    cursor,
                    framed_record: bytes.to_vec(),
                    position: StorePositionV1 {
                        commit_revision: commit.revision,
                        ordinal: ordinal as u32,
                    },
                });
                if records.len() == crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                    visit(std::mem::take(&mut records))?;
                }
            }
        }
        if !records.is_empty() {
            visit(records)?;
        }
        Ok(())
    }
}
