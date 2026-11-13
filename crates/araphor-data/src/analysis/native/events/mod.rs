use std::path::Path;

use fjall::{BranchIterator, BranchSnapshot};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{records::Records, DataView, DataWrite, NativeStore};
use crate::analysis::raw::{RawCommit, RawKind, RawMeta};
use crate::{EvidenceIntakeIdentityV1, NativeStateSnafu, NativeStorageSnafu, Result};

mod intake;
mod read;
mod recovery;
mod retention;

pub(in crate::analysis) use read::EventRead;

pub(super) struct Events<'a> {
    view: &'a DataView,
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct EventBatch {
    pub source: EvidenceIntakeIdentityV1,
    pub first: u64,
    pub meta: RawMeta,
    pub bytes: usize,
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct EventSpan {
    pub last: u64,
    pub batch: u64,
    pub revision: u64,
    pub slot: usize,
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct EventExpiry {
    pub revision: u64,
    pub now: u64,
}

impl<'a> Events<'a> {
    pub(super) const PAYLOAD: &'static [u8] = b"\0data/evidence/payload/";
    pub(super) const SPANS: &'static [u8] = b"\0data/evidence/span/";
    pub(super) const POSITION: &'static [u8] = b"\0data/evidence/position/";
    pub(super) const EXPIRED: &'static [u8] = b"\0data/evidence/expired/";

    pub(super) fn new(view: &'a DataView) -> Self {
        Self { view }
    }

    pub(super) fn source_key(prefix: &[u8], source: &EvidenceIntakeIdentityV1) -> Vec<u8> {
        [prefix, &source.key()].concat()
    }

    pub(super) fn key(prefix: &[u8], source: &EvidenceIntakeIdentityV1, first: u64) -> Vec<u8> {
        [prefix, &source.key(), &first.to_be_bytes()].concat()
    }

    pub(super) fn position(prefix: &[u8], revision: u64) -> Vec<u8> {
        [prefix, &revision.to_be_bytes()].concat()
    }

    pub(super) fn row<T: serde::de::DeserializeOwned>(
        snapshot: &BranchSnapshot,
        key: &[u8],
    ) -> Result<Option<T>> {
        Records::payload(key, |key| Records::read(key, snapshot))?
            .map(|bytes| Records::decode(&bytes))
            .transpose()
    }

    pub(super) fn batch(&self, revision: u64) -> Result<EventBatch> {
        if revision > self.view.metadata_revision {
            return NativeStateSnafu {
                field: "evidence batch revision",
            }
            .fail();
        }
        let row: EventBatch = Self::row(
            &self.view.snapshot,
            &Self::position(Self::POSITION, revision),
        )?
        .ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence position index",
            }
            .build()
        })?;
        row.check(revision)?;
        Ok(row)
    }

    pub(super) fn expiry(&self, revision: u64) -> Result<Option<EventExpiry>> {
        let expiry: Option<EventExpiry> = Self::row(
            &self.view.snapshot,
            &Self::position(Self::EXPIRED, revision),
        )?;
        if expiry.as_ref().is_some_and(|expiry| {
            expiry.revision <= revision
                || expiry.revision > self.view.metadata_revision
                || expiry.now == 0
        }) {
            return NativeStateSnafu {
                field: "evidence expiry revision",
            }
            .fail();
        }
        Ok(expiry)
    }

    pub(super) fn batches(&self, after: u64) -> BranchIterator {
        if after > self.view.metadata_revision {
            let key = Self::position(Self::POSITION, after);
            return self.view.snapshot.range(key.clone()..key);
        }
        self.view.snapshot.range(
            Self::position(Self::POSITION, after)
                ..=Self::position(Self::POSITION, self.view.metadata_revision),
        )
    }

    pub(super) fn decode_batch(&self, key: &[u8], value: &[u8]) -> Result<EventBatch> {
        let revision = key.strip_prefix(Self::POSITION).ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence position key",
            }
            .build()
        })?;
        let revision = NativeStore::number(revision)?;
        if revision > self.view.metadata_revision {
            return NativeStateSnafu {
                field: "evidence index revision",
            }
            .fail();
        }
        let value = value.strip_prefix(&[0]).ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence position value",
            }
            .build()
        })?;
        let row: EventBatch = Records::decode(value)?;
        row.check(revision)?;
        Ok(row)
    }

    pub(super) fn bytes(&self, batch: &EventBatch) -> Result<fjall::Slice> {
        let bytes = self
            .view
            .snapshot
            .get(Self::key(Self::PAYLOAD, &batch.source, batch.first))
            .context(NativeStorageSnafu {
                operation: "read native evidence payload",
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "native evidence payload",
                }
                .build()
            })?;
        Ok(bytes)
    }

    pub(super) fn payload(
        &self,
        batch: &EventBatch,
        root: &Path,
    ) -> Result<(fjall::Slice, RawCommit)> {
        let bytes = self.bytes(batch)?;
        let commit = batch.decode(&bytes, root)?;
        Ok((bytes, commit))
    }

    pub(super) fn spans(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
    ) -> Result<BranchIterator> {
        let target = Self::key(Self::SPANS, source, first);
        let start = self
            .view
            .snapshot
            .range(Self::source_key(Self::SPANS, source)..=target.clone())
            .next_back()
            .transpose()
            .context(NativeStorageSnafu {
                operation: "locate first evidence span",
            })?;
        let start = start.map_or(target, |(key, _)| key.to_vec());
        Ok(self
            .view
            .snapshot
            .range(start..=Self::key(Self::SPANS, source, last)))
    }

    pub(super) fn lookup(
        &self,
        source: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> Result<Option<(EventBatch, usize)>> {
        let row = self
            .view
            .snapshot
            .range(Self::source_key(Self::SPANS, source)..=Self::key(Self::SPANS, source, cursor))
            .next_back()
            .transpose()
            .context(NativeStorageSnafu {
                operation: "locate native evidence span",
            })?;
        let Some((key, value)) = row else {
            return Ok(None);
        };
        let (first, span) = Self::decode_span(source, &key, &value)?;
        if span.revision > self.view.metadata_revision {
            return NativeStateSnafu {
                field: "evidence span bounds",
            }
            .fail();
        }
        if span.last < cursor {
            return Ok(None);
        }
        let batch = self.batch(span.revision)?;
        batch.check_span(source, first, &span)?;
        Ok(Some((batch, span.slot)))
    }

    pub(super) fn decode_span(
        source: &EvidenceIntakeIdentityV1,
        key: &[u8],
        value: &[u8],
    ) -> Result<(u64, EventSpan)> {
        let prefix = Self::source_key(Self::SPANS, source);
        let suffix = key.strip_prefix(prefix.as_slice()).ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence span source",
            }
            .build()
        })?;
        let first = NativeStore::number(suffix)?;
        let span: EventSpan = Records::decode(value.strip_prefix(&[0]).ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence span value",
            }
            .build()
        })?)?;
        if first == 0 || first > span.last || span.revision == 0 || span.batch == 0 {
            return NativeStateSnafu {
                field: "evidence span bounds",
            }
            .fail();
        }
        Ok((first, span))
    }
}

impl EventBatch {
    pub(super) fn check(&self, revision: u64) -> Result<()> {
        if !self.source.valid()
            || self.meta.revision != revision
            || revision == 0
            || self.bytes < 8
            || !matches!(self.meta.kind, RawKind::Evidence(_))
            || self.meta.intake == 0
            || self
                .meta
                .spans
                .first()
                .is_none_or(|span| span.first != self.first)
        {
            return NativeStateSnafu {
                field: "evidence batch header",
            }
            .fail();
        }
        let mut ordinal = 0_u64;
        let mut end = 0_u32;
        let mut last = 0;
        for span in &self.meta.spans {
            if span.first == 0
                || span.first <= last
                || span.last < span.first
                || span.start != end
                || u64::from(span.ordinal) != ordinal
                || span.bytes == 0
            {
                return NativeStateSnafu {
                    field: "evidence metadata span",
                }
                .fail();
            }
            ordinal = ordinal
                .checked_add(span.last - span.first + 1)
                .filter(|count| *count <= u64::from(u32::MAX) + 1)
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "evidence metadata ordinal",
                    }
                    .build()
                })?;
            end = end.checked_add(span.bytes).ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence metadata bytes",
                }
                .build()
            })?;
            last = span.last;
        }
        if end as usize > self.bytes - 8 || ordinal > u64::from(end) {
            return NativeStateSnafu {
                field: "evidence metadata body",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn check_span(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        span: &EventSpan,
    ) -> Result<()> {
        self.check(span.revision)?;
        let accepted = self.meta.spans.get(span.slot).ok_or_else(|| {
            NativeStateSnafu {
                field: "evidence span slot",
            }
            .build()
        })?;
        if self.source != *source
            || self.first != span.batch
            || accepted.first != first
            || accepted.last != span.last
        {
            return NativeStateSnafu {
                field: "evidence span binding",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn decode(&self, bytes: &[u8], root: &Path) -> Result<RawCommit> {
        let commit = RawCommit::from_frame(bytes, root)?;
        self.check_commit(&commit, bytes.len())?;
        Ok(commit)
    }

    pub(super) fn check_commit(&self, commit: &RawCommit, bytes: usize) -> Result<()> {
        let meta = RawMeta::try_from(commit)?;
        if bytes != self.bytes
            || meta.revision != self.meta.revision
            || meta.kind != self.meta.kind
            || meta.intake != self.meta.intake
            || meta.spans != self.meta.spans
        {
            return NativeStateSnafu {
                field: "evidence payload binding",
            }
            .fail();
        }
        Ok(())
    }
}
