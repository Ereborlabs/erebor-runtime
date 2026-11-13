use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super::{
    super::{
        inputs::InputRecord,
        managed::{PinTarget, References},
        records::Records,
    },
    DataWrite, EvidenceRetentionOwner,
};
use crate::analysis::{
    inputs::InputInterest,
    raw::{RawIdentity, RawJournal},
};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

pub(super) struct Selection {
    pub ids: Vec<u64>,
    pub batches: Vec<u64>,
    pub more: bool,
    pub deadline: Option<u64>,
}

struct Candidate {
    target: PinTarget,
    source: Vec<u8>,
    tenant: [u8; 16],
    bytes: u64,
    last: u64,
    intake: u64,
}

impl EvidenceRetentionOwner<'_> {
    pub(super) fn select(
        &self,
        tx: &DataWrite<'_>,
        raw: &RawJournal,
        now: u64,
        source: Option<&RawIdentity>,
    ) -> Result<Selection> {
        let view = self.store.view()?;
        let events = super::super::events::Events::new(&view);
        let required = events.required()?;
        let mut interests = Vec::new();
        let mut protected = BTreeSet::new();
        for entry in tx.transaction.prefix(InputRecord::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read retained input cursors",
            })?;
            if key.len() != InputRecord::PREFIX.len() + 16 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &tx.transaction))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "retained input cursor",
                    }
                    .build()
                })?;
            let record: InputRecord = Records::decode(&bytes)?;
            if let Some((_, segment, _)) = record.cut.raw {
                protected.insert(PinTarget::Segment(segment));
            }
            let interest = InputInterest::new(
                record.interest.selection,
                record.interest.requests,
                record.interest.owners,
            )?;
            for entry in raw.index.entries.values() {
                if raw.index.expired.contains_key(&entry.reference.id) {
                    continue;
                }
                if entry.commit.spans.iter().any(|span| {
                    interest
                        .raw_position(entry, span)
                        .is_some_and(|position| position > record.completed_through)
                }) {
                    protected.insert(PinTarget::Segment(entry.reference.id));
                }
            }
            interests.push((interest, record.completed_through));
        }
        let mut pins = BTreeMap::<PinTarget, u64>::new();
        for (prefix, native) in [(References::SEGMENT, false), (References::BATCH, true)] {
            for entry in tx.transaction.prefix(prefix) {
                let (key, value) = entry.context(NativeStorageSnafu {
                    operation: "read retention witness pins",
                })?;
                if key.len() != prefix.len() + 24 {
                    return NativeStateSnafu {
                        field: "retention witness key",
                    }
                    .fail();
                }
                let id = super::super::NativeStore::number(&key[prefix.len()..prefix.len() + 8])?;
                let target = if native {
                    PinTarget::Evidence(id)
                } else {
                    PinTarget::Segment(id)
                };
                let expires = super::super::NativeStore::number(&value)?;
                pins.entry(target)
                    .and_modify(|expiry| *expiry = (*expiry).max(expires))
                    .or_insert(expires);
            }
        }
        let mut candidates = BTreeMap::<u64, Candidate>::new();
        let mut totals = BTreeMap::<[u8; 16], u128>::new();
        for entry in raw.index.entries.values() {
            let Some(segment) = raw.segments.get(&entry.reference.id) else {
                continue;
            };
            let candidate = candidates.entry(entry.reference.id).or_insert_with(|| {
                *totals.entry(entry.identity.tenant()).or_default() += segment.end as u128;
                Candidate {
                    target: PinTarget::Segment(entry.reference.id),
                    source: entry.identity.key(),
                    tenant: entry.identity.tenant(),
                    bytes: segment.end,
                    last: 0,
                    intake: 0,
                }
            });
            candidate.intake = candidate.intake.max(entry.commit.intake);
            candidate.last = candidate.last.max(
                entry
                    .commit
                    .spans
                    .iter()
                    .map(|span| span.last)
                    .max()
                    .unwrap_or(0),
            );
        }
        let mut candidates = candidates.into_values().collect::<Vec<_>>();
        for row in events.batches(0) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "select retained evidence batches",
            })?;
            let batch = events.decode_batch(&key, &value)?;
            if events.expiry(batch.meta.revision)?.is_some() {
                continue;
            }
            let target = PinTarget::Evidence(batch.meta.revision);
            let identity = batch.source.clone().into();
            if interests.iter().any(|(interest, completed)| {
                batch.meta.spans.iter().any(|span| {
                    interest
                        .raw_span(&identity, &batch.meta, span)
                        .is_some_and(|position| position > *completed)
                })
            }) {
                protected.insert(target);
            }
            *totals.entry(batch.source.tenant_id).or_default() += batch.bytes as u128;
            candidates.push(Candidate {
                target,
                source: batch.source.key(),
                tenant: batch.source.tenant_id,
                bytes: batch.bytes as u64,
                last: batch.meta.spans.last().map_or(0, |span| span.last),
                intake: batch.meta.intake,
            });
        }
        candidates.sort_by_key(|candidate| (candidate.intake, candidate.target));
        let mut prior = BTreeMap::<[u8; 16], u128>::new();
        let mut result = Selection {
            ids: Vec::new(),
            batches: Vec::new(),
            more: false,
            deadline: None,
        };
        for candidate in candidates {
            if source.is_some_and(|source| source.key() != candidate.source)
                || protected.contains(&candidate.target)
            {
                continue;
            }
            let accepted = match candidate.target {
                PinTarget::Evidence(id) => {
                    let batch = events.batch(id)?;
                    view.source_receipt(&batch.source)?
                        .ok_or_else(|| {
                            NativeStateSnafu {
                                field: "retention evidence source",
                            }
                            .build()
                        })?
                        .contiguous_cursor
                }
                PinTarget::Segment(_) => raw
                    .index
                    .sources
                    .get(&candidate.source)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "retention source",
                        }
                        .build()
                    })?
                    .receipt
                    .cursor(),
            };
            if candidate.last
                > required
                    .get(&candidate.source)
                    .map_or(accepted, |(_, cursor)| *cursor)
                    .min(accepted)
            {
                continue;
            }
            let pin = pins.get(&candidate.target).copied().unwrap_or(0);
            let total = totals[&candidate.tenant];
            let over = self
                .store
                .retention
                .raw_max_bytes
                .is_some_and(|limit| total > limit as u128);
            let due = if over {
                Some(pin as u128)
            } else {
                self.store
                    .retention
                    .raw_max_age_ns
                    .map(|age| (candidate.intake as u128 + age as u128).max(pin as u128))
            };
            if let Some(due) = due.filter(|due| *due > now as u128 && *due <= u64::MAX as u128) {
                result.deadline = Some(
                    result
                        .deadline
                        .map_or(due as u64, |old| old.min(due as u64)),
                );
            }
            if pin > now {
                continue;
            }
            let before = prior.entry(candidate.tenant).or_default();
            let selected = self
                .store
                .retention
                .raw_max_age_ns
                .is_some_and(|age| candidate.intake as u128 + age as u128 <= now as u128)
                || self
                    .store
                    .retention
                    .raw_max_bytes
                    .is_some_and(|limit| total - *before > limit as u128);
            *before += candidate.bytes as u128;
            if selected {
                if result.ids.len() + result.batches.len() < 16 {
                    match candidate.target {
                        PinTarget::Evidence(id) => result.batches.push(id),
                        PinTarget::Segment(id) => result.ids.push(id),
                    }
                } else {
                    result.more = true;
                }
            }
        }
        Ok(result)
    }
}
