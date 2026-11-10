use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super :: { super :: { inputs :: InputRecord , managed :: References , records :: Records } , DataWrite , EvidenceRetentionOwner } ;
use crate :: analysis :: { inputs :: InputInterest , raw :: { RawIdentity , RawJournal } } ;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

pub(super) struct Selection {
    pub ids: Vec<u64>,
    pub more: bool,
    pub deadline: Option<u64>,
}

struct Candidate {
    id: u64,
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
        let required = &raw.budget.required;
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
                protected.insert(segment);
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
                    protected.insert(entry.reference.id);
                }
            }
        }
        let mut pins = BTreeMap::<u64, u64>::new();
        for entry in tx.transaction.prefix(References::SEGMENT) {
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "read retention witness pins",
            })?;
            if key.len() != References::SEGMENT.len() + 24 {
                return NativeStateSnafu {
                    field: "segment witness key",
                }
                .fail();
            }
            let id = super::super::NativeStore::number(
                &key[References::SEGMENT.len()..References::SEGMENT.len() + 8],
            )?;
            let expires = super::super::NativeStore::number(&value)?;
            pins.entry(id)
                .and_modify(|expiry| *expiry = (*expiry).max(expires))
                .or_insert(expires);
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
                    id: entry.reference.id,
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
        candidates.sort_by_key(|candidate| (candidate.intake, candidate.id));
        let mut prior = BTreeMap::<[u8; 16], u128>::new();
        let mut result = Selection {
            ids: Vec::new(),
            more: false,
            deadline: None,
        };
        for candidate in candidates {
            if source.is_some_and(|source| source.key() != candidate.source)
                || protected.contains(&candidate.id)
            {
                continue;
            }
            let accepted = raw
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
                .cursor();
            if candidate.last
                > required
                    .get(&candidate.source)
                    .copied()
                    .unwrap_or(accepted)
                    .min(accepted)
            {
                continue;
            }
            let pin = pins.get(&candidate.id).copied().unwrap_or(0);
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
                if result.ids.len() < 16 {
                    result.ids.push(candidate.id);
                } else {
                    result.more = true;
                }
            }
        }
        Ok(result)
    }
}
