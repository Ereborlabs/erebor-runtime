use super :: { super :: { records :: Records , source :: Sources , trace :: Traces } , DataWrite , ExpiredSegment } ;
use crate::analysis::raw::{RawJournal, RawKind, RawReceipt};
use crate::{NativeStateSnafu, Result, StorePositionV1};
use std::collections::{BTreeMap, BTreeSet};

impl DataWrite<'_> {
    pub(super) fn expire_segments(
        &mut self,
        raw: &RawJournal,
        ids: &[u64],
        now: u64,
        removed: &mut u32,
    ) -> Result<Vec<ExpiredSegment>> {
        let mut records = Vec::new();
        let mut sources = BTreeSet::new();
        let mut floors = BTreeMap::<[u8; 16], StorePositionV1>::new();
        for id in ids {
            let segment = raw.segments.get(id).ok_or_else(|| {
                NativeStateSnafu {
                    field: "retention segment",
                }
                .build()
            })?;
            let entries = raw
                .index
                .entries
                .values()
                .filter(|entry| entry.reference.id == *id)
                .collect::<Vec<_>>();
            let first = entries
                .iter()
                .flat_map(|entry| &entry.commit.spans)
                .map(|span| span.first)
                .min()
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "retention segment spans",
                    }
                    .build()
                })?;
            let last = entries
                .iter()
                .flat_map(|entry| &entry.commit.spans)
                .map(|span| span.last)
                .max()
                .unwrap_or(0);
            let intake = entries
                .iter()
                .map(|entry| entry.commit.intake)
                .max()
                .unwrap_or(0);
            let entries = raw
                .segment_entries(*id, first, last, intake, segment.end)?
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            let mut terminal = None;
            for entry in &entries {
                if let RawKind::Diagnostic(progress) = &entry.commit.kind {
                    if progress.terminal {
                        let RawReceipt::Diagnostic(receipt) =
                            &raw.index.sources[&entry.identity.key()].receipt
                        else {
                            return NativeStateSnafu {
                                field: "retention trace receipt",
                            }
                            .fail();
                        };
                        terminal = receipt.terminal.clone();
                    }
                }
                for span in &entry.commit.spans {
                    let count = u32::try_from(span.last - span.first + 1).map_err(|_| {
                        NativeStateSnafu {
                            field: "expired record count",
                        }
                        .build()
                    })?;
                    *removed = removed.checked_add(count).ok_or_else(|| {
                        NativeStateSnafu {
                            field: "expired record count",
                        }
                        .build()
                    })?;
                    self.expiry
                        .push((*id, entry.identity.key(), span.first, span.last));
                    let position = StorePositionV1 {
                        commit_revision: entry.commit.revision,
                        ordinal: span.ordinal.checked_add(count - 1).ok_or_else(|| {
                            NativeStateSnafu {
                                field: "expired record position",
                            }
                            .build()
                        })?,
                    };
                    floors
                        .entry(entry.identity.tenant())
                        .and_modify(|floor| *floor = (*floor).max(position))
                        .or_insert(position);
                }
                sources.insert(entry.identity.key());
            }
            let record = ExpiredSegment {
                id: *id,
                end: segment.end,
                revision: self.revision,
                time: now,
                entries,
                terminal,
            };
            Records::stage(
                &mut self.transaction,
                ExpiredSegment::key(ExpiredSegment::PREFIX, *id),
                Records::encode(&record)?,
            );
            self.transaction.insert(
                ExpiredSegment::key(ExpiredSegment::DELETING, *id),
                self.revision.to_be_bytes(),
            );
            self.transaction
                .remove(Sources::key(Sources::ENDS, &id.to_be_bytes()));
            self.raw.expired.insert_mut(*id, crate::analysis::raw::RawExpiry {
                revision: self.revision, identity: record.entries[0].identity.clone(),
            });
            records.push(record);
        }
        for key in sources {
            let accepted = self.raw.sources[&key].receipt.cursor();
            let floor = self
                .raw
                .ranges
                .range((key.clone(), 0)..=(key.clone(), accepted))
                .filter_map(|((_, first), (revision, _))| {
                    (!self
                        .raw
                        .expired
                        .contains_key(&self.raw.entries[revision].reference.id))
                    .then_some(first.saturating_sub(1))
                })
                .min()
                .unwrap_or(accepted);
            let source = self.raw.sources.get_mut(&key).ok_or_else(|| {
                NativeStateSnafu {
                    field: "expired source receipt",
                }
                .build()
            })?;
            source.receipt.set_floor(source.receipt.floor().max(floor));
            match &source.receipt {
                RawReceipt::Evidence(receipt) => {
                    Records::stage(
                        &mut self.transaction,
                        Sources::key(Sources::RECEIPTS, &key),
                        Records::encode(receipt)?,
                    );
                    self.note_relation("events", self.revision)?;
                    self.note_relation("source_receipts", self.revision)?;
                }
                RawReceipt::Diagnostic(receipt) => {
                    Records::stage(
                        &mut self.transaction,
                        Traces::receipt_key(&receipt.identity),
                        Records::encode(receipt)?,
                    );
                    self.note_relation("trace_output", self.revision)?;
                    self.note_relation("trace_receipts", self.revision)?;
                }
            }
        }
        for (tenant, floor) in floors {
            let key = [ExpiredSegment::FLOOR, &tenant].concat();
            let prior: Option<StorePositionV1> =
                Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                    .map(|bytes| Records::decode(&bytes))
                    .transpose()?;
            if prior.is_none_or(|prior| floor > prior) {
                Records::stage(&mut self.transaction, key, Records::encode(&floor)?);
            }
        }
        self.note_relation("expired_ranges", self.revision)?;
        self.note_relation("replay_floors", self.revision)?;
        self.dirty = true;
        Ok(records)
    }
}
