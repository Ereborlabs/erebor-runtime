use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::analysis::native::progress::Processor;
use crate::ProcessorClassV1;

impl Events<'_> {
    pub(in crate::analysis::native) fn required(
        &self,
    ) -> Result<BTreeMap<Vec<u8>, (EvidenceIntakeIdentityV1, u64)>> {
        let mut required: BTreeMap<Vec<u8>, (EvidenceIntakeIdentityV1, u64)> = BTreeMap::new();
        for row in self.view.snapshot.prefix(Processor::PREFIX) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read required evidence owners",
            })?;
            if key.len() != Processor::PREFIX.len() + 8 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.view.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "required evidence owner",
                    }
                    .build()
                })?;
            let state: Processor = Records::decode(&bytes)?;
            if state.class != ProcessorClassV1::Required || state.retirement.is_some() {
                continue;
            }
            if !state.scope.valid() || state.revision > self.view.metadata_revision {
                return NativeStateSnafu {
                    field: "required evidence scope",
                }
                .fail();
            }
            required
                .entry(state.scope.identity.key())
                .and_modify(|(_, cursor)| *cursor = (*cursor).min(state.consumed))
                .or_insert((state.scope.identity, state.consumed));
        }
        Ok(required)
    }

    fn bytes_after(&self, batch: &EventBatch, after: u64, root: &Path) -> Result<u64> {
        let mut bytes = 0_u64;
        let mut commit = None;
        for (slot, span) in batch.meta.spans.iter().enumerate() {
            if span.last <= after {
                continue;
            }
            let added = if span.first > after {
                u64::from(span.bytes)
            } else {
                if commit.is_none() {
                    commit = Some(self.payload(batch, root)?.1);
                }
                let span = &commit
                    .as_ref()
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "protected evidence payload",
                        }
                        .build()
                    })?
                    .spans[slot];
                u64::from(
                    *span.ends.last().unwrap_or(&0) - span.ends[(after - span.first) as usize],
                )
            };
            bytes = bytes.checked_add(added).ok_or_else(|| {
                NativeStateSnafu {
                    field: "protected evidence bytes",
                }
                .build()
            })?;
        }
        Ok(bytes)
    }
}

impl DataWrite<'_> {
    pub(super) fn evidence_capacity(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        input: &RawCommit,
    ) -> Result<()> {
        let limits = self.store.retention;
        if limits.raw_max_age_ns.is_none() && limits.raw_max_bytes.is_none() {
            return Ok(());
        }
        let view = self.store.view()?;
        let events = Events::new(&view);
        let required = events.required()?;
        if !required.contains_key(&identity.key()) {
            return Ok(());
        }
        let mut total = 0_u64;
        let mut oldest = None;
        for (key, (source, cursor)) in required {
            if source.tenant_id != identity.tenant_id {
                continue;
            }
            let Some(first) = cursor.checked_add(1) else {
                continue;
            };
            let mut seen = BTreeSet::new();
            for row in events.spans(&source, first, u64::MAX)? {
                let (span_key, value) = row.context(NativeStorageSnafu {
                    operation: "read protected evidence spans",
                })?;
                let (span_first, span) = Events::decode_span(&source, &span_key, &value)?;
                if span.last < first || !seen.insert(span.revision) {
                    continue;
                }
                let (batch, _) = events.lookup(&source, span_first)?.ok_or_else(|| {
                    NativeStateSnafu {
                        field: "protected evidence index",
                    }
                    .build()
                })?;
                if events.expiry(batch.meta.revision)?.is_some() {
                    continue;
                }
                total = total
                    .checked_add(events.bytes_after(&batch, cursor, &self.store.root)?)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "protected evidence total",
                        }
                        .build()
                    })?;
                if key == identity.key() {
                    oldest = Some(
                        oldest.map_or(batch.meta.intake, |prior: u64| prior.min(batch.meta.intake)),
                    );
                }
            }
        }
        if limits.raw_max_age_ns.is_some_and(|age| {
            oldest.is_some_and(|oldest| input.intake.saturating_sub(oldest) >= age)
        }) {
            return crate::ProtectedInputCapacitySnafu { resource: "age" }.fail();
        }
        if limits.raw_max_bytes.is_some_and(|limit| {
            total
                .checked_add(input.body.len() as u64)
                .is_none_or(|bytes| bytes > limit)
        }) {
            return crate::ProtectedInputCapacitySnafu { resource: "bytes" }.fail();
        }
        Ok(())
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn expire_events(
        &mut self,
        ids: &[u64],
        now: u64,
        removed: &mut u32,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let view = self.store.view()?;
        let events = Events::new(&view);
        let mut sources = BTreeMap::new();
        let mut floors = BTreeMap::<[u8; 16], crate::StorePositionV1>::new();
        for id in ids {
            let batch = events.batch(*id)?;
            if events.expiry(*id)?.is_some() {
                return NativeStateSnafu {
                    field: "evidence already expired",
                }
                .fail();
            }
            let expiry = EventExpiry {
                revision: self.revision,
                now,
            };
            Records::stage(
                &mut self.transaction,
                Events::position(Events::EXPIRED, *id),
                Records::encode(&expiry)?,
            );
            self.transaction
                .remove(Events::key(Events::PAYLOAD, &batch.source, batch.first));
            for span in &batch.meta.spans {
                let count = u32::try_from(span.last - span.first + 1).map_err(|_| {
                    NativeStateSnafu {
                        field: "expired evidence count",
                    }
                    .build()
                })?;
                *removed = removed.checked_add(count).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "expired evidence total",
                    }
                    .build()
                })?;
                let position = crate::StorePositionV1 {
                    commit_revision: *id,
                    ordinal: span.ordinal.checked_add(count - 1).ok_or_else(|| {
                        NativeStateSnafu {
                            field: "expired evidence position",
                        }
                        .build()
                    })?,
                };
                floors
                    .entry(batch.source.tenant_id)
                    .and_modify(|floor| *floor = (*floor).max(position))
                    .or_insert(position);
            }
            sources.insert(batch.source.key(), batch.source);
        }
        for (key, source) in sources {
            let mut receipt = view.source_receipt(&source)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "expired evidence receipt",
                }
                .build()
            })?;
            let mut floor = receipt.contiguous_cursor;
            for row in events.spans(&source, 0, receipt.contiguous_cursor)? {
                let (span_key, value) = row.context(NativeStorageSnafu {
                    operation: "find retained evidence floor",
                })?;
                let (first, index) = Events::decode_span(&source, &span_key, &value)?;
                if Records::staged(
                    &Events::position(Events::EXPIRED, index.revision),
                    &self.transaction,
                )?
                .is_none()
                {
                    floor = floor.min(first.saturating_sub(1));
                    break;
                }
            }
            receipt.retained_floor = receipt.retained_floor.max(floor);
            Records::stage(
                &mut self.transaction,
                super::super::source::Sources::key(super::super::source::Sources::RECEIPTS, &key),
                Records::encode(&receipt)?,
            );
        }
        for (tenant, floor) in floors {
            self.advance_replay_floor(tenant, floor)?;
        }
        self.note_relation("events", self.revision)?;
        self.note_relation("source_receipts", self.revision)?;
        self.note_relation("expired_ranges", self.revision)?;
        self.note_relation("replay_floors", self.revision)?;
        self.dirty = true;
        Ok(())
    }
}
