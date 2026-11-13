use super::*;
use crate::analysis::native::source::Sources;
use crate::analysis::raw::RawSpan;
use crate::{AnalysisSourceReceiptV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1};

impl NativeStore {
    pub(in crate::analysis::native) fn accept_events(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        batch.validate_identity(&identity, &self.root)?;
        if batch.intake_utc_ns == 0 {
            return crate::Error::reject_path(&self.root, "live evidence has no intake time");
        }
        let mut tx = self.write()?;
        let outcome = tx.evidence_batch(&identity, &batch)?;
        tx.commit([])?;
        Ok(outcome)
    }
}

impl DataWrite<'_> {
    fn evidence_batch(
        &mut self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        let view = self.store.view()?;
        let events = Events::new(&view);
        let previous = view.source_receipt(identity)?;
        if previous
            .as_ref()
            .is_some_and(|receipt| receipt.cpu_id != batch.cpu_id)
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let epoch = Sources::key(Sources::EPOCHS, &identity.epoch_key());
        if let Some(saved) = Events::row::<EvidenceIntakeIdentityV1>(&view.snapshot, &epoch)? {
            Sources::check_epoch(identity, &saved)?;
        }
        let floor = previous
            .as_ref()
            .map_or(0, |receipt| receipt.retained_floor);
        if batch.first_cursor <= floor {
            if batch.last_cursor <= floor {
                return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
            }
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: batch.first_cursor,
                last_cursor: floor,
            }
            .fail();
        }
        let contiguous = previous
            .as_ref()
            .map_or(0, |receipt| receipt.contiguous_cursor);
        let mut retained = vec![false; batch.frame_ends.len()];
        let mut expired = 0_u64;
        for row in events.spans(identity, batch.first_cursor, batch.last_cursor)? {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "check expired evidence overlaps",
            })?;
            let (first, span) = Events::decode_span(identity, &key, &value)?;
            if span.last < batch.first_cursor {
                continue;
            }
            let (stored, _) = events.lookup(identity, first)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence expiry span",
                }
                .build()
            })?;
            if events.expiry(stored.meta.revision)?.is_some() {
                let count = span.last.min(batch.last_cursor) - first.max(batch.first_cursor) + 1;
                expired = expired.checked_add(count).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "expired evidence range",
                    }
                    .build()
                })?;
            }
        }
        if expired != 0 {
            if expired == batch.frame_ends.len() as u64 {
                return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
            }
            return crate::Error::reject_path(
                &self.store.root,
                "an evidence retry crosses an expired range boundary",
            );
        }
        for row in events.spans(identity, batch.first_cursor, batch.last_cursor)? {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read overlapping evidence spans",
            })?;
            let (first, span) = Events::decode_span(identity, &key, &value)?;
            if span.last < batch.first_cursor {
                continue;
            }
            let (stored, slot) = events.lookup(identity, first)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence overlap index",
                }
                .build()
            })?;
            let from = first.max(batch.first_cursor);
            let until = span.last.min(batch.last_cursor);
            let (_, commit) = events.payload(&stored, &self.store.root)?;
            let saved = &commit.spans[slot];
            for cursor in from..=until {
                let old = (cursor - saved.first) as usize;
                let new = (cursor - batch.first_cursor) as usize;
                let old_start = saved.start as usize
                    + if old == 0 {
                        0
                    } else {
                        saved.ends[old - 1] as usize
                    };
                let new_start = if new == 0 {
                    0
                } else {
                    batch.frame_ends[new - 1]
                };
                if commit.body[old_start..saved.start as usize + saved.ends[old] as usize]
                    != batch.framed_records[new_start..batch.frame_ends[new]]
                {
                    return crate::Error::reject_path(
                        &self.store.root,
                        "an evidence retry has conflicting record content",
                    );
                }
                retained[new] = true;
            }
        }
        let mut commit = RawCommit {
            revision: self.revision,
            kind: Some(RawKind::Evidence(batch.cpu_id)),
            intake: batch.intake_utc_ns,
            spans: Vec::new(),
            body: Default::default(),
        };
        if retained.iter().all(|retained| !retained) && batch.first_cursor > contiguous {
            commit.spans.push(RawSpan {
                first: batch.first_cursor,
                last: batch.last_cursor,
                start: 0,
                ordinal: 0,
                ends: batch
                    .frame_ends
                    .iter()
                    .map(|end| {
                        u32::try_from(*end).map_err(|_| {
                            NativeStateSnafu {
                                field: "evidence frame end",
                            }
                            .build()
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            });
            commit.body = batch.framed_records.clone();
        } else {
            let mut body = Vec::new();
            let mut start = 0;
            let mut ordinal = 0_u32;
            for (index, &end) in batch.frame_ends.iter().enumerate() {
                let cursor = batch.first_cursor + index as u64;
                if !retained[index] {
                    if cursor <= contiguous {
                        return crate::Error::reject_path(
                            &self.store.root,
                            "an acknowledged evidence record is not retained",
                        );
                    }
                    if commit
                        .spans
                        .last()
                        .is_none_or(|span| span.last.checked_add(1) != Some(cursor))
                    {
                        commit.spans.push(RawSpan {
                            first: cursor,
                            last: cursor,
                            start: u32::try_from(body.len()).map_err(|_| {
                                NativeStateSnafu {
                                    field: "evidence body offset",
                                }
                                .build()
                            })?,
                            ends: Vec::new(),
                            ordinal,
                        });
                    }
                    body.extend_from_slice(&batch.framed_records[start..end]);
                    let last = u32::try_from(body.len()).map_err(|_| {
                        NativeStateSnafu {
                            field: "evidence body size",
                        }
                        .build()
                    })?;
                    let span = commit.spans.last_mut().ok_or_else(|| {
                        NativeStateSnafu {
                            field: "accepted evidence span",
                        }
                        .build()
                    })?;
                    span.last = cursor;
                    span.ends.push(last - span.start);
                    ordinal = ordinal.checked_add(1).ok_or_else(|| {
                        NativeStateSnafu {
                            field: "evidence ordinal",
                        }
                        .build()
                    })?;
                }
                start = end;
            }
            commit.body = body.into();
        }
        if commit.spans.is_empty() {
            return Ok(if contiguous >= batch.last_cursor {
                EvidenceStoreOutcomeV1::Accepted
            } else {
                EvidenceStoreOutcomeV1::Pending
            });
        }
        self.store.require_retention()?;
        self.evidence_capacity(identity, &commit)?;
        let frame = commit.frame(&self.store.root)?;
        let first = commit.spans[0].first;
        let record = EventBatch {
            source: identity.clone(),
            first,
            meta: RawMeta::try_from(&commit)?,
            bytes: frame.len(),
        };
        self.transaction
            .insert(Events::key(Events::PAYLOAD, identity, first), frame);
        Records::stage(
            &mut self.transaction,
            Events::position(Events::POSITION, self.revision),
            Records::encode(&record)?,
        );
        for (slot, span) in commit.spans.iter().enumerate() {
            Records::stage(
                &mut self.transaction,
                Events::key(Events::SPANS, identity, span.first),
                Records::encode(&EventSpan {
                    last: span.last,
                    batch: first,
                    revision: self.revision,
                    slot,
                })?,
            );
        }
        let mut receipt = previous.clone().unwrap_or_else(|| AnalysisSourceReceiptV1 {
            identity: identity.clone(),
            cpu_id: batch.cpu_id,
            contiguous_cursor: 0,
            coverage_revision: 0,
            retained_floor: 0,
        });
        let target = Events::key(
            Events::SPANS,
            identity,
            receipt.contiguous_cursor.saturating_add(1),
        );
        for row in self
            .transaction
            .range(target..=Events::key(Events::SPANS, identity, u64::MAX))
        {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "advance evidence receipt",
            })?;
            let (from, span) = Events::decode_span(identity, &key, &value)?;
            if from > receipt.contiguous_cursor.saturating_add(1) {
                break;
            }
            if span.revision > self.revision {
                return NativeStateSnafu {
                    field: "evidence receipt span revision",
                }
                .fail();
            }
            let header =
                Records::payload(&Events::position(Events::POSITION, span.revision), |key| {
                    Records::staged(key, &self.transaction)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "evidence receipt batch",
                    }
                    .build()
                })?;
            let header: EventBatch = Records::decode(&header)?;
            header.check_span(identity, from, &span)?;
            receipt.contiguous_cursor = receipt.contiguous_cursor.max(span.last);
        }
        Records::stage(
            &mut self.transaction,
            Sources::key(Sources::RECEIPTS, &identity.key()),
            Records::encode(&receipt)?,
        );
        self.transaction.insert(epoch, Records::encode(identity)?);
        self.note_relation("events", self.revision)?;
        self.note_relation("source_receipts", self.revision)?;
        if previous.is_none() {
            self.note_relation("source_bindings", self.revision)?;
        }
        self.dirty = true;
        #[cfg(any(test, feature = "test-fixtures"))]
        {
            self.evidence = true;
        }
        Ok(if receipt.contiguous_cursor >= batch.last_cursor {
            EvidenceStoreOutcomeV1::Accepted
        } else {
            EvidenceStoreOutcomeV1::Pending
        })
    }
}
