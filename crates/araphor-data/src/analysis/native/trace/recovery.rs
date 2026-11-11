use super::{
    IntentRecord, NativeStateSnafu, NativeStorageSnafu, RawIdentity, RawReceipt, RawSource,
    Records, Result, Traces,
};
use crate::analysis::raw::RawJournal;
use crate::{TraceOutputReceiptV1, TraceStateV1};
use snafu::ResultExt as _;

impl Traces {
    pub(in crate::analysis::native) fn recover(
        raw: &mut RawJournal,
        snapshot: &fjall::BranchSnapshot,
    ) -> Result<()> {
        let metadata = super::NativeStore::number(&super::NativeStore::required(
            snapshot,
            super::super::HEAD,
        )?)?;
        let notice = snapshot
            .get(super::NativeStore::relation_key("traces"))
            .context(NativeStorageSnafu {
                operation: "read trace relation notice",
            })?
            .map(|bytes| super::NativeStore::number(&bytes))
            .transpose()?
            .unwrap_or(0);
        if notice > metadata {
            return NativeStateSnafu {
                field: "trace relation notice",
            }
            .fail();
        }
        let mut admissions = std::collections::BTreeMap::new();
        for row in snapshot.prefix(Self::INTENTS) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "recover trace intents",
            })?;
            if key.len() == Self::INTENTS.len() + 40 {
                continue;
            }
            let bytes =
                Records::payload(&key, |key| Records::read(key, snapshot))?.ok_or_else(|| {
                    NativeStateSnafu {
                        field: "trace intent baseline",
                    }
                    .build()
                })?;
            let intent: IntentRecord = Records::decode(&bytes)?;
            let (state, record) = Self::read(
                intent.intent.tenant_id,
                intent.intent.request_id,
                metadata,
                |key| Records::read(key, snapshot),
            )?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "trace intent state",
                }
                .build()
            })?;
            if state.revision > notice
                || Self::key(
                    Self::INTENTS,
                    intent.intent.tenant_id,
                    intent.intent.request_id,
                ) != key.as_ref()
                || record.intent != intent.intent
                || record.revision != intent.revision
            {
                return NativeStateSnafu {
                    field: "trace intent baseline identity",
                }
                .fail();
            }
            for binding in intent.intent.bindings {
                let key = RawIdentity::Diagnostic(binding.identity.clone()).key();
                if admissions
                    .insert(key, (binding.identity, intent.revision))
                    .is_some()
                {
                    return NativeStateSnafu {
                        field: "trace admitted execution identity",
                    }
                    .fail();
                }
            }
        }
        for row in snapshot.prefix(Self::RECEIPTS) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "recover trace receipt keys",
            })?;
            let bytes =
                Records::payload(&key, |key| Records::read(key, snapshot))?.ok_or_else(|| {
                    NativeStateSnafu {
                        field: "trace receipt baseline",
                    }
                    .build()
                })?;
            let receipt: TraceOutputReceiptV1 = Records::decode(&bytes)?;
            Self::check_receipt(&receipt)?;
            if Self::receipt_key(&receipt.identity) != key.as_ref()
                || receipt.commit_revision > metadata
            {
                return NativeStateSnafu {
                    field: "trace receipt baseline key",
                }
                .fail();
            }
            if admissions
                .get(&RawIdentity::Diagnostic(receipt.identity.clone()).key())
                .is_none_or(|(identity, revision)| {
                    identity != &receipt.identity
                        || receipt.commit_revision != 0 && receipt.commit_revision <= *revision
                })
            {
                return NativeStateSnafu {
                    field: "trace receipt binding",
                }
                .fail();
            }
            if receipt.commit_revision != 0 {
                let entry = raw
                    .index
                    .entries
                    .get(&receipt.commit_revision)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "trace receipt raw revision",
                        }
                        .build()
                    })?;
                let crate::analysis::raw::RawKind::Diagnostic(progress) = &entry.commit.kind else {
                    return NativeStateSnafu {
                        field: "trace receipt raw kind",
                    }
                    .fail();
                };
                if entry.identity != RawIdentity::Diagnostic(receipt.identity.clone())
                    || progress.last_sequence != receipt.last_sequence
                    || progress.output_bytes != receipt.output_bytes
                    || progress.terminal != receipt.terminal.is_some()
                {
                    return NativeStateSnafu {
                        field: "trace receipt raw revision",
                    }
                    .fail();
                }
            }
            let source_key = RawIdentity::Diagnostic(receipt.identity.clone()).key();
            if let Some(source) = raw.index.sources.get_mut(&source_key) {
                let RawReceipt::Diagnostic(saved) = &mut source.receipt else {
                    return NativeStateSnafu {
                        field: "trace receipt baseline kind",
                    }
                    .fail();
                };
                if saved.identity != receipt.identity
                    || saved.cursor() < receipt.cursor()
                    || saved.output_bytes < receipt.output_bytes
                    || receipt
                        .terminal
                        .as_ref()
                        .is_some_and(|terminal| saved.terminal.as_ref() != Some(terminal))
                    || saved.cursor() == receipt.cursor()
                        && (saved.output_bytes != receipt.output_bytes
                            || saved.terminal != receipt.terminal)
                {
                    return NativeStateSnafu {
                        field: "trace receipt raw baseline",
                    }
                    .fail();
                }
                saved.retained_floor = receipt.retained_floor;
            } else {
                if receipt.cursor() > receipt.retained_floor {
                    return NativeStateSnafu {
                        field: "trace receipt missing output",
                    }
                    .fail();
                }
                raw.index.sources.insert_mut(
                    source_key,
                    RawSource {
                        written: receipt.cursor() != 0,
                        receipt: RawReceipt::Diagnostic(receipt),
                        active: None,
                    },
                );
            }
        }
        for (identity, _) in admissions.values() {
            if raw
                .index
                .sources
                .get(&RawIdentity::Diagnostic(identity.clone()).key())
                .is_none_or(|source| {
                    !source
                        .receipt
                        .matches(&RawIdentity::Diagnostic(identity.clone()))
                })
            {
                return NativeStateSnafu {
                    field: "trace admitted identity",
                }
                .fail();
            }
        }
        for (_, entry) in raw.index.entries.iter() {
            let RawIdentity::Diagnostic(identity) = &entry.identity else {
                continue;
            };
            if admissions
                .get(&RawIdentity::Diagnostic(identity.clone()).key())
                .is_none_or(|(saved, revision)| {
                    saved != identity || *revision >= entry.commit.revision
                })
            {
                return NativeStateSnafu {
                    field: "trace raw intent order",
                }
                .fail();
            }
        }
        let mut bytes = 0u64;
        let mut slots = 0usize;
        for (key, source) in raw.index.sources.iter() {
            let RawReceipt::Diagnostic(receipt) = &source.receipt else {
                continue;
            };
            if receipt.terminal.is_some() {
                continue;
            }
            bytes = bytes
                .checked_add(crate::analysis::quota::TRACE_RESERVE)
                .ok_or_else(|| {
                    crate::NativeStateSnafu {
                        field: "diagnostic byte reserve",
                    }
                    .build()
                })?;
            slots = slots
                .checked_add(
                    if raw.segments.values().any(|segment| segment.source == *key) {
                        1
                    } else {
                        2
                    },
                )
                .ok_or_else(|| {
                    crate::NativeStateSnafu {
                        field: "diagnostic slot reserve",
                    }
                    .build()
                })?;
        }
        raw.budget.trace_reserve = bytes;
        raw.budget.trace_slots = slots;
        Ok(())
    }
}

impl super::NativeStore {
    pub(in crate::analysis::native) fn validate_trace_recovery(&self) -> Result<()> {
        let view = self.view()?;
        for row in view.snapshot.prefix(Traces::STATES) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate trace state history",
            })?;
            let bytes = value.strip_prefix(&[0]).ok_or_else(|| {
                NativeStateSnafu {
                    field: "trace state encoding",
                }
                .build()
            })?;
            let mut state: TraceStateV1 = Records::decode(bytes)?;
            let (_, intent) = Traces::read(
                state.tenant_id,
                state.request_id,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
            )?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "trace state intent",
                }
                .build()
            })?;
            if Traces::key(Traces::STATES, state.tenant_id, state.request_id) != key.as_ref() {
                return NativeStateSnafu {
                    field: "trace state key",
                }
                .fail();
            }
            loop {
                let at = self.read_at(state.revision)?;
                if at.trace_intent(state.tenant_id, state.request_id)?
                    != Some((state.clone(), intent.intent.clone()))
                {
                    return NativeStateSnafu {
                        field: "trace exact state revision",
                    }
                    .fail();
                }
                let before = self.read_at(state.revision - 1)?;
                let Some((prior, source)) =
                    before.trace_intent(state.tenant_id, state.request_id)?
                else {
                    if state.revision != intent.revision
                        || state.cancel_requested
                        || state.read_revoked
                    {
                        return NativeStateSnafu {
                            field: "trace initial state",
                        }
                        .fail();
                    }
                    break;
                };
                if source != intent.intent
                    || prior.revision >= state.revision
                    || prior.cancel_requested && !state.cancel_requested
                    || prior.read_revoked && !state.read_revoked
                    || (prior.cancel_requested, prior.read_revoked)
                        == (state.cancel_requested, state.read_revoked)
                {
                    return NativeStateSnafu {
                        field: "trace state transition",
                    }
                    .fail();
                }
                state = prior;
            }
        }
        Ok(())
    }
}
