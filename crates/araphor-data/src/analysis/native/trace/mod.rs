use std::ops::Bound::{Excluded, Included};

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{records::Records, DataView, DataWrite, NativeStore};
use crate::analysis::raw::{RawIdentity, RawReceipt, RawSource};
use crate::{
    NativeStateSnafu, NativeStorageSnafu, Result, TraceIntentPageV1, TraceIntentV1,
    TraceOutputReceiptV1, TraceStateV1,
};

mod raw;
mod recovery;

pub(super) struct Traces;

#[derive(Deserialize, Serialize)]
struct IntentRecord {
    intent: TraceIntentV1,
    revision: u64,
}

impl Traces {
    const INTENTS: &'static [u8] = b"\0data/@trace/intent/";
    const STATES: &'static [u8] = b"\0data/@trace/state/";
    pub(super) const RECEIPTS: &'static [u8] = b"\0data/@trace/receipt/";
    const PAGE: usize = 16;

    fn check_key(tenant: [u8; 16], request: [u8; 16]) -> Result<()> {
        if tenant == [0; 16] || request == [0; 16] {
            return crate::TraceInvalidSnafu {
                reason: "trace request key is invalid",
            }
            .fail();
        }
        Ok(())
    }

    fn key(prefix: &[u8], tenant: [u8; 16], request: [u8; 16]) -> Vec<u8> {
        [prefix, &tenant, &request].concat()
    }

    pub(super) fn receipt_key(identity: &crate::TraceIdentityV1) -> Vec<u8> {
        [
            Self::RECEIPTS,
            &RawIdentity::Diagnostic(identity.clone()).key(),
        ]
        .concat()
    }

    fn read(
        tenant: [u8; 16],
        request: [u8; 16],
        through: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<(TraceStateV1, IntentRecord)>> {
        Self::read_charged(tenant, request, through, get, &mut |_| Ok(()))
    }

    fn read_charged(
        tenant: [u8; 16],
        request: [u8; 16],
        through: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(TraceStateV1, IntentRecord)>> {
        Self::check_key(tenant, request)?;
        let intent =
            Records::charged_payload(&Self::key(Self::INTENTS, tenant, request), &mut get, charge)?;
        let state =
            Records::charged_payload(&Self::key(Self::STATES, tenant, request), &mut get, charge)?;
        let (Some(intent), Some(state)) = (intent.as_deref(), state.as_deref()) else {
            if intent.is_some() || state.is_some() {
                return NativeStateSnafu {
                    field: "trace intent state",
                }
                .fail();
            }
            return Ok(None);
        };
        let intent: IntentRecord = Records::decode(intent)?;
        let state: TraceStateV1 = Records::decode(state)?;
        intent.intent.validate()?;
        if intent.intent.tenant_id != tenant
            || intent.intent.request_id != request
            || intent.revision == 0
            || intent.revision > state.revision
            || state.tenant_id != tenant
            || state.request_id != request
            || state.revision > through
            || state.read_revoked && !state.cancel_requested
            || state.revision == intent.revision && (state.cancel_requested || state.read_revoked)
        {
            return NativeStateSnafu {
                field: "trace intent identity",
            }
            .fail();
        }
        Ok(Some((state, intent)))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn trace_intent_charged(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(TraceStateV1, TraceIntentV1)>> {
        Traces::read_charged(
            tenant,
            request,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )
        .map(|record| record.map(|(state, record)| (state, record.intent)))
    }

    pub(in crate::analysis::native) fn check_trace_reads(
        &self,
        tenant: [u8; 16],
        requests: &[[u8; 16]],
        control: &crate::AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        if tenant == [0; 16] || requests.contains(&[0; 16]) {
            return crate::AnalysisReadDeniedSnafu.fail();
        }
        for request in requests {
            control.check()?;
            let Some(bytes) =
                Records::payload(&Traces::key(Traces::STATES, tenant, *request), |key| {
                    Records::read(key, &self.snapshot)
                })?
            else {
                return crate::AnalysisReadDeniedSnafu.fail();
            };
            let state: TraceStateV1 = Records::decode(&bytes)?;
            if state.tenant_id != tenant
                || state.request_id != *request
                || state.revision == 0
                || state.revision > self.metadata_revision
                || state.read_revoked && !state.cancel_requested
            {
                return NativeStateSnafu {
                    field: "trace read state",
                }
                .fail();
            }
            if state.read_revoked {
                return crate::AnalysisReadDeniedSnafu.fail();
            }
        }
        Ok(())
    }

    pub fn trace_intent(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
    ) -> Result<Option<(TraceStateV1, TraceIntentV1)>> {
        Traces::read(tenant, request, self.metadata_revision, |key| {
            Records::read(key, &self.snapshot)
        })
        .map(|record| record.map(|(state, record)| (state, record.intent)))
    }

    pub fn trace_intents(
        &self,
        tenant: [u8; 16],
        after: Option<[u8; 16]>,
    ) -> Result<TraceIntentPageV1> {
        Traces::check_key(tenant, after.unwrap_or([1; 16]))?;
        let mut intents = Vec::new();
        let lower = Traces::key(Traces::INTENTS, tenant, after.unwrap_or([0; 16]));
        let upper = Traces::key(Traces::INTENTS, tenant, [u8::MAX; 16]);
        for row in self
            .snapshot
            .range::<Vec<u8>, _>((Excluded(lower), Included(upper)))
            .take(Traces::PAGE)
        {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read native trace intents",
            })?;
            if key.len() != Traces::INTENTS.len() + 32 {
                return NativeStateSnafu {
                    field: "trace intent key",
                }
                .fail();
            }
            let request = key[key.len() - 16..].try_into().map_err(|_| {
                NativeStateSnafu {
                    field: "trace intent request",
                }
                .build()
            })?;
            intents.push(self.trace_intent(tenant, request)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "trace intent page",
                }
                .build()
            })?);
        }
        let next_request = (intents.len() == Traces::PAGE)
            .then(|| intents.last().map(|(state, _)| state.request_id))
            .flatten();
        Ok(TraceIntentPageV1 {
            intents,
            next_request,
        })
    }

    pub(in crate::analysis::native) fn input_trace_key(key: &[u8]) -> bool {
        key.starts_with(Traces::STATES)
    }

    pub(in crate::analysis::native) fn input_trace(
        &self,
        key: &[u8],
        readers: &crate::analysis::inputs::InputChanges,
        position: crate::StorePositionV1,
    ) -> Result<()> {
        if key.len() != Traces::STATES.len() + 32 {
            return NativeStateSnafu {
                field: "input trace key",
            }
            .fail();
        }
        let suffix = &key[Traces::STATES.len()..];
        let tenant = suffix[..16].try_into().map_err(|_| {
            NativeStateSnafu {
                field: "input trace tenant",
            }
            .build()
        })?;
        let request = suffix[16..].try_into().map_err(|_| {
            NativeStateSnafu {
                field: "input trace request",
            }
            .build()
        })?;
        let (state, intent) = self.trace_intent(tenant, request)?.ok_or_else(|| {
            NativeStateSnafu {
                field: "input trace state",
            }
            .build()
        })?;
        if state.revision != self.metadata_revision {
            return NativeStateSnafu {
                field: "input trace revision",
            }
            .fail();
        }
        readers.publish(
            position,
            crate::analysis::inputs::InputChange::Trace {
                tenant,
                request,
                bindings: &intent.bindings,
            },
        );
        Ok(())
    }
}

impl NativeStore {
    pub fn trace_intent(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
    ) -> Result<Option<(TraceStateV1, TraceIntentV1)>> {
        self.view()?.trace_intent(tenant, request)
    }

    pub fn trace_intents(
        &self,
        tenant: [u8; 16],
        after: Option<[u8; 16]>,
    ) -> Result<TraceIntentPageV1> {
        self.view()?.trace_intents(tenant, after)
    }

    pub fn accept_trace(&self, intent: &TraceIntentV1) -> Result<TraceStateV1> {
        let mut write = self.maintenance_write()?;
        let state = write.accept_trace(intent)?;
        write.commit([])?;
        Ok(state)
    }

    pub fn update_trace(&self, next: &TraceStateV1) -> Result<TraceStateV1> {
        Traces::check_key(next.tenant_id, next.request_id)?;
        if next.revision == 0 || next.read_revoked && !next.cancel_requested {
            return crate::TraceInvalidSnafu {
                reason: "trace state revision or cancellation is invalid",
            }
            .fail();
        }
        let mut write = self.maintenance_write()?;
        let (stored, _) = Traces::read(
            next.tenant_id,
            next.request_id,
            write.metadata_revision,
            |key| Records::staged(key, &write.transaction),
        )?
        .ok_or_else(|| {
            NativeStateSnafu {
                field: "trace request is absent",
            }
            .build()
        })?;
        if stored.revision != next.revision
            || stored.cancel_requested && !next.cancel_requested
            || stored.read_revoked && !next.read_revoked
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if stored == *next {
            return Ok(stored);
        }
        let state = TraceStateV1 {
            revision: write.revision,
            ..next.clone()
        };
        Records::stage(
            &mut write.transaction,
            Traces::key(Traces::STATES, next.tenant_id, next.request_id),
            Records::encode(&state)?,
        );
        write.note_relation("traces", write.revision)?;
        let revoke = next.read_revoked && !stored.read_revoked;
        write.commit_published([], || {
            if revoke {
                self.controls.send_replace(());
            }
        })?;
        Ok(state)
    }
}

impl DataWrite<'_> {
    fn accept_trace(&mut self, intent: &TraceIntentV1) -> Result<TraceStateV1> {
        intent.validate()?;
        if let Some((state, stored)) = Traces::read(
            intent.tenant_id,
            intent.request_id,
            self.metadata_revision,
            |key| Records::staged(key, &self.transaction),
        )? {
            if stored.intent != *intent {
                return crate::AnalysisConflictSnafu.fail();
            }
            return Ok(state);
        }
        for binding in &intent.bindings {
            if self
                .raw
                .sources
                .contains_key(&RawIdentity::Diagnostic(binding.identity.clone()).key())
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let bytes = (intent.bindings.len() as u64)
            .checked_mul(crate::analysis::quota::TRACE_RESERVE)
            .and_then(|added| raw.budget.trace_reserve.checked_add(added))
            .ok_or_else(|| {
                crate::NativeStateSnafu {
                    field: "diagnostic byte reserve",
                }
                .build()
            })?;
        let slots = intent
            .bindings
            .len()
            .checked_mul(2)
            .and_then(|added| raw.budget.trace_slots.checked_add(added))
            .ok_or_else(|| {
                crate::NativeStateSnafu {
                    field: "diagnostic slot reserve",
                }
                .build()
            })?;
        drop(raw);
        let state = TraceStateV1 {
            tenant_id: intent.tenant_id,
            request_id: intent.request_id,
            revision: self.revision,
            cancel_requested: false,
            read_revoked: false,
        };
        let record = IntentRecord {
            intent: intent.clone(),
            revision: self.revision,
        };
        Records::stage(
            &mut self.transaction,
            Traces::key(Traces::INTENTS, intent.tenant_id, intent.request_id),
            Records::encode(&record)?,
        );
        Records::stage(
            &mut self.transaction,
            Traces::key(Traces::STATES, intent.tenant_id, intent.request_id),
            Records::encode(&state)?,
        );
        for binding in &intent.bindings {
            let receipt = TraceOutputReceiptV1 {
                identity: binding.identity.clone(),
                last_sequence: 0,
                output_bytes: 0,
                terminal: None,
                retained_floor: 0,
                commit_revision: 0,
            };
            Records::stage(
                &mut self.transaction,
                Traces::receipt_key(&binding.identity),
                Records::encode(&receipt)?,
            );
            self.raw.sources.insert_mut(
                RawIdentity::Diagnostic(binding.identity.clone()).key(),
                RawSource {
                    receipt: RawReceipt::Diagnostic(receipt),
                    written: false,
                    active: None,
                },
            );
        }
        self.trace_budget = Some((bytes, slots));
        self.note_relation("traces", self.revision)?;
        Ok(state)
    }
}
