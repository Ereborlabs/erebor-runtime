use super :: { DataView , NativeStateSnafu , NativeStore , RawIdentity , RawReceipt , Records , Result , Traces } ;
use crate::analysis::raw::{RawBatch, RawKind};
use crate :: { AnalysisReadControl , EvidenceStoreOutcomeV1 , TraceBatchV1 , TraceIdentityV1 , TraceOutputPageV1 , TraceOutputReceiptV1 } ;

impl DataView {
    pub fn trace_receipt(
        &self,
        identity: &TraceIdentityV1,
    ) -> Result<Option<TraceOutputReceiptV1>> {
        self.trace_receipt_charged(identity, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn trace_receipt_charged(
        &self,
        identity: &TraceIdentityV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<TraceOutputReceiptV1>> {
        identity.validate()?;
        let Some(bytes) = Records::charged_payload(
            &Traces::receipt_key(identity),
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        else {
            return Ok(None);
        };
        let mut receipt: TraceOutputReceiptV1 = Records::decode(&bytes)?;
        Traces::check_receipt(&receipt)?;
        if receipt.identity != *identity || receipt.commit_revision > self.metadata_revision {
            return NativeStateSnafu {
                field: "trace receipt identity",
            }
            .fail();
        }
        let key = RawIdentity::Diagnostic(identity.clone()).key();
        let Some(source) = self.raw.sources.get(&key) else {
            return Ok(Some(receipt));
        };
        let RawReceipt::Diagnostic(current) = &source.receipt else {
            return NativeStateSnafu {
                field: "trace receipt kind",
            }
            .fail();
        };
        if current.identity != *identity {
            return crate::AnalysisConflictSnafu.fail();
        }
        if self.raw.revision <= self.revision {
            return Ok(Some(current.clone()));
        }
        for (_, &(revision, _)) in self
            .raw
            .ranges
            .range((key.clone(), 0)..=(key, u64::MAX))
            .rev()
        {
            if revision > self.revision || revision <= receipt.commit_revision {
                continue;
            }
            let entry = &self.raw.entries[&revision];
            let RawKind::Diagnostic(progress) = &entry.commit.kind else {
                return NativeStateSnafu {
                    field: "trace raw kind",
                }
                .fail();
            };
            receipt.last_sequence = progress.last_sequence;
            receipt.output_bytes = progress.output_bytes;
            receipt.terminal = if progress.terminal {
                Some(current.terminal.clone().ok_or_else(|| {
                    NativeStateSnafu {
                        field: "trace raw terminal",
                    }
                    .build()
                })?)
            } else {
                None
            };
            receipt.commit_revision = revision;
            Traces::check_receipt(&receipt)?;
            break;
        }
        Ok(Some(receipt))
    }
}

impl Traces {
    pub(super) fn check_receipt(receipt: &TraceOutputReceiptV1) -> Result<()> {
        receipt.identity.validate()?;
        if receipt.last_sequence.checked_add(1).is_none()
            || receipt.retained_floor
                > receipt.last_sequence + u64::from(receipt.terminal.is_some())
            || receipt.output_bytes < receipt.last_sequence
            || receipt.commit_revision == 0 && receipt.output_bytes != 0
            || (receipt.commit_revision == 0)
                != (receipt.last_sequence == 0 && receipt.terminal.is_none())
            || receipt.terminal.as_ref().is_some_and(|terminal| {
                terminal.validate().is_err()
                    || terminal.execution_id != receipt.identity.execution_id
                    || terminal.last_sequence != receipt.last_sequence
                    || terminal.output_bytes != receipt.output_bytes
            })
        {
            return NativeStateSnafu {
                field: "trace receipt bounds",
            }
            .fail();
        }
        Ok(())
    }
}

impl NativeStore {
    pub fn trace_receipt(
        &self,
        identity: &TraceIdentityV1,
    ) -> Result<Option<TraceOutputReceiptV1>> {
        self.view()?.trace_receipt(identity)
    }

    pub fn append_trace(
        &self,
        identity: &TraceIdentityV1,
        batch: &TraceBatchV1,
        intake_utc_ns: u64,
    ) -> Result<TraceOutputReceiptV1> {
        identity.validate()?;
        if batch.execution_id != identity.execution_id {
            return crate::TraceInvalidSnafu {
                reason: "the trace batch execution differs",
            }
            .fail();
        }
        let input = RawBatch::trace(batch, intake_utc_ns, &self.root)?;
        let (first, last) = (input.first_cursor, input.last_cursor);
        let (outcome, receipt) = self.commit_raw(identity.clone().into(), input)?;
        let RawReceipt::Diagnostic(receipt) = receipt else {
            return NativeStateSnafu {
                field: "trace output receipt kind",
            }
            .fail();
        };
        if outcome == EvidenceStoreOutcomeV1::AlreadyAcceptedExpired {
            if batch.frames.is_empty() && receipt.terminal != batch.terminal {
                return crate::AnalysisConflictSnafu.fail();
            }
            if !(batch.frames.is_empty() && receipt.terminal == batch.terminal) {
                return crate::RetainedRangeExpiredSnafu {
                    first_cursor: first,
                    last_cursor: last,
                }
                .fail();
            }
        }
        Ok(receipt)
    }

    pub fn read_trace(
        &self,
        identity: &TraceIdentityV1,
        first_cursor: u64,
        control: &AnalysisReadControl,
    ) -> Result<TraceOutputPageV1> {
        let view = self.view()?;
        self.read_trace_at(&view, identity, first_cursor, control)
    }

    pub fn read_trace_at(
        &self,
        view: &DataView,
        identity: &TraceIdentityV1,
        first_cursor: u64,
        control: &AnalysisReadControl,
    ) -> Result<TraceOutputPageV1> {
        identity.validate()?;
        let _maintenance = self.maintenance.read_until(control)?;
        let _permit = self.reserve_reader()?;
        self.check_trace_binding(identity, control)?;
        if view.store_uuid != self.view()?.store_uuid {
            return NativeStateSnafu {
                field: "trace read store identity",
            }
            .fail();
        }
        let receipt = view.trace_receipt(identity)?.ok_or_else(|| {
            crate::TraceInvalidSnafu {
                reason: "the diagnostic source is absent",
            }
            .build()
        })?;
        let raw = self.raw.until(control)?;
        let page = raw.freeze_page(
            &view.raw,
            &RawReceipt::Diagnostic(receipt),
            first_cursor,
            view.revision,
            control,
            201,
        )?;
        drop(raw);
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::AfterTraceFreeze)?;
        let page = page.read(&self.root, control, 1024 * 1024 + 201 * 8 + 4096)?;
        let output = TraceOutputPageV1::decode(page, identity, &self.root, control)?;
        self.check_trace_binding(identity, control)?;
        Ok(output)
    }

    fn check_trace_binding(
        &self,
        identity: &TraceIdentityV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        let Some((state, intent)) = self.trace_intent(identity.tenant_id, identity.request_id)?
        else {
            return crate::AnalysisReadDeniedSnafu.fail();
        };
        if state.read_revoked
            || !intent
                .bindings
                .iter()
                .any(|binding| binding.identity == *identity)
        {
            return crate::AnalysisReadDeniedSnafu.fail();
        }
        Ok(())
    }
}
