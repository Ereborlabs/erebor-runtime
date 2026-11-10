use std::collections::BTreeMap;

use snafu::ResultExt as _;

use super::{Capture, DataView, NativeStore};
use crate::analysis::{extraction::SelectedTrace, native::trace::Traces, raw::RawReceipt};
use crate::{
    AnalysisExtractionV1, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisTableRead, NativeStateSnafu, NativeStorageSnafu, Result, Selection, StorePositionV1,
};

impl NativeStore {
    pub(super) fn select_traces(
        &self,
        view: &DataView,
        selection: &mut AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<BTreeMap<([u8; 16], [u8; 16]), (crate::TraceStateV1, crate::TraceIntentV1)>> {
        let mut requests = BTreeMap::new();
        if selection.traces.is_all() {
            let mut traces = Vec::new();
            let first = [vec![1], selection.tenant_id.to_vec(), vec![0; 16]].concat();
            let last = [vec![1], selection.tenant_id.to_vec(), vec![u8::MAX; 16]].concat();
            for (_, source) in view.raw.sources.range(first..=last) {
                control.check()?;
                let RawReceipt::Diagnostic(receipt) = &source.receipt else {
                    continue;
                };
                let identity = &receipt.identity;
                if identity.tenant_id != selection.tenant_id
                    || !selection.nodes.is_empty() && !selection.nodes.contains(&identity.node_id)
                    || view
                        .snapshot
                        .get(Traces::receipt_key(identity))
                        .context(NativeStorageSnafu {
                            operation: "select captured trace",
                        })?
                        .is_none()
                {
                    continue;
                }
                let key = (identity.tenant_id, identity.request_id);
                if let std::collections::btree_map::Entry::Vacant(entry) = requests.entry(key) {
                    output.charge(
                        size_of::<(crate::TraceStateV1, crate::TraceIntentV1)>()
                            + size_of::<([u8; 16], [u8; 16])>()
                            + 6 * size_of::<usize>(),
                    )?;
                    let record = view
                        .trace_intent_charged(
                            identity.tenant_id,
                            identity.request_id,
                            &mut |bytes| {
                                control.check()?;
                                output.charge(bytes)
                            },
                        )?
                        .ok_or_else(|| {
                            NativeStateSnafu {
                                field: "selected trace intent",
                            }
                            .build()
                        })?;
                    entry.insert(record);
                }
                let (state, intent) = &requests[&key];
                if state.read_revoked
                    || !intent.bindings.iter().any(|binding| {
                        binding.identity == *identity
                            && (selection.binding_ids.is_empty()
                                || selection.binding_ids.contains(&binding.binding_id))
                    })
                {
                    continue;
                }
                if output
                    .limits
                    .keys
                    .is_some_and(|limit| selection.key_count() + traces.len() >= limit)
                {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "selected input keys",
                    }
                    .fail();
                }
                output.charge(AnalysisExtractionV1::grow(
                    &mut traces,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?)?;
                output.charge(identity.node_id.len())?;
                traces.push(identity.clone());
            }
            traces.sort();
            selection.traces = Selection::Exact(traces);
        } else if !selection.nodes.is_empty() {
            if let Some(traces) = selection.traces.exact_mut() {
                traces.retain(|identity| selection.nodes.contains(&identity.node_id));
            }
        }
        Ok(requests)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Trace selection shares its decoded request headers with capture."
    )]
    pub(super) fn trace_headers<'a>(
        &self,
        view: &DataView,
        selection: &'a AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
        mut requests: BTreeMap<([u8; 16], [u8; 16]), (crate::TraceStateV1, crate::TraceIntentV1)>,
    ) -> Result<Vec<SelectedTrace<'a>>> {
        let mut traces = Vec::new();
        for identity in selection.traces.as_slice() {
            control.check()?;
            let key = (identity.tenant_id, identity.request_id);
            if !requests.contains_key(&key) {
                output.charge(
                    size_of::<(crate::TraceStateV1, crate::TraceIntentV1)>()
                        + size_of::<([u8; 16], [u8; 16])>()
                        + 6 * size_of::<usize>(),
                )?;
                let intent = view
                    .trace_intent_charged(identity.tenant_id, identity.request_id, &mut |bytes| {
                        control.check()?;
                        output.charge(bytes)
                    })?
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "selected trace intent",
                        }
                        .build()
                    })?;
                requests.insert(key, intent);
            }
            let (state, intent) = &requests[&key];
            if state.read_revoked {
                return crate::AnalysisReadDeniedSnafu.fail();
            }
            let index = intent
                .bindings
                .iter()
                .position(|binding| binding.identity == *identity)
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "selected trace binding",
                    }
                    .build()
                })?;
            let selected = selection.binding_ids.is_empty()
                || selection
                    .binding_ids
                    .contains(&intent.bindings[index].binding_id);
            output.charge(AnalysisExtractionV1::grow(
                &mut traces,
                output.input_bytes,
                output.limits.input_bytes,
            )?)?;
            traces.push(SelectedTrace {
                identity,
                target_index: index as u32,
                selected,
            });
            if !selected {
                continue;
            }
            let receipt = view
                .trace_receipt_charged(identity, &mut |bytes| {
                    control.check()?;
                    output.charge(bytes)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "selected trace receipt",
                    }
                    .build()
                })?;
            if !output.trace_reads.contains(&identity.request_id) {
                let added = AnalysisExtractionV1::grow(
                    &mut output.trace_reads,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?;
                output.charge(added)?;
                output.trace_reads.push(identity.request_id);
            }
            let changed = match read.mode {
                AnalysisReadModeV1::Changes(after) => {
                    StorePositionV1 {
                        commit_revision: state.revision.max(receipt.commit_revision),
                        ordinal: u32::MAX,
                    } > after
                }
                _ => true,
            };
            if changed {
                capture.trace(
                    state,
                    intent,
                    index as u32,
                    &receipt,
                    &mut output.sink(control),
                )?;
            }
        }
        self.check_trace_authority(selection.tenant_id, output.trace_reads(), control)?;
        Ok(traces)
    }
}
