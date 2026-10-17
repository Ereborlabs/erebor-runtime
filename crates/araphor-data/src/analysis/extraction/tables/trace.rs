use super::*;
use crate::{
    TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1, TraceIntentV1,
    TraceMeasurementV1, TraceOutputReceiptV1, TraceStateV1, TraceTerminalReasonV1,
};

impl Capture<'_> {
    table_row! {
        pub(in crate::analysis::extraction) fn trace(
            &mut self,
            state: &TraceStateV1,
            intent: &TraceIntentV1,
            target_index: u32,
            receipt: &TraceOutputReceiptV1,
            budget: &mut ReadBudget<'_>,
        );
        schema trace_fields;
        row(self, "traces", budget);
        setup {
            let binding = intent
                .bindings
                .get(target_index as usize)
                .ok_or_else(|| invalid("the trace target index is outside its frozen intent"))?;
            if self.read.requests.contains_key("trace_measurements") {
                if let Some(recipe) = TraceRecipeV1::identify(&intent.source)? {
                    budget.charge(128)?;
                    self.trace_recipes
                        .insert(binding.identity.execution_id, recipe);
                }
            }
            let terminal = receipt.terminal.as_ref();
        }
        fields {
            tenant_id => Binary(false):Some(&intent.tenant_id),
            request_id => Binary(false):Some(&intent.request_id),
            target_index => UInt32(false):Some(target_index),
            execution_id => Binary(false):Some(&binding.identity.execution_id),
            node_id => Utf8(false):Some(&binding.identity.node_id),
            node_boot_id => Binary(false):Some(&binding.identity.node_boot_id),
            binding_id => Binary(false):Some(&binding.binding_id),
            namespace_uid => Utf8(false):Some(&binding.namespace_uid),
            source => Binary(false):Some(&intent.source.bytes),
            source_sha256 => Binary(false):Some(&intent.source.sha256),
            trace_schema_version => UInt32(false):Some(1u32),
            request_revision => UInt64(false):Some(state.revision),
            accepted_unix_ns => UInt64(false):Some(intent.accepted_unix_ns),
            deadline_unix_ns => UInt64(false):Some(intent.deadline_unix_ns),
            last_sequence => UInt64(false):Some(receipt.last_sequence),
            output_bytes => UInt64(false):Some(receipt.output_bytes),
            retained_floor => UInt64(false):Some(receipt.retained_floor),
            cancel_requested => Boolean(false):Some(state.cancel_requested),
            read_revoked => Boolean(false):Some(state.read_revoked),
            terminal_reason => Utf8(true):terminal.map(|value|match value.reason {TraceTerminalReasonV1::Completed=>"completed",TraceTerminalReasonV1::Cancelled=>"cancelled",TraceTerminalReasonV1::Deadline=>"deadline",TraceTerminalReasonV1::PreparationFailed=>"preparation_failed",TraceTerminalReasonV1::TargetChanged=>"target_changed",TraceTerminalReasonV1::OutputLimit=>"output_limit",TraceTerminalReasonV1::ConsumerSlow=>"consumer_slow",TraceTerminalReasonV1::NodeRestarted=>"node_restarted",TraceTerminalReasonV1::StorageFailure=>"storage_failure",TraceTerminalReasonV1::BackendFailed=>"backend_failed"}),
            output_incomplete => Boolean(true):terminal.map(|value|value.output_incomplete),
            kernel_lost_events => UInt64(true):terminal.and_then(|value|value.kernel_lost_events),
            ready_at_unix_ns => UInt64(true):terminal.and_then(|value|value.ready_at_unix_ns),
            exit_code => Int32(true):terminal.and_then(|value|value.exit_code),
            forced_kill => Boolean(true):terminal.map(|value|value.forced_kill),
            cleanup => Utf8(true):terminal.map(|value|match value.cleanup {TraceCleanupV1::Verified=>"verified",TraceCleanupV1::Failed=>"failed",TraceCleanupV1::Unknown=>"unknown"}),
        }
    }

    table_row! {
        #[allow(clippy::too_many_arguments)]
        pub(in crate::analysis::extraction) fn frame(
            &mut self,
            identity: &TraceIdentityV1,
            target_index: u32,
            sequence: u64,
            position: StorePositionV1,
            kind: &str,
            bytes: &[u8],
            budget: &mut ReadBudget<'_>,
        );
        schema frame_fields;
        row(self, "trace_output", budget);
        setup {
            if self.read.requests.contains_key("trace_output")
                || self.read.requests.contains_key("trace_measurements")
            {
                budget.grow(&mut self.witnesses)?;
                budget.charge(identity.node_id.len())?;
                self.witnesses.push(AnalysisWitnessV1 {
                    identity: identity.clone().into(),
                    cursor: sequence,
                    expires_utc_ns: 0,
                });
            }
        }
        fields {
            tenant_id => Binary(false):Some(&identity.tenant_id),
            request_id => Binary(false):Some(&identity.request_id),
            execution_id => Binary(false):Some(&identity.execution_id),
            node_id => Utf8(false):Some(&identity.node_id),
            node_boot_id => Binary(false):Some(&identity.node_boot_id),
            source_sha256 => Binary(false):Some(&identity.source_sha256),
            target_index => UInt32(false):Some(target_index),
            sequence => UInt64(false):Some(sequence),
            commit_revision => UInt64(false):Some(position.commit_revision),
            ordinal => UInt32(false):Some(position.ordinal),
            kind => Utf8(false):Some(kind),
            bytes => Binary(false):Some(bytes),
        }
        then {
            if kind != "data" || self.read.projected("trace_measurements").is_none() {
                return Ok(true);
            }
            let Some(recipe) = self.trace_recipes.get(&identity.execution_id).copied() else {
                return Ok(true);
            };
            budget.charge(bytes.len().checked_mul(8).ok_or_else(overflow)?)?;
            let frame = TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: bytes.to_vec(),
            };
            if let Some(measurements) = recipe.measurements(&frame) {
                for measurement in &measurements {
                    if !self.measurement(identity, measurement, budget)? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
    }

    table_row! {
        fn measurement(
            &mut self,
            identity: &TraceIdentityV1,
            measurement: &TraceMeasurementV1,
            budget: &mut ReadBudget<'_>,
        );
        schema measurement_fields;
        row(self, "trace_measurements", budget);
        setup {
        }
        fields {
            tenant_id => Binary(false):Some(&identity.tenant_id),
            request_id => Binary(false):Some(&identity.request_id),
            execution_id => Binary(false):Some(&measurement.execution_id),
            sequence => UInt64(false):Some(measurement.sequence),
            ordinal => UInt32(false):Some(u32::from(measurement.ordinal)),
            syscall_id => UInt32(true):measurement.syscall_id,
            errno => Int64(false):Some(measurement.errno),
            count => UInt64(false):Some(measurement.count),
            cumulative => Boolean(false):Some(measurement.cumulative),
            atomic_snapshot => Boolean(false):Some(measurement.atomic_snapshot),
            unit => Utf8(false):Some(&measurement.unit),
        }
    }
}
