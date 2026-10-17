use super::*;
use crate::{
    TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1, TraceIntentV1,
    TraceMeasurementV1, TraceOutputReceiptV1, TraceStateV1, TraceTerminalReasonV1,
};

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn trace(
        &mut self,
        state: &TraceStateV1,
        intent: &TraceIntentV1,
        target_index: u32,
        receipt: &TraceOutputReceiptV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
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
        table_row!(self,"traces",budget;
            tenant_id=>Binary:Some(&intent.tenant_id),
            request_id=>Binary:Some(&intent.request_id),
            target_index=>UInt32:Some(target_index),
            execution_id=>Binary:Some(&binding.identity.execution_id),
            node_id=>Utf8:Some(&binding.identity.node_id),
            node_boot_id=>Binary:Some(&binding.identity.node_boot_id),
            binding_id=>Binary:Some(&binding.binding_id),
            namespace_uid=>Utf8:Some(&binding.namespace_uid),
            source=>Binary:Some(&intent.source.bytes),
            source_sha256=>Binary:Some(&intent.source.sha256),
            trace_schema_version=>UInt32:Some(1u32),
            request_revision=>UInt64:Some(state.revision),
            accepted_unix_ns=>UInt64:Some(intent.accepted_unix_ns),
            deadline_unix_ns=>UInt64:Some(intent.deadline_unix_ns),
            last_sequence=>UInt64:Some(receipt.last_sequence),
            output_bytes=>UInt64:Some(receipt.output_bytes),
            retained_floor=>UInt64:Some(receipt.retained_floor),
            cancel_requested=>Boolean:Some(state.cancel_requested),
            read_revoked=>Boolean:Some(state.read_revoked),
            terminal_reason=>Utf8:terminal.map(|value|match value.reason {TraceTerminalReasonV1::Completed=>"completed",TraceTerminalReasonV1::Cancelled=>"cancelled",TraceTerminalReasonV1::Deadline=>"deadline",TraceTerminalReasonV1::PreparationFailed=>"preparation_failed",TraceTerminalReasonV1::TargetChanged=>"target_changed",TraceTerminalReasonV1::OutputLimit=>"output_limit",TraceTerminalReasonV1::ConsumerSlow=>"consumer_slow",TraceTerminalReasonV1::NodeRestarted=>"node_restarted",TraceTerminalReasonV1::StorageFailure=>"storage_failure",TraceTerminalReasonV1::BackendFailed=>"backend_failed"}),
            output_incomplete=>Boolean:terminal.map(|value|value.output_incomplete),
            kernel_lost_events=>UInt64:terminal.and_then(|value|value.kernel_lost_events),
            ready_at_unix_ns=>UInt64:terminal.and_then(|value|value.ready_at_unix_ns),
            exit_code=>Int32:terminal.and_then(|value|value.exit_code),
            forced_kill=>Boolean:terminal.map(|value|value.forced_kill),
            cleanup=>Utf8:terminal.map(|value|match value.cleanup {TraceCleanupV1::Verified=>"verified",TraceCleanupV1::Failed=>"failed",TraceCleanupV1::Unknown=>"unknown"}),
        )
    }

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
    ) -> Result<bool> {
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
        if !table_row!(self,"trace_output",budget;
            tenant_id=>Binary:Some(&identity.tenant_id),
            request_id=>Binary:Some(&identity.request_id),
            execution_id=>Binary:Some(&identity.execution_id),
            node_id=>Utf8:Some(&identity.node_id),
            node_boot_id=>Binary:Some(&identity.node_boot_id),
            source_sha256=>Binary:Some(&identity.source_sha256),
            target_index=>UInt32:Some(target_index),
            sequence=>UInt64:Some(sequence),
            commit_revision=>UInt64:Some(position.commit_revision),
            ordinal=>UInt32:Some(position.ordinal),
            kind=>Utf8:Some(kind),
            bytes=>Binary:Some(bytes),
        )? {
            return Ok(false);
        }
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

    fn measurement(
        &mut self,
        identity: &TraceIdentityV1,
        measurement: &TraceMeasurementV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        table_row!(self,"trace_measurements",budget;
            tenant_id=>Binary:Some(&identity.tenant_id),
            request_id=>Binary:Some(&identity.request_id),
            execution_id=>Binary:Some(&measurement.execution_id),
            sequence=>UInt64:Some(measurement.sequence),
            ordinal=>UInt32:Some(u32::from(measurement.ordinal)),
            syscall_id=>UInt32:measurement.syscall_id,
            errno=>Int64:Some(measurement.errno),
            count=>UInt64:Some(measurement.count),
            cumulative=>Boolean:Some(measurement.cumulative),
            atomic_snapshot=>Boolean:Some(measurement.atomic_snapshot),
            unit=>Utf8:Some(&measurement.unit),
        )
    }
}
