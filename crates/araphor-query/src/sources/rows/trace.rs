use araphor_data::{
    AnalysisInputV1, AnalysisWitnessV1, ProjectionSink, TraceCleanupV1, TraceFrameKindV1,
    TraceFrameV1, TraceIdentityV1, TraceMeasurementV1, TraceRecipeV1, TraceTerminalReasonV1,
};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn trace(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        match input {
            AnalysisInputV1::Trace {
                state,
                intent,
                target_index,
                receipt,
            } => {
                let binding = intent.bindings.get(target_index as usize).ok_or_else(|| {
                    ArrowBatch::invalid("the trace target index is outside its frozen intent")
                })?;
                if self.sources.contains("trace_measurements") {
                    if let Some(recipe) = TraceRecipeV1::identify(&intent.source)? {
                        sink.charge(128)?;
                        self.trace_recipes
                            .insert(binding.identity.execution_id, recipe);
                    }
                }
                let terminal = receipt.terminal.as_ref();
                self.append("traces", sink, |name, _kind, sink| {
                    Ok(match name {
                        "tenant_id" => Self::binary(Some(&intent.tenant_id), sink)?,
                        "request_id" => Self::binary(Some(&intent.request_id), sink)?,
                        "target_index" => ScalarValue::UInt32(Some(target_index)),
                        "execution_id" => Self::binary(Some(&binding.identity.execution_id), sink)?,
                        "node_id" => Self::text(Some(&binding.identity.node_id), sink)?,
                        "node_boot_id" => Self::binary(Some(&binding.identity.node_boot_id), sink)?,
                        "binding_id" => Self::binary(Some(&binding.binding_id), sink)?,
                        "namespace_uid" => Self::text(Some(&binding.namespace_uid), sink)?,
                        "source" => Self::binary(Some(&intent.source.bytes), sink)?,
                        "source_sha256" => Self::binary(Some(&intent.source.sha256), sink)?,
                        "trace_schema_version" => ScalarValue::UInt32(Some(1)),
                        "request_revision" => ScalarValue::UInt64(Some(state.revision)),
                        "accepted_unix_ns" => ScalarValue::UInt64(Some(intent.accepted_unix_ns)),
                        "deadline_unix_ns" => ScalarValue::UInt64(Some(intent.deadline_unix_ns)),
                        "last_sequence" => ScalarValue::UInt64(Some(receipt.last_sequence)),
                        "output_bytes" => ScalarValue::UInt64(Some(receipt.output_bytes)),
                        "retained_floor" => ScalarValue::UInt64(Some(receipt.retained_floor)),
                        "cancel_requested" => ScalarValue::Boolean(Some(state.cancel_requested)),
                        "read_revoked" => ScalarValue::Boolean(Some(state.read_revoked)),
                        "terminal_reason" => Self::text(
                            terminal.map(|value| match value.reason {
                                TraceTerminalReasonV1::Completed => "completed",
                                TraceTerminalReasonV1::Cancelled => "cancelled",
                                TraceTerminalReasonV1::Deadline => "deadline",
                                TraceTerminalReasonV1::PreparationFailed => "preparation_failed",
                                TraceTerminalReasonV1::TargetChanged => "target_changed",
                                TraceTerminalReasonV1::OutputLimit => "output_limit",
                                TraceTerminalReasonV1::ConsumerSlow => "consumer_slow",
                                TraceTerminalReasonV1::NodeRestarted => "node_restarted",
                                TraceTerminalReasonV1::StorageFailure => "storage_failure",
                                TraceTerminalReasonV1::BackendFailed => "backend_failed",
                            }),
                            sink,
                        )?,
                        "output_incomplete" => {
                            ScalarValue::Boolean(terminal.map(|value| value.output_incomplete))
                        }
                        "kernel_lost_events" => {
                            ScalarValue::UInt64(terminal.and_then(|value| value.kernel_lost_events))
                        }
                        "ready_at_unix_ns" => {
                            ScalarValue::UInt64(terminal.and_then(|value| value.ready_at_unix_ns))
                        }
                        "exit_code" => {
                            ScalarValue::Int32(terminal.and_then(|value| value.exit_code))
                        }
                        "forced_kill" => {
                            ScalarValue::Boolean(terminal.map(|value| value.forced_kill))
                        }
                        "cleanup" => Self::text(
                            terminal.map(|value| match value.cleanup {
                                TraceCleanupV1::Verified => "verified",
                                TraceCleanupV1::Failed => "failed",
                                TraceCleanupV1::Unknown => "unknown",
                            }),
                            sink,
                        )?,
                        _ => {
                            return Err(ArrowBatch::invalid(
                                "the native source field has no adapter",
                            ));
                        }
                    })
                })
            }
            AnalysisInputV1::TraceOutput {
                identity,
                target_index,
                sequence,
                position,
                kind: frame_kind,
                bytes,
            } => {
                if self.sources.contains("trace_output")
                    || self.sources.contains("trace_measurements")
                {
                    sink.grow(&mut self.witnesses)?;
                    sink.charge(identity.node_id.len())?;
                    self.witnesses.push(AnalysisWitnessV1 {
                        identity: identity.clone().into(),
                        cursor: sequence,
                        expires_utc_ns: 0,
                    });
                }
                if !self.append("trace_output", sink, |name, _kind, sink| {
                    Ok(match name {
                        "tenant_id" => Self::binary(Some(&identity.tenant_id), sink)?,
                        "request_id" => Self::binary(Some(&identity.request_id), sink)?,
                        "execution_id" => Self::binary(Some(&identity.execution_id), sink)?,
                        "node_id" => Self::text(Some(&identity.node_id), sink)?,
                        "node_boot_id" => Self::binary(Some(&identity.node_boot_id), sink)?,
                        "source_sha256" => Self::binary(Some(&identity.source_sha256), sink)?,
                        "target_index" => ScalarValue::UInt32(Some(target_index)),
                        "sequence" => ScalarValue::UInt64(Some(sequence)),
                        "commit_revision" => ScalarValue::UInt64(Some(position.commit_revision)),
                        "ordinal" => ScalarValue::UInt32(Some(position.ordinal)),
                        "kind" => Self::text(Some(frame_kind), sink)?,
                        "bytes" => Self::binary(Some(bytes), sink)?,
                        _ => {
                            return Err(ArrowBatch::invalid(
                                "the native source field has no adapter",
                            ));
                        }
                    })
                })? {
                    return Ok(false);
                }
                if frame_kind != "data" || !self.requested.contains_key("trace_measurements") {
                    return Ok(true);
                }
                let Some(recipe) = self.trace_recipes.get(&identity.execution_id).copied() else {
                    return Ok(true);
                };
                sink.charge(
                    bytes
                        .len()
                        .checked_mul(8)
                        .ok_or_else(ArrowBatch::overflow)?,
                )?;
                let frame = TraceFrameV1 {
                    execution_id: identity.execution_id,
                    sequence,
                    kind: TraceFrameKindV1::Data,
                    bytes: bytes.to_vec(),
                };
                if let Some(measurements) = recipe.measurements(&frame) {
                    for measurement in &measurements {
                        if !self.measurement(identity, measurement, sink)? {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    fn measurement(
        &mut self,
        identity: &TraceIdentityV1,
        measurement: &TraceMeasurementV1,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        self.append("trace_measurements", sink, |name, _kind, sink| {
            Ok(match name {
                "tenant_id" => Self::binary(Some(&identity.tenant_id), sink)?,
                "request_id" => Self::binary(Some(&identity.request_id), sink)?,
                "execution_id" => Self::binary(Some(&measurement.execution_id), sink)?,
                "sequence" => ScalarValue::UInt64(Some(measurement.sequence)),
                "ordinal" => ScalarValue::UInt32(Some(u32::from(measurement.ordinal))),
                "syscall_id" => ScalarValue::UInt32(measurement.syscall_id),
                "errno" => ScalarValue::Int64(Some(measurement.errno)),
                "count" => ScalarValue::UInt64(Some(measurement.count)),
                "cumulative" => ScalarValue::Boolean(Some(measurement.cumulative)),
                "atomic_snapshot" => ScalarValue::Boolean(Some(measurement.atomic_snapshot)),
                "unit" => Self::text(Some(&measurement.unit), sink)?,
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            })
        })
    }
}
