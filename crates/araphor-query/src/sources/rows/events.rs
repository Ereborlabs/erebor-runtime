use araphor_data::{AnalysisInputV1, AnalysisWitnessV1, ProjectionSink};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn event(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let AnalysisInputV1::Event {
            identity,
            cpu_id,
            received_utc_ns,
            record,
            decoded,
        } = input
        else {
            return Ok(true);
        };
        if !self.sources.contains("events") {
            return Ok(true);
        }
        if self.inputs.is_some_and(|inputs| {
            !inputs
                .ranges
                .iter()
                .any(|(first, last)| (*first..=*last).contains(&received_utc_ns))
        }) {
            return Ok(true);
        }
        sink.grow(&mut self.witnesses)?;
        sink.charge(identity.node_id.len())?;
        self.witnesses.push(AnalysisWitnessV1 {
            identity: identity.clone().into(),
            cursor: record.cursor,
            expires_utc_ns: 0,
        });
        self.received_min = Some(
            self.received_min
                .map_or(received_utc_ns, |value| value.min(received_utc_ns)),
        );
        if !self.requested.contains_key("events") {
            return Ok(true);
        }
        let decoded = decoded
            .ok_or_else(|| ArrowBatch::invalid("a selected event has no decoded evidence"))?;
        let context = decoded.decision_context.as_ref();
        let exact = context.and_then(|context| context.exact_file_object.as_ref());
        self.append("events", sink, |name, _kind, sink| {
            let value = match name {
                "tenant_id" => Self::binary(Some(&identity.tenant_id), sink)?,
                "node_id" => Self::text(Some(&identity.node_id), sink)?,
                "node_boot_id" => Self::binary(Some(&identity.node_boot_id), sink)?,
                "label_epoch" => ScalarValue::UInt64(Some(identity.label_epoch)),
                "source_id" => Self::binary(Some(&identity.source_id), sink)?,
                "source_epoch" => ScalarValue::UInt64(Some(identity.source_epoch)),
                "cpu_id" => ScalarValue::UInt32(Some(cpu_id)),
                "source_cursor" => ScalarValue::UInt64(Some(record.cursor)),
                "commit_revision" => ScalarValue::UInt64(Some(record.position.commit_revision)),
                "ordinal" => ScalarValue::UInt32(Some(record.position.ordinal)),
                "received_utc_ns" => ScalarValue::UInt64(Some(received_utc_ns)),
                "received_at" => ScalarValue::TimestampMicrosecond(
                    Some(
                        i64::try_from(received_utc_ns / 1_000)
                            .map_err(|_| ArrowBatch::overflow())?,
                    ),
                    None,
                ),
                "observed_boottime_ns" => ScalarValue::UInt64(Some(decoded.observed_boottime_ns)),
                "ingested_utc_ns" => ScalarValue::Int64(Some(decoded.ingested_utc_ns)),
                "coverage_interval_id" => Self::binary(Some(&decoded.coverage_interval_id), sink)?,
                "profile_generation_ref_id" => {
                    ScalarValue::UInt64(decoded.profile_generation_ref_id)
                }
                "task_cookie" => ScalarValue::UInt64(Some(decoded.task_cookie)),
                "process_lineage_id" => Self::binary(Some(&decoded.process_lineage_id), sink)?,
                "authority_domain_id" => Self::binary(Some(&decoded.authority_domain_id), sink)?,
                "execution_set_id" => Self::binary(Some(&decoded.execution_set_id), sink)?,
                "exact_object_id" => Self::binary(Some(&decoded.exact_object_id), sink)?,
                "destination_id" => ScalarValue::UInt64(Some(decoded.destination_id)),
                "policy_rule_id" => ScalarValue::UInt64(Some(decoded.policy_rule_id)),
                "reason" => ScalarValue::UInt32(Some(decoded.reason)),
                "decision" => ScalarValue::UInt32(Some(decoded.decision)),
                "effect_family" => ScalarValue::UInt32(Some(decoded.effect_family)),
                "operation" => ScalarValue::UInt32(Some(decoded.operation)),
                "configured_errno" => ScalarValue::Int32(Some(decoded.configured_errno)),
                "kernel_result" => ScalarValue::Int32(Some(decoded.kernel_result)),
                "temporal_coverage" => ScalarValue::Int32(Some(decoded.temporal_coverage)),
                "target_task_cookie" => ScalarValue::UInt64(decoded.target_task_cookie),
                "operation_argument" => ScalarValue::UInt32(decoded.operation_argument),
                "context_schema_version" => {
                    ScalarValue::UInt32(context.map(|value| value.schema_version))
                }
                "kernel_sequence" => {
                    ScalarValue::UInt64(context.map(|value| value.original_kernel_sequence))
                }
                "process_instance_id" => Self::binary(
                    context.map(|value| value.process_instance_id.as_slice()),
                    sink,
                )?,
                "entry_instance_id" => Self::binary(
                    context.map(|value| value.entry_instance_id.as_slice()),
                    sink,
                )?,
                "binding_id" => {
                    Self::binary(context.map(|value| value.binding_id.as_slice()), sink)?
                }
                "context_profile_generation_ref_id" => {
                    ScalarValue::UInt64(context.map(|value| value.profile_generation_ref_id))
                }
                "role_id" => ScalarValue::UInt32(context.map(|value| value.role_id)),
                "state_id" => ScalarValue::UInt32(context.map(|value| value.state_id)),
                "entry_rule_id" => ScalarValue::UInt32(context.map(|value| value.entry_rule_id)),
                "exact_object_key_id" => {
                    ScalarValue::UInt64(context.map(|value| value.exact_object_key_id))
                }
                "composite_atom_id" => {
                    ScalarValue::UInt64(context.map(|value| value.composite_atom_id))
                }
                "catalog_json" => {
                    Self::binary(context.map(|value| value.catalog_json.as_slice()), sink)?
                }
                "catalog_state" => {
                    Self::text(context.map(|value| value.catalog_state.as_str()), sink)?
                }
                "exact_profile_generation_ref_id" => {
                    ScalarValue::UInt64(exact.map(|value| value.profile_generation_ref_id))
                }
                "mount_id_unique" => ScalarValue::UInt64(exact.map(|value| value.mount_id_unique)),
                "inode" => ScalarValue::UInt64(exact.map(|value| value.inode)),
                "inode_generation" => {
                    ScalarValue::UInt64(exact.map(|value| value.inode_generation))
                }
                "mount_namespace_inode" => {
                    ScalarValue::UInt32(exact.map(|value| value.mount_namespace_inode))
                }
                "filesystem_device" => {
                    ScalarValue::UInt32(exact.map(|value| value.filesystem_device))
                }
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            };
            Ok(value)
        })
    }
}
