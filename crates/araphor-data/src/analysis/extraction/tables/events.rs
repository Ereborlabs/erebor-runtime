use super::*;
use crate::{AnalysisRecordV1, EvidenceIntakeIdentityV1, EvidenceRecord};

impl Capture<'_> {
    table_row! {
        #[allow(clippy::too_many_arguments)]
        pub(in crate::analysis::extraction) fn event(
            &mut self,
            identity: &EvidenceIntakeIdentityV1,
            cpu_id: u32,
            received_utc_ns: u64,
            record: &AnalysisRecordV1,
            decoded: Option<&EvidenceRecord>,
            budget: &mut ReadBudget<'_>,
        );
        schema event_fields;
        row(self, "events", budget);
        setup {
            if !self.read.requests.contains_key("events") {
                return Ok(true);
            }
            if self.read.event_ranges.is_some_and(|ranges| {
                !ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&received_utc_ns))
            }) {
                return Ok(true);
            }
            budget.grow(&mut self.witnesses)?;
            budget.charge(identity.node_id.len())?;
            self.witnesses.push(AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor: record.cursor,
                expires_utc_ns: 0,
            });
            self.received_min = Some(
                self.received_min
                    .map_or(received_utc_ns, |value| value.min(received_utc_ns)),
            );
            if self.read.projected("events").is_none() {
                return Ok(true);
            }
            let context = decoded.and_then(|value| value.decision_context.as_ref());
            let exact = context.and_then(|value| value.exact_file_object.as_ref());
        }
        fields {
            tenant_id => Binary(false): Some(&identity.tenant_id),
            node_id => Utf8(false): Some(&identity.node_id),
            node_boot_id => Binary(false): Some(&identity.node_boot_id),
            label_epoch => UInt64(false): Some(identity.label_epoch),
            source_id => Binary(false): Some(&identity.source_id),
            source_epoch => UInt64(false): Some(identity.source_epoch),
            cpu_id => UInt32(false): Some(cpu_id),
            source_cursor => UInt64(false): Some(record.cursor),
            commit_revision => UInt64(false): Some(record.position.commit_revision),
            ordinal => UInt32(false): Some(record.position.ordinal),
            received_utc_ns => UInt64(false): Some(received_utc_ns),
            received_at => TimestampMicrosecond(false): Some(i64::try_from(received_utc_ns/1000).map_err(|_|overflow())?),
            observed_boottime_ns => UInt64(false): decoded.map(|value| value.observed_boottime_ns),
            ingested_utc_ns => Int64(false): decoded.map(|value| value.ingested_utc_ns),
            coverage_interval_id => Binary(false): decoded.map(|value| value.coverage_interval_id.as_ref()),
            profile_generation_ref_id => UInt64(true): decoded.and_then(|value| value.profile_generation_ref_id),
            task_cookie => UInt64(false): decoded.map(|value| value.task_cookie),
            process_lineage_id => Binary(false): decoded.map(|value| value.process_lineage_id.as_ref()),
            authority_domain_id => Binary(false): decoded.map(|value| value.authority_domain_id.as_ref()),
            execution_set_id => Binary(false): decoded.map(|value| value.execution_set_id.as_ref()),
            exact_object_id => Binary(false): decoded.map(|value| value.exact_object_id.as_ref()),
            destination_id => UInt64(false): decoded.map(|value| value.destination_id),
            policy_rule_id => UInt64(false): decoded.map(|value| value.policy_rule_id),
            reason => UInt32(false): decoded.map(|value| value.reason),
            decision => UInt32(false): decoded.map(|value| value.decision),
            effect_family => UInt32(false): decoded.map(|value| value.effect_family),
            operation => UInt32(false): decoded.map(|value| value.operation),
            configured_errno => Int32(false): decoded.map(|value| value.configured_errno),
            kernel_result => Int32(false): decoded.map(|value| value.kernel_result),
            temporal_coverage => Int32(false): decoded.map(|value| value.temporal_coverage),
            target_task_cookie => UInt64(true): decoded.and_then(|value| value.target_task_cookie),
            operation_argument => UInt32(true): decoded.and_then(|value| value.operation_argument),
            context_schema_version => UInt32(true): context.map(|value|value.schema_version),
            kernel_sequence => UInt64(true): context.map(|value|value.original_kernel_sequence),
            process_instance_id => Binary(true): context.map(|value|value.process_instance_id.as_slice()),
            entry_instance_id => Binary(true): context.map(|value|value.entry_instance_id.as_slice()),
            binding_id => Binary(true): context.map(|value|value.binding_id.as_slice()),
            context_profile_generation_ref_id => UInt64(true): context.map(|value|value.profile_generation_ref_id),
            role_id => UInt32(true): context.map(|value|value.role_id),
            state_id => UInt32(true): context.map(|value|value.state_id),
            entry_rule_id => UInt32(true): context.map(|value|value.entry_rule_id),
            exact_object_key_id => UInt64(true): context.map(|value|value.exact_object_key_id),
            composite_atom_id => UInt64(true): context.map(|value|value.composite_atom_id),
            catalog_json => Binary(true): context.map(|value|value.catalog_json.as_slice()),
            catalog_state => Utf8(true): context.map(|value|value.catalog_state.as_str()),
            exact_profile_generation_ref_id => UInt64(true): exact.map(|value|value.profile_generation_ref_id),
            mount_id_unique => UInt64(true): exact.map(|value|value.mount_id_unique),
            inode => UInt64(true): exact.map(|value|value.inode),
            inode_generation => UInt64(true): exact.map(|value|value.inode_generation),
            mount_namespace_inode => UInt32(true): exact.map(|value|value.mount_namespace_inode),
            filesystem_device => UInt32(true): exact.map(|value|value.filesystem_device),
            framed_record => Binary(false): Some(record.framed_record.as_slice()),
        }
    }
}
