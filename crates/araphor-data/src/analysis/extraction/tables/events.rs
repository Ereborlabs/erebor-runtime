use super::*;
use crate::{AnalysisRecordV1, EvidenceIntakeIdentityV1, EvidenceRecord};

impl Capture<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis::extraction) fn event(
        &mut self,
        identity: &EvidenceIntakeIdentityV1,
        cpu_id: u32,
        received_utc_ns: u64,
        record: &AnalysisRecordV1,
        decoded: Option<&EvidenceRecord>,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if !self.read.relations.contains("events") {
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
        if !self.read.columns.contains_key("events") {
            return Ok(true);
        }
        let decoded = decoded.ok_or_else(|| invalid("a selected event has no decoded evidence"))?;
        let context = decoded.decision_context.as_ref();
        let exact = context.and_then(|value| value.exact_file_object.as_ref());
        table_row!(self,"events",budget;
            tenant_id => Binary: Some(&identity.tenant_id),
            node_id => Utf8: Some(&identity.node_id),
            node_boot_id => Binary: Some(&identity.node_boot_id),
            label_epoch => UInt64: Some(identity.label_epoch),
            source_id => Binary: Some(&identity.source_id),
            source_epoch => UInt64: Some(identity.source_epoch),
            cpu_id => UInt32: Some(cpu_id),
            source_cursor => UInt64: Some(record.cursor),
            commit_revision => UInt64: Some(record.position.commit_revision),
            ordinal => UInt32: Some(record.position.ordinal),
            received_utc_ns => UInt64: Some(received_utc_ns),
            received_at => TimestampMicrosecond: Some(i64::try_from(received_utc_ns/1000).map_err(|_|overflow())?),
            observed_boottime_ns => UInt64: Some(decoded.observed_boottime_ns),
            ingested_utc_ns => Int64: Some(decoded.ingested_utc_ns),
            coverage_interval_id => Binary: Some(&decoded.coverage_interval_id),
            profile_generation_ref_id => UInt64: decoded.profile_generation_ref_id,
            task_cookie => UInt64: Some(decoded.task_cookie),
            process_lineage_id => Binary: Some(&decoded.process_lineage_id),
            authority_domain_id => Binary: Some(&decoded.authority_domain_id),
            execution_set_id => Binary: Some(&decoded.execution_set_id),
            exact_object_id => Binary: Some(&decoded.exact_object_id),
            destination_id => UInt64: Some(decoded.destination_id),
            policy_rule_id => UInt64: Some(decoded.policy_rule_id),
            reason => UInt32: Some(decoded.reason),
            decision => UInt32: Some(decoded.decision),
            effect_family => UInt32: Some(decoded.effect_family),
            operation => UInt32: Some(decoded.operation),
            configured_errno => Int32: Some(decoded.configured_errno),
            kernel_result => Int32: Some(decoded.kernel_result),
            temporal_coverage => Int32: Some(decoded.temporal_coverage),
            target_task_cookie => UInt64: decoded.target_task_cookie,
            operation_argument => UInt32: decoded.operation_argument,
            context_schema_version => UInt32: context.map(|value|value.schema_version),
            kernel_sequence => UInt64: context.map(|value|value.original_kernel_sequence),
            process_instance_id => Binary: context.map(|value|value.process_instance_id.as_slice()),
            entry_instance_id => Binary: context.map(|value|value.entry_instance_id.as_slice()),
            binding_id => Binary: context.map(|value|value.binding_id.as_slice()),
            context_profile_generation_ref_id => UInt64: context.map(|value|value.profile_generation_ref_id),
            role_id => UInt32: context.map(|value|value.role_id),
            state_id => UInt32: context.map(|value|value.state_id),
            entry_rule_id => UInt32: context.map(|value|value.entry_rule_id),
            exact_object_key_id => UInt64: context.map(|value|value.exact_object_key_id),
            composite_atom_id => UInt64: context.map(|value|value.composite_atom_id),
            catalog_json => Binary: context.map(|value|value.catalog_json.as_slice()),
            catalog_state => Utf8: context.map(|value|value.catalog_state.as_str()),
            exact_profile_generation_ref_id => UInt64: exact.map(|value|value.profile_generation_ref_id),
            mount_id_unique => UInt64: exact.map(|value|value.mount_id_unique),
            inode => UInt64: exact.map(|value|value.inode),
            inode_generation => UInt64: exact.map(|value|value.inode_generation),
            mount_namespace_inode => UInt32: exact.map(|value|value.mount_namespace_inode),
            filesystem_device => UInt32: exact.map(|value|value.filesystem_device),
        )
    }
}
