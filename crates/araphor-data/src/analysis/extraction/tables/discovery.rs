use super::*;
use crate::{
    BehaviorAtomV1, DiscoveryPhysicalResultV1, DiscoveryProfileV1, DiscoveryProofKindV1,
    EvidenceIntakeIdentityV1, Selection,
};

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn profile(
        &mut self,
        result_id: &str,
        body: &[u8],
        commit_revision: u64,
        sources: &[EvidenceIntakeIdentityV1],
        discovery_enabled: bool,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if !self.read.relations.contains("behaviors") {
            return Ok(true);
        }
        budget.charge(body.len().checked_mul(4).ok_or_else(overflow)?)?;
        let profile = DiscoveryProfileV1::try_from(body)?;
        if profile.profile_id != result_id || !sources.contains(&profile.scope.identity) {
            return Err(invalid(
                "the discovery result differs from its retained profile identity",
            ));
        }
        if !self.scope.nodes.is_empty()
            && !self.scope.nodes.contains(&profile.scope.identity.node_id)
        {
            return Ok(true);
        }
        if let Selection::Exact(sources) = &self.scope.sources {
            if !sources.contains(&profile.scope.identity) {
                return Ok(true);
            }
        }
        self.mutable_discovery |= !profile.sealed;
        if self.scope.binding_ids.is_empty()
            && !self.behavior(&profile, None, commit_revision, discovery_enabled, budget)?
        {
            return Ok(false);
        }
        for atom in &profile.snapshot.atoms {
            if !self.scope.binding_ids.is_empty()
                && !self.scope.binding_ids.contains(&atom.key.binding_id)
            {
                continue;
            }
            for evidence in &atom.evidence_sample {
                budget.grow(&mut self.witnesses)?;
                budget.charge(evidence.stream.node_id.len())?;
                self.witnesses.push(AnalysisWitnessV1 {
                    identity: evidence.stream.clone().into(),
                    cursor: evidence.durable_cursor,
                    expires_utc_ns: 0,
                });
            }
            if !self.behavior(
                &profile,
                Some(atom),
                commit_revision,
                discovery_enabled,
                budget,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn behavior(
        &mut self,
        profile: &DiscoveryProfileV1,
        atom: Option<&BehaviorAtomV1>,
        commit_revision: u64,
        discovery_enabled: bool,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        let key = atom.map(|atom| &atom.key);
        let identity = &profile.scope.identity;
        let proof = |value| match value {
            DiscoveryProofKindV1::ObservedRuntime => "observed_runtime",
            DiscoveryProofKindV1::RecordedInput => "recorded_input",
            DiscoveryProofKindV1::Synthetic => "synthetic",
            DiscoveryProofKindV1::ConfigurationScan => "configuration_scan",
        };
        table_row!(self,"behaviors",budget;
            tenant_id=>Binary:Some(&identity.tenant_id),
            node_id=>Utf8:Some(&identity.node_id),
            node_boot_id=>Binary:Some(&identity.node_boot_id),
            label_epoch=>UInt64:Some(identity.label_epoch),
            source_id=>Binary:Some(&identity.source_id),
            source_epoch=>UInt64:Some(identity.source_epoch),
            cpu_id=>UInt32:key.map(|value|value.cpu_id),
            profile_id=>Utf8:Some(&profile.profile_id),
            interval_id=>Utf8:Some(&profile.interval_id),
            profile_revision=>UInt64:Some(profile.revision),
            facts_revision=>UInt64:Some(profile.facts_revision),
            coverage_revision=>UInt64:Some(profile.coverage_revision),
            method_version=>UInt64:Some(profile.scope.method_version),
            commit_revision=>UInt64:Some(commit_revision),
            profile_state=>Utf8:Some(if profile.sealed{"sealed"}else{"open"}),
            created_utc_ns=>UInt64:Some(profile.created_utc_ns),
            updated_utc_ns=>UInt64:Some(profile.updated_utc_ns),
            input_bytes=>UInt64:Some(profile.input_bytes),
            incomplete=>Boolean:Some(profile.incomplete),
            kind=>Utf8:Some(if atom.is_some(){"atom"}else{"summary"}),
            source_revision=>Utf8:Some(&profile.snapshot.source_revision),
            proof_kind=>Utf8:Some(proof(key.map_or(profile.snapshot.proof_kind,|key|key.proof_kind))),
            accepted_records=>UInt64:atom.is_none().then_some(profile.snapshot.accepted_records),
            included_records=>UInt64:atom.is_none().then_some(profile.snapshot.included_records),
            unresolved_records=>UInt64:atom.is_none().then_some(profile.snapshot.unresolved_records),
            excluded_records=>UInt64:atom.is_none().then_some(profile.snapshot.excluded_records),
            atom_key=>Json:key,
            subject_revision=>Utf8:key.map(|value|value.subject_revision.as_str()),
            image_digest=>Utf8:key.map(|value|value.image_digest.as_str()),
            configuration_digest=>Utf8:key.map(|value|value.configuration_digest.as_str()),
            process_instance_id=>Binary:key.map(|value|value.process_instance_id.as_slice()),
            entry_instance_id=>Binary:key.map(|value|value.entry_instance_id.as_slice()),
            binding_id=>Binary:key.map(|value|value.binding_id.as_slice()),
            role_id=>UInt32:key.map(|value|value.role_id),
            state_id=>UInt32:key.map(|value|value.state_id),
            entry_rule_id=>UInt32:key.map(|value|value.entry_rule_id),
            catalog_revision=>UInt64:key.map(|value|value.catalog_revision),
            generation=>UInt64:key.map(|value|value.generation),
            coverage_interval_id=>Binary:key.map(|value|value.coverage_interval_id.as_slice()),
            temporal_coverage=>Int32:key.map(|value|value.temporal_coverage),
            operation_id=>Utf8:key.map(|value|value.static_key.operation_id.as_str()),
            static_key=>Json:key.map(|value|&value.static_key),
            policy_revision=>Json:key.map(|value|&value.policy_revision),
            effect=>Json:key.map(|value|&value.effect),
            source_reason=>UInt32:key.map(|value|value.effect.reason),
            source_decision=>UInt32:key.map(|value|value.effect.decision),
            kernel_result=>Int32:key.map(|value|value.effect.kernel_result),
            physical_result=>Utf8:key.map(|value|match value.physical_result {DiscoveryPhysicalResultV1::Prevented=>"prevented",DiscoveryPhysicalResultV1::Unknown=>"unknown"}),
            record_count=>UInt64:Some(atom.map_or(profile.snapshot.accepted_records,|value|value.count)),
            first_cursor=>UInt64:atom.map(|value|value.first_cursor),
            last_cursor=>UInt64:atom.map(|value|value.last_cursor),
            evidence_sample=>Json:atom.map(|value|&value.evidence_sample),
            coverage=>Json:Some(&profile.snapshot.coverage),
            lifecycle=>Json:atom.is_none().then_some(&profile.snapshot.lifecycle),
            gaps=>Json:atom.is_none().then_some(&profile.gaps),
            context_refs=>Json:atom.is_none().then_some(&profile.context_refs),
            effect_family=>UInt32:key.map(|value|value.effect.effect_family),
            operation=>UInt32:key.map(|value|value.effect.operation),
            operation_argument=>UInt32:key.and_then(|value|value.effect.operation_argument),
            configured_errno=>Int32:key.map(|value|value.effect.configured_errno),
            exact_object_id=>Binary:key.map(|value|value.effect.exact_object_id.as_slice()),
            task_cookie=>UInt64:key.map(|value|value.effect.task_cookie),
            target_task_cookie=>UInt64:key.and_then(|value|value.effect.target_task_cookie),
            unresolved=>Json:atom.is_none().then_some(&profile.snapshot.unresolved),
            excluded=>Json:atom.is_none().then_some(&profile.snapshot.excluded),
            discovery_enabled=>Boolean:Some(discovery_enabled),
        )
    }
}
