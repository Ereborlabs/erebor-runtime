use araphor_data::{
    AnalysisInputV1, AnalysisWitnessV1, BehaviorAtomV1, DiscoveryPhysicalResultV1,
    DiscoveryProfileV1, DiscoveryProofKindV1, ProjectionSink, Selection,
};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn discovery(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let AnalysisInputV1::Profile {
            result_id,
            body,
            commit_revision,
            sources,
            discovery_enabled,
        } = input
        else {
            return Ok(true);
        };
        if !self.sources.contains("behaviors") {
            return Ok(true);
        }
        sink.charge(body.len().checked_mul(4).ok_or_else(ArrowBatch::overflow)?)?;
        let profile = DiscoveryProfileV1::try_from(body)?;
        if profile.profile_id != result_id || !sources.contains(&profile.scope.identity) {
            return Err(ArrowBatch::invalid(
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
            && !self.behavior(&profile, None, commit_revision, discovery_enabled, sink)?
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
                sink.grow(&mut self.witnesses)?;
                sink.charge(evidence.stream.node_id.len())?;
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
                sink,
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
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let key = atom.map(|atom| &atom.key);
        let identity = &profile.scope.identity;
        let proof = |value| match value {
            DiscoveryProofKindV1::ObservedRuntime => "observed_runtime",
            DiscoveryProofKindV1::RecordedInput => "recorded_input",
            DiscoveryProofKindV1::Synthetic => "synthetic",
            DiscoveryProofKindV1::ConfigurationScan => "configuration_scan",
        };
        self.append("behaviors", sink, |name, kind, sink| {
            Ok(match name {
                "tenant_id" => Self::binary(Some(&identity.tenant_id), sink)?,
                "node_id" => Self::text(Some(&identity.node_id), sink)?,
                "node_boot_id" => Self::binary(Some(&identity.node_boot_id), sink)?,
                "label_epoch" => ScalarValue::UInt64(Some(identity.label_epoch)),
                "source_id" => Self::binary(Some(&identity.source_id), sink)?,
                "source_epoch" => ScalarValue::UInt64(Some(identity.source_epoch)),
                "cpu_id" => ScalarValue::UInt32(key.map(|value| value.cpu_id)),
                "profile_id" => Self::text(Some(&profile.profile_id), sink)?,
                "interval_id" => Self::text(Some(&profile.interval_id), sink)?,
                "profile_revision" => ScalarValue::UInt64(Some(profile.revision)),
                "facts_revision" => ScalarValue::UInt64(Some(profile.facts_revision)),
                "coverage_revision" => ScalarValue::UInt64(Some(profile.coverage_revision)),
                "method_version" => ScalarValue::UInt64(Some(profile.scope.method_version)),
                "commit_revision" => ScalarValue::UInt64(Some(commit_revision)),
                "profile_state" => {
                    Self::text(Some(if profile.sealed { "sealed" } else { "open" }), sink)?
                }
                "created_utc_ns" => ScalarValue::UInt64(Some(profile.created_utc_ns)),
                "updated_utc_ns" => ScalarValue::UInt64(Some(profile.updated_utc_ns)),
                "input_bytes" => ScalarValue::UInt64(Some(profile.input_bytes)),
                "incomplete" => ScalarValue::Boolean(Some(profile.incomplete)),
                "kind" => Self::text(Some(if atom.is_some() { "atom" } else { "summary" }), sink)?,
                "source_revision" => Self::text(Some(&profile.snapshot.source_revision), sink)?,
                "proof_kind" => Self::text(
                    Some(proof(
                        key.map_or(profile.snapshot.proof_kind, |key| key.proof_kind),
                    )),
                    sink,
                )?,
                "accepted_records" => {
                    ScalarValue::UInt64(atom.is_none().then_some(profile.snapshot.accepted_records))
                }
                "included_records" => {
                    ScalarValue::UInt64(atom.is_none().then_some(profile.snapshot.included_records))
                }
                "unresolved_records" => ScalarValue::UInt64(
                    atom.is_none()
                        .then_some(profile.snapshot.unresolved_records),
                ),
                "excluded_records" => {
                    ScalarValue::UInt64(atom.is_none().then_some(profile.snapshot.excluded_records))
                }
                "atom_key" => {
                    if let Some(key) = key {
                        Self::json(key, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "subject_revision" => {
                    Self::text(key.map(|value| value.subject_revision.as_str()), sink)?
                }
                "image_digest" => Self::text(key.map(|value| value.image_digest.as_str()), sink)?,
                "configuration_digest" => {
                    Self::text(key.map(|value| value.configuration_digest.as_str()), sink)?
                }
                "process_instance_id" => {
                    Self::binary(key.map(|value| value.process_instance_id.as_slice()), sink)?
                }
                "entry_instance_id" => {
                    Self::binary(key.map(|value| value.entry_instance_id.as_slice()), sink)?
                }
                "binding_id" => Self::binary(key.map(|value| value.binding_id.as_slice()), sink)?,
                "role_id" => ScalarValue::UInt32(key.map(|value| value.role_id)),
                "state_id" => ScalarValue::UInt32(key.map(|value| value.state_id)),
                "entry_rule_id" => ScalarValue::UInt32(key.map(|value| value.entry_rule_id)),
                "catalog_revision" => ScalarValue::UInt64(key.map(|value| value.catalog_revision)),
                "generation" => ScalarValue::UInt64(key.map(|value| value.generation)),
                "coverage_interval_id" => {
                    Self::binary(key.map(|value| value.coverage_interval_id.as_slice()), sink)?
                }
                "temporal_coverage" => ScalarValue::Int32(key.map(|value| value.temporal_coverage)),
                "operation_id" => Self::text(
                    key.map(|value| value.static_key.operation_id.as_str()),
                    sink,
                )?,
                "static_key" => {
                    if let Some(key) = key {
                        Self::json(&key.static_key, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "policy_revision" => {
                    if let Some(key) = key {
                        Self::json(&key.policy_revision, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "effect" => {
                    if let Some(key) = key {
                        Self::json(&key.effect, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "source_reason" => ScalarValue::UInt32(key.map(|value| value.effect.reason)),
                "source_decision" => ScalarValue::UInt32(key.map(|value| value.effect.decision)),
                "kernel_result" => ScalarValue::Int32(key.map(|value| value.effect.kernel_result)),
                "physical_result" => Self::text(
                    key.map(|value| match value.physical_result {
                        DiscoveryPhysicalResultV1::Prevented => "prevented",
                        DiscoveryPhysicalResultV1::Unknown => "unknown",
                    }),
                    sink,
                )?,
                "record_count" => ScalarValue::UInt64(Some(
                    atom.map_or(profile.snapshot.accepted_records, |value| value.count),
                )),
                "first_cursor" => ScalarValue::UInt64(atom.map(|value| value.first_cursor)),
                "last_cursor" => ScalarValue::UInt64(atom.map(|value| value.last_cursor)),
                "evidence_sample" => {
                    if let Some(atom) = atom {
                        Self::json(&atom.evidence_sample, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "coverage" => Self::json(&profile.snapshot.coverage, sink)?,
                "lifecycle" => {
                    if atom.is_none() {
                        Self::json(&profile.snapshot.lifecycle, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "gaps" => {
                    if atom.is_none() {
                        Self::json(&profile.gaps, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "context_refs" => {
                    if atom.is_none() {
                        Self::json(&profile.context_refs, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "effect_family" => ScalarValue::UInt32(key.map(|value| value.effect.effect_family)),
                "operation" => ScalarValue::UInt32(key.map(|value| value.effect.operation)),
                "operation_argument" => {
                    ScalarValue::UInt32(key.and_then(|value| value.effect.operation_argument))
                }
                "configured_errno" => {
                    ScalarValue::Int32(key.map(|value| value.effect.configured_errno))
                }
                "exact_object_id" => Self::binary(
                    key.map(|value| value.effect.exact_object_id.as_slice()),
                    sink,
                )?,
                "task_cookie" => ScalarValue::UInt64(key.map(|value| value.effect.task_cookie)),
                "target_task_cookie" => {
                    ScalarValue::UInt64(key.and_then(|value| value.effect.target_task_cookie))
                }
                "unresolved" => {
                    if atom.is_none() {
                        Self::json(&profile.snapshot.unresolved, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "excluded" => {
                    if atom.is_none() {
                        Self::json(&profile.snapshot.excluded, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "discovery_enabled" => ScalarValue::Boolean(Some(discovery_enabled)),
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            })
        })
    }
}
