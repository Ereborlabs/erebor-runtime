use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::model::require;
use super::*;
use crate::analysis::MAX_RESULT_BYTES;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisGapV1,
    ContextSensitivityV1, DiscoveryEncodingSnafu, ProcessorScopeV1, Result,
};

impl crate::CoverageInterval {
    pub fn has_gap(&self) -> bool {
        self.state == "GAPPED"
            || !self.gap_reasons.is_empty()
            || self
                .opening_counters
                .as_ref()
                .zip(self.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    after.lost != before.lost
                        || after.suppressed != before.suppressed
                        || after.unresolved != before.unresolved
                        || after.classifier_miss_count != before.classifier_miss_count
                        || after.attempted < before.attempted
                        || after.requested < before.requested
                        || after.emitted < before.emitted
                        || after.next_sequence < before.next_sequence
                })
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state.as_str(), "HEALTHY" | "CLOSED")
            && !self.has_gap()
            && self
                .opening_counters
                .as_ref()
                .zip(self.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    [before, after].into_iter().all(|counters| {
                        counters.suppressed.checked_add(counters.requested)
                            == Some(counters.attempted)
                            && counters.emitted.checked_add(counters.lost)
                                == Some(counters.requested)
                    }) && before.next_sequence <= self.first_sequence
                        && self
                            .last_sequence
                            .is_some_and(|last| after.next_sequence > last)
                })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProfileV1 {
    pub schema_version: u32,
    pub scope: ProcessorScopeV1,
    pub profile_id: String,
    pub interval_id: String,
    pub revision: u64,
    pub facts_revision: u64,
    pub coverage_revision: u64,
    pub created_utc_ns: u64,
    pub updated_utc_ns: u64,
    pub sealed: bool,
    pub input_bytes: u64,
    pub incomplete: bool,
    pub gaps: Vec<AnalysisGapV1>,
    pub snapshot: BehaviorSnapshotV1,
    pub context_refs: Vec<AnalysisContextRefV1>,
}

impl DiscoveryProfileV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION
                && self.scope.processor_id == DISCOVERY_PROCESSOR
                && self.scope.method_version == DISCOVERY_SCHEMA_VERSION as u64
                && self.scope.identity.valid()
                && self.snapshot.tenant_id == self.scope.identity.tenant_id
                && !self.profile_id.is_empty()
                && self.profile_id.len() <= 256
                && !self.interval_id.is_empty()
                && self.interval_id.len() <= 256
                && self.revision > 0
                && self.created_utc_ns > 0
                && self.updated_utc_ns >= self.created_utc_ns
                && self.input_bytes <= DISCOVERY_INPUT_BYTES as u64
                && self.gaps.len() <= 256
                && (self.gaps.is_empty() || self.incomplete)
                && self.gaps.iter().all(|gap| {
                    gap.first_cursor > 0
                        && gap.last_cursor >= gap.first_cursor
                        && gap.commit_revision > 0
                })
                && self
                    .gaps
                    .windows(2)
                    .all(|pair| pair[0].last_cursor < pair[1].first_cursor)
                && self.context_refs.len() <= 256
                && self
                    .context_refs
                    .windows(2)
                    .all(|pair| pair[0].key < pair[1].key)
                && self.context_refs.iter().all(|reference| {
                    reference.key.tenant_id == self.scope.identity.tenant_id
                        && reference.key.valid()
                        && reference.commit_revision > 0
                })
                && self
                    .snapshot
                    .coverage
                    .iter()
                    .all(|range| range.stream == self.scope.identity),
            "profile bounds",
        )?;
        self.snapshot.validate()
    }
}

impl TryFrom<&[u8]> for DiscoveryProfileV1 {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= MAX_RESULT_BYTES, "profile bytes")?;
        let profile: Self = serde_json::from_slice(bytes).context(DiscoveryEncodingSnafu)?;
        profile.validate()?;
        Ok(profile)
    }
}

impl TryFrom<&DiscoveryPinnedContextV1> for AnalysisContextVersionV1 {
    type Error = crate::Error;

    fn try_from(pinned: &DiscoveryPinnedContextV1) -> Result<Self> {
        pinned.validate()?;
        let binding = &pinned.binding;
        let key = AnalysisContextKeyV1 {
            tenant_id: binding.record_id.stream.tenant_id,
            owner_id: "discovery-facts-v1".into(),
            entity_key: uuid::Uuid::new_v4().as_bytes().to_vec(),
            lifetime_key: binding.record_id.stream.key(),
            owner_revision: pinned.control_commit_index,
        };
        require(key.valid(), "qualified context key")?;
        let body = serde_json::to_vec(&serde_json::json!({
            "subject_revision": binding.subject_revision,
            "image_digest": binding.image_digest,
            "configuration_digest": binding.configuration_digest,
            "process_instance_id": binding.process_instance_id,
            "entry_instance_id": binding.entry_instance_id,
            "binding_id": binding.binding_id,
            "role_id": binding.role_id, "state_id": binding.state_id,
            "entry_rule_id": binding.entry_rule_id, "catalog_revision": binding.catalog_revision,
            "static_key": binding.static_key, "policy_revision": binding.policy_revision,
            "workload": pinned.workload,
            "policy_source_revision_id": pinned.policy_source_revision_id,
            "target_snapshot_digest": pinned.target_snapshot_digest,
            "signed_profile_digest": pinned.signed_profile_digest,
            "control_commit_index": pinned.control_commit_index,
        }))
        .context(DiscoveryEncodingSnafu)?;
        require(body.len() <= DISCOVERY_PIN_BYTES, "qualified context bytes")?;
        Ok(Self {
            key,
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryReplayV1 {
    Available(Box<BehaviorSnapshotV1>),
    Unavailable {
        first_cursor: u64,
        last_cursor: u64,
        reason: String,
    },
}
