use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    error::DiscoverySnafu, CoverageStateV1, EvidenceIdV1, EvidenceIntakeIdentityV1,
    ObservationEnvelopeV1, Result, StaticDecisionKeyV1,
};

pub const DISCOVERY_SCHEMA_VERSION: u32 = 1;
pub const MAX_DISCOVERY_INPUT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DISCOVERY_RECORDS: usize = 1_000_000;
pub const MAX_DISCOVERY_ATOMS: usize = 50_000;

pub(super) struct InputByteLimit(pub(super) usize);

impl std::io::Write for InputByteLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("discovery input exceeds its byte limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DiscoveryDigestV1(pub [u8; 32]);

impl DiscoveryDigestV1 {
    pub fn of(value: &impl Serialize) -> Result<Self> {
        let value = serde_json::to_value(value).map_err(|error| Self::error(&error))?;
        let mut bytes = Vec::new();
        crate::canonical::encode_value(&mut minicbor::Encoder::new(&mut bytes), &value)
            .map_err(|error| Self::error(&error))?;
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-DISCOVERY-V1\0");
        hash.update(bytes);
        Ok(Self(hash.finalize().into()))
    }

    fn error(error: &impl std::fmt::Display) -> crate::Error {
        DiscoverySnafu {
            code: "CANONICAL_ENCODING",
            reason: error.to_string(),
        }
        .build()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryProofKindV1 {
    Synthetic,
    RecordedInput,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordIdV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub durable_cursor: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCoverageV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub expected_records: u64,
    pub coverage_revision: u64,
    pub coverage_interval_id: EvidenceIdV1,
    pub state: CoverageStateV1,
    pub gap_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextBindingV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub subject_revision: String,
    pub image_digest: String,
    pub configuration_digest: String,
    pub process_instance_id: EvidenceIdV1,
    pub entry_instance_id: EvidenceIdV1,
    pub binding_id: EvidenceIdV1,
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub catalog_revision: u64,
    #[serde(deserialize_with = "RecordedStaticKey::deserialize")]
    pub static_key: StaticDecisionKeyV1,
}

#[derive(Deserialize)]
#[serde(remote = "StaticDecisionKeyV1", deny_unknown_fields)]
struct RecordedStaticKey {
    workload_selector_id: String,
    protected_scope_id: String,
    execution_set_id: String,
    entry_kind: crate::EntryKindV1,
    role_id: String,
    process_state_id: String,
    effect_family: crate::EffectFamilyV1,
    operation_id: String,
    object_selector: String,
    binding_lifecycle: crate::BindingLifecycleV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordV1 {
    pub id: DiscoveryRecordIdV1,
    pub original_kernel_sequence: Option<u64>,
    pub observation: ObservationEnvelopeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryInputManifestV1 {
    pub schema_version: u32,
    pub tenant_id: EvidenceIdV1,
    pub source_revision: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub contexts: Vec<DiscoveryContextBindingV1>,
    pub records: Vec<DiscoveryRecordV1>,
}

impl DiscoveryInputManifestV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::require(bytes.len() <= MAX_DISCOVERY_INPUT_BYTES, "INPUT_LIMIT")?;
        let input: Self = serde_json::from_slice(bytes).map_err(|error| {
            DiscoverySnafu {
                code: "INPUT_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        input.validate()?;
        Ok(input)
    }

    pub(crate) fn require(valid: bool, code: &'static str) -> Result<()> {
        if valid {
            Ok(())
        } else {
            DiscoverySnafu {
                code,
                reason: "the input does not meet the recorded-input contract",
            }
            .fail()
        }
    }

    pub fn validate(&self) -> Result<()> {
        Self::require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "SCHEMA_VERSION",
        )?;
        Self::require(!self.tenant_id.is_zero(), "TENANT")?;
        Self::require(
            !self.source_revision.is_empty() && self.source_revision.len() <= 128,
            "SOURCE_REVISION",
        )?;
        Self::require(
            self.records.len() <= MAX_DISCOVERY_RECORDS
                && self.contexts.len() <= MAX_DISCOVERY_RECORDS
                && self.coverage.len() <= 4096,
            "INPUT_LIMIT",
        )?;
        let mut streams = BTreeMap::new();
        for coverage in &self.coverage {
            Self::require(
                coverage.stream.tenant_id == self.tenant_id.to_be_bytes()
                    && !coverage.stream.node_id.is_empty()
                    && coverage.stream.node_id.len() <= 256
                    && coverage.stream.node_boot_id != [0; 16]
                    && coverage.stream.source_id != [0; 16]
                    && coverage.stream.source_epoch > 0
                    && coverage.stream.label_epoch > 0
                    && coverage.first_cursor > 0
                    && coverage.last_cursor >= coverage.first_cursor
                    && coverage.expected_records <= MAX_DISCOVERY_RECORDS as u64
                    && coverage.expected_records
                        <= coverage.last_cursor - coverage.first_cursor + 1
                    && coverage.coverage_revision > 0
                    && !coverage.coverage_interval_id.is_zero(),
                "COVERAGE_IDENTITY",
            )?;
            Self::require(
                coverage.gap_reasons.len() <= 32
                    && coverage
                        .gap_reasons
                        .iter()
                        .all(|reason| !reason.is_empty() && reason.len() <= 128)
                    && (coverage.state != CoverageStateV1::Healthy
                        || coverage.gap_reasons.is_empty()),
                "COVERAGE_STATE",
            )?;
            Self::require(
                streams
                    .insert((&coverage.stream, coverage.cpu_id), coverage)
                    .is_none(),
                "DUPLICATE_STREAM",
            )?;
        }
        for context in &self.contexts {
            Self::require(
                !context.process_instance_id.is_zero()
                    && !context.entry_instance_id.is_zero()
                    && !context.binding_id.is_zero()
                    && context.role_id > 0
                    && context.state_id > 0
                    && context.entry_rule_id > 0
                    && context.catalog_revision > 0,
                "CONTEXT_IDENTITY",
            )?;
            for field in [
                &context.subject_revision,
                &context.image_digest,
                &context.configuration_digest,
                &context.static_key.workload_selector_id,
                &context.static_key.protected_scope_id,
                &context.static_key.execution_set_id,
                &context.static_key.role_id,
                &context.static_key.process_state_id,
                &context.static_key.operation_id,
                &context.static_key.object_selector,
            ] {
                Self::require(!field.is_empty() && field.len() <= 4096, "CONTEXT_FIELD")?;
            }
        }
        for record in &self.records {
            record.observation.validate().map_err(|error| {
                DiscoverySnafu {
                    code: "OBSERVATION",
                    reason: error.to_string(),
                }
                .build()
            })?;
            let observation = &record.observation;
            Self::require(
                record.id.stream.tenant_id == self.tenant_id.to_be_bytes()
                    && observation.tenant_id == self.tenant_id
                    && record.id.stream.node_boot_id == observation.node_boot_id.to_be_bytes()
                    && record.id.stream.source_id == observation.source_id.to_be_bytes()
                    && record.id.stream.source_epoch == observation.source_epoch
                    && record.id.cpu_id == observation.cpu_id
                    && record.id.durable_cursor > 0
                    && record.original_kernel_sequence != Some(0),
                "RECORD_IDENTITY",
            )?;
            let coverage = streams.get(&(&record.id.stream, record.id.cpu_id));
            Self::require(
                coverage.is_some_and(|range| {
                    record.id.durable_cursor >= range.first_cursor
                        && record.id.durable_cursor <= range.last_cursor
                        && record.observation.coverage_interval_id == range.coverage_interval_id
                }),
                "RECORD_OUTSIDE_RANGE",
            )?;
        }
        serde_json::to_writer(InputByteLimit(MAX_DISCOVERY_INPUT_BYTES), self).map_err(
            |error| {
                DiscoverySnafu {
                    code: "INPUT_LIMIT",
                    reason: error.to_string(),
                }
                .build()
            },
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryPhysicalResultV1 {
    Prevented,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAtomKeyV1 {
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub subject_revision: String,
    pub image_digest: String,
    pub configuration_digest: String,
    pub process_instance_id: EvidenceIdV1,
    pub entry_instance_id: EvidenceIdV1,
    pub binding_id: EvidenceIdV1,
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub catalog_revision: u64,
    pub static_key: StaticDecisionKeyV1,
    pub generation: u64,
    pub coverage_interval_id: EvidenceIdV1,
    pub temporal_coverage: crate::TemporalCoverageV1,
    pub effect: crate::KernelEffectEvidenceV1,
    pub proof_kind: DiscoveryProofKindV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAtomV1 {
    pub id: DiscoveryDigestV1,
    pub key: BehaviorAtomKeyV1,
    pub count: u64,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub source_reason: u8,
    pub source_decision: u8,
    pub kernel_result: i32,
    pub physical_result: DiscoveryPhysicalResultV1,
    pub static_key: StaticDecisionKeyV1,
    pub evidence_sample: Vec<DiscoveryRecordIdV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryUnresolvedV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorSnapshotV1 {
    pub schema_version: u32,
    pub input_digest: DiscoveryDigestV1,
    pub content_digest: DiscoveryDigestV1,
    pub proof_kind: DiscoveryProofKindV1,
    pub accepted_records: u64,
    pub included_records: u64,
    pub unresolved_records: u64,
    pub excluded_records: u64,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub atoms: Vec<BehaviorAtomV1>,
    pub unresolved: Vec<DiscoveryUnresolvedV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordedResultV1 {
    pub snapshot: BehaviorSnapshotV1,
    pub duplicate_deliveries: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryStaticPreviewV1 {
    pub input_digest: DiscoveryDigestV1,
    pub snapshot_digest: DiscoveryDigestV1,
    pub source_policy_digest: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub unresolved_records: u64,
    pub simulations: Vec<crate::EffectSimulationV1>,
}
