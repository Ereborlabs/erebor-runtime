use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    AnalysisRecordV1, DiscoveryConflictSnafu, DiscoveryEncodingSnafu, DiscoveryInvalidSnafu, Error,
    EvidenceIntakeIdentityV1, EvidenceRecord, Result, WorkloadTargetFactV1,
};

pub use araphor_analysis_builtins::discovery::{
    BehaviorAtomKeyV1, BehaviorAtomV1, BehaviorDisplayGroupV1, BehaviorDisplayKeyV1,
    DiscoveryComparisonV1, DiscoveryContextBindingV1, DiscoveryCoverageStateV1,
    DiscoveryCoverageV1, DiscoveryEffectKeyV1, DiscoveryFileObjectV1, DiscoveryGroupChangeV1,
    DiscoveryLifecycleCaseV1, DiscoveryLifecycleEntryV1, DiscoveryLifecycleStateV1,
    DiscoveryPhysicalResultV1, DiscoveryPolicyKeyV1, DiscoveryPolicyRevisionV1,
    DiscoveryProofKindV1, DiscoveryRecordIdV1, DiscoveryUnresolvedV1,
};

pub trait DiscoveryValidate {
    fn validate(&self) -> Result<()>;
}

pub const DISCOVERY_SCHEMA_VERSION: u32 = 3;
pub const DISCOVERY_INPUT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DISCOVERY_RECORDS: usize = 1_000_000;
pub const MAX_DISCOVERY_ATOMS: usize = 50_000;
pub const DISCOVERY_PIN_BYTES: usize = 32 * 1024;
pub const MAX_DISCOVERY_SAMPLES: usize = 8;

pub struct InputByteLimit(pub usize);

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

pub(crate) fn require(valid: bool, field: &'static str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        DiscoveryInvalidSnafu { field }.fail()
    }
}

pub(crate) fn same(valid: bool, kind: &'static str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        DiscoveryConflictSnafu { kind }.fail()
    }
}

pub(crate) fn add(count: &mut u64, value: u64) -> Result<()> {
    *count = count
        .checked_add(value)
        .ok_or_else(|| DiscoveryInvalidSnafu { field: "count" }.build())?;
    Ok(())
}

impl DiscoveryValidate for DiscoveryRecordIdV1 {
    fn validate(&self) -> Result<()> {
        require(
            self.stream.valid() && self.durable_cursor > 0,
            "record identity",
        )
    }
}

impl DiscoveryValidate for DiscoveryCoverageV1 {
    fn validate(&self) -> Result<()> {
        require(
            self.stream.valid()
                && self.first_cursor > 0
                && self.last_cursor >= self.first_cursor
                && self.expected_records <= MAX_DISCOVERY_RECORDS as u64
                && self.expected_records <= self.last_cursor - self.first_cursor + 1
                && (self.coverage_revision > 0
                    || (matches!(
                        self.state,
                        DiscoveryCoverageStateV1::Unknown | DiscoveryCoverageStateV1::Gapped
                    ) && !self.gap_reasons.is_empty()))
                && self.coverage_interval_id != [0; 16],
            "coverage identity",
        )?;
        require(
            self.gap_reasons.len() <= 32
                && self
                    .gap_reasons
                    .iter()
                    .all(|reason| !reason.is_empty() && reason.len() <= 128)
                && (self.state != DiscoveryCoverageStateV1::Healthy || self.gap_reasons.is_empty()),
            "coverage state",
        )
    }
}

impl DiscoveryValidate for DiscoveryContextBindingV1 {
    fn validate(&self) -> Result<()> {
        self.record_id.validate()?;
        require(
            self.process_instance_id != [0; 16]
                && self.entry_instance_id != [0; 16]
                && self.binding_id != [0; 16]
                && self.role_id > 0
                && self.state_id > 0
                && self.entry_rule_id > 0
                && self.catalog_revision > 0
                && self.policy_revision.profile_version == self.catalog_revision
                && self.static_key.effect_family > 0
                && self.static_key.operation > 0,
            "context identity",
        )?;
        for field in [
            &self.subject_revision,
            &self.image_digest,
            &self.configuration_digest,
            &self.static_key.workload_selector_id,
            &self.static_key.protected_scope_id,
            &self.static_key.execution_set_id,
            &self.static_key.entry_kind,
            &self.static_key.role_id,
            &self.static_key.process_state_id,
            &self.static_key.operation_id,
            &self.static_key.object_selector,
            &self.static_key.binding_lifecycle,
            &self.policy_revision.profile_id,
            &self.policy_revision.source_revision_id,
            &self.policy_revision.signed_profile_digest,
        ] {
            require(!field.is_empty() && field.len() <= 4096, "context field")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPinnedContextV1 {
    pub binding: DiscoveryContextBindingV1,
    pub workload: WorkloadTargetFactV1,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub signed_profile_digest: String,
    pub control_commit_index: u64,
}

impl DiscoveryPinnedContextV1 {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        require(
            self.policy_source_revision_id == self.binding.policy_revision.source_revision_id
                && self.signed_profile_digest == self.binding.policy_revision.signed_profile_digest
                && self.workload.node_id == self.binding.record_id.stream.node_id
                && self.workload.workload_binding_generation_digest
                    == self.binding.subject_revision
                && self.workload.image_digest == self.binding.image_digest
                && self.control_commit_index > 0
                && !self.target_snapshot_digest.is_empty(),
            "pinned context",
        )?;
        serde_json::to_writer(InputByteLimit(DISCOVERY_PIN_BYTES), self)
            .context(DiscoveryEncodingSnafu)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextUnavailableV1 {
    MissingSourceCpu,
    ContextLimit,
    MissingDecisionCatalog,
    MissingProcessLifetime,
    MissingWorkloadFact,
    AmbiguousWorkloadFact,
    PolicyContextMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextJoinV1 {
    Available(Box<DiscoveryPinnedContextV1>),
    Unresolved(DiscoveryContextUnavailableV1),
}

impl DiscoveryContextJoinV1 {
    pub fn into_bounded(self) -> Self {
        if serde_json::to_writer(InputByteLimit(DISCOVERY_PIN_BYTES), &self).is_ok() {
            self
        } else {
            Self::Unresolved(DiscoveryContextUnavailableV1::ContextLimit)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordV1 {
    pub id: DiscoveryRecordIdV1,
    pub original_kernel_sequence: Option<u64>,
    pub wire_record: Vec<u8>,
}

impl DiscoveryRecordV1 {
    pub fn decode(&self) -> Result<EvidenceRecord> {
        self.id.validate()?;
        let record = EvidenceRecord::try_from(self.wire_record.as_slice())?;
        require(
            self.original_kernel_sequence != Some(0)
                && record.reason <= u32::from(u8::MAX)
                && record.decision <= u32::from(u8::MAX)
                && record.effect_family > 0
                && record.effect_family <= u32::from(u16::MAX)
                && record.operation > 0
                && record.operation <= u32::from(u16::MAX)
                && i16::try_from(record.configured_errno).is_ok()
                && record.coverage_interval_id.len() == 16
                && record.coverage_interval_id.as_ref() != [0; 16]
                && record.profile_generation_ref_id != Some(0)
                && record.target_task_cookie != Some(0)
                && matches!(record.temporal_coverage, 0..=2),
            "record fields",
        )?;
        for id in [
            &record.process_lineage_id,
            &record.authority_domain_id,
            &record.execution_set_id,
            &record.exact_object_id,
        ] {
            require(
                id.is_empty() || (id.len() == 16 && id.as_ref() != [0; 16]),
                "record object",
            )?;
        }
        if let Some(context) = &record.decision_context {
            require(
                context.schema_version == 1
                    && context.original_kernel_sequence > 0
                    && self.original_kernel_sequence == Some(context.original_kernel_sequence)
                    && context.profile_generation_ref_id
                        == record.profile_generation_ref_id.unwrap_or_default(),
                "record context",
            )?;
        }
        Ok(record)
    }
}

impl TryFrom<(DiscoveryRecordIdV1, &[u8])> for DiscoveryRecordV1 {
    type Error = Error;

    fn try_from((id, bytes): (DiscoveryRecordIdV1, &[u8])) -> Result<Self> {
        let record = EvidenceRecord::try_from(bytes)?;
        let value = Self {
            id,
            original_kernel_sequence: record
                .decision_context
                .as_ref()
                .map(|context| context.original_kernel_sequence),
            wire_record: bytes.to_vec(),
        };
        value.decode()?;
        Ok(value)
    }
}

impl TryFrom<(&EvidenceIntakeIdentityV1, u32, &AnalysisRecordV1)> for DiscoveryRecordV1 {
    type Error = Error;

    fn try_from(
        (stream, cpu_id, record): (&EvidenceIntakeIdentityV1, u32, &AnalysisRecordV1),
    ) -> Result<Self> {
        Self::try_from((
            DiscoveryRecordIdV1 {
                stream: stream.clone(),
                cpu_id,
                durable_cursor: record.cursor,
            },
            record.framed_record.as_slice(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryInputManifestV1 {
    pub schema_version: u32,
    pub tenant_id: [u8; 16],
    pub source_revision: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub contexts: Vec<DiscoveryContextBindingV1>,
    pub records: Vec<DiscoveryRecordV1>,
    pub exclusions: Vec<DiscoveryUnresolvedV1>,
    pub lifecycle: Vec<DiscoveryLifecycleEntryV1>,
}

impl TryFrom<&[u8]> for DiscoveryInputManifestV1 {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= DISCOVERY_INPUT_BYTES, "input bytes")?;
        let input: Self = serde_json::from_slice(bytes).context(DiscoveryEncodingSnafu)?;
        input.validate()?;
        Ok(input)
    }
}

impl DiscoveryInputManifestV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "schema version",
        )?;
        require(self.tenant_id != [0; 16], "tenant")?;
        require(
            !self.source_revision.is_empty() && self.source_revision.len() <= 128,
            "source revision",
        )?;
        require(
            self.records.len() <= MAX_DISCOVERY_RECORDS
                && self.contexts.len() <= MAX_DISCOVERY_RECORDS
                && self.exclusions.len() <= MAX_DISCOVERY_RECORDS
                && self.coverage.len() <= 4096
                && self.lifecycle.len() <= DiscoveryLifecycleCaseV1::ALL.len(),
            "input count",
        )?;
        let mut ranges = BTreeSet::new();
        for coverage in &self.coverage {
            coverage.validate()?;
            require(
                coverage.stream.tenant_id == self.tenant_id,
                "coverage tenant",
            )?;
            require(
                ranges.insert((
                    &coverage.stream,
                    coverage.cpu_id,
                    coverage.first_cursor,
                    coverage.last_cursor,
                )),
                "duplicate range",
            )?;
        }
        for pair in ranges.iter().zip(ranges.iter().skip(1)) {
            require(
                pair.0 .0 != pair.1 .0 || pair.0 .1 != pair.1 .1 || pair.0 .3 < pair.1 .2,
                "overlapping range",
            )?;
        }
        for context in &self.contexts {
            context.validate()?;
            require(
                context.record_id.stream.tenant_id == self.tenant_id,
                "context tenant",
            )?;
        }
        for record in &self.records {
            let wire = record.decode()?;
            require(
                record.id.stream.tenant_id == self.tenant_id,
                "record tenant",
            )?;
            require(
                self.coverage.iter().any(|range| {
                    range.stream == record.id.stream
                        && range.cpu_id == record.id.cpu_id
                        && range.first_cursor <= record.id.durable_cursor
                        && range.last_cursor >= record.id.durable_cursor
                        && range.coverage_interval_id.as_slice()
                            == wire.coverage_interval_id.as_ref()
                }),
                "record outside range",
            )?;
        }
        for exclusion in &self.exclusions {
            exclusion.record_id.validate()?;
            require(
                exclusion.record_id.stream.tenant_id == self.tenant_id
                    && !exclusion.reason.is_empty()
                    && exclusion.reason.len() <= 128,
                "exclusion",
            )?;
        }
        let mut cases = BTreeSet::new();
        for entry in &self.lifecycle {
            require(cases.insert(entry.case), "duplicate lifecycle case")?;
            match &entry.state {
                DiscoveryLifecycleStateV1::Recorded { records } => {
                    require(
                        !records.is_empty() && records.len() <= 64,
                        "lifecycle records",
                    )?;
                    require(
                        !records.is_empty()
                            && records.iter().collect::<BTreeSet<_>>().len() == records.len()
                            && records.iter().all(|id| {
                                id.stream.tenant_id == self.tenant_id
                                    && self.records.iter().any(|record| &record.id == id)
                            }),
                        "lifecycle record identity",
                    )?;
                }
                DiscoveryLifecycleStateV1::Declared { reason }
                | DiscoveryLifecycleStateV1::NotApplicable { reason }
                | DiscoveryLifecycleStateV1::Unsupported { reason } => {
                    require(
                        !reason.is_empty() && reason.len() <= 128,
                        "lifecycle reason",
                    )?;
                }
                DiscoveryLifecycleStateV1::Missing => {}
            }
        }
        serde_json::to_writer(InputByteLimit(DISCOVERY_INPUT_BYTES), self)
            .context(DiscoveryEncodingSnafu)
    }
}

impl From<&crate::EvidenceExactFileObject> for DiscoveryFileObjectV1 {
    fn from(value: &crate::EvidenceExactFileObject) -> Self {
        Self {
            profile_generation_ref_id: value.profile_generation_ref_id,
            mount_id_unique: value.mount_id_unique,
            inode: value.inode,
            inode_generation: value.inode_generation,
            mount_namespace_inode: value.mount_namespace_inode,
            filesystem_device: value.filesystem_device,
        }
    }
}

impl From<&EvidenceRecord> for DiscoveryEffectKeyV1 {
    fn from(record: &EvidenceRecord) -> Self {
        Self {
            task_cookie: record.task_cookie,
            target_task_cookie: record.target_task_cookie,
            process_lineage_id: record.process_lineage_id.to_vec(),
            authority_domain_id: record.authority_domain_id.to_vec(),
            execution_set_id: record.execution_set_id.to_vec(),
            exact_object_id: record.exact_object_id.to_vec(),
            destination_id: record.destination_id,
            policy_rule_id: record.policy_rule_id,
            reason: record.reason,
            decision: record.decision,
            effect_family: record.effect_family,
            operation: record.operation,
            operation_argument: record.operation_argument,
            configured_errno: record.configured_errno,
            kernel_result: record.kernel_result,
            exact_file_object: record
                .decision_context
                .as_ref()
                .and_then(|context| context.exact_file_object.as_ref())
                .map(Into::into),
        }
    }
}

impl DiscoveryValidate for BehaviorAtomKeyV1 {
    fn validate(&self) -> Result<()> {
        require(
            self.stream.valid()
                && self.process_instance_id != [0; 16]
                && self.entry_instance_id != [0; 16]
                && self.binding_id != [0; 16]
                && self.role_id > 0
                && self.state_id > 0
                && self.entry_rule_id > 0
                && self.catalog_revision > 0
                && self.catalog_revision == self.policy_revision.profile_version
                && self.generation > 0
                && self.coverage_interval_id != [0; 16]
                && matches!(self.temporal_coverage, 0..=2)
                && self.effect.reason <= u32::from(u8::MAX)
                && self.effect.decision <= u32::from(u8::MAX)
                && self.effect.effect_family > 0
                && self.effect.effect_family <= u32::from(u16::MAX)
                && self.effect.operation > 0
                && self.effect.operation <= u32::from(u16::MAX)
                && i16::try_from(self.effect.configured_errno).is_ok()
                && self.effect.target_task_cookie != Some(0)
                && self.static_key.effect_family as u32 == self.effect.effect_family
                && self.static_key.operation as u32 == self.effect.operation
                && (self.static_key.argument_wildcard
                    || self.static_key.operation_argument
                        == self.effect.operation_argument.unwrap_or_default())
                && self.physical_result
                    == if self.effect.decision == 1 && self.effect.kernel_result < 0 {
                        DiscoveryPhysicalResultV1::Prevented
                    } else {
                        DiscoveryPhysicalResultV1::Unknown
                    },
            "atom key",
        )?;
        for id in [
            &self.effect.process_lineage_id,
            &self.effect.authority_domain_id,
            &self.effect.execution_set_id,
            &self.effect.exact_object_id,
        ] {
            require(
                id.is_empty() || (id.len() == 16 && id.as_slice() != [0; 16]),
                "atom object",
            )?;
        }
        require(!self.effect.exact_object_id.is_empty(), "atom exact object")?;
        for field in [
            &self.subject_revision,
            &self.image_digest,
            &self.configuration_digest,
            &self.static_key.workload_selector_id,
            &self.static_key.protected_scope_id,
            &self.static_key.execution_set_id,
            &self.static_key.entry_kind,
            &self.static_key.role_id,
            &self.static_key.process_state_id,
            &self.static_key.operation_id,
            &self.static_key.object_selector,
            &self.static_key.binding_lifecycle,
            &self.policy_revision.profile_id,
            &self.policy_revision.source_revision_id,
            &self.policy_revision.signed_profile_digest,
        ] {
            require(!field.is_empty() && field.len() <= 4096, "atom field")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorSnapshotV1 {
    pub schema_version: u32,
    pub tenant_id: [u8; 16],
    pub source_revision: String,
    pub proof_kind: DiscoveryProofKindV1,
    pub accepted_records: u64,
    pub included_records: u64,
    pub unresolved_records: u64,
    pub excluded_records: u64,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub atoms: Vec<BehaviorAtomV1>,
    pub unresolved: Vec<DiscoveryUnresolvedV1>,
    pub excluded: Vec<DiscoveryUnresolvedV1>,
    pub lifecycle: Vec<DiscoveryLifecycleEntryV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecordedResultV1 {
    pub snapshot: BehaviorSnapshotV1,
    pub duplicate_deliveries: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReviewedBaselineV1 {
    pub snapshot: BehaviorSnapshotV1,
    pub reviewer: String,
    pub reviewed_utc_ns: u64,
    pub forbidden: Vec<DiscoveryPolicyKeyV1>,
}
