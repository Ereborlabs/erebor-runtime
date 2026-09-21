use erebor_interceptor_abi::{
    EffectObservationReasonV1, Id128V1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use prost::Message as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{Location, Snafu};

use crate::{
    EvidenceDecisionContext, EvidenceExactFileObject, EvidenceRecord, EvidenceTemporalCoverage,
    TemporalCoverageV1,
};

const OBSERVATION_ID_DOMAIN: &[u8] = b"MITHRIL-KERNEL-OBSERVATION-V2\0";
pub const MAX_EVIDENCE_DECISION_CONTEXT_BYTES: usize = 16 * 1024;

pub type EvidenceDigestV1 = [u8; 32];
pub type EvidenceIdV1 = Id128V1;
pub type EvidenceModelResult<T> = std::result::Result<T, EvidenceModelError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum EvidenceModelError {
    #[snafu(display("Mithril evidence model is invalid: {reason}"))]
    Invalid {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

// Finding packages use these keys to select evidence. Kernel records use typed fields on the wire.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceFieldKeyV1 {
    FindingId,
    ReasonCode,
    Decision,
    EffectFamily,
    Operation,
    Errno,
    KernelResult,
    TaskCookie,
    ProcessLineageId,
    AuthorityDomainId,
    ExecutionSetId,
    ExactObjectId,
    ObjectClassId,
    DestinationId,
    ProviderRequestId,
    ProviderResult,
    CoverageIntervalIds,
    PolicyRuleIds,
    ResponseResult,
    ProviderPrincipalId,
    ProviderResourceId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSensitivityV1 {
    Public,
    Internal,
    SensitiveIdentifier,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStateV1 {
    Healthy,
    Gapped,
    Unknown,
    Closed,
}

impl CoverageStateV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Gapped => "GAPPED",
            Self::Unknown => "UNKNOWN",
            Self::Closed => "CLOSED",
        }
    }
}

impl TryFrom<&str> for CoverageStateV1 {
    type Error = EvidenceModelError;

    fn try_from(value: &str) -> EvidenceModelResult<Self> {
        match value {
            "HEALTHY" => Ok(Self::Healthy),
            "GAPPED" => Ok(Self::Gapped),
            "UNKNOWN" => Ok(Self::Unknown),
            "CLOSED" => Ok(Self::Closed),
            _ => InvalidSnafu {
                reason: format!("coverage state `{value}` is invalid"),
            }
            .fail(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageGapReasonV1 {
    SourceSequenceGap,
    DecoderError,
    RingLoss,
    ClassifierMiss,
    UnresolvedEffect,
    ReaderDelay,
    ReaderQueueOverflow,
    ReaderStopped,
    WalFailure,
    WalCapacity,
    ControlDelay,
    KernelStateMismatch,
    UncleanRestart,
    CounterRegression,
}

impl CoverageGapReasonV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceSequenceGap => "SOURCE_SEQUENCE_GAP",
            Self::DecoderError => "DECODER_ERROR",
            Self::RingLoss => "RING_LOSS",
            Self::ClassifierMiss => "CLASSIFIER_MISS",
            Self::UnresolvedEffect => "UNRESOLVED_EFFECT",
            Self::ReaderDelay => "READER_DELAY",
            Self::ReaderQueueOverflow => "READER_QUEUE_OVERFLOW",
            Self::ReaderStopped => "READER_STOPPED",
            Self::WalFailure => "WAL_FAILURE",
            Self::WalCapacity => "WAL_CAPACITY",
            Self::ControlDelay => "CONTROL_DELAY",
            Self::KernelStateMismatch => "KERNEL_STATE_MISMATCH",
            Self::UncleanRestart => "UNCLEAN_RESTART",
            Self::CounterRegression => "COUNTER_REGRESSION",
        }
    }
}

impl TryFrom<&str> for CoverageGapReasonV1 {
    type Error = EvidenceModelError;

    fn try_from(value: &str) -> EvidenceModelResult<Self> {
        match value {
            "SOURCE_SEQUENCE_GAP" => Ok(Self::SourceSequenceGap),
            "DECODER_ERROR" => Ok(Self::DecoderError),
            "RING_LOSS" => Ok(Self::RingLoss),
            "CLASSIFIER_MISS" => Ok(Self::ClassifierMiss),
            "UNRESOLVED_EFFECT" => Ok(Self::UnresolvedEffect),
            "READER_DELAY" => Ok(Self::ReaderDelay),
            "READER_QUEUE_OVERFLOW" => Ok(Self::ReaderQueueOverflow),
            "READER_STOPPED" => Ok(Self::ReaderStopped),
            "WAL_FAILURE" => Ok(Self::WalFailure),
            "WAL_CAPACITY" => Ok(Self::WalCapacity),
            "CONTROL_DELAY" => Ok(Self::ControlDelay),
            "KERNEL_STATE_MISMATCH" => Ok(Self::KernelStateMismatch),
            "UNCLEAN_RESTART" => Ok(Self::UncleanRestart),
            "COUNTER_REGRESSION" => Ok(Self::CounterRegression),
            _ => InvalidSnafu {
                reason: format!("coverage gap reason `{value}` is invalid"),
            }
            .fail(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelEffectEvidenceV1 {
    pub task_cookie: u64,
    pub target_task_cookie: Option<u64>,
    pub process_lineage_id: Option<EvidenceIdV1>,
    pub authority_domain_id: Option<EvidenceIdV1>,
    pub execution_set_id: Option<EvidenceIdV1>,
    pub exact_object_id: Option<EvidenceIdV1>,
    pub destination_id: Option<u64>,
    pub policy_rule_id: Option<u64>,
    pub reason: u8,
    pub decision: u8,
    pub effect_family: u16,
    pub operation: u16,
    pub operation_argument: Option<u32>,
    pub configured_errno: i16,
    pub kernel_result: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEnvelopeV1 {
    pub tenant_id: EvidenceIdV1,
    pub node_boot_id: EvidenceIdV1,
    pub source_id: EvidenceIdV1,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub cpu_id: u32,
    pub observed_boottime_ns: u64,
    pub ingested_utc_ns: i64,
    pub coverage_interval_id: EvidenceIdV1,
    pub profile_generation_ref_id: Option<u64>,
    pub temporal_coverage: TemporalCoverageV1,
    pub effect: KernelEffectEvidenceV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_context: Option<EvidenceDecisionContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDecisionCatalogV1 {
    pub node_boot_id: EvidenceIdV1,
    pub profile_id: String,
    pub profile_version: u64,
    pub policy_document_digest: String,
    pub profile_generation_ref_id: u64,
    pub binding_id: EvidenceIdV1,
    pub role_id: u32,
    pub state_id: u32,
    pub entry_rule_id: u32,
    pub exact_file_object: EvidenceExactFileObject,
    pub exact_object_key_id: u64,
    pub composite_atom_id: u64,
    pub static_key: crate::StaticDecisionKeyV1,
    pub digest: crate::DiscoveryDigestV1,
}

impl EvidenceDecisionCatalogV1 {
    pub fn content_digest(&self) -> crate::Result<crate::DiscoveryDigestV1> {
        let mut content = self.clone();
        content.digest = crate::DiscoveryDigestV1([0; 32]);
        crate::DiscoveryDigestV1::of(&("decision-catalog-v1", content))
    }

    pub fn seal(mut self) -> crate::Result<Vec<u8>> {
        self.digest = self.content_digest()?;
        serde_json::to_vec(&self).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "CATALOG_ENCODING",
                reason: error.to_string(),
            }
            .build()
        })
    }
}

impl EvidenceDecisionContext {
    pub fn catalog(&self) -> EvidenceModelResult<Option<EvidenceDecisionCatalogV1>> {
        if self.encoded_len() > MAX_EVIDENCE_DECISION_CONTEXT_BYTES {
            return InvalidSnafu {
                reason: "decision context exceeds its size limit",
            }
            .fail();
        }
        if self.catalog_json.is_empty() {
            if !matches!(
                self.catalog_state.as_str(),
                "" | "MISSING_CATALOG"
                    | "NO_EXACT_MATCH"
                    | "AMBIGUOUS"
                    | "CATALOG_LIMIT"
                    | "CONTEXT_LIMIT"
            ) {
                return InvalidSnafu {
                    reason: "missing decision catalog has an invalid state",
                }
                .fail();
            }
            return Ok(None);
        }
        if self.catalog_state != "AVAILABLE" {
            return InvalidSnafu {
                reason: "present decision catalog has an invalid state",
            }
            .fail();
        }
        let catalog: EvidenceDecisionCatalogV1 = serde_json::from_slice(&self.catalog_json)
            .map_err(|_| {
                InvalidSnafu {
                    reason: "decision catalog encoding is invalid",
                }
                .build()
            })?;
        let digest = catalog.content_digest().map_err(|_| {
            InvalidSnafu {
                reason: "decision catalog digest cannot be computed",
            }
            .build()
        })?;
        if catalog.digest != digest
            || catalog.profile_version == 0
            || !uuid::Uuid::parse_str(&catalog.profile_id).is_ok_and(|id| !id.is_nil())
            || catalog.policy_document_digest.len() != 64
            || !catalog
                .policy_document_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || catalog.profile_generation_ref_id != self.profile_generation_ref_id
            || catalog.exact_file_object.profile_generation_ref_id != self.profile_generation_ref_id
            || catalog.binding_id.is_zero()
            || catalog.binding_id.to_be_bytes().as_slice() != self.binding_id
            || catalog.role_id != self.role_id
            || catalog.state_id != self.state_id
            || catalog.entry_rule_id != self.entry_rule_id
            || self.exact_file_object.as_ref() != Some(&catalog.exact_file_object)
            || catalog.exact_object_key_id != self.exact_object_key_id
            || catalog.composite_atom_id != self.composite_atom_id
        {
            return InvalidSnafu {
                reason: "decision catalog digest or coordinates differ",
            }
            .fail();
        }
        Ok(Some(catalog))
    }

    fn validate_for(&self, observation: &ObservationEnvelopeV1) -> EvidenceModelResult<()> {
        if self.schema_version != 1
            || self.original_kernel_sequence == 0
            || self.encoded_len() > MAX_EVIDENCE_DECISION_CONTEXT_BYTES
            || self.profile_generation_ref_id
                != observation.profile_generation_ref_id.unwrap_or_default()
            || self.composite_atom_id != observation.effect.policy_rule_id.unwrap_or_default()
        {
            return InvalidSnafu {
                reason: "decision context version, size, sequence, or base coordinates differ",
            }
            .fail();
        }
        for (bytes, name) in [
            (&self.process_instance_id, "process instance"),
            (&self.entry_instance_id, "entry instance"),
            (&self.binding_id, "binding"),
        ] {
            optional_id(bytes, name)?;
        }
        match (&self.exact_file_object, observation.effect.exact_object_id) {
            (Some(object), Some(expected)) if self.exact_object_key_id != 0 => {
                if object.observation_id(self.exact_object_key_id) != expected {
                    return InvalidSnafu {
                        reason: "decision context exact object differs from the base observation",
                    }
                    .fail();
                }
            }
            (None, None) if self.exact_object_key_id == 0 => {}
            _ => {
                return InvalidSnafu {
                    reason: "decision context exact object or handle is absent",
                }
                .fail();
            }
        }
        if let Some(catalog) = self.catalog()? {
            let operation =
                crate::CompiledOperationV1::try_from(catalog.static_key.operation_id.as_str())
                    .map_err(|_| {
                        InvalidSnafu {
                            reason: "decision catalog operation is invalid",
                        }
                        .build()
                    })?;
            if catalog.node_boot_id != observation.node_boot_id
                || KernelEffectFamilyV1::from(catalog.static_key.effect_family) as u16
                    != observation.effect.effect_family
                || operation.kernel_id as u16 != observation.effect.operation
                || (!operation.argument_wildcard
                    && operation.argument
                        != observation.effect.operation_argument.unwrap_or_default())
            {
                return InvalidSnafu {
                    reason: "decision catalog effect differs from the base observation",
                }
                .fail();
            }
        }
        Ok(())
    }
}

impl From<erebor_interceptor_abi::ExactFileObjectKeyV1> for EvidenceExactFileObject {
    fn from(raw: erebor_interceptor_abi::ExactFileObjectKeyV1) -> Self {
        Self {
            profile_generation_ref_id: raw.profile_generation_ref_id,
            mount_id_unique: raw.mount_id_unique,
            inode: raw.inode,
            inode_generation: raw.inode_generation,
            mount_namespace_inode: raw.mount_namespace_inode,
            filesystem_device: raw.filesystem_device,
        }
    }
}

impl EvidenceExactFileObject {
    pub fn observation_id(&self, handle: u64) -> EvidenceIdV1 {
        use zerocopy::IntoBytes as _;
        let raw = erebor_interceptor_abi::ExactFileObjectKeyV1 {
            profile_generation_ref_id: self.profile_generation_ref_id,
            mount_id_unique: self.mount_id_unique,
            inode: self.inode,
            inode_generation: self.inode_generation,
            mount_namespace_inode: self.mount_namespace_inode,
            filesystem_device: self.filesystem_device,
        };
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-EXACT-OBJECT-V1\0");
        digest.update(raw.as_bytes());
        digest.update(handle.to_be_bytes());
        EvidenceDigestV1::from(digest.finalize()).into()
    }
}

impl ObservationEnvelopeV1 {
    pub fn validate(&self) -> EvidenceModelResult<()> {
        let process_control = self.effect.effect_family == KernelEffectFamilyV1::Privilege as u16
            && (self.effect.operation == KernelEffectOperationV1::Ptrace as u16
                || self.effect.operation == KernelEffectOperationV1::Signal as u16);
        let external_runtime_actor = self.effect.reason
            == EffectObservationReasonV1::PreparedRuntimeInfrastructure as u8
            || self.effect.reason == EffectObservationReasonV1::RuntimeEntryInfrastructure as u8;
        let subject_absence_is_observed =
            self.effect.reason == EffectObservationReasonV1::MissingIdentity as u8;
        let operation_uses_argument = self.effect.operation
            == KernelEffectOperationV1::Ioctl as u16
            || self.effect.operation == KernelEffectOperationV1::IpcAccess as u16
            || process_control
            || self.effect.operation == KernelEffectOperationV1::Capability as u16;
        let subject_is_valid = self.effect.task_cookie > 0
            || subject_absence_is_observed
            || (process_control
                && external_runtime_actor
                && self.effect.target_task_cookie.is_some());
        let optional_ids_are_valid = [
            self.effect.process_lineage_id,
            self.effect.authority_domain_id,
            self.effect.execution_set_id,
            self.effect.exact_object_id,
        ]
        .into_iter()
        .flatten()
        .all(|id| !id.is_zero());
        let invalid_field = [
            ("tenant identity", self.tenant_id.is_zero()),
            ("node boot identity", self.node_boot_id.is_zero()),
            ("source identity", self.source_id.is_zero()),
            ("source epoch", self.source_epoch == 0),
            ("source sequence", self.source_sequence == 0),
            ("boot timestamp", self.observed_boottime_ns == 0),
            ("coverage interval", self.coverage_interval_id.is_zero()),
            (
                "profile generation reference",
                self.profile_generation_ref_id == Some(0),
            ),
            ("subject identity", !subject_is_valid),
            (
                "target subject identity",
                self.effect.target_task_cookie == Some(0),
            ),
            (
                "operation argument",
                operation_uses_argument != self.effect.operation_argument.is_some(),
            ),
            ("effect family", self.effect.effect_family == 0),
            ("optional identity", !optional_ids_are_valid),
            (
                "destination identity",
                self.effect.destination_id == Some(0),
            ),
            (
                "policy rule identity",
                self.effect.policy_rule_id == Some(0),
            ),
        ]
        .into_iter()
        .find_map(|(field, invalid)| invalid.then_some(field));
        if let Some(field) = invalid_field {
            return InvalidSnafu {
                reason: format!("kernel observation {field} is invalid"),
            }
            .fail();
        }
        if let Some(context) = &self.decision_context {
            context.validate_for(self)?;
        }
        Ok(())
    }

    pub fn to_wire_record(&self) -> EvidenceModelResult<EvidenceRecord> {
        self.validate()?;
        Ok(EvidenceRecord {
            observed_boottime_ns: self.observed_boottime_ns,
            ingested_utc_ns: self.ingested_utc_ns,
            coverage_interval_id: self.coverage_interval_id.to_be_bytes().to_vec().into(),
            profile_generation_ref_id: self.profile_generation_ref_id,
            task_cookie: self.effect.task_cookie,
            target_task_cookie: self.effect.target_task_cookie,
            process_lineage_id: optional_id_bytes(self.effect.process_lineage_id),
            authority_domain_id: optional_id_bytes(self.effect.authority_domain_id),
            execution_set_id: optional_id_bytes(self.effect.execution_set_id),
            exact_object_id: optional_id_bytes(self.effect.exact_object_id),
            destination_id: self.effect.destination_id.unwrap_or_default(),
            policy_rule_id: self.effect.policy_rule_id.unwrap_or_default(),
            reason: u32::from(self.effect.reason),
            decision: u32::from(self.effect.decision),
            effect_family: u32::from(self.effect.effect_family),
            operation: u32::from(self.effect.operation),
            operation_argument: self.effect.operation_argument,
            configured_errno: i32::from(self.effect.configured_errno),
            kernel_result: self.effect.kernel_result,
            temporal_coverage: match self.temporal_coverage {
                TemporalCoverageV1::Complete => EvidenceTemporalCoverage::Complete as i32,
                TemporalCoverageV1::Gapped => EvidenceTemporalCoverage::Gapped as i32,
                TemporalCoverageV1::Unknown => EvidenceTemporalCoverage::Unknown as i32,
            },
            decision_context: self.decision_context.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_wire_record(
        tenant_id: EvidenceIdV1,
        node_boot_id: EvidenceIdV1,
        source_id: EvidenceIdV1,
        source_epoch: u64,
        source_sequence: u64,
        cpu_id: u32,
        record: &EvidenceRecord,
    ) -> EvidenceModelResult<Self> {
        let temporal_coverage = match EvidenceTemporalCoverage::try_from(record.temporal_coverage) {
            Ok(EvidenceTemporalCoverage::Complete) => TemporalCoverageV1::Complete,
            Ok(EvidenceTemporalCoverage::Gapped) => TemporalCoverageV1::Gapped,
            Ok(EvidenceTemporalCoverage::Unknown) => TemporalCoverageV1::Unknown,
            Err(_error) => {
                return InvalidSnafu {
                    reason: "kernel observation temporal coverage is invalid".to_owned(),
                }
                .fail();
            }
        };
        let observation = Self {
            tenant_id,
            node_boot_id,
            source_id,
            source_epoch,
            source_sequence,
            cpu_id,
            observed_boottime_ns: record.observed_boottime_ns,
            ingested_utc_ns: record.ingested_utc_ns,
            coverage_interval_id: required_id(&record.coverage_interval_id, "coverage interval")?,
            profile_generation_ref_id: record.profile_generation_ref_id,
            temporal_coverage,
            decision_context: record.decision_context.clone(),
            effect: KernelEffectEvidenceV1 {
                task_cookie: record.task_cookie,
                target_task_cookie: record.target_task_cookie,
                process_lineage_id: optional_id(&record.process_lineage_id, "process lineage")?,
                authority_domain_id: optional_id(&record.authority_domain_id, "authority domain")?,
                execution_set_id: optional_id(&record.execution_set_id, "execution set")?,
                exact_object_id: optional_id(&record.exact_object_id, "exact object")?,
                destination_id: (record.destination_id != 0).then_some(record.destination_id),
                policy_rule_id: (record.policy_rule_id != 0).then_some(record.policy_rule_id),
                reason: u8::try_from(record.reason).map_err(|_error| {
                    InvalidSnafu {
                        reason: "kernel observation reason exceeds u8".to_owned(),
                    }
                    .build()
                })?,
                decision: u8::try_from(record.decision).map_err(|_error| {
                    InvalidSnafu {
                        reason: "kernel observation decision exceeds u8".to_owned(),
                    }
                    .build()
                })?,
                effect_family: u16::try_from(record.effect_family).map_err(|_error| {
                    InvalidSnafu {
                        reason: "kernel observation effect family exceeds u16".to_owned(),
                    }
                    .build()
                })?,
                operation: u16::try_from(record.operation).map_err(|_error| {
                    InvalidSnafu {
                        reason: "kernel observation operation exceeds u16".to_owned(),
                    }
                    .build()
                })?,
                operation_argument: record.operation_argument,
                configured_errno: i16::try_from(record.configured_errno).map_err(|_error| {
                    InvalidSnafu {
                        reason: "kernel observation errno exceeds i16".to_owned(),
                    }
                    .build()
                })?,
                kernel_result: record.kernel_result,
            },
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn canonical_bytes(&self) -> EvidenceModelResult<Vec<u8>> {
        let record = self.to_wire_record()?;
        let mut bytes = Vec::with_capacity(80 + record.encoded_len());
        bytes.extend_from_slice(OBSERVATION_ID_DOMAIN);
        bytes.extend_from_slice(&self.tenant_id.to_be_bytes());
        bytes.extend_from_slice(&self.node_boot_id.to_be_bytes());
        bytes.extend_from_slice(&self.source_id.to_be_bytes());
        bytes.extend_from_slice(&self.source_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.source_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.cpu_id.to_be_bytes());
        record.encode(&mut bytes).map_err(|error| {
            InvalidSnafu {
                reason: format!("kernel observation encoding failed: {error}"),
            }
            .build()
        })?;
        Ok(bytes)
    }

    pub fn observation_id(&self) -> EvidenceModelResult<EvidenceDigestV1> {
        let mut identity = self.clone();
        identity.ingested_utc_ns = 0;
        Ok(Sha256::digest(identity.canonical_bytes()?).into())
    }

    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        self.temporal_coverage == TemporalCoverageV1::Complete
    }
}

fn optional_id_bytes(id: Option<EvidenceIdV1>) -> prost::bytes::Bytes {
    id.map_or_else(prost::bytes::Bytes::new, |id| {
        prost::bytes::Bytes::copy_from_slice(&id.to_be_bytes())
    })
}

fn optional_id(bytes: &[u8], name: &str) -> EvidenceModelResult<Option<EvidenceIdV1>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    required_id(bytes, name).map(Some)
}

fn required_id(bytes: &[u8], name: &str) -> EvidenceModelResult<EvidenceIdV1> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_error| {
        InvalidSnafu {
            reason: format!("kernel observation {name} is not Id128"),
        }
        .build()
    })?;
    let id = EvidenceIdV1::from(bytes);
    if id.is_zero() {
        return InvalidSnafu {
            reason: format!("kernel observation {name} is zero"),
        }
        .fail();
    }
    Ok(id)
}
