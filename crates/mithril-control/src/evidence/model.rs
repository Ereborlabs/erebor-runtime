use erebor_interceptor_abi::{
    EffectObservationReasonV1, Id128V1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use prost::Message as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{Location, Snafu};

use crate::{EvidenceRecord, EvidenceTemporalCoverage, TemporalCoverageV1};

const OBSERVATION_ID_DOMAIN: &[u8] = b"MITHRIL-KERNEL-OBSERVATION-V2\0";

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
}

impl ObservationEnvelopeV1 {
    pub fn validate(&self) -> EvidenceModelResult<()> {
        let process_control = self.effect.effect_family == KernelEffectFamilyV1::Privilege as u16
            && (self.effect.operation == KernelEffectOperationV1::Ptrace as u16
                || self.effect.operation == KernelEffectOperationV1::Signal as u16);
        let external_runtime_actor = self.effect.reason
            == EffectObservationReasonV1::PreparedRuntimeInfrastructure as u8
            || self.effect.reason == EffectObservationReasonV1::RuntimeEntryInfrastructure as u8;
        let operation_uses_argument = self.effect.operation
            == KernelEffectOperationV1::Ioctl as u16
            || self.effect.operation == KernelEffectOperationV1::IpcAccess as u16
            || process_control
            || self.effect.operation == KernelEffectOperationV1::Capability as u16;
        let subject_is_valid = self.effect.task_cookie > 0
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
        if self.tenant_id.is_zero()
            || self.node_boot_id.is_zero()
            || self.source_id.is_zero()
            || self.source_epoch == 0
            || self.source_sequence == 0
            || self.observed_boottime_ns == 0
            || self.coverage_interval_id.is_zero()
            || self.profile_generation_ref_id == Some(0)
            || !subject_is_valid
            || self.effect.target_task_cookie == Some(0)
            || operation_uses_argument != self.effect.operation_argument.is_some()
            || self.effect.effect_family == 0
            || !optional_ids_are_valid
            || self.effect.destination_id == Some(0)
            || self.effect.policy_rule_id == Some(0)
        {
            return InvalidSnafu {
                reason: "kernel observation identity or value is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    pub fn to_wire_record(&self) -> EvidenceModelResult<EvidenceRecord> {
        self.validate()?;
        Ok(EvidenceRecord {
            observed_boottime_ns: self.observed_boottime_ns,
            ingested_utc_ns: self.ingested_utc_ns,
            coverage_interval_id: self.coverage_interval_id.to_be_bytes().to_vec(),
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

fn optional_id_bytes(id: Option<EvidenceIdV1>) -> Vec<u8> {
    id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec())
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
