use erebor_interceptor_abi::Id128V1;
use minicbor::Encoder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{Location, Snafu};

use crate::{ProofQualityV1, SourceAuthorityV1, TemporalCoverageV1};

pub const MAX_EVIDENCE_FIELDS_V1: usize = 64;
pub const MAX_PROVENANCE_OBSERVATIONS_V1: usize = 16;
const MAX_NESTED_IDENTITIES_V1: usize = 64;
const MAX_PROVIDER_EVENT_ID_BYTES_V1: usize = 4_096;

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
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum EvidenceValueV1 {
    Digest(EvidenceDigestV1),
    ReasonCode(u32),
    Decision(u32),
    EffectFamily(u16),
    Operation(u16),
    Errno(i16),
    KernelResult(i32),
    TaskCookie(u64),
    Id(EvidenceIdV1),
    ObjectClass(u64),
    Destination(u64),
    ProviderResult(u32),
    CoverageIntervals(Vec<EvidenceIdV1>),
    PolicyRules(Vec<u64>),
    ResponseResult(u32),
    Redacted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFieldV1 {
    pub key: EvidenceFieldKeyV1,
    pub sensitivity: EvidenceSensitivityV1,
    pub provenance_observation_ids: Vec<EvidenceDigestV1>,
    pub proof_quality: ProofQualityV1,
    pub value: EvidenceValueV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePayloadV1 {
    pub fields: Vec<EvidenceFieldV1>,
}

impl EvidencePayloadV1 {
    pub fn new(mut fields: Vec<EvidenceFieldV1>) -> EvidenceModelResult<Self> {
        fields.sort_unstable_by_key(|field| field.key);
        let payload = Self { fields };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> EvidenceModelResult<()> {
        if self.fields.is_empty()
            || self.fields.len() > MAX_EVIDENCE_FIELDS_V1
            || self
                .fields
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || self.fields.iter().any(|field| {
                field.provenance_observation_ids.len() > MAX_PROVENANCE_OBSERVATIONS_V1
                    || field.provenance_observation_ids.contains(&[0; 32])
                    || field
                        .provenance_observation_ids
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || !field_value_matches_key(field.key, &field.value)
                    || !nested_value_is_bounded(&field.value)
            })
        {
            return InvalidSnafu {
                reason: "payload fields are unbounded, repeated, unsorted, or mistyped".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEnvelopeV1 {
    pub schema_version: u32,
    pub tenant_id: EvidenceIdV1,
    pub observation_id: EvidenceDigestV1,
    pub source_id: EvidenceIdV1,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub stable_provider_event_id: Option<Vec<u8>>,
    pub node_boot_id: Option<EvidenceIdV1>,
    pub cpu_id: Option<u32>,
    pub hook_or_adapter_id: u32,
    pub payload_schema_id: u32,
    pub abi_or_api_version: u32,
    pub profile_generation_ref_id: Option<u64>,
    pub boottime_ns: Option<u64>,
    pub projected_utc_ns: Option<i64>,
    pub time_uncertainty_ns: u64,
    pub ingested_utc_ns: i64,
    pub payload: EvidencePayloadV1,
    pub proof_quality: ProofQualityV1,
    pub coverage_interval_id: EvidenceIdV1,
    pub transport_integrity_digest: EvidenceDigestV1,
    pub signature_or_batch_digest: Option<EvidenceDigestV1>,
}

impl ObservationEnvelopeV1 {
    pub fn finalize(mut self) -> EvidenceModelResult<Self> {
        self.observation_id = self.expected_observation_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> EvidenceModelResult<()> {
        self.payload.validate()?;
        let valid = self.schema_version == 1
            && !self.tenant_id.is_zero()
            && self.observation_id != [0; 32]
            && !self.source_id.is_zero()
            && self.source_epoch > 0
            && self.source_sequence > 0
            && !self.coverage_interval_id.is_zero()
            && self.payload_schema_id > 0
            && self.abi_or_api_version > 0
            && self.transport_integrity_digest != [0; 32]
            && self
                .stable_provider_event_id
                .as_ref()
                .is_none_or(|id| !id.is_empty() && id.len() <= MAX_PROVIDER_EVENT_ID_BYTES_V1)
            && self.node_boot_id.is_none_or(|id| !id.is_zero())
            && self.profile_generation_ref_id.is_none_or(|id| id > 0)
            && self
                .signature_or_batch_digest
                .is_none_or(|digest| digest != [0; 32])
            && self.kernel_contract_is_complete();
        if !valid || self.observation_id != self.expected_observation_id()? {
            return InvalidSnafu {
                reason: "envelope identity, version, or bound is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> EvidenceModelResult<Vec<u8>> {
        self.validate()?;
        canonical_cbor(self)
    }

    pub fn wire_bytes(&self) -> EvidenceModelResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            InvalidSnafu {
                reason: format!("wire encoding failed: {error}"),
            }
            .build()
        })
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> EvidenceModelResult<Self> {
        let envelope: Self = serde_json::from_slice(bytes).map_err(|error| {
            InvalidSnafu {
                reason: format!("wire decoding failed: {error}"),
            }
            .build()
        })?;
        envelope.validate()?;
        Ok(envelope)
    }

    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        self.proof_quality.temporal_coverage == TemporalCoverageV1::Complete
            && self
                .payload
                .fields
                .iter()
                .all(|field| field.proof_quality.temporal_coverage == TemporalCoverageV1::Complete)
    }

    fn expected_observation_id(&self) -> EvidenceModelResult<EvidenceDigestV1> {
        let mut identity = self.clone();
        identity.observation_id = [0; 32];
        identity.ingested_utc_ns = 0;
        identity.signature_or_batch_digest = None;
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-OBSERVATION-ID-V1\0");
        digest.update(canonical_cbor(&identity)?);
        Ok(digest.finalize().into())
    }

    fn kernel_contract_is_complete(&self) -> bool {
        if self.proof_quality.source_authority != SourceAuthorityV1::KernelDecision {
            return true;
        }
        let expected_quality =
            ProofQualityV1::kernel_decision(self.proof_quality.temporal_coverage);
        let effect_family = self.payload.fields.iter().find_map(|field| {
            (field.key == EvidenceFieldKeyV1::EffectFamily).then_some(&field.value)
        });
        let expected_effect_family = u16::try_from(self.hook_or_adapter_id)
            .ok()
            .map(EvidenceValueV1::EffectFamily);
        self.proof_quality == expected_quality
            && self.node_boot_id.is_some()
            && self.cpu_id.is_some()
            && self.boottime_ns.is_some()
            && self.payload_schema_id == 1
            && self.abi_or_api_version == 1
            && effect_family == expected_effect_family.as_ref()
            && [
                EvidenceFieldKeyV1::ReasonCode,
                EvidenceFieldKeyV1::Decision,
                EvidenceFieldKeyV1::EffectFamily,
                EvidenceFieldKeyV1::Operation,
                EvidenceFieldKeyV1::Errno,
                EvidenceFieldKeyV1::KernelResult,
                EvidenceFieldKeyV1::TaskCookie,
            ]
            .into_iter()
            .all(|key| {
                self.payload.fields.iter().any(|field| {
                    field.key == key
                        && field.proof_quality == expected_quality
                        && !matches!(
                            field.value,
                            EvidenceValueV1::Redacted | EvidenceValueV1::Unknown
                        )
                })
            })
    }
}

fn nested_value_is_bounded(value: &EvidenceValueV1) -> bool {
    match value {
        EvidenceValueV1::CoverageIntervals(values) => {
            !values.is_empty()
                && values.len() <= MAX_NESTED_IDENTITIES_V1
                && values.iter().all(|id| !id.is_zero())
                && values.windows(2).all(|pair| pair[0] < pair[1])
        }
        EvidenceValueV1::PolicyRules(values) => {
            !values.is_empty()
                && values.len() <= MAX_NESTED_IDENTITIES_V1
                && values.iter().all(|id| *id > 0)
                && values.windows(2).all(|pair| pair[0] < pair[1])
        }
        _ => true,
    }
}

fn field_value_matches_key(key: EvidenceFieldKeyV1, value: &EvidenceValueV1) -> bool {
    matches!(
        (key, value),
        (EvidenceFieldKeyV1::FindingId, EvidenceValueV1::Digest(_))
            | (
                EvidenceFieldKeyV1::ReasonCode,
                EvidenceValueV1::ReasonCode(_)
            )
            | (EvidenceFieldKeyV1::Decision, EvidenceValueV1::Decision(_))
            | (
                EvidenceFieldKeyV1::EffectFamily,
                EvidenceValueV1::EffectFamily(_)
            )
            | (EvidenceFieldKeyV1::Operation, EvidenceValueV1::Operation(_))
            | (EvidenceFieldKeyV1::Errno, EvidenceValueV1::Errno(_))
            | (
                EvidenceFieldKeyV1::KernelResult,
                EvidenceValueV1::KernelResult(_)
            )
            | (
                EvidenceFieldKeyV1::TaskCookie,
                EvidenceValueV1::TaskCookie(_)
            )
            | (
                EvidenceFieldKeyV1::ProcessLineageId
                    | EvidenceFieldKeyV1::AuthorityDomainId
                    | EvidenceFieldKeyV1::ExecutionSetId
                    | EvidenceFieldKeyV1::ExactObjectId
                    | EvidenceFieldKeyV1::ProviderRequestId
                    | EvidenceFieldKeyV1::ProviderPrincipalId
                    | EvidenceFieldKeyV1::ProviderResourceId,
                EvidenceValueV1::Id(_)
            )
            | (
                EvidenceFieldKeyV1::ObjectClassId,
                EvidenceValueV1::ObjectClass(_)
            )
            | (
                EvidenceFieldKeyV1::DestinationId,
                EvidenceValueV1::Destination(_)
            )
            | (
                EvidenceFieldKeyV1::ProviderResult,
                EvidenceValueV1::ProviderResult(_)
            )
            | (
                EvidenceFieldKeyV1::CoverageIntervalIds,
                EvidenceValueV1::CoverageIntervals(_)
            )
            | (
                EvidenceFieldKeyV1::PolicyRuleIds,
                EvidenceValueV1::PolicyRules(_)
            )
            | (
                EvidenceFieldKeyV1::ResponseResult,
                EvidenceValueV1::ResponseResult(_)
            )
            | (_, EvidenceValueV1::Redacted | EvidenceValueV1::Unknown)
    )
}

fn canonical_cbor<T: Serialize>(value: &T) -> EvidenceModelResult<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|error| {
        InvalidSnafu {
            reason: format!("canonical value is invalid: {error}"),
        }
        .build()
    })?;
    let mut bytes = Vec::new();
    crate::canonical::encode_value(&mut Encoder::new(&mut bytes), &value).map_err(|error| {
        InvalidSnafu {
            reason: format!("canonical CBOR encoding failed: {error}"),
        }
        .build()
    })?;
    Ok(bytes)
}
