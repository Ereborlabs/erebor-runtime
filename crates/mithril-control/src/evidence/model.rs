use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use araphor_data::{
    EvidenceDecisionCatalogV1, EvidenceDigestV1, EvidenceFileObjectV1, EvidenceIdV1,
    EvidenceModelError, EvidenceModelResult, KernelEffectEvidenceV1, ObservationEnvelopeV1,
};

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
            _ => Err(EvidenceModelError::Invalid {
                reason: format!("coverage state `{value}` is invalid"),
                location: snafu::location!(),
            }),
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
            _ => Err(EvidenceModelError::Invalid {
                reason: format!("coverage gap reason `{value}` is invalid"),
                location: snafu::location!(),
            }),
        }
    }
}
