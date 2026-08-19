use std::convert::Infallible;

use erebor_interceptor_abi::{EffectObservationV1, Id128V1};
use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes as _;

use crate::error::{EvidenceStateSnafu, IdentityStateSnafu};
use crate::Result;

pub const MAX_EVIDENCE_FIELDS_V1: usize = 64;
pub const MAX_PROVENANCE_OBSERVATIONS_V1: usize = 16;

pub type EvidenceDigestV1 = [u8; 32];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdV1 {
    pub high: u64,
    pub low: u64,
}

impl EvidenceIdV1 {
    pub const ZERO: Self = Self { high: 0, low: 0 };

    #[must_use]
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.high == 0 && self.low == 0
    }

    #[must_use]
    pub fn from_digest(digest: EvidenceDigestV1) -> Self {
        Self {
            high: u64::from_be_bytes([
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            ]),
            low: u64::from_be_bytes([
                digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
                digest[15],
            ]),
        }
    }

    fn update_digest(self, digest: &mut Sha256) {
        digest.update(self.high.to_be_bytes());
        digest.update(self.low.to_be_bytes());
    }
}

impl From<Id128V1> for EvidenceIdV1 {
    fn from(value: Id128V1) -> Self {
        Self::new(value.high, value.low)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceFieldKeyV1 {
    FindingId,
    ReasonCode,
    Decision,
    Errno,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SensitivityV1 {
    Public,
    Internal,
    SensitiveIdentifier,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceAuthorityV1 {
    KernelDecision,
    SignedCoordinator,
    AuthoritativeProvider,
    AuthenticatedMeasurement,
    Unauthenticated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalSubjectBindingV1 {
    ExactTask,
    ExactProcess,
    ExactExecutionSet,
    Contextual,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteSubjectBindingV1 {
    ExactRequest,
    ExactSession,
    ExactObject,
    PrincipalOnly,
    Contextual,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationResultAuthorityV1 {
    PreEffectDecision,
    AuthoritativeSucceeded,
    AuthoritativeDenied,
    ObservedAttempt,
    Contextual,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TemporalCoverageV1 {
    Complete,
    Gapped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityV1 {
    Signed,
    AuthenticatedChannel,
    LocalAttested,
    Unverified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofQualityV1 {
    pub source_authority: SourceAuthorityV1,
    pub local_subject_binding: LocalSubjectBindingV1,
    pub remote_subject_binding: RemoteSubjectBindingV1,
    pub operation_result_authority: OperationResultAuthorityV1,
    pub temporal_coverage: TemporalCoverageV1,
    pub integrity: IntegrityV1,
}

impl ProofQualityV1 {
    #[must_use]
    pub const fn kernel_decision(temporal_coverage: TemporalCoverageV1) -> Self {
        Self {
            source_authority: SourceAuthorityV1::KernelDecision,
            local_subject_binding: LocalSubjectBindingV1::ExactTask,
            remote_subject_binding: RemoteSubjectBindingV1::None,
            operation_result_authority: OperationResultAuthorityV1::PreEffectDecision,
            temporal_coverage,
            integrity: IntegrityV1::LocalAttested,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum EvidenceValueV1 {
    Digest(EvidenceDigestV1),
    ReasonCode(u32),
    Decision(u32),
    Errno(i16),
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
    pub sensitivity: SensitivityV1,
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
    pub fn new(mut fields: Vec<EvidenceFieldV1>) -> Result<Self> {
        fields.sort_unstable_by_key(|field| field.key);
        let payload = Self { fields };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        if self.fields.is_empty()
            || self.fields.len() > MAX_EVIDENCE_FIELDS_V1
            || self
                .fields
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || self.fields.iter().any(|field| {
                field.provenance_observation_ids.len() > MAX_PROVENANCE_OBSERVATIONS_V1
                    || field
                        .provenance_observation_ids
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || !field_value_matches_key(field.key, &field.value)
            })
        {
            return IdentityStateSnafu {
                reason: "observation payload fields are unbounded, repeated, unsorted, or mistyped"
                    .to_owned(),
            }
            .fail();
        }
        Ok(())
    }
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
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.payload.validate()?;
        canonical_cbor(self)
    }

    pub fn wire_bytes(&self) -> Result<Vec<u8>> {
        self.payload.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("observation wire encoding failed: {error}"),
            }
            .build()
        })
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = serde_json::from_slice(bytes).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("observation wire decoding failed: {error}"),
            }
            .build()
        })?;
        envelope.payload.validate()?;
        if envelope.schema_version != 1
            || envelope.tenant_id.is_zero()
            || envelope.observation_id == [0; 32]
            || envelope.source_id.is_zero()
            || envelope.source_epoch == 0
            || envelope.source_sequence == 0
            || envelope.coverage_interval_id.is_zero()
            || envelope.transport_integrity_digest == [0; 32]
        {
            return EvidenceStateSnafu {
                reason: "observation wire identity or version is invalid".to_owned(),
            }
            .fail();
        }
        Ok(envelope)
    }

    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        self.proof_quality.temporal_coverage == TemporalCoverageV1::Complete
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ObservationCanonicalizer {
    tenant_id: EvidenceIdV1,
    source_id: EvidenceIdV1,
    source_epoch: u64,
    node_boot_id: EvidenceIdV1,
}

impl ObservationCanonicalizer {
    pub fn new(
        tenant_id: EvidenceIdV1,
        source_id: EvidenceIdV1,
        source_epoch: u64,
        node_boot_id: EvidenceIdV1,
    ) -> Result<Self> {
        if tenant_id.is_zero() || source_id.is_zero() || source_epoch == 0 || node_boot_id.is_zero()
        {
            return IdentityStateSnafu {
                reason: "observation canonicalizer requires nonzero tenant, source, epoch, and boot identities"
                    .to_owned(),
            }
            .fail();
        }
        Ok(Self {
            tenant_id,
            source_id,
            source_epoch,
            node_boot_id,
        })
    }

    #[must_use]
    pub const fn source_epoch(self) -> u64 {
        self.source_epoch
    }

    pub fn normalize_kernel(
        self,
        event: EffectObservationV1,
        coverage_interval_id: EvidenceIdV1,
        temporal_coverage: TemporalCoverageV1,
        ingested_utc_ns: i64,
    ) -> Result<ObservationEnvelopeV1> {
        if event.source_sequence == 0 || coverage_interval_id.is_zero() {
            return IdentityStateSnafu {
                reason:
                    "kernel observation requires a nonzero source sequence and coverage interval"
                        .to_owned(),
            }
            .fail();
        }
        let source_id = self.cpu_source_id(event.source_cpu_id);
        let proof_quality = ProofQualityV1::kernel_decision(temporal_coverage);
        let payload = kernel_payload(&event, proof_quality)?;
        let transport_integrity_digest = Sha256::digest(event.as_bytes()).into();
        let observation_id = observation_id(
            self.tenant_id,
            source_id,
            self.source_epoch,
            event.source_sequence,
            1,
            &payload,
        )?;
        Ok(ObservationEnvelopeV1 {
            schema_version: 1,
            tenant_id: self.tenant_id,
            observation_id,
            source_id,
            source_epoch: self.source_epoch,
            source_sequence: event.source_sequence,
            stable_provider_event_id: None,
            node_boot_id: Some(self.node_boot_id),
            cpu_id: Some(event.source_cpu_id),
            hook_or_adapter_id: u32::from(event.effect_family),
            payload_schema_id: 1,
            abi_or_api_version: 1,
            profile_generation_ref_id: (event.profile_generation_ref_id > 0)
                .then_some(event.profile_generation_ref_id),
            boottime_ns: Some(event.observed_boottime_ns),
            projected_utc_ns: None,
            time_uncertainty_ns: u64::MAX,
            ingested_utc_ns,
            payload,
            proof_quality,
            coverage_interval_id,
            transport_integrity_digest,
            signature_or_batch_digest: None,
        })
    }

    pub(crate) fn cpu_source_id(self, cpu_id: u32) -> EvidenceIdV1 {
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-KERNEL-SOURCE-V1\0");
        self.source_id.update_digest(&mut digest);
        digest.update(cpu_id.to_be_bytes());
        EvidenceIdV1::from_digest(digest.finalize().into())
    }
}

fn kernel_payload(
    event: &EffectObservationV1,
    proof_quality: ProofQualityV1,
) -> Result<EvidencePayloadV1> {
    let mut fields = vec![
        field(
            EvidenceFieldKeyV1::ReasonCode,
            EvidenceValueV1::ReasonCode(u32::from(event.reason)),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::Decision,
            EvidenceValueV1::Decision(u32::from(event.physical_result)),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::Errno,
            EvidenceValueV1::Errno(event.configured_errno),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::TaskCookie,
            EvidenceValueV1::TaskCookie(event.task_cookie),
            proof_quality,
        ),
    ];
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::ProcessLineageId,
        event.process_lineage_id,
        proof_quality,
    );
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::AuthorityDomainId,
        event.authority_domain_id,
        proof_quality,
    );
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::ExecutionSetId,
        event.execution_set_id,
        proof_quality,
    );
    if event.exact_object_key_id > 0 {
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-EXACT-OBJECT-V1\0");
        digest.update(event.file_object.as_bytes());
        digest.update(event.exact_object_key_id.to_be_bytes());
        fields.push(field(
            EvidenceFieldKeyV1::ExactObjectId,
            EvidenceValueV1::Id(EvidenceIdV1::from_digest(digest.finalize().into())),
            proof_quality,
        ));
    }
    if event.network_destination_policy_handle > 0 {
        fields.push(field(
            EvidenceFieldKeyV1::DestinationId,
            EvidenceValueV1::Destination(event.network_destination_policy_handle),
            proof_quality,
        ));
    }
    if event.composite_atom_id > 0 {
        fields.push(field(
            EvidenceFieldKeyV1::PolicyRuleIds,
            EvidenceValueV1::PolicyRules(vec![event.composite_atom_id]),
            proof_quality,
        ));
    }
    EvidencePayloadV1::new(fields)
}

fn field(
    key: EvidenceFieldKeyV1,
    value: EvidenceValueV1,
    proof_quality: ProofQualityV1,
) -> EvidenceFieldV1 {
    EvidenceFieldV1 {
        key,
        sensitivity: SensitivityV1::Internal,
        provenance_observation_ids: Vec::new(),
        proof_quality,
        value,
    }
}

fn push_id(
    fields: &mut Vec<EvidenceFieldV1>,
    key: EvidenceFieldKeyV1,
    value: Id128V1,
    proof_quality: ProofQualityV1,
) {
    if !value.is_zero() {
        fields.push(field(key, EvidenceValueV1::Id(value.into()), proof_quality));
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
            | (EvidenceFieldKeyV1::Errno, EvidenceValueV1::Errno(_))
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

fn observation_id(
    tenant_id: EvidenceIdV1,
    source_id: EvidenceIdV1,
    source_epoch: u64,
    source_sequence: u64,
    payload_schema_id: u32,
    payload: &EvidencePayloadV1,
) -> Result<EvidenceDigestV1> {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-OBSERVATION-ID-V1\0");
    tenant_id.update_digest(&mut digest);
    source_id.update_digest(&mut digest);
    digest.update(source_epoch.to_be_bytes());
    digest.update(source_sequence.to_be_bytes());
    digest.update(payload_schema_id.to_be_bytes());
    digest.update(canonical_cbor(payload)?);
    Ok(digest.finalize().into())
}

fn canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("canonical observation value is invalid: {error}"),
        }
        .build()
    })?;
    let mut bytes = Vec::new();
    encode_value(&mut Encoder::new(&mut bytes), &value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("canonical observation CBOR encoding failed: {error}"),
        }
        .build()
    })?;
    Ok(bytes)
}

fn encode_value(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: &serde_json::Value,
) -> std::result::Result<(), minicbor::encode::Error<Infallible>> {
    match value {
        serde_json::Value::Null => {
            encoder.null()?;
        }
        serde_json::Value::Bool(value) => {
            encoder.bool(*value)?;
        }
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                encoder.u64(value)?;
            } else if let Some(value) = value.as_i64() {
                encoder.i64(value)?;
            } else {
                return Err(minicbor::encode::Error::message(
                    "floating-point evidence values are forbidden",
                ));
            }
        }
        serde_json::Value::String(value) => {
            encoder.str(value)?;
        }
        serde_json::Value::Array(values) => {
            encoder.array(values.len() as u64)?;
            for value in values {
                encode_value(encoder, value)?;
            }
        }
        serde_json::Value::Object(values) => {
            let mut fields = values.iter().collect::<Vec<_>>();
            fields.sort_unstable_by_key(|(key, _)| *key);
            encoder.map(fields.len() as u64)?;
            for (key, value) in fields {
                encoder.str(key)?;
                encode_value(encoder, value)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{EffectObservationV1, Id128V1};

    use super::{
        EvidenceFieldKeyV1, EvidenceIdV1, EvidenceValueV1, ObservationCanonicalizer,
        TemporalCoverageV1,
    };

    fn canonicalizer() -> crate::Result<ObservationCanonicalizer> {
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            5,
            EvidenceIdV1::new(6, 7),
        )
    }

    fn event(cpu_id: u32) -> EffectObservationV1 {
        EffectObservationV1 {
            observed_boottime_ns: 10,
            source_sequence: 11,
            source_cpu_id: cpu_id,
            task_cookie: 12,
            profile_generation_ref_id: 13,
            process_lineage_id: Id128V1::new(14, 15),
            authority_domain_id: Id128V1::new(16, 17),
            execution_set_id: Id128V1::new(18, 19),
            exact_object_key_id: 20,
            composite_atom_id: 21,
            network_destination_policy_handle: 22,
            configured_errno: -13,
            reason: 9,
            physical_result: 1,
            ..EffectObservationV1::default()
        }
    }

    #[test]
    fn kernel_observation_has_stable_identity_and_no_raw_arguments() -> crate::Result<()> {
        let first = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let second = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            200,
        )?;
        assert_eq!(first.observation_id, second.observation_id);
        assert_ne!(first.canonical_bytes()?, second.canonical_bytes()?);
        assert!(first.supports_negative_claim());
        assert!(first.payload.fields.iter().any(|field| {
            field.key == EvidenceFieldKeyV1::TaskCookie
                && field.value == EvidenceValueV1::TaskCookie(12)
        }));
        let display = serde_json::to_string(&first);
        assert!(display.is_ok());
        let display = display.unwrap_or_default();
        assert!(!display.contains("argv"));
        assert!(!display.contains("secret"));
        Ok(())
    }

    #[test]
    fn each_cpu_is_an_independent_ordered_source() -> crate::Result<()> {
        let first = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let second = canonicalizer()?.normalize_kernel(
            event(3),
            EvidenceIdV1::new(32, 33),
            TemporalCoverageV1::Complete,
            100,
        )?;
        assert_ne!(first.source_id, second.source_id);
        assert_ne!(first.observation_id, second.observation_id);
        Ok(())
    }

    #[test]
    fn gapped_observation_cannot_support_a_negative_claim() -> crate::Result<()> {
        let observation = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Gapped,
            100,
        )?;
        assert!(!observation.supports_negative_claim());
        Ok(())
    }
}
