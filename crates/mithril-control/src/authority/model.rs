use std::collections::{BTreeMap, BTreeSet};

use minicbor::{bytes::ByteArray, Decode, Decoder, Encode, Encoder};
use serde::{Deserialize, Serialize};

use super::IntentReplayWindowV1;
use crate::{ProviderV1, Result};

pub const MAX_AUTHORITY_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorityErrorCodeV1 {
    Invalid,
    Denied,
    Expired,
    Replay,
    Conflict,
    Unavailable,
}

impl AuthorityErrorCodeV1 {
    pub(crate) fn require(self, value: bool, field: &'static str) -> Result<()> {
        if value {
            Ok(())
        } else {
            Err(self.error(field))
        }
    }

    pub(crate) fn error(self, field: &'static str) -> crate::Error {
        crate::error::AuthoritySnafu { code: self, field }.build()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum LocalAuthoritySubjectV1 {
    Process {
        node_boot_id: [u8; 16],
        execution_set_id: [u8; 16],
        process_lineage_id: [u8; 16],
    },
    Job {
        coordinator: ProviderV1,
        run_id: Vec<u8>,
        job_id: Vec<u8>,
        step_id: Option<Vec<u8>>,
    },
}

impl LocalAuthoritySubjectV1 {
    fn valid(&self) -> bool {
        match self {
            Self::Process {
                node_boot_id,
                execution_set_id,
                process_lineage_id,
            } => {
                *node_boot_id != [0; 16]
                    && *execution_set_id != [0; 16]
                    && *process_lineage_id != [0; 16]
            }
            Self::Job {
                coordinator,
                run_id,
                job_id,
                step_id,
            } => {
                coordinator.intent_tag().is_some()
                    && (1..=256).contains(&run_id.len())
                    && (1..=256).contains(&job_id.len())
                    && step_id
                        .as_ref()
                        .is_none_or(|step| (1..=256).contains(&step.len()))
            }
        }
    }

    fn key(
        decoder: &mut Decoder<'_>,
        expected: u8,
    ) -> std::result::Result<(), minicbor::decode::Error> {
        if decoder.u8()? == expected {
            Ok(())
        } else {
            Err(minicbor::decode::Error::message("invalid subject key"))
        }
    }
}

impl<C> Encode<C> for LocalAuthoritySubjectV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        context: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Process {
                node_boot_id,
                execution_set_id,
                process_lineage_id,
            } => {
                encoder
                    .map(4)?
                    .u8(0)?
                    .u8(1)?
                    .u8(1)?
                    .bytes(node_boot_id)?
                    .u8(2)?
                    .bytes(execution_set_id)?
                    .u8(3)?
                    .bytes(process_lineage_id)?;
            }
            Self::Job {
                coordinator,
                run_id,
                job_id,
                step_id,
            } => {
                encoder
                    .map(if step_id.is_some() { 5 } else { 4 })?
                    .u8(0)?
                    .u8(2)?
                    .u8(1)?;
                coordinator.encode_intent(encoder, context)?;
                encoder.u8(2)?.bytes(run_id)?.u8(3)?.bytes(job_id)?;
                if let Some(step) = step_id {
                    encoder.u8(4)?.bytes(step)?;
                }
            }
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for LocalAuthoritySubjectV1 {
    fn decode(
        decoder: &mut Decoder<'b>,
        context: &mut C,
    ) -> std::result::Result<Self, minicbor::decode::Error> {
        let fields = decoder
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite subject"))?;
        Self::key(decoder, 0)?;
        let tag = decoder.u8()?;
        Self::key(decoder, 1)?;
        let value = match tag {
            1 if fields == 4 => {
                let node_boot_id = decoder
                    .bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("subject boot ID"))?;
                Self::key(decoder, 2)?;
                let execution_set_id = decoder
                    .bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("subject execution ID"))?;
                Self::key(decoder, 3)?;
                let process_lineage_id = decoder
                    .bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("subject process ID"))?;
                Self::Process {
                    node_boot_id,
                    execution_set_id,
                    process_lineage_id,
                }
            }
            2 if (4..=5).contains(&fields) => {
                let coordinator = ProviderV1::decode_intent(decoder, context)?;
                Self::key(decoder, 2)?;
                let run_id = decoder.bytes()?.to_vec();
                Self::key(decoder, 3)?;
                let job_id = decoder.bytes()?.to_vec();
                let step_id = if fields == 5 {
                    Self::key(decoder, 4)?;
                    Some(decoder.bytes()?.to_vec())
                } else {
                    None
                };
                Self::Job {
                    coordinator,
                    run_id,
                    job_id,
                    step_id,
                }
            }
            _ => return Err(minicbor::decode::Error::message("subject variant fields")),
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(minicbor::decode::Error::message("invalid subject"))
        }
    }
}

impl ProviderV1 {
    fn intent_tag(self) -> Option<u8> {
        match self {
            Self::Kubernetes => Some(1),
            Self::Aws => Some(2),
            Self::Gcp => Some(3),
            Self::Github => Some(4),
            Self::InternalConnector => Some(5),
            Self::OciRegistry => Some(6),
            _ => None,
        }
    }

    fn encode_intent<W: minicbor::encode::Write, C>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u8(self
            .intent_tag()
            .ok_or_else(|| minicbor::encode::Error::message("unregistered provider"))?)?;
        Ok(())
    }

    fn decode_intent<'b, C>(
        decoder: &mut Decoder<'b>,
        _context: &mut C,
    ) -> std::result::Result<Self, minicbor::decode::Error> {
        match decoder.u8()? {
            1 => Ok(Self::Kubernetes),
            2 => Ok(Self::Aws),
            3 => Ok(Self::Gcp),
            4 => Ok(Self::Github),
            5 => Ok(Self::InternalConnector),
            6 => Ok(Self::OciRegistry),
            _ => Err(minicbor::decode::Error::message("unregistered provider")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
#[cbor(map)]
pub struct AuthorityResourceV1 {
    #[n(0)]
    pub resource_kind_id: u16,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub canonical_resource: Vec<u8>,
    #[n(2)]
    pub immutable_revision: Option<AuthorityResourceDigestV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
#[cbor(map)]
pub struct AuthorityResourceDigestV1 {
    #[n(0)]
    pub algorithm: u8,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
#[cbor(map)]
pub struct AuthorityLeaseBodyV1 {
    #[n(0)]
    pub subject: LocalAuthoritySubjectV1,
    #[n(1)]
    #[cbor(
        encode_with = "ProviderV1::encode_intent",
        decode_with = "ProviderV1::decode_intent"
    )]
    pub provider: ProviderV1,
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub account: Vec<u8>,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub audience: Vec<u8>,
    #[n(4)]
    pub permission_ids: Vec<u32>,
    #[n(5)]
    pub resources: Vec<AuthorityResourceV1>,
    #[n(6)]
    pub maximum_ttl_ns: u64,
    #[n(7)]
    #[cbor(with = "minicbor::bytes")]
    pub issuer_subject: Vec<u8>,
    #[n(8)]
    #[cbor(with = "minicbor::bytes")]
    pub request_nonce: [u8; 16],
}

impl AuthorityLeaseBodyV1 {
    pub fn validate(&self) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(
            self.subject.valid()
                && self.provider.intent_tag().is_some()
                && (1..=256).contains(&self.account.len())
                && (1..=512).contains(&self.audience.len())
                && (1..=128).contains(&self.permission_ids.len())
                && self.permission_ids[0] > 0
                && self.permission_ids.windows(2).all(|pair| pair[0] < pair[1])
                && (1..=128).contains(&self.resources.len())
                && self.resources.windows(2).all(|pair| pair[0] < pair[1])
                && self.resources.iter().all(|resource| {
                    resource.resource_kind_id > 0
                        && (1..=1024).contains(&resource.canonical_resource.len())
                        && resource
                            .immutable_revision
                            .as_ref()
                            .is_none_or(|digest| digest.algorithm == 1 && digest.sha256 != [0; 32])
                })
                && (1..=86_400_000_000_000).contains(&self.maximum_ttl_ns)
                && (1..=256).contains(&self.issuer_subject.len())
                && self.request_nonce != [0; 16],
            "authority body",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub(crate) struct AuthorityIntentBodyV1 {
    #[n(0)]
    pub tag: u8,
    #[n(1)]
    pub lease: AuthorityLeaseBodyV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub(crate) struct AuthorityIntentPayloadV1 {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub kind: u8,
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub proof_id: [u8; 16],
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub tenant_id: [u8; 16],
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub trust_domain_id: [u8; 16],
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub issuer_id: [u8; 16],
    #[n(6)]
    pub sequence_epoch: u64,
    #[n(7)]
    pub sequence: u64,
    #[n(8)]
    pub issued_utc_ns: i64,
    #[n(9)]
    pub not_before_utc_ns: i64,
    #[n(10)]
    pub expires_utc_ns: i64,
    #[n(11)]
    pub slots: Vec<ByteArray<16>>,
    #[n(12)]
    pub body: AuthorityIntentBodyV1,
    #[n(13)]
    #[cbor(with = "minicbor::bytes")]
    pub parent: Option<[u8; 16]>,
    #[n(14)]
    pub triggers: Option<Vec<ByteArray<16>>>,
}

impl AuthorityIntentPayloadV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.body.lease.validate()?;
        AuthorityErrorCodeV1::Invalid.require(
            self.version == 1
                && self.kind == 3
                && self.body.tag == 3
                && self.proof_id != [0; 16]
                && self.tenant_id != [0; 16]
                && self.trust_domain_id != [0; 16]
                && self.issuer_id != [0; 16]
                && self.sequence_epoch > 0
                && self.sequence > 0
                && self.issued_utc_ns > 0
                && self.not_before_utc_ns >= self.issued_utc_ns
                && self.expires_utc_ns > self.not_before_utc_ns
                && self
                    .expires_utc_ns
                    .checked_sub(self.issued_utc_ns)
                    .is_some_and(|duration| duration <= 86_400_000_000_000)
                && self.slots.len() == 1
                && self.slots.iter().all(|slot| **slot != [0; 16])
                && self.parent.is_none_or(|id| id != [0; 16])
                && self.triggers.as_ref().is_none_or(|triggers| {
                    (1..=16).contains(&triggers.len())
                        && triggers.iter().all(|id| **id != [0; 16])
                        && triggers.windows(2).all(|pair| pair[0] < pair[1])
                }),
            "authority intent",
        )
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = minicbor::to_vec(self)?;
        super::CanonicalIntentV1::validate(&bytes)?;
        Ok(bytes)
    }
}

impl TryFrom<&[u8]> for AuthorityIntentPayloadV1 {
    type Error = crate::Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        super::CanonicalIntentV1::validate(bytes)?;
        let payload: Self = minicbor::decode(bytes)?;
        payload.validate()?;
        AuthorityErrorCodeV1::Invalid
            .require(payload.bytes()? == bytes, "intent canonical fields")?;
        Ok(payload)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScopeV1 {
    pub tenant_id: [u8; 16],
    pub subject: LocalAuthoritySubjectV1,
    pub provider: ProviderV1,
    pub account: Vec<u8>,
    pub audience: Vec<u8>,
    pub permission_ids: Vec<u32>,
    pub resources: Vec<AuthorityResourceV1>,
    pub maximum_ttl_ns: u64,
    pub issuer_subject: Vec<u8>,
}

impl AuthorityScopeV1 {
    pub(crate) fn permits(&self, tenant: [u8; 16], body: &AuthorityLeaseBodyV1) -> bool {
        self.tenant_id == tenant
            && self.subject == body.subject
            && self.provider == body.provider
            && self.account == body.account
            && self.audience == body.audience
            && self.issuer_subject == body.issuer_subject
            && body.maximum_ttl_ns <= self.maximum_ttl_ns
            && body
                .permission_ids
                .iter()
                .all(|permission| self.permission_ids.contains(permission))
            && body
                .resources
                .iter()
                .all(|resource| self.resources.contains(resource))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityIssuerV1 {
    pub issuer_id: [u8; 16],
    pub key_id: Vec<u8>,
    pub public_key: [u8; 32],
    pub sequence_epoch: u64,
    pub valid_from_utc_ns: i64,
    pub valid_until_utc_ns: i64,
    pub revoked: bool,
    pub scopes: Vec<AuthorityScopeV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTrustV1 {
    pub trust_domain_id: [u8; 16],
    pub revision: u64,
    pub maximum_clock_skew_ns: i64,
    pub issuers: Vec<AuthorityIssuerV1>,
    pub approvers: Vec<[u8; 16]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityLeaseRequestV1 {
    pub schema_version: u32,
    pub request_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub requester_principal_id: [u8; 16],
    pub requested_utc_ns: i64,
    pub body: AuthorityLeaseBodyV1,
}

impl AuthorityLeaseRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.body.validate()?;
        AuthorityErrorCodeV1::Invalid.require(
            self.schema_version == 1
                && self.request_id != [0; 16]
                && self.tenant_id != [0; 16]
                && self.requester_principal_id != [0; 16]
                && self.requested_utc_ns > 0,
            "authority request",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorityIntentStateV1 {
    Pending,
    Requesting,
    Issued,
    Denied,
    Failed,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityApprovalV1 {
    pub request_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub approver_principal_id: [u8; 16],
    pub trust_revision: u64,
    pub proof_id: [u8; 16],
    pub claim_slot_id: [u8; 16],
    pub accepted_utc_ns: i64,
    pub expires_utc_ns: i64,
    pub signed_intent: Vec<u8>,
    pub state: AuthorityIntentStateV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialLeaseStateV1 {
    Active,
    Expired,
    RevokeRequested,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderAuthorityProofV1 {
    Missing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialLeaseV1 {
    pub schema_version: u32,
    pub lease_id: [u8; 16],
    pub request_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub provider: ProviderV1,
    pub account: Vec<u8>,
    pub audience: Vec<u8>,
    pub provider_principal: Vec<u8>,
    pub public_session_id: Vec<u8>,
    pub permission_ids: Vec<u32>,
    pub resources: Vec<AuthorityResourceV1>,
    pub request_nonce: [u8; 16],
    pub issued_utc_ns: i64,
    pub expires_utc_ns: i64,
    pub provider_proof: ProviderAuthorityProofV1,
    pub state: CredentialLeaseStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAuditHandleV1 {
    pub schema_version: u32,
    pub handle_id: [u8; 16],
    pub lease_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub provider: ProviderV1,
    pub provider_request_id: Vec<u8>,
    pub provider_result_id: Vec<u8>,
    pub public_audit_id: Vec<u8>,
}

pub(crate) type AuthorityReplayKeyV1 = super::IntentReplayKeyV1<[u8; 16]>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorityStateV1 {
    pub revision: u64,
    pub trust: Option<AuthorityTrustV1>,
    pub requests: BTreeMap<[u8; 16], AuthorityLeaseRequestV1>,
    pub approvals: BTreeMap<[u8; 16], AuthorityApprovalV1>,
    pub leases: BTreeMap<[u8; 16], CredentialLeaseV1>,
    pub handles: BTreeMap<[u8; 16], AuthorityAuditHandleV1>,
    pub windows: BTreeMap<AuthorityReplayKeyV1, IntentReplayWindowV1>,
    pub proofs: BTreeSet<[u8; 16]>,
    pub slots: BTreeSet<[u8; 16]>,
    pub notification_grants: BTreeMap<([u8; 16], [u8; 16]), ConfiguredNotificationGrantV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfiguredNotificationGrantV1 {
    pub grant: araphor_data::NotificationGrantV1,
    pub revoked: bool,
}

impl CredentialLeaseV1 {
    pub fn validate(&self) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(
            self.schema_version == 1
                && self.lease_id != [0; 16]
                && self.request_id != [0; 16]
                && self.tenant_id != [0; 16]
                && self.provider.intent_tag().is_some()
                && (1..=256).contains(&self.account.len())
                && (1..=512).contains(&self.audience.len())
                && (1..=256).contains(&self.provider_principal.len())
                && (1..=256).contains(&self.public_session_id.len())
                && self.request_nonce != [0; 16]
                && self.issued_utc_ns > 0
                && self.expires_utc_ns > self.issued_utc_ns
                && self.state != CredentialLeaseStateV1::Active
                && (1..=128).contains(&self.permission_ids.len())
                && self.permission_ids[0] > 0
                && self.permission_ids.windows(2).all(|pair| pair[0] < pair[1])
                && (1..=128).contains(&self.resources.len())
                && self.resources.windows(2).all(|pair| pair[0] < pair[1]),
            "credential lease record",
        )
    }
}

impl AuthorityAuditHandleV1 {
    pub fn validate(&self) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(
            self.schema_version == 1
                && self.handle_id != [0; 16]
                && self.lease_id != [0; 16]
                && self.tenant_id != [0; 16]
                && self.provider.intent_tag().is_some()
                && (1..=256).contains(&self.provider_request_id.len())
                && (1..=256).contains(&self.provider_result_id.len())
                && (1..=256).contains(&self.public_audit_id.len()),
            "authority audit handle",
        )
    }
}
