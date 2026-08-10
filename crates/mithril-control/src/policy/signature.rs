use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::canonical::canonical_cbor;
use super::{PolicyCompiler, PolicyDocumentV1, StaticExpandedProfileV1};
use crate::error::PolicySignatureSnafu;
use crate::Result;

const PROFILE_DOMAIN: &[u8] = b"MITHRIL-PROFILE-V1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileSignatureHeaderV1 {
    pub issuer_id: String,
    pub sequence_epoch: u64,
    pub issuer_sequence: u64,
    pub trust_domain_id: String,
    pub profile_id: String,
    pub profile_version: u64,
    pub valid_from_utc: String,
    pub valid_until_utc: Option<String>,
    pub rollback_authorization_id: Option<String>,
    pub policy_document_digest: String,
    pub provider_numeric_registry_bundle_digest: String,
    pub required_capability_schema_digest: String,
    pub source_selector_registry_digest: String,
    pub object_classifier_registry_digest: String,
    pub reason_code_registry_digest: String,
    pub correlation_package_registry_digest: String,
    pub provider_vocabulary_registry_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedWorkloadProtectionProfileV1 {
    pub schema_version: u32,
    pub signing_key_id: String,
    pub algorithm: SignatureAlgorithmV1,
    pub canonical_header: Vec<u8>,
    pub canonical_policy: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileCandidateArtifactV1 {
    pub header: ProfileSignatureHeaderV1,
    pub signed_profile: SignedWorkloadProtectionProfileV1,
    pub policy_document: PolicyDocumentV1,
    pub compiled_profile: StaticExpandedProfileV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignatureAlgorithmV1 {
    Ed25519,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileSealRequestV1 {
    pub signing_key_id: String,
    pub issuer_id: String,
    pub sequence_epoch: u64,
    pub issuer_sequence: u64,
    pub rollback_authorization_id: Option<String>,
    pub registry_digests: RegistryDigestsV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryDigestsV1 {
    pub provider_numeric_registry_bundle_digest: String,
    pub required_capability_schema_digest: String,
    pub source_selector_registry_digest: String,
    pub object_classifier_registry_digest: String,
    pub reason_code_registry_digest: String,
    pub correlation_package_registry_digest: String,
    pub provider_vocabulary_registry_digest: String,
}

impl SignedWorkloadProtectionProfileV1 {
    pub fn sign(
        document: &PolicyDocumentV1,
        compiled: &StaticExpandedProfileV1,
        request: ProfileSealRequestV1,
        key: &SigningKey,
    ) -> Result<Self> {
        require_nonzero(
            &request.signing_key_id,
            request.sequence_epoch,
            request.issuer_sequence,
        )?;
        let header = profile_header(document, compiled, request.clone());
        let canonical_header = canonical_cbor(document.profile_id(), &header)?;
        let input = signature_input(&canonical_header, &compiled.canonical_policy);
        Ok(Self {
            schema_version: 1,
            signing_key_id: request.signing_key_id,
            algorithm: SignatureAlgorithmV1::Ed25519,
            canonical_header,
            canonical_policy: compiled.canonical_policy.clone(),
            signature: key.sign(&input).to_bytes().to_vec(),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        if self.schema_version != 1
            || self.algorithm != SignatureAlgorithmV1::Ed25519
            || self.canonical_header.len() > 4096
            || self.canonical_policy.len() > 1_048_576
        {
            return PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: "envelope version, algorithm, or size is invalid",
            }
            .fail();
        }
        let signature = Signature::from_slice(&self.signature).map_err(|error| {
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: error.to_string(),
            }
            .build()
        })?;
        key.verify(
            &signature_input(&self.canonical_header, &self.canonical_policy),
            &signature,
        )
        .map_err(|error| {
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: error.to_string(),
            }
            .build()
        })
    }
}

impl ProfileCandidateArtifactV1 {
    pub fn sign(
        document: &PolicyDocumentV1,
        compiled_profile: StaticExpandedProfileV1,
        request: ProfileSealRequestV1,
        key: &SigningKey,
    ) -> Result<Self> {
        let header = profile_header(document, &compiled_profile, request.clone());
        let signed_profile =
            SignedWorkloadProtectionProfileV1::sign(document, &compiled_profile, request, key)?;
        Ok(Self {
            header,
            signed_profile,
            policy_document: document.clone(),
            compiled_profile,
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let canonical_header = canonical_cbor(&self.header.profile_id, &self.header)?;
        let verified_compilation = PolicyCompiler.compile(&self.policy_document)?;
        if canonical_header != self.signed_profile.canonical_header
            || verified_compilation != self.compiled_profile
            || self.compiled_profile.canonical_policy != self.signed_profile.canonical_policy
            || self.header.policy_document_digest
                != format!(
                    "{:x}",
                    Sha256::digest(&self.signed_profile.canonical_policy)
                )
            || self.header.profile_id != self.compiled_profile.profile_id
            || self.header.profile_version != self.compiled_profile.profile_version
            || self.header.trust_domain_id != self.policy_document.metadata.trust_domain_id
            || self.header.valid_from_utc != self.policy_document.metadata.valid_from_utc
            || self.header.valid_until_utc != self.policy_document.metadata.valid_until_utc
            || self.header.sequence_epoch == 0
            || self.header.issuer_sequence == 0
            || self.signed_profile.signing_key_id.is_empty()
            || !valid_uuid(&self.header.issuer_id)
            || !valid_uuid(&self.header.trust_domain_id)
            || !valid_uuid(&self.header.profile_id)
            || !header_digests(&self.header).all(valid_sha256)
        {
            return PolicySignatureSnafu {
                key_id: &self.signed_profile.signing_key_id,
                reason: "candidate header, policy, or compiler digest does not match the signed envelope",
            }
            .fail();
        }
        self.signed_profile.verify(key)
    }

    pub fn verify_at(&self, key: &VerifyingKey, now_utc_ns: i64) -> Result<()> {
        self.verify(key)?;
        let valid_from = timestamp_ns(&self.header.valid_from_utc).ok_or_else(|| {
            PolicySignatureSnafu {
                key_id: &self.signed_profile.signing_key_id,
                reason: "candidate valid_from_utc is outside the exact UTC nanosecond range",
            }
            .build()
        })?;
        let valid_until = match self.header.valid_until_utc.as_deref() {
            Some(value) => Some(timestamp_ns(value).ok_or_else(|| {
                PolicySignatureSnafu {
                    key_id: &self.signed_profile.signing_key_id,
                    reason: "candidate valid_until_utc is outside the exact UTC nanosecond range",
                }
                .build()
            })?),
            None => None,
        };
        if now_utc_ns < valid_from || valid_until.is_some_and(|until| now_utc_ns >= until) {
            return PolicySignatureSnafu {
                key_id: &self.signed_profile.signing_key_id,
                reason: "candidate is not valid at the requested UTC instant",
            }
            .fail();
        }
        Ok(())
    }
}

fn timestamp_ns(value: &str) -> Option<i64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()?
        .unix_timestamp_nanos()
        .try_into()
        .ok()
}

fn header_digests(header: &ProfileSignatureHeaderV1) -> impl Iterator<Item = &str> {
    [
        header.policy_document_digest.as_str(),
        header.provider_numeric_registry_bundle_digest.as_str(),
        header.required_capability_schema_digest.as_str(),
        header.source_selector_registry_digest.as_str(),
        header.object_classifier_registry_digest.as_str(),
        header.reason_code_registry_digest.as_str(),
        header.correlation_package_registry_digest.as_str(),
        header.provider_vocabulary_registry_digest.as_str(),
    ]
    .into_iter()
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn profile_header(
    document: &PolicyDocumentV1,
    compiled: &StaticExpandedProfileV1,
    request: ProfileSealRequestV1,
) -> ProfileSignatureHeaderV1 {
    let digests = request.registry_digests;
    ProfileSignatureHeaderV1 {
        issuer_id: request.issuer_id,
        sequence_epoch: request.sequence_epoch,
        issuer_sequence: request.issuer_sequence,
        trust_domain_id: document.metadata.trust_domain_id.clone(),
        profile_id: document.metadata.profile_id.clone(),
        profile_version: document.metadata.profile_version,
        valid_from_utc: document.metadata.valid_from_utc.clone(),
        valid_until_utc: document.metadata.valid_until_utc.clone(),
        rollback_authorization_id: request.rollback_authorization_id,
        policy_document_digest: compiled.source_policy_digest.clone(),
        provider_numeric_registry_bundle_digest: digests.provider_numeric_registry_bundle_digest,
        required_capability_schema_digest: digests.required_capability_schema_digest,
        source_selector_registry_digest: digests.source_selector_registry_digest,
        object_classifier_registry_digest: digests.object_classifier_registry_digest,
        reason_code_registry_digest: digests.reason_code_registry_digest,
        correlation_package_registry_digest: digests.correlation_package_registry_digest,
        provider_vocabulary_registry_digest: digests.provider_vocabulary_registry_digest,
    }
}

fn signature_input(header: &[u8], policy: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PROFILE_DOMAIN.len() + 64);
    input.extend_from_slice(PROFILE_DOMAIN);
    input.extend_from_slice(&Sha256::digest(header));
    input.extend_from_slice(&Sha256::digest(policy));
    input
}

fn require_nonzero(key_id: &str, epoch: u64, sequence: u64) -> Result<()> {
    if !key_id.is_empty() && epoch > 0 && sequence > 0 {
        Ok(())
    } else {
        PolicySignatureSnafu {
            key_id,
            reason: "key ID and nonzero sequence epoch/sequence are required",
        }
        .fail()
    }
}
