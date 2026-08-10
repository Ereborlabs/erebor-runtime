use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::canonical::canonical_cbor;
use super::{ProfileCandidateArtifactV1, ProfileSignatureHeaderV1, SignatureAlgorithmV1};
use crate::error::{IoSnafu, JsonSnafu, PolicySignatureSnafu, PolicyStateSnafu};
use crate::Result;

const ROLLBACK_DOMAIN: &[u8] = b"MITHRIL-ROLLBACK-V1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackAuthorizationPayloadV1 {
    pub authorization_id: String,
    pub trust_domain_id: String,
    pub issuer_id: String,
    pub approver_principal_id: String,
    pub sequence_epoch: u64,
    pub issuer_sequence: u64,
    pub profile_id: String,
    pub current_digest: String,
    pub current_version: u64,
    pub exact_older_target_digest: String,
    pub exact_older_target_version: u64,
    pub closed_reason_code: u32,
    pub human_reason_artifact_digest: Option<String>,
    pub exact_platform_scope_digest: String,
    pub issued_at_utc_ns: i64,
    pub expires_at_utc_ns: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedRollbackAuthorizationV1 {
    pub schema_version: u32,
    pub signing_key_id: String,
    pub algorithm: SignatureAlgorithmV1,
    pub canonical_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackAuthorizationArtifactV1 {
    pub payload: RollbackAuthorizationPayloadV1,
    pub signed_authorization: SignedRollbackAuthorizationV1,
}

impl RollbackAuthorizationArtifactV1 {
    pub fn sign(
        signing_key_id: String,
        payload: RollbackAuthorizationPayloadV1,
        key: &SigningKey,
    ) -> Result<Self> {
        let canonical_payload = canonical_cbor(&payload.profile_id, &payload)?;
        let signature = key.sign(&rollback_input(&canonical_payload));
        Ok(Self {
            payload,
            signed_authorization: SignedRollbackAuthorizationV1 {
                schema_version: 1,
                signing_key_id,
                algorithm: SignatureAlgorithmV1::Ed25519,
                canonical_payload,
                signature: signature.to_bytes().to_vec(),
            },
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let canonical = canonical_cbor(&self.payload.profile_id, &self.payload)?;
        let signed = &self.signed_authorization;
        if signed.schema_version != 1
            || signed.algorithm != SignatureAlgorithmV1::Ed25519
            || canonical != signed.canonical_payload
            || signed.canonical_payload.len() > 16_384
        {
            return PolicySignatureSnafu {
                key_id: &signed.signing_key_id,
                reason:
                    "rollback envelope version, algorithm, canonical payload, or size is invalid",
            }
            .fail();
        }
        let signature = Signature::from_slice(&signed.signature).map_err(|error| {
            PolicySignatureSnafu {
                key_id: &signed.signing_key_id,
                reason: error.to_string(),
            }
            .build()
        })?;
        key.verify(&rollback_input(&signed.canonical_payload), &signature)
            .map_err(|error| {
                PolicySignatureSnafu {
                    key_id: &signed.signing_key_id,
                    reason: error.to_string(),
                }
                .build()
            })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct AntiRollbackStateV1 {
    high_water: BTreeMap<String, AcceptedProfileV1>,
    consumed_rollback_authorization_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptedProfileV1 {
    greatest_sequence_epoch: u64,
    greatest_issuer_sequence: u64,
    greatest_profile_version: u64,
    current_profile_version: u64,
    current_policy_digest: String,
}

pub struct AntiRollbackStore {
    path: PathBuf,
    state: AntiRollbackStateV1,
}

impl AntiRollbackStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                AntiRollbackStateV1::default()
            }
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };
        Ok(Self { path, state })
    }

    pub fn accept(
        &mut self,
        candidate: &ProfileCandidateArtifactV1,
        rollback: Option<(&RollbackAuthorizationArtifactV1, &VerifyingKey)>,
        platform_scope_digest: &str,
        now_utc_ns: i64,
    ) -> Result<()> {
        let header = &candidate.header;
        let state_key = state_key(header);
        if let Some(current) = self.state.high_water.get(&state_key) {
            let identical = header.profile_version == current.current_profile_version
                && header.policy_document_digest == current.current_policy_digest;
            if identical {
                return Ok(());
            }
            let advances = (header.sequence_epoch, header.issuer_sequence)
                > (
                    current.greatest_sequence_epoch,
                    current.greatest_issuer_sequence,
                )
                && header.profile_version > current.greatest_profile_version;
            if !advances {
                let (proof, key) = rollback.ok_or_else(|| {
                    PolicyStateSnafu {
                        path: &self.path,
                        reason:
                            "profile rollback requires a separate verified one-use authorization",
                    }
                    .build()
                })?;
                proof.verify(key)?;
                self.validate_rollback(header, current, proof, platform_scope_digest, now_utc_ns)?;
                self.state
                    .consumed_rollback_authorization_ids
                    .insert(proof.payload.authorization_id.clone());
            }
        }
        let next = match self.state.high_water.get(&state_key) {
            Some(current) => AcceptedProfileV1 {
                greatest_sequence_epoch: current.greatest_sequence_epoch.max(header.sequence_epoch),
                greatest_issuer_sequence: if header.sequence_epoch > current.greatest_sequence_epoch
                {
                    header.issuer_sequence
                } else {
                    current.greatest_issuer_sequence.max(header.issuer_sequence)
                },
                greatest_profile_version: current
                    .greatest_profile_version
                    .max(header.profile_version),
                current_profile_version: header.profile_version,
                current_policy_digest: header.policy_document_digest.clone(),
            },
            None => AcceptedProfileV1 {
                greatest_sequence_epoch: header.sequence_epoch,
                greatest_issuer_sequence: header.issuer_sequence,
                greatest_profile_version: header.profile_version,
                current_profile_version: header.profile_version,
                current_policy_digest: header.policy_document_digest.clone(),
            },
        };
        self.state.high_water.insert(state_key, next);
        self.persist()
    }

    fn validate_rollback(
        &self,
        target: &ProfileSignatureHeaderV1,
        current: &AcceptedProfileV1,
        proof: &RollbackAuthorizationArtifactV1,
        platform_scope_digest: &str,
        now_utc_ns: i64,
    ) -> Result<()> {
        let payload = &proof.payload;
        let exact = target.rollback_authorization_id.as_deref()
            == Some(payload.authorization_id.as_str())
            && payload.trust_domain_id == target.trust_domain_id
            && payload.issuer_id == target.issuer_id
            && payload.profile_id == target.profile_id
            && payload.current_digest == current.current_policy_digest
            && payload.current_version == current.current_profile_version
            && payload.exact_older_target_digest == target.policy_document_digest
            && payload.exact_older_target_version == target.profile_version
            && payload.exact_platform_scope_digest == platform_scope_digest
            && payload.issued_at_utc_ns <= now_utc_ns
            && now_utc_ns < payload.expires_at_utc_ns
            && payload.sequence_epoch > 0
            && payload.issuer_sequence > 0
            && payload.current_version > payload.exact_older_target_version
            && !self
                .state
                .consumed_rollback_authorization_ids
                .contains(&payload.authorization_id);
        if exact {
            Ok(())
        } else {
            PolicyStateSnafu {
                path: &self.path,
                reason: "rollback authorization is expired, replayed, or does not exactly bind current, target, issuer, and platform",
            }
            .fail()
        }
    }

    fn persist(&self) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        let temporary = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec(&self.state).context(JsonSnafu { path: &self.path })?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .context(IoSnafu { path: &temporary })?;
        file.write_all(&bytes)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .context(IoSnafu { path: parent })?
            .sync_all()
            .context(IoSnafu { path: parent })
    }
}

fn state_key(header: &ProfileSignatureHeaderV1) -> String {
    format!(
        "{}\0{}\0{}",
        header.trust_domain_id, header.issuer_id, header.profile_id
    )
}

fn rollback_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(ROLLBACK_DOMAIN.len() + 32);
    input.extend_from_slice(ROLLBACK_DOMAIN);
    input.extend_from_slice(&Sha256::digest(payload));
    input
}
