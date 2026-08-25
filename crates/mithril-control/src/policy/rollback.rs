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
    #[serde(default)]
    greatest_policy_digest: Option<String>,
    #[serde(default)]
    current_profile_version: Option<u64>,
    #[serde(default)]
    current_policy_digest: Option<String>,
    #[serde(default)]
    current_activation: Option<ProfileActivationMetadataV1>,
    #[serde(default)]
    pending_activation: Option<PendingActivationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileActivationMetadataV1 {
    pub profile_generation_ref_id: u64,
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    pub descriptor_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingActivationV1 {
    profile_id: String,
    profile_version: u64,
    policy_digest: String,
    sequence_epoch: u64,
    issuer_sequence: u64,
    activation: ProfileActivationMetadataV1,
    previous_profile_generation_ref_id: Option<u64>,
    rollback_authorization_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingProfileActivationV1 {
    state_key: String,
    pub profile_id: String,
    pub profile_version: u64,
    pub policy_digest: String,
    pub sequence_epoch: u64,
    pub issuer_sequence: u64,
    pub activation: ProfileActivationMetadataV1,
    pub previous_profile_generation_ref_id: Option<u64>,
    pub rollback_authorization_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProfileCandidateV1 {
    state_key: String,
    profile_id: String,
    profile_version: u64,
    policy_digest: String,
    sequence_epoch: u64,
    issuer_sequence: u64,
    rollback_authorization_id: Option<String>,
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

    pub fn validate(
        &self,
        candidate: &ProfileCandidateArtifactV1,
        rollback: Option<(&RollbackAuthorizationArtifactV1, &VerifyingKey)>,
        platform_scope_digest: &str,
        now_utc_ns: i64,
    ) -> Result<ValidatedProfileCandidateV1> {
        let header = &candidate.header;
        let state_key = state_key(header);
        let mut rollback_authorization_id = None;
        if let Some(current) = self.state.high_water.get(&state_key) {
            if is_current(current, header) {
                // The active candidate stays valid while a newer publication is pending.
            } else if let Some(pending) = &current.pending_activation {
                if pending.profile_version != header.profile_version
                    || pending.policy_digest != header.policy_document_digest
                    || pending.sequence_epoch != header.sequence_epoch
                    || pending.issuer_sequence != header.issuer_sequence
                    || pending.rollback_authorization_id.as_deref()
                        != header.rollback_authorization_id.as_deref()
                {
                    return PolicyStateSnafu {
                        path: &self.path,
                        reason: "a different policy activation is pending for this profile",
                    }
                    .fail();
                }
                rollback_authorization_id = pending.rollback_authorization_id.clone();
            } else if !is_current(current, header)
                && !strictly_advances(current, header)
                && !is_exact_greatest(current, header)
            {
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
                rollback_authorization_id = Some(proof.payload.authorization_id.clone());
            }
        }
        Ok(ValidatedProfileCandidateV1 {
            state_key,
            profile_id: header.profile_id.clone(),
            profile_version: header.profile_version,
            policy_digest: header.policy_document_digest.clone(),
            sequence_epoch: header.sequence_epoch,
            issuer_sequence: header.issuer_sequence,
            rollback_authorization_id,
        })
    }

    #[must_use]
    pub fn is_current_activation(
        &self,
        candidate: &ValidatedProfileCandidateV1,
        activation: &ProfileActivationMetadataV1,
    ) -> bool {
        self.state
            .high_water
            .get(&candidate.state_key)
            .is_some_and(|profile| {
                is_current(profile, candidate)
                    && profile.current_activation.as_ref() == Some(activation)
            })
    }

    pub fn prepare_activation(
        &mut self,
        candidate: &ValidatedProfileCandidateV1,
        activation: ProfileActivationMetadataV1,
        previous_profile_generation_ref_id: Option<u64>,
    ) -> Result<PendingProfileActivationV1> {
        let pending = PendingActivationV1 {
            profile_id: candidate.profile_id.clone(),
            profile_version: candidate.profile_version,
            policy_digest: candidate.policy_digest.clone(),
            sequence_epoch: candidate.sequence_epoch,
            issuer_sequence: candidate.issuer_sequence,
            activation,
            previous_profile_generation_ref_id,
            rollback_authorization_id: candidate.rollback_authorization_id.clone(),
        };
        if let Some(authorization_id) = pending.rollback_authorization_id.as_deref() {
            if self.state.high_water.iter().any(|(key, profile)| {
                key != &candidate.state_key
                    && profile
                        .pending_activation
                        .as_ref()
                        .and_then(|pending| pending.rollback_authorization_id.as_deref())
                        == Some(authorization_id)
            }) {
                return PolicyStateSnafu {
                    path: &self.path,
                    reason: "rollback authorization is reserved by another pending activation",
                }
                .fail();
            }
        }
        let current = self
            .state
            .high_water
            .entry(candidate.state_key.clone())
            .or_insert_with(|| AcceptedProfileV1 {
                greatest_sequence_epoch: candidate.sequence_epoch,
                greatest_issuer_sequence: candidate.issuer_sequence,
                greatest_profile_version: candidate.profile_version,
                greatest_policy_digest: Some(candidate.policy_digest.clone()),
                current_profile_version: None,
                current_policy_digest: None,
                current_activation: None,
                pending_activation: None,
            });
        if let Some(existing) = &current.pending_activation {
            if existing != &pending {
                return PolicyStateSnafu {
                    path: &self.path,
                    reason: "pending activation differs from the verified publication",
                }
                .fail();
            }
            return Ok(pending_snapshot(&candidate.state_key, existing));
        }
        if strictly_advances(current, candidate) {
            current.greatest_sequence_epoch = candidate.sequence_epoch;
            current.greatest_issuer_sequence = candidate.issuer_sequence;
            current.greatest_profile_version = candidate.profile_version;
            current.greatest_policy_digest = Some(candidate.policy_digest.clone());
        } else if !is_current(current, candidate) && !is_exact_greatest(current, candidate) {
            let authorization_id = candidate.rollback_authorization_id.as_deref();
            if authorization_id.is_none()
                || self
                    .state
                    .consumed_rollback_authorization_ids
                    .contains(authorization_id.unwrap_or_default())
            {
                return PolicyStateSnafu {
                    path: &self.path,
                    reason: "verified candidate no longer satisfies anti-rollback state",
                }
                .fail();
            }
        }
        let result = pending_snapshot(&candidate.state_key, &pending);
        current.pending_activation = Some(pending);
        self.persist()?;
        Ok(result)
    }

    #[must_use]
    pub fn pending_activations(&self) -> Vec<PendingProfileActivationV1> {
        self.state
            .high_water
            .iter()
            .filter_map(|(state_key, profile)| {
                profile
                    .pending_activation
                    .as_ref()
                    .map(|pending| pending_snapshot(state_key, pending))
            })
            .collect()
    }

    pub fn finalize_pending(&mut self, pending: &PendingProfileActivationV1) -> Result<()> {
        let profile = self
            .state
            .high_water
            .get_mut(&pending.state_key)
            .ok_or_else(|| {
                PolicyStateSnafu {
                    path: &self.path,
                    reason: "pending activation lost its anti-rollback profile",
                }
                .build()
            })?;
        let expected = PendingActivationV1::from(pending);
        if profile.pending_activation.as_ref() != Some(&expected) {
            if profile.current_profile_version == Some(pending.profile_version)
                && profile.current_policy_digest.as_deref() == Some(&pending.policy_digest)
                && profile.current_activation.as_ref() == Some(&pending.activation)
            {
                return Ok(());
            }
            return PolicyStateSnafu {
                path: &self.path,
                reason: "pending activation changed before finalization",
            }
            .fail();
        }
        if let Some(authorization_id) = pending.rollback_authorization_id.as_ref() {
            self.state
                .consumed_rollback_authorization_ids
                .insert(authorization_id.clone());
        }
        profile.current_profile_version = Some(pending.profile_version);
        profile.current_policy_digest = Some(pending.policy_digest.clone());
        profile.current_activation = Some(pending.activation.clone());
        profile.pending_activation = None;
        self.persist()
    }

    pub fn clear_old_epoch_pending(&mut self, pending: &PendingProfileActivationV1) -> Result<()> {
        let profile = self
            .state
            .high_water
            .get_mut(&pending.state_key)
            .ok_or_else(|| {
                PolicyStateSnafu {
                    path: &self.path,
                    reason: "pending activation lost its anti-rollback profile",
                }
                .build()
            })?;
        if profile.pending_activation.as_ref() != Some(&PendingActivationV1::from(pending)) {
            return PolicyStateSnafu {
                path: &self.path,
                reason: "pending activation changed before old-epoch recovery",
            }
            .fail();
        }
        profile.pending_activation = None;
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
            && current.current_policy_digest.as_deref() == Some(&payload.current_digest)
            && current.current_profile_version == Some(payload.current_version)
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

impl From<&PendingProfileActivationV1> for PendingActivationV1 {
    fn from(pending: &PendingProfileActivationV1) -> Self {
        Self {
            profile_id: pending.profile_id.clone(),
            profile_version: pending.profile_version,
            policy_digest: pending.policy_digest.clone(),
            sequence_epoch: pending.sequence_epoch,
            issuer_sequence: pending.issuer_sequence,
            activation: pending.activation.clone(),
            previous_profile_generation_ref_id: pending.previous_profile_generation_ref_id,
            rollback_authorization_id: pending.rollback_authorization_id.clone(),
        }
    }
}

fn pending_snapshot(state_key: &str, pending: &PendingActivationV1) -> PendingProfileActivationV1 {
    PendingProfileActivationV1 {
        state_key: state_key.to_owned(),
        profile_id: pending.profile_id.clone(),
        profile_version: pending.profile_version,
        policy_digest: pending.policy_digest.clone(),
        sequence_epoch: pending.sequence_epoch,
        issuer_sequence: pending.issuer_sequence,
        activation: pending.activation.clone(),
        previous_profile_generation_ref_id: pending.previous_profile_generation_ref_id,
        rollback_authorization_id: pending.rollback_authorization_id.clone(),
    }
}

trait CandidateIdentity {
    fn profile_version(&self) -> u64;
    fn policy_digest(&self) -> &str;
    fn sequence_epoch(&self) -> u64;
    fn issuer_sequence(&self) -> u64;
}

impl CandidateIdentity for ProfileSignatureHeaderV1 {
    fn profile_version(&self) -> u64 {
        self.profile_version
    }

    fn policy_digest(&self) -> &str {
        &self.policy_document_digest
    }

    fn sequence_epoch(&self) -> u64 {
        self.sequence_epoch
    }

    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

impl CandidateIdentity for ValidatedProfileCandidateV1 {
    fn profile_version(&self) -> u64 {
        self.profile_version
    }

    fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    fn sequence_epoch(&self) -> u64 {
        self.sequence_epoch
    }

    fn issuer_sequence(&self) -> u64 {
        self.issuer_sequence
    }
}

fn is_current(current: &AcceptedProfileV1, candidate: &impl CandidateIdentity) -> bool {
    current.current_profile_version == Some(candidate.profile_version())
        && current.current_policy_digest.as_deref() == Some(candidate.policy_digest())
}

fn strictly_advances(current: &AcceptedProfileV1, candidate: &impl CandidateIdentity) -> bool {
    // Target and terminal artifacts can advance within one Kubernetes source version.
    (candidate.sequence_epoch(), candidate.issuer_sequence())
        > (
            current.greatest_sequence_epoch,
            current.greatest_issuer_sequence,
        )
        && candidate.profile_version() >= current.greatest_profile_version
}

fn is_exact_greatest(current: &AcceptedProfileV1, candidate: &impl CandidateIdentity) -> bool {
    candidate.sequence_epoch() == current.greatest_sequence_epoch
        && candidate.issuer_sequence() == current.greatest_issuer_sequence
        && candidate.profile_version() == current.greatest_profile_version
        && current.greatest_policy_digest.as_deref() == Some(candidate.policy_digest())
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
