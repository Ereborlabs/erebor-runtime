use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use snafu::ResultExt as _;

use super::{
    EffectSimulationV1, HardSafetyConditionV1, PolicyCompiler, PolicyDocumentV1, PolicySimulator,
    ProfileCandidateArtifactV1, RollbackAuthorizationArtifactV1, StaticDecisionKeyV1,
};
use crate::error::{IoSnafu, JsonSnafu, PolicySignatureSnafu};
use crate::Result;

#[derive(Default)]
pub struct PolicyArtifactOwner {
    compiler: PolicyCompiler,
}

impl PolicyArtifactOwner {
    pub fn compile_and_sign(
        &self,
        source_path: &Path,
        seal_request_path: &Path,
        signing_key_path: &Path,
        output_path: &Path,
    ) -> Result<ProfileCandidateArtifactV1> {
        let source = fs::read(source_path).context(IoSnafu { path: source_path })?;
        let document = PolicyDocumentV1::parse(source_path, &source)?;
        let compiled = self.compiler.compile(&document)?;
        let request = read_json(seal_request_path)?;
        let key = signing_key(signing_key_path)?;
        let artifact = ProfileCandidateArtifactV1::sign(&document, compiled, request, &key)?;
        write_json_atomic(output_path, &artifact)?;
        Ok(artifact)
    }

    pub fn load_verified(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
    ) -> Result<ProfileCandidateArtifactV1> {
        let artifact: ProfileCandidateArtifactV1 = read_json(artifact_path)?;
        artifact.verify(&verifying_key(public_key_path)?)?;
        Ok(artifact)
    }

    pub fn load_verified_at(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
        now_utc_ns: i64,
    ) -> Result<ProfileCandidateArtifactV1> {
        let artifact: ProfileCandidateArtifactV1 = read_json(artifact_path)?;
        artifact.verify_at(&verifying_key(public_key_path)?, now_utc_ns)?;
        Ok(artifact)
    }

    pub fn load_verified_rollback(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
    ) -> Result<(RollbackAuthorizationArtifactV1, VerifyingKey)> {
        let artifact: RollbackAuthorizationArtifactV1 = read_json(artifact_path)?;
        let key = verifying_key(public_key_path)?;
        artifact.verify(&key)?;
        Ok((artifact, key))
    }

    pub fn simulate(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
        key: StaticDecisionKeyV1,
        hard_safety_condition: Option<HardSafetyConditionV1>,
    ) -> Result<EffectSimulationV1> {
        let artifact = self.load_verified(artifact_path, public_key_path)?;
        Ok(PolicySimulator::new(&artifact.compiled_profile).simulate(key, hard_safety_condition))
    }

    pub fn simulate_file(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
        decision_key_path: &Path,
        hard_safety_condition: Option<HardSafetyConditionV1>,
    ) -> Result<EffectSimulationV1> {
        let key = read_json(decision_key_path)?;
        self.simulate(artifact_path, public_key_path, key, hard_safety_condition)
    }

    pub fn simulate_json(
        &self,
        artifact_path: &Path,
        public_key_path: &Path,
        decision_key_path: &Path,
        hard_safety_condition: Option<HardSafetyConditionV1>,
    ) -> Result<String> {
        let simulation = self.simulate_file(
            artifact_path,
            public_key_path,
            decision_key_path,
            hard_safety_condition,
        )?;
        serde_json::to_string_pretty(&simulation).context(JsonSnafu {
            path: decision_key_path,
        })
    }
}

fn signing_key(path: &Path) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&read_key::<32>(path)?))
}

fn verifying_key(path: &Path) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&read_key::<32>(path)?).map_err(|error| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: error.to_string(),
        }
        .build()
    })
}

fn read_key<const N: usize>(path: &Path) -> Result<[u8; N]> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    let text = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|error| {
            PolicySignatureSnafu {
                key_id: path.display().to_string(),
                reason: error.to_string(),
            }
            .build()
        })?;
    let decoded = hex::decode(text).map_err(|error| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: error.to_string(),
        }
        .build()
    })?;
    decoded.try_into().map_err(|_: Vec<u8>| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: format!("expected a {}-byte lowercase hex key", N),
        }
        .build()
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    serde_json::from_slice(&bytes).context(JsonSnafu { path })
}

fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
    let temporary = temporary_path(path);
    let bytes = serde_json::to_vec_pretty(value).context(JsonSnafu { path })?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(&bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    OpenOptions::new()
        .read(true)
        .open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::PolicyArtifactOwner;
    use crate::{RollbackAuthorizationArtifactV1, RollbackAuthorizationPayloadV1};

    #[test]
    fn rollback_loader_uses_the_existing_signed_artifact_verifier(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("rollback.json");
        let public_key_path = directory.path().join("rollback-key.hex");
        let key = SigningKey::from_bytes(&[9; 32]);
        let artifact = RollbackAuthorizationArtifactV1::sign(
            "test-key".to_owned(),
            RollbackAuthorizationPayloadV1 {
                authorization_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                trust_domain_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                issuer_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                approver_principal_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                sequence_epoch: 1,
                issuer_sequence: 2,
                profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                current_digest: "a".repeat(64),
                current_version: 2,
                exact_older_target_digest: "b".repeat(64),
                exact_older_target_version: 1,
                closed_reason_code: 1,
                human_reason_artifact_digest: None,
                exact_platform_scope_digest: "c".repeat(64),
                issued_at_utc_ns: 10,
                expires_at_utc_ns: 20,
            },
            &key,
        )?;
        std::fs::write(&artifact_path, serde_json::to_vec(&artifact)?)?;
        std::fs::write(
            &public_key_path,
            hex::encode(key.verifying_key().as_bytes()),
        )?;

        let (loaded, _) = PolicyArtifactOwner::default()
            .load_verified_rollback(&artifact_path, &public_key_path)?;
        assert_eq!(loaded, artifact);

        let mut corrupt = artifact;
        corrupt.signed_authorization.signature[0] ^= 1;
        std::fs::write(&artifact_path, serde_json::to_vec(&corrupt)?)?;
        assert!(PolicyArtifactOwner::default()
            .load_verified_rollback(&artifact_path, &public_key_path)
            .is_err());
        Ok(())
    }
}
