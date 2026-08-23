use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{ControlProtocolSnafu, IdentityStateSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledTrustGenerationV1 {
    pub generation: u64,
    pub bundle_digest: String,
    pub control_connection_nonce: String,
    #[serde(default)]
    pub policy_issuer_sequence_epoch: u64,
    #[serde(default)]
    pub policy_signers: BTreeMap<String, InstalledPolicySignerV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPolicySignerV1 {
    pub ed25519_public_key_hex: String,
    pub revoked: bool,
}

pub struct TrustCache {
    path: PathBuf,
    installed: InstalledTrustGenerationV1,
}

impl TrustCache {
    pub fn load(state_directory: &Path) -> Result<Self> {
        let path = state_directory.join("control-trust.json");
        let installed = match fs::read(&path) {
            Ok(bytes) => {
                let installed: InstalledTrustGenerationV1 =
                    serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
                // Corrupt or partial trust state blocks reconnect and policy verification.
                ensure!(
                    installed.is_valid(),
                    IdentityStateSnafu {
                        reason: "persisted Control trust cache is invalid",
                    }
                );
                installed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                InstalledTrustGenerationV1::default()
            }
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        Ok(Self { path, installed })
    }

    #[must_use]
    pub const fn installed(&self) -> &InstalledTrustGenerationV1 {
        &self.installed
    }

    pub fn install(
        &mut self,
        generation: u64,
        bundle_digest: String,
        control_connection_nonce: &[u8],
    ) -> Result<()> {
        self.install_with_policy(generation, bundle_digest, 0, &[], control_connection_nonce)
    }

    pub fn install_with_policy(
        &mut self,
        generation: u64,
        bundle_digest: String,
        policy_issuer_sequence_epoch: u64,
        policy_signers: &[mithril_control::PolicySignerTrust],
        control_connection_nonce: &[u8],
    ) -> Result<()> {
        let policy_signers = policy_signers
            .iter()
            .map(|signer| {
                (
                    signer.signing_key_id.clone(),
                    InstalledPolicySignerV1 {
                        ed25519_public_key_hex: hex_encode(&signer.ed25519_public_key),
                        revoked: signer.revoked,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        // Verify the complete signer set digest before it becomes a candidate trust root.
        ensure!(
            generation > 0
                && is_sha256_hex(&bundle_digest)
                && control_connection_nonce.len() == 16
                && (policy_signers.is_empty()
                    || (policy_issuer_sequence_epoch > 0
                        && trust_bundle_digest(
                            generation,
                            policy_issuer_sequence_epoch,
                            &policy_signers,
                        ) == bundle_digest)),
            ControlProtocolSnafu {
                reason: "Control delivered an invalid trust generation",
            }
        );
        ensure!(
            generation >= self.installed.generation,
            ControlProtocolSnafu {
                reason: "Control attempted a trust-generation rollback",
            }
        );
        // A generation can repeat only with byte-identical immutable trust content.
        ensure!(
            generation != self.installed.generation
                || self.installed.bundle_digest.is_empty()
                || (bundle_digest == self.installed.bundle_digest
                    && policy_issuer_sequence_epoch == self.installed.policy_issuer_sequence_epoch
                    && policy_signers == self.installed.policy_signers),
            ControlProtocolSnafu {
                reason: "Control changed an already installed trust generation",
            }
        );
        let control_connection_nonce = hex_encode(control_connection_nonce);
        let installed = InstalledTrustGenerationV1 {
            generation,
            bundle_digest,
            control_connection_nonce,
            policy_issuer_sequence_epoch,
            policy_signers,
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        let bytes =
            serde_json::to_vec_pretty(&installed).context(JsonSnafu { path: &self.path })?;
        let temporary = self.path.with_extension("json.next");
        let mut file = File::create(&temporary).context(IoSnafu { path: &temporary })?;
        file.write_all(&bytes)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        // Persist trust before the node acknowledges this generation to Control.
        fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .context(IoSnafu { path: parent })?
                .sync_all()
                .context(IoSnafu { path: parent })?;
        }
        self.installed = installed;
        Ok(())
    }

    pub fn policy_signing_key(
        &self,
        signing_key_id: &str,
        issuer_sequence_epoch: u64,
    ) -> Result<ed25519_dalek::VerifyingKey> {
        let signer = self
            .installed
            .policy_signers
            .get(signing_key_id)
            .ok_or_else(|| {
                ControlProtocolSnafu {
                    reason: "the policy signer is absent from installed trust".to_owned(),
                }
                .build()
            })?;
        // Issuer epoch and revocation are checked at every candidate verification.
        ensure!(
            !signer.revoked && self.installed.policy_issuer_sequence_epoch == issuer_sequence_epoch,
            ControlProtocolSnafu {
                reason: "the policy signer is revoked or outside the installed issuer epoch",
            }
        );
        let bytes = hex::decode(&signer.ed25519_public_key_hex).map_err(|error| {
            ControlProtocolSnafu {
                reason: format!("the installed policy key is invalid hex: {error}"),
            }
            .build()
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            ControlProtocolSnafu {
                reason: "the installed policy key is not Ed25519".to_owned(),
            }
            .build()
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|error| {
            ControlProtocolSnafu {
                reason: format!("the installed policy key is not valid Ed25519: {error}"),
            }
            .build()
        })
    }
}

impl InstalledTrustGenerationV1 {
    fn is_valid(&self) -> bool {
        self.generation > 0
            && is_sha256_hex(&self.bundle_digest)
            && self.control_connection_nonce.len() == 32
            && self
                .control_connection_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && (self.policy_signers.is_empty()
                || (self.policy_issuer_sequence_epoch > 0
                    && self.policy_signers.iter().all(|(key_id, signer)| {
                        !key_id.is_empty()
                            && key_id.len() <= 128
                            && is_sha256_hex(&signer.ed25519_public_key_hex)
                    })
                    && trust_bundle_digest(
                        self.generation,
                        self.policy_issuer_sequence_epoch,
                        &self.policy_signers,
                    ) == self.bundle_digest))
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn trust_bundle_digest(
    generation: u64,
    issuer_epoch: u64,
    signers: &BTreeMap<String, InstalledPolicySignerV1>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-CONTROL-TRUST-BUNDLE-V1\0");
    digest.update(generation.to_be_bytes());
    digest.update(issuer_epoch.to_be_bytes());
    for (key_id, signer) in signers {
        digest.update(
            u64::try_from(key_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(key_id.as_bytes());
        digest.update(signer.ed25519_public_key_hex.as_bytes());
        digest.update([u8::from(signer.revoked)]);
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use ed25519_dalek::SigningKey;
    use mithril_control::PolicySignerTrust;
    use snafu::ResultExt as _;

    use super::{trust_bundle_digest, InstalledPolicySignerV1, TrustCache};
    use crate::error::IoSnafu;

    #[test]
    fn cache_rejects_rollback_and_same_generation_replacement() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary trust directory",
        })?;
        let mut cache = TrustCache::load(directory.path())?;
        cache.install(2, "a".repeat(64), &[1; 16])?;
        assert!(cache.install(1, "a".repeat(64), &[2; 16]).is_err());
        assert!(cache.install(2, "b".repeat(64), &[2; 16]).is_err());
        assert_eq!(
            TrustCache::load(directory.path())?.installed().generation,
            2
        );
        Ok(())
    }

    #[test]
    fn cache_rejects_structurally_invalid_persisted_state() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary trust directory",
        })?;
        fs::write(
            directory.path().join("control-trust.json"),
            br#"{
                "generation": 0,
                "bundle_digest": "",
                "control_connection_nonce": ""
            }"#,
        )
        .context(IoSnafu {
            path: "invalid trust cache",
        })?;
        assert!(TrustCache::load(directory.path()).is_err());
        Ok(())
    }

    #[test]
    fn policy_signer_rotation_and_revocation_are_durable_and_monotonic() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary policy trust directory",
        })?;
        let old_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let new_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let first = vec![PolicySignerTrust {
            signing_key_id: "policy-old".to_owned(),
            ed25519_public_key: old_key.to_bytes().to_vec(),
            revoked: false,
        }];
        let first_digest = policy_digest(4, 11, &first);
        let mut cache = TrustCache::load(directory.path())?;
        cache.install_with_policy(4, first_digest, 11, &first, &[1; 16])?;
        assert_eq!(cache.policy_signing_key("policy-old", 11)?, old_key);

        let rotated = vec![
            PolicySignerTrust {
                signing_key_id: "policy-new".to_owned(),
                ed25519_public_key: new_key.to_bytes().to_vec(),
                revoked: false,
            },
            PolicySignerTrust {
                signing_key_id: "policy-old".to_owned(),
                ed25519_public_key: old_key.to_bytes().to_vec(),
                revoked: true,
            },
        ];
        let rotated_digest = policy_digest(5, 11, &rotated);
        cache.install_with_policy(5, rotated_digest, 11, &rotated, &[2; 16])?;
        assert!(cache.policy_signing_key("policy-old", 11).is_err());
        assert_eq!(cache.policy_signing_key("policy-new", 11)?, new_key);
        assert!(cache
            .install_with_policy(4, policy_digest(4, 11, &first), 11, &first, &[3; 16],)
            .is_err());

        let reloaded = TrustCache::load(directory.path())?;
        assert!(reloaded.policy_signing_key("policy-old", 11).is_err());
        assert_eq!(reloaded.policy_signing_key("policy-new", 11)?, new_key);
        assert!(reloaded.policy_signing_key("policy-new", 12).is_err());
        Ok(())
    }

    fn policy_digest(generation: u64, epoch: u64, signers: &[PolicySignerTrust]) -> String {
        let signers = signers
            .iter()
            .map(|signer| {
                (
                    signer.signing_key_id.clone(),
                    InstalledPolicySignerV1 {
                        ed25519_public_key_hex: hex::encode(&signer.ed25519_public_key),
                        revoked: signer.revoked,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        trust_bundle_digest(generation, epoch, &signers)
    }
}
