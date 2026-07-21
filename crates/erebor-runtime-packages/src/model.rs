use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ensure;

use crate::{error::InvalidModelSnafu, Result};

pub const CANONICAL_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let digest = Self(value.into());
        digest.validate()?;
        Ok(digest)
    }

    #[must_use]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.0.len() == 64
                && self
                    .0
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            InvalidModelSnafu {
                reason: String::from("digest must be 64 lower-case SHA-256 hexadecimal characters")
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub trait CanonicalEncoding: Serialize {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|source| crate::PackageError::CanonicalEncoding {
            source,
            location: snafu::Location::default(),
        })
    }

    fn canonical_digest(&self) -> Result<ContentDigest> {
        Ok(ContentDigest::from_canonical_bytes(
            &self.canonical_bytes()?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPackageManifest {
    format_version: u32,
    name: String,
    adapter_id: String,
    minimum_daemon_version: String,
    entrypoint: Vec<String>,
    config_digest: ContentDigest,
    support_layer_digests: Vec<ContentDigest>,
}

impl AgentPackageManifest {
    pub fn new(
        name: impl Into<String>,
        adapter_id: impl Into<String>,
        minimum_daemon_version: impl Into<String>,
        entrypoint: Vec<String>,
        config_digest: ContentDigest,
        support_layer_digests: Vec<ContentDigest>,
    ) -> Result<Self> {
        let manifest = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            name: name.into(),
            adapter_id: adapter_id.into(),
            minimum_daemon_version: minimum_daemon_version.into(),
            entrypoint,
            config_digest,
            support_layer_digests,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && Self::is_identifier(&self.name)
                && Self::is_identifier(&self.adapter_id)
                && !self.minimum_daemon_version.trim().is_empty()
                && !self.entrypoint.is_empty()
                && self.entrypoint.iter().all(|entry| !entry.trim().is_empty())
                && Self::unique_digests(&self.support_layer_digests),
            InvalidModelSnafu {
                reason: String::from(
                    "agent package manifest has unknown semantics or invalid identity"
                )
            }
        );
        self.config_digest.validate()?;
        for digest in &self.support_layer_digests {
            digest.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    #[must_use]
    pub fn entrypoint(&self) -> &[String] {
        &self.entrypoint
    }

    pub(crate) fn is_identifier(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
    }

    pub(crate) fn unique_digests(digests: &[ContentDigest]) -> bool {
        digests.iter().collect::<BTreeSet<_>>().len() == digests.len()
    }
}

impl CanonicalEncoding for AgentPackageManifest {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPackageManifest {
    format_version: u32,
    name: String,
    policy_config_digest: ContentDigest,
    rule_layer_digests: Vec<ContentDigest>,
    example_layer_digests: Vec<ContentDigest>,
    test_layer_digests: Vec<ContentDigest>,
    documentation_layer_digest: ContentDigest,
}

impl PolicyPackageManifest {
    pub fn new(
        name: impl Into<String>,
        policy_config_digest: ContentDigest,
        rule_layer_digests: Vec<ContentDigest>,
        example_layer_digests: Vec<ContentDigest>,
        test_layer_digests: Vec<ContentDigest>,
        documentation_layer_digest: ContentDigest,
    ) -> Result<Self> {
        let manifest = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            name: name.into(),
            policy_config_digest,
            rule_layer_digests,
            example_layer_digests,
            test_layer_digests,
            documentation_layer_digest,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && AgentPackageManifest::is_identifier(&self.name)
                && !self.rule_layer_digests.is_empty()
                && !self.test_layer_digests.is_empty(),
            InvalidModelSnafu {
                reason: String::from("policy package must contain named rules and tests")
            }
        );
        self.policy_config_digest.validate()?;
        self.documentation_layer_digest.validate()?;
        for digest in self
            .rule_layer_digests
            .iter()
            .chain(&self.example_layer_digests)
            .chain(&self.test_layer_digests)
        {
            digest.validate()?;
        }
        Ok(())
    }
}

impl CanonicalEncoding for PolicyPackageManifest {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetRevision {
    format_version: u32,
    root_minimum_digest: ContentDigest,
    package_minimum_digests: Vec<ContentDigest>,
    local_override_digest: Option<ContentDigest>,
}

impl PolicySetRevision {
    pub fn new(
        root_minimum_digest: ContentDigest,
        package_minimum_digests: Vec<ContentDigest>,
        local_override_digest: Option<ContentDigest>,
    ) -> Result<Self> {
        let revision = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            root_minimum_digest,
            package_minimum_digests,
            local_override_digest,
        };
        revision.validate()?;
        Ok(revision)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && AgentPackageManifest::unique_digests(&self.package_minimum_digests),
            InvalidModelSnafu {
                reason: String::from("policy-set revision is not canonical")
            }
        );
        self.root_minimum_digest.validate()?;
        for digest in &self.package_minimum_digests {
            digest.validate()?;
        }
        if let Some(digest) = &self.local_override_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

impl CanonicalEncoding for PolicySetRevision {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRecord {
    format_version: u32,
    owner_uid: u32,
    package_digest: ContentDigest,
    installed_at_unix_ms: u64,
}

impl InstallationRecord {
    #[must_use]
    pub fn new(owner_uid: u32, package_digest: ContentDigest, installed_at_unix_ms: u64) -> Self {
        Self {
            format_version: CANONICAL_FORMAT_VERSION,
            owner_uid,
            package_digest,
            installed_at_unix_ms,
        }
    }

    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub fn package_digest(&self) -> &ContentDigest {
        &self.package_digest
    }
}

impl CanonicalEncoding for InstallationRecord {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    format_version: u32,
    subject_digest: ContentDigest,
    subject_reference: String,
    trust_policy_digest: ContentDigest,
    trust_policy_scope: String,
    verifier_version: String,
    verifier_digest: ContentDigest,
    verified_at_unix_ms: u64,
    revocation_snapshot_digest: Option<ContentDigest>,
}

/// Verified backend facts captured atomically in a durable receipt.
pub struct VerificationReceiptInput {
    pub subject_digest: ContentDigest,
    pub subject_reference: String,
    pub trust_policy_digest: ContentDigest,
    pub trust_policy_scope: String,
    pub verifier_version: String,
    pub verifier_digest: ContentDigest,
    pub verified_at_unix_ms: u64,
    pub revocation_snapshot_digest: Option<ContentDigest>,
}

impl VerificationReceipt {
    pub fn new(input: VerificationReceiptInput) -> Result<Self> {
        let receipt = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            subject_digest: input.subject_digest,
            subject_reference: input.subject_reference,
            trust_policy_digest: input.trust_policy_digest,
            trust_policy_scope: input.trust_policy_scope,
            verifier_version: input.verifier_version,
            verifier_digest: input.verifier_digest,
            verified_at_unix_ms: input.verified_at_unix_ms,
            revocation_snapshot_digest: input.revocation_snapshot_digest,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validates_current_trust(&self, trust_policy_digest: &ContentDigest) -> bool {
        &self.trust_policy_digest == trust_policy_digest
    }

    #[must_use]
    pub fn subject_digest(&self) -> &ContentDigest {
        &self.subject_digest
    }

    #[must_use]
    pub fn subject_reference(&self) -> &str {
        &self.subject_reference
    }

    #[must_use]
    pub fn trust_policy_scope(&self) -> &str {
        &self.trust_policy_scope
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && !self.subject_reference.trim().is_empty()
                && !self.trust_policy_scope.trim().is_empty()
                && !self.verifier_version.trim().is_empty(),
            InvalidModelSnafu {
                reason: String::from(
                    "verification receipt is not versioned or lacks a verifier version"
                )
            }
        );
        self.subject_digest.validate()?;
        self.trust_policy_digest.validate()?;
        self.verifier_digest.validate()?;
        if let Some(digest) = &self.revocation_snapshot_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

impl CanonicalEncoding for VerificationReceipt {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestAlias {
    format_version: u32,
    name: String,
    digest: ContentDigest,
}

impl DigestAlias {
    pub fn new(name: impl Into<String>, digest: ContentDigest) -> Result<Self> {
        let alias = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            name: name.into(),
            digest,
        };
        ensure!(
            AgentPackageManifest::is_identifier(&alias.name),
            InvalidModelSnafu {
                reason: String::from("alias must be an unambiguous identifier")
            }
        );
        Ok(alias)
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl CanonicalEncoding for DigestAlias {}
