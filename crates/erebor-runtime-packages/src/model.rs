use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

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
    adapter_digest: ContentDigest,
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
        Self::with_adapter_and_config(
            name,
            adapter_id,
            minimum_daemon_version,
            entrypoint,
            config_digest.clone(),
            config_digest,
            support_layer_digests,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_adapter_and_config(
        name: impl Into<String>,
        adapter_id: impl Into<String>,
        minimum_daemon_version: impl Into<String>,
        entrypoint: Vec<String>,
        adapter_digest: ContentDigest,
        config_digest: ContentDigest,
        support_layer_digests: Vec<ContentDigest>,
    ) -> Result<Self> {
        let manifest = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            name: name.into(),
            adapter_id: adapter_id.into(),
            minimum_daemon_version: minimum_daemon_version.into(),
            entrypoint,
            adapter_digest,
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
        self.adapter_digest.validate()?;
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
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn config_digest(&self) -> &ContentDigest {
        &self.config_digest
    }

    #[must_use]
    pub fn adapter_digest(&self) -> &ContentDigest {
        &self.adapter_digest
    }

    #[must_use]
    pub fn minimum_daemon_version(&self) -> &str {
        &self.minimum_daemon_version
    }

    #[must_use]
    pub fn entrypoint(&self) -> &[String] {
        &self.entrypoint
    }

    #[must_use]
    pub fn support_layer_digests(&self) -> &[ContentDigest] {
        &self.support_layer_digests
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

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn policy_config_digest(&self) -> &ContentDigest {
        &self.policy_config_digest
    }

    #[must_use]
    pub fn rule_layer_digests(&self) -> &[ContentDigest] {
        &self.rule_layer_digests
    }

    #[must_use]
    pub fn example_layer_digests(&self) -> &[ContentDigest] {
        &self.example_layer_digests
    }

    #[must_use]
    pub fn test_layer_digests(&self) -> &[ContentDigest] {
        &self.test_layer_digests
    }

    #[must_use]
    pub fn documentation_layer_digest(&self) -> &ContentDigest {
        &self.documentation_layer_digest
    }
}

impl CanonicalEncoding for PolicyPackageManifest {}

/// The complete immutable contents of one locally admitted policy package.
///
/// The package is stored as canonical data rather than a mutable user tree.
/// Its source layout is intentionally fixed to `policy.toml`, flat `rules/`,
/// `examples/`, `tests/`, and `README.md`; policy evaluation consumes only the
/// admitted rule bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPackageRevision {
    format_version: u32,
    manifest: PolicyPackageManifest,
    policy_config: Vec<u8>,
    rules: BTreeMap<String, Vec<u8>>,
    examples: BTreeMap<String, Vec<u8>>,
    tests: BTreeMap<String, Vec<u8>>,
    documentation: Vec<u8>,
}

impl PolicyPackageRevision {
    pub fn new(
        name: impl Into<String>,
        policy_config: Vec<u8>,
        rules: BTreeMap<String, Vec<u8>>,
        examples: BTreeMap<String, Vec<u8>>,
        tests: BTreeMap<String, Vec<u8>>,
        documentation: Vec<u8>,
    ) -> Result<Self> {
        let manifest = PolicyPackageManifest::new(
            name,
            ContentDigest::from_canonical_bytes(&policy_config),
            Self::layer_digests(&rules),
            Self::layer_digests(&examples),
            Self::layer_digests(&tests),
            ContentDigest::from_canonical_bytes(&documentation),
        )?;
        let revision = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            manifest,
            policy_config,
            rules,
            examples,
            tests,
            documentation,
        };
        revision.validate()?;
        Ok(revision)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && !self.policy_config.is_empty()
                && !self.documentation.is_empty()
                && Self::valid_files(&self.rules, true)
                && Self::valid_files(&self.examples, false)
                && Self::valid_files(&self.tests, true),
            InvalidModelSnafu {
                reason: String::from("policy package revision has invalid immutable contents")
            }
        );
        self.manifest.validate()?;
        let expected = PolicyPackageManifest::new(
            self.manifest.name(),
            ContentDigest::from_canonical_bytes(&self.policy_config),
            Self::layer_digests(&self.rules),
            Self::layer_digests(&self.examples),
            Self::layer_digests(&self.tests),
            ContentDigest::from_canonical_bytes(&self.documentation),
        )?;
        ensure!(
            self.manifest == expected,
            InvalidModelSnafu {
                reason: String::from("policy package manifest does not match immutable contents")
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn manifest(&self) -> &PolicyPackageManifest {
        &self.manifest
    }

    #[must_use]
    pub fn policy_config(&self) -> &[u8] {
        &self.policy_config
    }

    #[must_use]
    pub const fn rules(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.rules
    }

    #[must_use]
    pub const fn examples(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.examples
    }

    #[must_use]
    pub const fn tests(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.tests
    }

    #[must_use]
    pub fn documentation(&self) -> &[u8] {
        &self.documentation
    }

    fn layer_digests(files: &BTreeMap<String, Vec<u8>>) -> Vec<ContentDigest> {
        files
            .values()
            .map(|contents| ContentDigest::from_canonical_bytes(contents))
            .collect()
    }

    fn valid_files(files: &BTreeMap<String, Vec<u8>>, required: bool) -> bool {
        (!required || !files.is_empty())
            && files.iter().all(|(name, contents)| {
                !contents.is_empty()
                    && !name.is_empty()
                    && name.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_uppercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'-' | b'_')
                    })
            })
    }
}

impl CanonicalEncoding for PolicyPackageRevision {}

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

    #[must_use]
    pub fn policy_input_digests(&self) -> Vec<&ContentDigest> {
        let mut digests = Vec::with_capacity(
            1 + self.package_minimum_digests.len()
                + usize::from(self.local_override_digest.is_some()),
        );
        digests.push(&self.root_minimum_digest);
        digests.extend(&self.package_minimum_digests);
        if let Some(digest) = &self.local_override_digest {
            digests.push(digest);
        }
        digests
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
    #[serde(default)]
    local_artifact: Option<VerifiedLocalArtifact>,
}

impl InstallationRecord {
    #[must_use]
    pub fn new(owner_uid: u32, package_digest: ContentDigest, installed_at_unix_ms: u64) -> Self {
        Self {
            format_version: CANONICAL_FORMAT_VERSION,
            owner_uid,
            package_digest,
            installed_at_unix_ms,
            local_artifact: None,
        }
    }

    pub fn enrolled_local(
        owner_uid: u32,
        package_digest: ContentDigest,
        installed_at_unix_ms: u64,
        local_artifact: VerifiedLocalArtifact,
    ) -> Result<Self> {
        let record = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            owner_uid,
            package_digest,
            installed_at_unix_ms,
            local_artifact: Some(local_artifact),
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub fn package_digest(&self) -> &ContentDigest {
        &self.package_digest
    }

    #[must_use]
    pub const fn local_artifact(&self) -> Option<&VerifiedLocalArtifact> {
        self.local_artifact.as_ref()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION,
            InvalidModelSnafu {
                reason: String::from("installation record has an unsupported format version")
            }
        );
        self.package_digest.validate()?;
        if let Some(artifact) = &self.local_artifact {
            artifact.validate()?;
            ensure!(
                artifact.owner_uid == self.owner_uid,
                InvalidModelSnafu {
                    reason: String::from(
                        "a local installation artifact must remain owned by its installation UID"
                    )
                }
            );
        }
        Ok(())
    }
}

impl CanonicalEncoding for InstallationRecord {}

/// A vendor or user-supplied executable enrolled through the daemon's
/// UID-dropped descriptor broker. The path is never reopened as a separate
/// unchecked pathname: this record preserves the identity facts that must be
/// re-proved from a held descriptor before admission and start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedLocalArtifact {
    path: PathBuf,
    device: u64,
    inode: u64,
    mount_id: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    sha256: ContentDigest,
    provider: LocalArtifactProvider,
}

impl VerifiedLocalArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        device: u64,
        inode: u64,
        mount_id: u64,
        owner_uid: u32,
        owner_gid: u32,
        mode: u32,
        sha256: ContentDigest,
        provider: LocalArtifactProvider,
    ) -> Result<Self> {
        let artifact = Self {
            path,
            device,
            inode,
            mount_id,
            owner_uid,
            owner_gid,
            mode,
            sha256,
            provider,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            normalized_absolute_path(&self.path)
                && self.device != 0
                && self.inode != 0
                && self.mount_id != 0
                && self.mode & 0o111 != 0,
            InvalidModelSnafu {
                reason: String::from(
                    "a verified local artifact requires a normalized absolute executable path and complete stat identity"
                )
            }
        );
        self.sha256.validate()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }

    #[must_use]
    pub const fn provider(&self) -> LocalArtifactProvider {
        self.provider
    }
}

/// The local product supports only an explicit descriptor-backed enrollment. OCI
/// import, remote download, and provider discovery remain Phase 10 work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalArtifactProvider {
    CallerDescriptor,
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

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

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && AgentPackageManifest::is_identifier(&self.name),
            InvalidModelSnafu {
                reason: String::from(
                    "alias must have a supported format version and unambiguous identifier"
                )
            }
        );
        self.digest.validate()
    }
}

impl CanonicalEncoding for DigestAlias {}
