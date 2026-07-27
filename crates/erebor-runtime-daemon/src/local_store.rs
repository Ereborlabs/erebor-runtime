use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::{AgentAdapterDescriptor, ImmutableIdentity, SessionSpec};
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, CodexPackageDefinition, ContentDigest,
    InstallationRecord, PolicyPackageRevision, PolicySetRevision, VerifiedLocalArtifact,
};
use erebor_runtime_policy::LocalPolicy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    config::{RootCuratedAdmission, RootCuratedCodexPackage},
    error::{InvalidRequestSnafu, IoSnafu},
    DaemonPaths, Result,
};

/// Root-owned content reference indexes. A session lease keeps every immutable
/// identity named by a durable session reachable until that session is removed.
pub(crate) struct DaemonLocalStore {
    packages: PathBuf,
    users: PathBuf,
    write_lock: Mutex<()>,
}

/// Immutable package, installation, adapter, and policy-set facts resolved for
/// one session admission. The daemon derives these facts from its own store;
/// client-supplied digests merely select an already admitted record.
pub(crate) struct LocalAdmission {
    package: AgentPackageManifest,
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
    policy_input_digests: Vec<String>,
}

/// The exact root-curated Codex release selected before an explicit local
/// installation is enrolled. It is stored separately from the vendor binary
/// so no raw path can become a trusted package definition.
pub(crate) struct LocalCodexPackage {
    package: AgentPackageManifest,
    package_digest: String,
    definition: CodexPackageDefinition,
}

impl LocalCodexPackage {
    pub(crate) const fn package(&self) -> &AgentPackageManifest {
        &self.package
    }

    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) const fn definition(&self) -> &CodexPackageDefinition {
        &self.definition
    }
}

/// One caller-owned, descriptor-verified Codex installation resolved from the
/// daemon store. Its embedded artifact facts must be re-proved from a held
/// descriptor before the daemon admits or starts a workload.
pub(crate) struct LocalCodexInstallation {
    package: LocalCodexPackage,
    installation: InstallationRecord,
    installation_digest: String,
    entrypoint: String,
}

impl LocalCodexInstallation {
    pub(crate) const fn package(&self) -> &LocalCodexPackage {
        &self.package
    }

    pub(crate) const fn installation(&self) -> &InstallationRecord {
        &self.installation
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
}

pub(crate) struct BuiltInAdmission {
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
}

pub(crate) struct StoredPolicyPackage {
    name: String,
}

impl StoredPolicyPackage {
    fn new(revision: &PolicyPackageRevision) -> Self {
        Self {
            name: revision.manifest().name().to_owned(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) struct StoredPolicySet {
    name: String,
}

impl StoredPolicySet {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedResourceRecord {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: NamedResourceMetadata,
    spec: NamedResourceSpec,
    integrity_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedResourceMetadata {
    name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedResourceSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
}

impl NamedResourceRecord {
    const API_VERSION: &'static str = "erebor.dev/v1";

    fn new(kind: &str, name: &str, integrity_digest: &ContentDigest) -> Self {
        Self {
            api_version: Self::API_VERSION.to_owned(),
            kind: kind.to_owned(),
            metadata: NamedResourceMetadata {
                name: name.to_owned(),
            },
            spec: NamedResourceSpec::default(),
            integrity_digest: integrity_digest.as_str().to_owned(),
        }
    }

    fn agent(name: &str, integrity_digest: &ContentDigest, adapter: &str) -> Result<Self> {
        if adapter.is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("Agent spec.adapter must be explicit"),
            }
            .fail();
        }
        Ok(Self {
            spec: NamedResourceSpec {
                adapter: Some(adapter.to_owned()),
            },
            ..Self::new("Agent", name, integrity_digest)
        })
    }

    fn validate(&self, expected_kind: &str, requested_name: &str) -> Result<ContentDigest> {
        if self.api_version != Self::API_VERSION
            || self.kind != expected_kind
            || self.metadata.name != requested_name
            || !DaemonLocalStore::is_path_component(&self.metadata.name)
        {
            return InvalidRequestSnafu {
                reason: format!(
                    "named resource does not match required apiVersion, kind, and metadata.name for {expected_kind}"
                ),
            }
            .fail();
        }
        if expected_kind == "Agent"
            && !matches!(self.spec.adapter.as_deref(), Some(adapter) if !adapter.is_empty())
        {
            return InvalidRequestSnafu {
                reason: String::from("Agent resource is missing explicit spec.adapter"),
            }
            .fail();
        }
        DaemonLocalStore::parse_digest(&self.integrity_digest, expected_kind)
    }
}

impl BuiltInAdmission {
    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn adapter_digest(&self) -> &str {
        &self.adapter_digest
    }

    pub(crate) fn policy_set_digest(&self) -> &str {
        &self.policy_set_digest
    }
}

impl LocalAdmission {
    pub(crate) const fn package(&self) -> &AgentPackageManifest {
        &self.package
    }

    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) fn installation_digest(&self) -> &str {
        &self.installation_digest
    }

    pub(crate) fn adapter_digest(&self) -> &str {
        &self.adapter_digest
    }

    pub(crate) fn policy_set_digest(&self) -> &str {
        &self.policy_set_digest
    }

    pub(crate) fn policy_input_digests(&self) -> &[String] {
        &self.policy_input_digests
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionLease {
    session_id: String,
    owner_uid: u32,
    package_digest: Option<String>,
    installation_digest: Option<String>,
    adapter_digest: Option<String>,
    policy_set_digest: String,
    policy_input_digests: Vec<String>,
}

impl DaemonLocalStore {
    pub(crate) fn installed(paths: &DaemonPaths) -> Result<Self> {
        let packages = paths.packages_state_path();
        let users = paths.users_state_path();
        Self::require_safe_directory(&packages)?;
        Self::require_safe_directory(&users)?;
        Ok(Self {
            packages,
            users,
            write_lock: Mutex::new(()),
        })
    }

    pub(crate) fn seed_root_curated(&self, admissions: &[RootCuratedAdmission]) -> Result<()> {
        for admission in admissions {
            for policy in admission.policies() {
                self.validate_policy_package(policy)?;
                let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
                self.write_immutable(
                    &self.policy_package_path(&policy_digest),
                    &policy.canonical_bytes().map_err(Self::invalid_model)?,
                )?;
            }
            let package = admission.package();
            let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.package_manifest_path(&package_digest),
                &package.canonical_bytes().map_err(Self::invalid_model)?,
            )?;

            let installation = admission.installation();
            let installation_digest = installation
                .canonical_digest()
                .map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.installation_path(installation.owner_uid(), &installation_digest),
                &installation
                    .canonical_bytes()
                    .map_err(Self::invalid_model)?,
            )?;

            let policy_set = admission.policy_set();
            let policy_set_digest = policy_set.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.policy_set_path(installation.owner_uid(), &policy_set_digest),
                &policy_set.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn seed_root_curated_codex_packages(
        &self,
        packages: &[RootCuratedCodexPackage],
    ) -> Result<()> {
        for curated in packages {
            let package = curated.package();
            let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
            self.write_immutable(
                &self.package_manifest_path(&package_digest),
                &package.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
            let definition = curated.definition();
            let definition_digest = definition.canonical_digest().map_err(Self::invalid_model)?;
            if package.config_digest() != &definition_digest {
                return InvalidRequestSnafu {
                    reason: String::from(
                        "root-curated Codex package does not bind its exact definition digest",
                    ),
                }
                .fail();
            }
            self.write_immutable(
                &self.codex_definition_path(&package_digest),
                &definition.canonical_bytes().map_err(Self::invalid_model)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn seed_builtin_generic_content(&self) -> Result<()> {
        let (package, policy) = Self::builtin_generic_content()?;
        let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.package_manifest_path(&package_digest),
            &package.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        self.validate_policy_package(&policy)?;
        let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.policy_package_path(&policy_digest),
            &policy.canonical_bytes().map_err(Self::invalid_model)?,
        )
    }

    pub(crate) fn ensure_builtin_admission(&self, owner_uid: u32) -> Result<BuiltInAdmission> {
        self.seed_builtin_generic_content()?;
        let (package, policy) = Self::builtin_generic_content()?;
        let package_digest = package.canonical_digest().map_err(Self::invalid_model)?;
        let installation = InstallationRecord::new(owner_uid, package_digest.clone(), 0);
        let installation_digest = installation
            .canonical_digest()
            .map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.installation_path(owner_uid, &installation_digest),
            &installation
                .canonical_bytes()
                .map_err(Self::invalid_model)?,
        )?;
        let policy_digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        let policy_set =
            PolicySetRevision::new(policy_digest, Vec::new(), None).map_err(Self::invalid_model)?;
        let policy_set_digest = policy_set.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.policy_set_path(owner_uid, &policy_set_digest),
            &policy_set.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        Ok(BuiltInAdmission {
            package_digest: package_digest.as_str().to_owned(),
            installation_digest: installation_digest.as_str().to_owned(),
            adapter_digest: package.adapter_digest().as_str().to_owned(),
            policy_set_digest: policy_set_digest.as_str().to_owned(),
        })
    }

    fn builtin_generic_content() -> Result<(AgentPackageManifest, PolicyPackageRevision)> {
        let descriptor = AgentAdapterDescriptor::generic_process_v1().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("built-in generic adapter descriptor is invalid: {error}"),
            }
            .build()
        })?;
        let package = AgentPackageManifest::new(
            "generic-process",
            descriptor.id(),
            env!("CARGO_PKG_VERSION"),
            vec![String::from("<argv>")],
            ContentDigest::new(descriptor.sha256().map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("built-in generic adapter digest is invalid: {error}"),
                }
                .build()
            })?)
            .map_err(Self::invalid_model)?,
            Vec::new(),
        )
        .map_err(Self::invalid_model)?;
        let policy = PolicyPackageRevision::new(
            "generic-host-minimum",
            b"name = \"generic-host-minimum\"\n".to_vec(),
            std::collections::BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"generic-host-allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Built-in generic host minimum\n".to_vec(),
        )
        .map_err(Self::invalid_model)?;
        Ok((package, policy))
    }

    pub(crate) fn resolve_admission(
        &self,
        owner_uid: u32,
        package_digest: &str,
        installation_digest: &str,
        adapter_digest: &str,
        policy_set_digest: &str,
    ) -> Result<LocalAdmission> {
        let package_digest = Self::parse_digest(package_digest, "package")?;
        let installation_digest = Self::parse_digest(installation_digest, "installation")?;
        let adapter_digest = Self::parse_digest(adapter_digest, "adapter")?;
        let policy_set_digest = Self::parse_digest(policy_set_digest, "policy set")?;

        let package: AgentPackageManifest = self.read_canonical(
            &self.package_manifest_path(&package_digest),
            &package_digest,
            "agent package",
        )?;
        if package.adapter_digest() != &adapter_digest {
            return InvalidRequestSnafu {
                reason: String::from(
                    "package adapter identity does not match the requested adapter",
                ),
            }
            .fail();
        }
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "installation",
        )?;
        installation.validate().map_err(Self::invalid_model)?;
        if installation.owner_uid() != owner_uid || installation.package_digest() != &package_digest
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "installation does not belong to the caller or selected package",
                ),
            }
            .fail();
        }

        let policy_set: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &policy_set_digest),
            &policy_set_digest,
            "policy set",
        )?;
        policy_set.validate().map_err(Self::invalid_model)?;
        for policy_digest in policy_set.policy_input_digests() {
            self.read_policy_package(owner_uid, policy_digest)?;
        }
        let policy_input_digests = policy_set
            .policy_input_digests()
            .into_iter()
            .map(|digest| digest.as_str().to_owned())
            .collect();

        Ok(LocalAdmission {
            package,
            package_digest: package_digest.as_str().to_owned(),
            installation_digest: installation_digest.as_str().to_owned(),
            adapter_digest: adapter_digest.as_str().to_owned(),
            policy_set_digest: policy_set_digest.as_str().to_owned(),
            policy_input_digests,
        })
    }

    pub(crate) fn resolve_codex_package(&self, package_digest: &str) -> Result<LocalCodexPackage> {
        let package_digest = Self::parse_digest(package_digest, "Codex package")?;
        let package: AgentPackageManifest = self.read_canonical(
            &self.package_manifest_path(&package_digest),
            &package_digest,
            "Codex agent package",
        )?;
        if package.adapter_id() != "codex-v1" {
            return InvalidRequestSnafu {
                reason: String::from("selected package is not a root-curated codex-v1 package"),
            }
            .fail();
        }
        let definition: CodexPackageDefinition = self.read_canonical(
            &self.codex_definition_path(&package_digest),
            package.config_digest(),
            "Codex package definition",
        )?;
        definition.validate().map_err(Self::invalid_model)?;
        Ok(LocalCodexPackage {
            package,
            package_digest: package_digest.as_str().to_owned(),
            definition,
        })
    }

    pub(crate) fn resolve_codex_package_name(&self, name: &str) -> Result<LocalCodexPackage> {
        Self::require_resource_name(name, "AgentPackage")?;
        let mut matches = Vec::new();
        for entry in
            self.directory_entries(&self.packages, "listing root-curated Codex packages")?
        {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root-curated Codex package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|value| ContentDigest::new(value).ok())
            else {
                continue;
            };
            if !path.join("codex-v1.json").exists() {
                continue;
            }
            let package = self.resolve_codex_package(digest.as_str())?;
            if package.package().name() == name {
                matches.push(package);
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => InvalidRequestSnafu {
                reason: format!("no root-curated Codex package is named `{name}`"),
            }
            .fail(),
            _ => InvalidRequestSnafu {
                reason: format!("root-curated Codex package name `{name}` is ambiguous"),
            }
            .fail(),
        }
    }

    pub(crate) fn store_codex_installation(
        &self,
        owner_uid: u32,
        agent_name: &str,
        package_digest: &str,
        installed_at_unix_ms: u64,
        artifact: VerifiedLocalArtifact,
    ) -> Result<LocalCodexInstallation> {
        Self::require_resource_name(agent_name, "Agent")?;
        let package = self.resolve_codex_package(package_digest)?;
        if artifact.sha256() != package.definition().executable_sha256() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "the held Codex executable digest does not match the root-curated release",
                ),
            }
            .fail();
        }
        let package_digest =
            ContentDigest::new(package.package_digest()).map_err(Self::invalid_model)?;
        let installation = InstallationRecord::enrolled_local(
            owner_uid,
            package_digest,
            installed_at_unix_ms,
            artifact,
        )
        .map_err(Self::invalid_model)?;
        let installation_digest = installation
            .canonical_digest()
            .map_err(Self::invalid_model)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(
            &self.installation_path(owner_uid, &installation_digest),
            &installation
                .canonical_bytes()
                .map_err(Self::invalid_model)?,
        )?;
        let record = NamedResourceRecord::agent(
            agent_name,
            &installation_digest,
            package.package().adapter_id(),
        )?;
        let encoded =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.agent_path(owner_uid, agent_name),
                source,
                location: snafu::Location::default(),
            })?;
        self.write_immutable(&self.agent_path(owner_uid, agent_name), &encoded)?;
        self.resolve_codex_installation(
            owner_uid,
            package.package_digest(),
            installation_digest.as_str(),
            Some("codex"),
        )
    }

    pub(crate) fn resolve_codex_agent(
        &self,
        owner_uid: u32,
        name: &str,
        entrypoint: &str,
    ) -> Result<LocalCodexInstallation> {
        let installation_digest =
            self.read_named_resource(owner_uid, "Agent", name, self.agent_path(owner_uid, name))?;
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "Codex installation",
        )?;
        self.resolve_codex_installation(
            owner_uid,
            installation.package_digest().as_str(),
            installation_digest.as_str(),
            Some(entrypoint),
        )
    }

    pub(crate) fn resolve_codex_installation(
        &self,
        owner_uid: u32,
        package_digest: &str,
        installation_digest: &str,
        entrypoint: Option<&str>,
    ) -> Result<LocalCodexInstallation> {
        let package = self.resolve_codex_package(package_digest)?;
        let installation_digest = Self::parse_digest(installation_digest, "Codex installation")?;
        let installation: InstallationRecord = self.read_canonical(
            &self.installation_path(owner_uid, &installation_digest),
            &installation_digest,
            "Codex installation",
        )?;
        installation.validate().map_err(Self::invalid_model)?;
        if installation.owner_uid() != owner_uid
            || installation.package_digest().as_str() != package.package_digest()
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Codex installation does not belong to the caller or its selected package",
                ),
            }
            .fail();
        }
        if installation.local_artifact().is_none() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "Codex installation has no descriptor-verified local executable artifact",
                ),
            }
            .fail();
        }
        let entrypoint = entrypoint.unwrap_or("codex");
        if package.definition().entrypoint(entrypoint).is_none() {
            return InvalidRequestSnafu {
                reason: format!(
                    "Codex package does not certify the `{entrypoint}` entrypoint for this installation"
                ),
            }
            .fail();
        }
        Ok(LocalCodexInstallation {
            package,
            installation,
            installation_digest: installation_digest.as_str().to_owned(),
            entrypoint: entrypoint.to_owned(),
        })
    }

    pub(crate) fn validate_session_spec(&self, spec: &SessionSpec) -> Result<LocalAdmission> {
        let package = spec.package().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted agent package identity"),
            }
            .build()
        })?;
        let installation = spec.installation().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted installation identity"),
            }
            .build()
        })?;
        let adapter = spec.adapter().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted adapter identity"),
            }
            .build()
        })?;
        let configuration = spec.package_configuration().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("session has no admitted package configuration identity"),
            }
            .build()
        })?;
        let admission = self.resolve_admission(
            spec.owner().uid(),
            package.sha256(),
            installation.sha256(),
            adapter.sha256(),
            spec.policy_set().sha256(),
        )?;
        if configuration.sha256() != admission.package().config_digest().as_str() {
            return InvalidRequestSnafu {
                reason: String::from(
                    "session package configuration identity no longer matches its package manifest",
                ),
            }
            .fail();
        }
        Ok(admission)
    }

    pub(crate) fn policy_packages_for_session(
        &self,
        spec: &SessionSpec,
    ) -> Result<Vec<PolicyPackageRevision>> {
        let admission = self.validate_session_spec(spec)?;
        admission
            .policy_input_digests()
            .iter()
            .map(|digest| {
                let digest = Self::parse_digest(digest, "policy package")?;
                self.read_policy_package(spec.owner().uid(), &digest)
            })
            .collect()
    }

    pub(crate) fn store_user_policy_package(
        &self,
        owner_uid: u32,
        policy: &PolicyPackageRevision,
        maximum_stored_bytes: u64,
    ) -> Result<ContentDigest> {
        self.validate_policy_package(policy)?;
        let digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        for existing in self.list_policy_packages(owner_uid)? {
            if existing.name() == policy.manifest().name() {
                let existing_digest =
                    self.resolve_policy_package_name(owner_uid, existing.name())?;
                if existing_digest != digest {
                    return InvalidRequestSnafu {
                        reason: format!(
                            "PolicyPackage name `{}` already identifies a different immutable revision",
                            policy.manifest().name()
                        ),
                    }
                    .fail();
                }
            }
        }
        let encoded = policy.canonical_bytes().map_err(Self::invalid_model)?;
        let path = self.user_policy_package_path(owner_uid, &digest);
        if !path.exists()
            && self
                .user_policy_package_bytes(owner_uid)?
                .saturating_add(encoded.len() as u64)
                > maximum_stored_bytes
        {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "owner UID {owner_uid} would exceed the {maximum_stored_bytes}-byte stored policy limit",
                ),
            }
            .fail();
        }
        self.write_immutable(&path, &encoded)?;
        Ok(digest)
    }

    pub(crate) fn list_policy_packages(&self, owner_uid: u32) -> Result<Vec<StoredPolicyPackage>> {
        let mut packages = BTreeMap::new();
        self.collect_root_policy_packages(&mut packages)?;
        self.collect_user_policy_packages(owner_uid, &mut packages)?;
        Ok(packages.into_values().collect())
    }

    pub(crate) fn inspect_policy_package(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<StoredPolicyPackage> {
        let digest = self.resolve_policy_package_name(owner_uid, name)?;
        let policy = self.read_policy_package(owner_uid, &digest)?;
        self.validate_policy_package(&policy)?;
        Ok(StoredPolicyPackage::new(&policy))
    }

    pub(crate) fn create_user_policy_set(
        &self,
        owner_uid: u32,
        name: &str,
        package_names: &[String],
    ) -> Result<StoredPolicySet> {
        Self::require_resource_name(name, "PolicySet")?;
        let mut root_minimum = None;
        let mut package_minimums = Vec::new();
        for package_name in package_names {
            let digest = self.resolve_policy_package_name(owner_uid, package_name)?;
            if self.policy_package_path(&digest).exists() {
                if root_minimum.replace(digest).is_some() {
                    return InvalidRequestSnafu {
                        reason: String::from(
                            "a PolicySet composition may include only one root-curated PolicyPackage",
                        ),
                    }
                    .fail();
                }
            } else {
                package_minimums.push(digest);
            }
        }
        let root_minimum = root_minimum.ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from(
                    "a PolicySet composition must include the root-curated PolicyPackage by name",
                ),
            }
            .build()
        })?;
        let revision = PolicySetRevision::new(root_minimum, package_minimums, None)
            .map_err(Self::invalid_model)?;
        let digest = revision.canonical_digest().map_err(Self::invalid_model)?;
        let name_record = NamedResourceRecord::new("PolicySet", name, &digest);
        let encoded = serde_json::to_vec(&name_record).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: self.policy_set_name_path(owner_uid, name),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(
            &self.policy_set_path(owner_uid, &digest),
            &revision.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        self.write_immutable(&self.policy_set_name_path(owner_uid, name), &encoded)?;
        Ok(StoredPolicySet::new(name))
    }

    pub(crate) fn resolve_policy_set_name(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<ContentDigest> {
        let digest = self.read_named_resource(
            owner_uid,
            "PolicySet",
            name,
            self.policy_set_name_path(owner_uid, name),
        )?;
        let policy_set: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &digest),
            &digest,
            "policy set",
        )?;
        policy_set.validate().map_err(Self::invalid_model)?;
        Ok(digest)
    }

    pub(crate) fn list_policy_sets(&self, owner_uid: u32) -> Result<Vec<StoredPolicySet>> {
        self.list_named_resources(
            owner_uid,
            "PolicySet",
            self.policy_set_names_directory(owner_uid),
        )
        .map(|names| names.into_iter().map(StoredPolicySet::new).collect())
    }

    pub(crate) fn inspect_policy_set(&self, owner_uid: u32, name: &str) -> Result<StoredPolicySet> {
        let digest = self.resolve_policy_set_name(owner_uid, name)?;
        let revision: PolicySetRevision = self.read_canonical(
            &self.policy_set_path(owner_uid, &digest),
            &digest,
            "policy set",
        )?;
        revision.validate().map_err(Self::invalid_model)?;
        for policy_digest in revision.policy_input_digests() {
            self.read_policy_package(owner_uid, policy_digest)?;
        }
        Ok(StoredPolicySet::new(name))
    }

    pub(crate) fn record_session_lease(&self, spec: &SessionSpec) -> Result<()> {
        self.record_lease(SessionLease::from_spec(spec))
    }

    /// A removed session retains its immutable dependencies until its bounded
    /// output/evidence retention is pruned. Only that final retention step can
    /// release the corresponding content lease.
    pub(crate) fn release_session_lease(&self, owner_uid: u32, session_id: &str) -> Result<()> {
        if !Self::is_path_component(session_id) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session lease id is not a safe path component"),
            }
            .fail();
        }
        let path = self.lease_path(session_id);
        let encoded = match fs::read(&path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(crate::DaemonError::Io {
                    action: "reading session content lease before release",
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        let lease: SessionLease = serde_json::from_slice(&encoded).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: path.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        if lease.session_id != session_id || lease.owner_uid != owner_uid {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session content lease does not match the pruning owner"),
            }
            .fail();
        }
        let parent = path.parent().ok_or_else(|| {
            crate::error::UnsafePathSnafu {
                path: path.clone(),
                reason: String::from("session content lease has no parent directory"),
            }
            .build()
        })?;
        Self::require_safe_directory(parent)?;
        fs::remove_file(&path).context(IoSnafu {
            action: "releasing pruned session content lease",
            path: &path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening session content lease directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing released session content lease directory",
                path: parent,
            })
    }

    fn record_lease(&self, lease: SessionLease) -> Result<()> {
        if !Self::is_path_component(&lease.session_id) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session lease id is not a safe path component"),
            }
            .fail();
        }
        let encoded =
            serde_json::to_vec(&lease).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.lease_path(&lease.session_id),
                source,
                location: snafu::Location::default(),
            })?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        self.write_immutable(&self.lease_path(&lease.session_id), &encoded)
    }

    fn lease_path(&self, session_id: &str) -> PathBuf {
        self.packages
            .join("leases")
            .join("sessions")
            .join(format!("{session_id}.json"))
    }

    fn package_manifest_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages.join(digest.as_str()).join("manifest.json")
    }

    fn codex_definition_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages.join(digest.as_str()).join("codex-v1.json")
    }

    fn agent_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("agents")
            .join(format!("{name}.json"))
    }

    fn installation_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("installations")
            .join(format!("{}.json", digest.as_str()))
    }

    fn policy_set_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-sets")
            .join(format!("{}.json", digest.as_str()))
    }

    fn policy_set_names_directory(&self, owner_uid: u32) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-set-names")
    }

    fn policy_set_name_path(&self, owner_uid: u32, name: &str) -> PathBuf {
        self.policy_set_names_directory(owner_uid)
            .join(format!("{name}.json"))
    }

    fn policy_package_path(&self, digest: &ContentDigest) -> PathBuf {
        self.packages
            .join(digest.as_str())
            .join("policy-package.json")
    }

    fn user_policy_package_path(&self, owner_uid: u32, digest: &ContentDigest) -> PathBuf {
        self.users
            .join(owner_uid.to_string())
            .join("policy-packages")
            .join(format!("{}.json", digest.as_str()))
    }

    fn read_policy_package(
        &self,
        owner_uid: u32,
        digest: &ContentDigest,
    ) -> Result<PolicyPackageRevision> {
        let user_path = self.user_policy_package_path(owner_uid, digest);
        if user_path.exists() {
            return self.read_canonical(&user_path, digest, "user policy package");
        }
        self.read_canonical(
            &self.policy_package_path(digest),
            digest,
            "root policy package",
        )
    }

    fn collect_root_policy_packages(
        &self,
        packages: &mut BTreeMap<String, StoredPolicyPackage>,
    ) -> Result<()> {
        let entries = self.directory_entries(&self.packages, "listing root policy packages")?;
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            Self::require_safe_directory(&path)?;
            let digest = match entry.file_name().to_str() {
                Some(value) => match ContentDigest::new(value) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                None => continue,
            };
            let policy_path = path.join("policy-package.json");
            if !policy_path.exists() {
                continue;
            }
            let revision: PolicyPackageRevision =
                self.read_canonical(&policy_path, &digest, "root policy package")?;
            self.validate_policy_package(&revision)?;
            packages.insert(
                digest.as_str().to_owned(),
                StoredPolicyPackage::new(&revision),
            );
        }
        Ok(())
    }

    fn collect_user_policy_packages(
        &self,
        owner_uid: u32,
        packages: &mut BTreeMap<String, StoredPolicyPackage>,
    ) -> Result<()> {
        let directory = self
            .users
            .join(owner_uid.to_string())
            .join("policy-packages");
        for (digest, revision) in self
            .canonical_records_in_flat_directory::<PolicyPackageRevision>(
                &directory,
                "policy package",
            )?
        {
            self.validate_policy_package(&revision)?;
            packages.insert(
                digest.as_str().to_owned(),
                StoredPolicyPackage::new(&revision),
            );
        }
        Ok(())
    }

    fn user_policy_package_bytes(&self, owner_uid: u32) -> Result<u64> {
        let directory = self
            .users
            .join(owner_uid.to_string())
            .join("policy-packages");
        let mut total = 0_u64;
        for (digest, _policy) in self.canonical_records_in_flat_directory::<PolicyPackageRevision>(
            &directory,
            "policy package",
        )? {
            let path = self.user_policy_package_path(owner_uid, &digest);
            let metadata = fs::metadata(&path).context(IoSnafu {
                action: "measuring immutable user policy package",
                path: &path,
            })?;
            total = total.saturating_add(metadata.len());
        }
        Ok(total)
    }

    fn canonical_records_in_flat_directory<T>(
        &self,
        directory: &Path,
        record_kind: &str,
    ) -> Result<Vec<(ContentDigest, T)>>
    where
        T: CanonicalEncoding + DeserializeOwned,
    {
        let entries =
            self.directory_entries(directory, "listing immutable daemon store records")?;
        let mut records = Vec::new();
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting immutable daemon store record entry",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            let digest = match ContentDigest::new(name) {
                Ok(value) => value,
                Err(_) => continue,
            };
            records.push((
                digest.clone(),
                self.read_canonical(&path, &digest, record_kind)?,
            ));
        }
        records.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
        Ok(records)
    }

    fn resolve_policy_package_name(&self, owner_uid: u32, name: &str) -> Result<ContentDigest> {
        Self::require_resource_name(name, "PolicyPackage")?;
        let matches = self
            .list_policy_packages(owner_uid)?
            .into_iter()
            .filter(|package| package.name() == name)
            .count();
        if matches == 0 {
            return InvalidRequestSnafu {
                reason: format!("no PolicyPackage is named `{name}`"),
            }
            .fail();
        }
        if matches > 1 {
            return InvalidRequestSnafu {
                reason: format!("PolicyPackage name `{name}` is ambiguous"),
            }
            .fail();
        }
        let mut candidates = Vec::new();
        for (digest, package) in self.canonical_records_in_flat_directory::<PolicyPackageRevision>(
            &self
                .users
                .join(owner_uid.to_string())
                .join("policy-packages"),
            "policy package",
        )? {
            if package.manifest().name() == name {
                candidates.push(digest);
            }
        }
        for entry in
            self.directory_entries(&self.packages, "listing root policy packages by name")?
        {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting root policy package directory",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|value| ContentDigest::new(value).ok())
            else {
                continue;
            };
            let policy_path = path.join("policy-package.json");
            if !policy_path.exists() {
                continue;
            }
            let package: PolicyPackageRevision =
                self.read_canonical(&policy_path, &digest, "root policy package")?;
            if package.manifest().name() == name {
                candidates.push(digest);
            }
        }
        candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        candidates.dedup();
        match candidates.as_slice() {
            [digest] => Ok(digest.clone()),
            _ => InvalidRequestSnafu {
                reason: format!("PolicyPackage name `{name}` is ambiguous"),
            }
            .fail(),
        }
    }

    fn read_named_resource(
        &self,
        owner_uid: u32,
        kind: &str,
        name: &str,
        path: PathBuf,
    ) -> Result<ContentDigest> {
        Self::require_resource_name(name, kind)?;
        let record: NamedResourceRecord = self.read_json_record(&path, "named resource")?;
        let digest = record.validate(kind, name)?;
        let _owner_uid = owner_uid;
        Ok(digest)
    }

    fn list_named_resources(
        &self,
        owner_uid: u32,
        kind: &str,
        directory: PathBuf,
    ) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in self.directory_entries(&directory, "listing named resources")? {
            let path = entry.path();
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting named resource entry",
                path: &path,
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|value| value.strip_suffix(".json"))
            else {
                continue;
            };
            let _digest = self.read_named_resource(owner_uid, kind, name, path)?;
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn directory_entries(
        &self,
        directory: &Path,
        action: &'static str,
    ) -> Result<Vec<fs::DirEntry>> {
        match fs::read_dir(directory) {
            Ok(entries) => {
                Self::require_safe_directory(directory)?;
                entries
                    .map(|entry| {
                        entry.context(IoSnafu {
                            action,
                            path: directory,
                        })
                    })
                    .collect()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(crate::DaemonError::Io {
                action,
                path: directory.to_path_buf(),
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    fn read_canonical<T>(
        &self,
        path: &Path,
        expected_digest: &ContentDigest,
        record_kind: &str,
    ) -> Result<T>
    where
        T: CanonicalEncoding + DeserializeOwned,
    {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting immutable daemon store record",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable file",
                ),
            }
            .fail();
        }
        let bytes = fs::read(path).context(IoSnafu {
            action: "reading immutable daemon store record",
            path,
        })?;
        let record = serde_json::from_slice::<T>(&bytes).map_err(|source| {
            crate::DaemonError::InvalidConfig {
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        let canonical = record.canonical_bytes().map_err(Self::invalid_model)?;
        if canonical != bytes || ContentDigest::from_canonical_bytes(&canonical) != *expected_digest
        {
            return InvalidRequestSnafu {
                reason: format!("stored {record_kind} does not match its canonical digest"),
            }
            .fail();
        }
        Ok(record)
    }

    fn read_json_record<T>(&self, path: &Path, _record_kind: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting named daemon store record",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable file",
                ),
            }
            .fail();
        }
        let bytes = fs::read(path).context(IoSnafu {
            action: "reading named daemon store record",
            path,
        })?;
        serde_json::from_slice::<T>(&bytes).map_err(|source| crate::DaemonError::InvalidConfig {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })
    }

    fn write_immutable(&self, path: &Path, encoded: &[u8]) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| crate::DaemonError::UnsafePath {
                path: path.to_path_buf(),
                reason: String::from("immutable store record has no parent directory"),
                location: snafu::Location::default(),
            })?;
        fs::create_dir_all(parent).context(IoSnafu {
            action: "creating immutable store directory",
            path: parent,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).context(IoSnafu {
            action: "securing immutable store directory",
            path: parent,
        })?;
        Self::require_safe_directory(parent)?;
        match fs::read(path) {
            Ok(existing) if existing == encoded => return Ok(()),
            Ok(_) => {
                return crate::error::InvalidRequestSnafu {
                    reason: format!(
                        "immutable daemon store record `{}` conflicts with an earlier value",
                        path.display()
                    ),
                }
                .fail()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::DaemonError::Io {
                    action: "reading immutable store record",
                    path: path.to_path_buf(),
                    source,
                    location: snafu::Location::default(),
                })
            }
        }
        let temporary = path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(IoSnafu {
                action: "writing immutable store temporary record",
                path: &temporary,
            })?;
        file.write_all(encoded).context(IoSnafu {
            action: "writing immutable store temporary record",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing immutable store temporary record",
            path: &temporary,
        })?;
        fs::rename(&temporary, path).context(IoSnafu {
            action: "publishing immutable store record",
            path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening immutable store directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing immutable store directory",
                path: parent,
            })
    }

    fn require_safe_directory(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting immutable store directory",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return crate::error::UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from(
                    "must be an effective-owner-controlled non-symlink non-writable directory",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn is_path_component(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }

    fn require_resource_name(name: &str, kind: &str) -> Result<()> {
        if Self::is_path_component(name) {
            return Ok(());
        }
        InvalidRequestSnafu {
            reason: format!("{kind} metadata.name is not a safe immutable resource name"),
        }
        .fail()
    }

    fn parse_digest(value: &str, kind: &str) -> Result<ContentDigest> {
        ContentDigest::new(value).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("{kind} digest is invalid: {error}"),
            }
            .build()
        })
    }

    fn invalid_model(error: erebor_runtime_packages::PackageError) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: error.to_string(),
        }
        .build()
    }

    fn validate_policy_package(&self, policy: &PolicyPackageRevision) -> Result<()> {
        std::str::from_utf8(policy.policy_config()).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!(
                    "policy package `{}` has non-UTF-8 policy.toml: {error}",
                    policy.manifest().name()
                ),
            }
            .build()
        })?;
        for (name, source) in policy.rules() {
            let source = std::str::from_utf8(source).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "policy package `{}` rule `{name}` is not UTF-8: {error}",
                        policy.manifest().name()
                    ),
                }
                .build()
            })?;
            LocalPolicy::from_json_str(source).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "policy package `{}` rule `{name}` is invalid: {error}",
                        policy.manifest().name()
                    ),
                }
                .build()
            })?;
        }
        Ok(())
    }
}

impl SessionLease {
    fn from_spec(spec: &SessionSpec) -> Self {
        Self {
            session_id: spec.session_id().as_str().to_owned(),
            owner_uid: spec.owner().uid(),
            package_digest: spec
                .package()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            installation_digest: spec
                .installation()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            adapter_digest: spec
                .adapter()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned),
            policy_set_digest: spec.policy_set().sha256().to_owned(),
            policy_input_digests: spec
                .policy_inputs()
                .iter()
                .map(ImmutableIdentity::sha256)
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erebor_runtime_packages::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
        PolicyPackageRevision, PolicySetRevision,
    };

    use super::{DaemonLocalStore, NamedResourceRecord, SessionLease};
    use crate::{config::RootCuratedAdmission, DaemonPaths};

    const ADAPTER_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn session_leases_are_crash_safe_idempotent_and_immutable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let lease = SessionLease {
            session_id: String::from("session-1"),
            owner_uid: 1000,
            package_digest: Some(String::from("package")),
            installation_digest: Some(String::from("installation")),
            adapter_digest: Some(String::from("adapter")),
            policy_set_digest: String::from("policy-set"),
            policy_input_digests: vec![String::from("policy-a"), String::from("policy-b")],
        };
        store.record_lease(lease.clone())?;
        store.record_lease(lease)?;
        assert!(store
            .record_lease(SessionLease {
                session_id: String::from("session-1"),
                owner_uid: 1000,
                package_digest: Some(String::from("different-package")),
                installation_digest: Some(String::from("installation")),
                adapter_digest: Some(String::from("adapter")),
                policy_set_digest: String::from("policy-set"),
                policy_input_digests: vec![String::from("policy-a"), String::from("policy-b")],
            })
            .is_err());
        store.release_session_lease(1000, "session-1")?;
        assert!(!store.lease_path("session-1").exists());
        store.release_session_lease(1000, "session-1")?;
        Ok(())
    }

    #[test]
    fn named_resource_envelopes_are_versioned_and_never_retargeted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let first = ContentDigest::new(ADAPTER_DIGEST)?;
        let second =
            ContentDigest::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
        let path = store.agent_path(1000, "local-codex");
        let record = NamedResourceRecord::agent("local-codex", &first, "codex-v1")?;
        let encoded = serde_json::to_vec(&record)?;
        store.write_immutable(&path, &encoded)?;
        assert_eq!(
            store.read_named_resource(1000, "Agent", "local-codex", path.clone())?,
            first
        );
        let replacement = NamedResourceRecord::agent("local-codex", &second, "codex-v1")?;
        assert!(store
            .write_immutable(&path, &serde_json::to_vec(&replacement)?)
            .is_err());

        let mut unknown_version = record;
        unknown_version.api_version = String::from("erebor.dev/v2");
        assert!(unknown_version.validate("Agent", "local-codex").is_err());
        assert!(replacement.validate("PolicySet", "local-codex").is_err());
        Ok(())
    }

    #[test]
    fn root_curated_records_are_immutable_and_resolved_per_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;

        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let package_digest = package.canonical_digest()?;
        let installation = InstallationRecord::new(1000, package_digest.clone(), 1);
        let installation_digest = installation.canonical_digest()?;
        let policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let policy_digest = policy.canonical_digest()?;
        let policy_set = PolicySetRevision::new(policy_digest.clone(), Vec::new(), None)?;
        let policy_set_digest = policy_set.canonical_digest()?;
        store.seed_root_curated(&[RootCuratedAdmission::new(
            package,
            installation,
            policy_set,
            vec![policy],
        )])?;

        let admission = store.resolve_admission(
            1000,
            package_digest.as_str(),
            installation_digest.as_str(),
            ADAPTER_DIGEST,
            policy_set_digest.as_str(),
        )?;
        assert_eq!(admission.package_digest(), package_digest.as_str());
        assert_eq!(
            admission.installation_digest(),
            installation_digest.as_str()
        );
        assert_eq!(admission.adapter_digest(), ADAPTER_DIGEST);
        assert_eq!(admission.policy_set_digest(), policy_set_digest.as_str());
        assert_eq!(
            admission.policy_input_digests(),
            &[policy_digest.as_str().to_owned()]
        );
        assert!(store
            .resolve_admission(
                1001,
                package_digest.as_str(),
                installation_digest.as_str(),
                ADAPTER_DIGEST,
                policy_set_digest.as_str(),
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn policy_catalogs_are_daemon_owned_and_revalidate_canonical_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let _admission = store.ensure_builtin_admission(1000)?;

        let packages = store.list_policy_packages(1000)?;
        let package = packages
            .iter()
            .find(|package| package.name() == "generic-host-minimum")
            .ok_or("built-in host policy package was not listed")?;
        let inspected_package = store.inspect_policy_package(1000, package.name())?;
        assert_eq!(inspected_package.name(), "generic-host-minimum");

        let policy_set = store.create_user_policy_set(
            1000,
            "company-workspace",
            &[String::from("generic-host-minimum")],
        )?;
        let policy_sets = store.list_policy_sets(1000)?;
        assert!(policy_sets
            .iter()
            .any(|listed| listed.name() == policy_set.name()));
        assert_eq!(
            store.inspect_policy_set(1000, "company-workspace")?.name(),
            "company-workspace"
        );
        assert!(store.list_policy_sets(1001)?.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_root_policy_is_rejected_before_it_reaches_the_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let installation = InstallationRecord::new(1000, package.canonical_digest()?, 1);
        let policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(String::from("terminal.json"), b"not-json".to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let policy_set = PolicySetRevision::new(policy.canonical_digest()?, Vec::new(), None)?;
        assert!(store
            .seed_root_curated(&[RootCuratedAdmission::new(
                package,
                installation,
                policy_set,
                vec![policy],
            )])
            .is_err());
        Ok(())
    }

    #[test]
    fn user_policy_revisions_compose_only_with_a_root_curated_minimum(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let installation = InstallationRecord::new(1000, package.canonical_digest()?, 1);
        let root_policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"root-allow","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let root_digest = root_policy.canonical_digest()?;
        let root_set = PolicySetRevision::new(root_digest.clone(), Vec::new(), None)?;
        store.seed_root_curated(&[RootCuratedAdmission::new(
            package,
            installation,
            root_set,
            vec![root_policy],
        )])?;
        let user_policy = PolicyPackageRevision::new(
            "user-guardrail",
            b"name = \"user-guardrail\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"user-deny","match":{"surface":"terminal"},"decision":"deny"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# User guardrail\n".to_vec(),
        )?;
        let user_digest = store.store_user_policy_package(1000, &user_policy, u64::MAX)?;
        let policy_set = store.create_user_policy_set(
            1000,
            "workspace-policy",
            &[String::from("host-minimum"), String::from("user-guardrail")],
        )?;
        assert!(store
            .create_user_policy_set(1000, "invalid-policy", &[String::from("user-guardrail")])
            .is_err());
        let policy_set_digest = store.resolve_policy_set_name(1000, policy_set.name())?;
        let revision: PolicySetRevision = store.read_canonical(
            &store.policy_set_path(1000, &policy_set_digest),
            &policy_set_digest,
            "policy set",
        )?;
        assert_eq!(
            revision
                .policy_input_digests()
                .iter()
                .map(|digest| digest.as_str())
                .collect::<Vec<_>>(),
            vec![root_digest.as_str(), user_digest.as_str()]
        );
        Ok(())
    }

    #[test]
    fn policy_storage_quota_rejects_before_a_new_immutable_record_is_written(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        let policy = PolicyPackageRevision::new(
            "bounded-user-policy",
            b"name = \"bounded-user-policy\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Bounded user policy\n".to_vec(),
        )?;
        let bytes = policy.canonical_bytes()?.len() as u64;
        assert!(store
            .store_user_policy_package(1000, &policy, bytes.saturating_sub(1))
            .is_err());
        assert!(store.list_policy_packages(1000)?.is_empty());
        assert!(store
            .store_user_policy_package(1000, &policy, bytes)
            .is_ok());
        Ok(())
    }

    #[test]
    fn daemon_installed_builtin_generic_content_is_canonical_and_idempotent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        paths.prepare(crate::paths::DaemonSecurity::current_process())?;
        let store = DaemonLocalStore::installed(&paths)?;
        store.seed_builtin_generic_content()?;
        store.seed_builtin_generic_content()?;
        let descriptor = erebor_runtime_core::AgentAdapterDescriptor::generic_process_v1()?;
        let package = AgentPackageManifest::new(
            "generic-process",
            descriptor.id(),
            env!("CARGO_PKG_VERSION"),
            vec![String::from("<argv>")],
            ContentDigest::new(descriptor.sha256()?)?,
            Vec::new(),
        )?;
        let digest = package.canonical_digest()?;
        let stored: AgentPackageManifest = store.read_canonical(
            &store.package_manifest_path(&digest),
            &digest,
            "built-in package",
        )?;
        assert_eq!(stored, package);
        let first = store.ensure_builtin_admission(1000)?;
        let second = store.ensure_builtin_admission(1000)?;
        assert_eq!(first.package_digest(), digest.as_str());
        assert_eq!(first.package_digest(), second.package_digest());
        assert_eq!(first.installation_digest(), second.installation_digest());
        assert_eq!(first.adapter_digest(), second.adapter_digest());
        assert_eq!(first.policy_set_digest(), second.policy_set_digest());
        let resolved = store.resolve_admission(
            1000,
            first.package_digest(),
            first.installation_digest(),
            first.adapter_digest(),
            first.policy_set_digest(),
        )?;
        assert_eq!(resolved.package_digest(), first.package_digest());
        Ok(())
    }
}
