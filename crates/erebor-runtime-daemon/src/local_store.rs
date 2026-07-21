use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::{AgentAdapterDescriptor, ImmutableIdentity, SessionSpec};
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
    PolicyPackageRevision, PolicySetRevision,
};
use erebor_runtime_policy::LocalPolicy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    config::RootCuratedAdmission,
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

pub(crate) struct BuiltInAdmission {
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
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
            adapter_digest: package.config_digest().as_str().to_owned(),
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
        if package.config_digest() != &adapter_digest {
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
        self.resolve_admission(
            spec.owner().uid(),
            package.sha256(),
            installation.sha256(),
            adapter.sha256(),
            spec.policy_set().sha256(),
        )
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
    ) -> Result<ContentDigest> {
        self.validate_policy_package(policy)?;
        let digest = policy.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.user_policy_package_path(owner_uid, &digest),
            &policy.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        Ok(digest)
    }

    pub(crate) fn create_user_policy_set(
        &self,
        owner_uid: u32,
        root_minimum_digest: &str,
        package_minimum_digests: &[String],
        local_override_digest: Option<&str>,
    ) -> Result<ContentDigest> {
        let root_minimum = Self::parse_digest(root_minimum_digest, "root policy package")?;
        self.read_canonical::<PolicyPackageRevision>(
            &self.policy_package_path(&root_minimum),
            &root_minimum,
            "root policy package",
        )?;
        let package_minimums = package_minimum_digests
            .iter()
            .map(|digest| {
                let digest = Self::parse_digest(digest, "package policy")?;
                self.read_policy_package(owner_uid, &digest)?;
                Ok(digest)
            })
            .collect::<Result<Vec<_>>>()?;
        let local_override = local_override_digest
            .filter(|digest| !digest.is_empty())
            .map(|digest| {
                let digest = Self::parse_digest(digest, "local policy")?;
                self.read_policy_package(owner_uid, &digest)?;
                Ok(digest)
            })
            .transpose()?;
        let revision = PolicySetRevision::new(root_minimum, package_minimums, local_override)
            .map_err(Self::invalid_model)?;
        let digest = revision.canonical_digest().map_err(Self::invalid_model)?;
        self.write_immutable(
            &self.policy_set_path(owner_uid, &digest),
            &revision.canonical_bytes().map_err(Self::invalid_model)?,
        )?;
        Ok(digest)
    }

    pub(crate) fn record_session_lease(&self, spec: &SessionSpec) -> Result<()> {
        self.record_lease(SessionLease::from_spec(spec))
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

    use super::{DaemonLocalStore, SessionLease};
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
        let user_digest = store.store_user_policy_package(1000, &user_policy)?;
        let policy_set = store.create_user_policy_set(
            1000,
            root_digest.as_str(),
            &[user_digest.as_str().to_owned()],
            None,
        )?;
        assert!(store
            .create_user_policy_set(1000, user_digest.as_str(), &[], None)
            .is_err());
        let revision: PolicySetRevision = store.read_canonical(
            &store.policy_set_path(1000, &policy_set),
            &policy_set,
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
