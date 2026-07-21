use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::{ImmutableIdentity, SessionSpec};
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord, PolicySetRevision,
};
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
    package_digest: String,
    installation_digest: String,
    adapter_digest: String,
    policy_set_digest: String,
    policy_input_digests: Vec<String>,
}

impl LocalAdmission {
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
        if package.adapter_id() != "generic-process-v1" {
            return InvalidRequestSnafu {
                reason: format!(
                    "package `{}` selects adapter `{}` instead of the Phase 3 generic adapter",
                    package_digest.as_str(),
                    package.adapter_id()
                ),
            }
            .fail();
        }
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
        let policy_input_digests = policy_set
            .policy_input_digests()
            .into_iter()
            .map(|digest| digest.as_str().to_owned())
            .collect();

        Ok(LocalAdmission {
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
    use erebor_runtime_packages::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
        PolicySetRevision,
    };

    use super::{DaemonLocalStore, SessionLease};
    use crate::{config::RootCuratedAdmission, DaemonPaths};

    const ADAPTER_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
        let policy_set =
            PolicySetRevision::new(ContentDigest::new(POLICY_DIGEST)?, Vec::new(), None)?;
        let policy_set_digest = policy_set.canonical_digest()?;
        store.seed_root_curated(&[RootCuratedAdmission::new(package, installation, policy_set)])?;

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
            &[String::from(POLICY_DIGEST)]
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
}
