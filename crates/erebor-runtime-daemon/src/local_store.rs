use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::{ImmutableIdentity, SessionSpec};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{error::IoSnafu, DaemonPaths, Result};

/// Root-owned content reference indexes. A session lease keeps every immutable
/// identity named by a durable session reachable until that session is removed.
pub(crate) struct DaemonLocalStore {
    packages: PathBuf,
    write_lock: Mutex<()>,
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
        Self::require_safe_directory(&packages)?;
        Ok(Self {
            packages,
            write_lock: Mutex::new(()),
        })
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
    use super::{DaemonLocalStore, SessionLease};
    use crate::DaemonPaths;

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
}
