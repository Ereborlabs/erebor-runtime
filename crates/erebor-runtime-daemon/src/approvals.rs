use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_approvals::{
    ApprovalError, ApprovalRecord, ApprovalRepository, ApprovalState, Result as ApprovalResult,
};
use snafu::ResultExt;

use crate::{error::IoSnafu, DaemonPaths, Result};

/// Root-owned durable approval repository. Pending and terminal paths are the
/// restart indexes; the JSON record remains the complete state-machine fact.
pub(crate) struct DaemonApprovalRepository {
    root: PathBuf,
    state: Mutex<()>,
}

impl DaemonApprovalRepository {
    pub(crate) fn installed(paths: &DaemonPaths) -> Result<Self> {
        let root = paths.users_state_path();
        fs::create_dir_all(&root).context(IoSnafu {
            action: "creating daemon users approval root",
            path: &root,
        })?;
        Ok(Self {
            root,
            state: Mutex::new(()),
        })
    }

    fn record_path(&self, state: ApprovalState, owner_uid: u32, approval_id: &str) -> PathBuf {
        self.root
            .join(owner_uid.to_string())
            .join("approvals")
            .join(if state.is_terminal() {
                "terminal"
            } else {
                "pending"
            })
            .join(format!("{approval_id}.json"))
    }

    fn record_paths(&self, owner_uid: u32, approval_id: &str) -> [PathBuf; 2] {
        [
            self.record_path(ApprovalState::Pending, owner_uid, approval_id),
            self.record_path(ApprovalState::Denied, owner_uid, approval_id),
        ]
    }

    fn write_record(&self, path: &Path, record: &ApprovalRecord) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| crate::DaemonError::UnsafePath {
                path: path.to_path_buf(),
                reason: String::from("approval record has no parent directory"),
                location: snafu::Location::default(),
            })?;
        fs::create_dir_all(parent).context(IoSnafu {
            action: "creating approval record directory",
            path: parent,
        })?;
        let temporary = path.with_extension("json.tmp");
        let encoded =
            serde_json::to_vec(record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(IoSnafu {
                action: "writing approval record",
                path: &temporary,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "writing approval record",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing approval record",
            path: &temporary,
        })?;
        fs::rename(&temporary, path).context(IoSnafu {
            action: "publishing approval record",
            path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening approval record directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing approval record directory",
                path: parent,
            })
    }

    fn read_record(&self, owner_uid: u32, approval_id: &str) -> ApprovalResult<ApprovalRecord> {
        let path = self
            .record_paths(owner_uid, approval_id)
            .into_iter()
            .find(|path| path.exists())
            .ok_or_else(|| ApprovalError::not_found(approval_id))?;
        let encoded = fs::read(&path)
            .map_err(|source| ApprovalError::repository_unavailable(source.to_string()))?;
        serde_json::from_slice(&encoded)
            .map_err(|source| ApprovalError::repository_unavailable(source.to_string()))
    }

    fn replace_record(&self, record: &ApprovalRecord) -> Result<()> {
        let owner_uid = record.binding().owner_uid();
        let target = self.record_path(record.state(), owner_uid, record.id());
        self.write_record(&target, record)?;
        for path in self.record_paths(owner_uid, record.id()) {
            if path != target {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(crate::DaemonError::Io {
                            action: "removing superseded approval index record",
                            path,
                            source,
                            location: snafu::Location::default(),
                        })
                    }
                }
            }
        }
        Ok(())
    }

    fn unavailable(error: crate::DaemonError) -> ApprovalError {
        ApprovalError::repository_unavailable(error.to_string())
    }
}

impl ApprovalRepository for DaemonApprovalRepository {
    fn create(&self, record: ApprovalRecord) -> ApprovalResult<ApprovalRecord> {
        let _state = self.state.lock().map_err(|_error| {
            ApprovalError::repository_unavailable("approval repository lock is poisoned")
        })?;
        if self
            .record_paths(record.binding().owner_uid(), record.id())
            .into_iter()
            .any(|path| path.exists())
        {
            return Err(ApprovalError::repository_unavailable(
                "approval id already exists",
            ));
        }
        self.replace_record(&record).map_err(Self::unavailable)?;
        Ok(record)
    }

    fn inspect(&self, owner_uid: u32, approval_id: &str) -> ApprovalResult<ApprovalRecord> {
        let _state = self.state.lock().map_err(|_error| {
            ApprovalError::repository_unavailable("approval repository lock is poisoned")
        })?;
        self.read_record(owner_uid, approval_id)
    }

    fn list_pending(&self, owner_uid: u32) -> ApprovalResult<Vec<ApprovalRecord>> {
        let _state = self.state.lock().map_err(|_error| {
            ApprovalError::repository_unavailable("approval repository lock is poisoned")
        })?;
        let root = self
            .record_path(ApprovalState::Pending, owner_uid, "placeholder")
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                ApprovalError::repository_unavailable("approval pending index has no parent")
            })?;
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(ApprovalError::repository_unavailable(source.to_string())),
        };
        entries
            .map(|entry| {
                let entry = entry
                    .map_err(|source| ApprovalError::repository_unavailable(source.to_string()))?;
                let encoded = fs::read(entry.path())
                    .map_err(|source| ApprovalError::repository_unavailable(source.to_string()))?;
                serde_json::from_slice(&encoded)
                    .map_err(|source| ApprovalError::repository_unavailable(source.to_string()))
            })
            .collect()
    }

    fn replace(&self, record: ApprovalRecord) -> ApprovalResult<ApprovalRecord> {
        let _state = self.state.lock().map_err(|_error| {
            ApprovalError::repository_unavailable("approval repository lock is poisoned")
        })?;
        self.replace_record(&record).map_err(Self::unavailable)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_approvals::{ApprovalBinding, ApprovalRecord, ApprovalRepository};

    use super::DaemonApprovalRepository;
    use crate::DaemonPaths;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn record() -> Result<ApprovalRecord, Box<dyn std::error::Error>> {
        Ok(ApprovalRecord::pending(
            "approval-1",
            ApprovalBinding::new(1000, "session-1", 1, DIGEST, "pidfd:8", DIGEST, "rule")?,
            1,
            20,
        )?)
    }

    #[test]
    fn pending_and_terminal_indexes_survive_a_repository_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths = DaemonPaths::for_testing(root.path());
        let repository = DaemonApprovalRepository::installed(&paths)?;
        repository.create(record()?)?;
        assert_eq!(repository.list_pending(1000)?.len(), 1);
        let mut updated = repository.inspect(1000, "approval-1")?;
        updated.deny(2, "not now")?;
        repository.replace(updated)?;
        let reopened = DaemonApprovalRepository::installed(&paths)?;
        assert!(reopened.list_pending(1000)?.is_empty());
        assert!(reopened.inspect(1000, "approval-1")?.state().is_terminal());
        Ok(())
    }
}
