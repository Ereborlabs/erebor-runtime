use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::{
    error::{HookPeerReplayedSnafu, HookRegistryLockSnafu, IncompatibleProfileSnafu},
    CodexSessionError,
};
use erebor_runtime_ipc::v1::HookPeerEvidence;
use erebor_runtime_packages::{CodexHookEventName, CodexHookExec, CodexPackageDefinition};

#[derive(Clone)]
pub struct CodexManagedSession {
    session_id: String,
    profile: CodexManagedProfile,
    peers: CodexHookPeerRegistry,
}

#[derive(Clone)]
pub(crate) struct CodexManagedProfile {
    id: String,
    executable: PathBuf,
    hook_exec_history: Vec<PathBuf>,
    events: Vec<CodexHookEventName>,
}

impl CodexManagedProfile {
    fn from_package(executable: PathBuf, definition: &CodexPackageDefinition) -> Self {
        Self {
            id: definition.release_id().to_owned(),
            executable: executable.clone(),
            hook_exec_history: definition
                .hook_contract()
                .exec_history()
                .iter()
                .map(|entry| match entry {
                    CodexHookExec::InstalledExecutable => executable.clone(),
                    CodexHookExec::AbsolutePath(path) => path.clone(),
                    CodexHookExec::ManagedHook => definition
                        .managed_artifacts()
                        .managed_hook_path()
                        .to_path_buf(),
                })
                .collect(),
            events: definition.hook_contract().events().to_vec(),
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn allows_hook_executable(&self, executable: &str) -> bool {
        self.hook_exec_history
            .iter()
            .any(|expected| expected == Path::new(executable))
    }

    pub(crate) fn allows_event(&self, event: &CodexHookEventName) -> bool {
        self.events.contains(event)
    }
}

impl CodexManagedSession {
    pub(crate) fn from_package(
        session_id: impl Into<String>,
        executable: PathBuf,
        definition: &CodexPackageDefinition,
    ) -> Result<Self, CodexSessionError> {
        if !definition.supported_platform().matches_host() {
            return IncompatibleProfileSnafu {
                reason: String::from("Codex package is not supported by this Linux host"),
            }
            .fail();
        }
        Ok(Self {
            session_id: session_id.into(),
            profile: CodexManagedProfile::from_package(executable, definition),
            peers: CodexHookPeerRegistry::default(),
        })
    }

    #[must_use]
    pub(crate) fn profile(&self) -> &CodexManagedProfile {
        &self.profile
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn hook_peers(&self) -> &CodexHookPeerRegistry {
        &self.peers
    }
}

#[derive(Clone, Default)]
pub struct CodexHookPeerRegistry {
    authenticated: Arc<Mutex<Vec<HookPeerEvidence>>>,
}

impl CodexHookPeerRegistry {
    pub(crate) fn authenticate_peer(
        &self,
        observed_peer: HookPeerEvidence,
    ) -> Result<(), CodexSessionError> {
        let mut authenticated = self
            .authenticated
            .lock()
            .map_err(|_error| HookRegistryLockSnafu.build())?;
        if authenticated.iter().any(|peer| peer == &observed_peer) {
            return HookPeerReplayedSnafu.fail();
        }
        authenticated.push(observed_peer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::{HookPeerEvidence, PipeIdentity};

    use super::{CodexHookPeerRegistry, CodexSessionError};

    #[test]
    fn authenticated_kernel_peer_is_one_use() -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookPeerRegistry::default();
        registry.authenticate_peer(peer())?;
        assert!(matches!(
            registry.authenticate_peer(peer()),
            Err(CodexSessionError::HookPeerReplayed { .. })
        ));
        Ok(())
    }

    fn peer() -> HookPeerEvidence {
        HookPeerEvidence {
            observed_pid: 42,
            process_start_time_ticks: 100,
            executable: String::from("/run/erebor/codex/hooks/erebor-codex-hook"),
            argv: vec![String::from("erebor-codex-hook")],
            cgroup_inode: 7,
            mount_namespace_inode: 8,
            stdin: Some(PipeIdentity {
                device: 1,
                inode: 2,
            }),
            stdout: Some(PipeIdentity {
                device: 1,
                inode: 3,
            }),
            pidfd_identity: 100,
            exec_chain: vec![
                String::from("/opt/codex/codex"),
                String::from("/run/erebor/codex/hooks/erebor-codex-hook"),
            ],
            observed_uid: 1000,
            observed_gid: 1000,
        }
    }
}
