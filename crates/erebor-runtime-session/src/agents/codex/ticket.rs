use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use erebor_runtime_ipc::v1::{HookHello, HookPeerEvidence};
use erebor_runtime_packages::{CodexHookEventName, CodexHookExec, CodexPackageDefinition};
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    fd::OwnedFd,
    process::{pidfd_open, Pid, PidfdFlags},
};
use snafu::{ensure, ResultExt};

use super::{
    broker::LinuxHookPeerInspector,
    error::{
        IncompatibleProfileSnafu, TicketExpiredSnafu, TicketNotFoundSnafu, TicketPeerMismatchSnafu,
        TicketProcessExitedSnafu, TicketRegistryLockSnafu, TicketReplayedSnafu,
        UnsupportedHookProtocolSnafu,
    },
    CodexLeaseRuntimeEvidence, CodexSessionError,
};

const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(10);

/// Session-owned authority for one configured Codex executable profile.
#[derive(Clone)]
pub struct CodexManagedSession {
    session_id: String,
    profile: CodexManagedProfile,
    tickets: CodexHookTicketRegistry,
}

#[derive(Clone)]
pub(crate) struct CodexManagedProfile {
    id: String,
    executable: PathBuf,
    managed_hook_path: PathBuf,
    hook_exec_history: Vec<PathBuf>,
    event_schemas: Vec<CodexManagedEventSchema>,
}

#[derive(Clone)]
pub(crate) struct CodexManagedEventSchema {
    event: CodexHookEventName,
    sha256: String,
}

impl CodexManagedProfile {
    fn from_package(executable: PathBuf, definition: &CodexPackageDefinition) -> Self {
        Self {
            id: definition.release_id().to_owned(),
            executable: executable.clone(),
            managed_hook_path: definition
                .managed_artifacts()
                .managed_hook_path()
                .to_path_buf(),
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
            event_schemas: definition
                .hook_contract()
                .event_schemas()
                .iter()
                .map(|schema| CodexManagedEventSchema {
                    event: schema.event().clone(),
                    sha256: schema.sha256().as_str().to_owned(),
                })
                .collect(),
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn managed_hook_path(&self) -> &Path {
        &self.managed_hook_path
    }

    pub(crate) fn hook_exec_history(&self) -> &[PathBuf] {
        &self.hook_exec_history
    }

    pub(crate) fn event_schema(
        &self,
        event: &CodexHookEventName,
    ) -> Option<&CodexManagedEventSchema> {
        self.event_schemas
            .iter()
            .find(|schema| &schema.event == event)
    }
}

impl CodexManagedEventSchema {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
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
            tickets: CodexHookTicketRegistry::default(),
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
    pub fn hook_tickets(&self) -> &CodexHookTicketRegistry {
        &self.tickets
    }

    pub fn issue_hook_ticket(
        &self,
        peer: HookPeerEvidence,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        self.tickets.issue(
            self.session_id.clone(),
            self.profile.id.clone(),
            peer,
            DEFAULT_TICKET_LIFETIME,
        )
    }

    pub(crate) fn issue_guarded_hook_ticket(
        &self,
        peer: HookPeerEvidence,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        let runtime = LinuxHookPeerInspector::runtime_evidence(&peer, self.profile.executable())?;
        let pid = i32::try_from(peer.observed_pid).map_err(|_error| CodexSessionError::Pidfd {
            pid: i32::MIN,
            source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
            location: snafu::Location::default(),
        })?;
        let pid = Pid::from_raw(pid).ok_or_else(|| CodexSessionError::Pidfd {
            pid,
            source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
            location: snafu::Location::default(),
        })?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .map_err(|source| CodexSessionError::Pidfd {
                pid: peer.observed_pid as i32,
                source,
                location: snafu::Location::default(),
            })?;
        self.tickets.issue_with_pidfd(
            self.session_id.clone(),
            self.profile.id.clone(),
            peer,
            DEFAULT_TICKET_LIFETIME,
            Some(pidfd),
            Some(runtime),
        )
    }
}

#[derive(Clone, Default)]
pub struct CodexHookTicketRegistry {
    state: Arc<Mutex<CodexHookTicketState>>,
}

#[derive(Default)]
struct CodexHookTicketState {
    pending: HashMap<String, PendingHookTicket>,
    consumed: HashMap<String, HookPeerEvidence>,
}

struct PendingHookTicket {
    ticket: CodexHookTicket,
    expected_peer: HookPeerEvidence,
    expires_at: Instant,
    pidfd: Option<OwnedFd>,
}

impl PendingHookTicket {
    fn process_is_live(&self) -> Result<bool, CodexSessionError> {
        let Some(pidfd) = &self.pidfd else {
            return Ok(true);
        };
        let mut descriptors = [PollFd::new(pidfd, PollFlags::IN)];
        let ready = poll(&mut descriptors, Some(&Timespec::default())).map_err(|source| {
            CodexSessionError::Pidfd {
                pid: self.expected_peer.observed_pid as i32,
                source: std::io::Error::from(source),
                location: snafu::Location::default(),
            }
        })?;
        Ok(ready == 0)
    }
}

/// A one-use binding from a guarded hook exec to its expected peer identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexHookTicket {
    id: String,
    session_id: String,
    profile_id: String,
    runtime: Option<CodexLeaseRuntimeEvidence>,
}

impl CodexHookTicket {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn runtime_evidence(&self) -> Option<CodexLeaseRuntimeEvidence> {
        self.runtime.clone()
    }
}

impl CodexHookTicketRegistry {
    pub fn issue(
        &self,
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        expected_peer: HookPeerEvidence,
        lifetime: Duration,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        self.issue_with_pidfd(session_id, profile_id, expected_peer, lifetime, None, None)
    }

    fn issue_with_pidfd(
        &self,
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        mut expected_peer: HookPeerEvidence,
        lifetime: Duration,
        pidfd: Option<OwnedFd>,
        runtime: Option<CodexLeaseRuntimeEvidence>,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        let ticket = CodexHookTicket {
            id: random_ticket_id()?,
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            runtime,
        };
        expected_peer.ticket_id = ticket.id.clone();
        let pending = PendingHookTicket {
            ticket: ticket.clone(),
            expected_peer,
            expires_at: Instant::now() + lifetime,
            pidfd,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_error| TicketRegistryLockSnafu.build())?;
        state.pending.insert(ticket.id.clone(), pending);
        Ok(ticket)
    }

    pub fn consume(
        &self,
        hello: &HookHello,
        observed_peer: &HookPeerEvidence,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        ensure!(
            hello.uses_supported_protocol(),
            UnsupportedHookProtocolSnafu {
                version: hello.protocol_version
            }
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_error| TicketRegistryLockSnafu.build())?;
        if state.consumed.contains_key(&hello.ticket_id) {
            return TicketReplayedSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        }
        let Some(pending) = state.pending.get(&hello.ticket_id) else {
            return TicketNotFoundSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        };
        if pending.expires_at <= Instant::now() {
            state.pending.remove(&hello.ticket_id);
            return TicketExpiredSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        }
        if !pending.process_is_live()? {
            state.pending.remove(&hello.ticket_id);
            return TicketProcessExitedSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        }
        if hello.session_id != pending.ticket.session_id
            || hello.ticket_id != observed_peer.ticket_id
            || pending.expected_peer != *observed_peer
        {
            return TicketPeerMismatchSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        }
        let Some(pending) = state.pending.remove(&hello.ticket_id) else {
            return TicketNotFoundSnafu {
                ticket_id: hello.ticket_id.clone(),
            }
            .fail();
        };
        state
            .consumed
            .insert(hello.ticket_id.clone(), pending.expected_peer);
        Ok(pending.ticket)
    }

    /// Consumes the one ticket whose complete kernel-observed identity matches
    /// this hook connection. Managed hooks intentionally do not receive a
    /// bearer ticket value: the broker selects only a unique, guard-issued
    /// pending ticket after it has independently collected peer evidence.
    pub fn consume_matching_peer(
        &self,
        hello: &HookHello,
        observed_peer: &HookPeerEvidence,
    ) -> Result<CodexHookTicket, CodexSessionError> {
        ensure!(
            hello.uses_supported_protocol(),
            UnsupportedHookProtocolSnafu {
                version: hello.protocol_version
            }
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_error| TicketRegistryLockSnafu.build())?;

        if let Some((ticket_id, _peer)) = state
            .consumed
            .iter()
            .find(|(_ticket_id, peer)| same_peer_identity(peer, observed_peer))
        {
            return TicketReplayedSnafu {
                ticket_id: ticket_id.clone(),
            }
            .fail();
        }

        let now = Instant::now();
        let matching = state
            .pending
            .iter()
            .filter(|(_ticket_id, pending)| {
                pending.ticket.session_id == hello.session_id
                    && pending.expires_at > now
                    && same_peer_identity(&pending.expected_peer, observed_peer)
            })
            .map(|(ticket_id, _pending)| ticket_id.clone())
            .collect::<Vec<_>>();
        let [ticket_id] = matching.as_slice() else {
            let pipe_mismatch = state
                .pending
                .iter()
                .filter(|(_ticket_id, pending)| {
                    pending.ticket.session_id == hello.session_id
                        && pending.expires_at > now
                        && same_peer_identity_without_pipes(&pending.expected_peer, observed_peer)
                })
                .map(|(ticket_id, _pending)| ticket_id.clone())
                .collect::<Vec<_>>();
            if let [ticket_id] = pipe_mismatch.as_slice() {
                return TicketPeerMismatchSnafu {
                    ticket_id: ticket_id.clone(),
                }
                .fail();
            }
            return TicketNotFoundSnafu {
                ticket_id: String::from("kernel-peer"),
            }
            .fail();
        };
        let Some(pending) = state.pending.remove(ticket_id) else {
            return TicketNotFoundSnafu {
                ticket_id: String::from("kernel-peer"),
            }
            .fail();
        };
        if !pending.process_is_live()? {
            return TicketProcessExitedSnafu {
                ticket_id: ticket_id.clone(),
            }
            .fail();
        }
        state
            .consumed
            .insert(ticket_id.clone(), pending.expected_peer);
        Ok(pending.ticket)
    }
}

fn same_peer_identity(expected: &HookPeerEvidence, observed: &HookPeerEvidence) -> bool {
    let mut expected = expected.clone();
    expected.ticket_id.clear();
    let mut observed = observed.clone();
    observed.ticket_id.clear();
    expected == observed
}

fn same_peer_identity_without_pipes(
    expected: &HookPeerEvidence,
    observed: &HookPeerEvidence,
) -> bool {
    let mut expected = expected.clone();
    expected.ticket_id.clear();
    expected.stdin = None;
    expected.stdout = None;
    let mut observed = observed.clone();
    observed.ticket_id.clear();
    observed.stdin = None;
    observed.stdout = None;
    expected == observed
}

fn random_ticket_id() -> Result<String, CodexSessionError> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .context(super::error::ReadArtifactSnafu {
            path: std::path::PathBuf::from("/dev/urandom"),
        })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use std::{process::Command, time::Duration};

    use erebor_runtime_ipc::v1::{HookHello, HookPeerEvidence, PipeIdentity, PROTOCOL_VERSION};
    #[cfg(target_os = "linux")]
    use rustix::process::{pidfd_open, Pid, PidfdFlags};

    use super::CodexHookTicketRegistry;
    use crate::CodexSessionError;

    fn peer() -> HookPeerEvidence {
        HookPeerEvidence {
            ticket_id: String::new(),
            observed_pid: 42,
            process_start_time_ticks: 77,
            executable: String::from("/usr/lib/erebor/codex-hooks/erebor-codex-hook"),
            argv: vec![String::from("erebor-codex-hook")],
            cgroup_inode: 88,
            mount_namespace_inode: 99,
            stdin: Some(PipeIdentity {
                device: 1,
                inode: 2,
            }),
            stdout: Some(PipeIdentity {
                device: 1,
                inode: 3,
            }),
            pidfd_identity: 123,
            exec_chain: vec![
                String::from("/bin/sh"),
                String::from("/usr/lib/erebor/codex-hooks/erebor-codex-hook"),
            ],
            observed_uid: 1000,
            observed_gid: 1000,
        }
    }

    #[test]
    fn ticket_consumption_requires_the_exact_peer_and_is_one_use(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookTicketRegistry::default();
        let ticket = registry.issue("session-1", "codex-1", peer(), Duration::from_secs(1))?;
        let hello = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: ticket.id().to_owned(),
            session_id: String::from("session-1"),
        };
        let mut forged = peer();
        forged.ticket_id = ticket.id().to_owned();
        forged.observed_pid = 999;
        assert!(matches!(
            registry.consume(&hello, &forged),
            Err(CodexSessionError::TicketPeerMismatch { .. })
        ));

        let mut observed = peer();
        observed.ticket_id = ticket.id().to_owned();
        assert_eq!(registry.consume(&hello, &observed)?, ticket);
        assert!(matches!(
            registry.consume(&hello, &observed),
            Err(CodexSessionError::TicketReplayed { .. })
        ));
        Ok(())
    }

    #[test]
    fn ticket_rejects_expired_and_unsupported_hello() -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookTicketRegistry::default();
        let ticket = registry.issue("session-1", "codex-1", peer(), Duration::ZERO)?;
        let mut observed = peer();
        observed.ticket_id = ticket.id().to_owned();
        let expired = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: ticket.id().to_owned(),
            session_id: String::from("session-1"),
        };
        assert!(matches!(
            registry.consume(&expired, &observed),
            Err(CodexSessionError::TicketExpired { .. })
        ));
        let unsupported = HookHello {
            protocol_version: PROTOCOL_VERSION + 1,
            ticket_id: String::from("ignored"),
            session_id: String::from("session-1"),
        };
        assert!(matches!(
            registry.consume(&unsupported, &observed),
            Err(CodexSessionError::UnsupportedHookProtocol { .. })
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_ticket_rejects_a_hook_that_exited_after_guard_observation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookTicketRegistry::default();
        let mut hook = Command::new("/bin/sleep").arg("60").spawn()?;
        let pid = i32::try_from(hook.id())?;
        let pid = Pid::from_raw(pid).ok_or("sleep pid is invalid")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let mut expected = peer();
        expected.observed_pid = i64::from(hook.id());
        let ticket = registry.issue_with_pidfd(
            "session-1",
            "codex-1",
            expected.clone(),
            Duration::from_secs(1),
            Some(pidfd),
            None,
        )?;
        hook.kill()?;
        hook.wait()?;

        expected.ticket_id = ticket.id().to_owned();
        let hello = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: ticket.id().to_owned(),
            session_id: String::from("session-1"),
        };
        assert!(matches!(
            registry.consume(&hello, &expected),
            Err(CodexSessionError::TicketProcessExited { .. })
        ));
        Ok(())
    }

    #[test]
    fn ticket_can_be_selected_only_by_a_unique_kernel_peer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookTicketRegistry::default();
        let ticket = registry.issue("session-1", "codex-1", peer(), Duration::from_secs(1))?;
        let hello = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: String::new(),
            session_id: String::from("session-1"),
        };
        assert_eq!(registry.consume_matching_peer(&hello, &peer())?, ticket);
        assert!(matches!(
            registry.consume_matching_peer(&hello, &peer()),
            Err(CodexSessionError::TicketReplayed { .. })
        ));
        Ok(())
    }

    #[test]
    fn ticket_reports_replaced_pipe_for_an_otherwise_matching_kernel_peer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = CodexHookTicketRegistry::default();
        let ticket = registry.issue("session-1", "codex-1", peer(), Duration::from_secs(1))?;
        let hello = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: String::new(),
            session_id: String::from("session-1"),
        };
        let mut replaced_stdout = peer();
        replaced_stdout
            .stdout
            .as_mut()
            .ok_or("missing stdout")?
            .inode += 1;
        assert!(matches!(
            registry.consume_matching_peer(&hello, &replaced_stdout),
            Err(CodexSessionError::TicketPeerMismatch { ticket_id, .. }) if ticket_id == ticket.id()
        ));
        Ok(())
    }

    #[test]
    fn ticket_rejects_replaced_descriptors_and_process_identity_drift(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, mutate) in [
            (
                "direct-hook-exec-chain",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.exec_chain = vec![peer.executable.clone()];
                }) as Box<dyn Fn(&mut HookPeerEvidence)>,
            ),
            (
                "tool-descendant-exec-chain",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.exec_chain[0] = String::from("/usr/bin/tool-child");
                }),
            ),
            (
                "stdin-replacement",
                Box::new(|peer: &mut HookPeerEvidence| {
                    let Some(stdin) = peer.stdin.as_mut() else {
                        return;
                    };
                    stdin.inode += 1;
                }),
            ),
            (
                "stdout-result-rewrite",
                Box::new(|peer: &mut HookPeerEvidence| {
                    let Some(stdout) = peer.stdout.as_mut() else {
                        return;
                    };
                    stdout.inode += 1;
                }),
            ),
            (
                "pid-reuse-start-identity",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.process_start_time_ticks += 1;
                }),
            ),
            (
                "pidfd-identity",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.pidfd_identity += 1;
                }),
            ),
            (
                "cgroup-namespace",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.cgroup_inode += 1;
                }),
            ),
            (
                "mount-namespace",
                Box::new(|peer: &mut HookPeerEvidence| {
                    peer.mount_namespace_inode += 1;
                }),
            ),
        ] {
            let registry = CodexHookTicketRegistry::default();
            let ticket = registry.issue("session-1", "codex-1", peer(), Duration::from_secs(1))?;
            let hello = HookHello {
                protocol_version: PROTOCOL_VERSION,
                ticket_id: ticket.id().to_owned(),
                session_id: String::from("session-1"),
            };
            let mut observed = peer();
            observed.ticket_id = ticket.id().to_owned();
            mutate(&mut observed);
            assert!(
                matches!(
                    registry.consume(&hello, &observed),
                    Err(CodexSessionError::TicketPeerMismatch { .. })
                ),
                "{name} must fail closed"
            );
        }
        Ok(())
    }
}
