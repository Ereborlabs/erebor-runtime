use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use erebor_runtime_ipc::v1::{
    GuardLifecycleEvent, GuardLifecycleEventKind, GuardLifecycleReply, GuardLifecycleReplyKind,
};

use crate::runtime_interception_broker::GuardLifecycleHandler;

use super::{broker::LinuxHookPeerInspector, CodexInvocationLeaseOwner, CodexManagedSession};

/// Codex-specific interpretation of generic process-guard lifecycle facts.
///
/// It has no listener or guard-owned descriptor. The session interception
/// broker invokes it only after it authenticates the guard connection.
pub(crate) struct CodexGuardLifecycleHandler {
    managed_session: CodexManagedSession,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    tracked_hook_pids: Mutex<HashSet<i64>>,
}

impl CodexGuardLifecycleHandler {
    pub(crate) fn new(
        managed_session: CodexManagedSession,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        Self {
            managed_session,
            lease_owner,
            tracked_hook_pids: Mutex::new(HashSet::new()),
        }
    }

    fn reply(
        event: &GuardLifecycleEvent,
        decision: GuardLifecycleReplyKind,
        reason: impl Into<String>,
    ) -> GuardLifecycleReply {
        GuardLifecycleReply {
            request_id: event.request_id,
            decision: decision as i32,
            reason: reason.into(),
        }
    }

    fn handle_exec(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        let expected_history = self
            .managed_session
            .profile()
            .hook_exec_history()
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        if event.exec_history != expected_history {
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "exec chain is not the managed Codex hook",
            );
        }

        let pid = match i32::try_from(event.pid) {
            Ok(pid) if pid > 0 => pid,
            _ => {
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook lifecycle event had an invalid process id",
                );
            }
        };
        let peer = match LinuxHookPeerInspector::inspect_pid(pid, "") {
            Ok(peer) => peer,
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex hook peer inspection failed"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook peer inspection failed",
                );
            }
        };
        let profile = self.managed_session.profile();
        if peer.executable != profile.managed_hook_path().display().to_string()
            || peer.argv != [profile.managed_hook_path().display().to_string()]
        {
            erebor_runtime_telemetry::log!(
                erebor_runtime_telemetry::tracing::Level::WARN,
                pid = event.pid,
                executable = %peer.executable,
                argv = %peer.argv.join(" "),
                "managed Codex hook identity did not match its projected profile"
            );
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed Codex hook identity did not match its projected profile",
            );
        }
        match self.managed_session.issue_guarded_hook_ticket(peer) {
            Ok(_ticket) => match self.tracked_hook_pids.lock() {
                Ok(mut pids) => {
                    pids.insert(event.pid);
                    Self::reply(
                        event,
                        GuardLifecycleReplyKind::Hold,
                        "managed Codex hook ticket issued; hold physical effects until hook exit",
                    )
                }
                Err(_error) => Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook lifecycle state is unavailable",
                ),
            },
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex hook ticket issuance failed"
                );
                Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook ticket issuance failed",
                )
            }
        }
    }

    fn handle_fork(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        match self
            .lease_owner
            .record_guarded_process_fork(event.parent_pid, event.child_pid)
        {
            Ok(()) => Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "process fork recorded",
            ),
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    parent_pid = event.parent_pid,
                    child_pid = event.child_pid,
                    "managed Codex guard fork observation failed"
                );
                Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex guard fork observation failed",
                )
            }
        }
    }

    fn handle_exit(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        if let Err(error) = self.lease_owner.record_guarded_process_exit(event.pid) {
            erebor_runtime_telemetry::log!(
                erebor_runtime_telemetry::tracing::Level::WARN,
                error = ?error,
                pid = event.pid,
                "managed Codex guard exit observation failed"
            );
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed Codex guard exit observation failed",
            );
        }
        let tracked_hook = match self.tracked_hook_pids.lock() {
            Ok(mut pids) => pids.remove(&event.pid),
            Err(_error) => {
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook lifecycle state is unavailable",
                );
            }
        };
        if !tracked_hook {
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "process exit is not a managed Codex hook",
            );
        }
        match self
            .lease_owner
            .record_guarded_hook_exit(event.pid, event.exited_successfully)
        {
            Ok(true) => Self::reply(
                event,
                GuardLifecycleReplyKind::Release,
                "managed Codex hook exited after an accepted lifecycle event",
            ),
            Ok(false) => Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed Codex hook exited before successful lifecycle completion",
            ),
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex hook exit could not update its invocation lease"
                );
                Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook exit could not update its invocation lease",
                )
            }
        }
    }
}

impl GuardLifecycleHandler for CodexGuardLifecycleHandler {
    fn decide_guard_lifecycle(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        match GuardLifecycleEventKind::try_from(event.event).ok() {
            Some(GuardLifecycleEventKind::Exec) => self.handle_exec(event),
            Some(GuardLifecycleEventKind::Fork) => self.handle_fork(event),
            Some(GuardLifecycleEventKind::Exit) => self.handle_exit(event),
            Some(GuardLifecycleEventKind::Unspecified) | None => Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "guard lifecycle event had an unsupported kind",
            ),
        }
    }
}
