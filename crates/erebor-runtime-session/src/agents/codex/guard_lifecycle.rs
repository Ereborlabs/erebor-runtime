use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use erebor_runtime_ipc::v1::{
    GuardLifecycleEvent, GuardLifecycleEventKind, GuardLifecycleReply, GuardLifecycleReplyKind,
};

use crate::{runtime_interception_broker::GuardLifecycleHandler, ChildSessionAdmissionHandler};

use super::{broker::LinuxHookPeerInspector, CodexInvocationLeaseOwner, CodexManagedSession};

/// Codex-specific interpretation of generic process-guard lifecycle facts.
///
/// It has no listener or guard-owned descriptor. The session interception
/// broker invokes it only after it authenticates the guard connection.
pub(crate) struct CodexGuardLifecycleHandler {
    managed_session: CodexManagedSession,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    child_admissions: Arc<dyn ChildSessionAdmissionHandler>,
    tracked_pids: Mutex<HashMap<i64, ManagedLifecycle>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ManagedLifecycle {
    Hook,
    DelegationBridge,
}

impl CodexGuardLifecycleHandler {
    pub(crate) fn new(
        managed_session: CodexManagedSession,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
        child_admissions: Arc<dyn ChildSessionAdmissionHandler>,
    ) -> Self {
        Self {
            managed_session,
            lease_owner,
            child_admissions,
            tracked_pids: Mutex::new(HashMap::new()),
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
        if event.exec_history == expected_history {
            return self.admit_hook_exec(event);
        }
        self.admit_delegation_exec(event)
    }

    fn admit_hook_exec(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
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
            Ok(_ticket) => match self.tracked_pids.lock() {
                Ok(mut pids) => {
                    pids.insert(event.pid, ManagedLifecycle::Hook);
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

    fn admit_delegation_exec(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        let Some(bridge_path) = self.managed_session.profile().delegation_bridge_path() else {
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "Codex package has no daemon-physical delegation bridge",
            );
        };
        let bridge = bridge_path.display().to_string();
        let expected_history = vec![
            self.managed_session
                .profile()
                .executable()
                .display()
                .to_string(),
            bridge.clone(),
        ];
        if event.exec_history != expected_history {
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "exec chain is not the managed Codex delegation bridge",
            );
        }
        let pid = match i32::try_from(event.pid) {
            Ok(pid) if pid > 0 => pid,
            _ => {
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex delegation lifecycle event had an invalid process id",
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
                    "managed Codex delegation bridge peer inspection failed"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex delegation bridge peer inspection failed",
                );
            }
        };
        if peer.executable != bridge || peer.argv.as_slice() != [bridge.as_str()] {
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed Codex delegation bridge identity did not match its projected profile",
            );
        }
        let runtime = match LinuxHookPeerInspector::runtime_evidence(
            &peer,
            self.managed_session.profile().executable(),
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex delegation bridge runtime evidence failed"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex delegation bridge runtime evidence failed",
                );
            }
        };
        let admission = match self
            .lease_owner
            .prepare_child_admission(event.pid, &runtime)
        {
            Ok(admission) => admission,
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed delegation bridge has no exact parent lease"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed delegation bridge has no exact parent lease",
                );
            }
        };
        if let Err(reason) = self.child_admissions.admit_child(admission) {
            let _result = self.lease_owner.complete_child_admission(event.pid, false);
            erebor_runtime_telemetry::log!(
                erebor_runtime_telemetry::tracing::Level::WARN,
                %reason,
                pid = event.pid,
                "daemon rejected managed child admission"
            );
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "daemon rejected managed child admission",
            );
        }
        if let Err(error) = self.lease_owner.complete_child_admission(event.pid, true) {
            erebor_runtime_telemetry::log!(
                erebor_runtime_telemetry::tracing::Level::WARN,
                error = ?error,
                pid = event.pid,
                "managed child admission could not complete its delegation lease"
            );
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed child admission could not complete its delegation lease",
            );
        }
        match self.tracked_pids.lock() {
            Ok(mut pids) => {
                pids.insert(event.pid, ManagedLifecycle::DelegationBridge);
                Self::reply(
                    event,
                    GuardLifecycleReplyKind::Hold,
                    "daemon admitted child from the managed delegation bridge",
                )
            }
            Err(_error) => Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed delegation lifecycle state is unavailable",
            ),
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
        let tracked = match self.tracked_pids.lock() {
            Ok(mut pids) => pids.remove(&event.pid),
            Err(_error) => {
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook lifecycle state is unavailable",
                );
            }
        };
        let Some(tracked) = tracked else {
            if let Err(error) = self.lease_owner.record_guarded_process_exit(event.pid) {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed guard exit observation failed"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed guard exit observation failed",
                );
            }
            return Self::reply(
                event,
                GuardLifecycleReplyKind::Ignore,
                "process exit is not a managed Codex hook",
            );
        };
        if tracked == ManagedLifecycle::Hook {
            if let Err(error) = self.lease_owner.record_guarded_process_exit(event.pid) {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex hook exit observation failed"
                );
                return Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex hook exit observation failed",
                );
            }
        }
        let released = match tracked {
            ManagedLifecycle::Hook => self
                .lease_owner
                .record_guarded_hook_exit(event.pid, event.exited_successfully),
            ManagedLifecycle::DelegationBridge => self
                .lease_owner
                .record_guarded_delegation_exit(event.pid, event.exited_successfully),
        };
        match released {
            Ok(true) => Self::reply(
                event,
                GuardLifecycleReplyKind::Release,
                "managed Codex lifecycle process exited after its accepted request",
            ),
            Ok(false) => Self::reply(
                event,
                GuardLifecycleReplyKind::Deny,
                "managed Codex lifecycle process exited before successful completion",
            ),
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                    pid = event.pid,
                    "managed Codex lifecycle exit could not update its invocation lease"
                );
                Self::reply(
                    event,
                    GuardLifecycleReplyKind::Deny,
                    "managed Codex lifecycle exit could not update its invocation lease",
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
