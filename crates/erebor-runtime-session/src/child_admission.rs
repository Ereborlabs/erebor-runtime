use std::sync::{Arc, Mutex};

use erebor_runtime_context::ContextPin;
use erebor_runtime_packages::CodexFrozenContextMode;

/// Daemon-owned facts needed to admit one already-authenticated physical
/// child. This is an in-process callback payload, not a workload IPC message.
#[derive(Clone, Debug)]
pub struct ChildSessionAdmission {
    parent_session_id: String,
    parent_context: ContextPin,
    child_profile: String,
    frozen_context_mode: CodexFrozenContextMode,
    last_turns: u32,
}

impl ChildSessionAdmission {
    #[must_use]
    pub fn new(
        parent_session_id: impl Into<String>,
        parent_context: ContextPin,
        child_profile: impl Into<String>,
        frozen_context_mode: CodexFrozenContextMode,
        last_turns: u32,
    ) -> Self {
        Self {
            parent_session_id: parent_session_id.into(),
            parent_context,
            child_profile: child_profile.into(),
            frozen_context_mode,
            last_turns,
        }
    }

    #[must_use]
    pub fn parent_session_id(&self) -> &str {
        &self.parent_session_id
    }

    #[must_use]
    pub const fn parent_context(&self) -> &ContextPin {
        &self.parent_context
    }

    #[must_use]
    pub fn child_profile(&self) -> &str {
        &self.child_profile
    }

    #[must_use]
    pub const fn frozen_context_mode(&self) -> CodexFrozenContextMode {
        self.frozen_context_mode
    }

    #[must_use]
    pub const fn last_turns(&self) -> u32 {
        self.last_turns
    }
}

/// The daemon callback invoked by the existing process-guard lifecycle route
/// after it has matched a declared bridge process to an armed lease.
pub trait ChildSessionAdmissionHandler: Send + Sync {
    fn admit_child(&self, admission: ChildSessionAdmission) -> std::result::Result<(), String>;
}

/// Startup-bound forwarding seam between a session runtime and the daemon.
/// It has no socket, descriptor, or workload-facing protocol.
#[derive(Default)]
pub struct ChildSessionAdmissionDispatcher {
    handler: Mutex<Option<Arc<dyn ChildSessionAdmissionHandler>>>,
}

impl ChildSessionAdmissionDispatcher {
    pub fn install(
        &self,
        handler: Arc<dyn ChildSessionAdmissionHandler>,
    ) -> std::result::Result<(), String> {
        let mut installed = self
            .handler
            .lock()
            .map_err(|_error| String::from("child-admission dispatcher state is unavailable"))?;
        if installed.is_some() {
            return Err(String::from("child-admission dispatcher is already bound"));
        }
        *installed = Some(handler);
        Ok(())
    }
}

impl ChildSessionAdmissionHandler for ChildSessionAdmissionDispatcher {
    fn admit_child(&self, admission: ChildSessionAdmission) -> std::result::Result<(), String> {
        let handler = self
            .handler
            .lock()
            .map_err(|_error| String::from("child-admission dispatcher state is unavailable"))?
            .clone()
            .ok_or_else(|| String::from("child-admission dispatcher is not bound"))?;
        handler.admit_child(admission)
    }
}
