use std::sync::{Arc, Mutex};

use erebor_runtime_context::ScopeRef;

/// A source-authenticated collaboration identity bound to one existing context
/// scope. It is not an operating-system process or a new Erebor session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextAgentIdentity {
    thread_id: String,
    turn_id: String,
    scope: ScopeRef,
}

impl ContextAgentIdentity {
    pub fn new(
        thread_id: impl Into<String>,
        turn_id: impl Into<String>,
        scope: ScopeRef,
    ) -> std::result::Result<Self, String> {
        let thread_id = thread_id.into();
        let turn_id = turn_id.into();
        for (label, value) in [("thread ID", &thread_id), ("turn ID", &turn_id)] {
            if value.is_empty()
                || value.len() > 128
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
            {
                return Err(format!(
                    "context agent {label} must be a bounded ASCII identifier"
                ));
            }
        }
        Ok(Self {
            thread_id,
            turn_id,
            scope,
        })
    }

    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    #[must_use]
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    #[must_use]
    pub const fn scope(&self) -> &ScopeRef {
        &self.scope
    }
}

/// The collaboration controls that the daemon may authorize from an existing
/// authenticated agent invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextAgentControlAction {
    List,
    FollowUp,
    Interrupt,
}

impl ContextAgentControlAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list_agents",
            Self::FollowUp => "follow_up",
            Self::Interrupt => "interrupt",
        }
    }
}

/// One in-process request from the authenticated hook adapter to the daemon.
/// It deliberately carries identities the adapter has already bound; it never
/// accepts a workload-provided scope ref or opens another listener.
#[derive(Clone, Debug)]
pub struct ContextAgentControl {
    session_id: String,
    requester: ContextAgentIdentity,
    target: Option<ContextAgentIdentity>,
    action: ContextAgentControlAction,
    content_sha256: Option<String>,
    known_agents: Vec<ContextAgentIdentity>,
}

impl ContextAgentControl {
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        requester: ContextAgentIdentity,
        target: Option<ContextAgentIdentity>,
        action: ContextAgentControlAction,
        content_sha256: Option<String>,
        known_agents: Vec<ContextAgentIdentity>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            requester,
            target,
            action,
            content_sha256,
            known_agents,
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn requester(&self) -> &ContextAgentIdentity {
        &self.requester
    }

    #[must_use]
    pub const fn target(&self) -> Option<&ContextAgentIdentity> {
        self.target.as_ref()
    }

    #[must_use]
    pub const fn action(&self) -> ContextAgentControlAction {
        self.action
    }

    #[must_use]
    pub fn content_sha256(&self) -> Option<&str> {
        self.content_sha256.as_deref()
    }

    #[must_use]
    pub fn known_agents(&self) -> &[ContextAgentIdentity] {
        &self.known_agents
    }
}

/// The daemon's authorization result returned to the adapter through the
/// existing hook response. The source runtime performs its own native
/// follow-up or interruption only after this result allows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextAgentControlResult {
    action: ContextAgentControlAction,
    agents: Vec<ContextAgentIdentity>,
}

impl ContextAgentControlResult {
    #[must_use]
    pub fn allowed(action: ContextAgentControlAction, agents: Vec<ContextAgentIdentity>) -> Self {
        Self { action, agents }
    }

    #[must_use]
    pub const fn action(&self) -> ContextAgentControlAction {
        self.action
    }

    #[must_use]
    pub fn agents(&self) -> &[ContextAgentIdentity] {
        &self.agents
    }
}

/// Startup-bound forwarding seam between the authenticated adapter and the
/// daemon-owned context coordinator. It has no wire protocol or listener.
pub trait ContextAgentControlHandler: Send + Sync {
    fn handle_agent_control(
        &self,
        control: ContextAgentControl,
    ) -> std::result::Result<ContextAgentControlResult, String>;
}

#[derive(Default)]
pub struct ContextAgentControlDispatcher {
    handler: Mutex<Option<Arc<dyn ContextAgentControlHandler>>>,
}

impl ContextAgentControlDispatcher {
    pub fn install(
        &self,
        handler: Arc<dyn ContextAgentControlHandler>,
    ) -> std::result::Result<(), String> {
        let mut installed = self.handler.lock().map_err(|_error| {
            String::from("context-agent-control dispatcher state is unavailable")
        })?;
        if installed.is_some() {
            return Err(String::from(
                "context-agent-control dispatcher is already bound",
            ));
        }
        *installed = Some(handler);
        Ok(())
    }
}

impl ContextAgentControlHandler for ContextAgentControlDispatcher {
    fn handle_agent_control(
        &self,
        control: ContextAgentControl,
    ) -> std::result::Result<ContextAgentControlResult, String> {
        let handler = self
            .handler
            .lock()
            .map_err(|_error| {
                String::from("context-agent-control dispatcher state is unavailable")
            })?
            .clone()
            .ok_or_else(|| String::from("context-agent-control dispatcher is not bound"))?;
        handler.handle_agent_control(control)
    }
}
