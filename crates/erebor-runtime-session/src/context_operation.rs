use std::sync::{Arc, Mutex};

use erebor_runtime_context::{ContextPin, ScopeRef};

/// Daemon-owned facts that identify one authenticated operation within an
/// already-running agent session. This is an in-process callback payload, not
/// a workload IPC message or a second process-guard protocol.
#[derive(Clone, Debug)]
pub struct ContextOperationAdmission {
    session_id: String,
    parent_context: ContextPin,
    operation_key: String,
}

impl ContextOperationAdmission {
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        parent_context: ContextPin,
        operation_key: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            parent_context,
            operation_key: operation_key.into(),
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn parent_context(&self) -> &ContextPin {
        &self.parent_context
    }

    #[must_use]
    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }
}

/// The daemon callback that admits a logical operation scope from an exact
/// authenticated agent invocation. Its return value is the daemon-created
/// source scope later used for that operation's bounded deliveries.
pub trait ContextOperationAdmissionHandler: Send + Sync {
    fn admit_operation(
        &self,
        admission: ContextOperationAdmission,
    ) -> std::result::Result<ScopeRef, String>;
}

/// Startup-bound forwarding seam between a session runtime and the daemon.
/// It has no listener, descriptor, or workload-facing protocol.
#[derive(Default)]
pub struct ContextOperationAdmissionDispatcher {
    handler: Mutex<Option<Arc<dyn ContextOperationAdmissionHandler>>>,
}

impl ContextOperationAdmissionDispatcher {
    pub fn install(
        &self,
        handler: Arc<dyn ContextOperationAdmissionHandler>,
    ) -> std::result::Result<(), String> {
        let mut installed = self
            .handler
            .lock()
            .map_err(|_error| String::from("context-operation dispatcher state is unavailable"))?;
        if installed.is_some() {
            return Err(String::from(
                "context-operation dispatcher is already bound",
            ));
        }
        *installed = Some(handler);
        Ok(())
    }
}

impl ContextOperationAdmissionHandler for ContextOperationAdmissionDispatcher {
    fn admit_operation(
        &self,
        admission: ContextOperationAdmission,
    ) -> std::result::Result<ScopeRef, String> {
        let handler = self
            .handler
            .lock()
            .map_err(|_error| String::from("context-operation dispatcher state is unavailable"))?
            .clone()
            .ok_or_else(|| String::from("context-operation dispatcher is not bound"))?;
        handler.admit_operation(admission)
    }
}
