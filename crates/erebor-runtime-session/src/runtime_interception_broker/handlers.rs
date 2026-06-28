use std::{fmt, sync::Arc};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SurfaceInterceptionDecision,
};
use erebor_runtime_ipc::v1::InterceptionRequest;

#[derive(Debug)]
pub(super) struct SessionRegistration {
    pub(super) token: String,
    pub(super) broker_id: String,
    pub(super) router: SessionInterceptionRouter,
}

#[derive(Clone, Default)]
pub struct SessionInterceptionRouter {
    process_exec: Option<Arc<dyn ProcessExecSurfaceHandler>>,
}

impl SessionInterceptionRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_process_exec_handler(
        mut self,
        handler: impl ProcessExecSurfaceHandler + 'static,
    ) -> Self {
        self.process_exec = Some(Arc::new(handler));
        self
    }

    pub(super) fn decide_process_exec(
        &self,
        request: &InterceptionRequest,
    ) -> Option<SurfaceInterceptionDecision> {
        let process_exec_request = ProcessExecInterceptionRequest::new(
            &request.executable,
            &request.argv,
            &request.matched_handler_id,
        );
        self.process_exec
            .as_ref()
            .map(|handler| handler.decide_process_exec(&process_exec_request))
    }
}

impl fmt::Debug for SessionInterceptionRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionInterceptionRouter")
            .field(
                "process_exec",
                &self.process_exec.as_ref().map(|handler| handler.surface()),
            )
            .finish()
    }
}
