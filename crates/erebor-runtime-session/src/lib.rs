mod adoption;
mod agents;
mod diagnostic;
mod error;
mod interception_backend;
mod interception_setup;
mod policies;
mod registry_lifecycle;
mod runtime_interception_broker;
mod session_context;
mod session_resources;
mod session_run;
mod session_side_resources;
mod surface_services;
mod surfaces;

#[cfg(test)]
mod tests;

pub use adoption::SessionAdoptionService;
pub use agents::codex::{
    CodexHookClient, CodexHookTicket, CodexHookTicketRegistry, CodexManagedSession,
    CodexSessionError,
};
pub use diagnostic::SessionDiagnosticOutcome;
pub use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};
pub use error::SessionExecutionError;
pub use runtime_interception_broker::{
    InterceptionBrokerClient, RuntimeInterceptionBroker, RuntimeInterceptionBrokerError,
    RuntimeInterceptionEndpoint, SessionInterceptionRegistration, SessionInterceptionRouter,
};
pub use session_run::SessionExecutionService;
pub use surface_services::SurfaceServiceRunner;
pub use surfaces::filesystem::{FilesystemFileOperationHandler, FilesystemSessionContext};
pub use surfaces::terminal::browser_cdp_process_mediation::BrowserCdpProcessMediationCapability;

pub(crate) use registry_lifecycle::SessionStorage;
pub(crate) use session_context::SessionPlanContext;
