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
mod session_helper;
mod session_manager;
mod session_output;
mod session_repository;
mod session_resources;
mod session_run;
mod session_side_resources;
mod surface_services;
mod surfaces;

#[cfg(test)]
mod tests;

pub use adoption::SessionAdoptionService;
pub use agents::codex::{
    CodexHookClient, CodexHookResultOutput, CodexHookTicket, CodexHookTicketRegistry,
    CodexManagedSession, CodexNativeHookEvent, CodexSessionError,
};
pub use diagnostic::SessionDiagnosticOutcome;
pub use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};
pub use error::{
    SessionExecutionError, SessionHelperError, SessionManagerError, SessionOutputError,
    SessionRepositoryError,
};
pub use runtime_interception_broker::{
    InterceptionBrokerClient, RuntimeGuardService, RuntimeInterceptionBroker,
    RuntimeInterceptionBrokerError, RuntimeInterceptionEndpoint, SessionInterceptionRegistration,
    SessionInterceptionRouter,
};
#[doc(hidden)]
pub use session_helper::run_session_helper;
pub use session_manager::{
    output_endpoints, ResolvedSessionPath, RunnerRegistry, SessionAttachOutcome,
    SessionInterceptionRouterFactory, SessionManager, SessionPathResolver,
    SessionPathResolverError, SessionRuntimeResources, ValidatedStartConstraints,
};
pub use session_output::{
    DurableStreamCursor, DurableStreamRecord, DurableStreamStore, InputLease, InputLeaseManager,
    SessionOutputStores, StreamKind,
};
pub use session_repository::{DurableSessionRecord, SessionPruneResult, SessionRepository};
pub use session_run::SessionExecutionService;
pub use surface_services::SurfaceServiceRunner;
pub use surfaces::filesystem::{FilesystemFileOperationHandler, FilesystemSessionContext};
pub use surfaces::terminal::browser_cdp_process_mediation::BrowserCdpProcessMediationCapability;

pub(crate) use registry_lifecycle::SessionStorage;
pub(crate) use session_context::SessionPlanContext;
