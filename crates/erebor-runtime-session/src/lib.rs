mod adoption;
mod agents;
mod child_admission;
mod child_delivery;
mod controller_support;
mod diagnostic;
mod docker_controller;
mod error;
mod interception_backend;
mod interception_setup;
mod linux_controller;
mod policies;
mod registry_lifecycle;
mod runners;
mod runtime_interception_broker;
mod session_context;
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
    CodexAppServerInput, CodexAppServerService, CodexHookClient, CodexHookResultOutput,
    CodexHookService, CodexHookTicket, CodexHookTicketRegistry, CodexManagedSession,
    CodexNativeHookEvent, CodexSessionError, CodexSessionHookRegistration,
    MAX_APP_SERVER_FRAME_BYTES,
};
pub use agents::{AgentAdapter, AgentAdapterRegistry, PreparedAgentInvocation};
pub use child_admission::{
    ChildSessionAdmission, ChildSessionAdmissionDispatcher, ChildSessionAdmissionHandler,
};
pub use child_delivery::{
    ChildContextDelivery, ChildContextDeliveryDispatcher, ChildContextDeliveryHandler,
};
pub use diagnostic::SessionDiagnosticOutcome;
#[doc(hidden)]
pub use docker_controller::run_docker_session_controller;
pub use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};
pub use error::{
    SessionControllerError, SessionExecutionError, SessionManagerError, SessionOutputError,
    SessionRepositoryError,
};
#[doc(hidden)]
pub use linux_controller::run_linux_session_controller;
pub use runners::{
    RunnerAdmissionContext, RunnerAdmissionRequest, RunnerCapabilityReport, RunnerDriver,
    RunnerExecutionAdmission, RunnerInstallConfig, RunnerPreparation, RunnerRegistry,
};
pub use runtime_interception_broker::{
    InterceptionBrokerClient, RuntimeGuardService, RuntimeInterceptionBroker,
    RuntimeInterceptionBrokerError, RuntimeInterceptionEndpoint, SessionInterceptionRegistration,
    SessionInterceptionRouter,
};
pub use session_manager::{
    output_endpoints, ResolvedSessionPath, SessionAttachOutcome, SessionInterceptionRouterFactory,
    SessionManager, SessionPathResolver, SessionPathResolverError, SessionRuntimeResources,
    ValidatedStartConstraints,
};
pub use session_output::{
    DurableStreamCursor, DurableStreamRecord, DurableStreamStore, InputLease, InputLeaseManager,
    SessionOutputStores, StreamKind,
};
pub use session_repository::{
    DurableSessionRecord, SessionAlias, SessionPruneResult, SessionRepository,
};
pub use session_run::SessionExecutionService;
pub use surface_services::SurfaceServiceRunner;
pub use surfaces::filesystem::{FilesystemFileOperationHandler, FilesystemSessionContext};
pub use surfaces::terminal::browser_cdp_process_mediation::BrowserCdpProcessMediationCapability;

pub(crate) use registry_lifecycle::SessionStorage;
pub(crate) use session_context::SessionPlanContext;
pub(crate) use session_manager::SessionRuntime;
