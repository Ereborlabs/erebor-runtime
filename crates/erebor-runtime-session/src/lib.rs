mod adoption;
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

pub use adoption::adopt_session_target;
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
pub use session_run::{
    adopt_session_plan, adopt_session_plan_capture, run_session_diagnostic, run_session_plan,
};
pub use surface_services::start_surface_launch_plan;
pub use surfaces::terminal::browser_cdp_process_mediation::BrowserCdpProcessMediationCapability;

pub(crate) use registry_lifecycle::SessionStorage;
pub(crate) use session_context::SessionPlanContext;
