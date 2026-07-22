//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod interception;
mod runtime;
mod session;
mod session_registry;
#[cfg(test)]
mod tests;

pub use config::{
    AuditCommandLogLevel, BrowserCdpAuditSurfaceLoggingConfig, BrowserCdpSurfaceConfig,
    BrowserCdpSurfaceLayerConfig, BrowserLaunchConfig, BrowserLaunchLayerConfig,
    DesktopAuditSurfaceLoggingConfig, DockerSessionCommandOptions,
    DockerSessionCommandPlan, DockerSessionMount, DockerSessionRunnerConfig,
    DockerSessionRunnerLayerConfig, FilesystemAuditSurfaceLoggingConfig, FilesystemBackendConfig,
    FilesystemBackendKind, FilesystemBackendLayerConfig, FilesystemPreimageBackendKind,
    FilesystemRevertConfig, FilesystemRevertLayerConfig, FilesystemSessionWorkAutocommitConfig,
    FilesystemSessionWorkAutocommitLayerConfig, FilesystemSessionWorkAutocommitRuleConfig,
    FilesystemSessionWorkAutocommitRuleLayerConfig, FilesystemSurfaceConfig,
    FilesystemSurfaceLayerConfig, FilesystemVolumeConfig, FilesystemVolumeLayerConfig,
    FilesystemVolumeMode, InternalSystemAuditSurfaceLoggingConfig, LinuxHostSessionCommandOptions,
    LinuxHostSessionCommandPlan, LinuxHostSessionRunnerConfig, LinuxHostSessionRunnerLayerConfig,
    McpAuditSurfaceLoggingConfig, NetworkAuditSurfaceLoggingConfig, PolicyPathValidator,
    ProcessInterceptionDecision, ProcessInterceptionHandlerConfig, ProcessInterceptionHandlerKind,
    ProcessMediationCompatibilityConfig, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEndpointSource, ProcessMediationEnvironmentConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerConfig,
    ProcessMediationHandlerKind, ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationPrivateEndpointConfig,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementConfig, ProcessMediationReplacementLayerConfig,
    ProcessMediationReplacementSurface, ProcessMediationRequestedEndpointConfig,
    ProcessMediationRequestedEndpointLayerConfig, RuntimeAuditConfig,
    RuntimeAuditSurfaceLoggingConfig, RuntimeConfig, SaaSAuditSurfaceLoggingConfig,
    SessionActorLayerConfig, SessionAdoptPlan, SessionAdoptTarget, SessionDiagnosticLayerConfig,
    SessionInterceptionBackendKind, SessionInterceptionCapabilityReport, SessionInterceptionConfig,
    SessionInterceptionLayerConfig, SessionInterceptionOperation,
    SessionInterceptionOperationCapability, SessionLayerConfig, SessionRunPlan,
    SessionRunnerConfig, SessionRunnerKind, SessionRunnerLayerConfig, SessionSurfaceKind,
    SessionSurfaceLayers, SessionSurfaceStartPlan, SessionSurfaceToggleConfig,
    TerminalAuditSurfaceLoggingConfig, TerminalProcessInterceptionConfig,
    TerminalProcessInterceptionLayerConfig, TerminalProcessInterceptionMode,
    TerminalProcessMediationConfig, TerminalProcessMediationLayerConfig,
    TerminalProcessMediationMode, TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, DurableAuditSink, EnforcementOutcome, LocalEnforcementEngine,
    NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError, SessionRegistryError, SessionSpecError};
pub use interception::{
    FileInterceptionOperationKind, FileInterceptionRequest, FileOperationSurfaceHandler,
    FileResolvedIdentity, ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
    SessionInterceptionDecision, SocketConnectInterceptionRequest, SocketConnectSurfaceHandler,
    SurfaceInterceptionDecision, SurfaceMediationDecision,
};
pub use runtime::{
    RunningSessionSurface, SessionSurfaceDefinition, SessionSurfaceFailure,
    SessionSurfaceFailureSender, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
    SessionSurfaceService, SessionSurfaceSupervisor,
};
pub use session::{
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal,
    ActiveSessionSignalKind, AgentAdapterDescriptor, AgentAdapterInvocationShape,
    DaemonFailureMode, DockerSessionRunner, EndpointProjection, EvidenceRequirement,
    FilesystemProjection, ImmutableIdentity, LinuxHostSessionRunner, OutputEndpoints, OutputPlan,
    PreparedFilesystemProjection,
    OutputStreamRequirements, RunRequest, RunnerBinding, RunnerCapabilityDocument, RunnerId,
    RunnerRecovery, SafePathBinding, SafePathKind, ScriptInterpreterBinding, SessionAdmission,
    SessionCapturedRunOutcome, SessionLifecycleState, SessionOwner, SessionRunOutcome,
    SessionRunnerLauncher, SessionSpec, WorkloadPrivilegePlan,
    AGENT_ADAPTER_DESCRIPTOR_SCHEMA_VERSION, RUNNER_CAPABILITY_SCHEMA_VERSION,
    RUNNER_RECOVERY_SCHEMA_VERSION, SESSION_SPEC_SCHEMA_VERSION,
};
pub use session_registry::{
    SessionContextArtifact, SessionRegistry, SessionRegistryFinish, SessionRegistryRecord,
    SessionRegistryStatus, StartedSessionRegistryRecord, DEFAULT_SESSION_REGISTRY_PATH,
};
