mod audit;
mod runner;
mod runtime;
mod session;
mod surfaces;

#[cfg(test)]
pub(in crate::config) mod test_prelude;

pub use audit::{
    AuditCommandLogLevel, BrowserCdpAuditSurfaceLoggingConfig, DesktopAuditSurfaceLoggingConfig,
    FilesystemAuditSurfaceLoggingConfig, InternalSystemAuditSurfaceLoggingConfig,
    McpAuditSurfaceLoggingConfig, NetworkAuditSurfaceLoggingConfig, RuntimeAuditConfig,
    RuntimeAuditSurfaceLoggingConfig, SaaSAuditSurfaceLoggingConfig,
    TerminalAuditSurfaceLoggingConfig,
};
pub use runner::{
    DockerSessionCommandOptions, DockerSessionCommandPlan, DockerSessionMount,
    DockerSessionRunnerConfig, DockerSessionRunnerLayerConfig, LinuxHostSessionCommandOptions,
    LinuxHostSessionCommandPlan, LinuxHostSessionRunnerConfig, LinuxHostSessionRunnerLayerConfig,
    SessionRunnerConfig, SessionRunnerKind, SessionRunnerLayerConfig,
};
pub use runtime::RuntimeConfig;
pub use session::{
    SessionActorLayerConfig, SessionDiagnosticLayerConfig, SessionInterceptionBackendKind,
    SessionInterceptionCapabilityReport, SessionInterceptionConfig, SessionInterceptionLayerConfig,
    SessionInterceptionOperation, SessionInterceptionOperationCapability, SessionLayerConfig,
};
pub use session::{SessionAdoptPlan, SessionAdoptTarget, SessionRunPlan};
pub use surfaces::{
    BrowserCdpSurfaceConfig, BrowserCdpSurfaceLayerConfig, BrowserLaunchConfig,
    BrowserLaunchLayerConfig, FilesystemBackendConfig, FilesystemBackendKind,
    FilesystemBackendLayerConfig, FilesystemPreimageBackendKind, FilesystemRevertConfig,
    FilesystemRevertLayerConfig, FilesystemSessionWorkAutocommitConfig,
    FilesystemSessionWorkAutocommitLayerConfig, FilesystemSessionWorkAutocommitRuleConfig,
    FilesystemSessionWorkAutocommitRuleLayerConfig, FilesystemSurfaceConfig,
    FilesystemSurfaceLayerConfig, FilesystemVolumeConfig, FilesystemVolumeLayerConfig,
    FilesystemVolumeMode, PolicyPathValidator, ProcessInterceptionDecision,
    ProcessInterceptionHandlerConfig, ProcessInterceptionHandlerKind,
    ProcessMediationCompatibilityConfig, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEndpointSource, ProcessMediationEnvironmentConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerConfig,
    ProcessMediationHandlerKind, ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationPrivateEndpointConfig,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementConfig, ProcessMediationReplacementLayerConfig,
    ProcessMediationReplacementSurface, ProcessMediationRequestedEndpointConfig,
    ProcessMediationRequestedEndpointLayerConfig, SessionSurfaceKind, SessionSurfaceLayers,
    SessionSurfaceStartPlan, SessionSurfaceToggleConfig, TerminalProcessInterceptionConfig,
    TerminalProcessInterceptionLayerConfig, TerminalProcessInterceptionMode,
    TerminalProcessMediationConfig, TerminalProcessMediationLayerConfig,
    TerminalProcessMediationMode, TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
};
