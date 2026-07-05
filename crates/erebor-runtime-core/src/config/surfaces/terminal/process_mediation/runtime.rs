use super::{
    ProcessInterceptionDecision, ProcessMediationCompatibilityConfig,
    ProcessMediationEnvironmentConfig, ProcessMediationHandlerKind,
    ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationReplacementConfig, ProcessMediationRequestedEndpointConfig,
    TerminalProcessMediationLayerConfig, TerminalProcessMediationMode,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalProcessMediationConfig {
    enabled: bool,
    mode: TerminalProcessMediationMode,
    handlers: Vec<ProcessMediationHandlerConfig>,
}

impl TerminalProcessMediationConfig {
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn mode(&self) -> TerminalProcessMediationMode {
        self.mode
    }

    #[must_use]
    pub fn handlers(&self) -> &[ProcessMediationHandlerConfig] {
        &self.handlers
    }
}

impl From<TerminalProcessMediationLayerConfig> for TerminalProcessMediationConfig {
    fn from(config: TerminalProcessMediationLayerConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode,
            handlers: config.handlers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationHandlerConfig {
    id: String,
    kind: ProcessMediationHandlerKind,
    matcher: ProcessMediationMatcherConfig,
    requested_endpoint: ProcessMediationRequestedEndpointConfig,
    replacement: ProcessMediationReplacementConfig,
    environment: ProcessMediationEnvironmentConfig,
    compatibility: ProcessMediationCompatibilityConfig,
    decision: ProcessInterceptionDecision,
}

impl ProcessMediationHandlerConfig {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessMediationHandlerKind {
        self.kind
    }

    #[must_use]
    pub const fn decision(&self) -> ProcessInterceptionDecision {
        self.decision
    }

    #[must_use]
    pub const fn matcher(&self) -> &ProcessMediationMatcherConfig {
        &self.matcher
    }

    #[must_use]
    pub const fn requested_endpoint(&self) -> &ProcessMediationRequestedEndpointConfig {
        &self.requested_endpoint
    }

    #[must_use]
    pub const fn replacement(&self) -> &ProcessMediationReplacementConfig {
        &self.replacement
    }

    #[must_use]
    pub const fn environment(&self) -> &ProcessMediationEnvironmentConfig {
        &self.environment
    }

    #[must_use]
    pub const fn compatibility(&self) -> &ProcessMediationCompatibilityConfig {
        &self.compatibility
    }
}

impl From<ProcessMediationHandlerLayerConfig> for ProcessMediationHandlerConfig {
    fn from(config: ProcessMediationHandlerLayerConfig) -> Self {
        Self {
            id: config.id,
            decision: config.decision,
            kind: config.kind,
            matcher: config.matcher.into(),
            requested_endpoint: config.requested_endpoint.into(),
            replacement: config.replacement.into(),
            environment: config.environment.into(),
            compatibility: config.compatibility.into(),
        }
    }
}
