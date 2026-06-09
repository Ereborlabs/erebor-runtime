use std::io;

use erebor_runtime_policy::PolicyError;
use snafu::Location;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("runtime config is empty")]
    EmptyConfig { location: Location },
    #[error("runtime config JSON is invalid: {source}")]
    InvalidJson {
        source: serde_json::Error,
        location: Location,
    },
    #[error("runtime config must include at least one policy")]
    MissingPolicy { location: Location },
    #[error("runtime config policy paths cannot be empty")]
    EmptyPolicyPath { location: Location },
    #[error("runtime config audit jsonl path cannot be empty")]
    EmptyAuditJsonlPath { location: Location },
    #[error("runtime config session actor id cannot be empty")]
    EmptySessionActorId { location: Location },
    #[error("runtime config session workspace path cannot be empty")]
    EmptySessionWorkspace { location: Location },
    #[error("runtime config session diagnostic name cannot be empty")]
    EmptySessionDiagnosticName { location: Location },
    #[error("runtime config session diagnostic `{name}` is duplicated")]
    DuplicateSessionDiagnosticName { name: String, location: Location },
    #[error("runtime config session diagnostic `{name}` command cannot be empty")]
    EmptySessionDiagnosticCommand { name: String, location: Location },
    #[error("runtime config session diagnostic `{name}` was not found")]
    UnknownSessionDiagnostic { name: String, location: Location },
    #[error("runtime config Docker/OCI session runtime image cannot be empty")]
    EmptyDockerSessionImage { location: Location },
    #[error("runtime config Docker/OCI session runtime network cannot be empty")]
    EmptyDockerSessionNetwork { location: Location },
    #[error("session run command cannot be empty")]
    EmptySessionCommand { location: Location },
    #[error("runtime config must enable at least one governance layer or session runtime")]
    NoGovernanceLayers { location: Location },
    #[error("runtime config browser_cdp browser_url must start with ws://")]
    BrowserCdpInvalidBrowserUrl { location: Location },
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {source}")]
    Policy {
        source: PolicyError,
        location: Location,
    },
    #[error("failed to build async runtime: {source}")]
    BuildAsyncRuntime {
        source: io::Error,
        location: Location,
    },
    #[error("runtime start plan includes unsupported governance layer `{layer}`")]
    UnsupportedGovernanceLayer { layer: String, location: Location },
    #[error("runtime start plan did not include any governance runtimes")]
    NoGovernanceRuntimes { location: Location },
    #[error("failed to start governance runtime `{layer}`: {reason}")]
    RuntimeStart {
        layer: String,
        reason: String,
        location: Location,
    },
    #[error("governance runtime `{layer}` exited: {reason}")]
    RuntimeExited {
        layer: String,
        reason: String,
        location: Location,
    },
}

impl RuntimeConfigError {
    #[track_caller]
    pub fn empty_config() -> Self {
        Self::EmptyConfig {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_json(source: serde_json::Error) -> Self {
        Self::InvalidJson {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn missing_policy() -> Self {
        Self::MissingPolicy {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_policy_path() -> Self {
        Self::EmptyPolicyPath {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_audit_jsonl_path() -> Self {
        Self::EmptyAuditJsonlPath {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_actor_id() -> Self {
        Self::EmptySessionActorId {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_workspace() -> Self {
        Self::EmptySessionWorkspace {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_diagnostic_name() -> Self {
        Self::EmptySessionDiagnosticName {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn duplicate_session_diagnostic_name(name: impl Into<String>) -> Self {
        Self::DuplicateSessionDiagnosticName {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_diagnostic_command(name: impl Into<String>) -> Self {
        Self::EmptySessionDiagnosticCommand {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unknown_session_diagnostic(name: impl Into<String>) -> Self {
        Self::UnknownSessionDiagnostic {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_docker_session_image() -> Self {
        Self::EmptyDockerSessionImage {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_docker_session_network() -> Self {
        Self::EmptyDockerSessionNetwork {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_command() -> Self {
        Self::EmptySessionCommand {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn no_governance_layers() -> Self {
        Self::NoGovernanceLayers {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn browser_cdp_invalid_browser_url() -> Self {
        Self::BrowserCdpInvalidBrowserUrl {
            location: Location::default(),
        }
    }
}

impl RuntimeError {
    #[track_caller]
    pub fn policy(source: PolicyError) -> Self {
        Self::Policy {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn build_async_runtime(source: io::Error) -> Self {
        Self::BuildAsyncRuntime {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unsupported_governance_layer(layer: impl Into<String>) -> Self {
        Self::UnsupportedGovernanceLayer {
            layer: layer.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn no_governance_runtimes() -> Self {
        Self::NoGovernanceRuntimes {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn runtime_start(layer: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::RuntimeStart {
            layer: layer.into(),
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn runtime_exited(layer: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::RuntimeExited {
            layer: layer.into(),
            reason: reason.into(),
            location: Location::default(),
        }
    }
}
