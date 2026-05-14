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
    #[error("runtime config must enable at least one governance layer")]
    NoGovernanceLayers { location: Location },
    #[error("runtime config browser_cdp requires browser_url when enabled")]
    BrowserCdpMissingBrowserUrl { location: Location },
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
    pub fn no_governance_layers() -> Self {
        Self::NoGovernanceLayers {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn browser_cdp_missing_browser_url() -> Self {
        Self::BrowserCdpMissingBrowserUrl {
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
