use std::io;

use erebor_runtime_policy::PolicyError;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeConfigError {
    #[error("runtime config is empty")]
    EmptyConfig,
    #[error("runtime config JSON is invalid: {reason}")]
    InvalidJson { reason: String },
    #[error("runtime config must include at least one policy")]
    MissingPolicy,
    #[error("runtime config policy paths cannot be empty")]
    EmptyPolicyPath,
    #[error("runtime config must enable at least one governance layer")]
    NoGovernanceLayers,
    #[error("runtime config browser_cdp requires browser_url when enabled")]
    BrowserCdpMissingBrowserUrl,
    #[error("runtime config browser_cdp browser_url must start with ws://")]
    BrowserCdpInvalidBrowserUrl,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
    #[error("failed to build async runtime: {source}")]
    BuildAsyncRuntime { source: io::Error },
    #[error("runtime start plan includes unsupported governance layer `{layer}`")]
    UnsupportedGovernanceLayer { layer: String },
    #[error("runtime start plan did not include any governance runtimes")]
    NoGovernanceRuntimes,
    #[error("failed to start governance runtime `{layer}`: {reason}")]
    RuntimeStart { layer: String, reason: String },
    #[error("governance runtime `{layer}` exited: {reason}")]
    RuntimeExited { layer: String, reason: String },
}
