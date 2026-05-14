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
    #[error("runtime config must enable at least one governance layer")]
    NoGovernanceLayers,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
}
