use erebor_runtime_policy::PolicyError;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
}
