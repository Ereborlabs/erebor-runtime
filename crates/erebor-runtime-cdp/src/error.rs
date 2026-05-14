use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CdpError {
    #[error("CDP method is missing")]
    MissingMethod,
    #[error("CDP message is invalid JSON: {0}")]
    InvalidJson(String),
    #[error("CDP message id is required for governed commands")]
    MissingMessageId,
    #[error("unsupported governed CDP method `{0}`")]
    UnsupportedMethod(String),
    #[error("runtime enforcement failed: {0}")]
    Enforcement(String),
}
