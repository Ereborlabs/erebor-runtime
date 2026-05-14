use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CdpError {
    #[error("CDP method is missing")]
    MissingMethod,
    #[error("unsupported governed CDP method `{0}`")]
    UnsupportedMethod(String),
}
