use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("failed to open audit log `{}`: {source}", path.display())]
    Open { path: PathBuf, source: io::Error },
    #[error("failed to read audit log `{}`: {source}", path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to write audit log `{}`: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to serialize audit record for `{}`: {source}", path.display())]
    SerializeRecord {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid audit record in `{}` at line {line}: {source}", path.display())]
    InvalidRecord {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },
}
