use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use super::constants::RUNTIME_INTERCEPTION_PROTOCOL;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInterceptionEndpoint {
    transport: String,
    path: PathBuf,
    token: String,
    timeout_ms: u64,
}

impl RuntimeInterceptionEndpoint {
    #[must_use]
    pub fn unix(path: impl Into<PathBuf>, token: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            transport: String::from("unix"),
            path: path.into(),
            token: token.into(),
            timeout_ms,
        }
    }

    #[must_use]
    pub fn with_path(&self, path: impl Into<PathBuf>) -> Self {
        Self {
            transport: self.transport.clone(),
            path: path.into(),
            token: self.token.clone(),
            timeout_ms: self.timeout_ms,
        }
    }

    #[must_use]
    pub fn with_timeout_ms(&self, timeout_ms: u64) -> Self {
        Self {
            transport: self.transport.clone(),
            path: self.path.clone(),
            token: self.token.clone(),
            timeout_ms,
        }
    }

    #[must_use]
    pub fn environment(&self) -> Vec<(String, String)> {
        vec![
            (
                String::from("EREBOR_RUNTIME_INTERCEPTION_PROTOCOL"),
                String::from(RUNTIME_INTERCEPTION_PROTOCOL),
            ),
            (
                String::from("EREBOR_RUNTIME_INTERCEPTION_TRANSPORT"),
                self.transport.clone(),
            ),
            (
                String::from("EREBOR_RUNTIME_INTERCEPTION_PATH"),
                self.path.display().to_string(),
            ),
            (
                String::from("EREBOR_RUNTIME_INTERCEPTION_TOKEN"),
                self.token.clone(),
            ),
            (
                String::from("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS"),
                self.timeout_ms.to_string(),
            ),
        ]
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}
