use std::path::{Path, PathBuf};

use clap::ValueEnum;
use erebor_runtime_audit::SessionReviewOutputFormat;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebSocketUrl(String);

impl WebSocketUrl {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl From<OutputFormat> for SessionReviewOutputFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Text => Self::Text,
            OutputFormat::Json => Self::Json,
        }
    }
}

pub(crate) fn parse_ws_url(value: &str) -> Result<WebSocketUrl, String> {
    if value.starts_with("ws://") {
        Ok(WebSocketUrl(value.to_owned()))
    } else {
        Err(String::from("must start with ws://"))
    }
}

pub(crate) fn parse_non_empty_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() {
        Err(String::from("path cannot be empty"))
    } else {
        Ok(path.to_path_buf())
    }
}

pub(crate) fn parse_non_empty_string(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(String::from("value cannot be empty"))
    } else {
        Ok(value.to_owned())
    }
}
