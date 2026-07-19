//! Privileged local daemon control service for Erebor.

mod config;
mod control;
mod error;
mod idempotency;
mod log;
mod paths;

pub use control::DaemonControlService;
pub use error::{DaemonError, Result};
pub use paths::DaemonPaths;

#[cfg(test)]
mod tests;
