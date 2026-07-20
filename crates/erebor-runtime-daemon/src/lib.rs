//! Privileged local daemon control service for Erebor.

mod config;
mod control;
mod error;
mod idempotency;
mod log;
mod path_broker;
mod paths;
mod session_control;

pub use control::DaemonControlService;
pub use error::{DaemonError, Result};
#[doc(hidden)]
pub use path_broker::run_path_broker;
pub use paths::DaemonPaths;

#[cfg(test)]
mod tests;
