//! Privileged local daemon control service for Erebor.

mod approvals;
mod config;
mod context_dag;
mod control;
mod error;
mod idempotency;
mod local_store;
mod log;
mod path_broker;
mod paths;
mod session_api;

pub use control::DaemonControlService;
pub use error::{DaemonError, Result};
#[doc(hidden)]
pub use path_broker::run_path_broker;
pub use paths::DaemonPaths;

#[cfg(test)]
mod tests;
