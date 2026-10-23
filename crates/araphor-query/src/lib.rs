//! SQL parsing, planning, and execution through DataFusion.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod definition;
mod error;
pub mod execution;
pub mod follow;
pub mod inputs;
pub mod memory;
pub mod parser;
pub mod planner;
pub mod sources;
mod stream;

pub use araphor_data::AnalysisTableRequests;
pub use araphor_package_runtime::Error as PackageRuntimeError;
pub use datafusion;
pub(crate) use error::*;
pub use error::{Error, Failure, Result};
