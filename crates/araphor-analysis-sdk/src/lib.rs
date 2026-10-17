mod batch;
mod bindings;
mod descriptor;
mod error;
mod evaluation;
mod fixture;
mod memory;
mod model;
mod validation;
pub mod wire;

#[cfg(all(feature = "oci", not(target_arch = "wasm32")))]
pub mod oci;

#[cfg(feature = "guest")]
pub mod guest;

#[cfg(feature = "native")]
#[allow(unsafe_code)]
pub mod native;

pub use arrow_array;
pub use arrow_array::RecordBatch;
pub use arrow_schema::{DataType, Field, Schema, TimeUnit};
pub use bindings::InterfaceDeclarations;
pub use error::{Error, ErrorCode, Result};
pub use evaluation::*;
pub use fixture::{Fixture, FixtureReport};
pub use model::*;
pub use validation::{CheckedEvaluation, Guest};

pub(crate) use error::*;

#[cfg(test)]
mod tests;
extern crate self as araphor_analysis_sdk;
