mod bindings;
mod descriptor;
mod error;
mod evaluation;
mod fixture;
mod model;
mod validation;

pub use arrow_array;
pub use arrow_array::RecordBatch;
pub use arrow_schema::{DataType, Field, Schema, TimeUnit};
pub use bindings::InterfaceDeclarations;
pub use error::{Error, ErrorCode, Result};
pub use evaluation::*;
pub use fixture::{Fixture, FixtureReport};
pub use model::*;

pub(crate) use error::*;

#[cfg(test)]
mod tests;
extern crate self as araphor_analysis_sdk;
