mod compile;
mod definition;
mod error;

pub use definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};
pub use error::{Error, Result};

#[cfg(test)]
mod tests;
