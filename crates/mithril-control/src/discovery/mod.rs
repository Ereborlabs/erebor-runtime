mod context;
mod index;
mod investigation;
mod live;
mod model;
mod recorded;
mod runtime;

pub use context::*;
pub use index::*;
pub use investigation::*;
pub use live::*;
pub(crate) use model::InputByteLimit;
pub use model::*;
pub use recorded::DiscoveryOwner;
pub use runtime::DiscoveryRuntimeConfigV1;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn test_crash_boundary(boundary: &str) {
    if std::env::var("ARAPHOR_TEST_DERIVATION_KILL").as_deref() == Ok(boundary) {
        std::process::exit(73);
    }
}
