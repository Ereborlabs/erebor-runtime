//! Shared Araphor capture contracts and owners.

mod capture;
mod dispatch;
mod error;
mod model;
mod owner;
mod recipe;
mod target;

pub use araphor_data::{
    ContainerKindV1, DiscoveryDigestV1, KubernetesWorkloadIdentityV1, WorkloadTargetFactV1,
};
pub use capture::*;
pub use dispatch::*;
pub use error::{Error, Result};
pub use model::*;
pub use owner::*;
pub use recipe::*;
pub use target::*;

#[cfg(any(test, feature = "test-support"))]
pub use owner::test_support;
