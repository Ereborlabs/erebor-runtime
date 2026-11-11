use super::ManagedBudget;
use crate::{PackageErrorCodeV1 as Code, Result};

mod admission;
pub(in crate::analysis) use admission::GraphDeclarations;
pub(in crate::analysis) mod domain;
mod proof;
mod provenance;
pub(in crate::analysis) use provenance::{FindingBasis, FindingOrigin};
