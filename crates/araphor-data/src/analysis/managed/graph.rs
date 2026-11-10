
use crate::{PackageErrorCodeV1 as Code, Result};
use super::ManagedBudget;

mod admission;
pub(in crate::analysis) mod domain;
mod proof;
mod provenance;
pub(in crate::analysis) use provenance::{FindingBasis, FindingOrigin};
