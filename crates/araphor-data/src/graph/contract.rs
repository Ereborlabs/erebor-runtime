use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
use crate::{AnalysisContractSnafu, GraphInvalidSnafu, Result};

#[cfg(test)]
mod tests;

fn contract_id(package_id: &str) -> Result<()> {
    if FindingV1::PACKAGES.contains(&package_id) {
        Ok(())
    } else {
        GraphInvalidSnafu {
            field: "analysis package identity",
        }
        .fail()
    }
}

pub(crate) fn validate(reason: &FindingReasonV1, package: &str) -> Result<()> {
    match reason {
        FindingReasonV1::Declared(reason) => validate_declared(reason, package),
        _ => contract_id(package),
    }
}
fn validate_declared(reason: &DeclaredFindingReasonV1, package: &str) -> Result<()> {
    match reason.validate(package) {
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Invalid,
            field,
            ..
        }) if field == "finding reason namespace" => GraphInvalidSnafu {
            field: "finding reason namespace",
        }
        .fail(),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Invalid,
            field,
            ..
        }) if field == "finding reason details" => GraphInvalidSnafu {
            field: "finding reason details",
        }
        .fail(),
        result => result.context(AnalysisContractSnafu),
    }
}
