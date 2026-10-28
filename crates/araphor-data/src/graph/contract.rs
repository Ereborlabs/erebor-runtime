use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
use crate::{AnalysisContractSnafu, GraphEncodingSnafu, GraphInvalidSnafu, Result};

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

pub(crate) fn label(reason: &FindingReasonV1) -> Result<String> {
    match reason.label() {
        Ok(value) => Ok(value),
        Err(sdk::Error::Encoding { source, .. }) => Err(source).context(GraphEncodingSnafu),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Invalid,
            field,
            ..
        }) if field == "finding reason label" => GraphInvalidSnafu {
            field: "finding reason label",
        }
        .fail(),
        Err(source) => Err(source).context(AnalysisContractSnafu),
    }
}

pub(crate) fn storage(reason: &FindingReasonV1) -> Result<String> {
    match reason {
        FindingReasonV1::Declared(_) => serde_json::to_string(reason).context(GraphEncodingSnafu),
        _ => label(reason),
    }
}

pub(crate) fn restore(value: &str) -> Result<FindingReasonV1> {
    if value.starts_with('{') {
        serde_json::from_str(value).context(GraphEncodingSnafu)
    } else {
        serde_json::from_value(serde_json::Value::String(value.into())).context(GraphEncodingSnafu)
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
