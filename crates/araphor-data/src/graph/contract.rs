use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{FindingReasonV1, FindingV1, GraphAndFindingOwner};
use crate::{AnalysisContractSnafu, GraphEncodingSnafu, GraphInvalidSnafu, Result};

impl GraphAndFindingOwner {
    pub fn analysis_package(package_id: &str) -> Result<sdk::Package> {
        Self::contract_id(package_id)?;
        let package = araphor_analysis_builtins::graph::Detector::from_id(package_id)
            .context(AnalysisContractSnafu)?
            .descriptor();
        package.validate().context(AnalysisContractSnafu)?;
        Ok(package)
    }

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
}

impl FindingReasonV1 {
    pub fn analysis_code(self, package_id: &str) -> Result<String> {
        GraphAndFindingOwner::contract_id(package_id)?;
        let value = serde_json::to_value(self).context(GraphEncodingSnafu)?;
        let code = value.as_str().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "analysis reason spelling",
            }
            .build()
        })?;
        Ok(format!("{package_id}.{code}"))
    }

    pub fn from_analysis_code(package_id: &str, code: &str) -> Result<Self> {
        GraphAndFindingOwner::contract_id(package_id)?;
        let local = code
            .strip_prefix(&format!("{package_id}."))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "analysis reason namespace",
                }
                .build()
            })?;
        serde_json::from_value(serde_json::Value::String(local.into())).map_err(|_| {
            GraphInvalidSnafu {
                field: "analysis reason code",
            }
            .build()
        })
    }
}

#[cfg(test)]
mod tests;
