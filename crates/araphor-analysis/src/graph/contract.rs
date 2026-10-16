use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::*;
use crate::{AnalysisContractSnafu, GraphInvalidSnafu};

impl GraphAndFindingOwner {
    pub fn supports_analysis(model: &sdk::Model) -> bool {
        let expected = araphor_analysis_builtins::graph::Detector::Process.descriptor();
        let expected = &expected.exports[0];
        model
            .inputs
            .iter()
            .map(|input| &input.port)
            .eq(expected.inputs.iter().map(|input| &input.port))
            && model.outputs == expected.outputs
            && model.checkpoint == expected.checkpoint
    }

    pub fn analysis_package(package_id: &str) -> Result<sdk::Package> {
        if !FindingV1::PACKAGES.contains(&package_id) {
            return GraphInvalidSnafu {
                field: "analysis package identity",
            }
            .fail()
            .map_err(Into::into);
        }
        let package = araphor_analysis_builtins::graph::Detector::from_id(package_id)
            .context(AnalysisContractSnafu)?
            .descriptor();
        package.validate().context(AnalysisContractSnafu)?;
        Ok(package)
    }
}

#[cfg(test)]
mod tests;
