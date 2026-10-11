use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1, GraphAndFindingOwner};
use crate::{AnalysisContractSnafu, GraphEncodingSnafu, GraphInvalidSnafu, Result};

impl GraphAndFindingOwner {
    pub fn supports_analysis(model: &sdk::Model) -> bool {
        let expected = araphor_analysis_builtins::graph::Detector::Process.descriptor();
        let expected = &expected.exports[0];
        model.inputs == expected.inputs
            && model.outputs == expected.outputs
            && model.checkpoint == expected.checkpoint
    }

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
    pub fn analysis_code(&self, package_id: &str) -> Result<String> {
        if let Self::Declared(reason) = self {
            reason.validate(package_id)?;
            return Ok(reason.code.clone());
        }
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
    pub(crate) fn label(&self) -> Result<String> {
        match self {
            Self::Declared(reason) => Ok(reason.code.clone()),
            _ => serde_json::to_value(self)
                .context(GraphEncodingSnafu)?
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "finding reason label",
                    }
                    .build()
                }),
        }
    }

    pub(crate) fn storage(&self) -> Result<String> {
        match self {
            Self::Declared(_) => serde_json::to_string(self).context(GraphEncodingSnafu),
            _ => self.label(),
        }
    }

    pub(crate) fn restore(value: &str) -> Result<Self> {
        if value.starts_with('{') {
            serde_json::from_str(value).context(GraphEncodingSnafu)
        } else {
            serde_json::from_value(serde_json::Value::String(value.into()))
                .context(GraphEncodingSnafu)
        }
    }

    pub(super) fn validate(&self, package: &str) -> Result<()> {
        match self {
            Self::Declared(reason) => reason.validate(package),
            _ => GraphAndFindingOwner::contract_id(package),
        }
    }
}

impl DeclaredFindingReasonV1 {
    pub(super) fn from_value(value: &sdk::ReasonValue, limits: sdk::Limits) -> Result<Self> {
        let schema = value.details.schema().as_ref().clone();
        let encoded = crate::PackageDatasetV1::encode(
            &sdk::Dataset {
                name: "details".into(),
                batches: vec![value.details.clone()],
            },
            &schema,
            limits,
        )?;
        Ok(Self {
            code: value.code.clone(),
            schema,
            ipc: encoded.ipc,
        })
    }

    fn validate(&self, package: &str) -> Result<()> {
        let local = self.code.strip_prefix(&format!("{package}."));
        if local.is_none_or(str::is_empty) || self.code.len() > 256 {
            return GraphInvalidSnafu {
                field: "finding reason namespace",
            }
            .fail();
        }
        let limits = sdk::Limits {
            max_rows: 1,
            max_batches: 1,
            max_bytes: super::GRAPH_WINDOW_BYTES as u64,
            ..sdk::Limits::default()
        };
        let data = crate::PackageDatasetV1 {
            name: "details".into(),
            ipc: self.ipc.clone(),
        }
        .decode(&self.schema, limits)?;
        if data.batches.len() != 1 || data.batches[0].num_rows() != 1 {
            return GraphInvalidSnafu {
                field: "finding reason details",
            }
            .fail();
        }
        sdk::Package::new(
            package,
            "1",
            vec![sdk::Model::new(
                "reason",
                Vec::new(),
                vec![sdk::Port::new("details", self.schema.clone())],
            )],
        )
        .validate()
        .context(AnalysisContractSnafu)
    }
}

#[cfg(test)]
mod tests;
