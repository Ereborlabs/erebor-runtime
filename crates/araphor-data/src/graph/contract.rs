use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
use crate::{AnalysisContractSnafu, GraphEncodingSnafu, GraphInvalidSnafu, Result};

#[cfg(test)]
mod tests;

impl FindingReasonV1 {
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

    pub fn analysis_code(&self, package_id: &str) -> Result<String> {
        if let Self::Declared(reason) = self {
            reason.validate(package_id)?;
            return Ok(reason.code.clone());
        }
        Self::contract_id(package_id)?;
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
        Self::contract_id(package_id)?;
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
    pub fn label(&self) -> Result<String> {
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

    pub fn storage(&self) -> Result<String> {
        match self {
            Self::Declared(_) => serde_json::to_string(self).context(GraphEncodingSnafu),
            _ => self.label(),
        }
    }

    pub fn restore(value: &str) -> Result<Self> {
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
            _ => Self::contract_id(package),
        }
    }
}

impl DeclaredFindingReasonV1 {
    pub fn from_value(value: &sdk::ReasonValue) -> Result<Self> {
        let schema = value.details.schema().as_ref().clone();
        let encoded = sdk::wire::Dataset::encode(
            &sdk::Dataset {
                name: "details".into(),
                batches: vec![value.details.clone()],
            },
            &schema,
        )
        .context(AnalysisContractSnafu)?;
        Ok(Self {
            code: value.code.clone(),
            schema,
            ipc: encoded.arrow_ipc,
        })
    }

    fn validate(&self, package: &str) -> Result<()> {
        let local = self.code.strip_prefix(&format!("{package}."));
        if local.is_none_or(str::is_empty) {
            return GraphInvalidSnafu {
                field: "finding reason namespace",
            }
            .fail();
        }
        let data = sdk::wire::Dataset::decode_ipc("details", &self.ipc, Some(&self.schema))
            .context(AnalysisContractSnafu)?;
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
