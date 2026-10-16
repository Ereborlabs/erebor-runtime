use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;

#[cfg(test)]
use super::super::*;
use crate::{AnalysisContractSnafu, DiscoveryEncodingSnafu, Result};

mod atoms;
mod compare;
mod context;
#[cfg(test)]
mod native;
mod pages;
mod snapshot;
mod validation;

struct Adapter;

impl Adapter {
    fn json(value: &impl Serialize) -> Result<String> {
        Ok(serde_json::to_string(value).context(DiscoveryEncodingSnafu)?)
    }

    fn revision(value: &impl Serialize) -> Result<String> {
        Ok(araphor_data::InputRevision::of(value).context(DiscoveryEncodingSnafu)?)
    }

    fn decode<T: DeserializeOwned>(bytes: &str) -> Result<T> {
        Ok(serde_json::from_str(bytes).context(DiscoveryEncodingSnafu)?)
    }

    fn dataset<T: Serialize + JsonSchema>(name: &str, rows: &[T]) -> Result<sdk::Dataset> {
        Rows::encode(
            &builtin::Discovery::port::<T>(name),
            rows,
            builtin::Discovery::limits(),
        )
        .context(AnalysisContractSnafu)
    }

    fn output<T: DeserializeOwned + JsonSchema>(
        output: &sdk::Output,
        name: &str,
    ) -> Result<Vec<T>> {
        let dataset = output
            .datasets
            .iter()
            .find(|data| data.name == name)
            .ok_or_else(|| {
                crate::DiscoveryInvalidSnafu {
                    field: "analysis output",
                }
                .build()
            })?;
        Rows::decode(
            &builtin::Discovery::port::<T>(name),
            dataset,
            builtin::Discovery::limits(),
        )
        .context(AnalysisContractSnafu)
    }

    fn run(
        execution: &crate::InstalledAnalysis,
        tenant: [u8; 16],
        export: &str,
        datasets: Vec<sdk::Dataset>,
        revision: String,
    ) -> Result<crate::InstalledEvaluation> {
        Self::run_control(
            execution,
            tenant,
            export,
            datasets,
            revision,
            &crate::AnalysisReadControl::with_timeout(std::time::Duration::from_secs(60))?,
        )
    }

    fn run_control(
        execution: &crate::InstalledAnalysis,
        tenant: [u8; 16],
        export: &str,
        datasets: Vec<sdk::Dataset>,
        revision: String,
        control: &crate::AnalysisReadControl,
    ) -> Result<crate::InstalledEvaluation> {
        control.check()?;
        let input = sdk::Evaluation {
            export: export.into(),
            inputs: datasets
                .into_iter()
                .map(|data| sdk::Input {
                    revision: sdk::Revision {
                        owner: "discovery".into(),
                        id: revision.clone(),
                        window: None,
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Unknown,
                        limits: vec!["HOST_VALIDATED_COVERAGE_ROWS".into()],
                    },
                    data,
                })
                .collect(),
            parameters: None,
            context: sdk::EvaluationContext {
                id: revision,
                time_utc_ns: 0,
                seed: None,
                limits: builtin::Discovery::limits(),
            },
            checkpoint: None,
        };
        execution
            .evaluate(tenant, &builtin::Discovery::package().id, &input, control)
            .map_err(|error| match error {
                crate::Error::AnalysisContract { source, .. } => Self::error(source),
                error => error,
            })
    }

    fn error(source: sdk::Error) -> crate::Error {
        if let sdk::Error::Contract { code, field, .. } = &source {
            if *code == sdk::ErrorCode::Incompatible {
                for kind in [
                    "record bytes",
                    "context values",
                    "exclusion reason",
                    "snapshot source",
                    "snapshot overlap",
                    "lifecycle state",
                ] {
                    if field == kind {
                        return crate::DiscoveryConflictSnafu { kind }.build().into();
                    }
                }
            }
            if *code == sdk::ErrorCode::Invalid {
                for field_name in [
                    "orphan context",
                    "orphan exclusion",
                    "record range",
                    "atom key",
                    "atom count",
                    "count",
                    "lifecycle records",
                ] {
                    if field == field_name {
                        return crate::DiscoveryInvalidSnafu { field: field_name }
                            .build()
                            .into();
                    }
                }
            }
        }
        crate::Error::AnalysisContract {
            source,
            location: snafu::location!(),
        }
    }
}
