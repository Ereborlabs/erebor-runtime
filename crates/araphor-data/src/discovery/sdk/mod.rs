use std::collections::BTreeMap;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;

use super::super::*;
use crate::{AnalysisContractSnafu, DiscoveryEncodingSnafu, Result};

mod atoms;
mod compare;
mod context;
mod project;
mod snapshot;

struct Adapter {
    identities: BTreeMap<DiscoveryRecordIdV1, u64>,
}

impl Adapter {
    fn at<'a, T>(rows: &'a [T], index: u64, field: &'static str) -> Result<&'a T> {
        usize::try_from(index)
            .ok()
            .and_then(|index| rows.get(index))
            .ok_or_else(|| crate::DiscoveryInvalidSnafu { field }.build())
    }
    fn new<'a>(records: impl IntoIterator<Item = &'a DiscoveryRecordIdV1>) -> Self {
        let mut identities: BTreeMap<_, _> =
            records.into_iter().map(|id| (id.clone(), 0)).collect();
        for (index, (_, rank)) in identities.iter_mut().enumerate() {
            *rank = index as u64;
        }
        Self { identities }
    }

    fn identity(&self, id: &DiscoveryRecordIdV1) -> Result<builtin::Identity> {
        let order = self.identities.get(id).copied().ok_or_else(|| {
            crate::DiscoveryInvalidSnafu {
                field: "analysis identity",
            }
            .build()
        })?;
        Ok(builtin::Identity {
            order,
            value: Self::json(id)?,
        })
    }

    fn record(&self, id: builtin::Identity) -> Result<DiscoveryRecordIdV1> {
        let value: DiscoveryRecordIdV1 = Self::decode(&id.value)?;
        crate::discovery::model::require(
            self.identities.get(&value).copied() == Some(id.order),
            "analysis record reference",
        )?;
        Ok(value)
    }

    fn json(value: &impl Serialize) -> Result<String> {
        serde_json::to_string(value).context(DiscoveryEncodingSnafu)
    }

    fn revision(value: &impl Serialize) -> Result<String> {
        crate::digest::InputRevision::of(value).context(DiscoveryEncodingSnafu)
    }

    fn decode<T: DeserializeOwned>(bytes: &str) -> Result<T> {
        serde_json::from_str(bytes).context(DiscoveryEncodingSnafu)
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

    fn run(export: &str, datasets: Vec<sdk::Dataset>, revision: String) -> Result<sdk::Output> {
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
        builtin::Discovery::evaluate(&input).map_err(Self::error)
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
                        return crate::DiscoveryConflictSnafu { kind }.build();
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
                        return crate::DiscoveryInvalidSnafu { field: field_name }.build();
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
