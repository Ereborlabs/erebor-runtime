use std::sync::OnceLock;

use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use serde::Serialize;

use crate::Rows;

mod atoms;
mod compare;
mod groups;
mod merge;
mod model;
mod ranges;
mod record;
mod source;
pub mod sql;
#[cfg(test)]
mod tests;

pub use model::*;
pub use source::*;

pub struct Discovery;

impl Discovery {
    pub fn package() -> sdk::Package {
        Self::declaration().clone()
    }

    fn declaration() -> &'static sdk::Package {
        static PACKAGE: OnceLock<sdk::Package> = OnceLock::new();
        PACKAGE.get_or_init(Self::build_package)
    }

    fn build_package() -> sdk::Package {
        let result = vec![
            Self::port::<BehaviorAtomV1>("atoms"),
            Self::port::<DiscoveryCoverageV1>("coverage"),
            Self::port::<DiscoveryUnresolvedV1>("unresolved"),
            Self::port::<DiscoveryUnresolvedV1>("excluded"),
            Self::port::<DiscoveryLifecycleEntryV1>("lifecycle"),
            Self::port::<Counts>("counts"),
        ];
        sdk::Package::new(
            "discovery",
            "1",
            vec![
                sdk::Model::new(
                    "atoms",
                    vec![
                        Record::port(),
                        Self::port::<Context>("contexts"),
                        Self::port::<DiscoveryUnresolvedV1>("exclusions"),
                        Self::port::<DiscoveryCoverageV1>("coverage"),
                        Self::port::<DiscoveryLifecycleEntryV1>("lifecycle"),
                        Self::port::<bool>("observed"),
                    ],
                    result.clone(),
                ),
                sdk::Model::new(
                    "merge",
                    vec![
                        Self::port::<Snapshot>("snapshots"),
                        Self::port::<Side<BehaviorAtomV1>>("atoms"),
                        Self::port::<Side<DiscoveryCoverageV1>>("coverage"),
                        Self::port::<Side<DiscoveryUnresolvedV1>>("unresolved"),
                        Self::port::<Side<DiscoveryUnresolvedV1>>("excluded"),
                        Self::port::<Side<DiscoveryLifecycleEntryV1>>("lifecycle"),
                    ],
                    result,
                ),
                sdk::Model::new(
                    "groups",
                    vec![
                        Self::port::<BehaviorAtomV1>("atoms"),
                        Self::port::<DiscoveryCoverageV1>("coverage"),
                    ],
                    vec![Self::port::<BehaviorDisplayGroupV1>("groups")],
                ),
                sdk::Model::new(
                    "compare",
                    vec![
                        Self::port::<Side<BehaviorDisplayGroupV1>>("groups"),
                        Self::port::<Side<BehaviorAtomKeyV1>>("resources"),
                        Self::port::<DiscoveryPolicyKeyV1>("forbidden"),
                        Self::port::<MatchState>("states"),
                    ],
                    vec![Self::port::<DiscoveryComparisonV1>("comparison")],
                ),
            ],
        )
    }

    pub fn evaluate(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Self::declaration()
            .check_evaluation(input)?
            .evaluate(<Self as sdk::Guest>::compute)
    }

    pub fn port<T: JsonSchema>(name: &str) -> sdk::Port {
        Rows::port::<T>(name, &format!("discovery.{}.v1", T::schema_name()))
    }

    fn write<T: Serialize>(
        input: &sdk::CheckedEvaluation<'_>,
        name: &str,
        rows: &[T],
    ) -> sdk::Result<sdk::Dataset> {
        let port = input
            .model()
            .outputs
            .iter()
            .find(|port| port.name == name)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "row port"))?;
        Rows::encode(port, rows)
    }

    fn require(valid: bool, field: &'static str) -> sdk::Result<()> {
        if valid {
            Ok(())
        } else {
            Err(sdk::Error::contract(sdk::ErrorCode::Invalid, field))
        }
    }

    fn same(valid: bool, field: &'static str) -> sdk::Result<()> {
        if valid {
            Ok(())
        } else {
            Err(sdk::Error::contract(sdk::ErrorCode::Incompatible, field))
        }
    }

    fn add(count: &mut u64, value: u64) -> sdk::Result<()> {
        *count = count
            .checked_add(value)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "count"))?;
        Ok(())
    }
}

impl sdk::Guest for Discovery {
    fn package() -> sdk::Package {
        Self::package()
    }

    fn compute(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        if input.package() != Self::declaration() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "discovery package",
            ));
        }
        match input.evaluation().export.as_str() {
            "atoms" => Self::atoms(input),
            "merge" => Self::merge(input),
            "groups" => Self::groups(input),
            "compare" => Self::compare(input),
            _ => Err(sdk::Error::contract(sdk::ErrorCode::Incompatible, "export")),
        }
    }
}
