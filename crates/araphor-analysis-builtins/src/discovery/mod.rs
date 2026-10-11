use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};

use crate::Rows;

mod atoms;
mod compare;
mod groups;
mod merge;
mod model;
mod ranges;
#[cfg(test)]
mod tests;

pub use model::*;

pub struct Discovery;

impl Discovery {
    pub fn package() -> sdk::Package {
        let result = vec![
            Self::port::<Atom>("atoms"),
            Self::port::<Coverage>("coverage"),
            Self::port::<Disposition>("unresolved"),
            Self::port::<Disposition>("excluded"),
            Self::port::<Lifecycle>("lifecycle"),
            Self::port::<Counts>("counts"),
        ];
        let mut package = sdk::Package::new(
            "discovery",
            "1",
            vec![
                sdk::Model::new(
                    "atoms",
                    vec![
                        Self::port::<Record>("records"),
                        Self::port::<Context>("contexts"),
                        Self::port::<Disposition>("exclusions"),
                        Self::port::<Coverage>("coverage"),
                        Self::port::<Lifecycle>("lifecycle"),
                        Self::port::<bool>("observed"),
                    ],
                    result.clone(),
                ),
                sdk::Model::new(
                    "merge",
                    vec![
                        Self::port::<Snapshot>("snapshots"),
                        Self::port::<Side<Atom>>("atoms"),
                        Self::port::<Side<Coverage>>("coverage"),
                        Self::port::<Side<Disposition>>("unresolved"),
                        Self::port::<Side<Disposition>>("excluded"),
                        Self::port::<Side<Lifecycle>>("lifecycle"),
                    ],
                    result,
                ),
                sdk::Model::new(
                    "groups",
                    vec![
                        Self::port::<GroupAtom>("atoms"),
                        Self::port::<Coverage>("coverage"),
                    ],
                    vec![Self::port::<Group>("groups")],
                ),
                sdk::Model::new(
                    "compare",
                    vec![
                        Self::port::<MatchGroup>("groups"),
                        Self::port::<Side<String>>("resources"),
                        Self::port::<String>("forbidden"),
                        Self::port::<MatchState>("states"),
                    ],
                    vec![Self::port::<Comparison>("comparison")],
                ),
            ],
        );
        for model in &mut package.exports {
            model.limits = Self::limits();
        }
        package
    }

    pub fn limits() -> sdk::Limits {
        sdk::Limits {
            max_batches: 1024,
            max_rows: 4_000_000,
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_checkpoint_bytes: 16 * 1024 * 1024,
        }
    }

    pub fn evaluate(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let package = Self::package();
        package.validate_evaluation(input)?;
        let output = match input.export.as_str() {
            "atoms" => Self::atoms(input),
            "merge" => Self::merge(input),
            "groups" => Self::groups(input),
            "compare" => Self::compare(input),
            _ => Err(sdk::Error::contract(sdk::ErrorCode::Incompatible, "export")),
        }?;
        package.validate_output(input, &output)?;
        Ok(output)
    }

    pub fn port<T: JsonSchema>(name: &str) -> sdk::Port {
        Rows::port::<T>(name, &format!("discovery.{}.v1", T::schema_name()))
    }

    fn read<T: DeserializeOwned + JsonSchema>(
        input: &sdk::Evaluation,
        name: &str,
    ) -> sdk::Result<Vec<T>> {
        Rows::decode(
            &Self::port::<T>(name),
            &input.input(name)?.data,
            input.context.limits,
        )
    }

    fn write<T: Serialize + JsonSchema>(
        input: &sdk::Evaluation,
        name: &str,
        rows: &[T],
    ) -> sdk::Result<sdk::Dataset> {
        Rows::encode(&Self::port::<T>(name), rows, input.context.limits)
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
