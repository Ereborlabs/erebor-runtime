use std::sync::Arc;

use araphor_data::{AnalysisReadControl, PackageErrorCodeV1};
use araphor_discovery_definition::{Definition, ResolvedDefinition};
use datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use crate::execution::Engine;
use crate::planner::Planner;
use crate::{InvalidSnafu, Result, SqlSnafu};

mod call;
mod package;
#[cfg(test)]
mod tests;

pub use call::PackageCall;

pub struct PreparedDefinition {
    pub resolved: ResolvedDefinition,
    pub plan: LogicalPlan,
}

impl Engine {
    pub async fn admit_definition(
        &self,
        tenant: [u8; 16],
        definition: Definition,
        control: Arc<AnalysisReadControl>,
    ) -> Result<ResolvedDefinition> {
        Ok(self
            .prepare_definition(tenant, &definition, control)
            .await?
            .resolved)
    }

    pub async fn prepare_definition(
        &self,
        tenant: [u8; 16],
        definition: &Definition,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PreparedDefinition> {
        control.check()?;
        if tenant == [0; 16] {
            return InvalidSnafu {
                field: "definition tenant",
            }
            .fail();
        }
        definition
            .validate_captured()
            .map_err(araphor_data::Error::from)?;
        let sql = definition
            .program
            .sql()
            .map_err(araphor_data::Error::from)?;
        let statement = self.limits().parser.parse(&sql)?;
        let references = package::Packages::references(&statement)?;
        let bundles = if references.is_empty() {
            Vec::new()
        } else {
            let store = Arc::clone(self.store());
            let read = Arc::clone(&control);
            Self::blocking(Arc::clone(&control), move || {
                references
                    .into_iter()
                    .map(|image| {
                        store
                            .package_image(tenant, &image.package_id, Some(&image.revision), &read)?
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Missing.error("definition image revision")
                            })
                            .map_err(crate::Error::from)
                    })
                    .collect()
            })
            .await?
        };
        let packages = Arc::new(package::Packages::new(self, bundles)?);
        let mut state = packages.state.clone();
        state
            .register_relation_planner(packages.clone())
            .context(SqlSnafu)?;
        let plan = Planner::new(&state).build(statement, Vec::new()).await?;
        let images = packages.pins()?;
        let plan = state.optimize(&plan).context(SqlSnafu)?;
        packages.validate().await?;
        if !package::Packages::contains_call(&plan)? {
            state
                .query_planner()
                .create_physical_plan(&plan, &state)
                .await
                .context(SqlSnafu)?;
        }
        control.check()?;
        Ok(PreparedDefinition {
            resolved: ResolvedDefinition::new(definition.clone(), sql, images)
                .map_err(araphor_data::Error::from)?,
            plan,
        })
    }
}
