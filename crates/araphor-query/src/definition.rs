use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition};
use araphor_package::PackageBundleV1;
use datafusion::execution::SessionState;
use datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use crate::execution::Engine;
use crate::planner::Planner;
use crate::sources::SourceSnapshot;
use crate::{Result, SqlSnafu};

mod call;
mod package;
#[cfg(test)]
mod tests;

pub use call::PackageCall;

pub struct PreparedDefinition {
    pub resolved: ResolvedDefinition,
    pub plan: LogicalPlan,
    pub sql_plan: Option<LogicalPlan>,
}

impl Engine {
    pub async fn admit_definition(
        &self,
        definition: Definition,
        bundles: &[PackageBundleV1],
    ) -> Result<ResolvedDefinition> {
        Ok(self
            .prepare_definition(&definition, bundles)
            .await?
            .resolved)
    }

    pub async fn prepare_definition(
        &self,
        definition: &Definition,
        bundles: &[PackageBundleV1],
    ) -> Result<PreparedDefinition> {
        definition
            .validate_captured()
            .map_err(araphor_data::Error::from)?;
        if let Some(sql) = definition
            .program
            .sql()
            .map_err(araphor_data::Error::from)?
        {
            let state = self.catalog(SourceSnapshot::providers())?;
            let plan = self.definition_sql(&state, &sql).await?;
            state
                .query_planner()
                .create_physical_plan(&plan, &state)
                .await
                .context(SqlSnafu)?;
            return Ok(PreparedDefinition {
                resolved: ResolvedDefinition::new(definition.clone(), sql, Vec::new())
                    .map_err(araphor_data::Error::from)?,
                sql_plan: Some(plan.clone()),
                plan,
            });
        }
        let Program::Package { call } = &definition.program else {
            return crate::InvalidSnafu {
                field: "definition program",
            }
            .fail();
        };
        let mut matching = bundles.iter().filter(|bundle| bundle.root == call.image);
        let bundle = matching
            .next()
            .ok_or_else(|| araphor_package::ErrorCode::Missing.error("definition image revision"))
            .map_err(araphor_data::Error::from)?;
        if matching.next().is_some() {
            return crate::InvalidSnafu {
                field: "duplicate definition image",
            }
            .fail();
        }
        bundle.validate().map_err(araphor_data::Error::from)?;
        let pin = ImagePin {
            image: bundle.root.clone(),
            digest: bundle.digest().map_err(araphor_data::Error::from)?,
        };
        let admitted = package::PackagePlanner::new(self, bundle, pin.clone())
            .admit(call)
            .await?;
        let sql = admitted.call.sql();
        let mut state = self.catalog(SourceSnapshot::providers())?;
        state
            .register_relation_planner(std::sync::Arc::new(admitted.call))
            .context(SqlSnafu)?;
        let plan = self.definition_sql(&state, &sql).await?;
        Ok(PreparedDefinition {
            resolved: ResolvedDefinition::new(definition.clone(), sql, vec![pin])
                .map_err(araphor_data::Error::from)?,
            plan,
            sql_plan: admitted.sql,
        })
    }

    async fn definition_sql(&self, state: &SessionState, sql: &str) -> Result<LogicalPlan> {
        let statement = self.limits().parser.parse(sql)?;
        let plan = Planner::new(state).build(statement, Vec::new()).await?;
        state.optimize(&plan).context(SqlSnafu)
    }
}
