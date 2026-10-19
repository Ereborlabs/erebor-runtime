use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, Result as NativeResult, ScalarValue};
use datafusion::datasource::source_as_provider;
use datafusion::execution::context::SQLOptions;
use datafusion::execution::SessionState;
use datafusion::functions_window::lead_lag::WindowShift;
use datafusion::logical_expr::planner::{
    PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
};
use datafusion::logical_expr::{Expr, LogicalPlan, WindowFrameBound, WindowFrameUnits};
use datafusion::sql::parser::Statement;
use datafusion::sql::sqlparser::ast::TableFactor;
use snafu::ResultExt as _;

use crate::execution::Limits;
use crate::sources::{SourceOrigin, SourceProvider};
use crate::Result;

pub(crate) mod subscription;

#[cfg(test)]
mod tests;

pub struct Planner<'a> {
    state: &'a SessionState,
}

#[derive(Debug, Default)]
struct SourceDemand {
    origins: Mutex<BTreeSet<SourceOrigin>>,
    active: AtomicBool,
}

impl SourceDemand {
    fn collect(plan: &LogicalPlan) -> NativeResult<BTreeSet<SourceOrigin>> {
        let mut origins = BTreeSet::new();
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                if let Ok(provider) = source_as_provider(&scan.source) {
                    if let Some(source) = provider.as_any().downcast_ref::<SourceProvider>() {
                        origins.insert(source.origin.clone());
                    }
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(origins)
    }
}

impl RelationPlanner for SourceDemand {
    fn plan_relation(
        &self,
        relation: TableFactor,
        context: &mut dyn RelationPlannerContext,
    ) -> NativeResult<RelationPlanning> {
        if !matches!(&relation, TableFactor::Table { args: None, .. })
            || self.active.swap(true, Ordering::Relaxed)
        {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        }
        let plan = context.plan(relation);
        self.active.store(false, Ordering::Relaxed);
        let plan = plan?;
        self.origins
            .lock()
            .map_err(|_| DataFusionError::Internal("source demand lock is poisoned".into()))?
            .extend(Self::collect(&plan)?);
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            plan, None,
        ))))
    }
}

impl<'a> Planner<'a> {
    pub fn new(state: &'a SessionState) -> Self {
        Self { state }
    }

    pub(crate) fn sources(plan: &LogicalPlan) -> Result<BTreeSet<SourceOrigin>> {
        SourceDemand::collect(plan).context(crate::SqlSnafu)
    }

    pub async fn build(
        self,
        statement: Statement,
        parameters: Vec<ScalarValue>,
    ) -> Result<LogicalPlan> {
        self.build_with_sources(statement, parameters)
            .await
            .map(|(plan, _)| plan)
    }

    pub(crate) async fn build_with_sources(
        self,
        statement: Statement,
        parameters: Vec<ScalarValue>,
    ) -> Result<(LogicalPlan, BTreeSet<SourceOrigin>)> {
        let limits = self
            .state
            .config()
            .get_extension::<Limits>()
            .unwrap_or_default();
        if limits
            .parameter_count
            .is_some_and(|maximum| parameters.len() > maximum)
            || limits
                .parameter_bytes
                .is_some_and(|maximum| ScalarValue::size_of_vec(&parameters) > maximum)
        {
            return Err(crate::InvalidSnafu {
                field: "SQL parameters",
            }
            .build());
        }
        // Reject commands before native DDL planning can read external metadata.
        if !matches!(&statement, Statement::Statement(statement)
            if matches!(statement.as_ref(), datafusion::sql::sqlparser::ast::Statement::Query(_)))
        {
            return Err(crate::InvalidSnafu {
                field: "SQL statement",
            }
            .build());
        }
        let demand = Arc::new(SourceDemand::default());
        let mut state = self.state.clone();
        state
            .register_relation_planner(demand.clone())
            .context(crate::SqlSnafu)?;
        let plan = state
            .statement_to_plan(statement)
            .await
            .and_then(|plan| plan.with_param_values(parameters))
            .context(crate::SqlSnafu)?;
        SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false)
            .verify_plan(&plan)
            .context(crate::SqlSnafu)?;
        Self::quotas(&plan, &limits)?;
        let mut origins =
            std::mem::take(&mut *demand.origins.lock().map_err(|_| crate::Error::Sql {
                source: DataFusionError::Internal("source demand lock is poisoned".into()),
            })?);
        origins.extend(Self::sources(&plan)?);
        Ok((plan, origins))
    }

    pub(crate) fn quotas(plan: &LogicalPlan, limits: &Limits) -> Result<()> {
        if limits.projection_columns.is_none() && limits.window_bound.is_none() {
            return Ok(());
        }
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::Projection(projection) = plan {
                if limits.projection_columns.is_some_and(|maximum| projection.expr.len() > maximum) {
                    return datafusion::common::plan_err!("SQL projection is too wide");
                }
            }
            let Some(maximum) = limits.window_bound else {
                return Ok(TreeNodeRecursion::Continue);
            };
            plan.apply_expressions(|expression| expression.apply(|expression| {
                if let Expr::WindowFunction(window) = expression {
                    if matches!(&window.fun,
                        datafusion::logical_expr::WindowFunctionDefinition::WindowUDF(function)
                            if function.inner().as_any().is::<WindowShift>())
                    {
                        let bounded = match window.params.args.get(1) {
                            None => maximum >= 1,
                            Some(Expr::Literal(value, _)) if value.data_type().is_integer() => {
                                matches!(value.cast_to(&datafusion::arrow::datatypes::DataType::UInt64),
                                    Ok(ScalarValue::UInt64(Some(value))) if value <= maximum as u64)
                            }
                            _ => false,
                        };
                        if !bounded {
                            return datafusion::common::plan_err!("SQL window offset exceeds its quota");
                        }
                    }
                    if matches!(window.fun, datafusion::logical_expr::WindowFunctionDefinition::AggregateUDF(_)) {
                        let bounded = |bound: &WindowFrameBound| match bound {
                            WindowFrameBound::CurrentRow => true,
                            WindowFrameBound::Preceding(ScalarValue::UInt64(Some(value)))
                            | WindowFrameBound::Following(ScalarValue::UInt64(Some(value))) => *value <= maximum as u64,
                            _ => false,
                        };
                        let frame = &window.params.window_frame;
                        if frame.units != WindowFrameUnits::Rows
                            || !bounded(&frame.start_bound) || !bounded(&frame.end_bound)
                        {
                            return datafusion::common::plan_err!("SQL window frame exceeds its quota");
                        }
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            }))?;
            Ok(TreeNodeRecursion::Continue)
        }).context(crate::SqlSnafu)?;
        Ok(())
    }
}
