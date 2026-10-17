use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::ScalarValue;
use datafusion::execution::context::SQLOptions;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{Expr, LogicalPlan, WindowFrameBound, WindowFrameUnits};
use datafusion::sql::parser::Statement;
use snafu::ResultExt as _;

use crate::execution::Limits;
use crate::Result;

pub(crate) mod subscription;

#[cfg(test)]
mod tests;

pub struct Planner<'a> {
    state: &'a SessionState,
}

impl<'a> Planner<'a> {
    pub fn new(state: &'a SessionState) -> Self {
        Self { state }
    }

    pub async fn build(
        self,
        statement: Statement,
        parameters: Vec<ScalarValue>,
    ) -> Result<LogicalPlan> {
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
        let plan = self
            .state
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
        Ok(plan)
    }

    fn quotas(plan: &LogicalPlan, limits: &Limits) -> Result<()> {
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
                            if matches!(function.name(), "lag" | "lead"))
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
