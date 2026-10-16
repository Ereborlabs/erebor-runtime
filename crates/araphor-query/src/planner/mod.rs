use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::ScalarValue;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{Expr, LogicalPlan, Operator, WindowFrameBound, WindowFrameUnits};
use datafusion::sql::parser::Statement;
use snafu::ResultExt as _;

use crate::Result;

pub(crate) mod subscription;

#[cfg(test)]
mod tests;

pub struct Planner<'a> {
    state: &'a SessionState,
}

impl<'a> Planner<'a> {
    pub const PARAMETER_COUNT: usize = 256;
    pub const PARAMETER_BYTES: usize = 1024 * 1024;

    pub fn new(state: &'a SessionState) -> Self {
        Self { state }
    }

    pub async fn build(
        self,
        statement: Statement,
        parameters: Vec<ScalarValue>,
    ) -> Result<LogicalPlan> {
        if parameters.len() > Self::PARAMETER_COUNT
            || ScalarValue::size_of_vec(&parameters) > Self::PARAMETER_BYTES
            || parameters.iter().any(|value| {
                matches!(value, ScalarValue::Float32(Some(value)) if !value.is_finite())
                    || matches!(value, ScalarValue::Float64(Some(value)) if !value.is_finite())
            })
        {
            return Err(crate::InvalidSnafu {
                field: "SQL parameters",
            }
            .build());
        }
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
        Self::check(&plan)?;
        Ok(plan)
    }

    fn check(plan: &LogicalPlan) -> Result<()> {
        plan.apply_with_subqueries(|plan| {
            match plan {
                LogicalPlan::Projection(projection) if projection.expr.len() > 256 => {
                    return datafusion::common::plan_err!("SQL projection is too wide");
                }
                LogicalPlan::Join(join) => {
                    let left = join.left.schema();
                    let right = join.right.schema();
                    let key = |first: &Expr, second: &Expr| {
                        match (first, second) {
                            (Expr::Column(first), Expr::Column(second)) => {
                                (left.index_of_column(first).is_ok() && right.index_of_column(second).is_ok())
                                    || (right.index_of_column(first).is_ok() && left.index_of_column(second).is_ok())
                            }
                            _ => false,
                        }
                    };
                    let mut valid = !join.on.is_empty() || join.filter.is_some();
                    for (first, second) in &join.on {
                        valid &= key(first, second);
                    }
                    if let Some(filter) = &join.filter {
                        filter.apply(|expression| match expression {
                            Expr::BinaryExpr(binary) if binary.op == Operator::And => {
                                Ok(TreeNodeRecursion::Continue)
                            }
                            Expr::BinaryExpr(binary)
                                if binary.op == Operator::Eq && key(&binary.left, &binary.right) =>
                            {
                                Ok(TreeNodeRecursion::Jump)
                            }
                            _ => {
                                valid = false;
                                Ok(TreeNodeRecursion::Stop)
                            }
                        })?;
                    }
                    if !valid {
                        return datafusion::common::plan_err!("SQL join keys are invalid");
                    }
                }
                LogicalPlan::Projection(_) | LogicalPlan::Filter(_) | LogicalPlan::TableScan(_)
                | LogicalPlan::Aggregate(_) | LogicalPlan::Window(_) | LogicalPlan::Subquery(_) | LogicalPlan::SubqueryAlias(_)
                | LogicalPlan::Sort(_) | LogicalPlan::Limit(_) | LogicalPlan::Distinct(_)
                | LogicalPlan::Union(_) | LogicalPlan::EmptyRelation(_) => {}
                _ => return datafusion::common::plan_err!("SQL plan is unavailable"),
            }
            plan.apply_expressions(|expression| expression.apply(|expression| {
                if let Expr::WindowFunction(window) = expression {
                    if window.params.order_by.is_empty() {
                        return datafusion::common::plan_err!("SQL window order is absent");
                    }
                    if matches!(&window.fun,
                        datafusion::logical_expr::WindowFunctionDefinition::WindowUDF(function)
                            if matches!(function.name(), "lag" | "lead"))
                    {
                        let bounded = match window.params.args.get(1) {
                            None => true,
                            Some(Expr::Literal(value, _)) if value.data_type().is_integer() => {
                                matches!(
                                    value.cast_to(&datafusion::arrow::datatypes::DataType::UInt64),
                                    Ok(ScalarValue::UInt64(Some(value))) if value <= 200
                                )
                            }
                            _ => false,
                        };
                        if !bounded {
                            return datafusion::common::plan_err!("SQL window offset is unbounded");
                        }
                    }
                    if matches!(window.fun, datafusion::logical_expr::WindowFunctionDefinition::AggregateUDF(_)) {
                        let bounded = |bound: &WindowFrameBound| match bound {
                            WindowFrameBound::CurrentRow => true,
                            WindowFrameBound::Preceding(ScalarValue::UInt64(Some(value)))
                            | WindowFrameBound::Following(ScalarValue::UInt64(Some(value))) => *value <= 200,
                            _ => false,
                        };
                        let frame = &window.params.window_frame;
                        if frame.units != WindowFrameUnits::Rows
                            || !bounded(&frame.start_bound) || !bounded(&frame.end_bound)
                        {
                            return datafusion::common::plan_err!("SQL aggregate window frame is unbounded");
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
