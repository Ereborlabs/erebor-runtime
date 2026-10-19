use std::collections::BTreeSet;
use std::ops::ControlFlow;

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, ScalarValue, TableReference};
use datafusion::execution::context::SQLOptions;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{Expr, LogicalPlan, WindowFrameBound, WindowFrameUnits};
use datafusion::sql::parser::Statement;
use datafusion::sql::planner::object_name_to_table_reference;
use datafusion::sql::sqlparser::ast::{TableFactor, Visit, Visitor};
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

struct Relations {
    tables: BTreeSet<TableReference>,
    normalize: bool,
}

impl Visitor for Relations {
    type Break = DataFusionError;

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            match object_name_to_table_reference(name.clone(), self.normalize) {
                Ok(name) => {
                    self.tables.insert(name);
                }
                Err(error) => return ControlFlow::Break(error),
            }
        }
        ControlFlow::Continue(())
    }
}

impl<'a> Planner<'a> {
    pub fn new(state: &'a SessionState) -> Self {
        Self { state }
    }

    pub(crate) async fn sources(&self, statement: &Statement) -> Result<BTreeSet<SourceOrigin>> {
        let mut relations = Relations {
            tables: BTreeSet::new(),
            normalize: self
                .state
                .config_options()
                .sql_parser
                .enable_ident_normalization,
        };
        if let Statement::Statement(statement) = statement {
            if let ControlFlow::Break(error) = statement.visit(&mut relations) {
                return Err(error).context(crate::SqlSnafu);
            }
        }
        let mut origins = BTreeSet::new();
        for name in self
            .state
            .resolve_table_references(statement)
            .context(crate::SqlSnafu)?
        {
            // The native resolver also returns table function names.
            if !relations.tables.contains(&name) {
                continue;
            }
            let schema = self
                .state
                .schema_for_ref(name.clone())
                .context(crate::SqlSnafu)?;
            let provider = schema.table(name.table()).await.context(crate::SqlSnafu)?;
            if let Some(source) = provider
                .as_ref()
                .and_then(|provider| provider.as_any().downcast_ref::<SourceProvider>())
            {
                origins.insert(source.origin.clone());
            }
        }
        Ok(origins)
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
