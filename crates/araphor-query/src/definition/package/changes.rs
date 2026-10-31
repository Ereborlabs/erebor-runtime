use datafusion::common::{Column, NullEquality};
use datafusion::logical_expr::{ExprFunctionExt, JoinType};

use super::*;
use crate::definition::call::{ChangeCall, ChangePort};

impl Packages {
    pub(super) fn changes(
        &self,
        model: &sdk::Model,
        children: &mut Vec<LogicalPlan>,
    ) -> Result<Option<ChangeCall>> {
        let Some(changes) = &model.change_inputs else {
            return Ok(None);
        };
        let mut call = ChangeCall {
            start: children.len(),
            ports: Vec::new(),
        };
        for pair in &changes.ports {
            let before = model
                .inputs
                .iter()
                .position(|input| input.port.name == pair.before)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change before port",
                    }
                    .build()
                })?;
            let after = model
                .inputs
                .iter()
                .position(|input| input.port.name == pair.after)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "change after port",
                    }
                    .build()
                })?;
            let schema = Arc::new(model.inputs[after].port.schema.clone());
            let mut ordinal = "__change_occurrence".to_owned();
            while schema.field_with_name(&ordinal).is_ok() {
                ordinal.push('_');
            }
            let columns = schema
                .fields()
                .iter()
                .map(|field| field.name().clone())
                .collect::<Vec<_>>();
            let numbered = |name: &str| -> Result<_> {
                let (id, provider) = Self::port(Arc::clone(&schema))?;
                let scan = Inputs::scan(name, provider, &schema)?;
                let row = row_number()
                    .partition_by(
                        columns
                            .iter()
                            .map(|name| Expr::Column(Column::from_name(name)))
                            .collect(),
                    )
                    .build()
                    .context(SqlSnafu)?;
                let plan = DataFrame::new(self.state.clone(), scan)
                    .with_column(&ordinal, row)
                    .context(SqlSnafu)?
                    .into_unoptimized_plan();
                let plan = LogicalPlanBuilder::from(plan)
                    .alias(name)
                    .and_then(LogicalPlanBuilder::build)
                    .context(SqlSnafu)?;
                self.demand
                    .record(&BTreeSet::new(), [id].into_iter())
                    .context(SqlSnafu)?;
                Ok((id, plan))
            };
            let (base, old) = numbered("before")?;
            let (target, new) = numbered("after")?;
            for (left, right, left_name, right_name) in [
                (&old, &new, "before", "after"),
                (&new, &old, "after", "before"),
            ] {
                let keys = |relation: &str| {
                    columns
                        .iter()
                        .chain(std::iter::once(&ordinal))
                        .map(|name| Column::new(Some(relation), name))
                        .collect::<Vec<_>>()
                };
                let plan = LogicalPlanBuilder::from(left.clone())
                    .join_detailed(
                        right.clone(),
                        JoinType::LeftAnti,
                        (keys(left_name), keys(right_name)),
                        None,
                        NullEquality::NullEqualsNull,
                    )
                    .and_then(|plan| {
                        plan.project(
                            columns
                                .iter()
                                .map(|name| Expr::Column(Column::new(Some(left_name), name))),
                        )
                    })
                    .and_then(LogicalPlanBuilder::build)
                    .context(SqlSnafu)?;
                crate::planner::Planner::quotas(&plan, &self.limits)?;
                children.push(plan);
            }
            call.ports.push(ChangePort {
                before,
                after,
                base,
                target,
            });
        }
        Ok(Some(call))
    }
}
