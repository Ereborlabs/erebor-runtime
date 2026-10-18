use std::ops::ControlFlow;

use datafusion::common::{DataFusionError, Result};
use datafusion::logical_expr::planner::{
    PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
};
use datafusion::sql::parser::{DFParser, Statement};
use datafusion::sql::sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, Ident, Query, Statement as SqlStatement, TableAlias,
    TableFactor, VisitMut, VisitorMut,
};

#[derive(Debug)]
pub struct ObservedEffects;

struct Inputs(Vec<(&'static str, Box<Query>)>);

impl VisitorMut for Inputs {
    type Break = ();

    fn post_visit_table_factor(&mut self, relation: &mut TableFactor) -> ControlFlow<()> {
        let TableFactor::Table { name, alias, .. } = relation else {
            return ControlFlow::Continue(());
        };
        let Some((name, query)) = self.0.iter().find(|(input, _)| name.to_string() == *input)
        else {
            return ControlFlow::Continue(());
        };
        *relation = TableFactor::Derived {
            lateral: false,
            subquery: query.clone(),
            alias: alias.clone().or_else(|| {
                Some(TableAlias {
                    explicit: true,
                    name: Ident::new(*name),
                    columns: Vec::new(),
                })
            }),
            sample: None,
        };
        ControlFlow::Continue(())
    }
}

impl ObservedEffects {
    fn query(sql: &str, mut inputs: Inputs) -> Result<Box<Query>> {
        let mut statements = DFParser::parse_sql(sql)?;
        let Some(Statement::Statement(statement)) = statements.pop_front() else {
            return Err(DataFusionError::Internal("Discovery SQL is absent".into()));
        };
        let SqlStatement::Query(mut query) = *statement else {
            return Err(DataFusionError::Internal(
                "Discovery SQL is not a query".into(),
            ));
        };
        let _visited = query.visit(&mut inputs);
        Ok(query)
    }
}

impl RelationPlanner for ObservedEffects {
    fn plan_relation(
        &self,
        relation: TableFactor,
        context: &mut dyn RelationPlannerContext,
    ) -> Result<RelationPlanning> {
        let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = &relation
        else {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        };
        let name = context.object_name_to_table_reference(name.clone())?;
        if name.catalog().is_some() || name.schema() != Some("discovery") {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        }
        let (sql, inputs): (&str, &[&'static str]) = match name.table() {
            "observed_effects" => (include_str!("observed_effects.sql"), &["records"]),
            "coverage_ranges" => (include_str!("coverage_ranges.sql"), &["records", "reports"]),
            _ => return Ok(RelationPlanning::Original(Box::new(relation))),
        };
        let TableFactor::Table {
            alias,
            args: Some(args),
            with_hints,
            version,
            with_ordinality,
            partitions,
            json_path,
            sample,
            index_hints,
            ..
        } = relation
        else {
            return Err(DataFusionError::Internal("Discovery call changed".into()));
        };
        if args.settings.is_some()
            || !with_hints.is_empty()
            || version.is_some()
            || with_ordinality
            || !partitions.is_empty()
            || json_path.is_some()
            || sample.is_some()
            || !index_hints.is_empty()
        {
            return Err(DataFusionError::Plan(
                "Discovery call has unsupported modifiers".into(),
            ));
        }
        if args.args.len() != inputs.len() {
            return Err(DataFusionError::Plan(format!(
                "Discovery {} requires {} subquery arguments",
                name.table(),
                inputs.len()
            )));
        }
        let inputs = inputs
            .iter()
            .zip(args.args)
            .map(|(name, arg)| match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Subquery(query))) => {
                    Ok((*name, query))
                }
                _ => Err(DataFusionError::Plan(
                    "Discovery requires subquery arguments".into(),
                )),
            })
            .collect::<Result<Vec<_>>>()?;
        let plan = context.plan(TableFactor::Derived {
            lateral: false,
            subquery: Self::query(sql, Inputs(inputs))?,
            alias: None,
            sample: None,
        })?;
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            plan, alias,
        ))))
    }
}
