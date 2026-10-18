use datafusion::common::{DataFusionError, Result};
use datafusion::logical_expr::planner::{
    PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
};
use datafusion::sql::parser::{DFParser, Statement};
use datafusion::sql::sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, Ident, Query, SetExpr, Statement as SqlStatement,
    TableAlias, TableFactor,
};

#[derive(Debug)]
pub struct ObservedEffects;

impl ObservedEffects {
    const SQL: &'static str = include_str!("observed_effects.sql");

    fn query(input: Box<Query>) -> Result<Box<Query>> {
        let mut statements = DFParser::parse_sql(Self::SQL)?;
        let Some(Statement::Statement(statement)) = statements.pop_front() else {
            return Err(DataFusionError::Internal("Discovery SQL is absent".into()));
        };
        let SqlStatement::Query(mut query) = *statement else {
            return Err(DataFusionError::Internal(
                "Discovery SQL is not a query".into(),
            ));
        };
        let SetExpr::Select(select) = query.body.as_mut() else {
            return Err(DataFusionError::Internal(
                "Discovery SQL has no SELECT".into(),
            ));
        };
        let [source] = select.from.as_mut_slice() else {
            return Err(DataFusionError::Internal(
                "Discovery SQL has no input".into(),
            ));
        };
        source.relation = TableFactor::Derived {
            lateral: false,
            subquery: input,
            alias: Some(TableAlias {
                explicit: true,
                name: Ident::new("records"),
                columns: Vec::new(),
            }),
            sample: None,
        };
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
        if name.catalog().is_some()
            || name.schema() != Some("discovery")
            || name.table() != "observed_effects"
        {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        }
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
        let mut args = args.args.into_iter();
        let (Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Subquery(input)))), None) =
            (args.next(), args.next())
        else {
            return Err(DataFusionError::Plan(
                "Discovery requires one subquery argument".into(),
            ));
        };
        let plan = context.plan(TableFactor::Derived {
            lateral: false,
            subquery: Self::query(input)?,
            alias: None,
            sample: None,
        })?;
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            plan, alias,
        ))))
    }
}
