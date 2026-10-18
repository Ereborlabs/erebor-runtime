use std::sync::Arc;

use datafusion::arrow::datatypes::{DataType, FieldRef, SchemaRef};
use datafusion::common::config::ConfigOptions;
use datafusion::common::file_options::file_type::FileType;
use datafusion::common::{DataFusionError, Result, TableReference};
use datafusion::logical_expr::planner::{
    ExprPlanner, PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
    TypePlanner,
};
use datafusion::logical_expr::{
    AggregateUDF, Expr as LogicalExpr, LogicalPlanBuilder, ScalarUDF, TableSource, WindowUDF,
};
use datafusion::sql::parser::{DFParserBuilder, Statement};
use datafusion::sql::planner::{ContextProvider, PlannerContext, SqlToRel};
use datafusion::sql::sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, Statement as SqlStatement, TableFactor,
};

#[derive(Debug)]
pub struct ObservedEffects;

// Adapt the borrowed provider to the sized native planner interface.
struct NativeContext<'a>(&'a dyn ContextProvider);

impl ContextProvider for NativeContext<'_> {
    fn get_table_source(&self, name: TableReference) -> Result<Arc<dyn TableSource>> {
        self.0.get_table_source(name)
    }

    fn get_file_type(&self, extension: &str) -> Result<Arc<dyn FileType>> {
        self.0.get_file_type(extension)
    }

    fn get_table_function_source(
        &self,
        name: &str,
        args: Vec<LogicalExpr>,
    ) -> Result<Arc<dyn TableSource>> {
        self.0.get_table_function_source(name, args)
    }

    fn create_cte_work_table(&self, name: &str, schema: SchemaRef) -> Result<Arc<dyn TableSource>> {
        self.0.create_cte_work_table(name, schema)
    }

    fn get_expr_planners(&self) -> &[Arc<dyn ExprPlanner>] {
        self.0.get_expr_planners()
    }

    fn get_relation_planners(&self) -> &[Arc<dyn RelationPlanner>] {
        self.0.get_relation_planners()
    }

    fn get_type_planner(&self) -> Option<Arc<dyn TypePlanner>> {
        self.0.get_type_planner()
    }

    fn get_function_meta(&self, name: &str) -> Option<Arc<ScalarUDF>> {
        self.0.get_function_meta(name)
    }

    fn get_aggregate_meta(&self, name: &str) -> Option<Arc<AggregateUDF>> {
        self.0.get_aggregate_meta(name)
    }

    fn get_window_meta(&self, name: &str) -> Option<Arc<WindowUDF>> {
        self.0.get_window_meta(name)
    }

    fn get_variable_type(&self, names: &[String]) -> Option<DataType> {
        self.0.get_variable_type(names)
    }

    fn get_variable_field(&self, names: &[String]) -> Option<FieldRef> {
        self.0.get_variable_field(names)
    }

    fn options(&self) -> &ConfigOptions {
        self.0.options()
    }

    fn udf_names(&self) -> Vec<String> {
        self.0.udf_names()
    }

    fn udaf_names(&self) -> Vec<String> {
        self.0.udaf_names()
    }

    fn udwf_names(&self) -> Vec<String> {
        self.0.udwf_names()
    }
}

impl ObservedEffects {
    pub const CONTEXT_BINDINGS_SQL: &str = include_str!("context_bindings.sql");
    pub const RECORDED_SNAPSHOT_SQL: &str = include_str!("recorded_snapshot.sql");

    pub(crate) fn query(sql: &str) -> Result<SqlStatement> {
        let mut statements = DFParserBuilder::new(sql)
            .with_recursion_limit(usize::MAX)
            .build()?
            .parse_statements()?;
        let Some(Statement::Statement(statement)) = statements.pop_front() else {
            return Err(DataFusionError::Internal("Discovery SQL is absent".into()));
        };
        if !matches!(statement.as_ref(), SqlStatement::Query(_)) {
            return Err(DataFusionError::Internal(
                "Discovery SQL is not a query".into(),
            ));
        }
        Ok(*statement)
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
            "context_bindings" => (
                Self::CONTEXT_BINDINGS_SQL,
                &["records", "targets", "policies"],
            ),
            "recorded_snapshot" => (
                Self::RECORDED_SNAPSHOT_SQL,
                &[
                    "records",
                    "contexts",
                    "ranges",
                    "exclusions",
                    "lifecycle",
                    "metadata",
                ],
            ),
            "merge_snapshot" => (Self::MERGE_SQL, &["left_snapshot", "right_snapshot"]),
            "live" => (
                Self::LIVE_BODY.as_str(),
                &[
                    "records",
                    "targets",
                    "policies",
                    "reports",
                    "state",
                    "exclusions",
                    "lifecycle",
                    "metadata",
                ],
            ),
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
        let mut scope = PlannerContext::new();
        for (name, argument) in inputs.iter().zip(args.args) {
            let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Subquery(query))) = argument
            else {
                return Err(DataFusionError::Plan(
                    "Discovery requires subquery arguments".into(),
                ));
            };
            let plan = context.plan(TableFactor::Derived {
                lateral: false,
                subquery: query,
                alias: None,
                sample: None,
            })?;
            let plan = LogicalPlanBuilder::from(plan).alias(*name)?.build()?;
            scope.insert_cte(*name, plan);
        }
        let provider = NativeContext(context.context_provider());
        let plan = SqlToRel::new(&provider)
            .sql_statement_to_plan_with_context(Self::query(sql)?, &mut scope)?;
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            plan, alias,
        ))))
    }
}
