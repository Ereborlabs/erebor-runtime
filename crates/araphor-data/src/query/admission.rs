use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Bound, ControlFlow};
use std::sync::Arc;

use datafusion::arrow::datatypes::{Field, FieldRef, Schema, SchemaRef};
use datafusion::catalog::default_table_source::provider_as_source;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{Column, DFSchema, Result as EngineResult, ScalarValue, TableReference};
use datafusion::datasource::empty::EmptyTable;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{
    AggregateUDF, Expr as EngineExpression, LogicalPlan, LogicalPlanBuilder, Operator, Projection,
    ScalarUDF, TableSource, WindowUDF,
};
use datafusion::sql::planner::{ContextProvider, ParserOptions, PlannerContext, SqlToRel};

use datafusion::sql::sqlparser::ast::{
    BinaryOperator, DataType, DateTimeField, Distinct, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, JoinConstraint, JoinOperator,
    LimitClause, NamedWindowExpr, ObjectName, OrderBy, OrderByExpr, OrderByKind, Query, Select,
    SelectFlavor, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, SetQuantifier, Statement,
    TableAlias, TableFactor, TimezoneInfo, UnaryOperator, Value as SqlValue, VisitMut as _,
    VisitorMut, WildcardAdditionalOptions, WindowFrameBound, WindowFrameUnits, WindowSpec,
    WindowType,
};
use datafusion::sql::sqlparser::dialect::GenericDialect;
use datafusion::sql::sqlparser::parser::{Parser, ParserError};
use duckdb::types::{TimeUnit, Value};
use time::PrimitiveDateTime;

use super::{engine::QueryEngine, input::SCHEMAS, QueryOperation};
use crate::Result;

const SQL_BYTES: usize = 16 * 1024;
const PARAMETER_BYTES: usize = 1024 * 1024;
const PARAMETER_COUNT: usize = 256;
const AST_DEPTH: usize = 64;
const POSITION_FIELDS: [&str; 2] = ["__araphor_commit_revision", "__araphor_ordinal"];

/// Client SQL uses the available code-owned schemas.
#[derive(Clone, Debug, PartialEq)]
pub struct QuerySql {
    program: Arc<AdmittedSql>,
}

#[derive(Debug, PartialEq)]
struct AdmittedSql {
    original: String,
    plan: Arc<LogicalPlan>,
    complete_sql: String,
    append_sql: Option<String>,
    plan_bytes: usize,
    source_columns: Vec<Option<(&'static str, &'static str)>>,
    parameters: Vec<Value>,
    dependencies: BTreeSet<String>,
    operation: QueryOperation,
    moving: Option<u32>,
    tests: Vec<TimeTest>,
    clocks: usize,
    follow: bool,
    event_operation: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct QueryBinding {
    pub sql: String,
    pub parameters: Vec<Value>,
    pub received_from: Bound<u64>,
    pub received_until: Bound<u64>,
    pub evaluated_utc_ns: u64,
    pub append: bool,
    pub(super) plan: Arc<LogicalPlan>,
}

impl QuerySql {
    pub const PARAMETER_COUNT: usize = PARAMETER_COUNT;
    pub const PARAMETER_BYTES: usize = PARAMETER_BYTES;

    pub fn admit(sql: &str, parameters: Vec<Value>, follow: bool) -> Result<Self> {
        Self::admit_with(sql, parameters, follow, None)
    }

    pub(super) fn admit_relations(
        sql: &str,
        relations: BTreeMap<String, SchemaRef>,
    ) -> Result<Self> {
        Self::admit_with(sql, Vec::new(), false, Some(relations))
    }

    fn admit_with(
        sql: &str,
        parameters: Vec<Value>,
        follow: bool,
        relations: Option<BTreeMap<String, SchemaRef>>,
    ) -> Result<Self> {
        if sql.is_empty() || sql.len() > SQL_BYTES {
            return Err(SqlPolicy::invalid("SQL length"));
        }
        Parameters::validate(&parameters)?;
        let mut statements =
            SqlContext::parse(sql).map_err(|_| SqlPolicy::invalid("SQL syntax"))?;
        if statements.len() != 1 {
            return Err(SqlPolicy::invalid("SQL statement"));
        }
        let Some(Statement::Query(mut query)) = statements.pop() else {
            return Err(SqlPolicy::invalid("SQL statement"));
        };
        Parameters::bind(&mut query, parameters.len())?;
        let relations = relations.unwrap_or_else(|| {
            SCHEMAS
                .iter()
                .filter(|schema| {
                    matches!(schema.readiness, "available" | "conditional")
                        || schema.name == "behaviors"
                })
                .map(|schema| (schema.name.to_owned(), schema.arrow_schema()))
                .collect()
        });
        let mut policy = SqlPolicy {
            relations: &relations,
            aggregate: false,
            clocks: 0,
            depth: 0,
            dependencies: BTreeSet::new(),
        };
        policy.query(&mut query, &BTreeSet::new())?;
        let tests = TimeTest::extract(&query, &parameters);
        let moving: Vec<_> = tests
            .iter()
            .filter_map(|test| match (&test.op, &test.value) {
                (BinaryOperator::GtEq | BinaryOperator::Gt, TimeValue::Moving(seconds)) => {
                    Some(*seconds)
                }
                _ => None,
            })
            .collect();
        if follow && policy.clocks != moving.len() {
            return Err(SqlPolicy::invalid("moving SQL shape"));
        }
        let operation = if !policy.aggregate && policy.clocks == 0 && Self::append_shape(&query) {
            QueryOperation::Append
        } else {
            QueryOperation::Replace
        };
        let dependencies = policy.dependencies;
        let clocks = policy.clocks;
        let event_operation = TimeTest::direct_events(&query)
            .filter(|_| clocks == 0 && Self::append_shape(&query))
            .and_then(|(select, alias)| {
                Self::event_operation_for(select.selection.as_ref()?, &alias, &parameters)
            });
        if clocks > 0 {
            let index = parameters.len() + 1;
            let _ = query.visit(&mut FrozenClock(index));
        }
        let complete_sql = query.to_string();
        if complete_sql.len() > SQL_BYTES {
            return Err(SqlPolicy::invalid("expanded SQL length"));
        }
        let state = QueryEngine::state()?;
        let mut fields = SqlContext::parameter_fields(&QueryEngine::parameters(&parameters)?);
        if clocks > 0 {
            fields.push(Arc::new(Field::new(
                format!("${}", parameters.len() + 1),
                datafusion::arrow::datatypes::DataType::Timestamp(
                    datafusion::arrow::datatypes::TimeUnit::Microsecond,
                    None,
                ),
                false,
            )));
        }
        let plan = SqlContext {
            state: &state,
            relations: &relations,
        }
        .plan(query.clone(), &fields)?;
        SqlPolicy::bound(&plan)?;
        let source_columns = Self::source_columns(&query, &plan);
        let plan_bytes = Self::plan_bytes(&plan);
        let append_sql = if operation == QueryOperation::Append {
            Self::append_positions(&mut query)?;
            Some(query.to_string())
        } else {
            None
        };
        Ok(Self {
            program: Arc::new(AdmittedSql {
                original: sql.to_owned(),
                plan: Arc::new(plan),
                complete_sql,
                append_sql,
                plan_bytes,
                source_columns,
                parameters,
                dependencies,
                operation,
                moving: moving.into_iter().min(),
                tests,
                clocks,
                follow,
                event_operation,
            }),
        })
    }

    pub(super) fn event_operation(&self) -> Option<u32> {
        self.program.event_operation
    }

    fn event_operation_for(expr: &Expr, alias: &str, parameters: &[Value]) -> Option<u32> {
        match expr {
            Expr::Nested(expr) => Self::event_operation_for(expr, alias, parameters),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => Self::event_operation_for(left, alias, parameters)
                .or_else(|| Self::event_operation_for(right, alias, parameters)),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                let column = |expr: &Expr| TimeTest::named_column(expr, alias, "operation");
                let value = if column(left) {
                    right.as_ref()
                } else if column(right) {
                    left.as_ref()
                } else {
                    return None;
                };
                let Expr::Value(value) = value else {
                    return None;
                };
                match &value.value {
                    SqlValue::Number(value, false) => value.parse().ok(),
                    SqlValue::Placeholder(mark) => {
                        let index = mark
                            .strip_prefix('$')?
                            .parse::<usize>()
                            .ok()?
                            .checked_sub(1)?;
                        match parameters.get(index)? {
                            Value::UInt(value) => Some(*value),
                            Value::UBigInt(value) => u32::try_from(*value).ok(),
                            Value::Int(value) => u32::try_from(*value).ok(),
                            Value::BigInt(value) => u32::try_from(*value).ok(),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn original(&self) -> &str {
        &self.program.original
    }

    pub(crate) fn uses_clock(&self) -> bool {
        self.program.clocks != 0
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        use std::mem::size_of;

        let tree = |names: &BTreeSet<String>| {
            names.iter().fold(
                names.len().max(1) * (11 * size_of::<String>() + 16 * size_of::<usize>()),
                |bytes, name| bytes.saturating_add(name.capacity()),
            )
        };
        let parameters = self.program.parameters.iter().fold(
            self.program.parameters.capacity() * size_of::<Value>(),
            |bytes, value| {
                bytes.saturating_add(match value {
                    Value::Text(value) => value.capacity(),
                    Value::Blob(value) => value.capacity(),
                    _ => 0,
                })
            },
        );
        size_of::<Self>()
            .saturating_add(size_of::<AdmittedSql>() + 2 * size_of::<usize>())
            .saturating_add(self.program.original.capacity())
            .saturating_add(self.program.plan_bytes)
            .saturating_add(
                self.program.source_columns.capacity() * size_of::<Option<(&str, &str)>>(),
            )
            .saturating_add(self.program.complete_sql.capacity())
            .saturating_add(self.program.append_sql.as_ref().map_or(0, String::capacity))
            .saturating_add(parameters)
            .saturating_add(self.program.tests.capacity() * size_of::<TimeTest>())
            .saturating_add(tree(&self.program.dependencies))
    }

    pub fn parameters(&self) -> &[Value] {
        &self.program.parameters
    }

    pub fn dependencies(&self) -> &BTreeSet<String> {
        &self.program.dependencies
    }

    pub fn operation(&self) -> QueryOperation {
        self.program.operation
    }

    pub fn follow(&self) -> bool {
        self.program.follow
    }

    fn source_columns(
        query: &Query,
        plan: &LogicalPlan,
    ) -> Vec<Option<(&'static str, &'static str)>> {
        let Some((_, alias, name)) = TimeTest::direct_table(query) else {
            return Vec::new();
        };
        let Some(schema) = SCHEMAS.iter().find(|schema| schema.name == name) else {
            return Vec::new();
        };
        let mut current = plan;
        let projection = loop {
            if let LogicalPlan::Projection(projection) = current {
                break projection;
            }
            let inputs = current.inputs();
            let [input] = inputs.as_slice() else {
                return Vec::new();
            };
            current = input;
        };
        projection
            .expr
            .iter()
            .map(|expr| {
                let mut expr = expr;
                while let EngineExpression::Alias(alias) = expr {
                    expr = &alias.expr;
                }
                let EngineExpression::Column(column) = expr else {
                    return None;
                };
                if !column
                    .relation
                    .as_ref()
                    .is_some_and(|table| table.table() == alias)
                {
                    return None;
                }
                schema
                    .fields()
                    .iter()
                    .find(|field| field.name() == &column.name)
                    .map(|field| (schema.name, field.name().as_str()))
            })
            .collect()
    }

    pub(super) fn source_column(
        &self,
        name: &str,
    ) -> Option<(&'static super::input::InputSchema, usize)> {
        let mut selected = self
            .program
            .plan
            .schema()
            .fields()
            .iter()
            .zip(&self.program.source_columns)
            .filter(|(output, _)| output.name() == name);
        let (_, source) = selected.next()?;
        if selected.next().is_some() {
            return None;
        }
        let (table, column) = (*source)?;
        let schema = SCHEMAS.iter().find(|schema| schema.name == table)?;
        let ordinal = schema
            .fields()
            .iter()
            .position(|field| field.name() == column)?;
        Some((schema, ordinal))
    }

    pub fn moving_seconds(&self) -> Option<u32> {
        self.program.moving
    }

    pub(super) fn bind_complete(&self, now_ns: u64) -> Result<QueryBinding> {
        self.bind(now_ns, false)
    }

    pub fn bind_at(&self, now_ns: u64) -> Result<QueryBinding> {
        self.bind(now_ns, self.program.operation == QueryOperation::Append)
    }

    fn bind(&self, now_ns: u64, append: bool) -> Result<QueryBinding> {
        let mut parameters = self.program.parameters.clone();
        if self.program.clocks > 0 {
            parameters.push(Value::Timestamp(
                TimeUnit::Microsecond,
                (now_ns / 1_000) as i64,
            ));
        }
        let mut first = 0_i128;
        let mut last = i128::from(u64::MAX);
        for test in &self.program.tests {
            let micros = match test.value {
                TimeValue::Fixed(value) => i128::from(value),
                TimeValue::Moving(seconds) => {
                    i128::from(now_ns / 1_000) - i128::from(seconds) * 1_000_000
                }
            };
            // received_at truncates intake nanoseconds to microseconds.
            match test.op {
                BinaryOperator::GtEq => first = first.max(micros * 1_000),
                BinaryOperator::Gt => first = first.max((micros + 1) * 1_000),
                BinaryOperator::LtEq => last = last.min((micros + 1) * 1_000 - 1),
                BinaryOperator::Lt => last = last.min(micros * 1_000 - 1),
                BinaryOperator::Eq => {
                    first = first.max(micros * 1_000);
                    last = last.min((micros + 1) * 1_000 - 1);
                }
                _ => return Err(SqlPolicy::invalid("SQL time bound")),
            }
        }
        let (received_from, received_until) = if first > last {
            (Bound::Included(1), Bound::Included(0))
        } else {
            (
                if first == 0 {
                    Bound::Unbounded
                } else {
                    Bound::Included(first as u64)
                },
                if last == i128::from(u64::MAX) {
                    Bound::Unbounded
                } else {
                    Bound::Included(last as u64)
                },
            )
        };
        let plan = if append {
            Arc::new(Self::append_plan(self.program.plan.as_ref().clone())?)
        } else {
            Arc::clone(&self.program.plan)
        };
        Ok(QueryBinding {
            sql: if append {
                self.program
                    .append_sql
                    .as_ref()
                    .unwrap_or(&self.program.complete_sql)
            } else {
                &self.program.complete_sql
            }
            .clone(),
            parameters,
            received_from,
            received_until,
            evaluated_utc_ns: now_ns,
            append,
            plan,
        })
    }

    fn plan_bytes(plan: &LogicalPlan) -> usize {
        use std::mem::size_of;
        let mut bytes = 0usize;
        let _ = plan.apply_with_subqueries(|plan| {
            let schema = plan.schema();
            bytes = bytes
                .saturating_add(2 * size_of::<LogicalPlan>())
                .saturating_add(schema.fields().size())
                .saturating_add(size_of::<DFSchema>())
                .saturating_add(schema.metadata().capacity() * size_of::<(String, String)>())
                .saturating_add(
                    schema
                        .metadata()
                        .iter()
                        .map(|(key, value)| key.capacity() + value.capacity())
                        .sum::<usize>(),
                );
            bytes = bytes.saturating_add(
                schema
                    .iter()
                    .map(|(name, _)| {
                        size_of::<Option<TableReference>>()
                            + name.map_or(0, |name| name.to_string().len())
                    })
                    .sum::<usize>(),
            );
            plan.apply_expressions(|expr| {
                expr.apply(|expr| {
                    bytes = bytes
                        .saturating_add(2 * size_of::<EngineExpression>())
                        .saturating_add(match expr {
                            EngineExpression::Literal(value, _) => value.size(),
                            EngineExpression::Column(column) => column.name.capacity(),
                            EngineExpression::Alias(alias) => alias.name.capacity(),
                            EngineExpression::Cast(cast) => cast.data_type.size(),
                            EngineExpression::TryCast(cast) => cast.data_type.size(),
                            EngineExpression::Placeholder(mark) => {
                                mark.id.capacity()
                                    + mark.field.as_ref().map_or(0, |field| field.size())
                            }
                            _ => 0,
                        });
                    Ok(TreeNodeRecursion::Continue)
                })
            })?;
            Ok(TreeNodeRecursion::Continue)
        });
        bytes
    }

    fn append_plan(plan: LogicalPlan) -> Result<LogicalPlan> {
        let plan = match plan {
            LogicalPlan::Projection(mut projection) => {
                for (name, alias) in ["commit_revision", "ordinal"]
                    .into_iter()
                    .zip(POSITION_FIELDS)
                {
                    let (qualifier, field) = projection
                        .input
                        .schema()
                        .qualified_field_with_unqualified_name(name)
                        .map_err(|_| SqlPolicy::invalid("append SQL source"))?;
                    projection.expr.push(
                        EngineExpression::Column(Column::from((qualifier, field))).alias(alias),
                    );
                }
                LogicalPlan::Projection(
                    Projection::try_new(projection.expr, projection.input)
                        .map_err(|_| SqlPolicy::invalid("append SQL projection"))?,
                )
            }
            _ => return Err(SqlPolicy::invalid("append SQL shape")),
        };
        LogicalPlanBuilder::from(plan)
            .sort(POSITION_FIELDS.map(|name| {
                EngineExpression::Column(Column::new_unqualified(name)).sort(true, false)
            }))
            .and_then(LogicalPlanBuilder::build)
            .map_err(|_| SqlPolicy::invalid("append SQL ordering"))
    }

    fn append_shape(query: &Query) -> bool {
        let Some((select, _, relation)) = TimeTest::direct_table(query) else {
            return false;
        };
        matches!(relation.as_str(), "events" | "trace_output")
            && query.limit_clause.is_none()
            && query.order_by.is_none()
            && select.distinct.is_none()
            && select.having.is_none()
            && matches!(&select.group_by, GroupByExpr::Expressions(items, _) if items.is_empty())
    }

    fn append_positions(query: &mut Query) -> Result<()> {
        let Some((_, alias, relation)) = TimeTest::direct_table(query) else {
            return Err(SqlPolicy::invalid("append SQL shape"));
        };
        if !matches!(relation.as_str(), "events" | "trace_output") {
            return Err(SqlPolicy::invalid("append SQL shape"));
        }
        let SetExpr::Select(select) = query.body.as_mut() else {
            return Err(SqlPolicy::invalid("append SQL shape"));
        };
        let mut order = Vec::new();
        for (source, field) in ["commit_revision", "ordinal"]
            .into_iter()
            .zip(POSITION_FIELDS)
        {
            let expr = Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', &alias),
                Ident::with_quote('"', source),
            ]);
            select.projection.push(SelectItem::ExprWithAlias {
                expr: expr.clone(),
                alias: Ident::with_quote('"', field),
            });
            order.push(OrderByExpr {
                expr,
                options: Default::default(),
                with_fill: None,
            });
        }
        query.order_by = Some(OrderBy {
            kind: OrderByKind::Expressions(order),
            interpolate: None,
        });
        Ok(())
    }
}

impl PartialEq for QueryBinding {
    fn eq(&self, other: &Self) -> bool {
        self.sql == other.sql
            && self.parameters == other.parameters
            && self.received_from == other.received_from
            && self.received_until == other.received_until
            && self.evaluated_utc_ns == other.evaluated_utc_ns
            && self.append == other.append
    }
}

impl QueryBinding {
    pub(super) fn trusted(sql: String, parameters: Vec<Value>, now_ns: u64) -> Result<Self> {
        let mut statements =
            SqlContext::parse(&sql).map_err(|_| SqlPolicy::invalid("trusted SQL syntax"))?;
        if statements.len() != 1 {
            return Err(SqlPolicy::invalid("trusted SQL statement"));
        }
        let Some(Statement::Query(mut query)) = statements.pop() else {
            return Err(SqlPolicy::invalid("trusted SQL statement"));
        };
        Parameters::bind(&mut query, parameters.len())?;
        let sql = query.to_string();
        let state = QueryEngine::state()?;
        let relations = SCHEMAS
            .iter()
            .map(|schema| (schema.name.to_owned(), schema.arrow_schema()))
            .collect();
        let values = QueryEngine::parameters(&parameters)?;
        let plan = SqlContext {
            state: &state,
            relations: &relations,
        }
        .plan(query, &SqlContext::parameter_fields(&values))?;
        Ok(Self {
            sql,
            plan: Arc::new(plan),
            parameters,
            received_from: Bound::Unbounded,
            received_until: Bound::Unbounded,
            evaluated_utc_ns: now_ns,
            append: false,
        })
    }

    pub(super) fn plan(&self) -> Result<LogicalPlan> {
        self.plan
            .as_ref()
            .clone()
            .with_param_values(QueryEngine::parameters(&self.parameters)?)
            .map_err(|_| SqlPolicy::invalid("SQL parameters"))
    }
}

struct SqlContext<'a> {
    state: &'a SessionState,
    relations: &'a BTreeMap<String, SchemaRef>,
}

impl SqlContext<'_> {
    fn parse(sql: &str) -> std::result::Result<Vec<Statement>, ParserError> {
        const STACK_BYTES: usize = 16 * 1024 * 1024;
        // Reserve stack space for the parser depth limit.
        stacker::maybe_grow(STACK_BYTES, STACK_BYTES, || {
            Parser::new(&GenericDialect {})
                .with_recursion_limit(AST_DEPTH)
                .try_with_sql(sql)
                .and_then(|mut parser| parser.parse_statements())
        })
    }

    fn parameter_fields(parameters: &[ScalarValue]) -> Vec<FieldRef> {
        parameters
            .iter()
            .enumerate()
            .map(|(index, value)| {
                Arc::new(Field::new(
                    format!("${}", index + 1),
                    value.data_type(),
                    value.is_null(),
                ))
            })
            .collect()
    }

    fn plan(&self, query: Box<Query>, parameters: &[FieldRef]) -> Result<LogicalPlan> {
        let mut context = PlannerContext::new().with_prepare_param_data_types(parameters.to_vec());
        SqlToRel::new_with_options(
            self,
            ParserOptions::new().with_map_string_types_to_utf8view(false),
        )
        .sql_statement_to_plan_with_context(Statement::Query(query), &mut context)
        .map_err(|_| SqlPolicy::invalid("SQL binding"))
    }
}

impl ContextProvider for SqlContext<'_> {
    fn get_table_source(&self, name: TableReference) -> EngineResult<Arc<dyn TableSource>> {
        let schema = match name {
            TableReference::Bare { table } => self.relations.get(table.as_ref()),
            _ => None,
        }
        .ok_or_else(|| datafusion::common::DataFusionError::Plan("Unknown SQL relation".into()))?;
        Ok(provider_as_source(Arc::new(EmptyTable::new(
            schema.clone(),
        ))))
    }

    fn get_expr_planners(&self) -> &[Arc<dyn datafusion::logical_expr::planner::ExprPlanner>] {
        self.state.expr_planners()
    }
    fn get_function_meta(&self, name: &str) -> Option<Arc<ScalarUDF>> {
        self.state.scalar_functions().get(name).cloned()
    }
    fn get_aggregate_meta(&self, name: &str) -> Option<Arc<AggregateUDF>> {
        self.state.aggregate_functions().get(name).cloned()
    }
    fn get_window_meta(&self, name: &str) -> Option<Arc<WindowUDF>> {
        self.state.window_functions().get(name).cloned()
    }
    fn get_variable_type(&self, _: &[String]) -> Option<datafusion::arrow::datatypes::DataType> {
        None
    }
    fn options(&self) -> &datafusion::common::config::ConfigOptions {
        self.state.config_options()
    }
    fn udf_names(&self) -> Vec<String> {
        self.state.scalar_functions().keys().cloned().collect()
    }
    fn udaf_names(&self) -> Vec<String> {
        self.state.aggregate_functions().keys().cloned().collect()
    }
    fn udwf_names(&self) -> Vec<String> {
        self.state.window_functions().keys().cloned().collect()
    }
}

struct SqlPolicy<'a> {
    relations: &'a BTreeMap<String, SchemaRef>,
    aggregate: bool,
    clocks: usize,
    depth: usize,
    dependencies: BTreeSet<String>,
}

impl SqlPolicy<'_> {
    fn invalid(field: &'static str) -> crate::Error {
        crate::QueryInvalidSnafu { field }.build()
    }

    fn identifier(name: &Ident) -> Result<String> {
        let folded = name.value.to_ascii_lowercase();
        if folded.is_empty() || folded.len() > 256 || folded.starts_with("__araphor_") {
            return Err(Self::invalid("SQL name"));
        }
        Ok(if name.quote_style.is_some() {
            name.value.clone()
        } else {
            folded
        })
    }

    fn name(name: &ObjectName) -> Result<String> {
        let [part] = name.0.as_slice() else {
            return Err(Self::invalid("SQL name"));
        };
        Self::identifier(part.as_ident().ok_or_else(|| Self::invalid("SQL name"))?)
    }

    fn query(&mut self, query: &mut Query, inherited: &BTreeSet<String>) -> Result<()> {
        self.depth += 1;
        if self.depth > AST_DEPTH
            || !query.locks.is_empty()
            || query.for_clause.is_some()
            || query.settings.is_some()
            || query.format_clause.is_some()
            || query.fetch.is_some()
            || !query.pipe_operators.is_empty()
        {
            return Err(Self::invalid("SQL shape"));
        }
        let mut scope = inherited.clone();
        if let Some(with) = &mut query.with {
            if with.recursive {
                return Err(Self::invalid("recursive SQL"));
            }
            for cte in &mut with.cte_tables {
                if cte.from.is_some() || cte.materialized.is_some() {
                    return Err(Self::invalid("SQL CTE"));
                }
                let name = Self::alias(&cte.alias)?;
                self.query(&mut cte.query, &scope)?;
                scope.insert(name);
            }
        }
        self.body(&mut query.body, &scope)?;
        if let Some(order) = &mut query.order_by {
            let OrderByKind::Expressions(items) = &mut order.kind else {
                return Err(Self::invalid("SQL ordering"));
            };
            if order.interpolate.is_some() {
                return Err(Self::invalid("SQL ordering"));
            }
            for item in items {
                Self::order(item)?;
                self.expression(&mut item.expr, &BTreeMap::new())?;
            }
        }
        if let Some(limit) = &query.limit_clause {
            let LimitClause::LimitOffset {
                limit,
                offset,
                limit_by,
            } = limit
            else {
                return Err(Self::invalid("SQL limit"));
            };
            if !limit_by.is_empty()
                || limit
                    .as_ref()
                    .is_some_and(|value| Self::integer(value).is_none())
                || offset
                    .as_ref()
                    .is_some_and(|value| Self::integer(&value.value).is_none())
            {
                return Err(Self::invalid("SQL limit"));
            }
        }
        self.depth -= 1;
        Ok(())
    }

    fn body(&mut self, body: &mut SetExpr, scope: &BTreeSet<String>) -> Result<()> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return Err(Self::invalid("SQL depth"));
        }
        match body {
            SetExpr::Select(select) => self.select(select, scope)?,
            SetExpr::Query(query) => self.query(query, scope)?,
            SetExpr::SetOperation {
                left,
                right,
                set_quantifier: SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
                ..
            } => {
                self.aggregate = true;
                self.body(left, scope)?;
                self.body(right, scope)?;
            }
            _ => return Err(Self::invalid("SQL body")),
        }
        self.depth -= 1;
        Ok(())
    }

    fn select(&mut self, select: &mut Select, scope: &BTreeSet<String>) -> Result<()> {
        if select.into.is_some()
            || select.optimizer_hint.is_some()
            || select.select_modifiers.is_some()
            || select.top.is_some()
            || select.exclude.is_some()
            || !select.lateral_views.is_empty()
            || select.prewhere.is_some()
            || !select.connect_by.is_empty()
            || !select.cluster_by.is_empty()
            || !select.distribute_by.is_empty()
            || !select.sort_by.is_empty()
            || select.qualify.is_some()
            || select.value_table_mode.is_some()
            || !matches!(select.flavor, SelectFlavor::Standard)
            || matches!(select.distinct, Some(Distinct::On(_)))
            || select.from.len() > 1
        {
            return Err(Self::invalid("SQL select"));
        }
        let mut aliases = BTreeSet::new();
        for source in &mut select.from {
            if !aliases.insert(self.table(&mut source.relation, scope)?) {
                return Err(Self::invalid("SQL alias"));
            }
            for join in &mut source.joins {
                if join.global {
                    return Err(Self::invalid("SQL join"));
                }
                let right = self.table(&mut join.relation, scope)?;
                if !aliases.insert(right.clone()) {
                    return Err(Self::invalid("SQL alias"));
                }
                let constraint = match &mut join.join_operator {
                    JoinOperator::Join(value)
                    | JoinOperator::Inner(value)
                    | JoinOperator::Left(value)
                    | JoinOperator::LeftOuter(value)
                    | JoinOperator::Right(value)
                    | JoinOperator::RightOuter(value)
                    | JoinOperator::FullOuter(value) => value,
                    _ => return Err(Self::invalid("SQL join")),
                };
                let JoinConstraint::On(expr) = constraint else {
                    return Err(Self::invalid("SQL join"));
                };
                self.expression(expr, &BTreeMap::new())?;
                if !Self::join_shape(expr, &right, &aliases) {
                    return Err(Self::invalid("SQL join"));
                }
            }
        }
        let mut windows = BTreeMap::new();
        for window in &mut select.named_window {
            let NamedWindowExpr::WindowSpec(spec) = &mut window.1 else {
                return Err(Self::invalid("SQL window"));
            };
            Expression::window(spec)?;
            for expr in spec
                .partition_by
                .iter_mut()
                .chain(spec.order_by.iter_mut().map(|item| &mut item.expr))
            {
                self.expression(expr, &BTreeMap::new())?;
            }
            if windows
                .insert(Self::identifier(&window.0)?, spec.clone())
                .is_some()
            {
                return Err(Self::invalid("SQL window"));
            }
        }
        if select.projection.is_empty() || select.projection.len() > 256 {
            return Err(Self::invalid("SQL projection"));
        }
        for item in &mut select.projection {
            match item {
                SelectItem::Wildcard(options) => Self::wildcard(options)?,
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    options,
                ) => {
                    Self::name(name)?;
                    Self::wildcard(options)?;
                }
                SelectItem::UnnamedExpr(expr) => self.expression(expr, &windows)?,
                SelectItem::ExprWithAlias { expr, alias } => {
                    Self::identifier(alias)?;
                    self.expression(expr, &windows)?;
                }
                _ => return Err(Self::invalid("SQL projection")),
            }
        }
        if let Some(expr) = &mut select.selection {
            self.expression(expr, &windows)?;
        }
        match &mut select.group_by {
            GroupByExpr::Expressions(items, modifiers) if modifiers.is_empty() => {
                for expr in items {
                    self.expression(expr, &windows)?;
                }
            }
            _ => return Err(Self::invalid("SQL grouping")),
        }
        if let Some(expr) = &mut select.having {
            self.expression(expr, &windows)?;
        }
        Ok(())
    }

    fn table(&mut self, table: &mut TableFactor, scope: &BTreeSet<String>) -> Result<String> {
        match table {
            TableFactor::Table {
                name,
                alias,
                args: None,
                with_hints,
                version: None,
                with_ordinality: false,
                partitions,
                json_path: None,
                sample: None,
                index_hints,
            } if with_hints.is_empty() && partitions.is_empty() && index_hints.is_empty() => {
                let name = Self::name(name)?;
                if !scope.contains(&name) {
                    if !self.relations.contains_key(&name) {
                        return Err(Self::invalid("SQL relation"));
                    }
                    self.dependencies.insert(name.clone());
                }
                alias
                    .as_ref()
                    .map(Self::alias)
                    .transpose()
                    .map(|alias| alias.unwrap_or(name))
            }
            TableFactor::Derived {
                lateral: false,
                subquery,
                alias: Some(alias),
                sample: None,
            } => {
                let name = Self::alias(alias)?;
                self.query(subquery, scope)?;
                Ok(name)
            }
            _ => Err(Self::invalid("SQL relation")),
        }
    }

    fn alias(alias: &TableAlias) -> Result<String> {
        for column in &alias.columns {
            if column.data_type.is_some() {
                return Err(Self::invalid("SQL alias"));
            }
            Self::identifier(&column.name)?;
        }
        Self::identifier(&alias.name)
    }

    fn expression(
        &mut self,
        expr: &mut Expr,
        windows: &BTreeMap<String, WindowSpec>,
    ) -> Result<()> {
        let mut check = Expression {
            windows,
            aggregate: false,
            clocks: 0,
            depth: 0,
        };
        if let ControlFlow::Break(error) = expr.visit(&mut check) {
            return Err(error);
        }
        self.aggregate |= check.aggregate;
        self.clocks += check.clocks;
        Ok(())
    }

    fn join_shape(expr: &Expr, right: &str, aliases: &BTreeSet<String>) -> bool {
        match expr {
            Expr::Nested(expr) => Self::join_shape(expr, right, aliases),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right: other,
            } => Self::join_shape(left, right, aliases) && Self::join_shape(other, right, aliases),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right: other,
            } => {
                let qualifier = |mut expr: &Expr| {
                    while let Expr::Nested(inner) = expr {
                        expr = inner;
                    }
                    match expr {
                        Expr::Identifier(_) => Some(None),
                        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
                            Self::identifier(&parts[0]).ok().map(Some)
                        }
                        _ => None,
                    }
                };
                match (qualifier(left), qualifier(other)) {
                    (Some(Some(left)), Some(Some(other))) => {
                        aliases.contains(&left)
                            && aliases.contains(&other)
                            && ((left == right) != (other == right))
                    }
                    (Some(Some(name)), Some(None)) | (Some(None), Some(Some(name))) => {
                        aliases.contains(&name)
                    }
                    (Some(None), Some(None)) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn bound(plan: &LogicalPlan) -> Result<()> {
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::Projection(projection) = plan {
                if projection.expr.len() > 256 {
                    return Err(datafusion::common::DataFusionError::Plan(
                        "SQL projection".into(),
                    ));
                }
            }
            if let LogicalPlan::Join(join) = plan {
                if !join.on.is_empty()
                    || !join
                        .filter
                        .as_ref()
                        .is_some_and(|expr| Self::equijoin(expr, join.right.schema()))
                {
                    return Err(datafusion::common::DataFusionError::Plan("SQL join".into()));
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .map(|_| ())
        .map_err(|_| Self::invalid("SQL plan"))
    }

    fn equijoin(expr: &EngineExpression, right: &DFSchema) -> bool {
        match expr {
            EngineExpression::BinaryExpr(binary) if binary.op == Operator::And => {
                Self::equijoin(&binary.left, right) && Self::equijoin(&binary.right, right)
            }
            EngineExpression::BinaryExpr(binary) if binary.op == Operator::Eq => {
                matches!((binary.left.as_ref(), binary.right.as_ref()),
                    (EngineExpression::Column(left), EngineExpression::Column(other))
                    if left.relation != other.relation
                        && (right.has_column(left) != right.has_column(other)))
            }
            _ => false,
        }
    }

    fn wildcard(options: &WildcardAdditionalOptions) -> Result<()> {
        if options.opt_ilike.is_some()
            || options.opt_exclude.is_some()
            || options.opt_except.is_some()
            || options.opt_replace.is_some()
            || options.opt_rename.is_some()
        {
            return Err(Self::invalid("SQL wildcard"));
        }
        Ok(())
    }

    fn order(item: &OrderByExpr) -> Result<()> {
        if item.with_fill.is_some() {
            return Err(Self::invalid("SQL ordering"));
        }
        Ok(())
    }

    fn integer(expr: &Expr) -> Option<u64> {
        let Expr::Value(value) = expr else {
            return None;
        };
        let SqlValue::Number(number, false) = &value.value else {
            return None;
        };
        number.parse().ok()
    }
}

struct Expression<'a> {
    windows: &'a BTreeMap<String, WindowSpec>,
    aggregate: bool,
    clocks: usize,
    depth: usize,
}

impl Expression<'_> {
    fn check(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(name) => {
                SqlPolicy::identifier(name)?;
            }
            Expr::CompoundIdentifier(parts) => {
                if !(1..=2).contains(&parts.len()) {
                    return Err(SqlPolicy::invalid("SQL column"));
                }
                for name in parts {
                    SqlPolicy::identifier(name)?;
                }
            }
            Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::IsDistinctFrom(_, _)
            | Expr::IsNotDistinctFrom(_, _)
            | Expr::InList { .. }
            | Expr::Between { .. }
            | Expr::Nested(_)
            | Expr::Case { .. } => {}
            Expr::Like { any: false, .. } | Expr::ILike { any: false, .. } => {}
            Expr::BinaryOp {
                op:
                    BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
                    | BinaryOperator::Modulo
                    | BinaryOperator::StringConcat
                    | BinaryOperator::Gt
                    | BinaryOperator::Lt
                    | BinaryOperator::GtEq
                    | BinaryOperator::LtEq
                    | BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::And
                    | BinaryOperator::Or,
                ..
            } => {}
            Expr::UnaryOp {
                op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
                ..
            } => {}
            Expr::Cast {
                array: false,
                format: None,
                ..
            } => {}
            Expr::TypedString(value)
                if !value.uses_odbc_syntax
                    && matches!(value.data_type, DataType::Timestamp(_, _) | DataType::Date) => {}
            Expr::Value(value)
                if matches!(
                    value.value,
                    SqlValue::Number(_, false)
                        | SqlValue::SingleQuotedString(_)
                        | SqlValue::Boolean(_)
                        | SqlValue::Null
                        | SqlValue::Placeholder(_)
                ) => {}
            Expr::Interval(value)
                if value.leading_precision.is_none()
                    && value.last_field.is_none()
                    && value.fractional_seconds_precision.is_none()
                    && matches!(value.value.as_ref(), Expr::Value(value) if matches!(value.value, SqlValue::SingleQuotedString(_))) =>
                {}
            Expr::Function(function) => self.function(function)?,
            _ => return Err(SqlPolicy::invalid("SQL expression")),
        }
        Ok(())
    }

    fn function(&mut self, function: &mut Function) -> Result<()> {
        let name = SqlPolicy::name(&function.name)?;
        if function.uses_odbc_syntax
            || !matches!(function.parameters, FunctionArguments::None)
            || !function.within_group.is_empty()
            || function.null_treatment.is_some()
        {
            return Err(SqlPolicy::invalid("SQL function"));
        }
        if FrozenClock::matches(function) {
            self.clocks += 1;
            return Ok(());
        }
        let aggregate = matches!(name.as_str(), "count" | "sum" | "min" | "max" | "avg");
        let window = matches!(
            name.as_str(),
            "lag" | "lead" | "row_number" | "rank" | "dense_rank"
        );
        if !aggregate
            && !window
            && !matches!(
                name.as_str(),
                "coalesce" | "nullif" | "lower" | "upper" | "length" | "abs" | "date_bin"
            )
        {
            return Err(SqlPolicy::invalid("SQL function"));
        }
        let FunctionArguments::List(arguments) = &function.args else {
            return Err(SqlPolicy::invalid("SQL function"));
        };
        if !arguments.clauses.is_empty() || (!aggregate && arguments.duplicate_treatment.is_some())
        {
            return Err(SqlPolicy::invalid("SQL function"));
        }
        let count = arguments.args.len();
        let arity = match name.as_str() {
            "row_number" | "rank" | "dense_rank" => count == 0,
            "coalesce" => count >= 2,
            "nullif" => count == 2,
            "date_bin" => (2..=3).contains(&count),
            "lag" | "lead" => (1..=3).contains(&count),
            _ => count == 1,
        };
        if !arity {
            return Err(SqlPolicy::invalid("SQL function"));
        }
        if name == "date_bin" {
            let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(width))) = arguments.args.first()
            else {
                return Err(SqlPolicy::invalid("SQL bucket width"));
            };
            if TimeTest::fixed_interval(width).is_none() {
                return Err(SqlPolicy::invalid("SQL bucket width"));
            }
        }
        for arg in &arguments.args {
            match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(_)) => {}
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                    if name == "count" && count == 1 && arguments.duplicate_treatment.is_none() => {
                }
                _ => return Err(SqlPolicy::invalid("SQL function")),
            }
        }
        if matches!(name.as_str(), "lag" | "lead") && count > 1 {
            let FunctionArg::Unnamed(FunctionArgExpr::Expr(offset)) = &arguments.args[1] else {
                return Err(SqlPolicy::invalid("SQL window"));
            };
            if !SqlPolicy::integer(offset).is_some_and(|value| value <= 200) {
                return Err(SqlPolicy::invalid("SQL window"));
            }
        }
        if function.filter.is_some() && !aggregate {
            return Err(SqlPolicy::invalid("SQL function"));
        }
        if window && function.over.is_none() {
            return Err(SqlPolicy::invalid("SQL window"));
        }
        if let Some(over) = &function.over {
            if !aggregate && !window {
                return Err(SqlPolicy::invalid("SQL window"));
            }
            let spec = match over {
                WindowType::WindowSpec(spec) => spec,
                WindowType::NamedWindow(name) => self
                    .windows
                    .get(&SqlPolicy::identifier(name)?)
                    .ok_or_else(|| SqlPolicy::invalid("SQL window"))?,
            };
            Self::window(spec)?;
            if aggregate && spec.window_frame.is_none() {
                return Err(SqlPolicy::invalid("SQL window"));
            }
        }
        self.aggregate |= aggregate || window;
        Ok(())
    }

    fn window(spec: &WindowSpec) -> Result<()> {
        if spec.window_name.is_some() || spec.order_by.is_empty() {
            return Err(SqlPolicy::invalid("SQL window"));
        }
        for item in &spec.order_by {
            SqlPolicy::order(item)?;
        }
        if let Some(frame) = &spec.window_frame {
            if frame.units != WindowFrameUnits::Rows
                || !Self::window_bound(&frame.start_bound)
                || frame
                    .end_bound
                    .as_ref()
                    .is_some_and(|bound| !Self::window_bound(bound))
            {
                return Err(SqlPolicy::invalid("SQL window"));
            }
        }
        Ok(())
    }

    fn window_bound(bound: &WindowFrameBound) -> bool {
        match bound {
            WindowFrameBound::CurrentRow => true,
            WindowFrameBound::Preceding(Some(value)) | WindowFrameBound::Following(Some(value)) => {
                SqlPolicy::integer(value).is_some_and(|value| value <= 200)
            }
            _ => false,
        }
    }
}

impl VisitorMut for Expression<'_> {
    type Break = crate::Error;

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return ControlFlow::Break(SqlPolicy::invalid("SQL depth"));
        }
        match self.check(expr) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(error),
        }
    }

    fn post_visit_expr(&mut self, _: &mut Expr) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

struct Parameters {
    used: Vec<bool>,
    next: usize,
    numbered: bool,
    positional: bool,
    depth: usize,
}

impl Parameters {
    fn validate(values: &[Value]) -> Result<()> {
        if values.len() > PARAMETER_COUNT {
            return Err(SqlPolicy::invalid("SQL parameters"));
        }
        let mut bytes = 0_usize;
        for value in values {
            bytes = bytes.saturating_add(std::mem::size_of::<Value>());
            match value {
                Value::Null
                | Value::Boolean(_)
                | Value::TinyInt(_)
                | Value::SmallInt(_)
                | Value::Int(_)
                | Value::BigInt(_)
                | Value::UTinyInt(_)
                | Value::USmallInt(_)
                | Value::UInt(_)
                | Value::UBigInt(_)
                | Value::Timestamp(_, _) => {}
                Value::Float(value) if value.is_finite() => {}
                Value::Double(value) if value.is_finite() => {}
                Value::Text(value) => bytes = bytes.saturating_add(value.len()),
                Value::Blob(value) => bytes = bytes.saturating_add(value.len()),
                _ => return Err(SqlPolicy::invalid("SQL parameter type")),
            }
        }
        if bytes > PARAMETER_BYTES {
            return Err(SqlPolicy::invalid("SQL parameters"));
        }
        Ok(())
    }

    fn bind(query: &mut Query, count: usize) -> Result<()> {
        let mut binding = Self {
            used: vec![false; count],
            next: 0,
            numbered: false,
            positional: false,
            depth: 0,
        };
        if let ControlFlow::Break(error) = query.visit(&mut binding) {
            return Err(error);
        }
        if binding.used.iter().any(|used| !used) || (binding.numbered && binding.positional) {
            return Err(SqlPolicy::invalid("SQL parameters"));
        }
        Ok(())
    }
}

impl VisitorMut for Parameters {
    type Break = crate::Error;

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return ControlFlow::Break(SqlPolicy::invalid("SQL depth"));
        }
        let Expr::Value(value) = expr else {
            return ControlFlow::Continue(());
        };
        let SqlValue::Placeholder(mark) = &mut value.value else {
            return ControlFlow::Continue(());
        };
        let index = if mark == "?" {
            self.positional = true;
            self.next += 1;
            Some(self.next)
        } else {
            self.numbered = true;
            mark.strip_prefix('$')
                .and_then(|value| value.parse::<usize>().ok())
        };
        let Some(index) = index.filter(|index| *index > 0 && *index <= self.used.len()) else {
            return ControlFlow::Break(SqlPolicy::invalid("SQL parameters"));
        };
        self.used[index - 1] = true;
        *mark = format!("${index}");
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, _: &mut Expr) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

struct FrozenClock(usize);

impl FrozenClock {
    fn matches(function: &Function) -> bool {
        SqlPolicy::name(&function.name).is_ok_and(|name| name == "current_timestamp")
            && matches!(function.parameters, FunctionArguments::None)
            && (matches!(function.args, FunctionArguments::None)
                || matches!(&function.args, FunctionArguments::List(args) if args.args.is_empty() && args.clauses.is_empty() && args.duplicate_treatment.is_none()))
            && function.filter.is_none()
            && function.over.is_none()
            && function.within_group.is_empty()
            && function.null_treatment.is_none()
            && !function.uses_odbc_syntax
    }
}

impl VisitorMut for FrozenClock {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        if matches!(expr, Expr::Function(function) if Self::matches(function)) {
            *expr = Expr::Value(SqlValue::Placeholder(format!("${}", self.0)).into());
        }
        ControlFlow::Continue(())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum TimeValue {
    Fixed(i64),
    Moving(u32),
}

#[derive(Clone, Debug, PartialEq)]
struct TimeTest {
    op: BinaryOperator,
    value: TimeValue,
}

impl TimeTest {
    fn direct_events(query: &Query) -> Option<(&Select, String)> {
        let (select, alias, relation) = Self::direct_table(query)?;
        (relation == "events").then_some((select, alias))
    }

    fn direct_table(query: &Query) -> Option<(&Select, String, String)> {
        if query.with.is_some() {
            return None;
        }
        let SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        let [from] = select.from.as_slice() else {
            return None;
        };
        if !from.joins.is_empty() {
            return None;
        }
        let TableFactor::Table { name, alias, .. } = &from.relation else {
            return None;
        };
        let relation = SqlPolicy::name(name).ok()?;
        if alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
        {
            return None;
        }
        Some((
            select,
            alias.as_ref().map_or_else(
                || relation.clone(),
                |alias| SqlPolicy::identifier(&alias.name).unwrap_or_default(),
            ),
            relation,
        ))
    }

    fn extract(query: &Query, parameters: &[Value]) -> Vec<Self> {
        let Some((select, alias)) = Self::direct_events(query) else {
            return Vec::new();
        };
        let mut tests = Vec::new();
        if let Some(expr) = &select.selection {
            Self::predicate(expr, &alias, parameters, &mut tests);
        }
        tests
    }

    fn predicate(expr: &Expr, alias: &str, parameters: &[Value], tests: &mut Vec<Self>) {
        match expr {
            Expr::Nested(expr) => Self::predicate(expr, alias, parameters, tests),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                Self::predicate(left, alias, parameters, tests);
                Self::predicate(right, alias, parameters, tests);
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                let lower = |expr| {
                    let mut branch = Vec::new();
                    Self::predicate(expr, alias, parameters, &mut branch);
                    branch
                        .into_iter()
                        .filter_map(|test| match (test.op, test.value) {
                            (BinaryOperator::GtEq, TimeValue::Fixed(value)) => Some((value, false)),
                            (BinaryOperator::Gt, TimeValue::Fixed(value)) => Some((value, true)),
                            _ => None,
                        })
                        .max()
                };
                if let Some((value, strict)) = lower(left)
                    .zip(lower(right))
                    .map(|(left, right)| left.min(right))
                {
                    tests.push(Self {
                        op: if strict {
                            BinaryOperator::Gt
                        } else {
                            BinaryOperator::GtEq
                        },
                        value: TimeValue::Fixed(value),
                    });
                }
            }
            Expr::BinaryOp { left, op, right }
                if matches!(
                    op,
                    BinaryOperator::Gt
                        | BinaryOperator::GtEq
                        | BinaryOperator::Lt
                        | BinaryOperator::LtEq
                        | BinaryOperator::Eq
                ) =>
            {
                let (value, op) = if Self::column(left, alias) {
                    (right.as_ref(), op.clone())
                } else if Self::column(right, alias) {
                    let op = match op {
                        BinaryOperator::Gt => BinaryOperator::Lt,
                        BinaryOperator::GtEq => BinaryOperator::LtEq,
                        BinaryOperator::Lt => BinaryOperator::Gt,
                        BinaryOperator::LtEq => BinaryOperator::GtEq,
                        _ => BinaryOperator::Eq,
                    };
                    (left.as_ref(), op)
                } else {
                    return;
                };
                if let Some(value) = Self::value(value, parameters) {
                    tests.push(Self { op, value });
                }
            }
            Expr::Between {
                expr,
                negated: false,
                low,
                high,
            } if Self::column(expr, alias) => {
                if let Some(value) = Self::value(low, parameters) {
                    tests.push(Self {
                        op: BinaryOperator::GtEq,
                        value,
                    });
                }
                if let Some(value) = Self::value(high, parameters) {
                    tests.push(Self {
                        op: BinaryOperator::LtEq,
                        value,
                    });
                }
            }
            _ => {}
        }
    }

    fn column(expr: &Expr, alias: &str) -> bool {
        Self::named_column(expr, alias, "received_at")
    }

    fn named_column(expr: &Expr, alias: &str, name: &str) -> bool {
        match expr {
            Expr::Identifier(column) => {
                SqlPolicy::identifier(column).is_ok_and(|column| column == name)
            }
            Expr::CompoundIdentifier(parts) => matches!(parts.as_slice(), [table, column]
                if SqlPolicy::identifier(table).is_ok_and(|table| table == alias)
                    && SqlPolicy::identifier(column).is_ok_and(|column| column == name)),
            _ => false,
        }
    }

    fn value(expr: &Expr, parameters: &[Value]) -> Option<TimeValue> {
        match expr {
            Expr::Nested(expr) => Self::value(expr, parameters),
            Expr::Value(value) => {
                let SqlValue::Placeholder(mark) = &value.value else {
                    return None;
                };
                let index = mark
                    .strip_prefix('$')?
                    .parse::<usize>()
                    .ok()?
                    .checked_sub(1)?;
                match parameters.get(index)? {
                    Value::Timestamp(TimeUnit::Microsecond, value) => {
                        Some(TimeValue::Fixed(*value))
                    }
                    _ => None,
                }
            }
            Expr::TypedString(value)
                if matches!(
                    value.data_type,
                    DataType::Timestamp(None, TimezoneInfo::None)
                ) && !value.uses_odbc_syntax =>
            {
                let SqlValue::SingleQuotedString(value) = &value.value.value else {
                    return None;
                };
                Self::timestamp(value).map(TimeValue::Fixed)
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Minus,
                right,
            } if matches!(left.as_ref(), Expr::Function(function) if FrozenClock::matches(function)) => {
                Self::seconds(right).map(TimeValue::Moving)
            }
            _ => None,
        }
    }

    fn seconds(expr: &Expr) -> Option<u32> {
        let Expr::Interval(interval) = expr else {
            return None;
        };
        if interval.leading_precision.is_some()
            || interval.last_field.is_some()
            || interval.fractional_seconds_precision.is_some()
        {
            return None;
        }
        let Expr::Value(value) = interval.value.as_ref() else {
            return None;
        };
        let SqlValue::SingleQuotedString(value) = &value.value else {
            return None;
        };
        let parts: Vec<_> = value.split_whitespace().collect();
        let value = match (interval.leading_field.as_ref(), parts.as_slice()) {
            (Some(DateTimeField::Second), [value]) => value,
            (None, [value, unit])
                if unit.eq_ignore_ascii_case("second") || unit.eq_ignore_ascii_case("seconds") =>
            {
                value
            }
            _ => return None,
        };
        let seconds = value.parse::<u32>().ok()?;
        (1..=86_400).contains(&seconds).then_some(seconds)
    }

    fn fixed_interval(expr: &Expr) -> Option<i64> {
        let Expr::Interval(interval) = expr else {
            return None;
        };
        if interval.leading_precision.is_some()
            || interval.last_field.is_some()
            || interval.fractional_seconds_precision.is_some()
        {
            return None;
        }
        let Expr::Value(value) = interval.value.as_ref() else {
            return None;
        };
        let SqlValue::SingleQuotedString(value) = &value.value else {
            return None;
        };
        let parts: Vec<_> = value.split_whitespace().collect();
        let (number, unit) = match (interval.leading_field.as_ref(), parts.as_slice()) {
            (None, [number, unit]) => (
                *number,
                unit.to_ascii_lowercase().trim_end_matches('s').to_owned(),
            ),
            (Some(unit), [number]) => (*number, unit.to_string().to_ascii_lowercase()),
            _ => return None,
        };
        let scale = match unit.as_str() {
            "microsecond" => 1_u64,
            "millisecond" => 1_000,
            "second" => 1_000_000,
            "minute" => 60_000_000,
            "hour" => 3_600_000_000,
            "day" => 86_400_000_000,
            _ => return None,
        };
        number
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .and_then(|number| number.checked_mul(scale))
            .and_then(|micros| i64::try_from(micros).ok())
    }

    fn timestamp(value: &str) -> Option<i64> {
        let value = value
            .strip_suffix('Z')
            .or_else(|| value.strip_suffix("+00:00"))
            .unwrap_or(value);
        let value = value.replacen('T', " ", 1);
        let (whole, fraction) = value
            .split_once('.')
            .map_or((value.as_str(), ""), |parts| parts);
        if fraction.len() > 6 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let format = time::format_description::parse_borrowed::<2>(
            "[year]-[month]-[day] [hour]:[minute]:[second]",
        )
        .ok()?;
        let parsed = PrimitiveDateTime::parse(whole, &format).ok()?;
        let micros = parsed.assume_utc().unix_timestamp_nanos() / 1_000;
        let fraction = if fraction.is_empty() {
            0
        } else {
            i128::from(fraction.parse::<u32>().ok()?) * 10_i128.pow(6 - fraction.len() as u32)
        };
        i64::try_from(micros + fraction).ok()
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(test)]
mod engine_tests {
    use super::*;
    use datafusion::arrow::datatypes::DataType as ArrowType;

    #[test]
    fn retained_clock_parameter() -> Result<()> {
        let sql = QuerySql::admit(
            "SELECT CAST(? AS BIGINT) AS value, CURRENT_TIMESTAMP AS clock",
            vec![Value::BigInt(7)],
            false,
        )?;
        let fields = sql
            .program
            .plan
            .get_parameter_fields()
            .map_err(|_| SqlPolicy::invalid("test plan"))?;
        assert_eq!(fields.len(), 2);
        assert_eq!(
            fields["$2"].as_ref().map(|field| field.data_type()),
            Some(&ArrowType::Timestamp(
                datafusion::arrow::datatypes::TimeUnit::Microsecond,
                None,
            ))
        );
        for (now, micros) in [(1_001, 1), (2_001, 2)] {
            let binding = sql.bind_complete(now)?;
            assert_eq!(
                binding.parameters,
                vec![
                    Value::BigInt(7),
                    Value::Timestamp(TimeUnit::Microsecond, micros)
                ]
            );
            assert!(Arc::ptr_eq(&binding.plan, &sql.program.plan));
            assert!(binding
                .plan()?
                .get_parameter_names()
                .map_err(|_| SqlPolicy::invalid("test plan"))?
                .is_empty());
        }
        assert_eq!(
            sql.program
                .plan
                .get_parameter_names()
                .map_err(|_| SqlPolicy::invalid("test plan"))?
                .len(),
            2
        );
        let fixed = QuerySql::admit("SELECT 1 AS value", Vec::new(), false)?;
        assert!(fixed
            .program
            .plan
            .get_parameter_names()
            .map_err(|_| SqlPolicy::invalid("test plan"))?
            .is_empty());
        assert!(fixed.bind_complete(1)?.parameters.is_empty());
        Ok(())
    }

    #[test]
    fn retained_append_projection() -> Result<()> {
        let sql = QuerySql::admit("SELECT operation FROM events", Vec::new(), false)?;
        assert_eq!(sql.program.plan.schema().fields().len(), 1);
        let appended = sql.bind_at(1)?;
        let plan = appended.plan()?;
        assert!(matches!(&plan, LogicalPlan::Sort(_)));
        assert_eq!(plan.schema().fields().len(), 3);
        assert_eq!(plan.schema().field(1).name(), POSITION_FIELDS[0]);
        assert_eq!(plan.schema().field(2).name(), POSITION_FIELDS[1]);
        assert_eq!(sql.bind_complete(1)?.plan()?.schema().fields().len(), 1);
        assert_eq!(sql.program.plan.schema().fields().len(), 1);
        Ok(())
    }

    #[test]
    fn retained_source_metadata() -> Result<()> {
        for query in [
            "SELECT operation + 1 AS operation FROM events ORDER BY source_cursor",
            "SELECT operation + 1 AS operation FROM events LIMIT 1",
            "WITH t AS (SELECT operation FROM events) SELECT operation FROM t",
        ] {
            assert!(QuerySql::admit(query, Vec::new(), false)?
                .source_column("operation")
                .is_none());
        }
        assert!(QuerySql::admit(
            "SELECT operation FROM events ORDER BY source_cursor",
            Vec::new(),
            false
        )?
        .source_column("operation")
        .is_some());
        let sql = QuerySql::admit(
            r#"SELECT operation AS "Pick", source_cursor AS "pick" FROM events"#,
            Vec::new(),
            false,
        )?;
        for (name, expected) in [("Pick", "operation"), ("pick", "source_cursor")] {
            let (schema, index) = sql
                .source_column(name)
                .ok_or_else(|| SqlPolicy::invalid("test source metadata"))?;
            assert_eq!(schema.fields()[index].name(), expected);
        }
        assert!(sql.source_column("PICK").is_none());
        Ok(())
    }

    #[test]
    fn retained_plan_field_metadata() -> Result<()> {
        let metadata = std::collections::HashMap::from([("unit".into(), "source".into())]);
        let schema = Arc::new(Schema::new_with_metadata(
            vec![Field::new("value", ArrowType::Int64, false).with_metadata(metadata.clone())],
            std::collections::HashMap::from([("dataset".into(), "data".into())]),
        ));
        for query in [
            "SELECT value FROM data",
            "WITH t(picked) AS (SELECT value FROM data) SELECT picked FROM t",
            "SELECT value FROM data UNION ALL SELECT value FROM data",
            "SELECT SUM(value) AS total FROM data",
        ] {
            let sql = QuerySql::admit_relations(
                query,
                BTreeMap::from([("data".into(), schema.clone())]),
            )?;
            sql.program
                .plan
                .apply(|plan| {
                    assert_eq!(plan.schema().metadata(), schema.metadata(), "{query}");
                    assert!(
                        plan.schema()
                            .fields()
                            .iter()
                            .all(|field| { !field.metadata().contains_key("__araphor_sql_name") }),
                        "{query}"
                    );
                    if let LogicalPlan::TableScan(scan) = plan {
                        assert_eq!(scan.source.schema().as_ref(), schema.as_ref(), "{query}");
                    }
                    for expr in plan.expressions() {
                        expr.apply(|expr| {
                            if let EngineExpression::Alias(alias) = expr {
                                assert!(
                                    !alias.metadata.as_ref().is_some_and(|metadata| {
                                        metadata.inner().contains_key("__araphor_sql_name")
                                    }),
                                    "{query}"
                                );
                            }
                            Ok(TreeNodeRecursion::Continue)
                        })?;
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .map_err(|_| SqlPolicy::invalid("test plan"))?;
            if !query.contains("SUM") {
                assert_eq!(
                    sql.program.plan.schema().field(0).metadata(),
                    &metadata,
                    "{query}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn retained_schema_charge() -> Result<()> {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            ArrowType::Int64,
            false,
        )
        .with_metadata(std::collections::HashMap::from([(
            "payload".into(),
            "x".repeat(100_000),
        )]))]));
        let sql = QuerySql::admit_relations(
            "SELECT value FROM data",
            BTreeMap::from([("data".into(), schema)]),
        )?;
        assert!(sql.allocated_bytes() >= 100_000);
        Ok(())
    }

    #[test]
    fn nested_cte_scope() -> Result<()> {
        assert!(QuerySql::admit("WITH t AS (SELECT operation FROM events) SELECT operation FROM (WITH t AS (SELECT operation FROM events) SELECT operation FROM t) x", Vec::new(), false).is_err());
        let sql = QuerySql::admit("WITH t AS (SELECT operation FROM events) SELECT operation FROM (WITH inner_t AS (SELECT operation FROM t) SELECT operation FROM inner_t) x", Vec::new(), false)?;
        assert_eq!(sql.dependencies(), &BTreeSet::from(["events".to_owned()]));
        assert_eq!(
            sql.bind_complete(0)?.plan()?.schema().field(0).data_type(),
            &ArrowType::UInt32
        );
        Ok(())
    }

    #[test]
    fn full_query_policy_before_pruning() -> Result<()> {
        let relations = BTreeMap::from([
            (
                "events".to_owned(),
                SCHEMAS
                    .iter()
                    .find(|schema| schema.name == "events")
                    .ok_or_else(|| SqlPolicy::invalid("test event schema"))?
                    .arrow_schema(),
            ),
            (
                "data".to_owned(),
                Arc::new(Schema::new(vec![
                    Field::new("value", ArrowType::Int64, false),
                    Field::new("cursor", ArrowType::UInt64, false),
                ])),
            ),
        ]);
        let query = "WITH unused AS (SELECT operation FROM events), t(alias_name, cursor) AS (SELECT value, cursor FROM data) SELECT d.inner_name AS \"Pick\", d.cursor FROM (WITH inner_t(inner_name, cursor) AS (SELECT alias_name, cursor FROM t) SELECT inner_name, cursor FROM inner_t WINDOW unused AS (ORDER BY missing)) d WHERE false";
        let sql = QuerySql::admit_relations(query, relations.clone())?;
        assert_eq!(
            sql.dependencies(),
            &BTreeSet::from(["data".to_owned(), "events".to_owned()])
        );
        let binding = sql.bind_complete(0)?;
        assert_eq!(binding.plan.schema().field(0).name(), "Pick");
        assert_eq!(binding.plan.schema().field(1).name(), "cursor");
        let plan = QueryEngine::state()?
            .optimize(&binding.plan)
            .map_err(|_| SqlPolicy::invalid("test optimized plan"))?;
        let mut scans = 0;
        plan.apply(|plan| {
            scans += usize::from(matches!(plan, LogicalPlan::TableScan(_)));
            Ok(TreeNodeRecursion::Continue)
        })
        .map_err(|_| SqlPolicy::invalid("test optimized sources"))?;
        assert_eq!(scans, 0);
        assert!(QuerySql::admit_relations(
            &query.replace("ORDER BY missing", "ORDER BY random()"),
            relations,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn quoted_names_and_labels() -> Result<()> {
        let sql = QuerySql::admit(
            r#"SELECT "E"."operation" AS "Pick" FROM "events" AS "E""#,
            Vec::new(),
            false,
        )?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().field(0).name(), "Pick");
        for query in [
            r#"SELECT "E"."operation" FROM "EVENTS" AS "E""#,
            r#"SELECT "E"."Operation" FROM "events" AS "E""#,
        ] {
            assert!(
                QuerySql::admit(query, Vec::new(), false).is_err(),
                "{query}"
            );
        }
        Ok(())
    }

    #[test]
    fn visible_index_and_partial_alias() -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("value", ArrowType::Int64, false),
            Field::new("__row_index", ArrowType::UInt64, false),
        ]));
        let sources = BTreeMap::from([("data".to_owned(), schema)]);
        let sql = QuerySql::admit_relations(
            "SELECT a.*, b.__row_index AS right_index FROM data a JOIN data b ON a.value = b.value",
            sources,
        )?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().fields().len(), 3);
        assert_eq!(plan.schema().field(0).name(), "value");
        assert_eq!(plan.schema().field(1).name(), "__row_index");
        assert_eq!(plan.schema().field(2).name(), "right_index");
        assert!(QuerySql::admit("WITH t(first) AS (SELECT operation, source_cursor FROM events) SELECT first, source_cursor FROM t", Vec::new(), false).is_err());
        let sql = QuerySql::admit("WITH t(first, second) AS (SELECT operation, source_cursor FROM events) SELECT first, second FROM t", Vec::new(), false)?;
        assert_eq!(sql.bind_complete(0)?.plan()?.schema().fields().len(), 2);
        Ok(())
    }

    #[test]
    fn wildcard_index_before_grouping() -> Result<()> {
        for index in [false, true] {
            let mut fields = vec![Field::new("value", ArrowType::Int64, false)];
            if index {
                fields.push(Field::new("__row_index", ArrowType::UInt64, false));
            }
            let sources = BTreeMap::from([("data".to_owned(), Arc::new(Schema::new(fields)))]);
            let result =
                QuerySql::admit_relations("SELECT * FROM data GROUP BY value", sources.clone());
            if index {
                assert!(result.is_err());
                let sql = QuerySql::admit_relations(
                    "SELECT * FROM data GROUP BY value, __row_index",
                    sources,
                )?;
                assert_eq!(sql.bind_complete(0)?.plan()?.schema().fields().len(), 2);
            } else {
                let plan = result?.bind_complete(0)?.plan()?;
                assert_eq!(plan.schema().fields().len(), 1);
                assert_eq!(plan.schema().field(0).name(), "value");
            }
        }
        Ok(())
    }

    #[test]
    fn declared_field_names() -> Result<()> {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "CamelCase",
            ArrowType::Int64,
            false,
        )]));
        let relations = BTreeMap::from([("data".to_owned(), schema)]);
        for (query, expected) in [
            (r#"SELECT "CamelCase" FROM data"#, "CamelCase"),
            (r#"SELECT "CamelCase" AS InnerName FROM data"#, "innername"),
            (
                r#"SELECT "CamelCase" AS "InnerName" FROM data"#,
                "InnerName",
            ),
            (
                r#"WITH t AS (SELECT "CamelCase" AS innername FROM data) SELECT innername FROM t"#,
                "innername",
            ),
            (
                r#"WITH t(AliasName) AS (SELECT "CamelCase" AS value FROM data) SELECT aliasname FROM t"#,
                "aliasname",
            ),
            (
                r#"WITH t("AliasName") AS (SELECT "CamelCase" AS value FROM data) SELECT "AliasName" FROM t"#,
                "AliasName",
            ),
            (
                r#"SELECT q.aliasname FROM (SELECT "CamelCase" AS value FROM data) q(AliasName)"#,
                "aliasname",
            ),
        ] {
            let sql = QuerySql::admit_relations(query, relations.clone())?;
            assert_eq!(
                sql.bind_complete(0)?.plan()?.schema().field(0).name(),
                expected,
                "{query}"
            );
        }
        for query in [
            "SELECT camelcase FROM data",
            "SELECT aliasname FROM data d(AliasName)",
        ] {
            assert!(
                QuerySql::admit_relations(query, relations.clone()).is_err(),
                "{query}"
            );
        }
        Ok(())
    }

    #[test]
    fn division_types() -> Result<()> {
        for (query, expected) in [
            ("SELECT 3 / 2 AS value", ArrowType::Int64),
            (
                "SELECT CAST(3 AS FLOAT) / CAST(2 AS FLOAT) AS value",
                ArrowType::Float32,
            ),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let plan = sql.bind_complete(0)?.plan()?;
            assert_eq!(plan.schema().field(0).data_type(), &expected);
        }
        Ok(())
    }

    #[test]
    fn literal_types() -> Result<()> {
        for (query, expected) in [
            (
                "SELECT CAST(1 AS TINYINT UNSIGNED) AS value",
                ArrowType::UInt8,
            ),
            (
                "SELECT CAST(1 AS SMALLINT UNSIGNED) AS value",
                ArrowType::UInt16,
            ),
            (
                "SELECT CAST(1 AS INTEGER UNSIGNED) AS value",
                ArrowType::UInt32,
            ),
            (
                "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
                ArrowType::UInt64,
            ),
            (
                "SELECT CAST('1970-01-01' AS TIMESTAMP(6)) AS value",
                ArrowType::Timestamp(datafusion::arrow::datatypes::TimeUnit::Microsecond, None),
            ),
            ("SELECT 1.5 AS value", ArrowType::Float64),
            ("SELECT 1e3 AS value", ArrowType::Float64),
            ("SELECT 9223372036854775808 AS value", ArrowType::UInt64),
            (
                "SELECT 170141183460469231731687303715884105727 AS value",
                ArrowType::Float64,
            ),
            (
                "SELECT -170141183460469231731687303715884105728 AS value",
                ArrowType::Float64,
            ),
            ("SELECT -9223372036854775808 AS value", ArrowType::Int64),
            (
                "SELECT 1 AS value UNION ALL SELECT 2 AS value",
                ArrowType::Int64,
            ),
            (
                "SELECT CAST('1' AS DECIMAL(20, 0)) AS value",
                ArrowType::Decimal128(20, 0),
            ),
            (
                "SELECT TIMESTAMP '1970-01-01 00:00:00' AS value",
                ArrowType::Timestamp(datafusion::arrow::datatypes::TimeUnit::Nanosecond, None),
            ),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            assert_eq!(
                sql.bind_complete(0)?.plan()?.schema().field(0).data_type(),
                &expected,
                "{query}"
            );
        }
        assert!(QuerySql::admit("SELECT CAST('1' AS HUGEINT)", Vec::new(), false).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_alias_names() -> Result<()> {
        for query in [
            "SELECT SUM(1) AS value",
            "SELECT SUM(operation + 1) AS value FROM events",
            "SELECT lag(1) OVER (ORDER BY source_cursor) AS value FROM events",
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            assert_eq!(
                sql.bind_complete(0)?.plan()?.schema().field(0).name(),
                "value"
            );
        }
        Ok(())
    }

    #[test]
    fn grouped_having_aliases() -> Result<()> {
        assert!(matches!(
            QuerySql::admit(
                "SELECT operation AS source_cursor, COUNT(*) AS amount FROM events GROUP BY operation HAVING source_cursor > 1 ORDER BY source_cursor",
                Vec::new(), false,
            ),
            Err(crate::Error::QueryInvalid { field: "SQL binding", .. })
        ));
        for query in [
            "SELECT operation AS source_cursor, COUNT(*) AS amount FROM events GROUP BY operation HAVING events.operation > 1 ORDER BY source_cursor",
            "SELECT COUNT(*) AS operation FROM events GROUP BY operation HAVING operation = 2 ORDER BY 1",
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            sql.bind_complete(0)?;
        }
        Ok(())
    }

    #[test]
    fn native_bucket_type() -> Result<()> {
        for (query, expected) in [
            (
                "SELECT date_bin(INTERVAL '1 day', TIMESTAMP '2000-01-03 00:00:00') AS value",
                datafusion::arrow::datatypes::TimeUnit::Nanosecond,
            ),
            (
                "SELECT date_bin(INTERVAL '1 day', received_at) AS value FROM events",
                datafusion::arrow::datatypes::TimeUnit::Microsecond,
            ),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            assert_eq!(
                sql.bind_complete(0)?.plan()?.schema().field(0).data_type(),
                &ArrowType::Timestamp(expected, None)
            );
        }
        assert!(QuerySql::admit(
            "SELECT time_bucket(INTERVAL '1 day', TIMESTAMP '2000-01-03 00:00:00')",
            Vec::new(),
            false
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn parameter_projection_type() -> Result<()> {
        let sql = QuerySql::admit("SELECT $1 AS value", vec![Value::Int(7)], false)?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().field(0).data_type(), &ArrowType::Int32);
        let sql = QuerySql::admit("SELECT $1 AS value", vec![Value::BigInt(7)], false)?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().field(0).data_type(), &ArrowType::Int64);
        let sql = QuerySql::admit("SELECT 7 AS value", Vec::new(), false)?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().field(0).data_type(), &ArrowType::Int64);
        Ok(())
    }

    #[test]
    fn computed_output_names() -> Result<()> {
        for (query, expected) in [
            ("SELECT 1, NULL, true, 1e3", vec!["Int64(1)", "NULL", "Boolean(true)", "Float64(1000)"]),
            ("SELECT operation + 1, length(node_id) FROM events", vec!["events.operation + Int64(1)", "length(events.node_id)"]),
            ("SELECT COUNT(*), SUM(operation) FROM events", vec!["count(*)", "sum(events.operation)"]),
            ("SELECT CAST('1.5' AS DECIMAL(20, 0))", vec!["Utf8(\"1.5\")"]),
            ("SELECT row_number() OVER (ORDER BY source_cursor) FROM events", vec!["row_number() ORDER BY [events.source_cursor ASC NULLS LAST] RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"]),
            ("SELECT lag(operation) OVER w FROM events WINDOW w AS (ORDER BY source_cursor)", vec!["lag(events.operation) ORDER BY [events.source_cursor ASC NULLS LAST] RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"]),
            ("SELECT current_timestamp", vec!["$1"]),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let binding = sql.bind_complete(123_000)?;
            assert_eq!(binding.plan.schema().fields().iter().map(|field| field.name().as_str()).collect::<Vec<_>>(), expected, "{query}");
        }
        assert!(QuerySql::admit("SELECT 1, 1", Vec::new(), false).is_err());
        let sql = QuerySql::admit("SELECT 1 AS first, 1 AS second", Vec::new(), false)?;
        assert_eq!(sql.program.plan.schema().fields().len(), 2);
        assert!(QuerySql::admit("SELECT now()", Vec::new(), false).is_err());
        Ok(())
    }

    #[test]
    fn trusted_wildcard_schema() -> Result<()> {
        let binding = QueryBinding::trusted("SELECT * FROM events".into(), Vec::new(), 0)?;
        let schema = SCHEMAS
            .iter()
            .find(|schema| schema.name == "events")
            .ok_or_else(|| SqlPolicy::invalid("test schema"))?
            .arrow_schema();
        assert_eq!(binding.plan()?.schema().as_arrow(), schema.as_ref());
        Ok(())
    }

    #[test]
    fn result_numeric_widths() -> Result<()> {
        for (query, expected) in [
            ("SELECT length(node_id) AS value FROM events", ArrowType::Int32),
            ("SELECT rank() OVER (ORDER BY source_cursor) AS value FROM events", ArrowType::UInt64),
            ("SELECT dense_rank() OVER (ORDER BY source_cursor) AS value FROM events", ArrowType::UInt64),
            ("SELECT SUM(operation) AS value FROM events", ArrowType::UInt64),
            ("SELECT SUM(CAST(operation AS DECIMAL(20, 0))) AS value FROM events", ArrowType::Decimal128(30, 0)),
            ("SELECT SUM(CAST(operation AS FLOAT)) AS value FROM events", ArrowType::Float64),
            ("SELECT SUM(CAST(true AS BIGINT)) AS value", ArrowType::Int64),
            ("SELECT SUM(operation) OVER (ORDER BY source_cursor ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS value FROM events", ArrowType::UInt64),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            assert_eq!(sql.bind_complete(0)?.plan()?.schema().field(0).data_type(), &expected, "{query}");
        }
        assert!(QuerySql::admit("SELECT SUM(true) AS value", Vec::new(), false).is_err());
        Ok(())
    }

    #[test]
    fn native_sum_execution() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use datafusion::arrow::array::{Decimal128Array, Int64Array};
        use datafusion::datasource::MemTable;
        use duckdb::core::LogicalTypeId;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            ArrowType::Int64,
            false,
        )]));
        let relations = BTreeMap::from([("data".to_owned(), schema.clone())]);
        let budget = crate::query::budget::QueryBudget::new(crate::query::QueryLimits::default());
        let lease = budget.evaluate([1; 16])?;
        let batch = datafusion::arrow::record_batch::RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int64Array::from(vec![i64::MAX, i64::MAX]))],
        )?;
        let tables = BTreeMap::from([(
            "data".to_owned(),
            Arc::new(MemTable::try_new(
                schema,
                vec![vec![lease.retain_batch(&batch)?]],
            )?),
        )]);
        let engine = QueryEngine::default();
        let state = QueryEngine::state()?;
        let control = crate::AnalysisReadControl::with_timeout(std::time::Duration::from_secs(5))?;
        let sql =
            QuerySql::admit_relations("SELECT SUM(value) AS total FROM data", relations.clone())?;
        let batches = engine.query(
            &state,
            &sql.bind_complete(0)?,
            &tables,
            araphor_analysis_sdk::Limits::default(),
            &control,
            &lease,
        )?;
        assert_eq!(batches[0].num_rows(), 1);
        assert_eq!(
            super::super::values::QueryValues::value(
                batches[0].column(0),
                0,
                LogicalTypeId::Bigint
            )?
            .to_owned(),
            Value::BigInt(-2)
        );
        let sql = QuerySql::admit_relations(
            "SELECT SUM(CAST(value AS DECIMAL(20, 0))) AS total FROM data",
            relations.clone(),
        )?;
        let batches = engine.query(
            &state,
            &sql.bind_complete(0)?,
            &tables,
            araphor_analysis_sdk::Limits::default(),
            &control,
            &lease,
        )?;
        let values = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .ok_or("native decimal sum type")?;
        assert_eq!(values.value(0), 2 * i128::from(i64::MAX));
        let sql = QuerySql::admit_relations(
            "SELECT SUM(CAST(value AS DECIMAL(2, 0))) AS total FROM data",
            relations,
        )?;
        assert!(engine
            .query(
                &state,
                &sql.bind_complete(0)?,
                &tables,
                araphor_analysis_sdk::Limits::default(),
                &control,
                &lease
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn engine_bound_full_inventory() -> Result<()> {
        let sql = QuerySql::admit(
            "WITH unused AS (SELECT state FROM coverage), t AS (SELECT operation, source_cursor FROM events) SELECT a.operation FROM t a JOIN t b ON a.source_cursor = b.source_cursor",
            Vec::new(), false,
        )?;
        assert_eq!(
            sql.dependencies(),
            &BTreeSet::from(["coverage".into(), "events".into()])
        );
        let mut scans = Vec::new();
        sql.program
            .plan
            .apply(|plan| {
                if let LogicalPlan::TableScan(scan) = plan {
                    scans.push(scan.table_name.table().to_owned());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .map_err(|_| SqlPolicy::invalid("test plan"))?;
        assert_eq!(scans, ["events", "events"]);
        assert_eq!(sql.bind_complete(0)?.plan()?.schema().fields().len(), 1);
        Ok(())
    }

    #[test]
    fn engine_bound_unused_windows() -> Result<()> {
        for query in [
            "SELECT operation FROM events WINDOW unused AS (ORDER BY missing)",
            "SELECT operation FROM events WINDOW unused AS (PARTITION BY missing ORDER BY source_cursor)",
            "SELECT operation FROM events WINDOW unused AS (ORDER BY CAST(operation AS DECIMAL(20, 0)))",
            "SELECT lag(operation) OVER \"Subject\" FROM events WINDOW \"Subject\" AS (ORDER BY source_cursor)",
            "SELECT operation FROM events WINDOW same AS (ORDER BY source_cursor), \"SAME\" AS (ORDER BY source_cursor)",
        ] {
            QuerySql::admit(query, Vec::new(), false)?;
        }
        for query in [
            "SELECT lag(operation) OVER \"Subject\" FROM events WINDOW \"SUBJECT\" AS (ORDER BY source_cursor)",
            "SELECT operation FROM events WINDOW same AS (ORDER BY source_cursor), same AS (ORDER BY source_cursor)",
            "SELECT operation FROM events WINDOW unused AS (ORDER BY random())",
            "SELECT operation FROM events WINDOW unused AS (ORDER BY lag(operation, 201) OVER (ORDER BY source_cursor))",
            "SELECT operation FROM events WINDOW unused AS (ORDER BY source_cursor ROWS UNBOUNDED PRECEDING)",
        ] {
            assert!(QuerySql::admit(query, Vec::new(), false).is_err(), "{query}");
        }
        Ok(())
    }

    #[test]
    fn engine_bound_join_policy() -> Result<()> {
        QuerySql::admit(
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = b.source_cursor JOIN events c ON b.source_cursor = c.source_cursor",
            Vec::new(), false,
        )?;
        QuerySql::admit(
            "SELECT e.operation FROM events e JOIN coverage c ON source_cursor = c.first_cursor",
            Vec::new(),
            false,
        )?;
        QuerySql::admit(
            "SELECT a.operation FROM events a JOIN events b ON (a.source_cursor) = b.source_cursor",
            Vec::new(),
            false,
        )?;
        let discarded = QuerySql::admit(
            "WITH unused AS (SELECT a.operation FROM events a JOIN coverage c ON source_cursor = received_utc_ns) SELECT 1 AS value",
            Vec::new(), false,
        )?;
        assert_eq!(
            discarded.dependencies(),
            &BTreeSet::from(["coverage".into(), "events".into()])
        );
        for query in [
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = a.commit_revision",
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = a.commit_revision WHERE false LIMIT 0",
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = b.source_cursor JOIN events c ON a.source_cursor = b.source_cursor",
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor = b.source_cursor AND b.operation = 1",
            "SELECT a.operation FROM events a JOIN events b ON a.source_cursor + 0 = b.source_cursor",
            "SELECT a.operation FROM events a JOIN events a ON a.source_cursor = a.source_cursor",
        ] {
            assert!(QuerySql::admit(query, Vec::new(), false).is_err(), "{query}");
        }
        Ok(())
    }

    #[test]
    fn engine_bound_original_metadata() -> Result<()> {
        let sql = QuerySql::admit(
            "SELECT source_cursor FROM events e WHERE operation = 2 AND received_at >= TIMESTAMP '1970-01-01 00:00:00.000001'",
            Vec::new(), false,
        )?;
        assert_eq!(sql.event_operation(), Some(2));
        assert!(sql.source_column("source_cursor").is_some());
        let bound = sql.bind_at(2_000)?;
        let (plan, _) = QueryEngine::prepare(&QueryEngine::state()?, &bound, None)?;
        let mut fields = BTreeSet::new();
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                fields.extend(
                    scan.projected_schema
                        .fields()
                        .iter()
                        .map(|field| field.name().clone()),
                );
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .map_err(|_| SqlPolicy::invalid("test source projection"))?;
        assert_eq!(
            fields,
            BTreeSet::from([
                "commit_revision".into(),
                "ordinal".into(),
                "source_cursor".into(),
                "operation".into(),
                "received_at".into(),
            ])
        );
        assert!(bound.append);
        assert_eq!(bound.received_from, Bound::Included(1_000));
        assert_eq!(bound.plan()?.schema().fields().len(), 3);
        assert!(!bound.sql.contains("__araphor_bound"));
        Ok(())
    }

    #[test]
    fn engine_bound_having_alias() -> Result<()> {
        for (query, source) in [
            ("SELECT COUNT(*) AS operation FROM events GROUP BY operation HAVING operation = 2", true),
            ("SELECT COUNT(*) AS operation FROM events GROUP BY (operation) HAVING operation = 2", true),
            ("SELECT operation AS key, COUNT(*) AS operation FROM events GROUP BY 1 HAVING operation = 2", true),
            ("SELECT operation AS key, COUNT(*) AS operation FROM events GROUP BY key HAVING operation = 2", true),
            ("SELECT COUNT(*) AS amount FROM events GROUP BY operation HAVING amount = 2", false),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let mut columns = Vec::new();
            let mut aggregate = None;
            sql.program.plan.apply(|plan| {
                if let LogicalPlan::Aggregate(value) = plan {
                    assert_eq!(value.aggr_expr.len(), 1);
                    aggregate = Some(Column::from(value.schema.qualified_field(value.group_expr.len())));
                }
                if let LogicalPlan::Filter(filter) = plan {
                    filter.predicate.apply(|expr| {
                        if let EngineExpression::Column(column) = expr {
                            columns.push(column.clone());
                        }
                        Ok(TreeNodeRecursion::Continue)
                    })?;
                }
                Ok(TreeNodeRecursion::Continue)
            }).map_err(|_| SqlPolicy::invalid("test plan"))?;
            let expected = if source {
                Column::new(Some("events"), "operation")
            } else {
                aggregate.ok_or_else(|| SqlPolicy::invalid("test aggregate field"))?
            };
            assert_eq!(columns, [expected], "{query}");
        }
        Ok(())
    }

    #[test]
    fn trusted_uinteger_cast() -> Result<()> {
        let binding = QueryBinding::trusted(
            "SELECT CAST(? AS INTEGER UNSIGNED) AS value".into(),
            vec![Value::UInt(7)],
            0,
        )?;
        assert_eq!(
            binding.plan()?.schema().field(0).data_type(),
            &ArrowType::UInt32
        );
        Ok(())
    }

    #[test]
    fn trusted_scoped_events() -> Result<()> {
        let binding = QueryBinding::trusted(
            "WITH scoped_events AS (SELECT * FROM events WHERE received_utc_ns >= ? AND received_utc_ns <= ?) SELECT * FROM scoped_events WHERE (CAST(? AS INTEGER UNSIGNED) IS NULL OR operation = ?) ORDER BY commit_revision, ordinal".into(),
            vec![Value::UBigInt(0), Value::UBigInt(u64::MAX), Value::Null, Value::Null], 0,
        )?;
        let schema = SCHEMAS
            .iter()
            .find(|schema| schema.name == "events")
            .ok_or_else(|| SqlPolicy::invalid("test schema"))?;
        assert_eq!(
            binding.plan()?.schema().fields().len(),
            schema.fields().len()
        );
        Ok(())
    }
}
