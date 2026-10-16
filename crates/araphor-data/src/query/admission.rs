use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Bound, ControlFlow};
use std::sync::Arc;

use datafusion::arrow::datatypes::{Field, FieldRef, Schema, SchemaRef};
use datafusion::catalog::default_table_source::provider_as_source;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{Column, DFSchema, Result as EngineResult, ScalarValue, TableReference};
use datafusion::datasource::empty::EmptyTable;
use datafusion::execution::SessionState;
use datafusion::logical_expr::expr_rewriter::NamePreserver;
use datafusion::logical_expr::{
    AggregateUDF, Expr as EngineExpression, ExprSchemable, LogicalPlan, LogicalPlanBuilder,
    Operator, Projection, ScalarUDF, TableSource, WindowUDF,
};
use datafusion::sql::planner::{ContextProvider, PlannerContext, SqlToRel};

use datafusion::sql::sqlparser::ast::{
    visit_expressions, BinaryOperator, DataType, DateTimeField, Distinct, ExactNumberInfo, Expr,
    Function, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, JoinConstraint,
    JoinOperator, LimitClause, NamedWindowExpr, ObjectName, OrderBy, OrderByExpr, OrderByKind,
    Query, Select, SelectFlavor, SelectItem, SelectItemQualifiedWildcardKind, SetExpr,
    SetQuantifier, Statement, TableAlias, TableFactor, TimezoneInfo, UnaryOperator,
    Value as SqlValue, VisitMut as _, VisitorMut, WildcardAdditionalOptions, WindowFrameBound,
    WindowFrameUnits, WindowSpec, WindowType,
};
use datafusion::sql::sqlparser::dialect::DuckDbDialect;
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
    output_names: Vec<String>,
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
    output_names: Option<Vec<String>>,
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
            return Err(Binder::invalid("SQL length"));
        }
        Parameters::validate(&parameters)?;
        let mut statements = SqlContext::parse(sql).map_err(|_| Binder::invalid("SQL syntax"))?;
        if statements.len() != 1 {
            return Err(Binder::invalid("SQL statement"));
        }
        let Some(Statement::Query(mut query)) = statements.pop() else {
            return Err(Binder::invalid("SQL statement"));
        };
        Parameters::bind(&mut query, parameters.len())?;
        let mut binder = Binder {
            model: relations.is_some(),
            relations: relations.unwrap_or_else(|| {
                SCHEMAS
                    .iter()
                    .filter(|schema| {
                        matches!(schema.readiness, "available" | "conditional")
                            || schema.name == "behaviors"
                    })
                    .map(|schema| (schema.name.to_owned(), schema.arrow_schema()))
                    .collect()
            }),
            state: QueryEngine::state()?,
            parameters: SqlContext::parameter_fields(&QueryEngine::parameters(&parameters)?),
            aggregate: false,
            clocks: 0,
            depth: 0,
            next: 0,
            clock: None,
            dependencies: BTreeSet::new(),
        };
        let mut has_clock = false;
        let _ = visit_expressions(&query, |expr| {
            has_clock |= matches!(expr, Expr::Function(function) if FrozenClock::matches(function));
            ControlFlow::<()>::Continue(())
        });
        if has_clock {
            let index = parameters.len() + 1;
            binder.clock = Some(index);
            binder.parameters.push(Arc::new(Field::new(
                format!("${index}"),
                datafusion::arrow::datatypes::DataType::Timestamp(
                    datafusion::arrow::datatypes::TimeUnit::Microsecond,
                    None,
                ),
                false,
            )));
        }
        let context =
            PlannerContext::new().with_prepare_param_data_types(binder.parameters.clone());
        let (_, plan, output_names) = binder.query(&mut query, &context)?;
        Binder::metadata(&mut query);
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
        if follow && binder.clocks != moving.len() {
            return Err(Binder::invalid("moving SQL shape"));
        }
        let operation = if !binder.aggregate && binder.clocks == 0 && Self::append_shape(&query) {
            QueryOperation::Append
        } else {
            QueryOperation::Replace
        };
        let dependencies = binder.dependencies.clone();
        let clocks = binder.clocks;
        let event_operation = TimeTest::direct_events(&query)
            .filter(|_| clocks == 0 && Self::append_shape(&query))
            .and_then(|(select, alias)| {
                Self::event_operation_for(select.selection.as_ref()?, &alias, &parameters)
            });
        let source_columns = Self::source_columns(&query);
        if clocks > 0 {
            let index = parameters.len() + 1;
            let _ = query.visit(&mut FrozenClock(index));
        }
        let complete_sql = query.to_string();
        if complete_sql.len() > SQL_BYTES {
            return Err(Binder::invalid("expanded SQL length"));
        }
        let plan = SqlContext::numeric(plan)?;
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
                output_names,
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
                let column = |expr: &Expr| {
                    matches!(expr, Expr::CompoundIdentifier(parts) if matches!(parts.as_slice(), [table, column]
                        if table.value == alias && column.value == "operation"))
                };
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
            .saturating_add(self.program.output_names.capacity() * size_of::<String>())
            .saturating_add(
                self.program
                    .output_names
                    .iter()
                    .map(String::capacity)
                    .sum::<usize>(),
            )
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

    fn source_columns(query: &Query) -> Vec<Option<(&'static str, &'static str)>> {
        let Some((select, _, name)) = TimeTest::direct_table(query) else {
            return Vec::new();
        };
        let Some(schema) = SCHEMAS.iter().find(|schema| schema.name == name) else {
            return Vec::new();
        };
        select
            .projection
            .iter()
            .map(|item| {
                let expr = match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
                    _ => return None,
                };
                let Expr::CompoundIdentifier(parts) = expr else {
                    return None;
                };
                let [_, column] = parts.as_slice() else {
                    return None;
                };
                schema
                    .fields()
                    .iter()
                    .find(|field| field.name().as_str() == column.value)
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
            .output_names
            .iter()
            .zip(&self.program.source_columns)
            .filter(|(output, _)| output.to_ascii_lowercase() == name);
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
                _ => return Err(Binder::invalid("SQL time bound")),
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
        let mut output_names = self.program.output_names.clone();
        if append {
            output_names.extend(POSITION_FIELDS.map(str::to_owned));
        }
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
            output_names: Some(output_names),
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
                        .map_err(|_| Binder::invalid("append SQL source"))?;
                    projection.expr.push(
                        EngineExpression::Column(Column::from((qualifier, field))).alias(alias),
                    );
                }
                LogicalPlan::Projection(
                    Projection::try_new(projection.expr, projection.input)
                        .map_err(|_| Binder::invalid("append SQL projection"))?,
                )
            }
            _ => return Err(Binder::invalid("append SQL shape")),
        };
        LogicalPlanBuilder::from(plan)
            .sort(POSITION_FIELDS.map(|name| {
                EngineExpression::Column(Column::new_unqualified(name)).sort(true, false)
            }))
            .and_then(LogicalPlanBuilder::build)
            .map_err(|_| Binder::invalid("append SQL ordering"))
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
            return Err(Binder::invalid("append SQL shape"));
        };
        if !matches!(relation.as_str(), "events" | "trace_output") {
            return Err(Binder::invalid("append SQL shape"));
        }
        let SetExpr::Select(select) = query.body.as_mut() else {
            return Err(Binder::invalid("append SQL shape"));
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
            && self.output_names == other.output_names
    }
}

impl QueryBinding {
    pub(super) fn trusted(sql: String, parameters: Vec<Value>, now_ns: u64) -> Result<Self> {
        let mut statements =
            SqlContext::parse(&sql).map_err(|_| Binder::invalid("trusted SQL syntax"))?;
        if statements.len() != 1 {
            return Err(Binder::invalid("trusted SQL statement"));
        }
        let Some(Statement::Query(mut query)) = statements.pop() else {
            return Err(Binder::invalid("trusted SQL statement"));
        };
        Parameters::bind(&mut query, parameters.len())?;
        let output_names = Self::output_names(&query.body);
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
            output_names,
        })
    }

    pub(super) fn plan(&self) -> Result<LogicalPlan> {
        self.plan
            .as_ref()
            .clone()
            .with_param_values(QueryEngine::parameters(&self.parameters)?)
            .map_err(|_| Binder::invalid("SQL parameters"))
    }

    pub(super) fn output_schema(&self, schema: &Schema) -> Result<SchemaRef> {
        let Some(names) = &self.output_names else {
            return Ok(Arc::new(schema.clone()));
        };
        if names.len() != schema.fields().len() {
            return Err(Binder::invalid("SQL result width"));
        }
        Ok(Arc::new(Schema::new_with_metadata(
            schema
                .fields()
                .iter()
                .zip(names)
                .map(|(field, name)| field.as_ref().clone().with_name(name))
                .collect::<Vec<_>>(),
            schema.metadata().clone(),
        )))
    }

    fn output_names(body: &SetExpr) -> Option<Vec<String>> {
        match body {
            SetExpr::Select(select) => select
                .projection
                .iter()
                .map(|item| match item {
                    SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
                    SelectItem::UnnamedExpr(expr) => Binder::output_name(item)
                        .or_else(|| Some(SqlName::expression(expr, &BTreeMap::new()))),
                    _ => None,
                })
                .collect(),
            SetExpr::Query(query) => Self::output_names(&query.body),
            SetExpr::SetOperation { left, .. } => Self::output_names(left),
            _ => None,
        }
    }
}

struct SqlName;

impl SqlName {
    fn identifier(name: &Ident) -> String {
        let mut chars = name.value.chars();
        if chars
            .next()
            .is_some_and(|char| char.is_ascii_alphabetic() || char == '_')
            && chars.all(|char| char.is_ascii_alphanumeric() || char == '_')
            && !matches!(
                name.value.to_ascii_lowercase().as_str(),
                "select"
                    | "from"
                    | "where"
                    | "group"
                    | "order"
                    | "limit"
                    | "having"
                    | "join"
                    | "on"
                    | "union"
                    | "case"
                    | "when"
                    | "then"
                    | "else"
                    | "end"
                    | "null"
                    | "true"
                    | "false"
            )
        {
            name.value.clone()
        } else {
            format!("\"{}\"", name.value.replace('"', "\"\""))
        }
    }

    fn data_type(kind: &DataType) -> String {
        match kind {
            DataType::Bool | DataType::Boolean => "BOOLEAN".into(),
            DataType::Int(None) | DataType::Integer(None) => "INTEGER".into(),
            DataType::Real | DataType::Float(_) => "FLOAT".into(),
            DataType::Text | DataType::Varchar(None) => "VARCHAR".into(),
            DataType::Date
            | DataType::Double(_)
            | DataType::HugeInt
            | DataType::UTinyInt
            | DataType::USmallInt
            | DataType::UBigInt
            | DataType::IntegerUnsigned(None) => {
                format!(
                    "\"{}\"",
                    match kind {
                        DataType::IntegerUnsigned(None) => "UINTEGER".into(),
                        _ => kind.to_string(),
                    }
                )
            }
            _ => kind.to_string(),
        }
    }

    fn number(value: &str) -> String {
        if value.contains(['e', 'E']) {
            if let Ok(value) = value.parse::<f64>() {
                let value = format!("{value:?}");
                if let Some((base, exponent)) = value.split_once('e') {
                    if let Ok(exponent) = exponent.parse::<i32>() {
                        return format!("{base}e{exponent:+03}");
                    }
                }
                return value;
            }
        }
        if let Ok(value) = value.parse::<i128>() {
            value.to_string()
        } else if let Some((whole, fraction)) = value.split_once('.') {
            let whole = whole.trim_start_matches('0');
            let whole = if whole.is_empty() { "0" } else { whole };
            format!("{whole}.{fraction}")
        } else {
            value.to_owned()
        }
    }

    fn conjunction(
        expr: &Expr,
        op: &BinaryOperator,
        windows: &BTreeMap<String, WindowSpec>,
        output: &mut Vec<String>,
    ) {
        match expr {
            Expr::Nested(expr) => Self::conjunction(expr, op, windows, output),
            Expr::BinaryOp {
                left,
                op: inner,
                right,
            } if inner == op => {
                Self::conjunction(left, op, windows, output);
                Self::conjunction(right, op, windows, output);
            }
            _ => output.push(Self::expression(expr, windows)),
        }
    }

    fn expression(expr: &Expr, windows: &BTreeMap<String, WindowSpec>) -> String {
        let render = |expr: &Expr| Self::expression(expr, windows);
        match expr {
            Expr::Identifier(name) => Self::identifier(name),
            Expr::CompoundIdentifier(parts) => parts
                .iter()
                .map(Self::identifier)
                .collect::<Vec<_>>()
                .join("."),
            Expr::Value(value) => match &value.value {
                SqlValue::Number(value, _) => Self::number(value),
                SqlValue::Boolean(value) => {
                    format!("CAST('{}' AS BOOLEAN)", if *value { "t" } else { "f" })
                }
                _ => value.value.to_string(),
            },
            Expr::Nested(expr) => render(expr),
            Expr::BinaryOp { left, op, right } => {
                if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
                    let mut parts = Vec::new();
                    Self::conjunction(expr, op, windows, &mut parts);
                    return format!("({})", parts.join(&format!(" {op} ")));
                }
                let op = if *op == BinaryOperator::NotEq {
                    "!=".into()
                } else {
                    op.to_string()
                };
                format!("({} {op} {})", render(left), render(right))
            }
            Expr::UnaryOp { op, expr } => match op {
                UnaryOperator::Not => format!("(NOT {})", render(expr)),
                UnaryOperator::Minus if matches!(expr.as_ref(), Expr::Value(value) if matches!(value.value, SqlValue::Number(..))) =>
                {
                    format!("-{}", render(expr))
                }
                _ => format!("{op}({})", render(expr)),
            },
            Expr::IsNull(expr) | Expr::IsUnknown(expr) => format!("({} IS NULL)", render(expr)),
            Expr::IsNotNull(expr) | Expr::IsNotUnknown(expr) => {
                format!("({} IS NOT NULL)", render(expr))
            }
            Expr::IsTrue(value)
            | Expr::IsNotTrue(value)
            | Expr::IsFalse(value)
            | Expr::IsNotFalse(value) => {
                let negated = matches!(expr, Expr::IsNotTrue(_) | Expr::IsNotFalse(_));
                let truth = matches!(expr, Expr::IsTrue(_) | Expr::IsNotTrue(_));
                format!(
                    "(CAST({} AS BOOLEAN) IS {}DISTINCT FROM {})",
                    render(value),
                    if negated { "" } else { "NOT " },
                    if truth { "true" } else { "false" }
                )
            }
            Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => format!(
                "({} IS {}DISTINCT FROM {})",
                render(left),
                if matches!(expr, Expr::IsNotDistinctFrom(..)) {
                    "NOT "
                } else {
                    ""
                },
                render(right)
            ),
            Expr::Between {
                expr,
                negated,
                low,
                high,
            } => {
                let between = format!(
                    "({} BETWEEN {} AND {})",
                    render(expr),
                    render(low),
                    render(high)
                );
                if *negated {
                    format!("(NOT {between})")
                } else {
                    between
                }
            }
            Expr::InList {
                expr,
                list,
                negated,
            } => format!(
                "({} {}IN ({}))",
                render(expr),
                if *negated { "NOT " } else { "" },
                list.iter().map(render).collect::<Vec<_>>().join(", ")
            ),
            Expr::Like {
                expr: value,
                pattern,
                negated,
                escape_char,
                ..
            }
            | Expr::ILike {
                expr: value,
                pattern,
                negated,
                escape_char,
                ..
            } => {
                let insensitive = matches!(expr, Expr::ILike { .. });
                if let Some(escape) = escape_char {
                    let call = format!(
                        "main.{}like_escape({}, {}, {escape})",
                        if insensitive { "i" } else { "" },
                        render(value),
                        render(pattern)
                    );
                    if *negated {
                        format!("(NOT {call})")
                    } else {
                        call
                    }
                } else {
                    format!(
                        "({} {}~~{} {})",
                        render(value),
                        if *negated { "!" } else { "" },
                        if insensitive { "*" } else { "" },
                        render(pattern)
                    )
                }
            }
            Expr::Cast {
                kind,
                expr,
                data_type,
                ..
            } => format!(
                "{}CAST({} AS {})",
                if matches!(
                    kind,
                    datafusion::sql::sqlparser::ast::CastKind::TryCast
                        | datafusion::sql::sqlparser::ast::CastKind::SafeCast
                ) {
                    "TRY_"
                } else {
                    ""
                },
                render(expr),
                Self::data_type(data_type)
            ),
            Expr::TypedString(value) => format!(
                "CAST({} AS {})",
                value.value,
                Self::data_type(&value.data_type)
            ),
            Expr::Interval(value) => {
                let argument = render(&value.value);
                if let Some(unit) = &value.leading_field {
                    let cast = format!("CAST({argument} AS DOUBLE)");
                    let cast = match unit {
                        DateTimeField::Second | DateTimeField::Millisecond => cast,
                        DateTimeField::Day => format!("CAST(trunc({cast}) AS INTEGER)"),
                        _ => format!("CAST(trunc({cast}) AS BIGINT)"),
                    };
                    format!("to_{}s({cast})", unit.to_string().to_ascii_lowercase())
                } else {
                    format!("CAST({argument} AS INTERVAL)")
                }
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                let mut result = "CASE ".to_owned();
                for condition in conditions {
                    let check = operand.as_ref().map_or_else(
                        || render(&condition.condition),
                        |operand| {
                            format!("({} = {})", render(operand), render(&condition.condition))
                        },
                    );
                    result.push_str(&format!(
                        " WHEN ({check}) THEN ({})",
                        render(&condition.result)
                    ));
                }
                result.push_str(&format!(
                    " ELSE {} END",
                    else_result
                        .as_ref()
                        .map_or_else(|| "NULL".to_owned(), |expr| render(expr))
                ));
                result
            }
            Expr::Function(function) => Self::function(function, windows),
            _ => expr.to_string(),
        }
    }

    fn function(function: &Function, windows: &BTreeMap<String, WindowSpec>) -> String {
        let name = EngineExpr::name(function).to_ascii_lowercase();
        let FunctionArguments::List(arguments) = &function.args else {
            return name;
        };
        let star = matches!(
            arguments.args.as_slice(),
            [FunctionArg::Unnamed(FunctionArgExpr::Wildcard)]
        );
        let name = match name.as_str() {
            "count" if star && function.over.is_none() => "count_star",
            "coalesce" => "COALESCE",
            "nullif" => "\"nullif\"",
            _ => name.as_str(),
        };
        let args = arguments
            .args
            .iter()
            .filter_map(|arg| match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                    Some(Self::expression(expr, windows))
                }
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ");
        let distinct = matches!(
            arguments.duplicate_treatment,
            Some(datafusion::sql::sqlparser::ast::DuplicateTreatment::Distinct)
        );
        let mut result = format!("{name}({}{args})", if distinct { "DISTINCT " } else { "" });
        if let Some(filter) = &function.filter {
            result.push_str(&format!(
                " FILTER (WHERE {})",
                Self::expression(filter, windows)
            ));
        }
        if let Some(over) = &function.over {
            let window = match over {
                WindowType::WindowSpec(spec) => Some(spec),
                WindowType::NamedWindow(name) => windows.get(&name.value.to_ascii_lowercase()),
            };
            if let Some(window) = window {
                let mut parts = Vec::new();
                if !window.partition_by.is_empty() {
                    parts.push(format!(
                        "PARTITION BY {}",
                        window
                            .partition_by
                            .iter()
                            .map(|expr| Self::expression(expr, windows))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !window.order_by.is_empty() {
                    parts.push(format!(
                        "ORDER BY {}",
                        window
                            .order_by
                            .iter()
                            .map(|order| format!(
                                "{}{}",
                                Self::expression(&order.expr, windows),
                                order.options
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if let Some(frame) = &window.window_frame {
                    parts.push(format!(
                        "{} BETWEEN {} AND {}",
                        frame.units,
                        frame.start_bound,
                        frame
                            .end_bound
                            .as_ref()
                            .unwrap_or(&WindowFrameBound::CurrentRow)
                    ));
                }
                result.push_str(&format!(" OVER ({})", parts.join(" ")));
            }
        }
        result
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
            Parser::new(&DuckDbDialect {})
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

    fn plan(&self, mut query: Box<Query>, parameters: &[FieldRef]) -> Result<LogicalPlan> {
        if let ControlFlow::Break(error) = query.visit(&mut EngineExpr) {
            return Err(error);
        }
        let mut context = PlannerContext::new().with_prepare_param_data_types(parameters.to_vec());
        let plan = SqlToRel::new(self)
            .sql_statement_to_plan_with_context(Statement::Query(query), &mut context)
            .map_err(|_| Binder::invalid("SQL binding"))?;
        Self::numeric(plan)
    }

    fn numeric(plan: LogicalPlan) -> Result<LogicalPlan> {
        plan.transform_up(|plan| {
            if let LogicalPlan::Union(union) = plan {
                return Ok(Transformed::yes(LogicalPlan::Union(
                    datafusion::logical_expr::Union::try_new_with_loose_types(union.inputs)?,
                )));
            }
            if plan.expressions().is_empty() {
                return Ok(Transformed::yes(plan.recompute_schema()?));
            }
            let schema = plan
                .inputs()
                .into_iter()
                .try_fold(DFSchema::empty(), |schema, input| {
                    schema.join(input.schema())
                })?;
            let names = NamePreserver::new(&plan);
            let result = plan.map_expressions(|expr| {
                let name = names.save(&expr);
                let mut result = expr.transform_up(|expr| {
                    let expr = match expr {
                        EngineExpression::Alias(mut alias)
                            if alias.metadata.as_ref().is_some_and(|metadata| {
                                metadata.inner().contains_key("__araphor_sql_name")
                            }) =>
                        {
                            if let Some(metadata) = alias.metadata.take() {
                                let mut metadata = metadata.inner().clone();
                                metadata.remove("__araphor_sql_name");
                                alias.metadata = (!metadata.is_empty()).then(|| metadata.into());
                            }
                            return Ok(Transformed::yes(EngineExpression::Alias(alias)));
                        }
                        EngineExpression::Literal(ScalarValue::Int64(Some(value)), metadata)
                            if i32::try_from(value).is_ok() =>
                        {
                            return Ok(Transformed::yes(EngineExpression::Literal(
                                ScalarValue::Int32(Some(value as i32)),
                                metadata,
                            )));
                        }
                        EngineExpression::Literal(ScalarValue::UInt64(Some(value)), metadata) => {
                            return Ok(Transformed::yes(EngineExpression::Literal(
                                ScalarValue::Decimal256(
                                    Some(datafusion::arrow::datatypes::i256::from_i128(
                                        i128::from(value),
                                    )),
                                    39,
                                    0,
                                ),
                                metadata,
                            )));
                        }
                        expr => expr,
                    };
                    let EngineExpression::BinaryExpr(mut binary) = expr else {
                        return Ok(Transformed::no(expr));
                    };
                    if binary.op == Operator::Divide {
                        let left = binary.left.get_type(&schema)?;
                        let right = binary.right.get_type(&schema)?;
                        let exact = |kind: &datafusion::arrow::datatypes::DataType| {
                            kind.is_integer() || kind.is_decimal() || kind.is_null()
                        };
                        if exact(&left) && exact(&right) {
                            binary.left = Box::new((*binary.left).cast_to(
                                &datafusion::arrow::datatypes::DataType::Float64,
                                &schema,
                            )?);
                            binary.right = Box::new((*binary.right).cast_to(
                                &datafusion::arrow::datatypes::DataType::Float64,
                                &schema,
                            )?);
                            return Ok(Transformed::yes(EngineExpression::BinaryExpr(binary)));
                        }
                    }
                    Ok(Transformed::no(EngineExpression::BinaryExpr(binary)))
                })?;
                result.data = name.restore(result.data);
                Ok(result)
            })?;
            Ok(Transformed::yes(result.data.recompute_schema()?))
        })
        .map(|result| result.data)
        .map_err(|_| Binder::invalid("SQL numeric expression"))
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

struct EngineExpr;

impl EngineExpr {
    fn name(function: &Function) -> &str {
        function
            .name
            .0
            .first()
            .and_then(|part| part.as_ident())
            .map_or("", |name| name.value.as_str())
    }
    fn call(name: &str, argument: Expr) -> Expr {
        Expr::Function(Function {
            name: ObjectName::from(vec![Ident::with_quote('"', name)]),
            uses_odbc_syntax: false,
            parameters: FunctionArguments::None,
            args: FunctionArguments::List(datafusion::sql::sqlparser::ast::FunctionArgumentList {
                duplicate_treatment: None,
                args: vec![FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))],
                clauses: Vec::new(),
            }),
            filter: None,
            null_treatment: None,
            over: None,
            within_group: Vec::new(),
        })
    }

    fn integer(number: &str) -> Option<Expr> {
        if number.contains(['.', 'e', 'E']) || number.parse::<i64>().is_ok() {
            return None;
        }
        let value = Expr::Value(SqlValue::SingleQuotedString(number.to_owned()).into());
        Some(if number.parse::<i128>().is_ok() {
            Self::call("__araphor_hugeint", value)
        } else {
            Expr::Cast {
                kind: datafusion::sql::sqlparser::ast::CastKind::Cast,
                expr: Box::new(value),
                data_type: DataType::Double(ExactNumberInfo::None),
                array: false,
                format: None,
            }
        })
    }

    fn data_type(kind: &mut DataType) {
        *kind = match &*kind {
            DataType::UTinyInt => DataType::TinyIntUnsigned(None),
            DataType::USmallInt => DataType::SmallIntUnsigned(None),
            DataType::UBigInt => DataType::BigIntUnsigned(None),
            DataType::Custom(name, modifiers)
                if modifiers.is_empty()
                    && matches!(name.0.as_slice(), [part]
                    if part.as_ident().is_some_and(|name| name.value.eq_ignore_ascii_case("uinteger"))) =>
            {
                DataType::IntegerUnsigned(None)
            }
            DataType::Blob(None) => DataType::Bytea,
            DataType::Timestamp(None, zone) => DataType::Timestamp(Some(6), *zone),
            other => other.clone(),
        };
    }
}

impl VisitorMut for EngineExpr {
    type Break = crate::Error;

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        match expr {
            Expr::UnaryOp {
                op: UnaryOperator::Minus,
                expr: value,
            } => {
                if let Expr::Value(datafusion::sql::sqlparser::ast::ValueWithSpan {
                    value: SqlValue::Number(number, false),
                    ..
                }) = value.as_ref()
                {
                    if !number.contains(['.', 'e', 'E']) {
                        let signed = format!("-{number}");
                        *expr = Self::integer(&signed)
                            .unwrap_or_else(|| Expr::Value(SqlValue::Number(signed, false).into()));
                    }
                }
            }
            Expr::Function(function) => {
                for part in &mut function.name.0 {
                    if let datafusion::sql::sqlparser::ast::ObjectNamePart::Identifier(name) = part
                    {
                        name.value.make_ascii_lowercase();
                    }
                }
                if let Some(WindowType::NamedWindow(name)) = &mut function.over {
                    name.value.make_ascii_lowercase();
                }
                if Self::name(function) == "sum" {
                    if let FunctionArguments::List(arguments) = &mut function.args {
                        if let [FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))] =
                            arguments.args.as_mut_slice()
                        {
                            *argument = Self::call("__araphor_sum_input", argument.clone());
                        }
                    }
                }
            }
            Expr::Cast {
                kind,
                expr: argument,
                data_type: DataType::HugeInt,
                ..
            } => {
                let name = if matches!(
                    kind,
                    datafusion::sql::sqlparser::ast::CastKind::TryCast
                        | datafusion::sql::sqlparser::ast::CastKind::SafeCast
                ) {
                    "__araphor_try_hugeint"
                } else {
                    "__araphor_hugeint"
                };
                *expr = Self::call(name, argument.as_ref().clone());
            }
            Expr::Cast { data_type, .. } => Self::data_type(data_type),
            Expr::TypedString(value) => Self::data_type(&mut value.data_type),
            Expr::Interval(_) => {
                if let Some(micros) = TimeTest::fixed_interval(expr) {
                    *expr = Expr::Interval(datafusion::sql::sqlparser::ast::Interval {
                        value: Box::new(Expr::Value(
                            SqlValue::SingleQuotedString(format!(
                                "{} days {} microseconds",
                                micros / 86_400_000_000,
                                micros % 86_400_000_000
                            ))
                            .into(),
                        )),
                        leading_field: None,
                        leading_precision: None,
                        last_field: None,
                        fractional_seconds_precision: None,
                    });
                }
            }
            Expr::Value(datafusion::sql::sqlparser::ast::ValueWithSpan {
                value: SqlValue::Number(number, _),
                ..
            }) if number.contains(['e', 'E']) => {
                *expr = Expr::Cast {
                    kind: datafusion::sql::sqlparser::ast::CastKind::Cast,
                    expr: Box::new(Expr::Value(
                        SqlValue::SingleQuotedString(number.clone()).into(),
                    )),
                    data_type: DataType::Double(ExactNumberInfo::None),
                    array: false,
                    format: None,
                };
            }
            Expr::Value(datafusion::sql::sqlparser::ast::ValueWithSpan {
                value: SqlValue::Number(number, false),
                ..
            }) => {
                if let Some(value) = Self::integer(number) {
                    *expr = value;
                }
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(function) = expr else {
            return ControlFlow::Continue(());
        };
        let name = Self::name(function);
        if name == "sum" {
            *expr = Self::call("__araphor_sum_result", expr.clone());
        } else if matches!(name, "length" | "row_number" | "rank" | "dense_rank") {
            *expr = Expr::Cast {
                kind: datafusion::sql::sqlparser::ast::CastKind::Cast,
                expr: Box::new(expr.clone()),
                data_type: DataType::BigInt(None),
                array: false,
                format: None,
            };
        }
        ControlFlow::Continue(())
    }
}

type BoundSelect = (Vec<Option<String>>, DFSchema, Vec<String>, Vec<bool>);

struct Binder {
    relations: BTreeMap<String, SchemaRef>,
    model: bool,
    state: SessionState,
    parameters: Vec<FieldRef>,
    aggregate: bool,
    clocks: usize,
    clock: Option<usize>,
    depth: usize,
    next: usize,
    dependencies: BTreeSet<String>,
}

impl Binder {
    fn invalid(field: &'static str) -> crate::Error {
        crate::QueryInvalidSnafu { field }.build()
    }

    fn identifier(name: &Ident) -> Result<String> {
        let name = name.value.to_ascii_lowercase();
        if name.is_empty() || name.len() > 256 || name.starts_with("__araphor_") {
            return Err(Self::invalid("SQL name"));
        }
        Ok(name)
    }

    fn name(name: &ObjectName) -> Result<String> {
        let [part] = name.0.as_slice() else {
            return Err(Self::invalid("SQL name"));
        };
        Self::identifier(part.as_ident().ok_or_else(|| Self::invalid("SQL name"))?)
    }

    fn fresh(&mut self, prefix: &str) -> Ident {
        self.next += 1;
        Ident::with_quote('"', format!("__araphor_{prefix}_{}", self.next))
    }

    fn projection(&mut self, select: &mut Select, schema: &DFSchema) {
        for window in &mut select.named_window {
            window.0.value.make_ascii_lowercase();
        }
        Self::having(select, schema);
        let mut names = BTreeSet::new();
        for item in &mut select.projection {
            if let SelectItem::UnnamedExpr(expr) = item {
                if Binder::output_name(&SelectItem::UnnamedExpr(expr.clone())).is_none() {
                    *item = SelectItem::ExprWithAlias {
                        expr: expr.clone(),
                        alias: self.fresh("column"),
                    };
                }
            }
            if let SelectItem::ExprWithAlias { alias, .. } = item {
                alias.quote_style = Some('"');
            }
            if let Some(name) = Binder::output_name(item) {
                if !names.insert(name.to_ascii_lowercase()) {
                    let expr = match item {
                        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                            expr.clone()
                        }
                        _ => continue,
                    };
                    *item = SelectItem::ExprWithAlias {
                        expr,
                        alias: self.fresh("column"),
                    };
                }
            }
        }
    }

    fn having(select: &mut Select, schema: &DFSchema) {
        let aliases: BTreeMap<_, _> = select
            .projection
            .iter()
            .filter_map(|item| match item {
                SelectItem::ExprWithAlias { expr, alias } => {
                    Some((alias.value.to_ascii_lowercase(), expr.clone()))
                }
                _ => None,
            })
            .collect();
        let grouped: Vec<_> = match &select.group_by {
            GroupByExpr::Expressions(items, _) => items
                .iter()
                .map(|expr| {
                    let mut expr = Binder::integer(expr)
                        .and_then(|ordinal| {
                            select.projection.get(ordinal.saturating_sub(1) as usize)
                        })
                        .and_then(|item| match item {
                            SelectItem::UnnamedExpr(expr)
                            | SelectItem::ExprWithAlias { expr, .. } => Some(expr),
                            _ => None,
                        })
                        .unwrap_or(expr);
                    while let Expr::Nested(inner) = expr {
                        expr = inner.as_ref();
                    }
                    let mut expr = match expr {
                        Expr::Identifier(name)
                            if !schema.has_column_with_unqualified_name(&name.value) =>
                        {
                            aliases
                                .get(&name.value.to_ascii_lowercase())
                                .unwrap_or(expr)
                        }
                        _ => expr,
                    };
                    while let Expr::Nested(inner) = expr {
                        expr = inner.as_ref();
                    }
                    if let Expr::Identifier(name) = expr {
                        if let Ok((qualifier, field)) =
                            schema.qualified_field_with_unqualified_name(&name.value)
                        {
                            if let Ok(expr) = Self::column(&Column::from((qualifier, field))) {
                                return expr;
                            }
                        }
                    }
                    expr.clone()
                })
                .collect(),
            _ => Vec::new(),
        };
        let Some(having) = &mut select.having else {
            return;
        };
        let _ = datafusion::sql::sqlparser::ast::visit_expressions_mut(having, |expr| {
            if let Expr::Identifier(name) = expr {
                if let Some(aliased) = aliases.get(&name.value.to_ascii_lowercase()) {
                    *expr = grouped
                        .iter()
                        .find(|expr| {
                            Self::column_name(expr)
                                .is_some_and(|column| column.eq_ignore_ascii_case(&name.value))
                        })
                        .unwrap_or(aliased)
                        .clone();
                }
            }
            ControlFlow::<()>::Continue(())
        });
    }

    fn column_name(expr: &Expr) -> Option<&str> {
        match expr {
            Expr::CompoundIdentifier(parts) => parts.last().map(|name| name.value.as_str()),
            Expr::Nested(expr) => Self::column_name(expr),
            _ => None,
        }
    }

    fn query(
        &mut self,
        query: &mut Query,
        inherited: &PlannerContext,
    ) -> Result<(Vec<Option<String>>, LogicalPlan, Vec<String>)> {
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
        let mut context = inherited.clone();
        if let Some(with) = &mut query.with {
            if with.recursive {
                return Err(Self::invalid("recursive SQL"));
            }
            let mut names = BTreeSet::new();
            for cte in &mut with.cte_tables {
                if cte.from.is_some() || cte.materialized.is_some() {
                    return Err(Self::invalid("SQL CTE"));
                }
                let name = Self::identifier(&cte.alias.name)?;
                if !names.insert(name.clone()) {
                    return Err(Self::invalid("SQL CTE"));
                }
                let (output, plan, _) = self.query(&mut cte.query, &context)?;
                let names = Self::rename(output, &mut cte.alias)?;
                context.insert_cte(name, Self::project(plan, &names, true)?);
            }
        }
        let mut planned = Box::new(query.clone());
        planned.with = None;
        let (mut output, input, mut labels, source_labels) =
            self.body(&mut query.body, &mut planned.body, &mut context)?;
        if let Some(order) = &query.order_by {
            let OrderByKind::Expressions(items) = &order.kind else {
                return Err(Self::invalid("SQL ordering"));
            };
            if order.interpolate.is_some() {
                return Err(Self::invalid("SQL ordering"));
            }
            for item in items {
                Self::order(item)?;
                if !Self::ordinal(&item.expr, output.len())? {
                    self.expression(&mut item.expr.clone(), &BTreeMap::new())?;
                    Self::aliases(&item.expr, &input, &output, true)?;
                }
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
        Self::fold(&mut planned);
        let plan = self.statement(planned, &mut context)?;
        plan.apply(|plan| {
            if matches!(plan, LogicalPlan::SubqueryAlias(_)) {
                return Ok(TreeNodeRecursion::Jump);
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
        .map_err(|_| Self::invalid("SQL join"))?;
        if plan.schema().fields().len() != labels.len() {
            return Err(Self::invalid("SQL result width"));
        }
        for (index, source) in source_labels.into_iter().enumerate() {
            if source {
                if let Some(name) = plan
                    .schema()
                    .field(index)
                    .metadata()
                    .get("__araphor_sql_name")
                {
                    labels[index] = name.clone();
                    output[index] = Some(name.clone());
                }
            }
        }
        let unique = labels
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let names = if unique.len() == labels.len() {
            labels.clone()
        } else {
            plan.schema()
                .fields()
                .iter()
                .map(|field| field.name().clone())
                .collect()
        };
        let plan = Self::project(plan, &names, true)?;
        self.depth -= 1;
        Ok((output, plan, labels))
    }

    fn body(
        &mut self,
        original: &mut SetExpr,
        planned: &mut SetExpr,
        context: &mut PlannerContext,
    ) -> Result<BoundSelect> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return Err(Self::invalid("SQL depth"));
        }
        let result = match (original, planned) {
            (SetExpr::Select(select), SetExpr::Select(target)) => {
                self.select(select, target, context)
            }
            (SetExpr::Query(query), target) => {
                let (output, plan, labels) = self.query(query, context)?;
                *target = self.reference(plan, &query.body, context)?;
                let source_labels = vec![false; labels.len()];
                Ok((output, DFSchema::empty(), labels, source_labels))
            }
            (
                SetExpr::SetOperation {
                    left,
                    right,
                    set_quantifier:
                        SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
                    ..
                },
                SetExpr::SetOperation {
                    left: target_left,
                    right: target_right,
                    ..
                },
            ) => {
                self.aggregate = true;
                let (output, _, labels, source_labels) = self.body(left, target_left, context)?;
                let (right, _, _, _) = self.body(right, target_right, context)?;
                if output.len() != right.len() {
                    return Err(Self::invalid("SQL set columns"));
                }
                Ok((output, DFSchema::empty(), labels, source_labels))
            }
            _ => Err(Self::invalid("SQL body")),
        };
        self.depth -= 1;
        result
    }

    fn select(
        &mut self,
        select: &mut Select,
        target: &mut Select,
        context: &mut PlannerContext,
    ) -> Result<BoundSelect> {
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
        let mut from = select.from.clone();
        let mut schema = DFSchema::empty();
        let mut aliases = BTreeSet::new();
        for (source, target) in select.from.iter_mut().zip(&mut from) {
            let (name, plan) = self.table(&mut source.relation, context)?;
            if !aliases.insert(name) {
                return Err(Self::invalid("SQL alias"));
            }
            schema = schema
                .join(plan.schema())
                .map_err(|_| Self::invalid("SQL source"))?;
            target.relation = self.table_reference(plan, context);
            for (source, target) in source.joins.iter_mut().zip(&mut target.joins) {
                if source.global {
                    return Err(Self::invalid("SQL join"));
                }
                let (name, plan) = self.table(&mut source.relation, context)?;
                if !aliases.insert(name) {
                    return Err(Self::invalid("SQL alias"));
                }
                schema = schema
                    .join(plan.schema())
                    .map_err(|_| Self::invalid("SQL source"))?;
                target.relation = self.table_reference(plan, context);
                let constraint = match &mut source.join_operator {
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
            }
        }
        let label_windows = select
            .named_window
            .iter()
            .filter_map(|window| match &window.1 {
                NamedWindowExpr::WindowSpec(spec) => {
                    Some((window.0.value.to_ascii_lowercase(), spec.clone()))
                }
                _ => None,
            })
            .collect();
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
                let mut expr = expr.clone();
                self.prepare(&mut expr)?;
                SqlToRel::new(&SqlContext {
                    state: &self.state,
                    relations: &self.relations,
                })
                .sql_to_expr(expr, &schema, context)
                .map_err(|_| Self::invalid("SQL window"))?;
            }
            if windows
                .insert(Self::identifier(&window.0)?, spec.clone())
                .is_some()
            {
                return Err(Self::invalid("SQL window"));
            }
        }
        let mut projection = Vec::new();
        let mut labels = Vec::new();
        let mut source_labels = Vec::new();
        for item in std::mem::take(&mut select.projection) {
            match item {
                SelectItem::Wildcard(options) => {
                    Self::wildcard(&options)?;
                    Self::expand(
                        &schema,
                        None,
                        self.model,
                        &mut projection,
                        &mut labels,
                        &mut source_labels,
                    )?;
                }
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    options,
                ) => {
                    Self::wildcard(&options)?;
                    Self::expand(
                        &schema,
                        Some(&Self::name(&name)?),
                        self.model,
                        &mut projection,
                        &mut labels,
                        &mut source_labels,
                    )?;
                }
                SelectItem::UnnamedExpr(mut expr) => {
                    let item = SelectItem::UnnamedExpr(expr.clone());
                    let name = Self::output_name(&item);
                    labels.push(
                        name.clone()
                            .unwrap_or_else(|| SqlName::expression(&expr, &label_windows)),
                    );
                    source_labels.push(name.is_some());
                    self.expression(&mut expr, &windows)?;
                    projection.push(SelectItem::UnnamedExpr(expr));
                }
                SelectItem::ExprWithAlias { mut expr, alias } => {
                    Self::identifier(&alias)?;
                    labels.push(alias.value.clone());
                    source_labels.push(false);
                    self.expression(&mut expr, &windows)?;
                    projection.push(SelectItem::ExprWithAlias { expr, alias });
                }
                _ => return Err(Self::invalid("SQL projection")),
            }
        }
        if projection.is_empty() || projection.len() > 256 {
            return Err(Self::invalid("SQL projection"));
        }
        let output: Vec<_> = projection.iter().map(Self::output_name).collect();
        select.projection = projection;
        if let Some(expr) = &mut select.selection {
            self.expression(expr, &windows)?;
        }
        match &mut select.group_by {
            GroupByExpr::Expressions(items, modifiers) if modifiers.is_empty() => {
                for expr in items {
                    if !Self::ordinal(expr, output.len())? {
                        self.expression(expr, &windows)?;
                        Self::aliases(expr, &schema, &output, false)?;
                    }
                }
            }
            _ => return Err(Self::invalid("SQL grouping")),
        }
        if let Some(expr) = &mut select.having {
            self.expression(expr, &windows)?;
            Self::aliases(expr, &schema, &output, true)?;
        }
        *target = select.clone();
        target.from = from;
        Self::fold(target);
        for item in &mut target.projection {
            if let SelectItem::ExprWithAlias { alias, .. } = item {
                alias.value.make_ascii_lowercase();
                alias.quote_style = Some('"');
            }
        }
        self.projection(target, &schema);
        Ok((output, schema, labels, source_labels))
    }

    fn table(
        &mut self,
        table: &mut TableFactor,
        context: &PlannerContext,
    ) -> Result<(String, LogicalPlan)> {
        let (plan, output, alias, name) = match table {
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
                let plan = if let Some(plan) = context.get_cte(&name) {
                    plan.clone()
                } else {
                    self.dependencies.insert(name.clone());
                    LogicalPlanBuilder::scan(
                        name.clone(),
                        SqlContext {
                            state: &self.state,
                            relations: &self.relations,
                        }
                        .get_table_source(TableReference::bare(name.clone()))
                        .map_err(|_| Self::invalid("SQL relation"))?,
                        None,
                    )
                    .and_then(LogicalPlanBuilder::build)
                    .map_err(|_| Self::invalid("SQL relation"))?
                };
                let output = plan
                    .schema()
                    .fields()
                    .iter()
                    .map(|field| Some(field.name().clone()))
                    .collect();
                (plan, output, alias.as_mut(), name)
            }
            TableFactor::Derived {
                lateral: false,
                subquery,
                alias: Some(alias),
                sample: None,
            } => {
                let (output, plan, _) = self.query(subquery, context)?;
                let name = Self::identifier(&alias.name)?;
                (plan, output, Some(alias), name)
            }
            _ => return Err(Self::invalid("SQL relation")),
        };
        let name = alias
            .as_ref()
            .map(|alias| Self::identifier(&alias.name))
            .transpose()?
            .unwrap_or(name);
        let names = if let Some(alias) = alias {
            Self::rename(output, alias)?
        } else {
            output
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| Self::invalid("SQL derived columns"))?
        };
        let plan = Self::project(plan, &names, false)?;
        LogicalPlanBuilder::from(plan)
            .alias(&name)
            .and_then(LogicalPlanBuilder::build)
            .map(|plan| (name, plan))
            .map_err(|_| Self::invalid("SQL alias"))
    }

    fn project(plan: LogicalPlan, names: &[String], declared: bool) -> Result<LogicalPlan> {
        let expressions = plan
            .schema()
            .iter()
            .zip(names)
            .map(|((qualifier, field), name)| {
                let mut metadata = field.metadata().clone();
                metadata.insert("__araphor_sql_name".into(), name.clone());
                EngineExpression::Column(Column::from((qualifier, field))).alias_with_metadata(
                    if declared {
                        name.clone()
                    } else {
                        name.to_ascii_lowercase()
                    },
                    Some(metadata.into()),
                )
            })
            .collect::<Vec<_>>();
        let result = if declared {
            if let LogicalPlan::Projection(projection) = &plan {
                let expressions = projection
                    .expr
                    .iter()
                    .zip(plan.schema().fields())
                    .zip(names)
                    .map(|((expr, field), name)| {
                        let mut metadata = field.metadata().clone();
                        metadata.insert("__araphor_sql_name".into(), name.clone());
                        expr.clone()
                            .unalias()
                            .alias_with_metadata(name.clone(), Some(metadata.into()))
                    })
                    .collect::<Vec<_>>();
                Projection::try_new(expressions, projection.input.clone())
                    .map(LogicalPlan::Projection)
            } else {
                LogicalPlanBuilder::from(plan)
                    .project(expressions)
                    .and_then(LogicalPlanBuilder::build)
            }
        } else {
            LogicalPlanBuilder::from(plan)
                .project(expressions)
                .and_then(LogicalPlanBuilder::build)
        };
        result.map_err(|_| Self::invalid("SQL output names"))
    }

    fn table_reference(&mut self, plan: LogicalPlan, context: &mut PlannerContext) -> TableFactor {
        let name = self.fresh("bound");
        context.insert_cte(name.value.clone(), plan);
        TableFactor::Table {
            name: ObjectName::from(vec![name]),
            alias: None,
            args: None,
            with_hints: Vec::new(),
            version: None,
            with_ordinality: false,
            partitions: Vec::new(),
            json_path: None,
            sample: None,
            index_hints: Vec::new(),
        }
    }

    fn reference(
        &mut self,
        plan: LogicalPlan,
        body: &SetExpr,
        context: &mut PlannerContext,
    ) -> Result<SetExpr> {
        fn select(body: &SetExpr) -> Option<&Select> {
            match body {
                SetExpr::Select(select) => Some(select),
                SetExpr::Query(query) => select(&query.body),
                SetExpr::SetOperation { left, .. } => select(left),
                _ => None,
            }
        }
        let mut select = Box::new(
            select(body)
                .cloned()
                .ok_or_else(|| Self::invalid("SQL body"))?,
        );
        select.projection = vec![SelectItem::Wildcard(Default::default())];
        select.from = vec![datafusion::sql::sqlparser::ast::TableWithJoins {
            relation: self.table_reference(plan, context),
            joins: Vec::new(),
        }];
        select.selection = None;
        select.group_by = GroupByExpr::Expressions(Vec::new(), Vec::new());
        select.having = None;
        select.distinct = None;
        select.named_window.clear();
        Ok(SetExpr::Select(select))
    }

    fn statement(
        &self,
        mut query: Box<Query>,
        context: &mut PlannerContext,
    ) -> Result<LogicalPlan> {
        self.prepare(&mut query)?;
        SqlToRel::new(&SqlContext {
            state: &self.state,
            relations: &self.relations,
        })
        .sql_statement_to_plan_with_context(Statement::Query(query), context)
        .map_err(|_| Self::invalid("SQL binding"))
    }

    fn prepare<T: datafusion::sql::sqlparser::ast::VisitMut>(&self, value: &mut T) -> Result<()> {
        Self::fold(value);
        if let Some(index) = self.clock {
            let _ = value.visit(&mut FrozenClock(index));
        }
        match value.visit(&mut EngineExpr) {
            ControlFlow::Break(error) => Err(error),
            ControlFlow::Continue(()) => Ok(()),
        }
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

    fn fold<T: datafusion::sql::sqlparser::ast::VisitMut>(value: &mut T) {
        let _ = datafusion::sql::sqlparser::ast::visit_expressions_mut(value, |expr| {
            match expr {
                Expr::Identifier(name) => name.value.make_ascii_lowercase(),
                Expr::CompoundIdentifier(parts) => {
                    for name in parts {
                        name.value.make_ascii_lowercase();
                    }
                }
                _ => {}
            }
            ControlFlow::<()>::Continue(())
        });
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

    fn aliases(
        expr: &Expr,
        schema: &DFSchema,
        output: &[Option<String>],
        output_first: bool,
    ) -> Result<()> {
        let result = visit_expressions(expr, |expr| {
            if let Expr::Identifier(name) = expr {
                let key = name.value.to_ascii_lowercase();
                let aliases = output
                    .iter()
                    .flatten()
                    .filter(|name| name.eq_ignore_ascii_case(&key))
                    .count();
                if aliases > 1 && (output_first || !schema.has_column_with_unqualified_name(&key)) {
                    return ControlFlow::Break(Self::invalid("SQL column"));
                }
            }
            ControlFlow::Continue(())
        });
        match result {
            ControlFlow::Break(error) => Err(error),
            ControlFlow::Continue(()) => Ok(()),
        }
    }

    fn column(column: &Column) -> Result<Expr> {
        let Some(table) = &column.relation else {
            return Err(Self::invalid("SQL column"));
        };
        Ok(Expr::CompoundIdentifier(vec![
            Ident::with_quote('"', table.table()),
            Ident::with_quote('"', &column.name),
        ]))
    }

    fn expand(
        schema: &DFSchema,
        target: Option<&str>,
        model: bool,
        projection: &mut Vec<SelectItem>,
        labels: &mut Vec<String>,
        source_labels: &mut Vec<bool>,
    ) -> Result<()> {
        let columns = if let Some(target) = target {
            datafusion::logical_expr::utils::expand_qualified_wildcard(
                &TableReference::bare(target),
                schema,
                None,
            )
        } else {
            Ok(schema
                .columns()
                .into_iter()
                .map(EngineExpression::Column)
                .collect())
        }
        .map_err(|_| Self::invalid("SQL wildcard"))?;
        for expr in columns {
            let EngineExpression::Column(column) = expr else {
                return Err(Self::invalid("SQL wildcard"));
            };
            if model && column.name == "__row_index" {
                continue;
            }
            let (_, field) = schema
                .qualified_field_with_name(column.relation.as_ref(), &column.name)
                .map_err(|_| Self::invalid("SQL wildcard"))?;
            let name = field
                .metadata()
                .get("__araphor_sql_name")
                .unwrap_or(field.name())
                .clone();
            let mut expr = Self::column(&column)?;
            if let Expr::CompoundIdentifier(parts) = &mut expr {
                if let Some(column) = parts.last_mut() {
                    column.value = name.clone();
                }
            }
            projection.push(SelectItem::UnnamedExpr(expr));
            labels.push(name);
            source_labels.push(true);
        }
        Ok(())
    }

    fn metadata(query: &mut Query) {
        let Some((_, alias, _)) = TimeTest::direct_table(query) else {
            return;
        };
        let SetExpr::Select(select) = query.body.as_mut() else {
            return;
        };
        for item in &mut select.projection {
            let expr = match item {
                SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
                _ => continue,
            };
            Self::qualify(expr, &alias);
        }
        if let Some(expr) = &mut select.selection {
            Self::qualify(expr, &alias);
        }
    }

    fn qualify(expr: &mut Expr, alias: &str) {
        let _ = datafusion::sql::sqlparser::ast::visit_expressions_mut(expr, |expr| {
            match expr {
                Expr::Identifier(name) => {
                    *expr = Expr::CompoundIdentifier(vec![
                        Ident::with_quote('"', alias),
                        Ident::with_quote('"', name.value.to_ascii_lowercase()),
                    ])
                }
                Expr::CompoundIdentifier(parts) => {
                    for name in parts {
                        name.value.make_ascii_lowercase();
                    }
                }
                _ => {}
            }
            ControlFlow::<()>::Continue(())
        });
    }

    fn rename(mut output: Vec<Option<String>>, alias: &mut TableAlias) -> Result<Vec<String>> {
        if alias.columns.len() > output.len() {
            return Err(Binder::invalid("SQL alias"));
        }
        for (column, target) in alias.columns.iter().zip(output.iter_mut()) {
            if column.data_type.is_some() {
                return Err(Binder::invalid("SQL alias"));
            }
            Binder::identifier(&column.name)?;
            *target = Some(column.name.value.clone());
        }
        let output: Vec<_> = output
            .into_iter()
            .collect::<Option<_>>()
            .ok_or_else(|| Binder::invalid("SQL derived columns"))?;
        if output
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .len()
            != output.len()
        {
            return Err(Binder::invalid("SQL derived columns"));
        }
        if !alias.columns.is_empty() {
            alias.columns = output
                .iter()
                .map(
                    |name| datafusion::sql::sqlparser::ast::TableAliasColumnDef {
                        name: Ident::with_quote('"', name),
                        data_type: None,
                    },
                )
                .collect();
        }
        Ok(output)
    }

    fn output_name(item: &SelectItem) -> Option<String> {
        match item {
            SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
            SelectItem::UnnamedExpr(Expr::Identifier(name)) => Some(name.value.clone()),
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                parts.last().map(|name| name.value.clone())
            }
            _ => None,
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

    fn ordinal(expr: &Expr, columns: usize) -> Result<bool> {
        let Some(value) = Self::integer(expr) else {
            return Ok(false);
        };
        if value == 0 || value > columns as u64 {
            return Err(Self::invalid("SQL ordinal"));
        }
        Ok(true)
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
                Binder::identifier(name)?;
            }
            Expr::CompoundIdentifier(parts) => {
                if !(1..=2).contains(&parts.len()) {
                    return Err(Binder::invalid("SQL column"));
                }
                for name in parts {
                    Binder::identifier(name)?;
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
                data_type,
                array: false,
                format: None,
                ..
            } if Self::data_type(data_type) => {}
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
            _ => return Err(Binder::invalid("SQL expression")),
        }
        Ok(())
    }

    fn data_type(value: &DataType) -> bool {
        matches!(
            value,
            DataType::Boolean
                | DataType::Bool
                | DataType::TinyInt(None)
                | DataType::SmallInt(None)
                | DataType::Int(None)
                | DataType::Integer(None)
                | DataType::BigInt(None)
                | DataType::UTinyInt
                | DataType::USmallInt
                | DataType::IntegerUnsigned(None)
                | DataType::UBigInt
                | DataType::HugeInt
                | DataType::Float(_)
                | DataType::Real
                | DataType::Double(_)
                | DataType::Varchar(None)
                | DataType::Text
                | DataType::Blob(None)
                | DataType::Date
                | DataType::Timestamp(None, TimezoneInfo::None)
        )
    }

    fn function(&mut self, function: &mut Function) -> Result<()> {
        let name = Binder::name(&function.name)?;
        if function.uses_odbc_syntax
            || !matches!(function.parameters, FunctionArguments::None)
            || !function.within_group.is_empty()
            || function.null_treatment.is_some()
        {
            return Err(Binder::invalid("SQL function"));
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
                "coalesce" | "nullif" | "lower" | "upper" | "length" | "abs" | "time_bucket"
            )
        {
            return Err(Binder::invalid("SQL function"));
        }
        let FunctionArguments::List(arguments) = &function.args else {
            return Err(Binder::invalid("SQL function"));
        };
        if !arguments.clauses.is_empty() || (!aggregate && arguments.duplicate_treatment.is_some())
        {
            return Err(Binder::invalid("SQL function"));
        }
        let count = arguments.args.len();
        let arity = match name.as_str() {
            "row_number" | "rank" | "dense_rank" => count == 0,
            "coalesce" => count >= 2,
            "nullif" => count == 2,
            "time_bucket" => (2..=3).contains(&count),
            "lag" | "lead" => (1..=3).contains(&count),
            _ => count == 1,
        };
        if !arity {
            return Err(Binder::invalid("SQL function"));
        }
        if name == "time_bucket" {
            let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(width))) = arguments.args.first()
            else {
                return Err(Binder::invalid("SQL bucket width"));
            };
            if TimeTest::fixed_interval(width).is_none() {
                return Err(Binder::invalid("SQL bucket width"));
            }
        }
        for arg in &arguments.args {
            match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(_)) => {}
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                    if name == "count" && count == 1 && arguments.duplicate_treatment.is_none() => {
                }
                _ => return Err(Binder::invalid("SQL function")),
            }
        }
        if matches!(name.as_str(), "lag" | "lead") && count > 1 {
            let FunctionArg::Unnamed(FunctionArgExpr::Expr(offset)) = &arguments.args[1] else {
                return Err(Binder::invalid("SQL window"));
            };
            if !Binder::integer(offset).is_some_and(|value| value <= 200) {
                return Err(Binder::invalid("SQL window"));
            }
        }
        if function.filter.is_some() && !aggregate {
            return Err(Binder::invalid("SQL function"));
        }
        if window && function.over.is_none() {
            return Err(Binder::invalid("SQL window"));
        }
        if let Some(over) = &function.over {
            if !aggregate && !window {
                return Err(Binder::invalid("SQL window"));
            }
            let spec = match over {
                WindowType::WindowSpec(spec) => spec,
                WindowType::NamedWindow(name) => self
                    .windows
                    .get(&Binder::identifier(name)?)
                    .ok_or_else(|| Binder::invalid("SQL window"))?,
            };
            Self::window(spec)?;
            if aggregate && spec.window_frame.is_none() {
                return Err(Binder::invalid("SQL window"));
            }
        }
        self.aggregate |= aggregate || window;
        Ok(())
    }

    fn window(spec: &WindowSpec) -> Result<()> {
        if spec.window_name.is_some() || spec.order_by.is_empty() {
            return Err(Binder::invalid("SQL window"));
        }
        for item in &spec.order_by {
            Binder::order(item)?;
        }
        if let Some(frame) = &spec.window_frame {
            if frame.units != WindowFrameUnits::Rows
                || !Self::window_bound(&frame.start_bound)
                || frame
                    .end_bound
                    .as_ref()
                    .is_some_and(|bound| !Self::window_bound(bound))
            {
                return Err(Binder::invalid("SQL window"));
            }
        }
        Ok(())
    }

    fn window_bound(bound: &WindowFrameBound) -> bool {
        match bound {
            WindowFrameBound::CurrentRow => true,
            WindowFrameBound::Preceding(Some(value)) | WindowFrameBound::Following(Some(value)) => {
                Binder::integer(value).is_some_and(|value| value <= 200)
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
            return ControlFlow::Break(Binder::invalid("SQL depth"));
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
            return Err(Binder::invalid("SQL parameters"));
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
                _ => return Err(Binder::invalid("SQL parameter type")),
            }
        }
        if bytes > PARAMETER_BYTES {
            return Err(Binder::invalid("SQL parameters"));
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
            return Err(Binder::invalid("SQL parameters"));
        }
        Ok(())
    }
}

impl VisitorMut for Parameters {
    type Break = crate::Error;

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return ControlFlow::Break(Binder::invalid("SQL depth"));
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
            return ControlFlow::Break(Binder::invalid("SQL parameters"));
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
        Binder::name(&function.name).is_ok_and(|name| name == "current_timestamp")
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
        let relation = Binder::name(name).ok()?;
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
                |alias| alias.name.value.to_ascii_lowercase(),
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
        matches!(expr, Expr::CompoundIdentifier(parts) if matches!(parts.as_slice(), [table, column]
            if table.value == alias && column.value == "received_at"))
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
            .map_err(|_| Binder::invalid("test plan"))?;
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
                .map_err(|_| Binder::invalid("test plan"))?
                .is_empty());
        }
        assert_eq!(
            sql.program
                .plan
                .get_parameter_names()
                .map_err(|_| Binder::invalid("test plan"))?
                .len(),
            2
        );
        let fixed = QuerySql::admit("SELECT 1 AS value", Vec::new(), false)?;
        assert!(fixed
            .program
            .plan
            .get_parameter_names()
            .map_err(|_| Binder::invalid("test plan"))?
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
        Ok(())
    }

    #[test]
    fn retained_plan_field_metadata() -> Result<()> {
        let metadata = std::collections::HashMap::from([("unit".into(), "source".into())]);
        let schema = Arc::new(Schema::new_with_metadata(
            vec![Field::new("CamelCase", ArrowType::Int64, false).with_metadata(metadata.clone())],
            std::collections::HashMap::from([("dataset".into(), "data".into())]),
        ));
        for query in [
            "SELECT camelcase FROM data",
            "WITH t(Picked) AS (SELECT camelcase FROM data) SELECT picked FROM t",
            "SELECT camelcase FROM data UNION ALL SELECT camelcase FROM data",
            "SELECT SUM(camelcase) AS total FROM data",
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
                .map_err(|_| Binder::invalid("test plan"))?;
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
        let sql = QuerySql::admit("WITH t AS (SELECT operation FROM events) SELECT operation FROM (WITH t AS (SELECT operation FROM events) SELECT operation FROM t) x", Vec::new(), false)?;
        assert_eq!(sql.dependencies(), &BTreeSet::from(["events".to_owned()]));
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(plan.schema().field(0).data_type(), &ArrowType::UInt32);
        Ok(())
    }

    #[test]
    fn full_query_child_compatibility_before_pruning() -> Result<()> {
        let relations = BTreeMap::from([
            (
                "events".to_owned(),
                SCHEMAS
                    .iter()
                    .find(|schema| schema.name == "events")
                    .ok_or_else(|| Binder::invalid("test event schema"))?
                    .arrow_schema(),
            ),
            (
                "data".to_owned(),
                Arc::new(Schema::new(vec![
                    Field::new("CamelCase", ArrowType::Int64, false),
                    Field::new("SourceCursor", ArrowType::UInt64, false),
                ])),
            ),
        ]);
        let query = "WITH unused AS (SELECT operation FROM events), t(AliasName) AS (SELECT camelcase, sourcecursor FROM data) SELECT d.innername AS \"Pick\", d.sourcecursor FROM (WITH t(InnerName) AS (SELECT camelcase, sourcecursor FROM data) SELECT innername, sourcecursor FROM t WINDOW unused AS (ORDER BY sourcecursor)) d WHERE false";
        let sql = QuerySql::admit_relations(query, relations.clone())?;
        assert_eq!(
            sql.dependencies(),
            &BTreeSet::from(["data".to_owned(), "events".to_owned()])
        );
        let binding = sql.bind_complete(0)?;
        assert_eq!(binding.plan.schema().field(0).name(), "Pick");
        assert_eq!(binding.plan.schema().field(1).name(), "SourceCursor");
        let plan = QueryEngine::state()?
            .optimize(&binding.plan)
            .map_err(|_| Binder::invalid("test optimized plan"))?;
        let mut scans = 0;
        plan.apply(|plan| {
            scans += usize::from(matches!(plan, LogicalPlan::TableScan(_)));
            Ok(TreeNodeRecursion::Continue)
        })
        .map_err(|_| Binder::invalid("test optimized sources"))?;
        assert_eq!(scans, 0);
        assert!(QuerySql::admit_relations(
            &query.replace("ORDER BY sourcecursor", "ORDER BY missing"),
            relations,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn quoted_names_and_labels() -> Result<()> {
        let sql = QuerySql::admit(
            r#"SELECT "E"."Operation" AS "Pick" FROM "EVENTS" AS "E""#,
            Vec::new(),
            false,
        )?;
        let binding = sql.bind_complete(0)?;
        let plan = binding.plan()?;
        assert_eq!(plan.schema().field(0).name(), "Pick");
        assert_eq!(
            binding
                .output_schema(plan.schema().as_arrow())?
                .field(0)
                .name(),
            "Pick"
        );
        Ok(())
    }

    #[test]
    fn hidden_index_and_partial_alias() -> Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("value", ArrowType::Int64, false),
            Field::new("__row_index", ArrowType::UInt64, false),
        ]));
        let sources = BTreeMap::from([("data".to_owned(), schema)]);
        let sql = QuerySql::admit_relations(
            "SELECT a.*, b.__row_index AS right_index FROM data a JOIN data b ON a.value = b.value",
            sources.clone(),
        )?;
        let binding = sql.bind_complete(0)?;
        let plan = binding.plan()?;
        assert_eq!(plan.schema().fields().len(), 2);
        assert_eq!(plan.schema().field(0).name(), "value");
        assert_eq!(plan.schema().field(1).name(), "right_index");
        let sql = QuerySql::admit("WITH t(first) AS (SELECT operation, source_cursor FROM events) SELECT first, source_cursor FROM t", Vec::new(), false)?;
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
            let sql =
                QuerySql::admit_relations("SELECT * FROM data GROUP BY value", sources.clone())?;
            let plan = sql.bind_complete(0)?.plan()?;
            assert_eq!(plan.schema().fields().len(), 1);
            assert_eq!(plan.schema().field(0).name(), "value");
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
            ("SELECT camelcase FROM data", "CamelCase"),
            (
                "WITH t AS (SELECT camelcase AS InnerName FROM data) SELECT innername FROM t",
                "InnerName",
            ),
            (
                "WITH t(AliasName) AS (SELECT camelcase FROM data) SELECT aliasname FROM t",
                "AliasName",
            ),
            (
                "WITH t(AliasName) AS (SELECT camelcase AS InnerName FROM data ORDER BY InnerName) SELECT aliasname FROM t",
                "AliasName",
            ),
            (
                "WITH t(AliasName) AS (SELECT camelcase AS InnerName FROM data GROUP BY InnerName HAVING InnerName > 0 ORDER BY InnerName) SELECT aliasname FROM t",
                "AliasName",
            ),
            ("SELECT aliasname FROM data d(AliasName)", "AliasName"),
            (
                "SELECT q.aliasname FROM (SELECT camelcase FROM data) q(AliasName)",
                "AliasName",
            ),
        ] {
            let sql = QuerySql::admit_relations(query, relations.clone())?;
            let binding = sql.bind_complete(0)?;
            let plan = binding.plan()?;
            assert_eq!(plan.schema().field(0).name(), expected);
            assert_eq!(
                binding
                    .output_schema(plan.schema().as_arrow())?
                    .field(0)
                    .name(),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn division_types() -> Result<()> {
        for (query, expected) in [
            ("SELECT 3 / 2 AS value", ArrowType::Float64),
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
            ("SELECT 1.5 AS value", ArrowType::Decimal128(2, 1)),
            ("SELECT 1e3 AS value", ArrowType::Float64),
            (
                "SELECT 9223372036854775808 AS value",
                ArrowType::Decimal256(39, 0),
            ),
            (
                "SELECT 170141183460469231731687303715884105727 AS value",
                ArrowType::Decimal256(39, 0),
            ),
            (
                "SELECT -170141183460469231731687303715884105728 AS value",
                ArrowType::Decimal256(39, 0),
            ),
            ("SELECT -9223372036854775808 AS value", ArrowType::Int64),
            (
                "SELECT 1 AS value UNION ALL SELECT 2 AS value",
                ArrowType::Int32,
            ),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let plan = sql.bind_complete(0)?.plan()?;
            assert_eq!(plan.schema().field(0).data_type(), &expected);
        }
        Ok(())
    }

    #[test]
    fn rewritten_aggregate_names() -> Result<()> {
        for query in [
            "SELECT SUM(1) AS value",
            "SELECT SUM(operation + 1) AS value FROM events",
            "SELECT lag(1) OVER (ORDER BY source_cursor) AS value FROM events",
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let binding = sql.bind_complete(0)?;
            let plan = binding.plan()?;
            assert_eq!(
                binding
                    .output_schema(plan.schema().as_arrow())?
                    .field(0)
                    .name(),
                "value"
            );
        }
        Ok(())
    }

    #[test]
    fn grouped_columns_before_having_aliases() -> Result<()> {
        for query in [
            "SELECT operation AS source_cursor, COUNT(*) AS amount FROM events GROUP BY operation HAVING source_cursor > 1 ORDER BY source_cursor",
            "SELECT COUNT(*) AS operation FROM events GROUP BY operation HAVING operation = 2 ORDER BY 1",
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            sql.bind_complete(0)?;
        }
        Ok(())
    }

    #[test]
    fn large_bucket_width() -> Result<()> {
        let sql = QuerySql::admit(
            "SELECT time_bucket(INTERVAL '9223372036854775807 microseconds', TIMESTAMP '2000-01-03 00:00:00') AS value",
            Vec::new(),
            false,
        )?;
        let plan = sql.bind_complete(0)?.plan()?;
        assert_eq!(
            plan.schema().field(0).data_type(),
            &ArrowType::Timestamp(datafusion::arrow::datatypes::TimeUnit::Microsecond, None)
        );
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
        assert_eq!(plan.schema().field(0).data_type(), &ArrowType::Int32);
        Ok(())
    }

    #[test]
    fn computed_output_names() -> Result<()> {
        for (query, expected) in [
            (
                "SELECT 1, 1, NULL, true, 1e3",
                vec!["1", "1", "NULL", "CAST('t' AS BOOLEAN)", "1000.0"],
            ),
            (
                "SELECT operation + 1, length(node_id) FROM events",
                vec!["(operation + 1)", "length(node_id)"],
            ),
            (
                "SELECT COUNT(*), SUM(operation) FROM events",
                vec!["count_star()", "sum(operation)"],
            ),
            (
                "SELECT CAST('1.5' AS HUGEINT)",
                vec!["CAST('1.5' AS \"HUGEINT\")"],
            ),
            (
                "SELECT row_number() OVER (ORDER BY source_cursor) FROM events",
                vec!["row_number() OVER (ORDER BY source_cursor)"],
            ),
            (
                "SELECT lag(operation) OVER w FROM events WINDOW w AS (ORDER BY source_cursor)",
                vec!["lag(operation) OVER (ORDER BY source_cursor)"],
            ),
            ("SELECT current_timestamp", vec!["current_timestamp"]),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let binding = sql.bind_complete(123_000)?;
            let plan = binding.plan()?;
            let schema = binding.output_schema(plan.schema().as_arrow())?;
            assert_eq!(
                schema
                    .fields()
                    .iter()
                    .map(|field| field.name().as_str())
                    .collect::<Vec<_>>(),
                expected,
                "{query}"
            );
        }
        assert!(QuerySql::admit("SELECT now()", Vec::new(), false).is_err());
        Ok(())
    }

    #[test]
    fn trusted_wildcard_schema() -> Result<()> {
        let binding = QueryBinding::trusted("SELECT * FROM events".into(), Vec::new(), 0)?;
        let plan = binding.plan()?;
        assert_eq!(
            binding.output_schema(plan.schema().as_arrow())?.as_ref(),
            plan.schema().as_arrow()
        );
        Ok(())
    }

    #[test]
    fn result_numeric_widths() -> Result<()> {
        for (query, expected) in [
            ("SELECT length(node_id) AS value FROM events", ArrowType::Int64),
            ("SELECT rank() OVER (ORDER BY source_cursor) AS value FROM events", ArrowType::Int64),
            ("SELECT dense_rank() OVER (ORDER BY source_cursor) AS value FROM events", ArrowType::Int64),
            ("SELECT SUM(operation) AS value FROM events", ArrowType::Decimal256(39, 0)),
            ("SELECT SUM(CAST(operation AS HUGEINT)) AS value FROM events", ArrowType::Decimal256(39, 0)),
            ("SELECT SUM(CAST(operation AS FLOAT)) AS value FROM events", ArrowType::Float64),
            ("SELECT SUM(true) AS value", ArrowType::Decimal256(39, 0)),
            ("SELECT SUM(operation) OVER (ORDER BY source_cursor ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS value FROM events", ArrowType::Decimal256(39, 0)),
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let plan = sql.bind_complete(0)?.plan()?;
            assert_eq!(plan.schema().field(0).data_type(), &expected, "{query}");
        }
        Ok(())
    }

    #[test]
    fn wider_sum_execution() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use datafusion::arrow::array::Int64Array;
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
        let sql =
            QuerySql::admit_relations("SELECT SUM(value) AS total FROM data", relations.clone())?;
        let engine = QueryEngine::default();
        let state = QueryEngine::state()?;
        let control = crate::AnalysisReadControl::with_timeout(std::time::Duration::from_secs(5))?;
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
                LogicalTypeId::Hugeint
            )?
            .to_owned(),
            Value::HugeInt(2 * i128::from(i64::MAX))
        );
        let sql = QuerySql::admit_relations(
            &format!(
                "SELECT SUM(CAST('{}' AS HUGEINT)) AS total FROM data",
                i128::MAX
            ),
            relations.clone(),
        )?;
        assert!(engine
            .query(
                &state,
                &sql.bind_complete(0)?,
                &tables,
                araphor_analysis_sdk::Limits::default(),
                &control,
                &lease,
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
            .map_err(|_| Binder::invalid("test plan"))?;
        assert_eq!(scans, ["events", "events"]);
        assert_eq!(sql.bind_complete(0)?.plan()?.schema().fields().len(), 1);
        Ok(())
    }

    #[test]
    fn engine_bound_unused_windows() -> Result<()> {
        QuerySql::admit(
            "SELECT operation FROM events WINDOW unused AS (ORDER BY CAST(operation AS HUGEINT))",
            Vec::new(),
            false,
        )?;
        QuerySql::admit(
            "SELECT lag(operation) OVER \"Subject\" FROM events WINDOW \"SUBJECT\" AS (ORDER BY source_cursor)",
            Vec::new(), false,
        )?;
        for query in [
            "SELECT operation FROM events WINDOW unused AS (ORDER BY missing)",
            "SELECT operation FROM events WINDOW unused AS (PARTITION BY missing ORDER BY source_cursor)",
            "SELECT operation FROM events WINDOW same AS (ORDER BY source_cursor), \"SAME\" AS (ORDER BY source_cursor)",
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
        .map_err(|_| Binder::invalid("test source projection"))?;
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
    fn engine_bound_grouped_input_before_having_alias() -> Result<()> {
        for query in [
            "SELECT COUNT(*) AS operation FROM events GROUP BY operation HAVING operation = 2",
            "SELECT COUNT(*) AS operation FROM events GROUP BY (operation) HAVING operation = 2",
            "SELECT operation AS key, COUNT(*) AS operation FROM events GROUP BY 1 HAVING operation = 2",
            "SELECT operation AS key, COUNT(*) AS operation FROM events GROUP BY key HAVING operation = 2",
        ] {
            let sql = QuerySql::admit(query, Vec::new(), false)?;
            let mut source = false;
            sql.program.plan.apply(|plan| {
                if let LogicalPlan::Filter(filter) = plan {
                    filter.predicate.apply(|expr| {
                        if let EngineExpression::Column(column) = expr {
                            source |= column.name == "operation"
                                && column.relation.as_ref().is_some_and(|name| name.table() == "events");
                        }
                        Ok(TreeNodeRecursion::Continue)
                    })?;
                }
                Ok(TreeNodeRecursion::Continue)
            }).map_err(|_| Binder::invalid("test plan"))?;
            assert!(source, "{query}");
        }
        Ok(())
    }

    #[test]
    fn trusted_uinteger_cast() -> Result<()> {
        let binding = QueryBinding::trusted(
            "SELECT CAST(? AS UINTEGER) AS value".into(),
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
            "WITH scoped_events AS (SELECT * FROM events WHERE received_utc_ns >= ? AND received_utc_ns <= ?) SELECT * FROM scoped_events WHERE (CAST(? AS UINTEGER) IS NULL OR operation = ?) ORDER BY commit_revision, ordinal".into(),
            vec![Value::UBigInt(0), Value::UBigInt(u64::MAX), Value::Null, Value::Null], 0,
        )?;
        let schema = SCHEMAS
            .iter()
            .find(|schema| schema.name == "events")
            .ok_or_else(|| Binder::invalid("test schema"))?;
        assert_eq!(
            binding.plan()?.schema().fields().len(),
            schema.fields().len()
        );
        assert_eq!(
            binding
                .output_schema(binding.plan()?.schema().as_arrow())?
                .fields()
                .len(),
            schema.fields().len()
        );
        Ok(())
    }
}
