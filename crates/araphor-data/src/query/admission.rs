use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Bound, ControlFlow};

use duckdb::types::{TimeUnit, Value};
use sqlparser::ast::{
    BinaryOperator, DataType, DateTimeField, Distinct, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, JoinConstraint, JoinOperator,
    LimitClause, NamedWindowExpr, ObjectName, OrderBy, OrderByExpr, OrderByKind, OrderBySort,
    Query, Select, SelectFlavor, SelectItem, SelectItemQualifiedWildcardKind, SetExpr,
    SetQuantifier, Statement, TableAlias, TableFactor, TimezoneInfo, UnaryOperator,
    Value as SqlValue, VisitMut as _, VisitorMut, WildcardAdditionalOptions, WindowFrameBound,
    WindowFrameUnits, WindowSpec, WindowType,
};
use sqlparser::dialect::DuckDbDialect;
use sqlparser::parser::Parser;
use time::PrimitiveDateTime;

use super::{input::SCHEMAS, QueryOperation};
use crate::Result;

const SQL_BYTES: usize = 16 * 1024;
const PARAMETER_BYTES: usize = 1024 * 1024;
const PARAMETER_COUNT: usize = 256;
const AST_DEPTH: usize = 64;
const POSITION_FIELDS: [&str; 2] = ["__araphor_commit_revision", "__araphor_ordinal"];

/// Client SQL uses the available code-owned schemas.
#[derive(Clone, Debug, PartialEq)]
pub struct QuerySql {
    original: String,
    query: Box<Query>,
    parameters: Vec<Value>,
    dependencies: BTreeSet<String>,
    operation: QueryOperation,
    moving: Option<u32>,
    tests: Vec<TimeTest>,
    clocks: usize,
    follow: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueryBinding {
    pub sql: String,
    pub parameters: Vec<Value>,
    pub received_from: Bound<u64>,
    pub received_until: Bound<u64>,
    pub evaluated_utc_ns: u64,
    pub append: bool,
}

impl QuerySql {
    pub fn admit(sql: &str, parameters: Vec<Value>, follow: bool) -> Result<Self> {
        if sql.is_empty() || sql.len() > SQL_BYTES {
            return Err(Binder::invalid("SQL length"));
        }
        Parameters::validate(&parameters)?;
        let mut statements = Parser::new(&DuckDbDialect {})
            .with_recursion_limit(AST_DEPTH)
            .try_with_sql(sql)
            .and_then(|mut parser| parser.parse_statements())
            .map_err(|_| Binder::invalid("SQL syntax"))?;
        if statements.len() != 1 {
            return Err(Binder::invalid("SQL statement"));
        }
        let Some(Statement::Query(mut query)) = statements.pop() else {
            return Err(Binder::invalid("SQL statement"));
        };
        Parameters::bind(&mut query, parameters.len())?;
        let mut binder = Binder {
            dependencies: BTreeSet::new(),
            aggregate: false,
            clocks: 0,
            depth: 0,
        };
        binder.query(&mut query, &BTreeMap::new())?;
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
        let dependencies = std::mem::take(&mut binder.dependencies);
        let clocks = binder.clocks;
        if query.to_string().len() > SQL_BYTES {
            return Err(Binder::invalid("expanded SQL length"));
        }
        Ok(Self {
            original: sql.to_owned(),
            query,
            parameters,
            dependencies,
            operation,
            moving: moving.into_iter().min(),
            tests,
            clocks,
            follow,
        })
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn parameters(&self) -> &[Value] {
        &self.parameters
    }

    pub fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    pub fn operation(&self) -> QueryOperation {
        self.operation
    }

    pub fn follow(&self) -> bool {
        self.follow
    }

    pub(super) fn source_column(
        &self,
        name: &str,
    ) -> Option<(
        &'static super::input::InputSchema,
        &'static super::input::InputField,
    )> {
        if self.query.with.is_some() {
            return None;
        }
        let SetExpr::Select(select) = self.query.body.as_ref() else {
            return None;
        };
        let [from] = select.from.as_slice() else {
            return None;
        };
        if !from.joins.is_empty() {
            return None;
        }
        let TableFactor::Table {
            name: table, alias, ..
        } = &from.relation
        else {
            return None;
        };
        if alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
        {
            return None;
        }
        let relation = Binder::name(table).ok()?;
        let mut items = select
            .projection
            .iter()
            .filter(|item| Scope::output_name(item).as_deref() == Some(name));
        let item = items.next()?;
        if items.next().is_some() {
            return None;
        }
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
        let schema = SCHEMAS.iter().find(|schema| schema.name == relation)?;
        let field = schema
            .columns
            .iter()
            .find(|field| field.0 == column.value)?;
        Some((schema, field))
    }

    pub fn moving_seconds(&self) -> Option<u32> {
        self.moving
    }

    pub fn bind_at(&self, now_ns: u64) -> Result<QueryBinding> {
        let mut query = self.query.clone();
        let mut parameters = self.parameters.clone();
        if self.clocks > 0 {
            parameters.push(Value::Timestamp(
                TimeUnit::Microsecond,
                (now_ns / 1_000) as i64,
            ));
            let _ = query.visit(&mut FrozenClock(parameters.len()));
        }
        let append = self.operation == QueryOperation::Append;
        if append {
            Self::append_positions(&mut query)?;
        }
        let mut first = 0_i128;
        let mut last = i128::from(u64::MAX);
        for test in &self.tests {
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
        Ok(QueryBinding {
            sql: query.to_string(),
            parameters,
            received_from,
            received_until,
            evaluated_utc_ns: now_ns,
            append,
        })
    }

    fn append_shape(query: &Query) -> bool {
        let Some((select, _)) = TimeTest::direct_events(query) else {
            return false;
        };
        query.limit_clause.is_none()
            && query.order_by.is_none()
            && select.distinct.is_none()
            && select.having.is_none()
            && matches!(&select.group_by, GroupByExpr::Expressions(items, _) if items.is_empty())
    }

    fn append_positions(query: &mut Query) -> Result<()> {
        let Some((_, alias)) = TimeTest::direct_events(query) else {
            return Err(Binder::invalid("append SQL shape"));
        };
        let SetExpr::Select(select) = query.body.as_mut() else {
            return Err(Binder::invalid("append SQL shape"));
        };
        let mut order = Vec::new();
        for field in POSITION_FIELDS {
            let expr = Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', &alias),
                Ident::with_quote('"', field),
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

struct Binder {
    dependencies: BTreeSet<String>,
    aggregate: bool,
    clocks: usize,
    depth: usize,
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

    fn query(
        &mut self,
        query: &mut Query,
        inherited: &BTreeMap<String, Vec<String>>,
    ) -> Result<Vec<Option<String>>> {
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
        let mut ctes = inherited.clone();
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
                let output = self.query(&mut cte.query, &ctes)?;
                ctes.insert(name, Scope::rename(output, &cte.alias)?);
            }
        }
        let (output, scope) = self.body(&mut query.body, &ctes)?;
        if let Some(order) = &mut query.order_by {
            let OrderByKind::Expressions(items) = &mut order.kind else {
                return Err(Self::invalid("SQL ordering"));
            };
            if order.interpolate.is_some() {
                return Err(Self::invalid("SQL ordering"));
            }
            for item in items {
                Self::order(item)?;
                if !Self::ordinal(&item.expr, output.len())? {
                    self.expression(&mut item.expr, &scope, &output, true, &BTreeMap::new())?;
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
        self.depth -= 1;
        Ok(output)
    }

    fn body(
        &mut self,
        body: &mut SetExpr,
        ctes: &BTreeMap<String, Vec<String>>,
    ) -> Result<(Vec<Option<String>>, Scope)> {
        self.depth += 1;
        if self.depth > AST_DEPTH {
            return Err(Self::invalid("SQL depth"));
        }
        let result = match body {
            SetExpr::Select(select) => self.select(select, ctes),
            SetExpr::Query(query) => {
                let output = self.query(query, ctes)?;
                Ok((output, Scope::default()))
            }
            SetExpr::SetOperation {
                left,
                right,
                set_quantifier: SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
                ..
            } => {
                self.aggregate = true;
                let (left, _) = self.body(left, ctes)?;
                let (right, _) = self.body(right, ctes)?;
                if left.len() != right.len() {
                    return Err(Self::invalid("SQL set columns"));
                }
                Ok((left, Scope::default()))
            }
            _ => Err(Self::invalid("SQL body")),
        };
        self.depth -= 1;
        result
    }

    fn select(
        &mut self,
        select: &mut Select,
        ctes: &BTreeMap<String, Vec<String>>,
    ) -> Result<(Vec<Option<String>>, Scope)> {
        if select.into.is_some()
            || !select.optimizer_hints.is_empty()
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
        let mut scope = Scope::default();
        for from in &mut select.from {
            scope.add(self.table(&mut from.relation, ctes)?)?;
            for join in &mut from.joins {
                if join.global {
                    return Err(Self::invalid("SQL join"));
                }
                let right = self.table(&mut join.relation, ctes)?;
                let right_name = right.0.clone();
                scope.add(right)?;
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
                self.expression(expr, &scope, &[], false, &BTreeMap::new())?;
                if !Self::equijoin(expr, &right_name) {
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
            for expr in &mut spec.partition_by {
                self.expression(expr, &scope, &[], false, &BTreeMap::new())?;
            }
            for item in &mut spec.order_by {
                self.expression(&mut item.expr, &scope, &[], false, &BTreeMap::new())?;
            }
            if windows
                .insert(Self::identifier(&window.0)?, spec.clone())
                .is_some()
            {
                return Err(Self::invalid("SQL window"));
            }
        }
        let mut projection = Vec::new();
        for item in std::mem::take(&mut select.projection) {
            match item {
                SelectItem::Wildcard(options) => {
                    Self::wildcard(&options)?;
                    scope.expand(None, &mut projection)?;
                }
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    options,
                ) => {
                    Self::wildcard(&options)?;
                    scope.expand(Some(&Self::name(&name)?), &mut projection)?;
                }
                SelectItem::UnnamedExpr(mut expr) => {
                    self.expression(&mut expr, &scope, &[], false, &windows)?;
                    projection.push(SelectItem::UnnamedExpr(expr));
                }
                SelectItem::ExprWithAlias { mut expr, alias } => {
                    Self::identifier(&alias)?;
                    self.expression(&mut expr, &scope, &[], false, &windows)?;
                    projection.push(SelectItem::ExprWithAlias { expr, alias });
                }
                _ => return Err(Self::invalid("SQL projection")),
            }
        }
        if projection.is_empty() || projection.len() > 256 {
            return Err(Self::invalid("SQL projection"));
        }
        let output: Vec<_> = projection.iter().map(Scope::output_name).collect();
        select.projection = projection;
        if let Some(expr) = &mut select.selection {
            self.expression(expr, &scope, &[], false, &windows)?;
        }
        match &mut select.group_by {
            GroupByExpr::Expressions(items, modifiers) if modifiers.is_empty() => {
                for expr in items {
                    if !Self::ordinal(expr, output.len())? {
                        self.expression(expr, &scope, &output, false, &windows)?;
                    }
                }
            }
            _ => return Err(Self::invalid("SQL grouping")),
        }
        if let Some(expr) = &mut select.having {
            // Keep output names unqualified. DuckDB checks grouped columns before aliases.
            self.expression(expr, &scope, &output, true, &windows)?;
        }
        Ok((output, scope))
    }

    fn table(
        &mut self,
        table: &mut TableFactor,
        ctes: &BTreeMap<String, Vec<String>>,
    ) -> Result<(String, Vec<String>)> {
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
                let columns = if let Some(columns) = ctes.get(&name) {
                    columns.clone()
                } else {
                    let columns = SCHEMAS
                        .iter()
                        .find(|schema| schema.name == name && schema.readiness == "available")
                        .ok_or_else(|| Self::invalid("SQL relation"))?
                        .columns
                        .iter()
                        .map(|field| field.0.to_owned())
                        .collect();
                    self.dependencies.insert(name.clone());
                    columns
                };
                if let Some(alias) = alias {
                    Ok((
                        Self::identifier(&alias.name)?,
                        Scope::rename(columns.into_iter().map(Some).collect(), alias)?,
                    ))
                } else {
                    Ok((name, columns))
                }
            }
            TableFactor::Derived {
                lateral: false,
                subquery,
                alias: Some(alias),
                sample: None,
            } => {
                let output = self.query(subquery, ctes)?;
                Ok((
                    Self::identifier(&alias.name)?,
                    Scope::rename(output, alias)?,
                ))
            }
            _ => Err(Self::invalid("SQL relation")),
        }
    }

    fn expression(
        &mut self,
        expr: &mut Expr,
        scope: &Scope,
        output: &[Option<String>],
        output_first: bool,
        windows: &BTreeMap<String, WindowSpec>,
    ) -> Result<()> {
        let mut check = Expression {
            scope,
            output,
            output_first,
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

    fn wildcard(options: &WildcardAdditionalOptions) -> Result<()> {
        if options.opt_ilike.is_some()
            || options.opt_exclude.is_some()
            || options.opt_except.is_some()
            || options.opt_replace.is_some()
            || options.opt_rename.is_some()
            || options.opt_alias.is_some()
        {
            return Err(Self::invalid("SQL wildcard"));
        }
        Ok(())
    }

    fn order(item: &OrderByExpr) -> Result<()> {
        if item.with_fill.is_some() || matches!(item.options.sort, Some(OrderBySort::Using(_))) {
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

    fn equijoin(expr: &Expr, right_name: &str) -> bool {
        match expr {
            Expr::Nested(expr) => Self::equijoin(expr, right_name),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => Self::equijoin(left, right_name) && Self::equijoin(right, right_name),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => match (left.as_ref(), right.as_ref()) {
                (Expr::CompoundIdentifier(left), Expr::CompoundIdentifier(right)) => {
                    left.len() == 2
                        && right.len() == 2
                        && left[0] != right[0]
                        && (left[0].value == right_name || right[0].value == right_name)
                }
                _ => false,
            },
            _ => false,
        }
    }
}

#[derive(Default)]
struct Scope(Vec<(String, Vec<String>)>);

impl Scope {
    fn add(&mut self, relation: (String, Vec<String>)) -> Result<()> {
        if self.0.iter().any(|entry| entry.0 == relation.0) {
            return Err(Binder::invalid("SQL alias"));
        }
        self.0.push(relation);
        Ok(())
    }

    fn rename(mut output: Vec<Option<String>>, alias: &TableAlias) -> Result<Vec<String>> {
        if alias.at.is_some() || alias.columns.len() > output.len() {
            return Err(Binder::invalid("SQL alias"));
        }
        for (column, target) in alias.columns.iter().zip(output.iter_mut()) {
            if column.data_type.is_some() {
                return Err(Binder::invalid("SQL alias"));
            }
            *target = Some(Binder::identifier(&column.name)?);
        }
        let output: Vec<_> = output
            .into_iter()
            .collect::<Option<_>>()
            .ok_or_else(|| Binder::invalid("SQL derived columns"))?;
        if output.iter().collect::<BTreeSet<_>>().len() != output.len() {
            return Err(Binder::invalid("SQL derived columns"));
        }
        Ok(output)
    }

    fn output_name(item: &SelectItem) -> Option<String> {
        match item {
            SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.to_ascii_lowercase()),
            SelectItem::UnnamedExpr(Expr::Identifier(name)) => {
                Some(name.value.to_ascii_lowercase())
            }
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                parts.last().map(|name| name.value.to_ascii_lowercase())
            }
            _ => None,
        }
    }

    fn expand(&self, target: Option<&str>, projection: &mut Vec<SelectItem>) -> Result<()> {
        let mut found = false;
        for (relation, columns) in &self.0 {
            if target.is_none_or(|name| name == relation) {
                found = true;
                projection.extend(columns.iter().map(|column| {
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(vec![
                        Ident::with_quote('"', relation),
                        Ident::with_quote('"', column),
                    ]))
                }));
            }
        }
        if !found {
            return Err(Binder::invalid("SQL column"));
        }
        Ok(())
    }

    fn has_column(&self, column: &str) -> bool {
        self.0
            .iter()
            .any(|(_, columns)| columns.iter().any(|name| name == column))
    }

    fn resolve(&self, parts: &[Ident]) -> Result<Expr> {
        let (target, column) = match parts {
            [column] => (None, Binder::identifier(column)?),
            [table, column] => (
                Some(Binder::identifier(table)?),
                Binder::identifier(column)?,
            ),
            _ => return Err(Binder::invalid("SQL column")),
        };
        let mut found = self.0.iter().filter(|(name, columns)| {
            target.as_ref().is_none_or(|target| target == name) && columns.contains(&column)
        });
        let Some((name, _)) = found.next() else {
            return Err(Binder::invalid("SQL column"));
        };
        if found.next().is_some() {
            return Err(Binder::invalid("SQL column"));
        }
        Ok(Expr::CompoundIdentifier(vec![
            Ident::with_quote('"', name),
            Ident::with_quote('"', column),
        ]))
    }
}

struct Expression<'a> {
    scope: &'a Scope,
    output: &'a [Option<String>],
    output_first: bool,
    windows: &'a BTreeMap<String, WindowSpec>,
    aggregate: bool,
    clocks: usize,
    depth: usize,
}

impl Expression<'_> {
    fn check(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(name) => {
                let key = Binder::identifier(name)?;
                let aliases = self
                    .output
                    .iter()
                    .filter(|name| name.as_deref() == Some(&key))
                    .count();
                if aliases > 0 && (self.output_first || !self.scope.has_column(&key)) {
                    if aliases != 1 {
                        return Err(Binder::invalid("SQL column"));
                    }
                    *name = Ident::with_quote('"', key);
                } else {
                    *expr = self.scope.resolve(std::slice::from_ref(name))?;
                }
            }
            Expr::CompoundIdentifier(parts) => *expr = self.scope.resolve(parts)?,
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
            if !TimeTest::fixed_interval(width) {
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
        if Binder::name(name).ok()?.as_str() != "events"
            || alias
                .as_ref()
                .is_some_and(|alias| !alias.columns.is_empty())
        {
            return None;
        }
        Some((
            select,
            alias.as_ref().map_or_else(
                || "events".to_owned(),
                |alias| alias.name.value.to_ascii_lowercase(),
            ),
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

    fn fixed_interval(expr: &Expr) -> bool {
        let Expr::Interval(interval) = expr else {
            return false;
        };
        if interval.leading_precision.is_some()
            || interval.last_field.is_some()
            || interval.fractional_seconds_precision.is_some()
        {
            return false;
        }
        let Expr::Value(value) = interval.value.as_ref() else {
            return false;
        };
        let SqlValue::SingleQuotedString(value) = &value.value else {
            return false;
        };
        let parts: Vec<_> = value.split_whitespace().collect();
        let (number, unit) = match (interval.leading_field.as_ref(), parts.as_slice()) {
            (None, [number, unit]) => (
                *number,
                unit.to_ascii_lowercase().trim_end_matches('s').to_owned(),
            ),
            (Some(unit), [number]) => (*number, unit.to_string().to_ascii_lowercase()),
            _ => return false,
        };
        let scale = match unit.as_str() {
            "microsecond" => 1_u64,
            "millisecond" => 1_000,
            "second" => 1_000_000,
            "minute" => 60_000_000,
            "hour" => 3_600_000_000,
            "day" => 86_400_000_000,
            _ => return false,
        };
        number
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .and_then(|number| number.checked_mul(scale))
            .is_some_and(|micros| micros <= i64::MAX as u64)
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
