use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use araphor_data::AnalysisSelectionV1;
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::common::{ExprSchema, ScalarValue};
use datafusion::datasource::empty::EmptyTable;
use datafusion::datasource::source_as_provider;
use datafusion::functions::datetime::{date_bin::DateBinFunc, now::NowFunc};
use datafusion::logical_expr::{
    BinaryExpr, Expr, ExprSchemable, LogicalPlan, Operator, Volatility,
};
use datafusion::optimizer::simplify_expressions::{ExprSimplifier, SimplifyContext};
use snafu::ResultExt as _;

use crate::definition::PackageCall;
use crate::sources::{SourcePort, SourceProvider};
use crate::{InvalidSnafu, Result, SqlSnafu};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Window {
    Moving {
        inclusive: Option<u64>,
        exclusive: Option<u64>,
    },
    Fixed {
        bin: Arc<Expr>,
        lower: bool,
        upper: bool,
    },
}

#[derive(Default)]
pub(crate) struct Windows {
    visited: BTreeMap<usize, Vec<Option<Window>>>,
    error: Option<crate::Error>,
    clocks: usize,
    stack: Vec<Option<Window>>,
    scans: Vec<Option<Window>>,
    filters: usize,
    invalid: bool,
    invalid_nested: bool,
    varying: bool,
    runtime: bool,
}

impl Windows {
    fn read(plan: &LogicalPlan) -> Result<Self> {
        let mut windows = Self::default();
        plan.visit_with_subqueries(&mut windows).context(SqlSnafu)?;
        if let Some(error) = windows.error.take() {
            match error {
                crate::Error::Invalid {
                    field: "follow clock filter",
                    ..
                } => {
                    windows.invalid_nested = true;
                    windows.varying = true;
                    windows.runtime = true;
                }
                error => return Err(error),
            }
        }
        windows.visited.clear();
        windows.stack.clear();
        Ok(windows)
    }

    pub(crate) fn programs(inputs: &[LogicalPlan]) -> Result<Self> {
        let mut windows = Self::default();
        for input in inputs {
            windows.absorb(&Self::read(input)?);
        }
        Ok(windows)
    }

    pub(crate) fn runtime(&self) -> bool {
        self.runtime
    }

    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.clocks == other.clocks
            && self.scans == other.scans
            && self.filters == other.filters
            && self.invalid == other.invalid
            && self.invalid_nested == other.invalid_nested
            && self.varying == other.varying
            && self.runtime == other.runtime
    }

    fn scan(&mut self, window: Option<Window>) {
        if let Some(first) = self.scans.first() {
            self.invalid |= first != &window;
        } else {
            self.scans.push(window);
        }
    }

    fn absorb(&mut self, other: &Self) {
        self.clocks += other.clocks;
        self.filters += other.filters;
        self.invalid |= other.invalid;
        self.invalid_nested |= other.invalid_nested;
        self.varying |= other.varying;
        self.runtime |= other.runtime;
        if let Some(window) = other.scans.first() {
            self.scan(window.clone());
        }
    }

    fn finish(mut self) -> Result<Option<Window>> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if self.invalid_nested {
            return InvalidSnafu {
                field: "follow clock filter",
            }
            .fail();
        }
        if self.clocks == 0 {
            return Ok(None);
        }
        let window = self.scans.first().cloned().flatten();
        if self.invalid
            || window.as_ref().is_none_or(|window| !window.complete())
            || self.filters != self.clocks
            || self.scans.iter().any(|scan| scan != &window)
        {
            return InvalidSnafu {
                field: "follow clock filter",
            }
            .fail();
        }
        Ok(window)
    }
}

impl<'n> TreeNodeVisitor<'n> for Windows {
    type Node = LogicalPlan;

    fn f_down(&mut self, plan: &'n LogicalPlan) -> datafusion::common::Result<TreeNodeRecursion> {
        let inherited = self.stack.last().cloned().flatten();
        let visits = self
            .visited
            .entry(std::ptr::from_ref(plan) as usize)
            .or_default();
        if visits.contains(&inherited) {
            self.stack.push(inherited);
            return Ok(TreeNodeRecursion::Jump);
        }
        visits.push(inherited.clone());
        if let LogicalPlan::TableScan(scan) = plan {
            self.varying |= !source_as_provider(&scan.source).is_ok_and(|provider| {
                provider.is::<SourceProvider>()
                    || provider.is::<SourcePort>()
                    || provider.is::<EmptyTable>()
            });
        }
        if matches!(
            plan,
            LogicalPlan::RecursiveQuery(_) | LogicalPlan::Extension(_)
        ) {
            self.runtime = true;
        }
        if let LogicalPlan::TableScan(scan) = plan {
            self.runtime |= !source_as_provider(&scan.source).is_ok_and(|provider| {
                if let Some(source) = provider.downcast_ref::<SourceProvider>() {
                    !matches!(source.origin, crate::sources::SourceOrigin::Local(_))
                } else {
                    provider.is::<SourcePort>() || provider.is::<EmptyTable>()
                }
            });
        }
        plan.apply_expressions(|expression| {
            expression.apply(|expression| {
                self.runtime |= match expression {
                    Expr::ScalarFunction(function) => {
                        function.func.signature().volatility == Volatility::Stable
                    }
                    Expr::AggregateFunction(function) => {
                        function.func.signature().volatility == Volatility::Stable
                    }
                    Expr::WindowFunction(function) => {
                        function.fun.signature().volatility == Volatility::Stable
                    }
                    Expr::ScalarVariable(..) | Expr::Placeholder(..) => true,
                    _ => false,
                };
                self.varying |= match expression {
                    Expr::ScalarFunction(function) => {
                        function.func.signature().volatility != Volatility::Immutable
                    }
                    Expr::AggregateFunction(function) => {
                        function.func.signature().volatility != Volatility::Immutable
                    }
                    Expr::WindowFunction(function) => {
                        function.fun.signature().volatility != Volatility::Immutable
                    }
                    Expr::ScalarVariable(..) | Expr::Placeholder(..) => true,
                    _ => false,
                };
                Ok(TreeNodeRecursion::Continue)
            })
        })?;
        if let LogicalPlan::TableScan(scan) = plan {
            if let Ok(provider) = source_as_provider(&scan.source) {
                if let Some(source) = provider.downcast_ref::<SourcePort>() {
                    self.absorb(source.windows());
                    self.stack.push(None);
                    return Ok(TreeNodeRecursion::Jump);
                }
            }
        }
        if let LogicalPlan::Extension(extension) = plan {
            if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                for child in &call.children {
                    let result = Windows::read(child).and_then(|windows| {
                        self.varying |= windows.varying;
                        self.runtime |= windows.runtime;
                        windows.finish()
                    });
                    if let Err(error) = result {
                        self.error = Some(error);
                        return Ok(TreeNodeRecursion::Stop);
                    }
                }
                self.stack.push(None);
                return Ok(TreeNodeRecursion::Jump);
            }
        }
        if let LogicalPlan::Join(join) = plan {
            if let Some(predicate) = &join.filter {
                self.clocks += Window::event_clocks(predicate, plan.schema())?;
            }
        }
        let mut window = inherited;
        if !Window::preserves(plan) && !Window::events(plan) {
            window = None;
        }
        if let LogicalPlan::Filter(filter) = plan {
            let filters = self.filters;
            filter.predicate.apply(|expression| {
                if matches!(expression, Expr::BinaryExpr(binary) if binary.op == Operator::And) {
                    return Ok(TreeNodeRecursion::Continue);
                }
                self.clocks += Window::event_clocks(expression, filter.input.schema())?;
                if let Some(found) = Window::predicate(expression, filter.input.schema()) {
                    window = match window.take() {
                        Some(current) => current.intersect(found),
                        None => Some(found),
                    };
                    self.invalid |= window.is_none();
                    self.filters += 1;
                }
                Ok(TreeNodeRecursion::Jump)
            })?;
            if self.filters != filters {
                let mut local = false;
                filter.input.apply(|input| {
                    if Window::events(input) {
                        local = true;
                    }
                    Ok(if Window::preserves(input) {
                        TreeNodeRecursion::Continue
                    } else {
                        TreeNodeRecursion::Jump
                    })
                })?;
                self.invalid |= !local;
            }
        }
        if Window::events(plan) {
            self.scan(window.clone());
        }
        self.stack.push(window);
        Ok(TreeNodeRecursion::Continue)
    }

    fn f_up(&mut self, _: &'n LogicalPlan) -> datafusion::common::Result<TreeNodeRecursion> {
        self.stack.pop();
        Ok(TreeNodeRecursion::Continue)
    }
}

impl Window {
    fn event_clocks(
        expression: &Expr,
        schema: &datafusion::common::DFSchema,
    ) -> datafusion::common::Result<usize> {
        let (mut clocks, mut event) = (0, false);
        expression.apply(|expression| {
            clocks += usize::from(Self::clock(expression));
            if let Expr::Column(column) = expression {
                event |= column.name == "received_at"
                    && schema.field_from_column(column).is_ok_and(|field| {
                        field.data_type() == &DataType::Timestamp(TimeUnit::Microsecond, None)
                            && field.metadata().get("araphor.units").map(String::as_str)
                                == Some("microseconds since Unix epoch")
                    });
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(if event { clocks } else { 0 })
    }

    pub(crate) fn clocks(plan: &LogicalPlan) -> Result<usize> {
        let mut count = 0;
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                if let Ok(provider) = source_as_provider(&scan.source) {
                    if let Some(source) = provider.downcast_ref::<SourcePort>() {
                        count += source.clocks();
                    }
                }
            }
            plan.apply_expressions(|expression| {
                expression.apply(|expression| {
                    if Self::clock(expression) {
                        count += 1;
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
            })?;
            Ok(TreeNodeRecursion::Continue)
        })
        .context(SqlSnafu)?;
        Ok(count)
    }

    pub(crate) fn infer(plan: &LogicalPlan) -> Result<(Option<Self>, bool)> {
        let windows = Windows::read(plan)?;
        let varying = windows.varying;
        match windows.finish() {
            Err(crate::Error::Invalid {
                field: "follow clock filter",
                ..
            }) => Ok((None, varying)),
            result => result.map(|window| (window, varying)),
        }
    }

    pub(crate) fn from_plan(plan: &LogicalPlan) -> Result<Option<Self>> {
        Windows::read(plan)?.finish()
    }

    fn complete(&self) -> bool {
        !matches!(self, Self::Fixed { lower, upper, .. } if !lower || !upper)
    }

    fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (
                Self::Moving {
                    inclusive,
                    exclusive,
                },
                Self::Moving {
                    inclusive: next,
                    exclusive: after,
                },
            ) => Some(Self::Moving {
                inclusive: inclusive.into_iter().chain(next).min(),
                exclusive: exclusive.into_iter().chain(after).min(),
            }),
            (
                Self::Fixed { bin, lower, upper },
                Self::Fixed {
                    bin: next,
                    lower: first,
                    upper: last,
                },
            ) if bin == next => Some(Self::Fixed {
                bin,
                lower: lower || first,
                upper: upper || last,
            }),
            _ => None,
        }
    }

    pub(crate) fn fixed_range(&self, now: u64) -> datafusion::common::Result<Option<(i64, i64)>> {
        let Self::Fixed { bin, .. } = self else {
            return Ok(None);
        };
        let Expr::ScalarFunction(function) = bin.as_ref() else {
            return Err(datafusion::common::DataFusionError::Internal(
                "window function is absent".into(),
            ));
        };
        let now = i64::try_from(now).map_err(|_| {
            datafusion::common::DataFusionError::Execution("window statement time".into())
        })?;
        let context = SimplifyContext::builder()
            .with_query_execution_start_time(Some(chrono::DateTime::from_timestamp_nanos(now)))
            .build();
        let simplifier = ExprSimplifier::new(context);
        let scalar = |expression| {
            let Expr::Literal(value, _) = simplifier.simplify(expression)? else {
                return Err(datafusion::common::DataFusionError::Internal(
                    "window boundary is not constant".into(),
                ));
            };
            let value = value.cast_to(&DataType::Timestamp(TimeUnit::Nanosecond, None))?;
            match value {
                ScalarValue::TimestampNanosecond(Some(value), _) => Ok(value),
                _ => Err(datafusion::common::DataFusionError::Internal(
                    "window boundary type".into(),
                )),
            }
        };
        let first = scalar(bin.as_ref().clone())?;
        let end = scalar(Expr::BinaryExpr(BinaryExpr::new(
            Box::new(bin.as_ref().clone()),
            Operator::Plus,
            Box::new(function.args[0].clone()),
        )))?;
        if first >= end {
            return Err(datafusion::common::DataFusionError::Execution(
                "window interval".into(),
            ));
        }
        Ok(Some((first, end)))
    }

    fn events(plan: &LogicalPlan) -> bool {
        matches!(plan, LogicalPlan::TableScan(scan)
        if source_as_provider(&scan.source).is_ok_and(|provider| {
                provider.downcast_ref::<SourceProvider>()
                    .is_some_and(|source| source.origin.durable() == Some("events"))
            }))
    }

    fn preserves(plan: &LogicalPlan) -> bool {
        if let LogicalPlan::Projection(projection) = plan {
            return projection.expr.iter().zip(projection.schema.fields()).any(|(expression, field)| {
                let expression = match expression {
                    Expr::Alias(alias) => alias.expr.as_ref(),
                    expression => expression,
                };
                field.name() == "received_at"
                    && matches!(expression, Expr::Column(column) if column.name == "received_at")
            });
        }
        matches!(
            plan,
            LogicalPlan::SubqueryAlias(_)
                | LogicalPlan::Filter(_)
                | LogicalPlan::Repartition(_)
                | LogicalPlan::Distinct(datafusion::logical_expr::Distinct::All(_))
        ) || matches!(plan, LogicalPlan::Sort(sort) if sort.fetch.is_none())
    }

    fn predicate(expression: &Expr, schema: &datafusion::common::DFSchema) -> Option<Self> {
        let Expr::BinaryExpr(binary) = expression else {
            return None;
        };
        let (column, bound, lower, inclusive) = match binary.op {
            Operator::GtEq => (&*binary.left, &*binary.right, true, true),
            Operator::Gt => (&*binary.left, &*binary.right, true, false),
            Operator::LtEq => (&*binary.left, &*binary.right, false, true),
            Operator::Lt => (&*binary.left, &*binary.right, false, false),
            _ => return None,
        };
        let (column, bound, lower) = if matches!(column, Expr::Column(_)) {
            (column, bound, lower)
        } else if matches!(bound, Expr::Column(_)) {
            (bound, column, !lower)
        } else {
            return None;
        };
        let Expr::Column(column) = column else {
            return None;
        };
        let field = schema.field_from_column(column).ok()?;
        if column.name != "received_at"
            || field.data_type() != &DataType::Timestamp(TimeUnit::Microsecond, None)
            || field.metadata().get("araphor.units").map(String::as_str)
                != Some("microseconds since Unix epoch")
        {
            return None;
        }
        let bound = match bound {
            Expr::Cast(cast)
                if cast.field.data_type() == field.data_type()
                    && cast.expr.get_type(schema).ok()?
                        == DataType::Timestamp(TimeUnit::Nanosecond, None) =>
            {
                cast.expr.as_ref()
            }
            _ => bound,
        };
        let bin = if lower && inclusive {
            Some(bound)
        } else if !lower && !inclusive {
            match bound {
                Expr::BinaryExpr(end) if end.op == Operator::Plus => {
                    let Expr::ScalarFunction(function) = end.left.as_ref() else {
                        return None;
                    };
                    (function.args.first() == Some(end.right.as_ref())).then_some(end.left.as_ref())
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(Expr::ScalarFunction(function)) = bin {
            if function.func.inner().is::<DateBinFunc>()
                && (2..=3).contains(&function.args.len())
                && matches!(function.args[0], Expr::Literal(_, _))
                && Self::clock(&function.args[1])
                && function
                    .args
                    .get(2)
                    .is_none_or(|origin| matches!(origin, Expr::Literal(_, _) | Expr::Cast(_)))
            {
                return Some(Self::Fixed {
                    bin: Arc::new(bin?.clone()),
                    lower,
                    upper: !lower,
                });
            }
        }
        if !lower {
            return None;
        }
        let Expr::BinaryExpr(bound) = bound else {
            return None;
        };
        if bound.op != Operator::Minus || !Self::clock(&bound.left) {
            return None;
        }
        let Expr::Literal(interval, _) = &*bound.right else {
            return None;
        };
        let width = match interval {
            ScalarValue::IntervalMonthDayNano(Some(value)) if value.months == 0 => {
                i128::from(value.days) * 86_400_000_000_000 + i128::from(value.nanoseconds)
            }
            ScalarValue::IntervalDayTime(Some(value)) => {
                i128::from(value.days) * 86_400_000_000_000
                    + i128::from(value.milliseconds) * 1_000_000
            }
            _ => return None,
        };
        let width = u64::try_from(width).ok().filter(|width| *width != 0)?;
        Some(Self::Moving {
            inclusive: inclusive.then_some(width),
            exclusive: (!inclusive).then_some(width),
        })
    }

    fn clock(expression: &Expr) -> bool {
        matches!(expression, Expr::ScalarFunction(function)
            if function.func.inner().is::<NowFunc>())
    }

    pub(crate) fn selection(
        &self,
        original: &AnalysisSelectionV1,
        now: u64,
    ) -> AnalysisSelectionV1 {
        let Self::Moving {
            inclusive,
            exclusive,
        } = self
        else {
            return original.clone();
        };
        let threshold = |width: &u64| (i128::from(now) - i128::from(*width)) / 1000;
        let micros = inclusive
            .iter()
            .map(threshold)
            .chain(exclusive.iter().map(|width| threshold(width) + 1))
            .max()
            .unwrap_or(0);
        let lower = u64::try_from(micros.max(0) * 1000).unwrap_or(u64::MAX);
        let mut selection = original.clone();
        selection.received_from = match original.received_from {
            Bound::Included(value) if value >= lower => Bound::Included(value),
            Bound::Excluded(value) if value >= lower => Bound::Excluded(value),
            _ => Bound::Included(lower),
        };
        selection
    }

    pub(crate) fn expiry(&self, received: Option<u64>) -> Option<u64> {
        let Self::Moving {
            inclusive,
            exclusive,
        } = self
        else {
            return None;
        };
        received.and_then(|received| {
            let received = received / 1000 * 1000;
            inclusive
                .and_then(|width| received.checked_add(width)?.checked_add(1000))
                .into_iter()
                .chain(exclusive.and_then(|width| {
                    if received == 0 {
                        Some(width.saturating_sub(999))
                    } else {
                        received.checked_add(width)
                    }
                }))
                .min()
        })
    }
}
