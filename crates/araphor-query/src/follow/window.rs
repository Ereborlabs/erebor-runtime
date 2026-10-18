use std::ops::Bound;

use araphor_data::AnalysisSelectionV1;
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::common::{ExprSchema, ScalarValue};
use datafusion::datasource::source_as_provider;
use datafusion::logical_expr::{Expr, LogicalPlan, Operator};
use snafu::ResultExt as _;

use crate::sources::SourceProvider;
use crate::{InvalidSnafu, Result, SqlSnafu};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Window {
    inclusive: Option<u64>,
    exclusive: Option<u64>,
}

#[derive(Default)]
struct Windows {
    stack: Vec<Option<Window>>,
    scans: Vec<Option<Window>>,
    filters: usize,
    invalid: bool,
}

impl<'n> TreeNodeVisitor<'n> for Windows {
    type Node = LogicalPlan;

    fn f_down(&mut self, plan: &'n LogicalPlan) -> datafusion::common::Result<TreeNodeRecursion> {
        let mut window = self.stack.last().copied().flatten();
        if !Window::preserves(plan) && !Window::events(plan) {
            window = None;
        }
        if let LogicalPlan::Filter(filter) = plan {
            let filters = self.filters;
            filter.predicate.apply(|expression| {
                if matches!(expression, Expr::BinaryExpr(binary) if binary.op == Operator::And) {
                    return Ok(TreeNodeRecursion::Continue);
                }
                if let Some(found) = Window::predicate(expression, filter.input.schema()) {
                    window = Some(window.map_or(found, |current| current.intersect(found)));
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
            self.scans.push(window);
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
    pub(crate) fn clocks(plan: &LogicalPlan) -> Result<usize> {
        let mut count = 0;
        plan.apply_with_subqueries(|plan| {
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

    pub(crate) fn infer(plan: &LogicalPlan) -> Result<Option<Self>> {
        match Self::from_plan(plan) {
            Err(crate::Error::Invalid {
                field: "follow clock filter",
                ..
            }) => Ok(None),
            result => result,
        }
    }

    pub(crate) fn from_plan(plan: &LogicalPlan) -> Result<Option<Self>> {
        let clocks = Self::clocks(plan)?;
        if clocks == 0 {
            return Ok(None);
        }
        let mut windows = Windows::default();
        plan.visit_with_subqueries(&mut windows).context(SqlSnafu)?;
        let window = windows.scans.first().copied().flatten();
        if windows.invalid
            || window.is_none()
            || windows.filters != clocks
            || windows.scans.iter().any(|scan| *scan != window)
        {
            return InvalidSnafu {
                field: "follow clock filter",
            }
            .fail();
        }
        Ok(window)
    }

    fn intersect(self, other: Self) -> Self {
        Self {
            inclusive: self.inclusive.into_iter().chain(other.inclusive).min(),
            exclusive: self.exclusive.into_iter().chain(other.exclusive).min(),
        }
    }

    fn events(plan: &LogicalPlan) -> bool {
        matches!(plan, LogicalPlan::TableScan(scan)
        if scan.table_name.table() == "events"
            && source_as_provider(&scan.source).is_ok_and(|provider| {
                provider.as_any().downcast_ref::<SourceProvider>()
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
        let (column, bound, inclusive) = match binary.op {
            Operator::GtEq => (&*binary.left, &*binary.right, true),
            Operator::Gt => (&*binary.left, &*binary.right, false),
            Operator::LtEq => (&*binary.right, &*binary.left, true),
            Operator::Lt => (&*binary.right, &*binary.left, false),
            _ => return None,
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
        Some(Self {
            inclusive: inclusive.then_some(width),
            exclusive: (!inclusive).then_some(width),
        })
    }

    fn clock(expression: &Expr) -> bool {
        matches!(expression, Expr::ScalarFunction(function)
            if matches!(function.name(), "now" | "current_timestamp"))
    }

    pub(crate) fn selection(
        &self,
        original: &AnalysisSelectionV1,
        now: u64,
    ) -> AnalysisSelectionV1 {
        let threshold = |width: &u64| (i128::from(now) - i128::from(*width)) / 1000;
        let micros = self
            .inclusive
            .iter()
            .map(threshold)
            .chain(self.exclusive.iter().map(|width| threshold(width) + 1))
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
        received.and_then(|received| {
            let received = received / 1000 * 1000;
            self.inclusive
                .and_then(|width| received.checked_add(width)?.checked_add(1000))
                .into_iter()
                .chain(self.exclusive.and_then(|width| {
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
