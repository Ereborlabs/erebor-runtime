use std::ops::Bound;

use araphor_data::AnalysisSelectionV1;
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{ExprSchema, ScalarValue};
use datafusion::datasource::source_as_provider;
use datafusion::logical_expr::{Expr, LogicalPlan, Operator};
use snafu::ResultExt as _;

use crate::sources::SourceProvider;
use crate::{InvalidSnafu, Result, SqlSnafu};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    width: u64,
    inclusive: bool,
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

    pub(crate) fn from_plan(plan: &LogicalPlan) -> Result<Option<Self>> {
        let clocks = Self::clocks(plan)?;
        if clocks == 0 {
            return Ok(None);
        }
        let mut windows = Vec::new();
        let mut scans = 0;
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                if scan.table_name.table() == "events"
                    && source_as_provider(&scan.source).is_ok_and(|provider| {
                        provider
                            .as_any()
                            .downcast_ref::<SourceProvider>()
                            .is_some_and(|source| source.origin.durable() == Some("events"))
                    })
                {
                    scans += 1;
                }
            }
            if let LogicalPlan::Filter(filter) = plan {
                filter.predicate.apply(|expression| {
                    if matches!(expression, Expr::BinaryExpr(binary) if binary.op == Operator::And)
                    {
                        return Ok(TreeNodeRecursion::Continue);
                    }
                    if let Some(window) = Self::predicate(expression, filter.input.schema()) {
                        windows.push(window);
                    }
                    Ok(TreeNodeRecursion::Jump)
                })?;
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .context(SqlSnafu)?;
        if scans != 1 || windows.len() != clocks {
            return InvalidSnafu {
                field: "follow clock filter",
            }
            .fail();
        }
        Ok(windows
            .into_iter()
            .min_by_key(|window| (window.width, window.inclusive)))
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
        Some(Self {
            width: u64::try_from(width).ok().filter(|width| *width != 0)?,
            inclusive,
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
        let threshold = i128::from(now) - i128::from(self.width);
        let micros = if self.inclusive {
            (threshold + 999).div_euclid(1000)
        } else {
            threshold.div_euclid(1000) + 1
        };
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
            (received / 1000 * 1000)
                .checked_add(self.width)?
                .checked_add(u64::from(self.inclusive))
        })
    }
}
