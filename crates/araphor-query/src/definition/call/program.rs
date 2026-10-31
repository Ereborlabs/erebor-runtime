use std::sync::Arc;

use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::Transformed;
use datafusion::common::{Result, TableReference};
use datafusion::datasource::{provider_as_source, source_as_provider, ViewTable};
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, TableScan};

use super::PackageCall;

impl PackageCall {
    pub(crate) fn defer_view(provider: Arc<dyn TableProvider>) -> Result<Arc<dyn TableProvider>> {
        let Some(view) = provider.as_any().downcast_ref::<ViewTable>() else {
            return Ok(provider);
        };
        if !Self::contains(view.logical_plan())? {
            return Ok(provider);
        }
        Ok(Arc::new(ViewTable::new(
            Self::defer_programs(view.logical_plan().clone())?,
            view.definition().cloned(),
        )))
    }

    pub(in crate::definition) fn defer_programs(plan: LogicalPlan) -> Result<LogicalPlan> {
        plan.transform_down_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = &plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<Self>() {
                    let name = TableReference::bare(call.export.clone());
                    let source = provider_as_source(Arc::new(ViewTable::new(plan, None)));
                    // Keep package programs outside native derived-relation cleanup.
                    return TableScan::try_new(name, source, None, Vec::new(), None)
                        .map(LogicalPlan::TableScan)
                        .map(Transformed::yes);
                }
            }
            let LogicalPlan::TableScan(mut scan) = plan else {
                return Ok(Transformed::no(plan));
            };
            let Ok(provider) = source_as_provider(&scan.source) else {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            };
            let Some(view) = provider.as_any().downcast_ref::<ViewTable>() else {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            };
            if matches!(view.logical_plan(), LogicalPlan::Extension(extension)
                if extension.node.as_any().is::<Self>())
                || !Self::contains(view.logical_plan())?
            {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            }
            scan.source = provider_as_source(Self::defer_view(provider)?);
            Ok(Transformed::yes(LogicalPlan::TableScan(scan)))
        })
        .map(|plan| plan.data)
    }

    pub(crate) fn expose_programs(plan: LogicalPlan) -> Result<LogicalPlan> {
        plan.transform_down_with_subqueries(|plan| {
            let LogicalPlan::TableScan(scan) = plan else {
                return Ok(Transformed::no(plan));
            };
            let Ok(provider) = source_as_provider(&scan.source) else {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            };
            let Some(view) = provider.as_any().downcast_ref::<ViewTable>() else {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            };
            if !Self::contains(view.logical_plan())? {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            }
            let columns = scan.projected_schema.columns();
            let mut plan = LogicalPlanBuilder::scan(scan.table_name, scan.source, None)?;
            if let Some(filter) = scan.filters.into_iter().reduce(Expr::and) {
                plan = plan.filter(filter)?;
            }
            if scan.projection.is_some() {
                plan = plan.project(columns.into_iter().map(Expr::Column))?;
            }
            if let Some(fetch) = scan.fetch {
                plan = plan.limit(0, Some(fetch))?;
            }
            plan.build().map(Transformed::yes)
        })
        .map(|plan| plan.data)
    }
}
