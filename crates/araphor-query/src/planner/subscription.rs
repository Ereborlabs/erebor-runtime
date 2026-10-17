use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::common::config::ConfigOptions;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchemaRef, DataFusionError, Result};
use datafusion::datasource::source_as_provider;
use datafusion::execution::context::QueryPlanner;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{
    Expr, Extension, LogicalPlan, UserDefinedLogicalNode, UserDefinedLogicalNodeCore, Volatility,
};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner};

use crate::sources::{JournalExec, SourceData, SourceProvider, SourceSnapshot};
use crate::stream::physical::SubscribeExec;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub(crate) struct Subscribe {
    input: LogicalPlan,
    append: bool,
}

impl Subscribe {
    pub(crate) fn appendable(plan: &LogicalPlan) -> Result<bool> {
        let LogicalPlan::Projection(projection) = plan else {
            return Ok(false);
        };
        let mut has_subquery = false;
        plan.apply_with_subqueries(|node| {
            if matches!(node, LogicalPlan::Subquery(_)) {
                has_subquery = true;
                Ok(TreeNodeRecursion::Stop)
            } else {
                Ok(TreeNodeRecursion::Continue)
            }
        })?;
        if has_subquery {
            return Ok(false);
        }
        let mut input = projection.input.as_ref();
        loop {
            input = match input {
                LogicalPlan::Filter(filter) => &filter.input,
                LogicalPlan::SubqueryAlias(alias) => &alias.input,
                LogicalPlan::TableScan(scan) => {
                    return Ok(matches!(scan.table_name.table(), "events" | "trace_output")
                        && scan.fetch.is_none()
                        && source_as_provider(&scan.source).is_ok_and(|provider| {
                            provider
                                .as_any()
                                .downcast_ref::<SourceProvider>()
                                .is_some_and(|source| {
                                    matches!(
                                        source.origin.durable(),
                                        Some("events" | "trace_output")
                                    )
                                })
                        }));
                }
                _ => return Ok(false),
            };
        }
    }

    pub(crate) fn runtime(input: LogicalPlan, append: bool) -> LogicalPlan {
        LogicalPlan::Extension(Extension {
            node: Arc::new(Self { input, append }),
        })
    }

    pub(crate) fn maintainable(input: &LogicalPlan) -> Result<()> {
        let mut scans = 0;
        input.apply_with_subqueries(|node| {
            match node {
                LogicalPlan::Projection(_)
                | LogicalPlan::Filter(_)
                | LogicalPlan::SubqueryAlias(_)
                | LogicalPlan::Aggregate(_) => {}
                LogicalPlan::TableScan(scan) => {
                    let provider = source_as_provider(&scan.source)?;
                    if !provider
                        .as_any()
                        .downcast_ref::<SourceProvider>()
                        .is_some_and(|source| source.origin.durable() == Some("events"))
                        || provider.schema() != SourceSnapshot::schemas()["events"]
                        || scan.fetch.is_some()
                    {
                        return Err(DataFusionError::NotImplemented(
                            "maintained evidence source".into(),
                        ));
                    }
                    scans += 1;
                }
                _ => {
                    return Err(DataFusionError::NotImplemented(
                        "maintained native COUNT plan".into(),
                    ));
                }
            }
            for expression in node.expressions() {
                expression.apply(|expression| {
                    if matches!(expression, Expr::ScalarFunction(function)
                        if function.func.signature().volatility != Volatility::Immutable)
                    {
                        return Err(DataFusionError::NotImplemented(
                            "maintained clock-dependent expression".into(),
                        ));
                    }
                    Ok(TreeNodeRecursion::Continue)
                })?;
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        if scans != 1 {
            return Err(DataFusionError::NotImplemented(
                "maintained single evidence source".into(),
            ));
        }
        Ok(())
    }
}

impl UserDefinedLogicalNodeCore for Subscribe {
    fn name(&self) -> &str {
        "Subscribe"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![&self.input]
    }

    fn schema(&self) -> &DFSchemaRef {
        self.input.schema()
    }

    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }

    fn necessary_children_exprs(&self, _output_columns: &[usize]) -> Option<Vec<Vec<usize>>> {
        Some(vec![(0..self.input.schema().fields().len()).collect()])
    }

    fn fmt_for_explain(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Subscribe")
    }

    fn with_exprs_and_inputs(
        &self,
        expressions: Vec<Expr>,
        mut inputs: Vec<LogicalPlan>,
    ) -> Result<Self> {
        if !expressions.is_empty() || inputs.len() != 1 {
            return Err(DataFusionError::Internal(
                "Subscribe requires one input and no expressions".into(),
            ));
        }
        Ok(Self {
            input: inputs.remove(0),
            append: self.append,
        })
    }
}

#[derive(Debug)]
pub(crate) struct SubscriptionPlanner;

#[async_trait]
impl QueryPlanner for SubscriptionPlanner {
    async fn create_physical_plan(
        &self,
        plan: &LogicalPlan,
        state: &SessionState,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(Self)])
            .create_physical_plan(plan, state)
            .await
    }
}

#[async_trait]
impl ExtensionPlanner for SubscriptionPlanner {
    async fn plan_extension(
        &self,
        _planner: &dyn PhysicalPlanner,
        node: &dyn UserDefinedLogicalNode,
        _logical_inputs: &[&LogicalPlan],
        physical_inputs: &[Arc<dyn ExecutionPlan>],
        _state: &SessionState,
    ) -> Result<Option<Arc<dyn ExecutionPlan>>> {
        let Some(subscription) = node.as_any().downcast_ref::<Subscribe>() else {
            return Ok(None);
        };
        let [input] = physical_inputs else {
            return Err(DataFusionError::Internal(
                "Subscribe input is absent".into(),
            ));
        };
        if subscription.append {
            return Ok(Some(Arc::new(SubscribeExec::page(Arc::clone(input))?)));
        }
        let mut scans = 0;
        let mut journal = None;
        if Subscribe::maintainable(&subscription.input).is_ok() {
            input.apply(|node| {
                if let Some(source) = SourceData::from_plan(node.as_ref()) {
                    scans += 1;
                    match JournalExec::new(source) {
                        Ok(source) => journal = Some(Arc::new(source) as Arc<dyn ExecutionPlan>),
                        Err(DataFusionError::NotImplemented(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        if scans != 1 {
            journal = None;
        }
        Ok(Some(Arc::new(SubscribeExec::new(
            Arc::clone(input),
            journal,
        )?)))
    }
}

#[derive(Debug)]
pub(crate) struct PageLineage;

impl PhysicalOptimizerRule for PageLineage {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        match plan.as_any().downcast_ref::<SubscribeExec>() {
            Some(subscription) => Ok(subscription.lower_page()?.unwrap_or(plan)),
            None => Ok(plan),
        }
    }

    fn name(&self) -> &str {
        "PageLineage"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::datasource::provider_as_source;
    use datafusion::execution::context::SessionContext;
    use datafusion::functions_aggregate::count::count_all;
    use datafusion::logical_expr::{col, LogicalPlanBuilder};

    #[tokio::test]
    async fn port_lacks_source_capabilities() -> Result<()> {
        let state = SessionContext::new().state();
        let schema = Arc::clone(&SourceSnapshot::schemas()["events"]);
        for (provider, durable) in [
            (SourceSnapshot::providers()["events"].clone(), true),
            (SourceProvider::port(0, schema), false),
        ] {
            let physical = provider.scan(&state, None, &[], None).await?;
            assert_eq!(
                JournalExec::new(SourceData::from_plan(physical.as_ref()).unwrap()).is_ok(),
                durable
            );
            let scan =
                LogicalPlanBuilder::scan("events", provider_as_source(provider), None)?.build()?;
            let projection = LogicalPlanBuilder::from(scan.clone())
                .project(vec![col("operation")])?
                .build()?;
            assert_eq!(Subscribe::appendable(&projection)?, durable);
            let aggregate = LogicalPlanBuilder::from(scan)
                .aggregate(Vec::<Expr>::new(), vec![count_all()])?
                .build()?;
            assert_eq!(Subscribe::maintainable(&aggregate).is_ok(), durable);
        }
        Ok(())
    }
}
