use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchemaRef, DataFusionError, Result};
use datafusion::datasource::source_as_provider;
use datafusion::execution::context::QueryPlanner;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{
    Expr, Extension, LogicalPlan, UserDefinedLogicalNode, UserDefinedLogicalNodeCore, Volatility,
};
use datafusion::physical_plan::streaming::StreamingTableExec;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner};

use crate::sources::{JournalExec, SourceProvider, SourceSnapshot};
use crate::stream::physical::SubscribeExec;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub(crate) struct Subscribe {
    input: LogicalPlan,
}

impl Subscribe {
    pub(crate) fn plan(input: LogicalPlan) -> Result<LogicalPlan> {
        let mut scans = 0;
        input.apply_with_subqueries(|node| {
            match node {
                LogicalPlan::Projection(_)
                | LogicalPlan::Filter(_)
                | LogicalPlan::SubqueryAlias(_)
                | LogicalPlan::Aggregate(_) => {}
                LogicalPlan::TableScan(scan) => {
                    let provider = source_as_provider(&scan.source)?;
                    if !provider.as_any().is::<SourceProvider>()
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
        Ok(LogicalPlan::Extension(Extension {
            node: Arc::new(Self { input }),
        }))
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
        state: &SessionState,
    ) -> Result<Option<Arc<dyn ExecutionPlan>>> {
        if !node.as_any().is::<Subscribe>() {
            return Ok(None);
        }
        let [input] = physical_inputs else {
            return Err(DataFusionError::Internal(
                "Subscribe input is absent".into(),
            ));
        };
        let snapshot = state
            .config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| {
                DataFusionError::Execution("source planning context is absent".into())
            })?;
        let (_, received) = snapshot.requests()?;
        let mut scans = 0;
        let mut journal = None;
        input.apply(|node| {
            if let Some(source) = node.as_any().downcast_ref::<StreamingTableExec>() {
                scans += 1;
                match JournalExec::new(source, received.clone()) {
                    Ok(source) => journal = Some(Arc::new(source) as Arc<dyn ExecutionPlan>),
                    Err(DataFusionError::NotImplemented(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        if scans != 1 {
            journal = None;
        }
        Ok(Some(Arc::new(SubscribeExec::new(
            Arc::clone(input),
            journal,
        )?)))
    }
}
