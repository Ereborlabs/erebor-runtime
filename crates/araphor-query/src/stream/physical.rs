use std::any::Any;
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::empty::EmptyTable;
use datafusion::datasource::memory::MemorySourceConfig;
use datafusion::datasource::source_as_provider;
use datafusion::datasource::view::ViewTable;
use datafusion::execution::TaskContext;
use datafusion::functions_aggregate::count::Count;
use datafusion::functions_aggregate::sum::Sum;
use datafusion::logical_expr::{Expr, LogicalPlan, Volatility};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode};
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    execute_stream, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning,
    PlanProperties, SendableRecordBatchStream,
};
use futures_util::{stream, TryStreamExt as _};
use snafu::ResultExt as _;

use super::progress::Progress;
use super::{Output, OutputStream, Run};
use crate::sources::{SourceData, SourcePort, SourceProvider, SourceSnapshot};
use crate::{Result, SqlSnafu};

mod kernel;
mod output;
mod page;
mod runtime;

pub(crate) use output::Fingerprint;

#[derive(Debug)]
pub(crate) struct SubscribeExec {
    input: Arc<dyn ExecutionPlan>,
    mode: Mode,
    properties: Arc<PlanProperties>,
}

#[derive(Debug)]
enum Mode {
    Replace {
        maintainable: bool,
        compiled: Option<Arc<Compiled>>,
    },
    Page,
}

#[derive(Debug)]
struct Compiled {
    aggregate: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
}

type Initial = (
    Arc<crate::execution::Permit>,
    u64,
    crate::execution::Session,
    Progress,
);

impl SubscribeExec {
    pub(crate) fn reusable(
        plan: &LogicalPlan,
        views: &mut std::collections::BTreeSet<usize>,
    ) -> NativeResult<bool> {
        let mut safe = true;
        plan.apply_with_subqueries(|node| {
            if matches!(node, LogicalPlan::RecursiveQuery(_)) {
                safe = false;
            }
            if let LogicalPlan::Extension(extension) = node {
                if let Some(port) = extension.node.as_any().downcast_ref::<SourcePort>() {
                    safe &= port.reusable();
                } else if !extension
                    .node
                    .as_any()
                    .is::<crate::definition::PackageCall>()
                {
                    safe = false;
                }
            }
            if let LogicalPlan::TableScan(scan) = node {
                if let Ok(provider) = source_as_provider(&scan.source) {
                    if let Some(view) = provider.as_any().downcast_ref::<ViewTable>() {
                        let identity = Arc::as_ptr(&provider) as *const () as usize;
                        if views.insert(identity) {
                            safe &= Self::reusable(view.logical_plan(), views)?;
                            views.remove(&identity);
                        } else {
                            safe = false;
                        }
                    } else {
                        safe &= provider.as_any().is::<SourceProvider>()
                            || provider.as_any().is::<EmptyTable>();
                    }
                } else {
                    safe = false;
                }
            }
            for expression in node.expressions() {
                expression.apply(|expression| {
                    safe &= match expression {
                        Expr::ScalarFunction(function) => {
                            function.func.signature().volatility == Volatility::Immutable
                        }
                        Expr::AggregateFunction(function) => {
                            function.func.signature().volatility == Volatility::Immutable
                        }
                        Expr::WindowFunction(function) => {
                            function.fun.signature().volatility == Volatility::Immutable
                        }
                        Expr::ScalarVariable(..) | Expr::Placeholder(..) => false,
                        _ => true,
                    };
                    Ok(TreeNodeRecursion::Continue)
                })?;
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(safe)
    }

    pub(crate) fn new(input: Arc<dyn ExecutionPlan>, maintainable: bool) -> NativeResult<Self> {
        let compiled = if maintainable {
            Self::compile(&input)?
        } else {
            None
        };
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(input.schema()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        ));
        Ok(Self {
            input,
            mode: Mode::Replace {
                maintainable,
                compiled: compiled.map(Arc::new),
            },
            properties,
        })
    }

    pub(crate) fn page(input: Arc<dyn ExecutionPlan>, schema: SchemaRef) -> NativeResult<Self> {
        if input.schema().fields().len() != schema.fields().len() + 2 {
            return Err(DataFusionError::Internal(
                "Subscribe page input schema changed".into(),
            ));
        }
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(schema),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        ));
        Ok(Self {
            input,
            mode: Mode::Page,
            properties,
        })
    }

    fn compile(input: &Arc<dyn ExecutionPlan>) -> NativeResult<Option<Compiled>> {
        let mut node = Arc::clone(input);
        let aggregate = loop {
            if node.as_any().is::<AggregateExec>() {
                break Arc::clone(&node);
            }
            if !node.as_any().is::<ProjectionExec>()
                && !node.as_any().is::<CoalescePartitionsExec>()
            {
                return Ok(None);
            }
            let children = node.children();
            let [child] = children.as_slice() else {
                return Ok(None);
            };
            node = Arc::clone(child);
        };
        let Some(definition) = aggregate.as_any().downcast_ref::<AggregateExec>() else {
            return Ok(None);
        };
        if definition.mode() != &AggregateMode::Single
            || !definition.group_expr().is_true_no_grouping()
            || definition.aggr_expr().is_empty()
            || definition.aggr_expr().iter().any(|expression| {
                let function = expression.fun().inner().as_any();
                expression.is_distinct()
                    || !(function.is::<Count>()
                        || (function.is::<Sum>()
                            && matches!(
                                expression.field().data_type(),
                                DataType::Int64 | DataType::UInt64
                            )))
            })
        {
            return Ok(None);
        }
        node = Arc::clone(definition.input());
        loop {
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                if !source.supports_changes()? {
                    return Ok(None);
                }
                break;
            }
            if !node.as_any().is::<ProjectionExec>()
                && !node.as_any().is::<FilterExec>()
                && !node.as_any().is::<CoalescePartitionsExec>()
            {
                return Ok(None);
            }
            let children = node.children();
            let [child] = children.as_slice() else {
                return Ok(None);
            };
            node = Arc::clone(child);
        }
        Ok(Some(Compiled {
            aggregate,
            source: node,
        }))
    }

    pub(crate) async fn open(run: Arc<Run>) -> Result<OutputStream> {
        let mut progress =
            Progress::new(run.session.engine().store(), Arc::clone(&run.clock), None);
        let (permit, now, session) = loop {
            let permit = Arc::new(if run.managed.is_some() && !run.follow {
                run.session
                    .engine()
                    .reserve_evaluation(run.session.selection().tenant_id)?
            } else {
                run.session
                    .control()
                    .query_async(
                        run.session
                            .engine()
                            .acquire_evaluation(run.session.selection().tenant_id),
                    )
                    .await?
            });
            let now = progress.begin()?;
            let session = run
                .session(now, &permit, Vec::new(), Vec::new(), run.resume.as_ref())
                .await?;
            if let Some(cursor) = run.resume.as_ref().filter(|_| {
                !run.resume_pending
                    && session
                        .managed
                        .as_ref()
                        .is_some_and(|managed| !managed.rebuild)
                    && run.resume_expiry.is_none_or(|expiry| expiry > now)
            }) {
                let selection = SourceSnapshot::selection(&run.selection(now)?, run.sources())?;
                let (meta, revision) = run
                    .dependencies(&session, selection, Some(&permit), None)
                    .await?;
                cursor.check_store(&meta)?;
                if revision <= cursor.read_revision() {
                    let calls = session
                        .calls
                        .as_ref()
                        .ok_or_else(|| {
                            DataFusionError::Internal("subscription call context is absent".into())
                        })
                        .context(SqlSnafu)?;
                    calls.finish().await;
                    drop(session);
                    drop(permit);
                    progress.captured(meta.commit_revision, run.resume_expiry);
                    run.session
                        .control()
                        .query_async(progress.next(run.session.control(), None))
                        .await?;
                    continue;
                }
            }
            break (permit, now, session);
        };
        let mut state = session.state()?;
        let reusable = run.follow
            && run.operation == crate::follow::Operation::Replace
            && run.window.is_none()
            && !session
                .calls
                .as_ref()
                .is_some_and(|calls| calls.has_windows())
            && Self::reusable(&run.plan, &mut std::collections::BTreeSet::new())
                .context(SqlSnafu)?;
        let logical = crate::planner::subscription::Subscribe::runtime(
            run.plan.as_ref().clone(),
            run.operation == crate::follow::Operation::Append,
        )
        .context(SqlSnafu)?;
        state.config_mut().set_extension(run);
        let mut planning = state.clone();
        planning.config_mut().set_extension(Arc::clone(&permit));
        if reusable {
            let config = planning
                .config()
                .clone()
                .set_bool("datafusion.optimizer.enable_dynamic_filter_pushdown", false);
            *planning.config_mut() = config;
        }
        let physical = session.physical(&logical, &planning).await?;
        let subscription = physical
            .as_any()
            .downcast_ref::<Self>()
            .ok_or_else(|| DataFusionError::Internal("subscription physical root changed".into()))
            .context(SqlSnafu)?;
        subscription.execute_committed(
            0,
            state.task_ctx(),
            Some((permit, now, session, progress)),
            reusable,
        )
    }

    pub(crate) fn execute_committed(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
        initial: Option<Initial>,
        reusable: bool,
    ) -> Result<OutputStream> {
        if partition != 0 {
            return Err(DataFusionError::Execution(
                "Subscribe has one partition".into(),
            ))
            .context(SqlSnafu);
        }
        let run = context
            .session_config()
            .get_extension::<Run>()
            .ok_or_else(|| DataFusionError::Execution("subscription run is absent".into()))
            .context(SqlSnafu)?;
        run.session.control().check()?;
        let (initial, progress) = match initial {
            Some((permit, now, session, progress)) => (Some((permit, now, session)), progress),
            None => (
                None,
                Progress::new(run.session.engine().store(), Arc::clone(&run.clock), None),
            ),
        };
        let state = runtime::Runtime::new(self, context, run, initial, progress, reusable)?;
        Ok(Box::pin(stream::try_unfold(
            state,
            |mut state| async move { Ok(state.next().await?.map(|output| (output, state))) },
        )))
    }

    #[cfg(test)]
    pub(super) fn maintained(&self) -> bool {
        matches!(
            &self.mode,
            Mode::Replace {
                compiled: Some(_),
                ..
            }
        )
    }

    pub(super) fn bind(
        plan: &Arc<dyn ExecutionPlan>,
        source: &Arc<dyn ExecutionPlan>,
        batches: Vec<RecordBatch>,
        context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        if batches
            .iter()
            .any(|batch| batch.schema() != source.schema())
        {
            return Err(DataFusionError::Execution(
                "physical input schema changed".into(),
            ));
        }
        let memory: Arc<dyn ExecutionPlan> =
            MemorySourceConfig::try_new_exec(&[batches], source.schema(), None)?;
        let mut found = false;
        let plan = Arc::clone(plan)
            .transform_up(|node| {
                if Arc::ptr_eq(&node, source) {
                    found = true;
                    Ok(Transformed::yes(Arc::clone(&memory)))
                } else {
                    Ok(Transformed::no(node))
                }
            })?
            .data;
        if !found {
            return Err(DataFusionError::Internal("physical input is absent".into()));
        }
        execute_stream(plan, context)
    }
}

impl DisplayAs for SubscribeExec {
    fn fmt_as(&self, _format: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("SubscribeExec")
    }
}

impl ExecutionPlan for SubscribeExec {
    fn name(&self) -> &str {
        "SubscribeExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn required_input_distribution(&self) -> Vec<Distribution> {
        self.children()
            .iter()
            .map(|_| Distribution::SinglePartition)
            .collect()
    }

    fn with_new_children(
        self: Arc<Self>,
        mut children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        if children.len() != self.children().len() {
            return Err(DataFusionError::Internal(
                "Subscribe child count changed".into(),
            ));
        }
        let input = children.remove(0);
        match &self.mode {
            Mode::Replace { maintainable, .. } => Ok(Arc::new(Self::new(input, *maintainable)?)),
            Mode::Page => Ok(Arc::new(Self::page(input, self.schema())?)),
        }
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        let stream = self
            .execute_committed(partition, context, None, false)
            .map_err(|source| DataFusionError::External(Box::new(source)))?
            .map_err(|(source, _)| source)
            .map_ok(
                |super::Event {
                     output:
                         Output {
                             batches, _memory, ..
                         },
                     ..
                 }| {
                    stream::iter(batches.into_iter().flatten().map(move |batch| {
                        let _metadata = &_memory;
                        Ok::<_, crate::Error>(batch)
                    }))
                },
            )
            .try_flatten()
            .map_err(|source| DataFusionError::External(Box::new(source)));
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}

#[cfg(test)]
mod reuse_tests {
    use super::*;

    #[tokio::test]
    async fn nested_view_clock_requires_replanning() -> NativeResult<()> {
        let context = datafusion::prelude::SessionContext::new();
        let inner = context
            .sql("SELECT CURRENT_TIMESTAMP AS captured_at")
            .await?;
        context.register_table(
            "clock_view",
            Arc::new(ViewTable::new(inner.logical_plan().clone(), None)),
        )?;
        let outer = context.sql("SELECT * FROM clock_view").await?;
        assert!(!SubscribeExec::reusable(
            outer.logical_plan(),
            &mut std::collections::BTreeSet::new(),
        )?);
        Ok(())
    }
}
