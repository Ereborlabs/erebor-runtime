use std::any::Any;
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::memory::MemorySourceConfig;
use datafusion::execution::TaskContext;
use datafusion::functions_aggregate::count::Count;
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
use crate::sources::{JournalExec, SourceData};
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
    Count {
        journal: Option<Arc<dyn ExecutionPlan>>,
        compiled: Option<Arc<Compiled>>,
    },
    Page,
}

#[derive(Debug)]
struct Compiled {
    aggregate: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
}

type Initial = (Arc<crate::execution::Permit>, u64, Progress);

impl SubscribeExec {
    pub(crate) fn new(
        input: Arc<dyn ExecutionPlan>,
        journal: Option<Arc<dyn ExecutionPlan>>,
    ) -> NativeResult<Self> {
        if journal
            .as_ref()
            .is_some_and(|source| !source.as_any().is::<JournalExec>())
        {
            return Err(DataFusionError::Internal(
                "Subscribe source is not a committed journal".into(),
            ));
        }
        let compiled = match journal.as_ref() {
            Some(source) => Self::compile(&input, source)?,
            None => None,
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
            mode: Mode::Count {
                journal,
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

    fn compile(
        input: &Arc<dyn ExecutionPlan>,
        journal: &Arc<dyn ExecutionPlan>,
    ) -> NativeResult<Option<Compiled>> {
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
                expression.is_distinct() || !expression.fun().inner().as_any().is::<Count>()
            })
        {
            return Ok(None);
        }
        node = Arc::clone(definition.input());
        loop {
            if SourceData::from_plan(node.as_ref()).is_some() {
                if node.fetch().is_some() {
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
        if journal.schema() != node.schema() {
            return Err(DataFusionError::Execution(
                "maintained source scan changed".into(),
            ));
        }
        Ok(Some(Compiled {
            aggregate,
            source: node,
        }))
    }

    pub(crate) async fn open(run: Arc<Run>) -> Result<OutputStream> {
        let permit = Arc::new(
            run.session
                .control()
                .query_async(
                    run.session
                        .engine()
                        .acquire_evaluation(run.session.selection().tenant_id),
                )
                .await?,
        );
        let mut progress =
            Progress::new(run.session.engine().store(), Arc::clone(&run.clock), None);
        let now = progress.begin()?;
        let session = run.session.at(run.session.selection().clone(), now);
        let mut state = session.state()?;
        let logical = crate::planner::subscription::Subscribe::runtime(
            run.plan.as_ref().clone(),
            run.operation == crate::follow::Operation::Append,
        )
        .context(SqlSnafu)?;
        state.config_mut().set_extension(run);
        let mut planning = state.clone();
        planning.config_mut().set_extension(Arc::clone(&permit));
        let physical = session.physical(&logical, &planning).await?;
        let subscription = physical
            .as_any()
            .downcast_ref::<Self>()
            .ok_or_else(|| DataFusionError::Internal("subscription physical root changed".into()))
            .context(SqlSnafu)?;
        subscription.execute_committed(0, state.task_ctx(), Some((permit, now, progress)))
    }

    pub(crate) fn execute_committed(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
        initial: Option<Initial>,
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
            Some((permit, now, progress)) => (Some((permit, now)), progress),
            None => (
                None,
                Progress::new(run.session.engine().store(), Arc::clone(&run.clock), None),
            ),
        };
        let state = runtime::Runtime::new(self, context, run, initial, progress)?;
        Ok(Box::pin(stream::try_unfold(
            state,
            |mut state| async move { Ok(state.next().await?.map(|output| (output, state))) },
        )))
    }

    #[cfg(test)]
    pub(super) fn maintained(&self) -> bool {
        matches!(
            &self.mode,
            Mode::Count {
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
        let mut children = vec![&self.input];
        if let Mode::Count { journal, .. } = &self.mode {
            children.extend(journal.iter());
        }
        children
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
        match self.mode {
            Mode::Count { .. } => Ok(Arc::new(Self::new(input, children.into_iter().next())?)),
            Mode::Page => Ok(Arc::new(Self::page(input, self.schema())?)),
        }
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        let stream = self
            .execute_committed(partition, context, None)
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
