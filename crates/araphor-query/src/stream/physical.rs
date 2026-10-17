use std::any::Any;
use std::fmt;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::StorePositionV1;
use datafusion::arrow::array::{ArrayRef, RecordBatch};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::memory::MemorySourceConfig;
use datafusion::execution::memory_pool::MemoryReservation;
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

use super::{Output, OutputStream, Run};
use crate::execution::{Read, Retention};
use crate::sources::{JournalExec, SourceData};
use crate::{Result, SqlSnafu};

mod kernel;
mod page;

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
    Page {
        lowered: bool,
    },
}

#[derive(Debug)]
struct Compiled {
    aggregate: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
}

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

    pub(crate) fn page(input: Arc<dyn ExecutionPlan>) -> NativeResult<Self> {
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(input.schema()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Final,
            Boundedness::Bounded,
        ));
        Ok(Self {
            input,
            mode: Mode::Page { lowered: false },
            properties,
        })
    }

    pub(crate) fn lower_page(&self) -> NativeResult<Option<Arc<dyn ExecutionPlan>>> {
        if !matches!(self.mode, Mode::Page { lowered: false }) {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self {
            input: Self::page_input(&self.input)?,
            mode: Mode::Page { lowered: true },
            properties: Arc::clone(&self.properties),
        })))
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

    pub(crate) fn execute_committed(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
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
        run.control.check()?;
        let Mode::Count { journal, compiled } = &self.mode else {
            if !matches!(self.mode, Mode::Page { lowered: true }) {
                return Err(DataFusionError::Internal(
                    "page lineage is not planned".into(),
                ))
                .context(SqlSnafu);
            }
            let permit = context
                .session_config()
                .get_extension::<crate::execution::Permit>()
                .ok_or_else(|| {
                    DataFusionError::Execution("page evaluation permit is absent".into())
                })
                .context(SqlSnafu)?;
            let input = Arc::clone(&self.input);
            let schema = self.schema();
            return Ok(Box::pin(stream::once(async move {
                let engine = &run.engine;
                let session = engine.session(run.selection.clone(), &run.control, run.now)?;
                let (snapshot, mut stream, permit, control, reservation) = session
                    .start_physical(
                        input,
                        context,
                        &run.sources,
                        Read::Page(run.after),
                        Retention::Output,
                        permit,
                    )
                    .await?;
                Output::page(
                    engine,
                    schema,
                    &mut stream,
                    control,
                    reservation,
                    snapshot,
                    permit,
                )
                .await
            })));
        };
        let compiled = compiled
            .as_ref()
            .ok_or_else(|| DataFusionError::NotImplemented("maintained native COUNT plan".into()))
            .context(SqlSnafu)?;
        let aggregate = compiled
            .aggregate
            .as_any()
            .downcast_ref::<AggregateExec>()
            .ok_or_else(|| DataFusionError::Internal("native COUNT descriptor changed".into()))
            .context(SqlSnafu)?;
        let journal = journal
            .as_ref()
            .and_then(|source| source.as_any().downcast_ref::<JournalExec>())
            .ok_or_else(|| DataFusionError::NotImplemented("native journal source".into()))
            .context(SqlSnafu)?;
        let stream = kernel::execute(
            aggregate,
            journal.execute_committed(partition, Arc::clone(&context))?,
            Arc::clone(&compiled.source),
            Arc::clone(&context),
            Arc::clone(&run.engine),
            Arc::clone(&run.control),
        );
        let state = Outputs {
            stream,
            plan: Arc::clone(&self.input),
            aggregate: Arc::clone(&compiled.aggregate),
            context,
            memory: run.engine.memory().reserve_input(0).context(SqlSnafu)?,
            run,
            previous: None,
        };
        Ok(Box::pin(stream::try_unfold(
            state,
            |mut state| async move { Ok(state.next().await?.map(|output| (output, state))) },
        )))
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
            Mode::Page { lowered } => Ok(Arc::new(Self {
                input,
                mode: Mode::Page { lowered },
                properties: Arc::clone(&self.properties),
            })),
        }
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        let stream = self
            .execute_committed(partition, context)
            .map_err(|source| DataFusionError::External(Box::new(source)))?
            .map_ok(
                |Output {
                     batches, _memory, ..
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

struct Outputs {
    stream: OutputStream,
    plan: Arc<dyn ExecutionPlan>,
    aggregate: Arc<dyn ExecutionPlan>,
    context: Arc<TaskContext>,
    run: Arc<Run>,
    previous: Option<Vec<RecordBatch>>,
    memory: MemoryReservation,
}

impl Outputs {
    async fn next(&mut self) -> Result<Option<Output>> {
        let Some(Output {
            snapshot,
            batches,
            _memory: _input,
            _permit,
            _control: control,
            ..
        }) = self.stream.try_next().await?
        else {
            return Ok(None);
        };
        let batches = batches.ok_or_else(|| {
            crate::InvalidSnafu {
                field: "native aggregate output",
            }
            .build()
        })?;
        control.check()?;
        let mut reservation = self
            .run
            .engine
            .memory()
            .prepare_output(self.run.engine.limits().output_bytes)
            .context(SqlSnafu)?;
        let mut stream = SubscribeExec::bind(
            &self.plan,
            &self.aggregate,
            batches,
            Arc::clone(&self.context),
        )
        .context(SqlSnafu)?;
        let mut batches = Vec::new();
        let (mut rows, mut bytes) = (0usize, 0usize);
        while let Some(batch) = control
            .query_async(async { stream.try_next().await.context(SqlSnafu) })
            .await?
        {
            rows = rows.saturating_add(batch.num_rows());
            bytes = bytes.saturating_add(batch.get_array_memory_size());
            if rows > self.run.engine.limits().output_rows
                || bytes > self.run.engine.limits().output_bytes
            {
                return Err(DataFusionError::ResourcesExhausted(
                    "maintained query output".into(),
                ))
                .context(SqlSnafu);
            }
            self.run
                .engine
                .memory()
                .retain_output(&batch, &mut reservation)
                .context(SqlSnafu)?;
            batches.push(batch);
        }
        control
            .query_async(self.run.engine.check_read(&snapshot))
            .await?;
        let unchanged = self.previous.as_ref() == Some(&batches);
        let metadata = batches.capacity() * size_of::<RecordBatch>()
            + batches
                .iter()
                .map(|batch| batch.num_columns() * size_of::<ArrayRef>())
                .sum::<usize>();
        if !unchanged {
            self.memory
                .try_grow(metadata)
                .map_err(|source| crate::Error::Capacity {
                    resource: "shared input",
                    source,
                })?;
            self.previous = Some(batches.clone());
            let metadata = self.previous.as_ref().map_or(0, |batches| {
                batches.capacity() * size_of::<RecordBatch>()
                    + batches
                        .iter()
                        .map(|batch| batch.num_columns() * size_of::<ArrayRef>())
                        .sum::<usize>()
            });
            self.memory
                .try_resize(metadata)
                .map_err(|source| crate::Error::Capacity {
                    resource: "shared input",
                    source,
                })?;
        }
        reservation
            .try_resize(if unchanged { 0 } else { metadata })
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })?;
        Ok(Some(Output {
            snapshot,
            batches: (!unchanged).then_some(batches),
            positions: Vec::new(),
            position: StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            limited: false,
            _memory: reservation,
            _permit,
            _control: control,
        }))
    }
}
