use std::any::Any;
use std::fmt;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::AnalysisReadControl;
use datafusion::arrow::array::{ArrayRef, RecordBatch};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::memory::MemorySourceConfig;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::functions_aggregate::count::Count;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode};
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::StreamingTableExec;
use datafusion::physical_plan::{
    execute_stream, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning,
    PlanProperties, SendableRecordBatchStream,
};
use futures_util::{stream, StreamExt as _, TryStreamExt as _};
use snafu::ResultExt as _;

use super::source::Source;
use super::{Input, Message, Output, OutputStream, Run};
use crate::sources::SourceSnapshot;
use crate::{Result, SqlSnafu};

mod kernel;

#[derive(Debug)]
pub(crate) struct SubscribeExec {
    input: Arc<dyn ExecutionPlan>,
    received: Option<Interval>,
    compiled: Option<Arc<Compiled>>,
    properties: Arc<PlanProperties>,
}

#[derive(Debug)]
struct Compiled {
    aggregate: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
    columns: Vec<usize>,
}

impl SubscribeExec {
    pub(crate) fn new(
        input: Arc<dyn ExecutionPlan>,
        received: Option<Interval>,
    ) -> NativeResult<Self> {
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(input.schema()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        ));
        Ok(Self {
            compiled: Self::compile(&input)?.map(Arc::new),
            input,
            received,
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
                expression.is_distinct() || !expression.fun().inner().as_any().is::<Count>()
            })
        {
            return Ok(None);
        }
        node = Arc::clone(definition.input());
        loop {
            if let Some(source) = node.as_any().downcast_ref::<StreamingTableExec>() {
                if source.is_infinite()
                    || source.limit().is_some()
                    || source.partitions().len() != 1
                {
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
        let schema = &SourceSnapshot::schemas()["events"];
        let columns = node
            .schema()
            .fields()
            .iter()
            .map(|field| schema.index_of(field.name()).map_err(DataFusionError::from))
            .collect::<NativeResult<Vec<_>>>()?;
        if schema.project(&columns)? != *node.schema() {
            return Err(DataFusionError::Execution(
                "maintained source schema changed".into(),
            ));
        }
        Ok(Some(Compiled {
            aggregate,
            source: node,
            columns,
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
        if run.sources.len() != 1 || !run.sources.contains("events") {
            return Err(DataFusionError::NotImplemented(
                "maintained original evidence inventory".into(),
            ))
            .context(SqlSnafu);
        }
        let compiled = self
            .compiled
            .as_ref()
            .ok_or_else(|| DataFusionError::NotImplemented("maintained native COUNT plan".into()))
            .context(SqlSnafu)?;
        let aggregate = compiled
            .aggregate
            .as_any()
            .downcast_ref::<AggregateExec>()
            .ok_or_else(|| DataFusionError::Internal("native COUNT descriptor changed".into()))
            .context(SqlSnafu)?;
        let input = Inputs {
            input: Source::new(
                Arc::clone(&run),
                compiled.columns.clone(),
                self.received.clone(),
            )?
            .execute(),
            plan: Arc::clone(aggregate.input()),
            source: Arc::clone(&compiled.source),
            context: Arc::clone(&context),
            run: Arc::clone(&run),
            active: None,
            control: None,
            bytes: 0,
            memory: run.engine.memory().reserve_input(0).context(SqlSnafu)?,
        };
        let input = Box::pin(stream::try_unfold(input, |mut input| async move {
            Ok(input.next().await?.map(|message| (message, input)))
        }));
        let stream = kernel::execute(
            aggregate,
            input,
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
        vec![&self.input]
    }

    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition]
    }

    fn with_new_children(
        self: Arc<Self>,
        mut children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        if children.len() != 1 {
            return Err(DataFusionError::Internal(
                "Subscribe requires one child".into(),
            ));
        }
        Ok(Arc::new(Self::new(
            children.remove(0),
            self.received.clone(),
        )?))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        let stream = self
            .execute_committed(partition, context)
            .map_err(|source| DataFusionError::External(Box::new(source)))?
            .map_ok(|output| {
                stream::iter(
                    output
                        .batches
                        .into_iter()
                        .flatten()
                        .map(Ok::<_, crate::Error>),
                )
            })
            .try_flatten()
            .map_err(|source| DataFusionError::External(Box::new(source)));
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}

struct Inputs {
    input: Input,
    plan: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
    context: Arc<TaskContext>,
    run: Arc<Run>,
    active: Option<(SendableRecordBatchStream, bool)>,
    control: Option<Arc<AnalysisReadControl>>,
    bytes: usize,
    memory: MemoryReservation,
}

impl Inputs {
    async fn next(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some((stream, retract)) = self.active.as_mut() {
                let control = self.control.as_ref().ok_or_else(|| {
                    crate::InvalidSnafu {
                        field: "physical transaction",
                    }
                    .build()
                })?;
                if let Some(batch) = control
                    .query_async(async { stream.try_next().await.context(SqlSnafu) })
                    .await?
                {
                    self.bytes = self.bytes.saturating_add(batch.get_array_memory_size());
                    if self.bytes > self.run.engine.limits().input_bytes {
                        return Err(DataFusionError::ResourcesExhausted(
                            "maintained native input".into(),
                        ))
                        .context(SqlSnafu);
                    }
                    self.run
                        .engine
                        .memory()
                        .retain_input(&batch, &mut self.memory)
                        .context(SqlSnafu)?;
                    return Ok(Some(if *retract {
                        Message::Delete(batch)
                    } else {
                        Message::Insert(batch)
                    }));
                }
                self.active = None;
            }
            let Some(message) = self.input.next().await.transpose()? else {
                return Ok(None);
            };
            let (batch, retract) = match message {
                Message::Begin(control) => {
                    if self.control.is_some() {
                        return Err(DataFusionError::Execution(
                            "physical transaction is already active".into(),
                        ))
                        .context(SqlSnafu);
                    }
                    control.check()?;
                    self.control = Some(Arc::clone(&control));
                    self.bytes = 0;
                    return Ok(Some(Message::Begin(control)));
                }
                Message::Insert(batch) => (batch, false),
                Message::Delete(batch) => (batch, true),
                message @ Message::Commit { .. } => {
                    let control = self.control.take().ok_or_else(|| {
                        crate::InvalidSnafu {
                            field: "physical transaction",
                        }
                        .build()
                    })?;
                    control.check()?;
                    return Ok(Some(message));
                }
            };
            self.control
                .as_ref()
                .ok_or_else(|| {
                    crate::InvalidSnafu {
                        field: "physical transaction",
                    }
                    .build()
                })?
                .check()?;
            let stream = SubscribeExec::bind(
                &self.plan,
                &self.source,
                vec![batch],
                Arc::clone(&self.context),
            )
            .context(SqlSnafu)?;
            self.active = Some((stream, retract));
        }
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
            _permit,
            _control: control,
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
        let mut input = self
            .run
            .engine
            .memory()
            .reserve_input(0)
            .context(SqlSnafu)?;
        for batch in &batches {
            self.run
                .engine
                .memory()
                .retain_input(batch, &mut input)
                .context(SqlSnafu)?;
        }
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
        Ok(Some(Output {
            snapshot,
            batches: (!unchanged).then_some(batches),
            _permit,
            _control: control,
        }))
    }
}
