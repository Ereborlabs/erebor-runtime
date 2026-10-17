use std::borrow::Cow;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, StorePositionV1};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::DataFusionError;
use datafusion::execution::{memory_pool::MemoryReservation, TaskContext};
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_expr_common::utils::evaluate_expressions_to_arrays;
use datafusion::physical_plan::aggregates::{
    aggregate_expressions, create_accumulators, finalize_aggregation, AccumulatorItem,
    AggregateExec, AggregateMode,
};
use datafusion::physical_plan::filter::batch_filter;
use datafusion::physical_plan::ExecutionPlan;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use crate::execution::Session;
use crate::stream::{Change, Output};
use crate::{Result, SqlSnafu};

impl Kernel {
    pub(super) fn new(
        aggregate: &AggregateExec,
        source: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
        session: Arc<Session>,
    ) -> Result<Self> {
        let definitions = aggregate.aggr_expr().to_vec();
        let filters = aggregate.filter_expr().to_vec();
        let input_schema = aggregate.input_schema();
        let schema = aggregate.schema();
        let plan = Arc::clone(aggregate.input());
        session.control().check()?;
        let expressions =
            aggregate_expressions(&definitions, &AggregateMode::Single, 0).context(SqlSnafu)?;
        let accumulators = create_accumulators(&definitions).context(SqlSnafu)?;
        let bytes = [
            size_of::<Self>(),
            expressions.capacity() * size_of::<Vec<Arc<dyn PhysicalExpr>>>(),
            filters.capacity() * size_of::<Option<Arc<dyn PhysicalExpr>>>(),
            accumulators.capacity() * size_of::<AccumulatorItem>(),
        ]
        .into_iter()
        .chain(
            expressions
                .iter()
                .map(|values| values.capacity() * size_of::<Arc<dyn PhysicalExpr>>()),
        )
        .chain(accumulators.iter().map(|accumulator| accumulator.size()))
        .fold(0usize, usize::saturating_add);
        if bytes > session.engine().limits().input_bytes {
            return Err(DataFusionError::ResourcesExhausted(
                "maintained aggregate state".into(),
            ))
            .context(SqlSnafu);
        }
        let memory = session.memory().reserve_input(bytes).context(SqlSnafu)?;
        Ok(Self {
            plan,
            source,
            context,
            input_schema,
            schema,
            expressions,
            filters,
            accumulators,
            frontier: None,
            session,
            _memory: memory,
        })
    }
}

pub(super) struct Kernel {
    plan: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
    context: Arc<TaskContext>,
    input_schema: SchemaRef,
    schema: SchemaRef,
    expressions: Vec<Vec<Arc<dyn PhysicalExpr>>>,
    filters: Vec<Option<Arc<dyn PhysicalExpr>>>,
    accumulators: Vec<AccumulatorItem>,
    frontier: Option<StorePositionV1>,
    session: Arc<Session>,
    _memory: MemoryReservation,
}

impl Kernel {
    pub(super) async fn apply(&mut self, change: Change) -> Result<Output> {
        let Change {
            before,
            after,
            position,
            snapshot,
            control,
            _permit,
            _memory,
        } = change;
        control.check()?;
        if position.ordinal != u32::MAX
            || position.commit_revision != snapshot.page.extraction.meta.commit_revision
            || position != snapshot.page.scanned_through
            || self.frontier.is_some_and(|previous| position <= previous)
        {
            return Err(DataFusionError::Execution(
                "maintained commit frontier is invalid".into(),
            ))
            .context(SqlSnafu);
        }
        let memory = self.session.memory().reserve_input(0).context(SqlSnafu)?;
        let mut bytes = 0usize;
        for (batches, retract) in [(before, true), (after, false)] {
            if batches.is_empty() {
                continue;
            }
            let mut stream = super::SubscribeExec::bind(
                &self.plan,
                &self.source,
                batches,
                Arc::clone(&self.context),
            )
            .context(SqlSnafu)?;
            while let Some(batch) = control
                .query_async(async { stream.try_next().await.context(SqlSnafu) })
                .await?
            {
                bytes = bytes.saturating_add(batch.get_array_memory_size());
                if bytes > self.session.engine().limits().input_bytes {
                    return Err(DataFusionError::ResourcesExhausted(
                        "maintained native input".into(),
                    ))
                    .context(SqlSnafu);
                }
                self.session
                    .memory()
                    .retain_input(&batch, &memory)
                    .context(SqlSnafu)?;
                self.update(&batch, retract, &control)?;
            }
        }
        control
            .query_async(self.session.engine().check_read(&snapshot))
            .await?;
        let columns = finalize_aggregation(&mut self.accumulators, &AggregateMode::Single)
            .context(SqlSnafu)?;
        let batch = RecordBatch::try_new(Arc::clone(&self.schema), columns)
            .map_err(DataFusionError::from)
            .context(SqlSnafu)?;
        self.session
            .memory()
            .retain_input(&batch, &memory)
            .context(SqlSnafu)?;
        control.check()?;
        self.frontier = Some(position);
        Ok(Output {
            snapshot,
            batches: Some(vec![batch]),
            positions: Vec::new(),
            position: StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            limited: false,
            _memory: memory,
            _permit,
            _control: control,
        })
    }

    fn update(
        &mut self,
        batch: &RecordBatch,
        retract: bool,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        if batch.schema() != self.input_schema {
            return Err(DataFusionError::Execution(
                "maintained aggregate input schema changed".into(),
            ))
            .context(SqlSnafu);
        }
        for ((accumulator, expressions), filter) in self
            .accumulators
            .iter_mut()
            .zip(&self.expressions)
            .zip(&self.filters)
        {
            let batch = match filter {
                Some(filter) => Cow::Owned(batch_filter(batch, filter).context(SqlSnafu)?),
                None => Cow::Borrowed(batch),
            };
            let values = evaluate_expressions_to_arrays(expressions, &batch).context(SqlSnafu)?;
            if retract {
                accumulator.retract_batch(&values).context(SqlSnafu)?;
            } else {
                accumulator.update_batch(&values).context(SqlSnafu)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
