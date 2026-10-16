use std::borrow::Cow;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, StorePositionV1};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::functions_aggregate::count::Count;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_expr_common::utils::evaluate_expressions_to_arrays;
use datafusion::physical_plan::aggregates::{
    aggregate_expressions, create_accumulators, finalize_aggregation, AccumulatorItem,
    AggregateExec, AggregateMode,
};
use datafusion::physical_plan::filter::batch_filter;
use datafusion::physical_plan::ExecutionPlan;
use futures_util::{stream, StreamExt as _, TryStreamExt as _};
use snafu::ResultExt as _;

use crate::execution::Engine;
use crate::stream::{Input, Message, Output, OutputStream};
use crate::{Result, SqlSnafu};

pub(super) fn execute(
    aggregate: &AggregateExec,
    input: Input,
    engine: Arc<Engine>,
    control: Arc<AnalysisReadControl>,
) -> OutputStream {
    let supported = aggregate.mode() == &AggregateMode::Single
        && aggregate.group_expr().is_true_no_grouping()
        && !aggregate.aggr_expr().is_empty();
    let definitions = aggregate.aggr_expr().to_vec();
    let filters = aggregate.filter_expr().to_vec();
    let input_schema = aggregate.input_schema();
    let schema = aggregate.schema();
    let initialize = stream::once(async move {
        control.check()?;
        if !supported {
            return Err(DataFusionError::NotImplemented(
                "maintained global COUNT aggregate".into(),
            ))
            .context(SqlSnafu);
        }
        if definitions.iter().any(|expression| {
            expression.is_distinct() || !expression.fun().inner().as_any().is::<Count>()
        }) {
            return Err(DataFusionError::NotImplemented(
                "maintained ordinary COUNT aggregate".into(),
            ))
            .context(SqlSnafu);
        }
        let expressions =
            aggregate_expressions(&definitions, &AggregateMode::Single, 0).context(SqlSnafu)?;
        let accumulators = create_accumulators(&definitions).context(SqlSnafu)?;
        let bytes = [
            size_of::<State>(),
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
        if bytes > engine.limits().input_bytes {
            return Err(DataFusionError::ResourcesExhausted(
                "maintained aggregate state".into(),
            ))
            .context(SqlSnafu);
        }
        let memory = engine.memory().reserve_input(bytes).context(SqlSnafu)?;
        Ok(State {
            input,
            input_schema,
            schema,
            expressions,
            filters,
            accumulators,
            frontier: None,
            stage: None,
            engine,
            control,
            _memory: memory,
        })
    });
    Box::pin(
        initialize
            .map_ok(|state| {
                stream::try_unfold(state, |mut state| async move {
                    Ok(state.next().await?.map(|output| (output, state)))
                })
            })
            .try_flatten(),
    )
}

struct State {
    input: Input,
    input_schema: SchemaRef,
    schema: SchemaRef,
    expressions: Vec<Vec<Arc<dyn PhysicalExpr>>>,
    filters: Vec<Option<Arc<dyn PhysicalExpr>>>,
    accumulators: Vec<AccumulatorItem>,
    frontier: Option<StorePositionV1>,
    stage: Option<Arc<AnalysisReadControl>>,
    engine: Arc<Engine>,
    control: Arc<AnalysisReadControl>,
    _memory: MemoryReservation,
}

impl State {
    async fn next(&mut self) -> Result<Option<Output>> {
        loop {
            let control = Arc::clone(self.stage.as_ref().unwrap_or(&self.control));
            let message = control
                .query_async(async { self.input.next().await.transpose() })
                .await?;
            let Some(message) = message else {
                if self.stage.is_some() {
                    return Err(DataFusionError::Execution(
                        "maintained input ended before commit".into(),
                    ))
                    .context(SqlSnafu);
                }
                return Ok(None);
            };
            match message {
                Message::Begin(control) => {
                    if self.stage.is_some() {
                        return Err(DataFusionError::Execution(
                            "maintained transaction has already started".into(),
                        ))
                        .context(SqlSnafu);
                    }
                    control.check()?;
                    self.stage = Some(control);
                }
                Message::Insert(batch) => self.update(&batch, false)?,
                Message::Delete(batch) => self.update(&batch, true)?,
                Message::Commit {
                    position,
                    snapshot,
                    _permit,
                } => {
                    let control = self.stage.take().ok_or_else(|| crate::Error::Sql {
                        source: DataFusionError::Execution(
                            "maintained transaction has not started".into(),
                        ),
                    })?;
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
                    control
                        .query_async(self.engine.check_read(&snapshot))
                        .await?;
                    let columns =
                        finalize_aggregation(&mut self.accumulators, &AggregateMode::Single)
                            .context(SqlSnafu)?;
                    let batch = RecordBatch::try_new(Arc::clone(&self.schema), columns)
                        .map_err(DataFusionError::from)
                        .context(SqlSnafu)?;
                    control.check()?;
                    self.frontier = Some(position);
                    return Ok(Some(Output {
                        snapshot,
                        batches: Some(vec![batch]),
                        _permit,
                        _control: control,
                    }));
                }
            }
        }
    }

    fn update(&mut self, batch: &RecordBatch, retract: bool) -> Result<()> {
        self.stage
            .as_ref()
            .ok_or_else(|| crate::Error::Sql {
                source: DataFusionError::Execution("maintained transaction has not started".into()),
            })?
            .check()?;
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
