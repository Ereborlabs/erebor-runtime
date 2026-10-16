use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::arrow::array::{RecordBatchOptions, UInt64Array};
use datafusion::catalog::default_table_source::provider_as_source;
use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;
use datafusion::logical_expr::{LogicalPlan, LogicalPlanBuilder, TableScan};
use futures_util::StreamExt as _;
use snafu::ResultExt as _;

use super::QueryEngine;
use crate::query::{QueryBinding, QueryLease};
#[cfg(test)]
use crate::AnalysisReadControl;
use crate::Result;

impl QueryEngine {
    pub(in crate::query) fn table(
        schema: Arc<sdk::Schema>,
        batches: &[sdk::RecordBatch],
        lease: &QueryLease,
    ) -> Result<Arc<MemTable>> {
        let mut fields = schema.fields().to_vec();
        fields.push(Arc::new(sdk::Field::new(
            "__row_index",
            sdk::DataType::UInt64,
            false,
        )));
        let schema = Arc::new(sdk::Schema::new_with_metadata(
            fields,
            schema.metadata().clone(),
        ));
        let mut offset = 0u64;
        let mut indexed = Vec::with_capacity(batches.len());
        for batch in batches {
            let end = offset.checked_add(batch.num_rows() as u64).ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model row index",
                }
                .build()
            })?;
            let mut columns = batch.columns().to_vec();
            columns.push(Arc::new(UInt64Array::from_iter_values(offset..end)));
            let batch = sdk::RecordBatch::try_new_with_options(
                schema.clone(),
                columns,
                &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
            )
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)?;
            indexed.push(lease.retain_batch(&batch)?);
            offset = end;
        }
        MemTable::try_new(schema, vec![indexed])
            .map(Arc::new)
            .context(crate::QueryEngineSnafu {
                operation: "register model Arrow input",
            })
    }

    pub(in crate::query) fn prepare(
        state: &SessionState,
        binding: &QueryBinding,
        fetch: Option<usize>,
    ) -> Result<(LogicalPlan, Arc<sdk::Schema>)> {
        let mut plan = binding.plan()?;
        if let Some(fetch) = fetch {
            plan = LogicalPlanBuilder::from(plan)
                .limit(0, Some(fetch))
                .and_then(LogicalPlanBuilder::build)
                .context(crate::QueryEngineSnafu {
                    operation: "bound client output",
                })?;
        }
        let plan = state.optimize(&plan).context(crate::QueryEngineSnafu {
            operation: "optimize query",
        })?;
        let schema = binding.output_schema(plan.schema().as_arrow())?;
        Ok((plan, schema))
    }

    pub(in crate::query) fn bind_sources(
        plan: LogicalPlan,
        tables: &BTreeMap<String, Arc<MemTable>>,
    ) -> Result<LogicalPlan> {
        let plan = plan
            .transform_up(|plan| {
                if let LogicalPlan::Filter(mut filter) = plan {
                    if filter
                        .input
                        .schema()
                        .fields()
                        .iter()
                        .any(|field| field.data_type() == &sdk::DataType::UInt64)
                    {
                        // IS TRUE keeps the predicate and avoids UInt64 statistics overflow.
                        filter.predicate =
                            datafusion::logical_expr::Expr::IsTrue(Box::new(filter.predicate));
                    }
                    return Ok(Transformed::yes(LogicalPlan::Filter(filter)));
                }
                let LogicalPlan::TableScan(scan) = plan else {
                    return Ok(Transformed::no(plan));
                };
                let table = tables.get(scan.table_name.table()).ok_or_else(|| {
                    datafusion::common::DataFusionError::Plan("admitted source is absent".into())
                })?;
                let original = scan.source.schema();
                let actual = table.schema();
                let fields = scan
                    .projection
                    .unwrap_or_else(|| (0..original.fields().len()).collect());
                let projection = fields
                    .into_iter()
                    .map(|index| {
                        let expected = original.field(index);
                        let actual_index = actual.index_of(expected.name())?;
                        if actual.field(actual_index).data_type() != expected.data_type() {
                            return datafusion::common::plan_err!(
                                "admitted source column type differs"
                            );
                        }
                        Ok(actual_index)
                    })
                    .collect::<datafusion::common::Result<Vec<_>>>()?;
                let scan = TableScan::try_new(
                    scan.table_name,
                    provider_as_source(table.clone()),
                    Some(projection),
                    scan.filters,
                    scan.fetch,
                )?;
                Ok(Transformed::yes(LogicalPlan::TableScan(scan)))
            })
            .context(crate::QueryEngineSnafu {
                operation: "bind selected Arrow sources",
            })?
            .data;
        Ok(plan)
    }

    pub(in crate::query) async fn stream(
        state: SessionState,
        plan: LogicalPlan,
        #[cfg(test)] gate: Option<crate::query::owner_tests::ScanGate>,
    ) -> Result<datafusion::physical_plan::SendableRecordBatchStream> {
        let plan = state
            .query_planner()
            .create_physical_plan(&plan, &state)
            .await
            .context(crate::QueryEngineSnafu {
                operation: "plan query execution",
            })?;
        let context = datafusion::prelude::SessionContext::new_with_state(state);
        let schema = plan.schema();
        let streams =
            datafusion::physical_plan::execute_stream_partitioned(plan, context.task_ctx())
                .context(crate::QueryEngineSnafu {
                    operation: "start query stream",
                })?;
        let stream: datafusion::physical_plan::SendableRecordBatchStream = Box::pin(
            datafusion::physical_plan::stream::RecordBatchStreamAdapter::new(
                schema,
                futures_util::stream::iter(streams).flatten(),
            ),
        );
        #[cfg(test)]
        let stream = crate::query::owner_tests::gate_stream(stream, gate);
        Ok(stream)
    }

    #[cfg(test)]
    pub(in crate::query) fn query(
        &self,
        state: &SessionState,
        binding: &QueryBinding,
        tables: &BTreeMap<String, Arc<MemTable>>,
        _limits: sdk::Limits,
        control: &AnalysisReadControl,
        lease: &QueryLease,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let (plan, schema) = Self::prepare(state, binding, None)?;
        let plan = Self::bind_sources(plan, tables)?;
        let state = state.clone();
        let lease = lease.clone();
        self.run(control, async move {
            let _retained = lease;
            let stream = Self::stream(state, plan, None).await?;
            datafusion::physical_plan::common::collect(stream)
                .await
                .context(crate::QueryEngineSnafu {
                    operation: "read query stream",
                })?
                .into_iter()
                .map(|batch| {
                    sdk::RecordBatch::try_new_with_options(
                        schema.clone(),
                        batch.columns().to_vec(),
                        &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
                    )
                    .map_err(sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)
                })
                .collect()
        })
    }

    pub(in crate::query) fn batch_bytes(batch: &sdk::RecordBatch) -> usize {
        batch
            .get_array_memory_size()
            .saturating_add(std::mem::size_of::<sdk::RecordBatch>())
            .saturating_add(
                batch
                    .schema()
                    .fields()
                    .iter()
                    .map(|field| field.size())
                    .sum::<usize>(),
            )
            .saturating_add(
                batch
                    .schema()
                    .metadata()
                    .iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum::<usize>(),
            )
    }
}
