use std::{collections::BTreeMap, sync::Arc};

use araphor_analysis_sdk as sdk;
use datafusion::datasource::MemTable;
use snafu::ResultExt as _;

use super::execute::ModelExecution;
use crate::query::{budget::QueryLease, engine::QueryEngine};
use crate::Result;

impl ModelExecution<'_> {
    pub(super) fn register(
        &mut self,
        model: &sdk::Model,
        evaluation: &sdk::Evaluation,
        bound: BTreeMap<String, Arc<MemTable>>,
        input_limit: usize,
    ) -> Result<()> {
        Self::check_input(
            evaluation
                .inputs
                .iter()
                .flat_map(|input| &input.data.batches)
                .chain(evaluation.parameters.iter())
                .chain(
                    evaluation
                        .checkpoint
                        .iter()
                        .flat_map(|checkpoint| &checkpoint.datasets)
                        .flat_map(|dataset| &dataset.batches),
                ),
            input_limit,
        )?;
        self.tables = bound;
        for port in &model.inputs {
            let port = &port.port;
            if self.tables.contains_key(&port.name.to_ascii_lowercase()) {
                continue;
            }
            self.table(
                &port.name,
                &port.schema,
                &evaluation
                    .input(&port.name)
                    .context(crate::AnalysisContractSnafu)?
                    .data
                    .batches,
            )?;
        }
        if let Some(parameters) = &evaluation.parameters {
            self.table(
                "parameters",
                &model.parameters,
                std::slice::from_ref(parameters),
            )?;
        }
        if let Some(spec) = &model.checkpoint {
            for port in &spec.datasets {
                let batches = evaluation
                    .checkpoint
                    .as_ref()
                    .and_then(|state| state.datasets.iter().find(|data| data.name == port.name))
                    .map_or(&[][..], |data| data.batches.as_slice());
                self.table(&format!("prior_{}", port.name), &port.schema, batches)?;
            }
        }
        Ok(())
    }

    pub(super) fn check_input<'a>(
        batches: impl Iterator<Item = &'a sdk::RecordBatch>,
        limit: usize,
    ) -> Result<usize> {
        let bytes = batches.fold(0usize, |total, batch| {
            total
                .saturating_add(QueryEngine::batch_bytes(batch))
                .saturating_add(QueryLease::batch_overhead(batch))
                .saturating_add(QueryLease::index_overhead(batch.num_rows()))
        });
        if bytes > limit {
            return crate::QueryLimitSnafu {
                resource: "model input bytes",
                limit,
            }
            .fail();
        }
        Ok(bytes)
    }

    pub(super) fn table(
        &mut self,
        name: &str,
        schema: &sdk::Schema,
        batches: &[sdk::RecordBatch],
    ) -> Result<()> {
        self.control.check()?;
        let name = name.to_ascii_lowercase();
        let table = QueryEngine::table(Arc::new(schema.clone()), batches, self.lease)?;
        self.control.check()?;
        self.tables.insert(name, table);
        Ok(())
    }
}
