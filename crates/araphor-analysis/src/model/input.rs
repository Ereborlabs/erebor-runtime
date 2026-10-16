use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{operation::ModelRun, schema::ModelSchema};
use crate::Result;

impl ModelRun<'_> {
    pub(super) fn register(
        &mut self,
        model: &sdk::Model,
        evaluation: &sdk::Evaluation,
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
                        .flat_map(|state| &state.datasets)
                        .flat_map(|data| &data.batches),
                ),
            self.owner.limits().input_bytes,
        )?;
        for input in &model.inputs {
            let port = &input.port;
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
                .saturating_add(batch.get_array_memory_size())
                .saturating_add(
                    std::mem::size_of::<sdk::RecordBatch>()
                        + batch.num_columns() * std::mem::size_of::<sdk::arrow_array::ArrayRef>(),
                )
                .saturating_add(batch.num_rows().saturating_mul(8))
        });
        if bytes > limit {
            return crate::ModelLimitSnafu {
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
        let mut relation = std::collections::BTreeMap::new();
        ModelSchema::relation(&mut relation, name, schema)?;
        let schema = relation.remove(name).ok_or_else(|| {
            crate::ModelInvalidSnafu {
                field: "model table schema",
            }
            .build()
        })?;
        let mut reservation = self.owner.memory().reserve_input(Self::check_input(
            batches.iter(),
            self.owner.limits().input_bytes,
        )?)?;
        let mut offset = 0u64;
        let mut indexed = Vec::with_capacity(batches.len());
        for batch in batches {
            self.control.check()?;
            let rows = u64::try_from(batch.num_rows()).map_err(|_| {
                crate::ModelInvalidSnafu {
                    field: "model row index",
                }
                .build()
            })?;
            let end = offset.checked_add(rows).ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model row index",
                }
                .build()
            })?;
            let mut columns = batch.columns().to_vec();
            columns.push(Arc::new(sdk::arrow_array::UInt64Array::from_iter_values(
                offset..end,
            )));
            let batch = sdk::RecordBatch::try_new(Arc::clone(&schema), columns)
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            self.owner.memory().retain_input(&batch, &mut reservation)?;
            indexed.push(batch);
            offset = end;
        }
        drop(reservation);
        self.session()?.register(name, schema, &indexed)?;
        self.control.check()?;
        Ok(())
    }
}
