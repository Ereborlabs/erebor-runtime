use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{execute::ModelExecution, schema::ModelSchema};
use crate::Result;

impl ModelExecution<'_> {
    pub(super) fn register(&self, model: &sdk::Model) -> Result<()> {
        for port in &model.inputs {
            self.table(
                &port.name,
                &port.schema,
                &self
                    .evaluation
                    .input(&port.name)
                    .context(crate::AnalysisContractSnafu)?
                    .data
                    .batches,
            )?;
        }
        if let Some(parameters) = &self.evaluation.parameters {
            self.table(
                "parameters",
                &model.parameters,
                std::slice::from_ref(parameters),
            )?;
        }
        if let Some(spec) = &model.checkpoint {
            for port in &spec.datasets {
                let batches = self
                    .evaluation
                    .checkpoint
                    .as_ref()
                    .and_then(|state| state.datasets.iter().find(|data| data.name == port.name))
                    .map_or(&[][..], |data| data.batches.as_slice());
                self.table(&format!("prior_{}", port.name), &port.schema, batches)?;
            }
        }
        Ok(())
    }

    pub(super) fn table(
        &self,
        name: &str,
        schema: &sdk::Schema,
        batches: &[sdk::RecordBatch],
    ) -> Result<()> {
        self.control.check()?;
        self.connection
            .execute_batch(&format!(
                "CREATE TABLE {} ({}, __row_index UBIGINT)",
                ModelSchema::quote(name),
                ModelSchema::fields(schema)?
            ))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "create model input",
            })?;
        let mut appender =
            self.connection
                .appender(name)
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "open model input",
                })?;
        let mut offset = 0u64;
        for batch in batches {
            self.control.check()?;
            let mut fields = schema.fields().to_vec();
            fields.push(Arc::new(sdk::Field::new(
                "__row_index",
                sdk::DataType::UInt64,
                false,
            )));
            let mut columns = batch.columns().to_vec();
            let end = offset.checked_add(batch.num_rows() as u64).ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model row index",
                }
                .build()
            })?;
            columns.push(Arc::new(sdk::arrow_array::UInt64Array::from_iter_values(
                offset..end,
            )));
            let batch = sdk::RecordBatch::try_new(Arc::new(sdk::Schema::new(fields)), columns)
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            appender
                .append_record_batch(ModelSchema::physical(&batch)?)
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "append model input",
                })?;
            offset = end;
        }
        appender.flush().context(crate::AnalysisDatabaseSnafu {
            operation: "finish model input",
        })
    }
}
