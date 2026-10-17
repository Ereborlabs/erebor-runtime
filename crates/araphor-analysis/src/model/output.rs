use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{Array, StringArray, UInt64Array};

use super::operation::ModelRun;
use crate::Result;
use araphor_query::datafusion::logical_expr::LogicalPlan;
use std::sync::Arc;

impl ModelRun {
    pub(super) async fn evidence(
        &mut self,
        query: Option<&Arc<LogicalPlan>>,
    ) -> Result<Vec<sdk::EvidenceLink>> {
        let Some(query) = query else {
            return Ok(Vec::new());
        };
        let schema = sdk::Schema::new(vec![
            sdk::Field::new("output_dataset", sdk::DataType::Utf8, false),
            sdk::Field::new("output_row", sdk::DataType::UInt64, false),
            sdk::Field::new("input_dataset", sdk::DataType::Utf8, false),
            sdk::Field::new("input_row", sdk::DataType::UInt64, false),
        ]);
        let batches = self.references(query, &schema).await?;
        let mut links = Vec::new();
        for batch in batches {
            let outputs = Self::strings(&batch, 0)?;
            let output_rows = Self::indices(&batch, 1)?;
            let inputs = Self::strings(&batch, 2)?;
            let input_rows = Self::indices(&batch, 3)?;
            for row in 0..batch.num_rows() {
                self.control.check()?;
                self.owned(
                    std::mem::size_of::<sdk::EvidenceLink>()
                        + outputs.value(row).len()
                        + inputs.value(row).len(),
                )?;
                links.try_reserve_exact(1).map_err(|_| {
                    crate::ModelInvalidSnafu {
                        field: "model evidence allocation",
                    }
                    .build()
                })?;
                links.push(sdk::EvidenceLink {
                    output: sdk::RowRef {
                        dataset: outputs.value(row).into(),
                        row: output_rows.value(row),
                    },
                    input: sdk::RowRef {
                        dataset: inputs.value(row).into(),
                        row: input_rows.value(row),
                    },
                });
            }
        }
        Ok(links)
    }

    pub(super) async fn reasons(
        &mut self,
        model: &sdk::Model,
        queries: &[(usize, usize, Arc<LogicalPlan>)],
    ) -> Result<Vec<sdk::ReasonValue>> {
        let mut reasons = Vec::new();
        for (output, reason, query) in queries {
            let (output, spec) = model
                .outputs
                .get(*output)
                .zip(model.reasons.get(*reason))
                .ok_or_else(|| {
                    crate::ModelInvalidSnafu {
                        field: "model reason declaration",
                    }
                    .build()
                })?;
            if spec.details.field_with_name("output_row").is_ok() {
                return crate::ModelInvalidSnafu {
                    field: "model reason row column",
                }
                .fail();
            }
            let schema = sdk::Schema::new(
                std::iter::once(sdk::Field::new("output_row", sdk::DataType::UInt64, false))
                    .chain(
                        spec.details
                            .fields()
                            .iter()
                            .map(|field| field.as_ref().clone()),
                    )
                    .collect::<Vec<_>>(),
            );
            for batch in self.references(query, &schema).await? {
                let rows = Self::indices(&batch, 0)?;
                let details = sdk::RecordBatch::try_new_with_options(
                    std::sync::Arc::new(spec.details.clone()),
                    batch.columns()[1..].to_vec(),
                    &sdk::arrow_array::RecordBatchOptions::new()
                        .with_row_count(Some(batch.num_rows())),
                )
                .map_err(|_| {
                    crate::ModelInvalidSnafu {
                        field: "model reason details",
                    }
                    .build()
                })?;
                for row in 0..batch.num_rows() {
                    self.owned(
                        std::mem::size_of::<sdk::ReasonValue>()
                            + output.name.len()
                            + spec.code.len()
                            + spec.details.fields().len() * 16,
                    )?;
                    reasons.try_reserve_exact(1).map_err(|_| {
                        crate::ModelInvalidSnafu {
                            field: "model reason allocation",
                        }
                        .build()
                    })?;
                    reasons.push(sdk::ReasonValue {
                        output: sdk::RowRef {
                            dataset: output.name.clone(),
                            row: rows.value(row),
                        },
                        code: spec.code.clone(),
                        details: details.slice(row, 1),
                    });
                }
            }
        }
        Ok(reasons)
    }

    fn strings(batch: &sdk::RecordBatch, index: usize) -> Result<&StringArray> {
        batch
            .column(index)
            .as_any()
            .downcast_ref::<StringArray>()
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model evidence string",
                }
                .build()
            })
    }

    fn indices(batch: &sdk::RecordBatch, index: usize) -> Result<&UInt64Array> {
        batch
            .column(index)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model output reference",
                }
                .build()
            })
    }
}
