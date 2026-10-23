use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use sdk::arrow_array::{Array, StringArray, UInt64Array};

use super::{external, internal, CallContext, PackageExec, Result, SourceSnapshot};

impl PackageExec {
    pub(super) async fn sql(
        &self,
        evaluation: &sdk::Evaluation,
        owner: &CallContext,
        context: &Arc<TaskContext>,
        source: &SourceSnapshot,
        memory: &MemoryReservation,
    ) -> Result<sdk::Output> {
        let sql = self
            .call
            .sql
            .as_ref()
            .ok_or_else(|| internal("package SQL plans are absent"))?;
        let model = self
            .call
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == self.call.export)
            .ok_or_else(|| internal("package export is absent"))?;
        for (input, slot) in evaluation.inputs.iter().zip(&sql.inputs) {
            if !sql.used.contains(slot) {
                continue;
            }
            let schema = input
                .data
                .batches
                .first()
                .ok_or_else(|| internal("package input batch is absent"))?
                .schema();
            source.bind_port(*slot, schema, input.data.batches.clone(), Some(input))?;
        }
        if let Some(slot) = sql.parameters.filter(|slot| sql.used.contains(slot)) {
            let parameters = evaluation
                .parameters
                .as_ref()
                .ok_or_else(|| internal("package parameters are absent"))?;
            source.bind_port(slot, parameters.schema(), vec![parameters.clone()], None)?;
        }
        if let Some(spec) = &model.checkpoint {
            for (port, slot) in spec.datasets.iter().zip(&sql.prior) {
                if !sql.used.contains(slot) {
                    continue;
                }
                let schema = Arc::new(port.schema.clone());
                let batches = evaluation
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| {
                        checkpoint
                            .datasets
                            .iter()
                            .find(|data| data.name == port.name)
                    })
                    .map_or_else(
                        || vec![sdk::RecordBatch::new_empty(Arc::clone(&schema))],
                        |data| data.batches.clone(),
                    );
                source.bind_port(*slot, schema, batches, None)?;
            }
        }
        let mut child = model.inputs.len() + usize::from(evaluation.parameters.is_some());
        let mut datasets = Vec::with_capacity(model.outputs.len());
        for port in &model.outputs {
            let batches = self
                .collect(child, &port.schema, owner, context, memory, false)
                .await?;
            child += 1;
            datasets.push(sdk::Dataset {
                name: port.name.clone(),
                batches,
            });
        }
        for ((data, port), slot) in datasets.iter().zip(&model.outputs).zip(&sql.outputs) {
            if !sql.used.contains(slot) {
                continue;
            }
            source.bind_port(
                *slot,
                Arc::new(port.schema.clone()),
                data.batches.clone(),
                None,
            )?;
        }
        let checkpoint = if let Some(spec) = &model.checkpoint {
            let mut datasets = Vec::with_capacity(spec.datasets.len());
            for port in &spec.datasets {
                let batches = self
                    .collect(child, &port.schema, owner, context, memory, false)
                    .await?;
                child += 1;
                datasets.push(sdk::Dataset {
                    name: port.name.clone(),
                    batches,
                });
            }
            Some(sdk::Checkpoint {
                version: spec.version,
                datasets,
            })
        } else {
            None
        };
        let mut evidence = Vec::new();
        if sql.evidence {
            let schema = sdk::Schema::new(vec![
                sdk::Field::new("output_dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("output_row", sdk::DataType::UInt64, false),
                sdk::Field::new("input_dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("input_row", sdk::DataType::UInt64, false),
            ]);
            for batch in self
                .collect(child, &schema, owner, context, memory, false)
                .await?
            {
                let outputs = strings(&batch, 0)?;
                let output_rows = indices(&batch, 1)?;
                let inputs = strings(&batch, 2)?;
                let input_rows = indices(&batch, 3)?;
                for row in 0..batch.num_rows() {
                    owner.control.check().map_err(external)?;
                    memory.try_grow(
                        std::mem::size_of::<sdk::EvidenceLink>()
                            + outputs.value(row).len()
                            + inputs.value(row).len(),
                    )?;
                    evidence.push(sdk::EvidenceLink {
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
            child += 1;
        }
        let mut reasons = Vec::new();
        for (output, code) in &sql.reasons {
            let spec = model
                .reasons
                .iter()
                .find(|reason| reason.code == *code)
                .ok_or_else(|| internal("package reason is absent"))?;
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
            for batch in self
                .collect(child, &schema, owner, context, memory, false)
                .await?
            {
                let rows = indices(&batch, 0)?;
                let details = sdk::RecordBatch::try_new_with_options(
                    Arc::new(spec.details.clone()),
                    batch.columns()[1..].to_vec(),
                    &sdk::arrow_array::RecordBatchOptions::new()
                        .with_row_count(Some(batch.num_rows())),
                )?;
                for row in 0..batch.num_rows() {
                    owner.control.check().map_err(external)?;
                    memory.try_grow(
                        std::mem::size_of::<sdk::ReasonValue>() + output.len() + code.len(),
                    )?;
                    reasons.push(sdk::ReasonValue {
                        output: sdk::RowRef {
                            dataset: output.clone(),
                            row: rows.value(row),
                        },
                        code: code.clone(),
                        details: details.slice(row, 1),
                    });
                }
            }
            child += 1;
        }
        if child != self.children.len() {
            return Err(internal("package SQL child count changed"));
        }
        Ok(sdk::Output {
            datasets,
            evidence,
            reasons,
            checkpoint,
        })
    }
}

fn strings(batch: &sdk::RecordBatch, column: usize) -> Result<&StringArray> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<StringArray>()
        .filter(|array| array.null_count() == 0)
        .ok_or_else(|| internal("package reference string is invalid"))
}

fn indices(batch: &sdk::RecordBatch, column: usize) -> Result<&UInt64Array> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .filter(|array| array.null_count() == 0)
        .ok_or_else(|| internal("package reference row is invalid"))
}
