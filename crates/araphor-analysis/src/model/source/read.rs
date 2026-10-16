use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use super::super::{operation::ModelRun, schema::ModelSchema};
use super::ModelInputRequest;
use crate::Result;

impl ModelRun<'_> {
    pub(in crate::model) fn read_input(
        &mut self,
        request: &ModelInputRequest<'_>,
        port: &sdk::Port,
        plan: &Arc<LogicalPlan>,
        reads: &BTreeSet<String>,
        inherited: &[sdk::Input],
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<sdk::Input> {
        let bounds = sdk::Limits {
            max_bytes: request
                .model
                .limits
                .max_bytes
                .min(self.owner.limits().input_bytes as u64),
            ..request.model.limits
        };
        authorize()?;
        self.session()?.set_output(
            usize::try_from(bounds.max_rows).map_err(|_| {
                crate::ModelInvalidSnafu {
                    field: "model source row limit",
                }
                .build()
            })?,
            usize::try_from(bounds.max_bytes).map_err(|_| {
                crate::ModelInvalidSnafu {
                    field: "model source byte limit",
                }
                .build()
            })?,
        )?;
        let (snapshot, native) = self.session()?.execute_input(Arc::clone(plan), reads)?;
        authorize()?;
        if snapshot.mutable_discovery {
            return Err(crate::PackageErrorCodeV1::Unsupported
                .error("mutable discovery input")
                .into());
        }
        self.input_memory.try_resize(bounds.max_bytes as usize)?;
        let schema = Arc::new(port.schema.clone());
        let mut batches = Vec::with_capacity(native.len().max(1));
        let mut bytes = 0usize;
        for batch in native {
            self.control.check()?;
            let conversion = batch.columns().iter().zip(schema.fields()).try_fold(
                0usize,
                |bytes, (array, field)| {
                    bytes
                        .checked_add(super::super::arrays::ModelArrays::conversion_bytes(
                            array,
                            field.data_type(),
                        )?)
                        .ok_or_else(|| {
                            crate::ModelInvalidSnafu {
                                field: "model conversion allocation",
                            }
                            .build()
                        })
                },
            )?;
            if conversion > self.input_memory.size() {
                return crate::ModelLimitSnafu {
                    resource: "model source conversion",
                    limit: bounds.max_bytes as usize,
                }
                .fail();
            }
            let batch = ModelSchema::normalize(batch, Arc::clone(&schema))?;
            bytes = bytes.saturating_add(batch.get_array_memory_size());
            if bytes > bounds.max_bytes as usize {
                return crate::ModelLimitSnafu {
                    resource: "model source input",
                    limit: bounds.max_bytes as usize,
                }
                .fail();
            }
            self.owner
                .memory()
                .retain_input(&batch, &mut self.input_memory)?;
            batches.push(batch);
        }
        if batches.is_empty() {
            batches.push(sdk::RecordBatch::new_empty(schema));
        }
        let data = sdk::Dataset {
            name: port.name.clone(),
            batches,
        };
        data.validate(port, bounds)
            .context(crate::AnalysisContractSnafu)?;
        self.inputs.add_snapshot(
            &snapshot,
            self.owner.store(),
            !reads.is_empty(),
            data,
            inherited,
        )
    }
}
