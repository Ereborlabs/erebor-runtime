use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use snafu::ResultExt as _;

use super::{operation::ModelRun, AdmittedModel};
use crate::Result;

pub struct SqlDatasetOutputV1 {
    pub data: sdk::Dataset,
    _metadata: MemoryReservation,
}

impl ModelRun<'_> {
    pub fn query_datasets(
        mut self,
        inputs: &[sdk::Dataset],
        sql: &str,
        limits: sdk::Limits,
    ) -> Result<SqlDatasetOutputV1> {
        let ports = inputs
            .iter()
            .map(|input| {
                let schema = input
                    .batches
                    .first()
                    .ok_or_else(|| {
                        crate::ModelInvalidSnafu {
                            field: "committed dataset schema",
                        }
                        .build()
                    })?
                    .schema();
                Ok(sdk::Port::new(&input.name, schema.as_ref().clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        sdk::Dataset::validate_all(inputs, &ports, limits).context(crate::AnalysisContractSnafu)?;
        let mut relations = BTreeMap::new();
        for port in &ports {
            AdmittedModel::relation(&mut relations, &port.name, &port.schema)?;
        }
        let state = self.owner.catalog(relations)?;
        let plan = AdmittedModel::plan(self.owner, &state, sql)?;
        let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos()).map_err(
            |_| {
                crate::ModelInvalidSnafu {
                    field: "model query time",
                }
                .build()
            },
        )?;
        self.control = self.control.within(self.owner.limits().evaluate_timeout)?;
        self.start(crate::AnalysisSelectionV1::tenant(self.tenant()), now)?;
        self.limits = limits;
        self.byte_limit = usize::try_from(limits.max_bytes)
            .unwrap_or(usize::MAX)
            .min(self.owner.limits().output_capacity);
        self.output_memory = Some(self.memory.reserve_output(0)?);
        self.session()?
            .check_input(inputs.iter().flat_map(|data| &data.batches))?;
        for (port, data) in ports.iter().zip(inputs) {
            self.table(&port.name, &port.schema, &data.batches)?;
        }
        let batches = self.query(&plan, None)?;
        let schema = batches
            .first()
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model query schema",
                }
                .build()
            })?
            .schema();
        let data = sdk::Dataset {
            name: "query".into(),
            batches,
        };
        data.validate(&sdk::Port::new("query", schema.as_ref().clone()), limits)
            .context(crate::AnalysisContractSnafu)?;
        self.control.check()?;
        let metadata = data.name.capacity()
            + data.batches.capacity() * std::mem::size_of::<sdk::RecordBatch>()
            + data
                .batches
                .iter()
                .map(|batch| {
                    batch.num_columns() * std::mem::size_of::<sdk::arrow_array::ArrayRef>()
                        + batch
                            .columns()
                            .iter()
                            .map(|array| {
                                array
                                    .get_array_memory_size()
                                    .saturating_sub(array.get_buffer_memory_size())
                            })
                            .sum::<usize>()
                        + batch
                            .schema_ref()
                            .fields()
                            .iter()
                            .map(|field| field.size())
                            .sum::<usize>()
                })
                .sum::<usize>();
        let reservation = self.output_memory.take().ok_or_else(|| {
            crate::ModelInvalidSnafu {
                field: "model output reservation",
            }
            .build()
        })?;
        reservation.try_resize(metadata)?;
        Ok(SqlDatasetOutputV1 {
            data,
            _metadata: reservation,
        })
    }
}
