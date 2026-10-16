use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::super::{budget::QueryLease, engine::QueryEngine};
use super::{execute::ModelExecution, schema::ModelSchema};
use crate::{AnalysisReadControl, QueryClock as _, QueryOwner, QuerySql, Result, SystemQueryClock};

pub struct SqlDatasetOutputV1 {
    pub data: sdk::Dataset,
    _lease: QueryLease,
}

impl QueryOwner {
    pub fn query_datasets(
        &self,
        tenant: [u8; 16],
        inputs: &[sdk::Dataset],
        sql: &str,
        limits: sdk::Limits,
        control: &AnalysisReadControl,
    ) -> Result<SqlDatasetOutputV1> {
        let ports = inputs
            .iter()
            .map(|input| {
                let schema = input
                    .batches
                    .first()
                    .ok_or_else(|| {
                        crate::QueryInvalidSnafu {
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
            ModelSchema::relation(&mut relations, &port.name, &port.schema)?;
        }
        let query = QuerySql::admit_relations(sql, relations)?;
        let now = i64::try_from(SystemQueryClock.now_ns()?).map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "model query time",
            }
            .build()
        })?;
        let capacity = (limits.max_bytes as usize).min(self.limits.output_capacity);
        let mut lease = self.budget.model(tenant, capacity)?;
        let control = control.within(self.limits.evaluate_timeout)?;
        let input_bytes = ModelExecution::check_input(
            inputs.iter().flat_map(|input| &input.batches),
            self.limits.input_bytes,
        )?;
        lease.shrink_input(input_bytes)?;
        let state = QueryEngine::state()?;
        let host = crate::QueryLimits {
            output_capacity: capacity,
            ..self.limits.clone()
        };
        let mut executor = ModelExecution::new(self, &state, &control, &lease, now, limits, &host);
        for (port, data) in ports.iter().zip(inputs) {
            executor.table(&port.name, &port.schema, &data.batches)?;
        }
        let batches = executor.query(&query, None)?;
        let bytes = batches.iter().fold(executor.bytes(), |bytes, batch| {
            bytes.saturating_add(QueryLease::batch_overhead(batch))
        });
        drop(executor);
        drop(state);
        let schema = batches
            .first()
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model query schema",
                }
                .build()
            })?
            .schema();
        let mut data = sdk::Dataset {
            name: "query".into(),
            batches,
        };
        data.validate(&sdk::Port::new("query", schema.as_ref().clone()), limits)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        let output = lease.split(bytes)?;
        for batch in &mut data.batches {
            *batch = output.retain_batch(batch)?;
        }
        drop(lease.retained_output(0)?);
        Ok(SqlDatasetOutputV1 {
            data,
            _lease: output,
        })
    }
}
