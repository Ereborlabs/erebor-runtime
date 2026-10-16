use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use duckdb::Connection;
use snafu::ResultExt as _;

use super::{schema::ModelSchema, AdmittedModel, SqlModelV1};
use crate::{AnalysisReadControl, QueryLimits, QuerySql, Result};

pub(super) struct ModelExecution<'a> {
    pub(super) connection: &'a Connection,
    pub(super) control: &'a AnalysisReadControl,
    time_utc_ns: i64,
    limits: sdk::Limits,
    byte_limit: usize,
    pub(super) bytes: usize,
    pub(super) rows: u64,
    batches: u32,
}

impl<'a> ModelExecution<'a> {
    pub(super) fn new(
        connection: &'a Connection,
        control: &'a AnalysisReadControl,
        time_utc_ns: i64,
        mut limits: sdk::Limits,
        host: &QueryLimits,
    ) -> Self {
        limits.max_bytes = limits.max_bytes.min(host.output_capacity as u64);
        limits.max_checkpoint_bytes = limits.max_checkpoint_bytes.min(host.output_capacity as u64);
        Self {
            connection,
            control,
            time_utc_ns,
            limits,
            byte_limit: host.output_capacity,
            bytes: 0,
            rows: 0,
            batches: 0,
        }
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn evaluate(
        &mut self,
        model: &sdk::Model,
        program: &SqlModelV1,
        admitted: &AdmittedModel,
    ) -> Result<sdk::Output> {
        let datasets = self.datasets(&model.outputs, &admitted.outputs)?;
        for (port, data) in model.outputs.iter().zip(&datasets) {
            self.table(
                &format!("output_{}", port.name),
                &port.schema,
                &data.batches,
            )?;
        }
        let checkpoint = model
            .checkpoint
            .as_ref()
            .map(|spec| {
                self.datasets(&spec.datasets, &admitted.checkpoint)
                    .map(|datasets| sdk::Checkpoint {
                        version: spec.version,
                        datasets,
                    })
            })
            .transpose()?;
        let evidence = self.evidence(admitted.evidence.as_ref())?;
        let reasons = self.reasons(model, &program.reasons, &admitted.reasons)?;
        Ok(sdk::Output {
            datasets,
            evidence,
            reasons,
            checkpoint,
        })
    }

    fn datasets(
        &mut self,
        ports: &[sdk::Port],
        queries: &BTreeMap<String, QuerySql>,
    ) -> Result<Vec<sdk::Dataset>> {
        ports
            .iter()
            .map(|port| {
                let query = queries.get(&port.name).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "model admitted output",
                    }
                    .build()
                })?;
                Ok(sdk::Dataset {
                    name: port.name.clone(),
                    batches: self.query(query, &port.schema)?,
                })
            })
            .collect()
    }

    pub(super) fn query(
        &mut self,
        query: &QuerySql,
        schema: &sdk::Schema,
    ) -> Result<Vec<sdk::RecordBatch>> {
        self.query_schema(query, Some(schema))
    }

    pub(super) fn query_schema(
        &mut self,
        query: &QuerySql,
        schema: Option<&sdk::Schema>,
    ) -> Result<Vec<sdk::RecordBatch>> {
        self.rows = 0;
        self.batches = 0;
        let now = u64::try_from(self.time_utc_ns).map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "model evaluation time",
            }
            .build()
        })?;
        let bound = query.bind_complete(now)?;
        let statement = crate::query::evaluation::QueryEvaluation::prepare(
            self.connection,
            &bound.sql,
            &bound.parameters,
            self.limits.max_rows,
            #[cfg(test)]
            None,
        )?;
        let actual = statement.schema();
        let schema = schema.unwrap_or(actual.as_ref());
        let empty = sdk::RecordBatch::new_empty(actual.clone());
        ModelSchema::normalize(empty, schema)?;
        let mut batches = Vec::new();
        while let Some(array) = statement.step().context(crate::AnalysisDatabaseSnafu {
            operation: "read model query",
        })? {
            self.control.check()?;
            let batch = ModelSchema::normalize(sdk::RecordBatch::from(array), schema)?;
            self.charge(&batch)?;
            batches.push(batch);
        }
        if batches.is_empty() {
            let batch = sdk::RecordBatch::new_empty(Arc::new(schema.clone()));
            self.charge(&batch)?;
            batches.push(batch);
        }
        Ok(batches)
    }

    pub(super) fn references(
        &mut self,
        query: &QuerySql,
        schema: &sdk::Schema,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let limit = self.limits.max_rows;
        self.limits.max_rows = self.limits.max_bytes / 16;
        let result = self.query(query, schema);
        self.limits.max_rows = limit;
        result
    }

    pub(super) fn owned(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.byte_limit {
            return crate::QueryLimitSnafu {
                resource: "model output ownership",
                limit: self.byte_limit,
            }
            .fail();
        }
        Ok(())
    }

    fn charge(&mut self, batch: &sdk::RecordBatch) -> Result<()> {
        let schema = batch.schema();
        let schema_bytes = schema
            .fields()
            .iter()
            .map(|field| field.size())
            .sum::<usize>()
            .saturating_add(
                schema
                    .metadata()
                    .iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum::<usize>(),
            );
        self.bytes = self
            .bytes
            .saturating_add(schema_bytes)
            .saturating_add(batch.get_array_memory_size())
            .saturating_add(std::mem::size_of::<sdk::RecordBatch>());
        self.rows = self.rows.saturating_add(batch.num_rows() as u64);
        self.batches = self.batches.saturating_add(1);
        if self.bytes > self.byte_limit
            || self.rows > self.limits.max_rows
            || self.batches > self.limits.max_batches
        {
            return crate::QueryLimitSnafu {
                resource: "model output",
                limit: self.byte_limit,
            }
            .fail();
        }
        Ok(())
    }
}
