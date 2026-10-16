use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::arrow::array::{RecordBatchOptions, UInt64Array};
use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;
use snafu::ResultExt as _;

use super::{schema::ModelSchema, AdmittedModel, SqlModelV1};
use crate::query::{budget::QueryLease, engine::QueryEngine};
use crate::{AnalysisReadControl, QueryLimits, QueryOwner, QuerySql, Result};

pub(super) struct ModelExecution<'a> {
    owner: &'a QueryOwner,
    pub(super) state: &'a SessionState,
    pub(super) lease: &'a QueryLease,
    pub(super) tables: BTreeMap<String, Arc<MemTable>>,
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
        owner: &'a QueryOwner,
        state: &'a SessionState,
        control: &'a AnalysisReadControl,
        lease: &'a QueryLease,
        time_utc_ns: i64,
        mut limits: sdk::Limits,
        host: &QueryLimits,
    ) -> Self {
        limits.max_bytes = limits.max_bytes.min(host.output_capacity as u64);
        limits.max_checkpoint_bytes = limits.max_checkpoint_bytes.min(host.output_capacity as u64);
        Self {
            owner,
            state,
            lease,
            tables: BTreeMap::new(),
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
            self.owned(data.batches.iter().fold(0_usize, |bytes, batch| {
                bytes
                    .saturating_add(QueryLease::batch_overhead(batch))
                    .saturating_add(QueryLease::index_overhead(batch.num_rows()))
            }))?;
            self.table(
                &format!("output_{}", port.name),
                &port.schema,
                &data.batches,
            )?;
        }
        let output_limit = self.limits.max_bytes;
        self.limits.max_bytes = self.limits.max_checkpoint_bytes;
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
            .transpose();
        self.limits.max_bytes = output_limit;
        let checkpoint = checkpoint?;
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
        let limits = self.limits;
        let mut remaining = limits;
        let byte_limit = self.byte_limit;
        let limit = || {
            crate::QueryLimitSnafu {
                resource: "model output",
                limit: byte_limit,
            }
            .build()
        };
        let result = ports
            .iter()
            .map(|port| {
                let query = queries.get(&port.name).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "model admitted output",
                    }
                    .build()
                })?;
                remaining.max_bytes = remaining
                    .max_bytes
                    .checked_sub(port.name.len() as u64)
                    .ok_or_else(limit)?;
                self.limits = remaining;
                let batches = self.query(query, &port.schema)?;
                let bytes = batches.iter().fold(0_u64, |bytes, batch| {
                    bytes.saturating_add(batch.get_array_memory_size() as u64)
                });
                remaining.max_bytes = remaining.max_bytes.checked_sub(bytes).ok_or_else(limit)?;
                remaining.max_rows -= self.rows;
                remaining.max_batches -= self.batches;
                Ok(sdk::Dataset {
                    name: port.name.clone(),
                    batches,
                })
            })
            .collect();
        self.limits = limits;
        result
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
        let limits = sdk::Limits {
            max_bytes: self
                .limits
                .max_bytes
                .min(self.byte_limit.saturating_sub(self.bytes) as u64),
            ..self.limits
        };
        let (plan, actual) = QueryEngine::plan(self.state, &bound, &self.tables, None)?;
        let schema = schema.map(|schema| Arc::new(schema.clone()));
        let state = self.state.clone();
        let lease = self.lease.clone();
        let control = self.control.within(self.control.remaining()?)?;
        let capacity = self.byte_limit.saturating_sub(self.bytes);
        let byte_limit = self.byte_limit;
        #[cfg(test)]
        let gate = self
            .owner
            .engine
            .scan_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let (batches, rows, bytes) = self.owner.engine.run(self.control, async move {
            let _retained = lease;
            let mut stream = QueryEngine::stream(
                state,
                plan,
                #[cfg(test)]
                gate,
            )
            .await?;
            let schema = schema.unwrap_or_else(|| actual.clone());
            let mut batches = Vec::new();
            let mut rows = 0u64;
            let mut raw_bytes = 0usize;
            let mut bytes = 0usize;
            loop {
                let next = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
                control.check()?;
                let empty = next.is_none();
                let batch = match next {
                    Some(batch) => batch.context(crate::QueryEngineSnafu {
                        operation: "read query stream",
                    })?,
                    None if batches.is_empty() => sdk::RecordBatch::new_empty(actual.clone()),
                    None => break,
                };
                rows = rows.saturating_add(batch.num_rows() as u64);
                if !empty
                    && (rows > limits.max_rows || batches.len() >= limits.max_batches as usize)
                {
                    return crate::QueryLimitSnafu {
                        resource: "model output",
                        limit: limits.max_bytes as usize,
                    }
                    .fail();
                }
                let mut batch = sdk::RecordBatch::try_new_with_options(
                    actual.clone(),
                    batch.columns().to_vec(),
                    &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
                )
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
                if raw_bytes.saturating_add(QueryEngine::batch_bytes(&batch))
                    > limits.max_bytes as usize
                {
                    let indices = UInt64Array::from_iter_values(0..batch.num_rows() as u64);
                    let columns = batch
                        .columns()
                        .iter()
                        .map(|array| {
                            datafusion::arrow::compute::take(array.as_ref(), &indices, None)
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(sdk::Error::from)
                        .context(crate::AnalysisContractSnafu)?;
                    batch = sdk::RecordBatch::try_new_with_options(
                        actual.clone(),
                        columns,
                        &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
                    )
                    .map_err(sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)?;
                }
                raw_bytes = raw_bytes.saturating_add(QueryEngine::batch_bytes(&batch));
                if raw_bytes > limits.max_bytes as usize {
                    return crate::QueryLimitSnafu {
                        resource: "model output",
                        limit: limits.max_bytes as usize,
                    }
                    .fail();
                }
                let batch = ModelSchema::normalize(batch, schema.clone())?;
                bytes = bytes.saturating_add(QueryEngine::batch_bytes(&batch));
                if bytes > capacity || (empty && limits.max_batches == 0) {
                    return crate::QueryLimitSnafu {
                        resource: "model output",
                        limit: byte_limit,
                    }
                    .fail();
                }
                batches.push(batch);
                if empty {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok((batches, rows, bytes))
        })?;
        self.bytes = self.bytes.saturating_add(bytes);
        self.rows = rows;
        self.batches = batches.len() as u32;
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
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::query::{engine::QueryEngine, tests::QueryFixture};

    use super::*;

    #[test]
    fn output_indices_use_reserved_bytes(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = QueryFixture::new()?;
        let owner = fixture.owner(QueryLimits {
            evaluate_timeout: Duration::from_secs(30),
            ..Default::default()
        })?;
        let port = sdk::Port::new(
            "rows",
            sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::Boolean,
                false,
            )]),
        );
        let mut model = sdk::Model::new("evaluate", Vec::new(), vec![port.clone()]);
        let program = SqlModelV1 {
            outputs: BTreeMap::from([("rows".into(), "SELECT true AS value".into())]),
            ..Default::default()
        };
        let admitted = program.admit(&model)?;
        let state = QueryEngine::state()?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let lease = owner.budget.model([1; 16], owner.limits.output_capacity)?;
        let mut probe = ModelExecution::new(
            &owner,
            &state,
            &control,
            &lease,
            100,
            model.limits,
            &owner.limits,
        );
        let batches = probe.query(&admitted.outputs["rows"], &port.schema)?;
        assert_eq!(probe.rows, 1);
        let capacity = probe.bytes() + std::mem::size_of::<u64>() - 1;
        drop(probe);
        drop(batches);
        drop(lease);
        model.limits.max_bytes = capacity as u64;
        let evaluation = sdk::Evaluation {
            export: model.name.clone(),
            inputs: Vec::new(),
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "index-budget".into(),
                time_utc_ns: 100,
                seed: None,
                limits: model.limits,
            },
        };
        let package = sdk::Package::new("index-budget", "1", vec![model]);
        assert!(matches!(
            owner.evaluate_model([1; 16], &package, &program, &evaluation, &control),
            Err(crate::Error::QueryLimit {
                resource: "model output ownership",
                limit,
                ..
            }) if limit == capacity,
        ));
        assert_eq!(owner.input_charge(), 0);
        drop(owner.budget.output(owner.limits.output_capacity)?);
        Ok(())
    }

    #[test]
    fn empty_output_retains_schema(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = QueryFixture::new()?;
        let owner = fixture.owner(QueryLimits::default())?;
        let schema = sdk::Schema::new_with_metadata(
            vec![sdk::Field::new("value", sdk::DataType::Boolean, false)],
            std::collections::HashMap::from([("owner".into(), "model".into())]),
        );
        let state = QueryEngine::state()?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
        let lease = owner.budget.model([1; 16], owner.limits.output_capacity)?;
        let mut executor = ModelExecution::new(
            &owner,
            &state,
            &control,
            &lease,
            100,
            sdk::Limits::default(),
            &owner.limits,
        );
        let query = QuerySql::admit_relations("SELECT true AS value WHERE false", BTreeMap::new())?;
        let batches = executor.query(&query, &schema)?;
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 0);
        assert_eq!(batches[0].schema().as_ref(), &schema);
        assert_eq!(executor.rows, 0);
        assert_eq!(executor.batches, 1);
        let empty_bytes = executor.bytes();
        assert_eq!(empty_bytes, QueryEngine::batch_bytes(&batches[0]));
        let query = QuerySql::admit_relations("SELECT true AS value", BTreeMap::new())?;
        let batches = executor.query(&query, &schema)?;
        assert_eq!(executor.rows, 1);
        assert_eq!(executor.batches, 1);
        assert_eq!(
            executor.bytes(),
            empty_bytes + QueryEngine::batch_bytes(&batches[0]),
        );
        Ok(())
    }

    #[test]
    fn normalized_output_uses_capacity(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = QueryFixture::new()?;
        let owner = fixture.owner(QueryLimits::default())?;
        let state = QueryEngine::state()?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
        let lease = owner.budget.model([1; 16], owner.limits.output_capacity)?;
        let schema = sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::Boolean,
            false,
        )]);
        let query = QuerySql::admit_relations("SELECT true AS value", BTreeMap::new())?;
        let mut probe = ModelExecution::new(
            &owner,
            &state,
            &control,
            &lease,
            100,
            sdk::Limits::default(),
            &owner.limits,
        );
        let batches = probe.query(&query, &schema)?;
        let capacity = probe.bytes();
        drop(batches);
        drop(probe);
        let schema = schema.with_metadata(std::collections::HashMap::from([(
            "owner".into(),
            "x".repeat(capacity),
        )]));
        let host = QueryLimits {
            output_capacity: capacity,
            ..owner.limits.clone()
        };
        for sql in ["SELECT true AS value", "SELECT true AS value WHERE false"] {
            let mut executor = ModelExecution::new(
                &owner,
                &state,
                &control,
                &lease,
                100,
                sdk::Limits::default(),
                &host,
            );
            let query = QuerySql::admit_relations(sql, BTreeMap::new())?;
            assert!(matches!(
                executor.query(&query, &schema),
                Err(crate::Error::QueryLimit { resource: "model output", limit, .. })
                    if limit == capacity,
            ));
        }
        Ok(())
    }
}
