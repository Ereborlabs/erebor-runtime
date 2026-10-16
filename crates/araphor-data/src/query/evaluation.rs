use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::datasource::MemTable;
use duckdb::core::LogicalTypeId;
use duckdb::types::{Value, ValueRef};
use snafu::ResultExt as _;

use super::engine::QueryEngine;
use super::input::InputRelations;
use super::values::QueryValues;
use super::{Column, QueryBinding, QueryLease, QueryOperation, QueryOwner};
use crate::{AnalysisReadControl, Result, StorePositionV1};

pub(super) struct EvaluationLimits {
    pub rows: usize,
    pub bytes: usize,
    pub summary_bytes: usize,
    pub operation: QueryOperation,
    pub complete: bool,
}

pub(super) struct EvaluationResult {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
    pub output_bytes: usize,
    pub limited: bool,
    pub scanned_through: StorePositionV1,
}

pub(super) struct QueryEvaluation;

impl QueryEvaluation {
    pub(super) fn run(
        owner: &QueryOwner,
        input: &InputRelations,
        binding: &QueryBinding,
        limits: EvaluationLimits,
        position: StorePositionV1,
        control: &AnalysisReadControl,
        lease: &QueryLease,
    ) -> Result<EvaluationResult> {
        let mut tables = BTreeMap::new();
        for (name, input) in &input.tables {
            control.check()?;
            let batches = input
                .batches
                .iter()
                .map(|batch| lease.retain_batch(batch))
                .collect::<Result<Vec<_>>>()?;
            #[cfg(test)]
            owner.test_arrays(&batches, lease);
            tables.insert(
                (*name).to_owned(),
                Arc::new(
                    MemTable::try_new(input.schema.clone(), vec![batches]).context(
                        crate::QueryEngineSnafu {
                            operation: "create query input",
                        },
                    )?,
                ),
            );
        }
        let fetch = limits.rows.saturating_add(1);
        let state = QueryEngine::state()?;
        let (plan, schema) = QueryEngine::plan(&state, binding, &tables, Some(fetch))?;
        let read = control.within(control.remaining()?)?;
        let retained = lease.clone();
        #[cfg(test)]
        let gate = owner
            .engine
            .scan_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let result = owner.engine.run(control, async move {
            let _retained = retained;
            let mut output = EvaluationResult::new(&schema, &limits, position)?;
            let kinds = schema
                .fields()
                .iter()
                .map(|field| QueryValues::logical_type(field.data_type()))
                .collect::<Result<Vec<_>>>()?;
            let mut stream = QueryEngine::stream(
                state,
                plan,
                #[cfg(test)]
                gate,
            )
            .await?;
            while let Some(batch) =
                std::future::poll_fn(|context| stream.as_mut().poll_next(context)).await
            {
                read.check()?;
                let batch = batch.context(crate::QueryEngineSnafu {
                    operation: "read client query stream",
                })?;
                let batch = sdk::RecordBatch::try_new_with_options(
                    schema.clone(),
                    batch.columns().to_vec(),
                    &sdk::arrow_array::RecordBatchOptions::new()
                        .with_row_count(Some(batch.num_rows())),
                )
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
                if output.push(&batch, &kinds, &limits, &read)? {
                    break;
                }
                tokio::task::yield_now().await;
            }
            drop(stream);
            output.finish(&limits)
        });
        #[cfg(test)]
        owner
            .engine
            .native_failed
            .store(result.is_err(), std::sync::atomic::Ordering::Release);
        result
    }
}

impl EvaluationLimits {
    fn check_output(&self, bytes: usize) -> Result<()> {
        if bytes > self.bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: self.bytes,
            }
            .fail();
        }
        Ok(())
    }
}

impl EvaluationResult {
    fn new(
        schema: &sdk::Schema,
        limits: &EvaluationLimits,
        position: StorePositionV1,
    ) -> Result<Self> {
        let columns = QueryValues::columns(schema)?;
        let mut output_bytes = limits.summary_bytes.saturating_add(
            columns
                .capacity()
                .saturating_mul(std::mem::size_of::<Column>()),
        );
        for column in &columns {
            output_bytes = output_bytes
                .saturating_add(column.name.capacity())
                .saturating_add(column.data_type.capacity());
        }
        limits.check_output(output_bytes)?;
        Ok(Self {
            columns,
            rows: Vec::new(),
            output_bytes,
            limited: false,
            scanned_through: position,
        })
    }

    fn push(
        &mut self,
        batch: &sdk::RecordBatch,
        kinds: &[LogicalTypeId],
        limits: &EvaluationLimits,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        control.check()?;
        for row in 0..batch.num_rows() {
            control.check()?;
            if self.rows.len() == limits.rows {
                self.limit_at(batch, row, limits.operation)?;
                return Ok(true);
            }
            let count = batch.num_columns();
            let mut row_bytes = count.saturating_mul(std::mem::size_of::<Value>());
            let descriptor = if self.rows.len() == self.rows.capacity() {
                std::mem::size_of::<Vec<Value>>()
            } else {
                0
            };
            if self
                .output_bytes
                .saturating_add(row_bytes)
                .saturating_add(descriptor)
                > limits.bytes
            {
                if self.rows.is_empty() {
                    limits.check_output(limits.bytes.saturating_add(1))?;
                }
                self.limit_at(batch, row, limits.operation)?;
                return Ok(true);
            }
            let mut values = Vec::with_capacity(count);
            for (array, kind) in batch.columns().iter().zip(kinds) {
                let value = QueryValues::value(array, row, *kind)?;
                let bytes = match &value {
                    ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                    _ => 0,
                };
                row_bytes = row_bytes.saturating_add(bytes);
                if self
                    .output_bytes
                    .saturating_add(row_bytes)
                    .saturating_add(descriptor)
                    > limits.bytes
                {
                    self.limited = true;
                    break;
                }
                values.push(value.to_owned());
            }
            if self.limited {
                if self.rows.is_empty() {
                    limits.check_output(limits.bytes.saturating_add(1))?;
                }
                self.limit_at(batch, row, limits.operation)?;
                return Ok(true);
            }
            let capacity = self.rows.capacity();
            self.rows.try_reserve_exact(1).map_err(|_| {
                crate::QueryLimitSnafu {
                    resource: "query output allocation",
                    limit: limits.bytes,
                }
                .build()
            })?;
            self.output_bytes = self.output_bytes.saturating_add(row_bytes).saturating_add(
                (self.rows.capacity() - capacity) * std::mem::size_of::<Vec<Value>>(),
            );
            limits.check_output(self.output_bytes)?;
            self.rows.push(values);
        }
        Ok(false)
    }

    fn finish(self, limits: &EvaluationLimits) -> Result<Self> {
        if self.limited && limits.complete && limits.operation == QueryOperation::Replace {
            return crate::QueryLimitSnafu {
                resource: "complete replacement output",
                limit: limits.bytes,
            }
            .fail();
        }
        Ok(self)
    }

    #[cfg(test)]
    fn from_batches(
        batches: &[sdk::RecordBatch],
        limits: EvaluationLimits,
        position: StorePositionV1,
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        let schema = batches
            .first()
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "query result schema",
                }
                .build()
            })?
            .schema();
        let kinds = schema
            .fields()
            .iter()
            .map(|field| QueryValues::logical_type(field.data_type()))
            .collect::<Result<Vec<_>>>()?;
        let mut output = Self::new(&schema, &limits, position)?;
        for batch in batches {
            if batch.schema() != schema {
                return crate::QueryInvalidSnafu {
                    field: "query result schema",
                }
                .fail();
            }
            if output.push(batch, &kinds, &limits, control)? {
                break;
            }
        }
        output.finish(&limits)
    }

    fn limit_at(
        &mut self,
        batch: &sdk::RecordBatch,
        row: usize,
        operation: QueryOperation,
    ) -> Result<()> {
        self.limited = true;
        if operation == QueryOperation::Append {
            self.scanned_through = Self::before_row(batch, row)?;
        }
        Ok(())
    }

    fn before_row(batch: &sdk::RecordBatch, row: usize) -> Result<StorePositionV1> {
        let invalid = || {
            crate::QueryInvalidSnafu {
                field: "append position",
            }
            .build()
        };
        let schema = batch.schema();
        let revision = schema
            .index_of("__araphor_commit_revision")
            .or_else(|_| schema.index_of("commit_revision"))
            .map_err(|_| invalid())?;
        let ordinal = schema
            .index_of("__araphor_ordinal")
            .or_else(|_| schema.index_of("ordinal"))
            .map_err(|_| invalid())?;
        let ValueRef::UBigInt(revision) =
            QueryValues::value(batch.column(revision), row, LogicalTypeId::UBigint)?
        else {
            return Err(invalid());
        };
        let ValueRef::UInt(ordinal) =
            QueryValues::value(batch.column(ordinal), row, LogicalTypeId::UInteger)?
        else {
            return Err(invalid());
        };
        match ordinal.checked_sub(1) {
            Some(ordinal) => Ok(StorePositionV1 {
                commit_revision: revision,
                ordinal,
            }),
            None => Ok(StorePositionV1 {
                commit_revision: revision.checked_sub(1).ok_or_else(invalid)?,
                ordinal: u32::MAX,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::array::{StringArray, UInt32Array, UInt64Array};

    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn batch(
        values: &[&str],
        revisions: Vec<u64>,
        ordinals: Vec<u32>,
    ) -> TestResult<sdk::RecordBatch> {
        Ok(sdk::RecordBatch::try_new(
            Arc::new(sdk::Schema::new(vec![
                sdk::Field::new("value", sdk::DataType::Utf8, false),
                sdk::Field::new("__araphor_commit_revision", sdk::DataType::UInt64, false),
                sdk::Field::new("__araphor_ordinal", sdk::DataType::UInt32, false),
            ])),
            vec![
                Arc::new(StringArray::from(values.to_vec())),
                Arc::new(UInt64Array::from(revisions)),
                Arc::new(UInt32Array::from(ordinals)),
            ],
        )?)
    }

    fn limits(rows: usize, bytes: usize, operation: QueryOperation) -> EvaluationLimits {
        EvaluationLimits {
            rows,
            bytes,
            summary_bytes: 41,
            operation,
            complete: false,
        }
    }

    #[test]
    fn arrow_output_bounds() -> TestResult {
        let batch = batch(&["first", &"x".repeat(1024)], vec![2, 3], vec![7, 0])?;
        let position = StorePositionV1 {
            commit_revision: 9,
            ordinal: 11,
        };
        let control = AnalysisReadControl::default();
        let first = EvaluationResult::from_batches(
            &[batch.slice(0, 1)],
            limits(2, usize::MAX, QueryOperation::Append),
            position,
            &control,
        )?;
        assert!(!first.limited);
        assert_eq!(
            first.rows,
            vec![vec![
                Value::Text("first".into()),
                Value::UBigInt(2),
                Value::UInt(7),
            ]],
        );
        for (rows, bytes) in [(1, usize::MAX), (2, first.output_bytes)] {
            let output = EvaluationResult::from_batches(
                &[batch.slice(0, 1), batch.slice(1, 1)],
                limits(rows, bytes, QueryOperation::Append),
                position,
                &control,
            )?;
            assert_eq!(output.rows, first.rows);
            assert_eq!(output.columns, first.columns);
            assert_eq!(output.output_bytes, first.output_bytes);
            assert!(output.limited);
            assert_eq!(
                output.scanned_through,
                StorePositionV1 {
                    commit_revision: 2,
                    ordinal: u32::MAX,
                },
            );
        }
        let empty = EvaluationResult::from_batches(
            &[batch.slice(0, 0)],
            limits(2, usize::MAX, QueryOperation::Append),
            position,
            &control,
        )?;
        assert_eq!(empty.columns, first.columns);
        assert!(empty.rows.is_empty());
        assert!(!empty.limited);
        assert_eq!(empty.scanned_through, position);
        assert!(matches!(
            EvaluationResult::from_batches(
                std::slice::from_ref(&batch),
                limits(2, first.output_bytes - 1, QueryOperation::Append),
                position,
                &control,
            ),
            Err(crate::Error::QueryLimit {
                resource: "query output bytes",
                ..
            }),
        ));
        let mut complete = limits(1, usize::MAX, QueryOperation::Replace);
        complete.complete = true;
        assert!(matches!(
            EvaluationResult::from_batches(&[batch], complete, position, &control),
            Err(crate::Error::QueryLimit {
                resource: "complete replacement output",
                ..
            }),
        ));
        Ok(())
    }

    #[test]
    fn arrow_append_positions() -> TestResult {
        let original = batch(&["value"], vec![5], vec![7])?;
        let schema = Arc::new(sdk::Schema::new(vec![
            sdk::Field::new("value", sdk::DataType::Utf8, false),
            sdk::Field::new("commit_revision", sdk::DataType::UInt64, false),
            sdk::Field::new("ordinal", sdk::DataType::UInt32, false),
        ]));
        let public = sdk::RecordBatch::try_new(schema, original.columns().to_vec())?;
        for batch in [&original, &public] {
            assert_eq!(
                EvaluationResult::before_row(batch, 0)?,
                StorePositionV1 {
                    commit_revision: 5,
                    ordinal: 6,
                },
            );
        }
        assert!(EvaluationResult::before_row(&batch(&["value"], vec![0], vec![0])?, 0).is_err());
        let wrong = sdk::RecordBatch::try_new(
            Arc::new(sdk::Schema::new(vec![
                sdk::Field::new("commit_revision", sdk::DataType::UInt64, true),
                sdk::Field::new("ordinal", sdk::DataType::UInt64, false),
            ])),
            vec![
                Arc::new(UInt64Array::from(vec![Some(5)])),
                Arc::new(UInt64Array::from(vec![7])),
            ],
        )?;
        assert!(EvaluationResult::before_row(&wrong, 0).is_err());
        let null = sdk::RecordBatch::try_new(
            Arc::new(sdk::Schema::new(vec![
                sdk::Field::new("commit_revision", sdk::DataType::UInt64, true),
                sdk::Field::new("ordinal", sdk::DataType::UInt32, false),
            ])),
            vec![
                Arc::new(UInt64Array::from(vec![None])),
                Arc::new(UInt32Array::from(vec![7])),
            ],
        )?;
        assert!(EvaluationResult::before_row(&null, 0).is_err());
        Ok(())
    }

    #[test]
    fn client_stream_output_exceeds_source_budget() -> TestResult {
        let fixture = super::super::tests::QueryFixture::new()?;
        let owner = fixture.owner(crate::QueryLimits {
            input_bytes: 64 * 1024,
            ..Default::default()
        })?;
        let text = "x".repeat(40 * 1024);
        let binding = QueryBinding::trusted(
            "SELECT ? || ? AS value".into(),
            vec![Value::Text(text.clone()), Value::Text(text.clone())],
            0,
        )?;
        let lease = owner.budget.evaluate([1; 16])?;
        let output = QueryEvaluation::run(
            &owner,
            &InputRelations::default(),
            &binding,
            limits(2, 1024 * 1024, QueryOperation::Replace),
            StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            &AnalysisReadControl::default(),
            &lease,
        )?;
        assert_eq!(output.rows, vec![vec![Value::Text(text.repeat(2))]]);
        assert!(!output.limited);
        Ok(())
    }

    #[test]
    fn client_stream_empty_result_keeps_public_columns() -> TestResult {
        let fixture = super::super::tests::QueryFixture::new()?;
        let owner = fixture.owner(crate::QueryLimits::default())?;
        let binding = QueryBinding::trusted(
            "SELECT CAST(7 AS BIGINT) AS \"Mixed Name\" WHERE FALSE".into(),
            Vec::new(),
            0,
        )?;
        let lease = owner.budget.evaluate([1; 16])?;
        let output = QueryEvaluation::run(
            &owner,
            &InputRelations::default(),
            &binding,
            limits(2, 1024 * 1024, QueryOperation::Replace),
            StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            },
            &AnalysisReadControl::default(),
            &lease,
        )?;
        assert_eq!(
            output.columns,
            vec![Column {
                name: "Mixed Name".into(),
                data_type: "Bigint".into()
            }]
        );
        assert!(output.rows.is_empty());
        assert!(!output.limited);
        Ok(())
    }
}
