use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use super::{operation::ModelRun, AdmittedExport, AdmittedModel, SqlModelOutputV1, SqlModelV1};
use crate::Result;

impl ModelRun<'_> {
    pub fn evaluate_model(
        self,
        package: &sdk::Package,
        program: &SqlModelV1,
        evaluation: &sdk::Evaluation,
    ) -> Result<SqlModelOutputV1> {
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model export",
                }
                .build()
            })?;
        let admitted = AdmittedModel::admit(self.owner, program, model)?;
        self.evaluate_program(package, &admitted, evaluation)
    }

    pub(crate) fn evaluate_admitted(
        self,
        package: &sdk::Package,
        admitted: &AdmittedExport,
        evaluation: &sdk::Evaluation,
    ) -> Result<SqlModelOutputV1> {
        let admitted = admitted.model.as_ref().ok_or_else(|| {
            crate::ModelInvalidSnafu {
                field: "model admitted program",
            }
            .build()
        })?;
        self.evaluate_program(package, admitted, evaluation)
    }

    fn evaluate_program(
        mut self,
        package: &sdk::Package,
        admitted: &AdmittedModel,
        evaluation: &sdk::Evaluation,
    ) -> Result<SqlModelOutputV1> {
        self.check_evaluation(evaluation)?;
        let checked = package
            .check_evaluation(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let model = checked.model();
        let requested =
            evaluation
                .context
                .limits
                .max_bytes
                .saturating_add(if model.checkpoint.is_some() {
                    evaluation.context.limits.max_checkpoint_bytes
                } else {
                    0
                });
        self.byte_limit = usize::try_from(requested)
            .unwrap_or(usize::MAX)
            .min(self.owner.limits().output_capacity);
        self.output_memory = Some(self.memory.reserve_output(0)?);
        self.control = self.control.within(self.owner.limits().evaluate_timeout)?;
        let now = u64::try_from(evaluation.context.time_utc_ns).map_err(|_| {
            crate::ModelInvalidSnafu {
                field: "model evaluation time",
            }
            .build()
        })?;
        self.start(crate::AnalysisSelectionV1::tenant(self.tenant()), now)?;
        self.limits = evaluation.context.limits;
        self.limits.max_bytes = self.limits.max_bytes.min(self.byte_limit as u64);
        self.limits.max_checkpoint_bytes =
            self.limits.max_checkpoint_bytes.min(self.byte_limit as u64);
        self.register(model, evaluation)?;
        let output = self.evaluate(model, admitted)?;
        checked
            .validate_output(&output)
            .context(crate::AnalysisContractSnafu)?;
        if SqlModelOutputV1::owned_bytes(&output, self.bytes) > self.byte_limit {
            return crate::ModelLimitSnafu {
                resource: "query output bytes",
                limit: self.byte_limit,
            }
            .fail();
        }
        self.control.check()?;
        if let Some(inputs) = &self.inputs {
            inputs.check(self.owner, &self.control)?;
        }
        let reservation = self.output_memory.take().ok_or_else(|| {
            crate::ModelInvalidSnafu {
                field: "model output reservation",
            }
            .build()
        })?;
        SqlModelOutputV1::retain(output, &self.memory, reservation)
    }

    pub(super) fn check_evaluation(&self, evaluation: &sdk::Evaluation) -> Result<()> {
        if let Some(inputs) = &self.inputs {
            inputs.check(self.owner, &self.control)?;
        }
        if evaluation.allocated_bytes() > self.owner.limits().input_bytes {
            return crate::ModelLimitSnafu {
                resource: "analysis input memory",
                limit: self.owner.limits().input_bytes,
            }
            .fail();
        }
        Ok(())
    }

    fn evaluate(&mut self, model: &sdk::Model, admitted: &AdmittedModel) -> Result<sdk::Output> {
        let datasets = self.datasets(&model.outputs, &admitted.outputs)?;
        for (port, data) in model.outputs.iter().zip(&datasets) {
            let name = format!("output_{}", port.name);
            if admitted.reads_output(&name)? {
                self.table(&name, &port.schema, &data.batches)?;
            }
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
        let reasons = self.reasons(model, &admitted.reasons)?;
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
        queries: &[Arc<LogicalPlan>],
    ) -> Result<Vec<sdk::Dataset>> {
        if ports.len() != queries.len() {
            return crate::ModelInvalidSnafu {
                field: "model admitted output",
            }
            .fail();
        }
        let limits = self.limits;
        let mut remaining = limits;
        let byte_limit = self.byte_limit;
        let limit = || {
            crate::ModelLimitSnafu {
                resource: "model output",
                limit: byte_limit,
            }
            .build()
        };
        let result = ports
            .iter()
            .zip(queries)
            .map(|(port, query)| {
                remaining.max_bytes = remaining
                    .max_bytes
                    .checked_sub(port.name.len() as u64)
                    .ok_or_else(limit)?;
                self.limits = remaining;
                let batches = self.query(query, Some(&port.schema))?;
                let bytes = batches.iter().fold(0u64, |bytes, batch| {
                    bytes.saturating_add(batch.get_array_memory_size() as u64)
                });
                remaining.max_bytes = remaining.max_bytes.checked_sub(bytes).ok_or_else(limit)?;
                remaining.max_rows = remaining
                    .max_rows
                    .checked_sub(self.rows)
                    .ok_or_else(limit)?;
                remaining.max_batches = remaining
                    .max_batches
                    .checked_sub(self.batches)
                    .ok_or_else(limit)?;
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
        plan: &Arc<LogicalPlan>,
        schema: Option<&sdk::Schema>,
    ) -> Result<Vec<sdk::RecordBatch>> {
        self.control.check()?;
        let capacity = self
            .byte_limit
            .saturating_sub(self.bytes)
            .min(self.limits.max_bytes as usize);
        let rows = usize::try_from(self.limits.max_rows).map_err(|_| {
            crate::ModelInvalidSnafu {
                field: "model output row limit",
            }
            .build()
        })?;
        if capacity == 0 {
            return crate::ModelLimitSnafu {
                resource: "model output bytes",
                limit: self.byte_limit,
            }
            .fail();
        }
        self.session()?.set_output(rows.max(1), capacity)?;
        let batches = self.session()?.execute_local(Arc::clone(plan))?;
        let mut owned = 0usize;
        let mut metadata = self
            .output_memory
            .as_ref()
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model output reservation",
                }
                .build()
            })?
            .size();
        let mut normalized = Vec::with_capacity(batches.len().max(1));
        for batch in batches {
            self.control.check()?;
            let conversion = schema
                .map_or(Ok(0usize), |schema| {
                    sdk::Dataset::conversion_bytes(&batch, schema)
                })
                .context(crate::AnalysisContractSnafu)?;
            let headers = std::mem::size_of::<sdk::RecordBatch>()
                + batch.num_columns() * std::mem::size_of::<sdk::arrow_array::ArrayRef>();
            self.output_memory
                .as_ref()
                .ok_or_else(|| {
                    crate::ModelInvalidSnafu {
                        field: "model output reservation",
                    }
                    .build()
                })?
                .try_grow(conversion + headers)?;
            let batch = match schema {
                Some(schema) => sdk::Dataset::normalize_batch(batch, Arc::new(schema.clone()))
                    .context(crate::AnalysisContractSnafu)?,
                None => batch,
            };
            owned = owned
                .saturating_add(batch.get_array_memory_size())
                .saturating_add(headers);
            if owned > capacity {
                return crate::ModelLimitSnafu {
                    resource: "model output",
                    limit: self.byte_limit,
                }
                .fail();
            }
            let memory = self.output_memory.as_ref().ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model output reservation",
                }
                .build()
            })?;
            self.memory.retain_output(&batch, memory)?;
            metadata = metadata.saturating_add(headers);
            memory.try_resize(metadata)?;
            normalized.push(batch);
        }
        if normalized.is_empty() {
            let schema = schema.map_or_else(
                || Arc::new(plan.schema().as_arrow().clone()),
                |schema| Arc::new(schema.clone()),
            );
            normalized.push(sdk::RecordBatch::new_empty(schema));
        }
        self.bytes = self.bytes.saturating_add(owned);
        self.rows = normalized.iter().map(|batch| batch.num_rows() as u64).sum();
        if self.rows > self.limits.max_rows {
            return crate::ModelLimitSnafu {
                resource: "model output rows",
                limit: rows,
            }
            .fail();
        }
        self.batches = u32::try_from(normalized.len()).map_err(|_| {
            crate::ModelLimitSnafu {
                resource: "model output batches",
                limit: self.limits.max_batches as usize,
            }
            .build()
        })?;
        if self.batches > self.limits.max_batches {
            return crate::ModelLimitSnafu {
                resource: "model output batches",
                limit: self.limits.max_batches as usize,
            }
            .fail();
        }
        Ok(normalized)
    }

    pub(super) fn references(
        &mut self,
        plan: &Arc<LogicalPlan>,
        schema: &sdk::Schema,
    ) -> Result<Vec<sdk::RecordBatch>> {
        let limit = self.limits.max_rows;
        self.limits.max_rows = self.limits.max_bytes / 16;
        let result = self.query(plan, Some(schema));
        self.limits.max_rows = limit;
        result
    }

    pub(super) fn owned(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.byte_limit {
            return crate::ModelLimitSnafu {
                resource: "model output ownership",
                limit: self.byte_limit,
            }
            .fail();
        }
        self.output_memory
            .as_ref()
            .ok_or_else(|| {
                crate::ModelInvalidSnafu {
                    field: "model output reservation",
                }
                .build()
            })?
            .try_grow(bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use araphor_analysis_sdk as sdk;
    use sdk::arrow_array::{StringArray, UInt64Array};

    use super::*;
    use crate::testing::QueryFixture;
    use crate::{AnalysisReadControl, Limits};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn evaluation(model: &sdk::Model, inputs: Vec<sdk::Input>) -> sdk::Evaluation {
        sdk::Evaluation {
            export: model.name.clone(),
            inputs,
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "native-output".into(),
                time_utc_ns: 1_000,
                seed: None,
                limits: model.limits,
            },
        }
    }

    #[test]
    fn output_alias_capacity() -> TestResult {
        let fixture = QueryFixture::new()?;
        let engine = fixture.owner(Limits::default())?;
        let port = sdk::Port::new(
            "rows",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        );
        let model = sdk::Model::new("evaluate", Vec::new(), vec![port]);
        let package = sdk::Package::new("retained-output", "1", vec![model.clone()]);
        let program = SqlModelV1 {
            outputs: BTreeMap::from([("rows".into(), "SELECT 7::BIGINT UNSIGNED AS value".into())]),
            ..Default::default()
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let output = ModelRun::new(&engine, [1; 16], &control)?.evaluate_model(
            &package,
            &program,
            &evaluation(&model, Vec::new()),
        )?;
        let alias = output.output.datasets[0].batches[0].column(0).slice(0, 1);
        drop(output);
        assert!(engine
            .memory()
            .reserve_output(engine.limits().output_capacity)
            .is_err());
        drop(engine.reserve_evaluation([1; 16])?);
        assert_eq!(
            alias
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("output array")?
                .value(0),
            7
        );
        drop(alias);
        drop(
            engine
                .memory()
                .reserve_output(engine.limits().output_capacity)?,
        );
        Ok(())
    }

    #[test]
    fn empty_output_retains_schema() -> TestResult {
        let fixture = QueryFixture::new()?;
        let engine = fixture.owner(Limits::default())?;
        let schema = sdk::Schema::new_with_metadata(
            vec![sdk::Field::new("value", sdk::DataType::Utf8, false)],
            std::collections::HashMap::from([("contract".into(), "empty-output".into())]),
        );
        let model = sdk::Model::new(
            "evaluate",
            Vec::new(),
            vec![sdk::Port::new("rows", schema.clone())],
        );
        let package = sdk::Package::new("empty-output", "1", vec![model.clone()]);
        let program = SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT 'value' AS value WHERE false".into(),
            )]),
            ..Default::default()
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let output = ModelRun::new(&engine, [1; 16], &control)?.evaluate_model(
            &package,
            &program,
            &evaluation(&model, Vec::new()),
        )?;
        let batch = &output.output.datasets[0].batches[0];
        assert_eq!(batch.num_rows(), 0);
        assert_eq!(batch.schema().as_ref(), &schema);
        assert!(batch.column(0).as_any().is::<StringArray>());
        assert!(engine
            .memory()
            .reserve_output(engine.limits().output_capacity)
            .is_err());
        drop(output);
        drop(
            engine
                .memory()
                .reserve_output(engine.limits().output_capacity)?,
        );
        Ok(())
    }

    #[test]
    fn fixed_binary_preflight_rejects() -> TestResult {
        let fixture = QueryFixture::new()?;
        let capacity = 64 * 1024;
        let engine = fixture.owner(Limits {
            output_capacity: capacity,
            output_bytes: capacity,
            ..Default::default()
        })?;
        let input_schema =
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Binary, true)]);
        let value = vec![7; 1024];
        let mut values = vec![None; 200];
        values[0] = Some(value.as_slice());
        let input = sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(input_schema.clone()),
                    vec![Arc::new(sdk::arrow_array::BinaryArray::from(values))],
                )?],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        };
        let mut model = sdk::Model::new(
            "evaluate",
            vec![sdk::Port::new("input", input_schema)],
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new(
                    "value",
                    sdk::DataType::FixedSizeBinary(1024),
                    true,
                )]),
            )],
        );
        model.limits.max_bytes = capacity as u64;
        let package = sdk::Package::new("fixed-conversion", "1", vec![model.clone()]);
        let program = SqlModelV1 {
            outputs: BTreeMap::from([("rows".into(), "SELECT value FROM input".into())]),
            ..Default::default()
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let result = ModelRun::new(&engine, [1; 16], &control)?.evaluate_model(
            &package,
            &program,
            &evaluation(&model, vec![input]),
        );
        assert!(matches!(
            result,
            Err(crate::Error::Query {
                source: araphor_query::Error::Sql {
                    source: araphor_query::datafusion::common::DataFusionError::ResourcesExhausted(
                        _
                    ),
                },
            })
        ));
        drop(engine.memory().reserve_output(capacity)?);
        drop(engine.reserve_evaluation([1; 16])?);
        Ok(())
    }

    #[test]
    fn normalized_output_uses_capacity() -> TestResult {
        let fixture = QueryFixture::new()?;
        let capacity = 64 * 1024;
        let engine = fixture.owner(Limits {
            output_capacity: capacity,
            output_bytes: capacity,
            ..Default::default()
        })?;
        let input_schema =
            sdk::Schema::new(vec![sdk::Field::new("id", sdk::DataType::UInt64, false)]);
        let input = sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(input_schema.clone()),
                    vec![Arc::new(UInt64Array::from_iter_values(0..200))],
                )?],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        };
        let mut model = sdk::Model::new(
            "evaluate",
            vec![sdk::Port::new("input", input_schema)],
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Utf8, false)]),
            )],
        );
        model.limits.max_bytes = capacity as u64;
        let package = sdk::Package::new("conversion-limit", "1", vec![model.clone()]);
        let program = SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                format!("SELECT '{}' AS value FROM input", "x".repeat(1024)),
            )]),
            ..Default::default()
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let result = ModelRun::new(&engine, [1; 16], &control)?.evaluate_model(
            &package,
            &program,
            &evaluation(&model, vec![input]),
        );
        assert!(result.is_err());
        drop(engine.memory().reserve_output(capacity)?);
        drop(engine.reserve_evaluation([1; 16])?);
        Ok(())
    }
}
