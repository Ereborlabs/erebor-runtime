use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{budget::QueryLease, evaluation::QueryEvaluation, QueryOwner, QuerySql};
use crate::{AnalysisReadControl, Result};

mod arrays;
mod component;
mod datasets;
mod execute;
mod guards;
mod input;
mod operation;
mod output;
pub(crate) use operation::SqlOperation;
mod parameters;
mod projection;
mod schema;
mod source;
pub use datasets::SqlDatasetOutputV1;
pub use source::{SqlModelInputRequestV1, SqlModelInputV1};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlModelV1 {
    pub outputs: BTreeMap<String, String>,
    pub checkpoint: BTreeMap<String, String>,
    pub evidence: Option<String>,
    pub reasons: Vec<SqlReasonV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlReasonV1 {
    pub output: String,
    pub code: String,
    pub sql: String,
}

pub struct SqlModelOutputV1 {
    pub output: sdk::Output,
    _lease: QueryLease,
}

impl SqlModelOutputV1 {
    pub(crate) fn into_parts(self) -> (sdk::Output, QueryLease) {
        (self.output, self._lease)
    }
}

impl QueryOwner {
    pub(crate) fn retain_analysis_input(&self, bytes: usize) -> Result<QueryLease> {
        self.budget.retained_input(bytes)
    }

    pub(crate) fn check_analysis_input(&self, evaluation: &sdk::Evaluation) -> Result<()> {
        if evaluation.allocated_bytes() > self.limits.input_bytes {
            return crate::QueryLimitSnafu {
                resource: "analysis input memory",
                limit: self.limits.input_bytes,
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn component_limits(&self, mut limits: sdk::Limits) -> sdk::Limits {
        limits.max_bytes = limits.max_bytes.min(self.limits.input_bytes as u64);
        crate::package::wasm::WasmExecution::limits(limits, &self.limits.wasm)
    }

    pub fn admit_model(model: &sdk::Model, program: &SqlModelV1) -> Result<()> {
        program.admit(model).map(|_| ())
    }

    pub fn evaluate_model(
        &self,
        tenant: [u8; 16],
        package: &sdk::Package,
        program: &SqlModelV1,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model export",
                }
                .build()
            })?;
        let admitted = program.admit(model)?;
        self.evaluate_analysis(tenant, package, evaluation, control, |control, host| {
            let connection = QueryEvaluation::connection()?;
            let mut executor =
                execute::ModelExecution::new(&connection, control, evaluation, host)?;
            let output = control.query_run(&connection, || {
                executor.register(model)?;
                executor.evaluate(model, program, admitted)
            })?;
            let bytes = executor.bytes();
            drop(connection);
            Ok((output, bytes))
        })
    }

    pub(crate) fn evaluate_analysis(
        &self,
        tenant: [u8; 16],
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        execute: impl FnOnce(&AnalysisReadControl, &super::QueryLimits) -> Result<(sdk::Output, usize)>,
    ) -> Result<SqlModelOutputV1> {
        self.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| self.budget.model(tenant, capacity),
            |control, host, _lease| execute(control, host),
        )
    }

    fn evaluate_model_reserved(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        reserve: impl FnOnce(usize) -> Result<QueryLease>,
        execute: impl FnOnce(
            &AnalysisReadControl,
            &super::QueryLimits,
            &mut QueryLease,
        ) -> Result<(sdk::Output, usize)>,
    ) -> Result<SqlModelOutputV1> {
        self.check_analysis_input(evaluation)?;
        package
            .validate_evaluation(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "model export",
                }
                .build()
            })?;
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
        let capacity = (requested as usize).min(self.limits.output_capacity);
        let mut lease = reserve(capacity)?;
        let control = control.within(self.limits.evaluate_timeout)?;
        let host = super::QueryLimits {
            output_capacity: capacity,
            ..self.limits.clone()
        };
        let (output, bytes) = execute(&control, &host, &mut lease)?;
        package
            .validate_output(evaluation, &output)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        Ok(SqlModelOutputV1 {
            output,
            _lease: lease.retained_output(bytes)?,
        })
    }
}

struct AdmittedModel {
    outputs: BTreeMap<String, QuerySql>,
    checkpoint: BTreeMap<String, QuerySql>,
    evidence: Option<QuerySql>,
    reasons: Vec<QuerySql>,
}

impl SqlModelV1 {
    pub(crate) fn uses_clock(&self, model: &sdk::Model) -> Result<bool> {
        let admitted = self.admit(model)?;
        Ok(admitted
            .outputs
            .values()
            .chain(admitted.checkpoint.values())
            .chain(admitted.evidence.iter())
            .chain(admitted.reasons.iter())
            .any(QuerySql::uses_clock))
    }

    fn admit(&self, model: &sdk::Model) -> Result<AdmittedModel> {
        let mut relations = schema::ModelSchema::relations(model)?;
        let outputs = Self::queries(&model.outputs, &self.outputs, &relations)?;
        for port in &model.outputs {
            schema::ModelSchema::relation(
                &mut relations,
                &format!("output_{}", port.name),
                &port.schema,
            )?;
        }
        let checkpoint = Self::queries(
            model
                .checkpoint
                .as_ref()
                .map_or(&[], |spec| spec.datasets.as_slice()),
            &self.checkpoint,
            &relations,
        )?;
        let evidence = self
            .evidence
            .as_ref()
            .map(|sql| QuerySql::admit_relations(sql, relations.clone()))
            .transpose()?;
        if self.reasons.len() > 128 {
            return crate::QueryInvalidSnafu {
                field: "model reason queries",
            }
            .fail();
        }
        let mut reasons = Vec::new();
        for reason in &self.reasons {
            if !model.outputs.iter().any(|port| port.name == reason.output)
                || !model.reasons.iter().any(|spec| spec.code == reason.code)
            {
                return crate::QueryInvalidSnafu {
                    field: "model reason binding",
                }
                .fail();
            }
            reasons.push(QuerySql::admit_relations(&reason.sql, relations.clone())?);
        }
        Ok(AdmittedModel {
            outputs,
            checkpoint,
            evidence,
            reasons,
        })
    }

    fn queries(
        ports: &[sdk::Port],
        queries: &BTreeMap<String, String>,
        relations: &BTreeMap<String, Vec<String>>,
    ) -> Result<BTreeMap<String, QuerySql>> {
        if ports.len() != queries.len() {
            return crate::QueryInvalidSnafu {
                field: "model output queries",
            }
            .fail();
        }
        ports
            .iter()
            .map(|port| {
                schema::ModelSchema::fields(&port.schema)?;
                let sql = queries.get(&port.name).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "model output query",
                    }
                    .build()
                })?;
                Ok((
                    port.name.clone(),
                    QuerySql::admit_relations(sql, relations.clone())?,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
