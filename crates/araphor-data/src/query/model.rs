use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{budget::QueryLease, QueryOwner, QuerySql};
use crate::{AnalysisReadControl, Result};

mod arrays;
mod component;
mod datasets;
mod execute;
mod guards;
mod input;
mod operation;
mod output;
mod parameters;
mod projection;
mod schema;
mod source;
pub use datasets::SqlDatasetOutputV1;
pub(crate) use operation::ModelOperation;
pub(crate) use source::{ModelInputRequest, ModelInputs};

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

pub(crate) struct AdmittedExport {
    inputs: Vec<AdmittedInput>,
    model: Option<AdmittedModel>,
}

struct AdmittedInput {
    port: usize,
    name: String,
    read: AdmittedRead,
    bindings: Vec<usize>,
    inherited: Vec<usize>,
}

enum AdmittedRead {
    Query(QuerySql),
    Output,
}

impl AdmittedInput {
    fn query(&self) -> Option<&QuerySql> {
        match &self.read {
            AdmittedRead::Query(sql) => Some(sql),
            AdmittedRead::Output => None,
        }
    }
}

impl AdmittedExport {
    pub(crate) fn admit(model: &sdk::Model, program: Option<&SqlModelV1>) -> Result<Self> {
        Ok(Self {
            inputs: QueryOwner::admit_inputs(model)?,
            model: program.map(|program| program.admit(model)).transpose()?,
        })
    }

    pub(crate) fn input_clock(&self) -> bool {
        self.inputs
            .iter()
            .filter_map(AdmittedInput::query)
            .any(|sql| sql.uses_clock() || sql.dependencies().contains("notifications"))
    }

    pub(crate) fn model_clock(&self) -> bool {
        self.model
            .iter()
            .flat_map(AdmittedModel::queries)
            .any(QuerySql::uses_clock)
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        use std::mem::size_of;

        let mut bytes = self.inputs.iter().fold(
            size_of::<Self>().saturating_add(self.inputs.capacity() * size_of::<AdmittedInput>()),
            |bytes, input| {
                bytes
                    .saturating_add(input.name.capacity())
                    .saturating_add(input.bindings.capacity() * size_of::<usize>())
                    .saturating_add(input.inherited.capacity() * size_of::<usize>())
            },
        );
        if let Some(model) = &self.model {
            bytes = bytes
                .saturating_add(model.outputs.capacity() * size_of::<QuerySql>())
                .saturating_add(model.checkpoint.capacity() * size_of::<QuerySql>())
                .saturating_add(model.reasons.capacity() * size_of::<(usize, usize, QuerySql)>());
        }
        self.inputs
            .iter()
            .filter_map(AdmittedInput::query)
            .chain(self.model.iter().flat_map(AdmittedModel::queries))
            .fold(bytes, |bytes, sql| {
                bytes.saturating_add(sql.allocated_bytes())
            })
    }
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

    fn admit_inputs(model: &sdk::Model) -> Result<Vec<AdmittedInput>> {
        let relations = schema::ModelSchema::sources(model)?;
        let mut inputs = Vec::new();
        for (port, input) in model.inputs.iter().enumerate() {
            let read = match &input.source {
                sdk::InputSource::Query(sql) => {
                    AdmittedRead::Query(QuerySql::admit_relations(sql, relations.clone())?)
                }
                sdk::InputSource::Table(sdk::TableRef::Named(name))
                    if model.input_mode == sdk::InputMode::Resolved =>
                {
                    let fields = input
                        .port
                        .schema
                        .fields()
                        .iter()
                        .map(|field| schema::ModelSchema::quote(field.name()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    AdmittedRead::Query(QuerySql::admit(
                        &format!("SELECT {fields} FROM {}", schema::ModelSchema::quote(name)),
                        Vec::new(),
                        false,
                    )?)
                }
                sdk::InputSource::Table(sdk::TableRef::Output(_))
                    if model.input_mode == sdk::InputMode::Resolved =>
                {
                    AdmittedRead::Output
                }
                _ => continue,
            };
            inputs.push(AdmittedInput {
                port,
                name: input.port.name.to_ascii_lowercase(),
                read,
                bindings: Vec::new(),
                inherited: Vec::new(),
            });
        }
        inputs.sort_by_key(|input| {
            matches!(model.inputs[input.port].source, sdk::InputSource::Query(_))
        });
        for query in 0..inputs.len() {
            if !matches!(
                model.inputs[inputs[query].port].source,
                sdk::InputSource::Query(_)
            ) {
                continue;
            }
            let AdmittedRead::Query(sql) = &inputs[query].read else {
                continue;
            };
            let bindings: Vec<_> = inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| {
                    matches!(model.inputs[input.port].source, sdk::InputSource::Table(_))
                        && sql.dependencies().contains(&input.name)
                        && !crate::query::input::SCHEMAS
                            .iter()
                            .any(|schema| schema.name == input.name)
                })
                .map(|(index, _)| index)
                .collect();
            let mut inherited: Vec<_> = (0..query)
                .filter(|source| {
                    bindings
                        .iter()
                        .any(|binding| inputs[*binding].name == inputs[*source].name)
                })
                .collect();
            inherited.sort_by(|a, b| {
                model.inputs[inputs[*a].port]
                    .port
                    .name
                    .cmp(&model.inputs[inputs[*b].port].port.name)
            });
            inputs[query].bindings = bindings;
            inputs[query].inherited = inherited;
        }
        Ok(inputs)
    }

    #[cfg(test)]
    pub(crate) fn inputs_use_clock(model: &sdk::Model) -> Result<bool> {
        Ok(AdmittedExport::admit(model, None)?.input_clock())
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
        let admitted = AdmittedExport {
            inputs: Vec::new(),
            model: Some(program.admit(model)?),
        };
        self.model_operation(tenant)
            .evaluate_admitted(package, &admitted, evaluation, control)
    }

    fn evaluate_model_reserved(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        reserve: impl FnOnce(usize) -> Result<QueryLease>,
        execute: impl FnOnce(
            &sdk::Model,
            &AnalysisReadControl,
            &super::QueryLimits,
            &mut QueryLease,
        ) -> Result<(sdk::Output, usize)>,
    ) -> Result<SqlModelOutputV1> {
        self.check_analysis_input(evaluation)?;
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
        let capacity = (requested as usize).min(self.limits.output_capacity);
        let mut lease = reserve(capacity)?;
        let control = control.within(self.limits.evaluate_timeout)?;
        let host = super::QueryLimits {
            output_capacity: capacity,
            ..self.limits.clone()
        };
        let (mut output, bytes) = execute(model, &control, &host, &mut lease)?;
        checked
            .validate_output(&output)
            .context(crate::AnalysisContractSnafu)?;
        let bytes = output
            .datasets
            .iter()
            .chain(
                output
                    .checkpoint
                    .iter()
                    .flat_map(|checkpoint| &checkpoint.datasets),
            )
            .flat_map(|dataset| &dataset.batches)
            .chain(output.reasons.iter().map(|reason| &reason.details))
            .fold(bytes, |bytes, batch| {
                bytes.saturating_add(QueryLease::batch_overhead(batch))
            });
        if bytes > capacity {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: capacity,
            }
            .fail();
        }
        for dataset in output.datasets.iter_mut().chain(
            output
                .checkpoint
                .iter_mut()
                .flat_map(|checkpoint| &mut checkpoint.datasets),
        ) {
            for batch in &mut dataset.batches {
                *batch = lease.retain_batch(batch)?;
            }
        }
        for reason in &mut output.reasons {
            reason.details = lease.retain_batch(&reason.details)?;
        }
        control.check()?;
        Ok(SqlModelOutputV1 {
            output,
            _lease: lease.retained_output(bytes)?,
        })
    }
}

struct AdmittedModel {
    outputs: Vec<QuerySql>,
    checkpoint: Vec<QuerySql>,
    evidence: Option<QuerySql>,
    reasons: Vec<(usize, usize, QuerySql)>,
}

impl AdmittedModel {
    fn queries(&self) -> impl Iterator<Item = &QuerySql> {
        self.outputs
            .iter()
            .chain(&self.checkpoint)
            .chain(self.evidence.iter())
            .chain(self.reasons.iter().map(|(_, _, sql)| sql))
    }
}

impl SqlModelV1 {
    #[cfg(test)]
    pub(crate) fn uses_clock(&self, model: &sdk::Model) -> Result<bool> {
        Ok(AdmittedExport::admit(model, Some(self))?.model_clock())
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
            let output = model
                .outputs
                .iter()
                .position(|port| port.name == reason.output);
            let spec = model
                .reasons
                .iter()
                .position(|spec| spec.code == reason.code);
            let (Some(output), Some(spec)) = (output, spec) else {
                return crate::QueryInvalidSnafu {
                    field: "model reason binding",
                }
                .fail();
            };
            reasons.push((
                output,
                spec,
                QuerySql::admit_relations(&reason.sql, relations.clone())?,
            ));
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
        relations: &BTreeMap<String, std::sync::Arc<sdk::Schema>>,
    ) -> Result<Vec<QuerySql>> {
        if ports.len() != queries.len() {
            return crate::QueryInvalidSnafu {
                field: "model output queries",
            }
            .fail();
        }
        ports
            .iter()
            .map(|port| {
                schema::ModelSchema::validate(&port.schema)?;
                let sql = queries.get(&port.name).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "model output query",
                    }
                    .build()
                })?;
                QuerySql::admit_relations(sql, relations.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
