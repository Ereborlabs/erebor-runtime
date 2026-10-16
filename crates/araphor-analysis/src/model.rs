use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::SqlModelV1;
use araphor_query::datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::datafusion::execution::SessionState;
use araphor_query::datafusion::logical_expr::{Expr, LogicalPlan, Volatility};
use araphor_query::datafusion::sql::sqlparser::ast::Ident;
use araphor_query::execution::Engine;
use araphor_query::memory::Memory;
use araphor_query::parser::Parser;

use crate::Result;

mod arrays;
mod component;
mod datasets;
mod execute;
mod input;
mod operation;
mod output;
mod schema;
mod source;
pub use datasets::SqlDatasetOutputV1;
pub use operation::ModelRun;
pub(crate) use source::{ModelInputRequest, ModelInputs};

pub struct SqlModelOutputV1 {
    pub output: sdk::Output,
    _metadata: MemoryReservation,
}

pub(crate) struct AdmittedExport {
    inputs: Vec<AdmittedInput>,
    model: Option<AdmittedModel>,
    implementation: Option<usize>,
}

enum AdmittedInput {
    Query {
        port: usize,
        plan: Arc<LogicalPlan>,
        reads: BTreeSet<String>,
        inputs: Vec<usize>,
        clock: bool,
    },
    Output {
        port: usize,
    },
}

impl AdmittedInput {
    fn port(&self) -> usize {
        match self {
            Self::Query { port, .. } | Self::Output { port } => *port,
        }
    }
}

impl AdmittedExport {
    pub(crate) fn admit(
        engine: &Engine,
        model: &sdk::Model,
        program: Option<&SqlModelV1>,
    ) -> Result<Self> {
        let relations = schema::ModelSchema::sources(model)?;
        let state = engine.catalog(relations.clone())?;
        let mut inputs = Vec::new();
        for (port, input) in model.inputs.iter().enumerate() {
            let sql = match &input.source {
                sdk::InputSource::Query(sql) => Some(sql.clone()),
                sdk::InputSource::Table(sdk::TableRef::Named(name))
                    if model.input_mode == sdk::InputMode::Resolved =>
                {
                    let fields = input
                        .port
                        .schema
                        .fields()
                        .iter()
                        .map(|field| Ident::with_quote('"', field.name()).to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(format!(
                        "SELECT {fields} FROM {}",
                        Ident::with_quote('"', name)
                    ))
                }
                sdk::InputSource::Table(sdk::TableRef::Output(_))
                    if model.input_mode == sdk::InputMode::Resolved =>
                {
                    inputs.push(AdmittedInput::Output { port });
                    None
                }
                _ => None,
            };
            if let Some(sql) = sql {
                let statement = Parser::parse(&sql)?;
                let sources = state
                    .resolve_table_references(&statement)?
                    .into_iter()
                    .map(|name| name.table().to_owned())
                    .collect::<BTreeSet<_>>();
                let reads = sources
                    .iter()
                    .filter(|name| !relations.contains_key(name.as_str()))
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let dependencies = model
                    .inputs
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| {
                        relations.contains_key(&input.port.name)
                            && sources.contains(&input.port.name)
                    })
                    .map(|(index, _)| index)
                    .collect();
                let plan = engine.plan(&state, statement, Vec::new())?;
                let clock = clock(&plan)? || reads.contains("notifications");
                inputs.push(AdmittedInput::Query {
                    port,
                    plan: Arc::new(plan),
                    reads,
                    inputs: dependencies,
                    clock,
                });
            }
        }
        inputs.sort_by_key(|input| {
            matches!(
                model.inputs[input.port()].source,
                sdk::InputSource::Query(_)
            )
        });
        Ok(Self {
            inputs,
            model: program
                .map(|program| AdmittedModel::admit(engine, program, model))
                .transpose()?,
            implementation: None,
        })
    }

    pub(crate) fn compile(
        engine: &Engine,
        artifact: &crate::PackageArtifactV1,
        model: &sdk::Model,
    ) -> Result<Self> {
        let selected = artifact.implementation(&model.name)?;
        let index = artifact
            .implementations
            .iter()
            .position(|candidate| std::ptr::eq(candidate, selected))
            .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("model implementation"))?;
        let program = match selected {
            crate::PackageImplementationV1::Sql { program, .. } => Some(program),
            _ => None,
        };
        let mut admitted = Self::admit(engine, model, program)?;
        admitted.implementation = Some(index);
        Ok(admitted)
    }

    pub(crate) fn implementation<'a>(
        &self,
        artifact: &'a crate::PackageArtifactV1,
    ) -> Result<&'a crate::PackageImplementationV1> {
        let index = self.implementation.ok_or_else(|| {
            crate::PackageErrorCodeV1::Incomplete.error("admitted implementation")
        })?;
        Ok(artifact.implementations.get(index).ok_or_else(|| {
            crate::PackageErrorCodeV1::Incomplete.error("admitted implementation")
        })?)
    }

    pub(crate) fn implementation_index(&self) -> Option<usize> {
        self.implementation
    }
    pub(crate) fn input_clock(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| matches!(input, AdmittedInput::Query { clock: true, .. }))
    }
    pub(crate) fn model_clock(&self) -> bool {
        self.model.as_ref().is_some_and(|model| model.clock)
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        use std::mem::size_of;
        let mut bytes =
            size_of::<Self>().saturating_add(self.inputs.capacity() * size_of::<AdmittedInput>());
        for input in &self.inputs {
            if let AdmittedInput::Query { reads, inputs, .. } = input {
                bytes = bytes
                    .saturating_add(
                        reads
                            .iter()
                            .map(|source| source.capacity() + size_of::<String>())
                            .sum::<usize>(),
                    )
                    .saturating_add(inputs.capacity() * size_of::<usize>());
            }
        }
        if let Some(model) = &self.model {
            bytes = bytes
                .saturating_add(model.outputs.capacity() * size_of::<Arc<LogicalPlan>>())
                .saturating_add(model.checkpoint.capacity() * size_of::<Arc<LogicalPlan>>())
                .saturating_add(
                    model.reasons.capacity() * size_of::<(usize, usize, Arc<LogicalPlan>)>(),
                );
        }
        bytes
    }
}

impl SqlModelOutputV1 {
    pub(crate) fn owned_bytes(output: &sdk::Output, bytes: usize) -> usize {
        bytes.max(output.allocated_bytes())
    }

    pub(crate) fn retain(
        output: sdk::Output,
        memory: &Memory,
        mut reservation: MemoryReservation,
    ) -> Result<Self> {
        let mut arrays = 0usize;
        for data in output
            .datasets
            .iter()
            .chain(output.checkpoint.iter().flat_map(|state| &state.datasets))
        {
            for batch in &data.batches {
                memory.retain_output(batch, &mut reservation)?;
                arrays = arrays.saturating_add(
                    batch
                        .columns()
                        .iter()
                        .map(|array| array.get_buffer_memory_size())
                        .sum::<usize>(),
                );
            }
        }
        for reason in &output.reasons {
            memory.retain_output(&reason.details, &mut reservation)?;
            arrays = arrays.saturating_add(
                reason
                    .details
                    .columns()
                    .iter()
                    .map(|array| array.get_buffer_memory_size())
                    .sum::<usize>(),
            );
        }
        reservation.try_resize(output.allocated_bytes().saturating_sub(arrays))?;
        Ok(Self {
            output,
            _metadata: reservation,
        })
    }

    pub(crate) fn into_parts(self) -> (sdk::Output, MemoryReservation) {
        (self.output, self._metadata)
    }
}

struct AdmittedModel {
    outputs: Vec<Arc<LogicalPlan>>,
    checkpoint: Vec<Arc<LogicalPlan>>,
    evidence: Option<Arc<LogicalPlan>>,
    reasons: Vec<(usize, usize, Arc<LogicalPlan>)>,
    clock: bool,
}

impl AdmittedModel {
    fn reads_output(&self, name: &str) -> Result<bool> {
        let mut read = false;
        for plan in self
            .checkpoint
            .iter()
            .chain(self.evidence.iter())
            .chain(self.reasons.iter().map(|(_, _, plan)| plan))
        {
            plan.apply_with_subqueries(|plan| {
                if let LogicalPlan::TableScan(scan) = plan {
                    read |= scan.table_name.table() == name;
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(read)
    }

    fn admit(engine: &Engine, program: &SqlModelV1, model: &sdk::Model) -> Result<Self> {
        let mut relations = schema::ModelSchema::relations(model)?;
        let state = engine.catalog(relations.clone())?;
        let outputs = Self::outputs(engine, &state, &model.outputs, &program.outputs, &relations)?;
        for port in &model.outputs {
            schema::ModelSchema::relation(
                &mut relations,
                &format!("output_{}", port.name),
                &port.schema,
            )?;
        }
        let state = engine.catalog(relations.clone())?;
        let checkpoint = Self::outputs(
            engine,
            &state,
            model
                .checkpoint
                .as_ref()
                .map_or(&[], |spec| spec.datasets.as_slice()),
            &program.checkpoint,
            &relations,
        )?;
        let evidence = program
            .evidence
            .as_ref()
            .map(|sql| Self::plan(engine, &state, sql, &relations))
            .transpose()?;
        if program.reasons.len() > 128 {
            return crate::ModelInvalidSnafu {
                field: "model reason queries",
            }
            .fail();
        }
        let mut reasons = Vec::new();
        for reason in &program.reasons {
            let output = model
                .outputs
                .iter()
                .position(|port| port.name == reason.output);
            let spec = model
                .reasons
                .iter()
                .position(|spec| spec.code == reason.code);
            let (Some(output), Some(spec)) = (output, spec) else {
                return crate::ModelInvalidSnafu {
                    field: "model reason binding",
                }
                .fail();
            };
            reasons.push((
                output,
                spec,
                Self::plan(engine, &state, &reason.sql, &relations)?,
            ));
        }
        let mut uses_clock = false;
        for plan in outputs
            .iter()
            .chain(&checkpoint)
            .chain(evidence.iter())
            .chain(reasons.iter().map(|(_, _, plan)| plan))
        {
            uses_clock |= clock(plan)?;
        }
        Ok(Self {
            outputs,
            checkpoint,
            evidence,
            reasons,
            clock: uses_clock,
        })
    }

    fn outputs(
        engine: &Engine,
        state: &SessionState,
        ports: &[sdk::Port],
        queries: &BTreeMap<String, String>,
        relations: &BTreeMap<String, Arc<sdk::Schema>>,
    ) -> Result<Vec<Arc<LogicalPlan>>> {
        if ports.len() != queries.len() {
            return crate::ModelInvalidSnafu {
                field: "model output queries",
            }
            .fail();
        }
        ports
            .iter()
            .map(|port| {
                schema::ModelSchema::validate(&port.schema)?;
                let sql = queries.get(&port.name).ok_or_else(|| {
                    crate::ModelInvalidSnafu {
                        field: "model output query",
                    }
                    .build()
                })?;
                Self::plan(engine, state, sql, relations)
            })
            .collect()
    }

    fn plan(
        engine: &Engine,
        state: &SessionState,
        sql: &str,
        relations: &BTreeMap<String, Arc<sdk::Schema>>,
    ) -> Result<Arc<LogicalPlan>> {
        let statement = Parser::parse(sql)?;
        if state
            .resolve_table_references(&statement)?
            .iter()
            .any(|name| !relations.contains_key(name.table()))
        {
            return crate::ModelInvalidSnafu {
                field: "model undeclared input",
            }
            .fail();
        }
        Ok(Arc::new(engine.plan(state, statement, Vec::new())?))
    }
}

fn clock(plan: &LogicalPlan) -> Result<bool> {
    let mut clock = false;
    plan.apply_with_subqueries(|plan| {
        plan.apply_expressions(|expression| {
            expression.apply(|expression| {
                if let Expr::ScalarFunction(function) = expression {
                    clock |= function.func.signature().volatility != Volatility::Immutable;
                }
                Ok(TreeNodeRecursion::Continue)
            })
        })?;
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(clock)
}

#[cfg(test)]
mod tests;
