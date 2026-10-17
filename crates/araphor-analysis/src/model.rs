use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::SqlModelV1;
use araphor_query::datafusion::catalog::TableProvider;
use araphor_query::datafusion::common::tree_node::TreeNodeRecursion;
use araphor_query::datafusion::datasource::MemTable;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::datafusion::execution::SessionState;
use araphor_query::datafusion::logical_expr::LogicalPlan;
use araphor_query::execution::{Engine, Session};
use araphor_query::inputs::Inputs;
use araphor_query::memory::Memory;

use crate::Result;

mod component;
mod datasets;
mod execute;
mod input;
mod operation;
mod output;
pub use datasets::SqlDatasetOutputV1;
pub(crate) use operation::ModelRun;

pub struct SqlModelOutputV1 {
    pub output: sdk::Output,
    _metadata: MemoryReservation,
}

pub(crate) struct AdmittedExport {
    pub(crate) inputs: Arc<Inputs>,
    model: Option<AdmittedModel>,
    implementation: Option<usize>,
}

impl AdmittedExport {
    pub(crate) fn admit(
        engine: &Engine,
        model: &sdk::Model,
        program: Option<&SqlModelV1>,
    ) -> Result<Self> {
        Ok(Self {
            inputs: Arc::new(Inputs::admit(engine, model)?),
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
        self.inputs.input_clock()
    }
    pub(crate) fn model_clock(&self) -> bool {
        self.model.as_ref().is_some_and(|model| model.clock)
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        use std::mem::size_of;
        let mut bytes = size_of::<Self>().saturating_add(self.inputs.allocated_bytes());
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
        reservation: MemoryReservation,
    ) -> Result<Self> {
        let mut arrays = 0usize;
        for data in output
            .datasets
            .iter()
            .chain(output.checkpoint.iter().flat_map(|state| &state.datasets))
        {
            for batch in &data.batches {
                memory.retain_output(batch, &reservation)?;
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
            memory.retain_output(&reason.details, &reservation)?;
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
        let mut relations = Self::relations(model)?;
        let state = engine.catalog(relations.clone())?;
        let outputs = Self::outputs(engine, &state, &model.outputs, &program.outputs)?;
        for port in &model.outputs {
            Self::relation(
                &mut relations,
                &format!("output_{}", port.name),
                &port.schema,
            )?;
        }
        let state = engine.catalog(relations)?;
        let checkpoint = Self::outputs(
            engine,
            &state,
            model
                .checkpoint
                .as_ref()
                .map_or(&[], |spec| spec.datasets.as_slice()),
            &program.checkpoint,
        )?;
        let evidence = program
            .evidence
            .as_ref()
            .map(|sql| Self::plan(engine, &state, sql))
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
            reasons.push((output, spec, Self::plan(engine, &state, &reason.sql)?));
        }
        let mut uses_clock = false;
        for plan in outputs
            .iter()
            .chain(&checkpoint)
            .chain(evidence.iter())
            .chain(reasons.iter().map(|(_, _, plan)| plan))
        {
            uses_clock |= Inputs::clocked(plan)?;
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
                let sql = queries.get(&port.name).ok_or_else(|| {
                    crate::ModelInvalidSnafu {
                        field: "model output query",
                    }
                    .build()
                })?;
                Self::plan(engine, state, sql)
            })
            .collect()
    }

    fn relations(model: &sdk::Model) -> Result<BTreeMap<String, Arc<dyn TableProvider>>> {
        let mut relations = BTreeMap::new();
        for input in &model.inputs {
            Self::relation(&mut relations, &input.port.name, &input.port.schema)?;
        }
        if !model.parameters.fields().is_empty() {
            Self::relation(&mut relations, "parameters", &model.parameters)?;
        }
        if let Some(spec) = &model.checkpoint {
            for port in &spec.datasets {
                Self::relation(
                    &mut relations,
                    &format!("prior_{}", port.name),
                    &port.schema,
                )?;
            }
        }
        Ok(relations)
    }

    fn relation(
        relations: &mut BTreeMap<String, Arc<dyn TableProvider>>,
        name: &str,
        schema: &sdk::Schema,
    ) -> Result<()> {
        let schema = Session::indexed_schema(schema)?;
        match relations.entry(name.to_owned()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::new(MemTable::try_new(schema, vec![vec![]])?));
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => crate::ModelInvalidSnafu {
                field: "model relation collision",
            }
            .fail(),
        }
    }

    fn plan(engine: &Engine, state: &SessionState, sql: &str) -> Result<Arc<LogicalPlan>> {
        Ok(Arc::new(engine.plan(
            state,
            engine.limits().parser.parse(sql)?,
            Vec::new(),
        )?))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod schema;
