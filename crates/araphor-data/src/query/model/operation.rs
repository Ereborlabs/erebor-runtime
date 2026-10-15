use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{
    execute::ModelExecution, schema::ModelSchema, ModelInputRequest, ModelInputs, SqlModelOutputV1,
    SqlModelV1,
};
use crate::query::{budget::QueryLease, evaluation::QueryEvaluation, input::ScopedSources};
use crate::{AnalysisReadControl, QueryOwner, Result};

pub(crate) struct ModelOperation<'a> {
    pub(super) owner: &'a QueryOwner,
    tenant: [u8; 16],
    engine: Option<(duckdb::Connection, QueryLease)>,
    pub(super) sources: ScopedSources,
    pub(super) bound: BTreeMap<String, String>,
}

impl QueryOwner {
    pub(crate) fn model_operation(&self, tenant: [u8; 16]) -> ModelOperation<'_> {
        ModelOperation {
            owner: self,
            tenant,
            engine: None,
            sources: ScopedSources::default(),
            bound: BTreeMap::new(),
        }
    }
}

impl ModelOperation<'_> {
    pub(super) fn engine(&mut self) -> Result<(&duckdb::Connection, &mut ScopedSources)> {
        let (connection, _) = match &mut self.engine {
            Some(engine) => engine,
            slot @ None => {
                let lease = self.owner.budget.model(self.tenant, 0)?;
                slot.insert((QueryEvaluation::connection()?, lease))
            }
        };
        Ok((connection, &mut self.sources))
    }

    pub(crate) fn inputs(
        mut self,
        request: ModelInputRequest<'_>,
        control: &AnalysisReadControl,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<(Self, ModelInputs)> {
        if request.grant.selection.tenant_id != self.tenant
            || request.activation.key.tenant_id != self.tenant
        {
            return crate::QueryDeniedSnafu.fail();
        }
        if request.model.input_mode == sdk::InputMode::Provided {
            return Err(crate::PackageErrorCodeV1::Missing.error("host-prepared inputs"));
        }
        let queries = QueryOwner::admit_inputs(request.model)?;
        let model = request.model;
        let limits = sdk::Limits {
            max_bytes: model
                .limits
                .max_bytes
                .min(self.owner.limits.input_bytes as u64),
            ..model.limits
        };
        let mut sources = BTreeMap::new();
        for input in &model.inputs {
            let sdk::InputSource::Table(table) = &input.source else {
                continue;
            };
            control.check()?;
            authorize()?;
            let source = match table {
                sdk::TableRef::Output(reference) => {
                    self.owner.output_table(&request, reference, &input.port)?
                }
                sdk::TableRef::Named(_) => self.read_input(
                    &request,
                    &input.port,
                    &queries[&input.port.name],
                    control,
                    &sources,
                )?,
            };
            sources.insert(input.port.name.clone(), source);
            ModelInputs::check(sources.values(), limits)?;
        }
        for input in &model.inputs {
            let sdk::InputSource::Query(_) = &input.source else {
                continue;
            };
            control.check()?;
            authorize()?;
            let sql = &queries[&input.port.name];
            for (index, input) in model.inputs.iter().enumerate() {
                if !matches!(input.source, sdk::InputSource::Table(_))
                    || !sql
                        .dependencies()
                        .contains(&input.port.name.to_ascii_lowercase())
                    || crate::query::input::SCHEMAS
                        .iter()
                        .any(|schema| schema.name.eq_ignore_ascii_case(&input.port.name))
                    || self.bound.contains_key(&input.port.name)
                {
                    continue;
                }
                let source = sources
                    .get(&input.port.name)
                    .ok_or_else(|| crate::PackageErrorCodeV1::Incomplete.error("table binding"))?;
                let table = format!("araphor:port:{index}");
                self.bound.insert(input.port.name.clone(), table.clone());
                ModelExecution::check_input(
                    sources
                        .iter()
                        .filter(|(name, _)| self.bound.contains_key(*name))
                        .flat_map(|(_, source)| &source.input.data.batches),
                    self.owner.limits.input_bytes,
                )?;
                let stage = control.within(self.owner.limits.evaluate_timeout)?;
                let (connection, _) = self.engine()?;
                stage.query_run(connection, || {
                    ModelExecution::table_on(
                        connection,
                        &stage,
                        &table,
                        &input.port.schema,
                        &source.input.data.batches,
                    )?;
                    connection
                        .execute_batch(&format!(
                            "CREATE TEMP VIEW {} AS SELECT * FROM {}",
                            ModelSchema::quote(&input.port.name),
                            ModelSchema::quote(&table)
                        ))
                        .context(crate::AnalysisDatabaseSnafu {
                            operation: "bind source table",
                        })
                })?;
            }
            let source = self.read_input(&request, &input.port, sql, control, &sources)?;
            sources.insert(input.port.name.clone(), source);
            ModelInputs::check(sources.values(), limits)?;
        }
        let mut selected = ModelInputs::default();
        for input in &model.inputs {
            selected.push(
                sources
                    .remove(&input.port.name)
                    .ok_or_else(|| crate::PackageErrorCodeV1::Incomplete.error("input binding"))?,
            );
        }
        selected.finish(request.now);
        Ok((self, selected))
    }

    pub(crate) fn evaluate(
        mut self,
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
        self.engine()?;
        let (connection, lease) = self.engine.take().ok_or_else(|| {
            crate::QueryInvalidSnafu {
                field: "model engine",
            }
            .build()
        })?;
        self.sources.clear(&connection)?;
        self.owner.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| {
                let mut lease = lease;
                lease.reserve_output(capacity)?;
                Ok(lease)
            },
            |control, host, _lease| {
                let mut executor = ModelExecution::new(
                    &connection,
                    control,
                    evaluation.context.time_utc_ns,
                    evaluation.context.limits,
                    host,
                );
                let output = control.query_run(&connection, || {
                    executor.register(model, evaluation, &self.bound, host.input_bytes)?;
                    executor.evaluate(model, program, admitted)
                })?;
                let bytes = executor.bytes();
                drop(connection);
                Ok((output, bytes))
            },
        )
    }
}

#[cfg(test)]
mod tests;
