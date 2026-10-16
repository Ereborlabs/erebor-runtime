use std::{collections::BTreeMap, sync::Arc};

use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;

use araphor_analysis_sdk as sdk;

use super::{
    execute::ModelExecution, AdmittedExport, ModelInputRequest, ModelInputs, SqlModelOutputV1,
    SqlModelV1,
};
use crate::query::{budget::QueryLease, engine::QueryEngine};
use crate::{AnalysisReadControl, QueryOwner, Result};

pub(crate) struct ModelOperation<'a> {
    pub(super) owner: &'a QueryOwner,
    tenant: [u8; 16],
    engine: Option<(SessionState, QueryLease)>,
    pub(super) bound: BTreeMap<String, Arc<MemTable>>,
    pub(super) retained_bytes: usize,
}

impl QueryOwner {
    pub(crate) fn model_operation(&self, tenant: [u8; 16]) -> ModelOperation<'_> {
        ModelOperation {
            owner: self,
            tenant,
            engine: None,
            bound: BTreeMap::new(),
            retained_bytes: 0,
        }
    }
}

impl ModelOperation<'_> {
    pub(super) fn engine(&mut self) -> Result<(&SessionState, &QueryLease)> {
        let (state, lease) = match &mut self.engine {
            Some(engine) => engine,
            slot @ None => {
                let lease = self.owner.budget.model(self.tenant, 0)?;
                slot.insert((QueryEngine::state()?, lease))
            }
        };
        Ok((state, lease))
    }

    pub(crate) fn release_inputs(mut self) -> Result<()> {
        if let Some((_, mut lease)) = self.engine.take() {
            lease.shrink_input(self.retained_bytes)?;
            drop(lease.retained_output(0)?);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn inputs(
        self,
        request: ModelInputRequest<'_>,
        control: &AnalysisReadControl,
        authorize: impl FnMut() -> Result<()>,
    ) -> Result<(Self, ModelInputs)> {
        let admitted = AdmittedExport::admit(request.model, None)?;
        self.inputs_admitted(request, &admitted, control, authorize)
    }

    pub(crate) fn inputs_admitted(
        mut self,
        request: ModelInputRequest<'_>,
        admitted: &AdmittedExport,
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
        let queries = &admitted.inputs;
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
            for input in &model.inputs {
                if !matches!(input.source, sdk::InputSource::Table(_))
                    || !sql
                        .dependencies()
                        .contains(&input.port.name.to_ascii_lowercase())
                    || crate::query::input::SCHEMAS
                        .iter()
                        .any(|schema| schema.name.eq_ignore_ascii_case(&input.port.name))
                    || self
                        .bound
                        .contains_key(&input.port.name.to_ascii_lowercase())
                {
                    continue;
                }
                let source = sources
                    .get(&input.port.name)
                    .ok_or_else(|| crate::PackageErrorCodeV1::Incomplete.error("table binding"))?;
                ModelExecution::check_input(
                    sources
                        .iter()
                        .filter(|(name, _)| {
                            self.bound.contains_key(&name.to_ascii_lowercase())
                                || name.as_str() == input.port.name.as_str()
                        })
                        .flat_map(|(_, source)| &source.input.data.batches),
                    self.owner.limits.input_bytes,
                )?;
                let bytes = source
                    .input
                    .data
                    .batches
                    .iter()
                    .map(|batch| {
                        let payload = if matches!(
                            &input.source,
                            sdk::InputSource::Table(sdk::TableRef::Output(_))
                        ) {
                            QueryEngine::batch_bytes(batch)
                        } else {
                            0
                        };
                        payload
                            .saturating_add(QueryLease::batch_overhead(batch))
                            .saturating_add(QueryLease::index_overhead(batch.num_rows()))
                    })
                    .sum::<usize>();
                let retained = self.retained_bytes.saturating_add(bytes);
                if retained > self.owner.limits.input_bytes {
                    return crate::QueryLimitSnafu {
                        resource: "model source input",
                        limit: self.owner.limits.input_bytes,
                    }
                    .fail();
                }
                let stage = control.within(self.owner.limits.evaluate_timeout)?;
                let (_, lease) = self.engine()?;
                let table = QueryEngine::table(
                    Arc::new(input.port.schema.clone()),
                    &source.input.data.batches,
                    lease,
                )?;
                stage.check()?;
                self.bound
                    .insert(input.port.name.to_ascii_lowercase(), table);
                self.retained_bytes = retained;
                #[cfg(test)]
                {
                    let resident = sources
                        .iter()
                        .filter(|(name, _)| self.bound.contains_key(&name.to_ascii_lowercase()))
                        .flat_map(|(_, source)| &source.input.data.batches)
                        .fold(0usize, |bytes, batch| {
                            bytes
                                .saturating_add(batch.get_array_memory_size())
                                .saturating_add(batch.num_rows() * std::mem::size_of::<u64>())
                        });
                    assert!(
                        self.retained_bytes >= resident,
                        "alias={}, retained={}, resident={resident}",
                        input.port.name,
                        self.retained_bytes,
                    );
                }
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

    #[cfg(test)]
    pub(crate) fn evaluate(
        self,
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
            inputs: BTreeMap::new(),
            model: Some(program.admit(model)?),
        };
        self.evaluate_admitted(package, program, &admitted, evaluation, control)
    }

    pub(crate) fn evaluate_admitted(
        mut self,
        package: &sdk::Package,
        program: &SqlModelV1,
        admitted: &AdmittedExport,
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
        let admitted = admitted.model.as_ref().ok_or_else(|| {
            crate::QueryInvalidSnafu {
                field: "model admitted program",
            }
            .build()
        })?;
        self.engine()?;
        let (state, lease) = self.engine.take().ok_or_else(|| {
            crate::QueryInvalidSnafu {
                field: "model engine",
            }
            .build()
        })?;
        self.owner.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| {
                let mut lease = lease;
                lease.reserve_output(capacity)?;
                Ok(lease)
            },
            |control, host, lease| {
                let mut executor = ModelExecution::new(
                    self.owner,
                    &state,
                    control,
                    lease,
                    evaluation.context.time_utc_ns,
                    evaluation.context.limits,
                    host,
                );
                executor.register(model, evaluation, self.bound, host.input_bytes)?;
                let output = executor.evaluate(model, program, admitted)?;
                let bytes = executor.bytes();
                drop(executor);
                drop(state);
                Ok((output, bytes))
            },
        )
    }
}

#[cfg(test)]
mod tests;
