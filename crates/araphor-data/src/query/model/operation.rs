use std::{collections::BTreeMap, sync::Arc};

use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;

use araphor_analysis_sdk as sdk;

#[cfg(test)]
use super::SqlModelV1;
use super::{
    execute::ModelExecution, source::ModelSource, AdmittedExport, AdmittedRead, ModelInputRequest,
    ModelInputs, SqlModelOutputV1,
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
        let model = request.model;
        let limits = sdk::Limits {
            max_bytes: model
                .limits
                .max_bytes
                .min(self.owner.limits.input_bytes as u64),
            ..model.limits
        };
        let mut sources: Vec<Option<ModelSource>> = (0..model.inputs.len()).map(|_| None).collect();
        for input in &admitted.inputs {
            control.check()?;
            authorize()?;
            for index in &input.bindings {
                let binding = &admitted.inputs[*index];
                if self.bound.contains_key(&binding.name) {
                    continue;
                }
                let port = &model.inputs[binding.port];
                let source = sources[binding.port]
                    .as_ref()
                    .ok_or_else(|| crate::PackageErrorCodeV1::Incomplete.error("table binding"))?;
                ModelExecution::check_input(
                    admitted
                        .inputs
                        .iter()
                        .filter(|input| {
                            self.bound.contains_key(&input.name) || input.port == binding.port
                        })
                        .filter_map(|input| sources[input.port].as_ref())
                        .flat_map(|source| &source.input.data.batches),
                    self.owner.limits.input_bytes,
                )?;
                let bytes = source
                    .input
                    .data
                    .batches
                    .iter()
                    .map(|batch| {
                        let payload = if matches!(binding.read, AdmittedRead::Output) {
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
                    Arc::new(port.port.schema.clone()),
                    &source.input.data.batches,
                    lease,
                )?;
                stage.check()?;
                self.bound.insert(binding.name.clone(), table);
                self.retained_bytes = retained;
                #[cfg(test)]
                {
                    let resident = admitted
                        .inputs
                        .iter()
                        .filter(|input| self.bound.contains_key(&input.name))
                        .filter_map(|input| sources[input.port].as_ref())
                        .flat_map(|source| &source.input.data.batches)
                        .fold(0usize, |bytes, batch| {
                            bytes
                                .saturating_add(batch.get_array_memory_size())
                                .saturating_add(batch.num_rows() * std::mem::size_of::<u64>())
                        });
                    assert!(
                        self.retained_bytes >= resident,
                        "alias={}, retained={}, resident={resident}",
                        port.port.name,
                        self.retained_bytes,
                    );
                }
            }
            let port = &model.inputs[input.port];
            let source = match &input.read {
                AdmittedRead::Query(sql) => {
                    let inherited = input
                        .inherited
                        .iter()
                        .map(|index| {
                            sources[admitted.inputs[*index].port]
                                .as_ref()
                                .ok_or_else(|| {
                                    crate::PackageErrorCodeV1::Incomplete.error("table binding")
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    self.read_input(&request, &port.port, sql, control, &inherited)?
                }
                AdmittedRead::Output => {
                    let sdk::InputSource::Table(sdk::TableRef::Output(reference)) = &port.source
                    else {
                        return Err(crate::PackageErrorCodeV1::Incomplete.error("table binding"));
                    };
                    self.owner.output_table(&request, reference, &port.port)?
                }
            };
            sources[input.port] = Some(source);
            ModelInputs::check(sources.iter().flatten(), limits)?;
        }
        let mut selected = ModelInputs::default();
        for source in sources {
            selected.push(
                source
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
            inputs: Vec::new(),
            model: Some(program.admit(model)?),
        };
        self.evaluate_admitted(package, &admitted, evaluation, control)
    }

    pub(crate) fn evaluate_admitted(
        mut self,
        package: &sdk::Package,
        admitted: &AdmittedExport,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
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
            |model, control, host, lease| {
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
                let output = executor.evaluate(model, admitted)?;
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
