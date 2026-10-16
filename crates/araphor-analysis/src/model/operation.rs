use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::execution::{Engine, Session};

use super::{AdmittedExport, AdmittedInput, ModelInputRequest, ModelInputs};
use crate::{AnalysisReadControl, AnalysisSelectionV1, Result};

pub struct ModelRun<'a> {
    pub(super) owner: &'a Arc<Engine>,
    pub(super) session: Option<Session>,
    tenant: [u8; 16],
    pub(super) inputs: ModelInputs,
    pub(super) input_memory: MemoryReservation,
    pub(super) output_memory: Option<MemoryReservation>,
    pub(super) control: AnalysisReadControl,
    pub(super) time_utc_ns: i64,
    pub(super) limits: sdk::Limits,
    pub(super) byte_limit: usize,
    pub(super) bytes: usize,
    pub(super) rows: u64,
    pub(super) batches: u32,
}

impl<'a> ModelRun<'a> {
    pub fn new(
        owner: &'a Arc<Engine>,
        tenant: [u8; 16],
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        control.check()?;
        Ok(Self {
            owner,
            session: None,
            tenant,
            inputs: ModelInputs::default(),
            input_memory: owner.memory().reserve_input(0)?,
            output_memory: None,
            control: control.within(control.remaining()?)?,
            time_utc_ns: 0,
            limits: sdk::Limits::default(),
            byte_limit: owner.limits().output_capacity,
            bytes: 0,
            rows: 0,
            batches: 0,
        })
    }

    pub fn admit_model(
        owner: &Engine,
        model: &sdk::Model,
        program: &super::SqlModelV1,
    ) -> Result<()> {
        super::AdmittedModel::admit(owner, program, model).map(|_| ())
    }

    pub(crate) fn tenant(&self) -> [u8; 16] {
        self.tenant
    }

    pub(crate) fn take_inputs(&mut self) -> Result<ModelInputs> {
        self.input_memory.try_resize(self.inputs.metadata_bytes())?;
        self.inputs._metadata = Some(self.input_memory.split(self.input_memory.size()));
        Ok(std::mem::take(&mut self.inputs))
    }

    pub(super) fn start(&mut self, selection: AnalysisSelectionV1, now: u64) -> Result<()> {
        let time = i64::try_from(now).map_err(|_| {
            crate::ModelInvalidSnafu {
                field: "model evaluation time",
            }
            .build()
        })?;
        if self.session.is_none() {
            self.time_utc_ns = time;
            self.session = Some(self.owner.session(selection, &self.control, now)?);
        } else if self.time_utc_ns != time {
            return crate::ModelInvalidSnafu {
                field: "changed model evaluation time",
            }
            .fail();
        } else {
            let remaining = self.control.remaining()?;
            self.session()?.set_timeout(remaining)?;
        }
        Ok(())
    }

    pub(super) fn session(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or_else(|| {
            crate::ModelInvalidSnafu {
                field: "model session",
            }
            .build()
        })
    }

    pub(crate) fn prepare_inputs(
        &mut self,
        request: ModelInputRequest<'_>,
        admitted: &AdmittedExport,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if request.grant.selection.tenant_id != self.tenant
            || request.activation.key.tenant_id != self.tenant
        {
            return Err(crate::PackageErrorCodeV1::Denied
                .error("model input tenant")
                .into());
        }
        if request.model.input_mode == sdk::InputMode::Provided {
            return Err(crate::PackageErrorCodeV1::Missing
                .error("host-prepared inputs")
                .into());
        }
        self.start(request.grant.selection.clone(), request.now)?;
        let model = request.model;
        let limits = sdk::Limits {
            max_bytes: model
                .limits
                .max_bytes
                .min(self.owner.limits().input_bytes as u64),
            ..model.limits
        };
        for input in &admitted.inputs {
            self.control.check()?;
            authorize()?;
            let port = &model.inputs[input.port()];
            let source = match input {
                AdmittedInput::Query {
                    plan,
                    reads,
                    inputs,
                    ..
                } => {
                    let mut inherited = inputs
                        .iter()
                        .map(|index| {
                            self.inputs
                                .inputs
                                .iter()
                                .find(|input| input.data.name == model.inputs[*index].port.name)
                                .cloned()
                                .ok_or_else(|| {
                                    crate::PackageErrorCodeV1::Incomplete
                                        .error("table binding")
                                        .into()
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    inherited.sort_by(|left, right| left.data.name.cmp(&right.data.name));
                    self.read_input(
                        &request,
                        &port.port,
                        plan,
                        reads,
                        &inherited,
                        &mut authorize,
                    )?
                }
                AdmittedInput::Output { .. } => {
                    let sdk::InputSource::Table(sdk::TableRef::Output(reference)) = &port.source
                    else {
                        return Err(crate::PackageErrorCodeV1::Incomplete
                            .error("table binding")
                            .into());
                    };
                    self.output_table(&request, reference, &port.port)?
                }
            };
            if matches!(port.source, sdk::InputSource::Table(_))
                && !matches!(&port.source, sdk::InputSource::Table(sdk::TableRef::Named(name)) if name == &port.port.name)
            {
                self.table(&port.port.name, &port.port.schema, &source.data.batches)?;
            }
            self.inputs.inputs.push(source);
            self.inputs.check(limits)?;
            Self::check_input(
                self.inputs
                    .inputs
                    .iter()
                    .flat_map(|input| &input.data.batches),
                self.owner.limits().input_bytes,
            )?;
            self.input_memory.try_resize(self.inputs.metadata_bytes())?;
        }
        self.inputs.inputs.sort_by_key(|input| {
            model
                .inputs
                .iter()
                .position(|port| port.port.name == input.data.name)
        });
        self.inputs.finish(request.now);
        self.input_memory.try_resize(self.inputs.metadata_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
