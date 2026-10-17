use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::execution::{Engine, Session};
use araphor_query::memory::Memory;

use crate::{AnalysisReadControl, AnalysisSelectionV1, Result};
use araphor_query::inputs::InputSet;

pub struct ModelRun<'a> {
    pub(super) owner: &'a Arc<Engine>,
    pub(super) session: Option<Session>,
    tenant: [u8; 16],
    pub(crate) inputs: Option<Arc<InputSet>>,
    pub(crate) memory: Arc<Memory>,
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
            inputs: None,
            memory: Arc::clone(owner.memory()),
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

    pub(crate) fn prepared(
        owner: &'a Arc<Engine>,
        tenant: [u8; 16],
        control: &AnalysisReadControl,
        inputs: Arc<InputSet>,
    ) -> Result<Self> {
        if inputs
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.selection.tenant_id != tenant)
        {
            return Err(crate::PackageErrorCodeV1::Denied
                .error("model input tenant")
                .into());
        }
        let mut run = Self::new(owner, tenant, control)?;
        run.memory = Arc::clone(inputs.memory());
        run.inputs = Some(inputs);
        Ok(run)
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
            self.session = Some(self.owner.session_on(
                selection,
                &self.control,
                now,
                Arc::clone(&self.memory),
            )?);
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
}

#[cfg(test)]
mod tests;
