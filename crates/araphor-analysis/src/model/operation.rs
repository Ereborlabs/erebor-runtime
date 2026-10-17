use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::execution::{Engine, Permit, Session};
use araphor_query::inputs::InputSet;
use araphor_query::memory::Memory;

use crate::{AnalysisReadControl, AnalysisSelectionV1, Result};

pub(crate) struct ModelRun {
    pub(super) session: Session,
    pub(crate) inputs: Option<Arc<InputSet>>,
    pub(crate) memory: Arc<Memory>,
    pub(super) output_memory: MemoryReservation,
    pub(super) control: AnalysisReadControl,
    pub(super) permit: Arc<Permit>,
    pub(super) limits: sdk::Limits,
    pub(super) byte_limit: usize,
    pub(super) bytes: usize,
    pub(super) rows: u64,
    pub(super) batches: u32,
}

impl ModelRun {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        owner: &Arc<Engine>,
        memory: &Arc<Memory>,
        tenant: [u8; 16],
        control: &AnalysisReadControl,
        now: u64,
        mut limits: sdk::Limits,
        byte_limit: usize,
        inputs: Option<Arc<InputSet>>,
    ) -> Result<Self> {
        control.check()?;
        i64::try_from(now).map_err(|_| {
            crate::ModelInvalidSnafu {
                field: "model evaluation time",
            }
            .build()
        })?;
        let control = control.within(owner.limits().evaluate_timeout)?;
        let byte_limit = byte_limit.min(owner.limits().output_capacity);
        limits.max_bytes = limits.max_bytes.min(byte_limit as u64);
        limits.max_checkpoint_bytes = limits.max_checkpoint_bytes.min(byte_limit as u64);
        let session = owner.session_on(
            AnalysisSelectionV1::tenant(tenant),
            &control,
            now,
            Arc::clone(memory),
        )?;
        let output_memory = memory.reserve_output(0)?;
        let permit = Arc::new(owner.reserve_evaluation(tenant)?);
        Ok(Self {
            session,
            inputs,
            memory: Arc::clone(memory),
            output_memory,
            control,
            permit,
            limits,
            byte_limit,
            bytes: 0,
            rows: 0,
            batches: 0,
        })
    }
}

#[cfg(test)]
mod tests;
