use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_package::PackageImplementationV1;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;

use crate::execution::Permit;

use super::{external, internal, limit, CallContext, PackageExec, Result};

struct Exchange {
    _input: Arc<MemoryReservation>,
    _scratch: MemoryReservation,
    _output: Arc<MemoryReservation>,
    _permit: Arc<Permit>,
    _image: Arc<MemoryReservation>,
    _scope: Option<araphor_package_runtime::TaskTrackerToken>,
}

impl PackageExec {
    pub(super) async fn guest(
        &self,
        evaluation: sdk::Evaluation,
        owner: &CallContext,
        input: Arc<MemoryReservation>,
        context: &TaskContext,
    ) -> Result<(
        Option<araphor_package_runtime::wasm::EvaluationLease>,
        sdk::Evaluation,
        sdk::Output,
        Arc<MemoryReservation>,
    )> {
        let permit = context
            .session_config()
            .get_extension::<Permit>()
            .ok_or_else(|| internal("package evaluation permit is absent"))?;
        let artifact = self
            .call
            .bundle
            .bundle()
            .artifact(&self.call.package)
            .map_err(external)?;
        let wasm = matches!(
            artifact
                .implementation(&evaluation.export)
                .map_err(external)?,
            PackageImplementationV1::Wasm { .. }
        );
        let admission = if wasm
            && context
                .session_config()
                .get_extension::<crate::stream::Run>()
                .is_some_and(|run| run.managed.is_some())
        {
            let control = context
                .session_config()
                .get_extension::<araphor_data::AnalysisReadControl>()
                .ok_or_else(|| internal("package execution control is absent"))?;
            self.prepared
                .as_ref()
                .ok_or_else(|| internal("package preparation is absent"))?
                .acquire_evaluation(&control)
                .await
                .map_err(external)?
        } else {
            None
        };
        let retained = admission.as_ref().map(|permit| permit.retain());
        let scratch = if owner.memory.input_capacity().is_some() {
            let retained = evaluation.allocated_bytes();
            let bytes = evaluation
                .encoding_scratch_bytes()
                .map_err(external)?
                .checked_add(retained)
                .and_then(|bytes| bytes.checked_mul(4))
                .and_then(|bytes| {
                    artifact
                        .descriptor
                        .allocated_bytes()
                        .checked_mul(4)
                        .and_then(|metadata| bytes.checked_add(metadata))
                })
                .and_then(|bytes| bytes.checked_sub(retained))
                .ok_or_else(limit)?;
            owner.memory.reserve_input(bytes)?
        } else {
            owner.memory.reserve_input(0)?
        };
        let output = match owner.memory.output_capacity() {
            Some(capacity) => {
                let limits = context
                    .session_config()
                    .get_extension::<crate::execution::Limits>()
                    .ok_or_else(|| internal("package execution limits are absent"))?;
                owner
                    .memory
                    .prepare_output(limits.output_bytes.min(capacity))?
            }
            None => owner.memory.reserve_output(0)?,
        };
        let output = Arc::new(output);
        let copy_bytes = owner.memory.output_capacity().map(|_| {
            if wasm {
                output.size() / 4
            } else {
                output.size()
            }
        });
        let lease = Exchange {
            _image: Arc::clone(&self.call._image),
            _input: input,
            _scratch: scratch,
            _output: Arc::clone(&output),
            _permit: permit,
            _scope: owner
                .scope
                .as_ref()
                .map(araphor_package_runtime::TaskTracker::token),
        };
        let (evaluation, result) = owner
            .runtime
            .evaluate_reserved(
                Arc::clone(&self.call.bundle),
                self.call.package.clone(),
                evaluation,
                owner.control.within(None).map_err(external)?,
                &owner.workers,
                copy_bytes,
                self.prepared.clone(),
                admission,
                lease,
            )
            .await
            .map_err(external)?;
        Ok((retained, evaluation, result, output))
    }
}
