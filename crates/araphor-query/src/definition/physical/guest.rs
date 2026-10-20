use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_package::PackageImplementationV1;
use araphor_package_runtime::wasm::WasmExecution;
use datafusion::execution::memory_pool::MemoryReservation;

use crate::execution::Permit;

use super::{external, limit, CallContext, PackageExec, Result};

struct Exchange {
    _input: Arc<MemoryReservation>,
    _scratch: MemoryReservation,
    _output: Arc<MemoryReservation>,
    _permit: Arc<Permit>,
    _scope: Option<araphor_package_runtime::TaskTrackerToken>,
}

impl PackageExec {
    pub(super) async fn guest(
        &self,
        mut evaluation: sdk::Evaluation,
        owner: &CallContext,
        input: Arc<MemoryReservation>,
        permit: Arc<Permit>,
    ) -> Result<(sdk::Evaluation, sdk::Output, Arc<MemoryReservation>)> {
        let artifact = self
            .call
            .bundle
            .artifact(&self.call.package)
            .map_err(external)?;
        let wasm = matches!(
            artifact
                .implementation(&evaluation.export)
                .map_err(external)?,
            PackageImplementationV1::Wasm { .. }
        );
        if wasm {
            evaluation.context.limits =
                WasmExecution::limits(evaluation.context.limits, &owner.runtime.limits().wasm);
        }
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
        let mut limits = evaluation.context.limits;
        let output = if let Some(capacity) = owner.memory.output_capacity() {
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == evaluation.export)
                .ok_or_else(|| {
                    external(araphor_data::PackageErrorCodeV1::Missing.error("package export"))
                })?;
            if wasm {
                // Hold wire buffers, decoding storage, copied arrays and conversion scratch.
                let bytes = (u128::from(limits.max_bytes)
                    + if model.checkpoint.is_some() {
                        u128::from(limits.max_checkpoint_bytes)
                    } else {
                        0
                    })
                    * 4;
                let reservation = if limits.max_bytes == u64::MAX
                    || (model.checkpoint.is_some() && limits.max_checkpoint_bytes == u64::MAX)
                {
                    owner.memory.prepare_output(capacity)?
                } else {
                    owner
                        .memory
                        .reserve_output(usize::try_from(bytes).map_err(|_| limit())?)?
                };
                let transferred = u64::try_from(reservation.size() / 4).map_err(|_| limit())?;
                if transferred == 0 {
                    return Err(limit());
                }
                limits.max_bytes = transferred;
                limits.max_checkpoint_bytes = limits.max_checkpoint_bytes.min(transferred);
                reservation
            } else {
                let reservation = owner.memory.prepare_output(
                    usize::try_from(u128::from(limits.max_bytes).min(capacity as u128))
                        .map_err(|_| limit())?,
                )?;
                // The native decoder charges output and checkpoint to one byte budget.
                let transferred = reservation.size() as u64;
                limits.max_bytes = limits.max_bytes.min(transferred);
                limits.max_checkpoint_bytes = limits.max_checkpoint_bytes.min(transferred);
                reservation
            }
        } else {
            owner.memory.reserve_output(0)?
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
                limits,
                copy_bytes,
                self.prepared.clone(),
                lease,
            )
            .await
            .map_err(external)?;
        Ok((evaluation, result, output))
    }
}
