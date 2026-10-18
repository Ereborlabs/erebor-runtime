use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::{AnalysisPackageOwner, Result};

impl AnalysisPackageOwner {
    pub(crate) fn component_limits(&self, mut limits: sdk::Limits) -> sdk::Limits {
        limits.max_bytes = limits.max_bytes.min(self.query.limits().input_bytes as u64);
        crate::package::wasm::WasmExecution::limits(limits, &self.limits.wasm)
    }

    pub(crate) fn exchange_preflight(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
    ) -> Result<usize> {
        if evaluation.allocated_bytes() > self.query.limits().input_bytes {
            return crate::ModelLimitSnafu {
                resource: "analysis input memory",
                limit: self.query.limits().input_bytes,
            }
            .fail();
        }
        // Reserve retained arrays, transport copies, and vector growth before execution.
        let scratch = evaluation
            .encoding_scratch_bytes()
            .context(crate::AnalysisContractSnafu)?;
        evaluation
            .allocated_bytes()
            .checked_add(scratch)
            .and_then(|bytes| bytes.checked_mul(4))
            // Reserve schema builder growth, its message copy, and padding.
            .and_then(|bytes| {
                package
                    .allocated_bytes()
                    .checked_mul(4)
                    .and_then(|scratch| bytes.checked_add(scratch))
            })
            .ok_or_else(|| {
                crate::ModelLimitSnafu {
                    resource: "component input allocation",
                    limit: self.query.limits().input_bytes,
                }
                .build()
            })
    }
}

#[cfg(test)]
mod tests;
