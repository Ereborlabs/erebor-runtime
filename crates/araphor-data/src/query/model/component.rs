use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, QueryOwner, Result};

use super::SqlModelOutputV1;

impl QueryOwner {
    pub(crate) fn evaluate_native(
        &self,
        tenant: [u8; 16],
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        execute: impl FnOnce(
            &AnalysisReadControl,
            &super::super::QueryLimits,
        ) -> Result<(sdk::Output, usize)>,
    ) -> Result<SqlModelOutputV1> {
        let retained = evaluation.allocated_bytes();
        let preflight = self.exchange_preflight(package, evaluation)?;
        self.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| self.budget.component(tenant, capacity, preflight),
            |control, host, lease| {
                control.check()?;
                let output = execute(control, host)?;
                lease.shrink_input(retained)?;
                Ok(output)
            },
        )
    }

    pub(crate) fn evaluate_component(
        &self,
        tenant: [u8; 16],
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        execute: impl FnOnce(
            &AnalysisReadControl,
            &super::super::QueryLimits,
            sdk::wire::Evaluation,
        ) -> Result<(sdk::Output, usize)>,
    ) -> Result<SqlModelOutputV1> {
        let retained = evaluation.allocated_bytes();
        let preflight = self.component_preflight(package, evaluation)?;
        self.evaluate_model_reserved(
            package,
            evaluation,
            control,
            |capacity| self.budget.component(tenant, capacity, preflight),
            |control, host, lease| {
                control.check()?;
                let input = sdk::wire::Evaluation::encode(package, evaluation)
                    .context(crate::AnalysisContractSnafu)?;
                let bytes = retained
                    .checked_add(input.allocated_bytes())
                    .ok_or_else(|| {
                        crate::QueryLimitSnafu {
                            resource: "component input allocation",
                            limit: self.limits.input_capacity,
                        }
                        .build()
                    })?;
                lease.shrink_input(bytes)?;
                control.check()?;
                let output = execute(control, host, input)?;
                lease.shrink_input(retained)?;
                Ok(output)
            },
        )
    }

    fn component_preflight(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
    ) -> Result<usize> {
        self.check_analysis_input(evaluation)?;
        let limits = self.component_limits(evaluation.context.limits);
        if limits != evaluation.context.limits {
            return crate::QueryInvalidSnafu {
                field: "component input limits",
            }
            .fail();
        }
        self.exchange_preflight(package, evaluation)
    }

    fn exchange_preflight(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
    ) -> Result<usize> {
        self.check_analysis_input(evaluation)?;
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
                crate::QueryLimitSnafu {
                    resource: "component input allocation",
                    limit: self.limits.input_capacity,
                }
                .build()
            })
    }
}

#[cfg(test)]
mod tests;
