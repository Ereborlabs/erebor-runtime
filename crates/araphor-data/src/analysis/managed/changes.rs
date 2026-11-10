use araphor_analysis_sdk as sdk;

use snafu::ResultExt as _;

use super::model::*;
use crate :: { PackageErrorCodeV1 as Code , Result } ;



impl RecordChanges {
    pub(in crate::analysis) fn prepare(
        attempt: &ManagedAttempt,
        call: u64,
        evaluation: &sdk::Evaluation,
        changes: Option<&ManagedChanges>,
        model: &sdk::Model,
    ) -> Result<Option<RecordChanges>> {
        let (Some(contract), Some(changes)) = (&model.change_inputs, changes) else {
            return if model.change_inputs.is_some() || changes.is_some() {
                Err(Code::Invalid.error("managed change inputs"))
            } else {
                Ok(None)
            };
        };
        let reset = contract
            .is_reset(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let expected = attempt.prior_result(call);
        if reset {
            if changes.base.is_some() {
                return Err(Code::Invalid.error("reset change base"));
            }
        } else if changes.base.as_ref() != expected || expected.is_none() {
            return Err(Code::Conflict.error("managed change base"));
        }
        Ok(Some(RecordChanges {
            base: changes.base.clone(),
        }))
    }
}
