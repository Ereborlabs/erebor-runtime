use crate::{Error, ErrorCode, Package, Result};

use super::codec::Codec;
use super::{Checkpoint, Output, ReasonValue};

impl Output {
    pub fn encode(
        package: &Package,
        evaluation: &crate::Evaluation,
        output: &crate::Output,
    ) -> Result<Self> {
        Self::encode_checked(&package.check_evaluation(evaluation)?, output)
    }

    pub(crate) fn encode_checked(
        checked: &crate::CheckedEvaluation<'_>,
        output: &crate::Output,
    ) -> Result<Self> {
        checked.validate_output(output)?;
        let evaluation = checked.evaluation();
        let limits = evaluation.context.limits;
        let model = checked.model();
        let mut codec = Codec::new(limits);
        let datasets = output
            .datasets
            .iter()
            .map(|data| codec.encode(data, Codec::schema(&model.outputs, &data.name)?))
            .collect::<Result<_>>()?;
        let reasons = output
            .reasons
            .iter()
            .map(|reason| {
                let spec = model
                    .reasons
                    .iter()
                    .find(|spec| spec.code == reason.code)
                    .ok_or_else(|| Error::contract(ErrorCode::Invalid, "reason code"))?;
                let details = codec.encode(
                    &crate::Dataset {
                        name: reason.code.clone(),
                        batches: vec![reason.details.clone()],
                    },
                    &spec.details,
                )?;
                Ok(ReasonValue {
                    output: reason.output.clone(),
                    code: reason.code.clone(),
                    details: details.arrow_ipc,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            datasets,
            evidence: output.evidence.clone(),
            reasons,
            checkpoint: output
                .checkpoint
                .as_ref()
                .map(|checkpoint| Checkpoint::encode(checkpoint, model, limits))
                .transpose()?,
        })
    }

    pub fn decode(
        &self,
        package: &Package,
        evaluation: &crate::Evaluation,
    ) -> Result<crate::Output> {
        let limits = evaluation.context.limits;
        let model = package.wire_validator(&evaluation.export, limits)?;
        let mut codec = Codec::new(limits);
        let datasets = self
            .datasets
            .iter()
            .map(|data| codec.decode(data, Codec::schema(&model.outputs, &data.name)?))
            .collect::<Result<_>>()?;
        let reasons = self
            .reasons
            .iter()
            .map(|reason| {
                let spec = model
                    .reasons
                    .iter()
                    .find(|spec| spec.code == reason.code)
                    .ok_or_else(|| Error::contract(ErrorCode::Invalid, "reason code"))?;
                Ok(crate::ReasonValue {
                    output: reason.output.clone(),
                    code: reason.code.clone(),
                    details: codec.single(&reason.code, &reason.details, &spec.details)?,
                })
            })
            .collect::<Result<_>>()?;
        let output = crate::Output {
            datasets,
            evidence: self.evidence.clone(),
            reasons,
            checkpoint: self
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.decode(model, limits))
                .transpose()?,
        };
        model.input(evaluation)?;
        model.output(evaluation, &output)?;
        Ok(output)
    }
}
