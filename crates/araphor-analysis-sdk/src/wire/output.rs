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
        Self::encode_parts(
            output,
            checked.model(),
            checked.evaluation().context.limits,
            true,
        )
    }

    /// Encode output values with per-dataset row and batch limits.
    /// The caller must validate the model and output contract.
    pub fn encode_model(
        output: &crate::Output,
        model: &crate::Model,
        limits: crate::Limits,
    ) -> Result<Self> {
        Self::encode_parts(output, model, limits, false)
    }

    fn encode_parts(
        output: &crate::Output,
        model: &crate::Model,
        limits: crate::Limits,
        aggregate: bool,
    ) -> Result<Self> {
        let mut codec = Codec::new(limits, aggregate);
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
                .map(|checkpoint| Checkpoint::encode(checkpoint, model, limits, aggregate))
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
        let output = self.decode_parts(model, limits, true)?;
        model.input(evaluation)?;
        model.output(evaluation, &output)?;
        Ok(output)
    }

    /// Decode output values with per-dataset row and batch limits.
    /// The caller must validate the model and output contract.
    pub fn decode_model(&self, model: &crate::Model) -> Result<crate::Output> {
        self.decode_parts(model, model.limits, false)
    }

    fn decode_parts(
        &self,
        model: &crate::Model,
        limits: crate::Limits,
        aggregate: bool,
    ) -> Result<crate::Output> {
        let mut codec = Codec::new(limits, aggregate);
        let datasets = self
            .datasets
            .iter()
            .map(|data| codec.decode(data, &model.outputs))
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
        Ok(crate::Output {
            datasets,
            evidence: self.evidence.clone(),
            reasons,
            checkpoint: self
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.decode(model, limits, aggregate))
                .transpose()?,
        })
    }
}
