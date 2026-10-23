use crate::{Error, ErrorCode, Package, Result};

use super::codec::Codec;
use super::{Checkpoint, Dataset, Output, ReasonValue};

impl Output {
    pub fn encode(
        package: &Package,
        evaluation: &crate::Evaluation,
        output: &crate::Output,
    ) -> Result<Self> {
        Self::encode_checked(&package.check_evaluation(evaluation)?, output)
    }

    pub fn encode_checked(
        checked: &crate::CheckedEvaluation<'_>,
        output: &crate::Output,
    ) -> Result<Self> {
        checked.validate_output(output)?;
        Self::encode_parts(output, checked.model())
    }

    /// Encode output values with their declared schemas.
    /// The caller must validate the model and output contract.
    pub fn encode_model(output: &crate::Output, model: &crate::Model) -> Result<Self> {
        Self::encode_parts(output, model)
    }

    fn encode_parts(output: &crate::Output, model: &crate::Model) -> Result<Self> {
        let datasets = output
            .datasets
            .iter()
            .map(|data| Dataset::encode(data, Codec::schema(&model.outputs, &data.name)?))
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
                let details = Dataset::encode(
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
                .map(|checkpoint| Checkpoint::encode(checkpoint, model))
                .transpose()?,
        })
    }

    pub fn decode(
        &self,
        package: &Package,
        evaluation: &crate::Evaluation,
    ) -> Result<crate::Output> {
        let model = package.wire_validator(&evaluation.export)?;
        let output = self.decode_parts(model, None, ErrorCode::Incompatible)?;
        model.input(evaluation)?;
        model.output(evaluation, &output)?;
        Ok(output)
    }

    pub fn decode_bounded(
        &self,
        package: &Package,
        evaluation: &crate::Evaluation,
        copy_bytes: usize,
    ) -> Result<crate::Output> {
        let checked = package.check_evaluation(evaluation)?;
        let output =
            self.decode_parts(checked.model(), Some(copy_bytes), ErrorCode::Incompatible)?;
        checked.validate_output(&output)?;
        if output.allocated_bytes() > copy_bytes {
            return Err(Error::contract(ErrorCode::Limit, "output allocation bytes"));
        }
        Ok(output)
    }

    pub fn decode_retained(
        &self,
        package: &Package,
        export: &str,
        inputs: &std::collections::BTreeMap<String, u64>,
    ) -> Result<crate::Output> {
        let model = package.wire_validator(export)?;
        let output = self.decode_parts(model, None, ErrorCode::Incompatible)?;
        package.validate_retained_output(export, inputs, &output)?;
        Ok(output)
    }

    /// Decode output values with their declared schemas.
    /// The caller must validate the model and output contract.
    pub fn decode_model(&self, model: &crate::Model) -> Result<crate::Output> {
        self.decode_parts(model, None, ErrorCode::Invalid)
    }

    fn decode_parts(
        &self,
        model: &crate::Model,
        copy_bytes: Option<usize>,
        version_error: ErrorCode,
    ) -> Result<crate::Output> {
        let mut codec = Codec::new(copy_bytes);
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
                    details: codec.single(
                        &reason.code,
                        &reason.details,
                        &spec.details,
                        if version_error == ErrorCode::Invalid {
                            "reason details"
                        } else {
                            "single row batch"
                        },
                    )?,
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
                .map(|checkpoint| checkpoint.decode(model, &mut codec, version_error))
                .transpose()?,
        })
    }
}
