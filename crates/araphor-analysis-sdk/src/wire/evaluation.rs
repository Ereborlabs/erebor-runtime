use crate::{Error, ErrorCode, Package, Result};

use super::codec::Codec;
use super::{Checkpoint, Dataset, Evaluation, Input};

impl crate::CheckedEvaluation<'_> {
    pub fn encode(&self) -> Result<Evaluation> {
        let model = self.model();
        let evaluation = self.evaluation();
        let inputs = evaluation
            .inputs
            .iter()
            .map(|input| {
                Ok(Input {
                    data: Dataset::encode(
                        &input.data,
                        Codec::schema(
                            model.inputs.iter().map(|input| &input.port),
                            &input.data.name,
                        )?,
                    )?,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let parameters = evaluation
            .parameters
            .as_ref()
            .map(|parameters| {
                Dataset::encode(
                    &crate::Dataset {
                        name: "parameters".into(),
                        batches: vec![parameters.clone()],
                    },
                    &model.parameters,
                )
                .map(|data| data.arrow_ipc)
            })
            .transpose()?;
        Ok(Evaluation {
            export_name: evaluation.export.clone(),
            inputs,
            parameters,
            context: evaluation.context.clone(),
            checkpoint: evaluation
                .checkpoint
                .as_ref()
                .map(|checkpoint| Checkpoint::encode(checkpoint, model))
                .transpose()?,
        })
    }
}

impl Evaluation {
    pub fn decode(&self, package: &Package) -> Result<crate::Evaluation> {
        self.decode_validated(package)
            .map(|(evaluation, _)| evaluation)
    }

    pub(crate) fn decode_validated<'a>(
        &self,
        package: &'a Package,
    ) -> Result<(crate::Evaluation, &'a crate::Model)> {
        let model = package.wire_validator(&self.export_name)?;
        let mut codec = Codec::new(None);
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                Ok(crate::Input {
                    data: codec
                        .decode(&input.data, model.inputs.iter().map(|input| &input.port))?,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let evaluation = crate::Evaluation {
            export: self.export_name.clone(),
            inputs,
            parameters: self
                .parameters
                .as_ref()
                .map(|bytes| {
                    codec.single("parameters", bytes, &model.parameters, "single row batch")
                })
                .transpose()?,
            context: self.context.clone(),
            checkpoint: self
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.decode(model, &mut codec, ErrorCode::Incompatible))
                .transpose()?,
        };
        model.input(&evaluation)?;
        Ok((evaluation, model))
    }
}

impl Checkpoint {
    /// Decode checkpoint values with their declared schemas.
    /// The caller must validate the model and checkpoint contract.
    pub fn decode_model(&self, model: &crate::Model) -> Result<crate::Checkpoint> {
        self.decode(model, &mut Codec::new(None), ErrorCode::Invalid)
    }

    pub(super) fn encode(checkpoint: &crate::Checkpoint, model: &crate::Model) -> Result<Self> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "checkpoint declaration"))?;
        let datasets = checkpoint
            .datasets
            .iter()
            .map(|data| Dataset::encode(data, Codec::schema(&spec.datasets, &data.name)?))
            .collect::<Result<_>>()?;
        Ok(Self {
            version: checkpoint.version,
            datasets,
        })
    }

    pub(super) fn decode(
        &self,
        model: &crate::Model,
        codec: &mut Codec,
        version_error: ErrorCode,
    ) -> Result<crate::Checkpoint> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "checkpoint declaration"))?;
        if spec.version != self.version {
            return Err(Error::contract(version_error, "checkpoint version"));
        }
        let datasets = self
            .datasets
            .iter()
            .map(|data| codec.decode(data, &spec.datasets))
            .collect::<Result<_>>()?;
        Ok(crate::Checkpoint {
            version: self.version,
            datasets,
        })
    }
}
