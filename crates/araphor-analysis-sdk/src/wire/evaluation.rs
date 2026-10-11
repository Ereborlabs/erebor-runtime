use crate::{Error, ErrorCode, Package, Result};

use super::codec::Codec;
use super::{Checkpoint, Evaluation, Input};

impl Evaluation {
    pub fn encode(package: &Package, evaluation: &crate::Evaluation) -> Result<Self> {
        package.validate_evaluation(evaluation)?;
        let limits = evaluation.context.limits;
        let model = Codec::model(package, &evaluation.export, limits)?;
        let mut codec = Codec::new(limits);
        let inputs = evaluation
            .inputs
            .iter()
            .map(|input| {
                Ok(Input {
                    data: codec
                        .encode(&input.data, Codec::schema(&model.inputs, &input.data.name)?)?,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let parameters = evaluation
            .parameters
            .as_ref()
            .map(|parameters| {
                codec
                    .encode(
                        &crate::Dataset {
                            name: "parameters".into(),
                            batches: vec![parameters.clone()],
                        },
                        &model.parameters,
                    )
                    .map(|data| data.arrow_ipc)
            })
            .transpose()?;
        Ok(Self {
            export_name: evaluation.export.clone(),
            inputs,
            parameters,
            context: evaluation.context.clone(),
            checkpoint: evaluation
                .checkpoint
                .as_ref()
                .map(|checkpoint| Checkpoint::encode(checkpoint, model, limits))
                .transpose()?,
        })
    }

    pub fn decode(&self, package: &Package) -> Result<crate::Evaluation> {
        let limits = self.context.limits;
        let model = Codec::model(package, &self.export_name, limits)?;
        let mut codec = Codec::new(limits);
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                Ok(crate::Input {
                    data: codec
                        .decode(&input.data, Codec::schema(&model.inputs, &input.data.name)?)?,
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
                .map(|bytes| codec.single("parameters", bytes, &model.parameters))
                .transpose()?,
            context: self.context.clone(),
            checkpoint: self
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.decode(model, limits))
                .transpose()?,
        };
        package.validate_evaluation(&evaluation)?;
        Ok(evaluation)
    }
}

impl Checkpoint {
    pub(super) fn encode(
        checkpoint: &crate::Checkpoint,
        model: &crate::Model,
        limits: crate::Limits,
    ) -> Result<Self> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "checkpoint declaration"))?;
        let mut codec = Codec::new(crate::Limits {
            max_bytes: limits.max_checkpoint_bytes,
            ..limits
        });
        let datasets = checkpoint
            .datasets
            .iter()
            .map(|data| codec.encode(data, Codec::schema(&spec.datasets, &data.name)?))
            .collect::<Result<_>>()?;
        Ok(Self {
            version: checkpoint.version,
            datasets,
        })
    }

    pub(super) fn decode(
        &self,
        model: &crate::Model,
        limits: crate::Limits,
    ) -> Result<crate::Checkpoint> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "checkpoint declaration"))?;
        if spec.version != self.version {
            return Err(Error::contract(
                ErrorCode::Incompatible,
                "checkpoint version",
            ));
        }
        let mut codec = Codec::new(crate::Limits {
            max_bytes: limits.max_checkpoint_bytes,
            ..limits
        });
        let datasets = self
            .datasets
            .iter()
            .map(|data| codec.decode(data, Codec::schema(&spec.datasets, &data.name)?))
            .collect::<Result<_>>()?;
        Ok(crate::Checkpoint {
            version: self.version,
            datasets,
        })
    }
}
