use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::Result;

use super::{
    PackageCheckpointV1, PackageDatasetV1, PackageErrorCodeV1 as Code, PackageOutputV1,
    PackageReasonV1,
};

impl PackageOutputV1 {
    pub fn json_rows(&self) -> Result<serde_json::Value> {
        let mut outputs = serde_json::Map::new();
        let mut remaining = 16 * 1024 * 1024;
        for dataset in &self.datasets {
            let data = dataset.decode_any(sdk::Limits::default())?;
            let mut writer =
                arrow_json::ArrayWriter::new(super::wire::PackageBuffer::new(remaining));
            for batch in data.batches {
                writer.write(&batch).context(crate::PackageArrowSnafu)?;
            }
            writer.finish().context(crate::PackageArrowSnafu)?;
            let bytes = writer.into_inner().finish();
            remaining = remaining.saturating_sub(bytes.len() as u64);
            let value = serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
            outputs.insert(dataset.name.clone(), value);
        }
        Ok(serde_json::Value::Object(outputs))
    }

    pub fn encode(output: &sdk::Output, model: &sdk::Model) -> Result<Self> {
        let datasets = Self::encode_datasets(&output.datasets, &model.outputs, model.limits)?;
        let mut remaining = model
            .limits
            .max_bytes
            .min(16 * 1024 * 1024)
            .saturating_sub(datasets.iter().map(|data| data.ipc.len() as u64).sum());
        let mut reasons = Vec::new();
        for reason in &output.reasons {
            let schema = &model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| Code::Invalid.error("reason code"))?
                .details;
            let details = PackageDatasetV1::encode(
                &sdk::Dataset {
                    name: reason.code.clone(),
                    batches: vec![reason.details.clone()],
                },
                schema,
                sdk::Limits {
                    max_bytes: remaining,
                    ..model.limits
                },
            )?;
            remaining = remaining.saturating_sub(details.ipc.len() as u64);
            reasons.push(PackageReasonV1 {
                output: reason.output.clone(),
                code: reason.code.clone(),
                details,
            });
        }
        let checkpoint = output
            .checkpoint
            .as_ref()
            .map(|checkpoint| {
                let spec = model
                    .checkpoint
                    .as_ref()
                    .ok_or_else(|| Code::Invalid.error("checkpoint declaration"))?;
                Ok(PackageCheckpointV1 {
                    version: checkpoint.version,
                    datasets: Self::encode_datasets(
                        &checkpoint.datasets,
                        &spec.datasets,
                        sdk::Limits {
                            max_bytes: model.limits.max_checkpoint_bytes,
                            ..model.limits
                        },
                    )?,
                })
            })
            .transpose()?;
        Ok(Self {
            datasets,
            evidence: output.evidence.clone(),
            reasons,
            checkpoint,
        })
    }

    pub fn decode(&self, model: &sdk::Model) -> Result<sdk::Output> {
        let datasets = Self::decode_datasets(&self.datasets, &model.outputs, model.limits)?;
        let mut reasons = Vec::new();
        for reason in &self.reasons {
            let schema = &model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| Code::Invalid.error("reason code"))?
                .details;
            let mut details = reason.details.decode(schema, model.limits)?.batches;
            if details.len() != 1 || details[0].num_rows() != 1 {
                return Err(Code::Invalid.error("reason details"));
            }
            reasons.push(sdk::ReasonValue {
                output: reason.output.clone(),
                code: reason.code.clone(),
                details: details.remove(0),
            });
        }
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.decode(model))
            .transpose()?;
        Ok(sdk::Output {
            datasets,
            evidence: self.evidence.clone(),
            reasons,
            checkpoint,
        })
    }

    pub(super) fn encode_datasets(
        datasets: &[sdk::Dataset],
        ports: &[sdk::Port],
        limits: sdk::Limits,
    ) -> Result<Vec<PackageDatasetV1>> {
        let mut remaining = limits.max_bytes.min(16 * 1024 * 1024);
        datasets
            .iter()
            .map(|dataset| {
                let schema = &ports
                    .iter()
                    .find(|port| port.name == dataset.name)
                    .ok_or_else(|| Code::Invalid.error("dataset name"))?
                    .schema;
                let encoded = PackageDatasetV1::encode(
                    dataset,
                    schema,
                    sdk::Limits {
                        max_bytes: remaining,
                        ..limits
                    },
                )?;
                remaining = remaining.saturating_sub(encoded.ipc.len() as u64);
                Ok(encoded)
            })
            .collect()
    }

    pub(super) fn decode_datasets(
        datasets: &[PackageDatasetV1],
        ports: &[sdk::Port],
        limits: sdk::Limits,
    ) -> Result<Vec<sdk::Dataset>> {
        let mut total = 0_u64;
        let mut decoded = 0_u64;
        datasets
            .iter()
            .map(|dataset| {
                total = total.saturating_add(dataset.ipc.len() as u64);
                if total > limits.max_bytes {
                    return Err(Code::Limit.error("encoded datasets"));
                }
                let schema = &ports
                    .iter()
                    .find(|port| port.name == dataset.name)
                    .ok_or_else(|| Code::Invalid.error("dataset name"))?
                    .schema;
                let data = dataset.decode(
                    schema,
                    sdk::Limits {
                        max_bytes: limits.max_bytes.saturating_sub(decoded),
                        ..limits
                    },
                )?;
                decoded = decoded.saturating_add(
                    data.batches
                        .iter()
                        .map(|batch| batch.get_array_memory_size() as u64)
                        .sum(),
                );
                Ok(data)
            })
            .collect()
    }
}

impl PackageCheckpointV1 {
    pub(super) fn decode(&self, model: &sdk::Model) -> Result<sdk::Checkpoint> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("checkpoint declaration"))?;
        if spec.version != self.version {
            return Err(Code::Invalid.error("checkpoint version"));
        }
        let limits = sdk::Limits {
            max_bytes: model.limits.max_checkpoint_bytes,
            ..model.limits
        };
        Ok(sdk::Checkpoint {
            version: self.version,
            datasets: PackageOutputV1::decode_datasets(&self.datasets, &spec.datasets, limits)?,
        })
    }
}
