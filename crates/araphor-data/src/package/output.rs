use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::Result;

use super::{AnalysisPackageOwner, PackageErrorCodeV1 as Code};

impl AnalysisPackageOwner {
    pub fn output_rows(output: &sdk::wire::Output) -> Result<serde_json::Value> {
        let mut outputs = serde_json::Map::new();
        let mut remaining = 16 * 1024 * 1024;
        for dataset in &output.datasets {
            let data = dataset
                .decode_any(sdk::Limits::default())
                .context(crate::AnalysisContractSnafu)?;
            let mut writer = arrow_json::ArrayWriter::new(sdk::wire::BoundedBuffer::new(remaining));
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

    pub(crate) fn encode_output(
        output: &sdk::Output,
        model: &sdk::Model,
    ) -> Result<sdk::wire::Output> {
        let datasets = Self::encode_datasets(&output.datasets, &model.outputs, model.limits)?;
        let mut remaining = model.limits.max_bytes.min(16 * 1024 * 1024).saturating_sub(
            datasets
                .iter()
                .map(|data| data.arrow_ipc.len() as u64)
                .sum(),
        );
        let mut reasons = Vec::new();
        for reason in &output.reasons {
            let schema = &model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| Code::Invalid.error("reason code"))?
                .details;
            let details = sdk::wire::Dataset::encode(
                &sdk::Dataset {
                    name: reason.code.clone(),
                    batches: vec![reason.details.clone()],
                },
                schema,
                sdk::Limits {
                    max_bytes: remaining,
                    ..model.limits
                },
            )
            .context(crate::AnalysisContractSnafu)?;
            remaining = remaining.saturating_sub(details.arrow_ipc.len() as u64);
            reasons.push(sdk::wire::ReasonValue {
                output: reason.output.clone(),
                code: reason.code.clone(),
                details: details.arrow_ipc,
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
                Ok(sdk::wire::Checkpoint {
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
        Ok(sdk::wire::Output {
            datasets,
            evidence: output.evidence.clone(),
            reasons,
            checkpoint,
        })
    }

    pub fn decode_output(output: &sdk::wire::Output, model: &sdk::Model) -> Result<sdk::Output> {
        let datasets = Self::decode_datasets(&output.datasets, &model.outputs, model.limits)?;
        let mut reasons = Vec::new();
        for reason in &output.reasons {
            let schema = &model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| Code::Invalid.error("reason code"))?
                .details;
            let mut details = sdk::wire::Dataset::decode_ipc(
                &reason.code,
                &reason.details,
                Some(schema),
                model.limits,
            )
            .context(crate::AnalysisContractSnafu)?
            .batches;
            if details.len() != 1 || details[0].num_rows() != 1 {
                return Err(Code::Invalid.error("reason details"));
            }
            reasons.push(sdk::ReasonValue {
                output: reason.output.clone(),
                code: reason.code.clone(),
                details: details.remove(0),
            });
        }
        let checkpoint = output
            .checkpoint
            .as_ref()
            .map(|checkpoint| Self::decode_checkpoint(checkpoint, model))
            .transpose()?;
        Ok(sdk::Output {
            datasets,
            evidence: output.evidence.clone(),
            reasons,
            checkpoint,
        })
    }

    pub(super) fn encode_datasets(
        datasets: &[sdk::Dataset],
        ports: &[sdk::Port],
        limits: sdk::Limits,
    ) -> Result<Vec<sdk::wire::Dataset>> {
        let mut remaining = limits.max_bytes.min(16 * 1024 * 1024);
        datasets
            .iter()
            .map(|dataset| {
                let schema = &ports
                    .iter()
                    .find(|port| port.name == dataset.name)
                    .ok_or_else(|| Code::Invalid.error("dataset name"))?
                    .schema;
                let encoded = sdk::wire::Dataset::encode(
                    dataset,
                    schema,
                    sdk::Limits {
                        max_bytes: remaining,
                        ..limits
                    },
                )
                .context(crate::AnalysisContractSnafu)?;
                remaining = remaining.saturating_sub(encoded.arrow_ipc.len() as u64);
                Ok(encoded)
            })
            .collect()
    }

    pub(super) fn decode_datasets(
        datasets: &[sdk::wire::Dataset],
        ports: &[sdk::Port],
        limits: sdk::Limits,
    ) -> Result<Vec<sdk::Dataset>> {
        let mut total = 0_u64;
        let mut decoded = 0_u64;
        datasets
            .iter()
            .map(|dataset| {
                total = total.saturating_add(dataset.arrow_ipc.len() as u64);
                if total > limits.max_bytes {
                    return Err(Code::Limit.error("encoded datasets"));
                }
                let schema = &ports
                    .iter()
                    .find(|port| port.name == dataset.name)
                    .ok_or_else(|| Code::Invalid.error("dataset name"))?
                    .schema;
                let data = dataset
                    .decode(
                        schema,
                        sdk::Limits {
                            max_bytes: limits.max_bytes.saturating_sub(decoded),
                            ..limits
                        },
                    )
                    .context(crate::AnalysisContractSnafu)?;
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

    pub(super) fn decode_checkpoint(
        checkpoint: &sdk::wire::Checkpoint,
        model: &sdk::Model,
    ) -> Result<sdk::Checkpoint> {
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("checkpoint declaration"))?;
        if spec.version != checkpoint.version {
            return Err(Code::Invalid.error("checkpoint version"));
        }
        let limits = sdk::Limits {
            max_bytes: model.limits.max_checkpoint_bytes,
            ..model.limits
        };
        Ok(sdk::Checkpoint {
            version: checkpoint.version,
            datasets: Self::decode_datasets(&checkpoint.datasets, &spec.datasets, limits)?,
        })
    }
}
