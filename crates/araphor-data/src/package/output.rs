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
        Self::codec_result(sdk::wire::Output::encode_model(
            output,
            model,
            sdk::Limits {
                max_bytes: model.limits.max_bytes.min(16 * 1024 * 1024),
                max_checkpoint_bytes: model.limits.max_checkpoint_bytes.min(16 * 1024 * 1024),
                ..model.limits
            },
        ))
    }

    pub fn decode_output(output: &sdk::wire::Output, model: &sdk::Model) -> Result<sdk::Output> {
        Self::codec_result(output.decode_model(model))
    }

    pub(super) fn decode_checkpoint(
        checkpoint: &sdk::wire::Checkpoint,
        model: &sdk::Model,
    ) -> Result<sdk::Checkpoint> {
        Self::codec_result(checkpoint.decode_model(model))
    }

    fn codec_result<T>(result: sdk::Result<T>) -> Result<T> {
        if let Err(sdk::Error::Contract { code, field, .. }) = &result {
            if matches!(code, sdk::ErrorCode::Invalid | sdk::ErrorCode::Limit) {
                if let Some(field) = [
                    "dataset name",
                    "reason code",
                    "reason details",
                    "checkpoint declaration",
                    "checkpoint version",
                    "encoded datasets",
                ]
                .into_iter()
                .find(|name| *name == field.as_str())
                {
                    let code = if *code == sdk::ErrorCode::Limit {
                        Code::Limit
                    } else {
                        Code::Invalid
                    };
                    return Err(code.error(field));
                }
            }
        }
        result.context(crate::AnalysisContractSnafu)
    }
}
