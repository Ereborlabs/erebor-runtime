use minicbor::{Decoder, Encoder};
use serde::Deserialize;
use snafu::ResultExt as _;

use super::{PackageBundleV1, PackageErrorCodeV1 as Code, PackageRequestV1};
use crate::Result;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum BundleMetadata {
    Install {
        scope_id: String,
        parameters: Option<serde_json::Value>,
    },
    Update {
        scope_id: String,
    },
}

#[derive(Deserialize)]
struct Operation<'a> {
    #[serde(borrow)]
    operation: &'a str,
}

impl PackageRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let metadata = serde_json::to_vec(self).context(crate::PackageEncodingSnafu)?;
        let archive = match self {
            Self::Install { bundle, .. } | Self::Update { bundle, .. } => bundle.encode()?,
            _ => Vec::new(),
        };
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(3)
            .and_then(|e| e.u32(1))
            .and_then(|e| e.bytes(&metadata))
            .and_then(|e| e.bytes(&archive))
            .map_err(|_| Code::Invalid.error("package request encoding"))?;
        Ok(encoder.into_writer())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let invalid = || Code::Invalid.error("package request encoding");
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| invalid())? != Some(3)
            || decoder.u32().map_err(|_| invalid())? != 1
        {
            return Err(invalid());
        }
        let metadata = decoder.bytes().map_err(|_| invalid())?;
        let archive = decoder.bytes().map_err(|_| invalid())?;
        if decoder.position() != bytes.len() {
            return Err(invalid());
        }
        let operation: Operation<'_> =
            serde_json::from_slice(metadata).context(crate::PackageEncodingSnafu)?;
        if matches!(operation.operation, "install" | "update") {
            let metadata: BundleMetadata =
                serde_json::from_slice(metadata).context(crate::PackageEncodingSnafu)?;
            if archive.is_empty() {
                return Err(Code::Invalid.error("package request archive"));
            }
            let bundle = PackageBundleV1::from_bytes(archive)?;
            Ok(match metadata {
                BundleMetadata::Install {
                    scope_id,
                    parameters,
                } => Self::Install {
                    scope_id,
                    parameters,
                    bundle,
                },
                BundleMetadata::Update { scope_id } => Self::Update { scope_id, bundle },
            })
        } else {
            if !archive.is_empty() {
                return Err(Code::Invalid.error("package request archive"));
            }
            serde_json::from_slice(metadata).context(crate::PackageEncodingSnafu)
        }
    }
}

#[cfg(test)]
mod tests;
