use std::io::{Read as _, Write};

use minicbor::{Decode, Encode};
use snafu::ResultExt as _;

use crate::Result;

use super::super::{admission::MAX_SOURCE_BYTES, Code};

const MAX_REQUEST_BYTES: usize = MAX_SOURCE_BYTES + 32;

#[derive(Decode, Encode)]
#[cbor(array)]
pub(super) struct CompilerRequest<'a> {
    #[n(0)]
    version: u8,
    #[n(1)]
    pub(super) fuel: bool,
    #[b(2)]
    #[cbor(with = "minicbor::bytes")]
    pub(super) source: &'a [u8],
}

pub(super) struct CompilerInput {
    bytes: Vec<u8>,
}

impl CompilerInput {
    pub(super) fn write(fuel: bool, source: &[u8], output: impl Write) -> Result<()> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(Code::Limit.error("component compiler source bytes").into());
        }
        minicbor::encode(
            CompilerRequest {
                version: 1,
                fuel,
                source,
            },
            minicbor::encode::write::Writer::new(output),
        )
        .map_err(wasmtime::Error::new)
        .context(crate::PackageWasmSnafu {
            code: Code::Incomplete,
            operation: "component compiler request write",
        })
    }

    pub(super) fn read(mut input: impl std::io::Read) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_REQUEST_BYTES + 1)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Limit,
                operation: "component compiler request allocation",
            })?;
        input
            .by_ref()
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler request read",
            })?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Code::Limit.error("component compiler request bytes").into());
        }
        Ok(Self { bytes })
    }

    pub(super) fn request(&self) -> Result<CompilerRequest<'_>> {
        if minicbor::Decoder::new(&self.bytes).array().ok() != Some(Some(3)) {
            return Err(Code::Invalid
                .error("component compiler request framing")
                .into());
        }
        let mut decoder = minicbor::Decoder::new(&self.bytes);
        let request: CompilerRequest<'_> =
            decoder
                .decode()
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Invalid,
                    operation: "component compiler request decode",
                })?;
        if decoder.position() != self.bytes.len() || request.version != 1 {
            return Err(Code::Invalid
                .error("component compiler request framing")
                .into());
        }
        if request.source.len() > MAX_SOURCE_BYTES {
            return Err(Code::Limit.error("component compiler source bytes").into());
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests;
