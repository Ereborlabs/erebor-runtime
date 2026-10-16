use std::io::{Read as _, Write};

use minicbor::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use wasmtime::{component::Component, Engine};

use crate::Result;

use super::super::{cache::MAX_IMAGE_BYTES, Code};

const MAX_REPLY_BYTES: usize = MAX_IMAGE_BYTES + 128;

#[derive(Decode, Encode)]
#[cbor(array)]
struct CompilerReply<'a> {
    #[n(0)]
    version: u8,
    #[n(1)]
    status: u8,
    #[b(2)]
    #[cbor(with = "minicbor::bytes")]
    image: &'a [u8],
    #[b(3)]
    #[cbor(with = "minicbor::bytes")]
    digest: &'a [u8],
}

#[derive(Debug, snafu::Snafu)]
enum CompilerProtocolError {
    #[snafu(display("component compiler reply framing"))]
    Framing,
    #[snafu(display("component compiler reply version"))]
    Version,
    #[snafu(display("component compiler reply status"))]
    Status,
    #[snafu(display("component compiler reply digest"))]
    Digest,
    #[snafu(display("component compiler reply image"))]
    Image,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component compiler result: {code:?}"))]
struct CompilerResultError {
    code: Code,
}

pub(super) struct CompilerImage {
    bytes: Vec<u8>,
}

impl CompilerImage {
    #[cfg(test)]
    pub(super) fn native_image(&self) -> Result<&[u8]> {
        Ok(self.reply()?.image)
    }

    pub(super) fn write(result: &Result<Vec<u8>>, output: impl Write) -> Result<()> {
        let (status, image) = match result {
            Ok(image) => (0, image.as_slice()),
            Err(
                crate::Error::Data {
                    source: araphor_data::Error::Package { code, .. },
                }
                | crate::Error::PackageWasm { code, .. },
            ) => {
                let status = match code {
                    Code::Invalid => 1,
                    Code::Limit => 2,
                    Code::Unsupported => 3,
                    _ => 4,
                };
                (status, &[][..])
            }
            Err(_) => (4, &[][..]),
        };
        let digest = Sha256::digest(image);
        let reply = CompilerReply {
            version: 1,
            status,
            image,
            digest: if status == 0 { &digest } else { &[] },
        };
        minicbor::encode(reply, minicbor::encode::write::Writer::new(output))
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler reply write",
            })
    }

    pub(super) fn read(mut input: impl std::io::Read) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_REPLY_BYTES + 1)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Limit,
                operation: "component compiler reply allocation",
            })?;
        input
            .by_ref()
            .take((MAX_REPLY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler reply read",
            })?;
        if bytes.len() > MAX_REPLY_BYTES {
            return Err(Code::Limit.error("component compiler reply bytes").into());
        }
        Ok(Self { bytes })
    }

    fn reply(&self) -> Result<CompilerReply<'_>> {
        if minicbor::Decoder::new(&self.bytes).array().ok() != Some(Some(4)) {
            return Err(wasmtime::Error::new(CompilerProtocolError::Framing)).context(
                crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler reply validation",
                },
            );
        }
        let mut decoder = minicbor::Decoder::new(&self.bytes);
        let reply: CompilerReply<'_> =
            decoder
                .decode()
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler reply decode",
                })?;
        let error = if decoder.position() != self.bytes.len() {
            Some(CompilerProtocolError::Framing)
        } else if reply.version != 1 {
            Some(CompilerProtocolError::Version)
        } else if reply.status > 4 {
            Some(CompilerProtocolError::Status)
        } else if reply.image.len() > MAX_IMAGE_BYTES
            || (reply.status != 0 && (!reply.image.is_empty() || !reply.digest.is_empty()))
        {
            Some(CompilerProtocolError::Image)
        } else if reply.status == 0 && &Sha256::digest(reply.image)[..] != reply.digest {
            Some(CompilerProtocolError::Digest)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(wasmtime::Error::new(error)).context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler reply validation",
            });
        }
        Ok(reply)
    }

    #[cfg(test)]
    pub(super) fn component(&self, engine: &Engine) -> Result<Component> {
        self.component_reserved(engine, |_| Ok(()))
            .map(|(component, ())| component)
    }

    #[allow(unsafe_code)]
    pub(super) fn component_reserved<T>(
        &self,
        engine: &Engine,
        reserve: impl FnOnce(usize) -> Result<T>,
    ) -> Result<(Component, T)> {
        let reply = self.reply()?;
        let code = match reply.status {
            0 => None,
            1 => Some(Code::Invalid),
            2 => Some(Code::Limit),
            3 => Some(Code::Unsupported),
            _ => Some(Code::Incomplete),
        };
        if let Some(code) = code {
            return Err(wasmtime::Error::new(CompilerResultError { code })).context(
                crate::PackageWasmSnafu {
                    code,
                    operation: "component compiler result",
                },
            );
        }
        if !matches!(
            Engine::detect_precompiled(reply.image),
            Some(wasmtime::Precompiled::Component)
        ) {
            return Err(wasmtime::Error::new(CompilerProtocolError::Image)).context(
                crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler reply validation",
                },
            );
        }
        let reservation = reserve(reply.image.len())?;
        // This image comes from the current executable through a private pipe.
        // The child makes the image from source. The digest protects the transfer.
        let component = unsafe { Component::deserialize(engine, reply.image) }.context(
            crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler image load",
            },
        )?;
        Ok((component, reservation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn compiler_reply_rejects_corruption() -> TestResult {
        let good = minicbor::to_vec(CompilerReply {
            version: 1,
            status: 2,
            image: &[],
            digest: &[],
        })?;
        CompilerImage::read(good.as_slice())?.reply()?;
        let mut trailing = good.clone();
        trailing.push(0);
        let corrupted = minicbor::to_vec(CompilerReply {
            version: 1,
            status: 0,
            image: b"untrusted native code",
            digest: &[0; 32],
        })?;
        for bytes in [Vec::new(), vec![0], trailing, corrupted] {
            assert!(CompilerImage::read(bytes.as_slice())?.reply().is_err());
        }
        assert!(
            CompilerImage::read(std::io::repeat(0).take((MAX_REPLY_BYTES + 1) as u64)).is_err()
        );
        Ok(())
    }
}
