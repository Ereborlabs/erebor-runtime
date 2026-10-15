use std::io::{self, Write};

use araphor_analysis_sdk as sdk;
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{
    PackageArtifactV1, PackageErrorCodeV1 as Code, PackageFixtureV1, PackageImplementationV1,
};
use crate::{PackageEncodingSnafu, Result};

pub(crate) struct StoredArtifact;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    implementations: Vec<PackageImplementationV1>,
    fixtures: Vec<PackageFixtureV1>,
}

#[cfg(test)]
mod tests;

#[derive(Serialize)]
struct MetadataRef<'a> {
    implementations: Vec<PackageImplementationV1>,
    fixtures: &'a [PackageFixtureV1],
}

#[derive(Default)]
struct EncodingSize(usize);

impl Write for EncodingSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StoredArtifact {
    #[cfg(test)]
    pub(crate) fn encoded_size(artifact: &PackageArtifactV1) -> Result<usize> {
        let encoded = artifact.encoding(false)?;
        Self::count_encoding(&encoded)
    }

    pub(super) fn count_encoding(encoded: &super::bundle::ArtifactEncoding<'_>) -> Result<usize> {
        let (metadata, binaries) = Self::split(encoded.implementations, encoded.fixtures);
        Self::count_parts(
            &encoded.borrowed(&metadata.implementations, metadata.fixtures),
            binaries.into_iter(),
            crate::analysis::MAX_PACKAGE_BYTES as u64,
        )
    }

    fn count_parts<'a>(
        encoded: &super::bundle::ArtifactEncoding<'_>,
        binaries: impl Iterator<Item = &'a [u8]>,
        limit: u64,
    ) -> Result<usize> {
        let mut size = EncodingSize::default();
        let mut writer = sdk::wire::BoundedBuffer::from_writer(&mut size, limit);
        serde_json::to_writer(&mut writer, encoded).context(PackageEncodingSnafu)?;
        // Count the added bytes through the existing bounded writer.
        let block = [0_u8; 8192];
        for binary in binaries {
            let mut added = binary
                .iter()
                .fold(0usize, |total, byte| {
                    total
                        + if *byte < 10 {
                            1
                        } else if *byte < 100 {
                            2
                        } else {
                            3
                        }
                })
                .saturating_add(binary.len().saturating_sub(1));
            while added != 0 {
                let chunk = added.min(block.len());
                writer
                    .write_all(&block[..chunk])
                    .map_err(serde_json::Error::io)
                    .context(PackageEncodingSnafu)?;
                added -= chunk;
            }
        }
        Ok(size.0)
    }

    #[cfg(test)]
    pub(crate) fn encode(artifact: &PackageArtifactV1) -> Result<(Vec<u8>, usize)> {
        let size = Self::encoded_size(artifact)?;
        Ok((Self::encode_sized(artifact, size)?, size))
    }

    pub(crate) fn encode_sized(artifact: &PackageArtifactV1, size: usize) -> Result<Vec<u8>> {
        if size == 0 || size > crate::analysis::MAX_PACKAGE_BYTES {
            return Err(Code::Limit.error("retained package bytes"));
        }
        let (metadata, binaries) = Self::split(&artifact.implementations, &artifact.fixtures);
        let mut output = sdk::wire::BoundedBuffer::new(crate::analysis::MAX_PACKAGE_BYTES as u64);
        serde_json::to_writer(&mut output, &metadata).context(PackageEncodingSnafu)?;
        let metadata = output.finish();
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(4)
            .and_then(|encoder| encoder.u32(1))
            .and_then(|encoder| encoder.u64(size as u64))
            .and_then(|encoder| encoder.bytes(&metadata))
            .and_then(|encoder| encoder.array(binaries.len() as u64))
            .map_err(|_| Code::Invalid.error("retained package frame"))?;
        for binary in binaries {
            encoder
                .bytes(binary)
                .map_err(|_| Code::Invalid.error("retained package frame"))?;
        }
        if bytes.len() > size {
            return Err(Code::Limit.error("retained package frame bytes"));
        }
        Ok(bytes)
    }

    fn split<'a>(
        implementations: &'a [PackageImplementationV1],
        fixtures: &'a [PackageFixtureV1],
    ) -> (MetadataRef<'a>, Vec<&'a [u8]>) {
        let mut binaries = Vec::new();
        let implementations = implementations
            .iter()
            .map(|implementation| match implementation {
                PackageImplementationV1::Sql { .. } => implementation.clone(),
                PackageImplementationV1::Wasm {
                    exports,
                    inputs,
                    artifact,
                } => {
                    binaries.push(artifact.as_slice());
                    PackageImplementationV1::Wasm {
                        exports: exports.clone(),
                        inputs: inputs.clone(),
                        artifact: Vec::new(),
                    }
                }
                PackageImplementationV1::Python { export, artifact } => {
                    binaries.push(artifact.as_slice());
                    PackageImplementationV1::Python {
                        export: export.clone(),
                        artifact: Vec::new(),
                    }
                }
                PackageImplementationV1::Native {
                    export,
                    artifact,
                    qualification,
                } => {
                    binaries.push(artifact.as_slice());
                    let qualification =
                        qualification
                            .as_ref()
                            .map(|qualification| super::native::Qualification {
                                exports: qualification.exports.clone(),
                                inputs: qualification.inputs.clone(),
                                target: qualification.target.clone(),
                                cpu_features: qualification.cpu_features.clone(),
                                contract_version: qualification.contract_version,
                                system_libraries: qualification.system_libraries.clone(),
                                dependencies: qualification
                                    .dependencies
                                    .iter()
                                    .map(|dependency| {
                                        binaries.push(dependency.artifact.as_slice());
                                        super::native::Dependency {
                                            name: dependency.name.clone(),
                                            digest: dependency.digest.clone(),
                                            artifact: Vec::new(),
                                        }
                                    })
                                    .collect(),
                            });
                    PackageImplementationV1::Native {
                        export: export.clone(),
                        artifact: Vec::new(),
                        qualification,
                    }
                }
            })
            .collect();
        (
            MetadataRef {
                implementations,
                fixtures,
            },
            binaries,
        )
    }

    pub(crate) fn frame_size(bytes: &[u8]) -> Result<usize> {
        if bytes.len() > crate::analysis::MAX_PACKAGE_BYTES {
            return Err(Code::Limit.error("retained package frame bytes"));
        }
        let mut decoder = Decoder::new(bytes);
        let invalid = |_| Code::Invalid.error("retained package frame");
        if decoder.array().map_err(invalid)? != Some(4) || decoder.u32().map_err(invalid)? != 1 {
            return Err(Code::Invalid.error("retained package frame"));
        }
        let size = usize::try_from(decoder.u64().map_err(invalid)?)
            .map_err(|_| Code::Limit.error("retained package bytes"))?;
        if size == 0 || size > crate::analysis::MAX_PACKAGE_BYTES || bytes.len() > size {
            return Err(Code::Limit.error("retained package bytes"));
        }
        decoder.bytes().map_err(invalid)?;
        let count = decoder
            .array()
            .map_err(invalid)?
            .ok_or_else(|| Code::Invalid.error("retained package frame"))?;
        if count > bytes.len() as u64 {
            return Err(Code::Invalid.error("retained package binary count"));
        }
        for _ in 0..count {
            decoder.bytes().map_err(invalid)?;
        }
        if decoder.position() != bytes.len() {
            return Err(Code::Invalid.error("retained package trailing bytes"));
        }
        Ok(size)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        descriptor: &sdk::Package,
        encoded_bytes: usize,
    ) -> Result<PackageArtifactV1> {
        let (mut metadata, mut decoder) = Self::metadata(bytes, descriptor, encoded_bytes)?;
        let invalid = |_| Code::Invalid.error("retained package frame");
        for implementation in &mut metadata.implementations {
            let (artifact, qualification) = match implementation {
                PackageImplementationV1::Sql { .. } => continue,
                PackageImplementationV1::Wasm { artifact, .. }
                | PackageImplementationV1::Python { artifact, .. } => (artifact, None),
                PackageImplementationV1::Native {
                    artifact,
                    qualification,
                    ..
                } => (artifact, qualification.as_mut()),
            };
            *artifact = decoder.bytes().map_err(invalid)?.to_vec();
            if let Some(qualification) = qualification {
                for dependency in &mut qualification.dependencies {
                    dependency.artifact = decoder.bytes().map_err(invalid)?.to_vec();
                }
            }
        }
        Ok(PackageArtifactV1 {
            descriptor: descriptor.clone(),
            implementations: metadata.implementations,
            fixtures: metadata.fixtures,
        })
    }

    pub(crate) fn validate(
        bytes: &[u8],
        descriptor: &sdk::Package,
        encoded_bytes: usize,
    ) -> Result<()> {
        Self::metadata(bytes, descriptor, encoded_bytes).map(|_| ())
    }

    fn metadata<'a>(
        bytes: &'a [u8],
        descriptor: &sdk::Package,
        encoded_bytes: usize,
    ) -> Result<(Metadata, Decoder<'a>)> {
        if Self::frame_size(bytes)? != encoded_bytes {
            return Err(Code::Invalid.error("retained package byte count"));
        }
        let mut decoder = Decoder::new(bytes);
        let invalid = |_| Code::Invalid.error("retained package frame");
        decoder.array().map_err(invalid)?;
        decoder.u32().map_err(invalid)?;
        decoder.u64().map_err(invalid)?;
        let metadata: Metadata = serde_json::from_slice(decoder.bytes().map_err(invalid)?)
            .context(PackageEncodingSnafu)?;
        let count = decoder
            .array()
            .map_err(invalid)?
            .ok_or_else(|| Code::Invalid.error("retained package frame"))?;
        let mut consumed = 0_u64;
        for implementation in &metadata.implementations {
            let (artifact, qualification) = match implementation {
                PackageImplementationV1::Sql { .. } => continue,
                PackageImplementationV1::Wasm { artifact, .. }
                | PackageImplementationV1::Python { artifact, .. } => (artifact, None),
                PackageImplementationV1::Native {
                    artifact,
                    qualification,
                    ..
                } => (artifact, qualification.as_ref()),
            };
            if !artifact.is_empty() || consumed >= count {
                return Err(Code::Invalid.error("retained package binaries"));
            }
            consumed += 1;
            if let Some(qualification) = qualification {
                for dependency in &qualification.dependencies {
                    if !dependency.artifact.is_empty() || consumed >= count {
                        return Err(Code::Invalid.error("retained package binaries"));
                    }
                    consumed += 1;
                }
            }
        }
        if consumed != count {
            return Err(Code::Invalid.error("retained package binary count"));
        }
        let encoded = super::bundle::ArtifactEncoding::new(
            descriptor,
            &metadata.implementations,
            &metadata.fixtures,
            false,
        )?;
        let mut counter = decoder.clone();
        let binaries = (0..count).map(|_| counter.bytes());
        let mut raw = Vec::with_capacity(count as usize);
        for binary in binaries {
            raw.push(binary.map_err(invalid)?);
        }
        let canonical = Self::count_parts(&encoded, raw.into_iter(), u64::MAX)?;
        if canonical != encoded_bytes {
            return Err(Code::Invalid.error("retained package encoded size"));
        }
        Ok((metadata, decoder))
    }
}
