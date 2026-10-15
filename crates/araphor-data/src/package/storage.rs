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
pub(super) struct MetadataRef<'a> {
    pub(super) implementations: Vec<PackageImplementationV1>,
    pub(super) fixtures: &'a [PackageFixtureV1],
}

impl StoredArtifact {
    pub(crate) fn encode(artifact: &PackageArtifactV1) -> Result<Vec<u8>> {
        let (metadata, binaries) = Self::split(&artifact.implementations, &artifact.fixtures);
        let metadata = serde_json::to_vec(&metadata).context(PackageEncodingSnafu)?;
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(3)
            .and_then(|encoder| encoder.u32(2))
            .and_then(|encoder| encoder.bytes(&metadata))
            .and_then(|encoder| encoder.array(binaries.len() as u64))
            .map_err(|_| Code::Invalid.error("retained package frame"))?;
        for binary in binaries {
            encoder
                .bytes(binary)
                .map_err(|_| Code::Invalid.error("retained package frame"))?;
        }
        Ok(bytes)
    }

    pub(super) fn split<'a>(
        implementations: &'a [PackageImplementationV1],
        fixtures: &'a [PackageFixtureV1],
    ) -> (MetadataRef<'a>, Vec<&'a [u8]>) {
        let mut binaries = Vec::new();
        let implementations = implementations
            .iter()
            .map(|implementation| match implementation {
                PackageImplementationV1::Sql { .. } => implementation.clone(),
                PackageImplementationV1::Wasm { exports, artifact } => {
                    binaries.push(artifact.as_slice());
                    PackageImplementationV1::Wasm {
                        exports: exports.clone(),
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

    pub(crate) fn decode(bytes: &[u8], descriptor: &sdk::Package) -> Result<PackageArtifactV1> {
        let (mut metadata, mut decoder) = Self::metadata(bytes)?;
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

    pub(crate) fn validate(bytes: &[u8]) -> Result<()> {
        Self::metadata(bytes).map(|_| ())
    }

    fn metadata(bytes: &[u8]) -> Result<(Metadata, Decoder<'_>)> {
        let mut decoder = Decoder::new(bytes);
        let invalid = |_| Code::Invalid.error("retained package frame");
        if decoder.array().map_err(invalid)? != Some(3) || decoder.u32().map_err(invalid)? != 2 {
            return Err(Code::Invalid.error("retained package frame"));
        }
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
        let mut remaining = decoder.clone();
        for _ in 0..count {
            remaining.bytes().map_err(invalid)?;
        }
        if remaining.position() != bytes.len() {
            return Err(Code::Invalid.error("retained package trailing bytes"));
        }
        Ok((metadata, decoder))
    }
}
