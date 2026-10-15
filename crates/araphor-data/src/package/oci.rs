use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

use araphor_analysis_sdk::{self as sdk, oci};
use snafu::ResultExt as _;

use super::storage::StoredArtifact;
use super::{
    PackageArtifactV1, PackageBundleV1, PackageCheckpointV1, PackageDatasetV1, PackageFixtureV1,
    PackageImplementationV1, PackageInputV1, PackageOutputV1, PackageReasonV1, MAX_PACKAGE_BYTES,
};
use crate::{AnalysisContractSnafu, IoSnafu, Result};

pub(super) struct PackageOci;

#[cfg(test)]
mod tests;

impl PackageOci {
    pub(super) fn layout(bundle: &PackageBundleV1) -> Result<oci::Layout<'_>> {
        let mut artifacts = bundle.artifacts.iter().collect::<Vec<_>>();
        artifacts.sort_by_key(|artifact| artifact.reference());
        let mut layers = Vec::new();
        let mut metadata = Vec::new();
        for artifact in artifacts {
            artifact
                .descriptor
                .validate()
                .context(AnalysisContractSnafu)?;
            let (split, _) = StoredArtifact::split(&artifact.implementations, &[]);
            for implementation in &artifact.implementations {
                Self::implementation_layers(implementation, &mut layers);
            }
            let fixtures = artifact
                .fixtures
                .iter()
                .map(|fixture| Self::fixture(fixture, &mut layers))
                .collect();
            metadata.push(PackageArtifactV1 {
                descriptor: artifact.descriptor.clone(),
                implementations: split.implementations,
                fixtures,
            });
        }
        oci::Layout::new(
            &PackageBundleV1 {
                schema_version: bundle.schema_version,
                root: bundle.root.clone(),
                artifacts: metadata,
            },
            &layers,
            MAX_PACKAGE_BYTES,
        )
        .context(AnalysisContractSnafu)
    }

    fn implementation_layers<'a>(
        implementation: &'a PackageImplementationV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) {
        match implementation {
            PackageImplementationV1::Sql { .. } => {}
            PackageImplementationV1::Wasm { artifact, .. } => layers.push(oci::Layer {
                media_type: oci::WASM_MEDIA_TYPE,
                bytes: artifact,
            }),
            PackageImplementationV1::Python { artifact, .. } => layers.push(oci::Layer {
                media_type: oci::PYTHON_MEDIA_TYPE,
                bytes: artifact,
            }),
            PackageImplementationV1::Native {
                artifact,
                qualification,
                ..
            } => {
                layers.push(oci::Layer {
                    media_type: oci::NATIVE_MEDIA_TYPE,
                    bytes: artifact,
                });
                if let Some(qualification) = qualification {
                    for dependency in &qualification.dependencies {
                        layers.push(oci::Layer {
                            media_type: oci::NATIVE_DEPENDENCY_MEDIA_TYPE,
                            bytes: &dependency.artifact,
                        });
                    }
                }
            }
        }
    }

    fn dataset<'a>(
        data: &'a PackageDatasetV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> PackageDatasetV1 {
        layers.push(oci::Layer {
            media_type: oci::ARROW_IPC_MEDIA_TYPE,
            bytes: &data.ipc,
        });
        PackageDatasetV1 {
            name: data.name.clone(),
            ipc: Vec::new(),
        }
    }

    fn checkpoint<'a>(
        checkpoint: &'a PackageCheckpointV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> PackageCheckpointV1 {
        PackageCheckpointV1 {
            version: checkpoint.version,
            datasets: checkpoint
                .datasets
                .iter()
                .map(|data| Self::dataset(data, layers))
                .collect(),
        }
    }

    fn fixture<'a>(
        fixture: &'a PackageFixtureV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> PackageFixtureV1 {
        PackageFixtureV1 {
            name: fixture.name.clone(),
            export: fixture.export.clone(),
            time_utc_ns: fixture.time_utc_ns,
            seed: fixture.seed,
            parameters: fixture.parameters.clone(),
            inputs: fixture
                .inputs
                .iter()
                .map(|input| PackageInputV1 {
                    data: Self::dataset(&input.data, layers),
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
                .collect(),
            checkpoint: fixture
                .checkpoint
                .as_ref()
                .map(|checkpoint| Self::checkpoint(checkpoint, layers)),
            expected: PackageOutputV1 {
                datasets: fixture
                    .expected
                    .datasets
                    .iter()
                    .map(|data| Self::dataset(data, layers))
                    .collect(),
                evidence: fixture.expected.evidence.clone(),
                reasons: fixture
                    .expected
                    .reasons
                    .iter()
                    .map(|reason| PackageReasonV1 {
                        output: reason.output.clone(),
                        code: reason.code.clone(),
                        details: Self::dataset(&reason.details, layers),
                    })
                    .collect(),
                checkpoint: fixture
                    .expected
                    .checkpoint
                    .as_ref()
                    .map(|checkpoint| Self::checkpoint(checkpoint, layers)),
            },
        }
    }

    pub(super) fn decode(mut content: oci::Content) -> Result<PackageBundleV1> {
        let mut bundle: PackageBundleV1 = content.package().context(AnalysisContractSnafu)?;
        let mut layers = std::mem::take(&mut content.layers).into_iter();
        for artifact in &mut bundle.artifacts {
            for implementation in &mut artifact.implementations {
                match implementation {
                    PackageImplementationV1::Sql { .. } => {}
                    PackageImplementationV1::Wasm { artifact, .. } => {
                        Self::fill(artifact, oci::WASM_MEDIA_TYPE, &mut layers)?
                    }
                    PackageImplementationV1::Python { artifact, .. } => {
                        Self::fill(artifact, oci::PYTHON_MEDIA_TYPE, &mut layers)?
                    }
                    PackageImplementationV1::Native {
                        artifact,
                        qualification,
                        ..
                    } => {
                        Self::fill(artifact, oci::NATIVE_MEDIA_TYPE, &mut layers)?;
                        if let Some(qualification) = qualification {
                            for dependency in &mut qualification.dependencies {
                                Self::fill(
                                    &mut dependency.artifact,
                                    oci::NATIVE_DEPENDENCY_MEDIA_TYPE,
                                    &mut layers,
                                )?;
                            }
                        }
                    }
                }
            }
            for fixture in &mut artifact.fixtures {
                for input in &mut fixture.inputs {
                    Self::fill_dataset(&mut input.data, &mut layers)?;
                }
                if let Some(checkpoint) = &mut fixture.checkpoint {
                    Self::fill_checkpoint(checkpoint, &mut layers)?;
                }
                for data in &mut fixture.expected.datasets {
                    Self::fill_dataset(data, &mut layers)?;
                }
                for reason in &mut fixture.expected.reasons {
                    Self::fill_dataset(&mut reason.details, &mut layers)?;
                }
                if let Some(checkpoint) = &mut fixture.expected.checkpoint {
                    Self::fill_checkpoint(checkpoint, &mut layers)?;
                }
            }
        }
        if layers.next().is_some() {
            return Err(super::PackageErrorCodeV1::Invalid.error("unreferenced OCI layer"));
        }
        if !Self::layout(&bundle)?.matches(&content) {
            return Err(
                super::PackageErrorCodeV1::Invalid.error("noncanonical Araphor OCI package")
            );
        }
        bundle.validate()?;
        Ok(bundle)
    }

    fn fill(
        bytes: &mut Vec<u8>,
        media: &str,
        layers: &mut std::vec::IntoIter<oci::Blob>,
    ) -> Result<()> {
        let layer = layers
            .next()
            .filter(|layer| layer.media_type == media && bytes.is_empty())
            .ok_or_else(|| super::PackageErrorCodeV1::Invalid.error("OCI raw buffer reference"))?;
        *bytes = layer.bytes;
        Ok(())
    }

    fn fill_dataset(
        data: &mut PackageDatasetV1,
        layers: &mut std::vec::IntoIter<oci::Blob>,
    ) -> Result<()> {
        Self::fill(&mut data.ipc, oci::ARROW_IPC_MEDIA_TYPE, layers)
    }

    fn fill_checkpoint(
        checkpoint: &mut PackageCheckpointV1,
        layers: &mut std::vec::IntoIter<oci::Blob>,
    ) -> Result<()> {
        for data in &mut checkpoint.datasets {
            Self::fill_dataset(data, layers)?;
        }
        Ok(())
    }

    pub(super) fn read(path: &Path) -> Result<PackageBundleV1> {
        let root = Self::open_path(path).context(IoSnafu { path })?;
        if root.metadata().context(IoSnafu { path })?.is_dir() {
            let content = oci::Content::read_files(
                |name, limit| {
                    Self::read_file(&root, name, limit).map_err(|source| sdk::Error::Io {
                        path: path.join(name),
                        source,
                        location: snafu::Location::new(file!(), line!(), column!()),
                    })
                },
                MAX_PACKAGE_BYTES,
            )
            .context(AnalysisContractSnafu)?;
            Self::decode(content)
        } else {
            let bytes = Self::read_open(root, MAX_PACKAGE_BYTES).context(IoSnafu { path })?;
            PackageBundleV1::from_bytes(&bytes)
        }
    }

    fn open_path(path: &Path) -> std::io::Result<File> {
        use rustix::fs::{open, openat, Mode, OFlags};
        let mut directory = open(
            if path.is_absolute() { "/" } else { "." },
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let parts = path.components().collect::<Vec<_>>();
        for (index, component) in parts.iter().enumerate() {
            let Component::Normal(name) = component else {
                if matches!(component, Component::RootDir | Component::CurDir) {
                    continue;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "OCI path",
                ));
            };
            let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            if index + 1 != parts.len() {
                flags |= OFlags::DIRECTORY;
            }
            directory = openat(&directory, *name, flags, Mode::empty())?;
        }
        Ok(directory.into())
    }

    fn read_file(root: &File, name: &str, limit: usize) -> std::io::Result<Vec<u8>> {
        use rustix::fs::{openat, Mode, OFlags};
        let mut directory = rustix::io::dup(root)?;
        let parts = name.split('/').collect::<Vec<_>>();
        for (index, part) in parts.iter().enumerate() {
            let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            if index + 1 != parts.len() {
                flags |= OFlags::DIRECTORY;
            }
            directory = openat(&directory, *part, flags, Mode::empty())?;
        }
        Self::read_open(directory.into(), limit)
    }

    fn read_open(file: File, limit: usize) -> std::io::Result<Vec<u8>> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OCI file size or type",
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "OCI file bytes",
            ));
        }
        Ok(bytes)
    }
}
