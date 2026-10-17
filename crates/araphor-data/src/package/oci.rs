use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

use araphor_analysis_sdk::{self as sdk, oci};
use snafu::ResultExt as _;

use super::{PackageArtifactV1, PackageBundleV1, PackageFixtureV1, PackageImplementationV1};
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
            metadata.push(Self::metadata(artifact, &mut layers)?);
        }
        oci::Layout::new(
            &PackageBundleV1 {
                schema_version: bundle.schema_version,
                root: bundle.root.clone(),
                artifacts: metadata,
            },
            &layers,
        )
        .context(AnalysisContractSnafu)
    }

    pub(super) fn artifact_layout(artifact: &PackageArtifactV1) -> Result<oci::Layout<'_>> {
        let mut layers = Vec::new();
        let metadata = Self::metadata(artifact, &mut layers)?;
        oci::Layout::new(&metadata, &layers).context(AnalysisContractSnafu)
    }

    fn metadata<'a>(
        artifact: &'a PackageArtifactV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> Result<PackageArtifactV1> {
        artifact
            .descriptor
            .validate()
            .context(AnalysisContractSnafu)?;
        Ok(PackageArtifactV1 {
            descriptor: artifact.descriptor.clone(),
            implementations: artifact
                .implementations
                .iter()
                .map(|implementation| Self::implementation(implementation, layers))
                .collect(),
            fixtures: artifact
                .fixtures
                .iter()
                .map(|fixture| Self::fixture(fixture, layers))
                .collect(),
        })
    }

    fn implementation<'a>(
        implementation: &'a PackageImplementationV1,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> PackageImplementationV1 {
        match implementation {
            PackageImplementationV1::Sql { .. } => implementation.clone(),
            PackageImplementationV1::Wasm { exports, artifact } => PackageImplementationV1::Wasm {
                exports: exports.clone(),
                artifact: Self::layer(layers, oci::WASM_MEDIA_TYPE, artifact),
            },
            PackageImplementationV1::Python { export, artifact } => {
                PackageImplementationV1::Python {
                    export: export.clone(),
                    artifact: Self::layer(layers, oci::PYTHON_MEDIA_TYPE, artifact),
                }
            }
            PackageImplementationV1::Native {
                export,
                artifact,
                qualification,
            } => PackageImplementationV1::Native {
                export: export.clone(),
                artifact: Self::layer(layers, oci::NATIVE_MEDIA_TYPE, artifact),
                qualification: qualification.as_ref().map(|qualification| {
                    super::native::Qualification {
                        exports: qualification.exports.clone(),
                        target: qualification.target.clone(),
                        cpu_features: qualification.cpu_features.clone(),
                        contract_version: qualification.contract_version,
                        system_libraries: qualification.system_libraries.clone(),
                        dependencies: qualification
                            .dependencies
                            .iter()
                            .map(|dependency| super::native::Dependency {
                                name: dependency.name.clone(),
                                digest: dependency.digest.clone(),
                                artifact: Self::layer(
                                    layers,
                                    oci::NATIVE_DEPENDENCY_MEDIA_TYPE,
                                    &dependency.artifact,
                                ),
                            })
                            .collect(),
                    }
                }),
            },
        }
    }

    fn layer<'a>(
        layers: &mut Vec<oci::Layer<'a>>,
        media_type: &'static str,
        bytes: &'a [u8],
    ) -> Vec<u8> {
        layers.push(oci::Layer { media_type, bytes });
        Vec::new()
    }

    fn dataset<'a>(
        data: &'a sdk::wire::Dataset,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> sdk::wire::Dataset {
        sdk::wire::Dataset {
            name: data.name.clone(),
            arrow_ipc: Self::layer(layers, oci::ARROW_IPC_MEDIA_TYPE, &data.arrow_ipc),
        }
    }

    fn checkpoint<'a>(
        checkpoint: &'a sdk::wire::Checkpoint,
        layers: &mut Vec<oci::Layer<'a>>,
    ) -> sdk::wire::Checkpoint {
        sdk::wire::Checkpoint {
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
                .map(|input| sdk::wire::Input {
                    data: Self::dataset(&input.data, layers),
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
                .collect(),
            checkpoint: fixture
                .checkpoint
                .as_ref()
                .map(|checkpoint| Self::checkpoint(checkpoint, layers)),
            expected: sdk::wire::Output {
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
                    .map(|reason| sdk::wire::ReasonValue {
                        output: reason.output.clone(),
                        code: reason.code.clone(),
                        details: Self::layer(layers, oci::ARROW_IPC_MEDIA_TYPE, &reason.details),
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
        Self::fill_artifacts(&mut bundle.artifacts, &mut content)?;
        if !Self::layout(&bundle)?.matches(&content) {
            return Err(
                super::PackageErrorCodeV1::Invalid.error("noncanonical Araphor OCI package")
            );
        }
        bundle.validate()?;
        Ok(bundle)
    }

    pub(super) fn decode_artifact(mut content: oci::Content) -> Result<PackageArtifactV1> {
        let mut artifact = content.package().context(AnalysisContractSnafu)?;
        Self::fill_artifacts(std::slice::from_mut(&mut artifact), &mut content)?;
        if !Self::artifact_layout(&artifact)?.matches(&content) {
            return Err(
                super::PackageErrorCodeV1::Invalid.error("noncanonical Araphor OCI artifact")
            );
        }
        Ok(artifact)
    }

    fn fill_artifacts(
        artifacts: &mut [PackageArtifactV1],
        content: &mut oci::Content,
    ) -> Result<()> {
        let mut layers = std::mem::take(&mut content.layers).into_iter();
        for artifact in artifacts {
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
                    Self::fill(&mut reason.details, oci::ARROW_IPC_MEDIA_TYPE, &mut layers)?;
                }
                if let Some(checkpoint) = &mut fixture.expected.checkpoint {
                    Self::fill_checkpoint(checkpoint, &mut layers)?;
                }
            }
        }
        if layers.next().is_some() {
            return Err(super::PackageErrorCodeV1::Invalid.error("unreferenced OCI layer"));
        }
        Ok(())
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
        data: &mut sdk::wire::Dataset,
        layers: &mut std::vec::IntoIter<oci::Blob>,
    ) -> Result<()> {
        Self::fill(&mut data.arrow_ipc, oci::ARROW_IPC_MEDIA_TYPE, layers)
    }

    fn fill_checkpoint(
        checkpoint: &mut sdk::wire::Checkpoint,
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
            let content = oci::Content::read_files(|name| {
                Self::read_file(&root, name).map_err(|source| sdk::Error::Io {
                    path: path.join(name),
                    source,
                    location: snafu::Location::new(file!(), line!(), column!()),
                })
            })
            .context(AnalysisContractSnafu)?;
            Self::decode(content)
        } else {
            let bytes = Self::read_open(root).context(IoSnafu { path })?;
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

    fn read_file(root: &File, name: &str) -> std::io::Result<Vec<u8>> {
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
        Self::read_open(directory.into())
    }

    fn read_open(mut file: File) -> std::io::Result<Vec<u8>> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OCI file type",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}
