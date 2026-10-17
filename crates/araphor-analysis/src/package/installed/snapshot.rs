use std::sync::Arc;

use crate::analysis::PackageActivationV1;
use crate::model::AdmittedExport;
use crate::{Engine, Result};
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::memory::Memory;

use super::super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageBundleV1, PackageErrorCodeV1 as Code,
    PackageRefV1,
};
use super::InstalledAnalysis;

mod memory;

pub(in crate::package) struct InstalledBundle {
    pub(in crate::package) value: PackageBundleV1,
    digest: String,
    identities: Vec<Vec<Option<super::super::PackageArtifactIdentityV1>>>,
    programs: Vec<Vec<Option<AdmittedExport>>>,
    _memory: MemoryReservation,
}

pub(super) struct InstalledSnapshot {
    pub(super) pins: Vec<PackageActivationV1>,
    pub(super) bundles: Vec<Arc<InstalledBundle>>,
    _memory: MemoryReservation,
}

impl InstalledBundle {
    pub(in crate::package) fn new(
        query: &Engine,
        value: PackageBundleV1,
        memory: &Memory,
    ) -> Result<Arc<Self>> {
        let digest = value.digest()?;
        let identities = value
            .artifacts
            .iter()
            .map(|artifact| {
                artifact
                    .implementations
                    .iter()
                    .map(|implementation| implementation.identity())
                    .collect()
            })
            .collect::<araphor_data::Result<Vec<Vec<_>>>>()?;
        let bytes = memory::BundleMemory::retained(&value, &digest, &identities, &Vec::new())?;
        let mut bundle = Self {
            value,
            digest,
            identities,
            programs: Vec::new(),
            _memory: memory.reserve_input(bytes)?,
        };
        bundle._memory.try_grow(
            bundle.value.artifacts.len() * std::mem::size_of::<Vec<Option<AdmittedExport>>>(),
        )?;
        bundle.programs.reserve_exact(bundle.value.artifacts.len());
        for artifact in &bundle.value.artifacts {
            let count = artifact.descriptor.exports.len();
            bundle
                ._memory
                .try_grow(count * std::mem::size_of::<Option<AdmittedExport>>())?;
            let mut entries = Vec::with_capacity(count);
            for model in &artifact.descriptor.exports {
                let program = match AdmittedExport::compile(query, artifact, model) {
                    Ok(program) => program,
                    Err(crate::Error::Data {
                        source:
                            araphor_data::Error::Package {
                                code: Code::Unsupported,
                                ..
                            },
                    }) => {
                        entries.push(None);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                bundle._memory.try_grow(program.allocated_bytes())?;
                entries.push(Some(program));
            }
            bundle.programs.push(entries);
        }
        Ok(Arc::new(bundle))
    }

    pub(in crate::package) fn admission(&self) -> super::super::PackageBundleRef<'_> {
        super::super::PackageBundleRef::retained(&self.value, &self.digest)
    }

    pub(in crate::package) fn export(
        &self,
        package: &str,
        revision: &str,
        export: &str,
    ) -> Result<(
        &PackageArtifactV1,
        &araphor_analysis_sdk::Model,
        &AdmittedExport,
    )> {
        let index = self
            .value
            .artifacts
            .iter()
            .position(|artifact| {
                artifact.descriptor.id == package && artifact.descriptor.revision == revision
            })
            .ok_or_else(|| Code::Missing.error("installed artifact"))?;
        let artifact = &self.value.artifacts[index];
        let model = artifact
            .descriptor
            .exports
            .iter()
            .position(|model| model.name == export)
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        let program = self.programs[index][model]
            .as_ref()
            .ok_or_else(|| Code::Unsupported.error("model target"))?;
        Ok((artifact, &artifact.descriptor.exports[model], program))
    }

    pub(in crate::package) fn clock(
        &self,
        artifact: &PackageArtifactV1,
        model: &araphor_analysis_sdk::Model,
    ) -> Result<super::super::owner::ClockDependency> {
        use super::super::owner::ClockDependency;
        let (_, _, admitted) = self.export(
            &artifact.descriptor.id,
            &artifact.descriptor.revision,
            &model.name,
        )?;
        Ok(
            if admitted.implementation(artifact)?.target() != "sql" || admitted.model_clock() {
                ClockDependency::Model
            } else if admitted.input_clock() {
                ClockDependency::Inputs
            } else {
                ClockDependency::None
            },
        )
    }

    pub(super) fn identity(
        &self,
        package: &str,
        export: &str,
    ) -> Result<Option<super::super::PackageArtifactIdentityV1>> {
        let artifact = self
            .value
            .artifacts
            .iter()
            .position(|artifact| artifact.descriptor.id == package)
            .ok_or_else(|| Code::Missing.error("installed artifact"))?;
        let model = self.value.artifacts[artifact]
            .descriptor
            .exports
            .iter()
            .position(|model| model.name == export)
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        let implementation = self.programs[artifact][model]
            .as_ref()
            .and_then(AdmittedExport::implementation_index)
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        Ok(self.identities[artifact][implementation].clone())
    }
}

impl AnalysisPackageOwner {
    pub(in crate::package) fn load_installed(
        &self,
        tenant: [u8; 16],
        root: &PackageRefV1,
    ) -> Result<Arc<InstalledBundle>> {
        InstalledBundle::new(
            &self.query,
            self.load_bundle(tenant, root, None)?,
            self.query.memory(),
        )
    }
}

impl InstalledSnapshot {
    pub(super) fn new(
        query: &Engine,
        pins: Vec<PackageActivationV1>,
        bundles: Vec<Arc<InstalledBundle>>,
    ) -> Result<Arc<Self>> {
        let bytes = memory::BundleMemory::snapshot(&pins, &bundles)?;
        let memory = query.memory().reserve_input(bytes)?;
        Ok(Arc::new(Self {
            pins,
            bundles,
            _memory: memory,
        }))
    }

    pub(super) fn bundle(&self, root: &PackageRefV1) -> Result<Arc<InstalledBundle>> {
        self.bundles
            .iter()
            .find(|bundle| bundle.value.root == *root)
            .cloned()
            .ok_or_else(|| Code::Missing.error("installed snapshot bundle").into())
    }
}

impl InstalledAnalysis {
    pub(super) fn pins(&self) -> &[PackageActivationV1] {
        self.snapshot
            .as_ref()
            .map_or(&[], |snapshot| snapshot.pins.as_slice())
    }

    pub(super) fn bundle(
        &self,
        tenant: [u8; 16],
        root: &PackageRefV1,
    ) -> Result<Arc<InstalledBundle>> {
        if self.tenant.is_some_and(|value| value != tenant) {
            return Err(Code::Denied.error("installed snapshot tenant").into());
        }
        if let Some(snapshot) = &self.snapshot {
            return snapshot.bundle(root);
        }
        self.owner.load_installed(tenant, root)
    }
}
