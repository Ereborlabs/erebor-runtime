use std::sync::Arc;

use crate::analysis::PackageActivationV1;
use crate::query::QueryLease;
use crate::{QueryOwner, Result};

use super::super::{PackageBundleV1, PackageErrorCodeV1 as Code, PackageRefV1};
use super::InstalledAnalysis;

mod memory;

pub(in crate::package) struct InstalledBundle {
    pub(in crate::package) value: PackageBundleV1,
    digest: String,
    identities: Vec<Vec<Option<super::super::PackageArtifactIdentityV1>>>,
    _lease: QueryLease,
}

pub(super) struct InstalledSnapshot {
    pub(super) pins: Vec<PackageActivationV1>,
    pub(super) bundles: Vec<Arc<InstalledBundle>>,
    _lease: QueryLease,
}

impl InstalledBundle {
    pub(in crate::package) fn new(query: &QueryOwner, value: PackageBundleV1) -> Result<Arc<Self>> {
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
            .collect::<Result<Vec<Vec<_>>>>()?;
        let bytes = memory::BundleMemory::retained(&value, &digest, &identities)?;
        let lease = query.retain_analysis_input(bytes)?;
        Ok(Arc::new(Self {
            value,
            digest,
            identities,
            _lease: lease,
        }))
    }

    pub(in crate::package) fn admission(&self) -> super::super::PackageBundleRef<'_> {
        super::super::PackageBundleRef::retained(&self.value, &self.digest)
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
        let selected = self.value.artifacts[artifact].implementation(export)?;
        let implementation = self.value.artifacts[artifact]
            .implementations
            .iter()
            .position(|implementation| std::ptr::eq(implementation, selected))
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        Ok(self.identities[artifact][implementation].clone())
    }
}

impl InstalledSnapshot {
    pub(super) fn new(
        query: &QueryOwner,
        pins: Vec<PackageActivationV1>,
        bundles: Vec<Arc<InstalledBundle>>,
    ) -> Result<Arc<Self>> {
        let bytes = memory::BundleMemory::snapshot(&pins, &bundles)?;
        let lease = query.retain_analysis_input(bytes)?;
        Ok(Arc::new(Self {
            pins,
            bundles,
            _lease: lease,
        }))
    }

    pub(super) fn bundle(&self, root: &PackageRefV1) -> Result<Arc<InstalledBundle>> {
        self.bundles
            .iter()
            .find(|bundle| bundle.value.root == *root)
            .cloned()
            .ok_or_else(|| Code::Missing.error("installed snapshot bundle"))
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
            return Err(Code::Denied.error("installed snapshot tenant"));
        }
        if let Some(snapshot) = &self.snapshot {
            return snapshot.bundle(root);
        }
        InstalledBundle::new(&self.owner.query, self.owner.load_bundle(tenant, root)?)
    }
}
