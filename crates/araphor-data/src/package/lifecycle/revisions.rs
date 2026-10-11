use std::collections::BTreeSet;

use crate::analysis::{PackageRevisionRefV1, PackageRevisionV1};
use crate::Result;

use crate::package::{
    AnalysisPackageOwner, PackageArtifactV1, PackageBundleV1, PackageErrorCodeV1 as Code,
    PackageGrantV1, PackageRefV1, MAX_PACKAGE_BYTES,
};

impl AnalysisPackageOwner {
    pub(super) fn install_revision(
        &self,
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let revision = Self::revision(grant, artifact)?;
        if let Some(saved) = self.store.package_revision(
            revision.tenant_id,
            &revision.package_id,
            &revision.revision,
        )? {
            if saved.dependencies == revision.dependencies
                && Self::decode::<araphor_analysis_sdk::Package>(&saved.descriptor)?
                    == artifact.descriptor
                && Self::decode::<PackageArtifactV1>(&saved.artifact)? == *artifact
            {
                return Ok(saved);
            }
        }
        Ok(revision)
    }

    pub(super) fn revision(
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let encoded = artifact.encoding(false)?;
        let dependencies: BTreeSet<_> = artifact
            .descriptor
            .dependencies
            .iter()
            .filter(|dependency| dependency.package != artifact.descriptor.id)
            .map(|dependency| (dependency.package.clone(), dependency.revision.clone()))
            .collect();
        Ok(PackageRevisionV1 {
            tenant_id: grant.selection.tenant_id,
            package_id: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            descriptor: encoded.descriptor.get().as_bytes().to_vec(),
            artifact: Self::encode(&encoded)?,
            dependencies: dependencies
                .into_iter()
                .map(|(package_id, revision)| PackageRevisionRefV1 {
                    package_id,
                    revision,
                })
                .collect(),
        })
    }

    pub(in crate::package) fn load_bundle(
        &self,
        tenant: [u8; 16],
        root: &PackageRefV1,
    ) -> Result<PackageBundleV1> {
        let mut pending = vec![root.clone()];
        let mut seen = BTreeSet::new();
        let mut artifacts = Vec::new();
        let mut bytes = 0usize;
        while let Some(reference) = pending.pop() {
            if !seen.insert(reference.clone()) {
                continue;
            }
            if seen.len() > 64 {
                return Err(Code::Limit.error("dependency closure"));
            }
            let record = self
                .store
                .package_revision(tenant, &reference.package_id, &reference.revision)?
                .ok_or_else(|| Code::Missing.error("installed artifact"))?;
            bytes = bytes
                .checked_add(record.artifact.len())
                .filter(|bytes| *bytes <= MAX_PACKAGE_BYTES)
                .ok_or_else(|| Code::Limit.error("installed dependency bytes"))?;
            pending.extend(
                record
                    .dependencies
                    .into_iter()
                    .map(|dependency| PackageRefV1 {
                        package_id: dependency.package_id,
                        revision: dependency.revision,
                    }),
            );
            artifacts.push(Self::decode::<PackageArtifactV1>(&record.artifact)?);
        }
        artifacts.sort_by_key(PackageArtifactV1::reference);
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: root.clone(),
            artifacts,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}
