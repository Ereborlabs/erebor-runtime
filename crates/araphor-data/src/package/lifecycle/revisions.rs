use std::collections::BTreeSet;

use crate::analysis::{PackageRevisionRefV1, PackageRevisionV1};
use crate::Result;

use crate::package::{
    AnalysisPackageOwner, PackageArtifactV1, PackageBundleV1, PackageErrorCodeV1 as Code,
    PackageGrantV1, PackageRefV1,
};

impl AnalysisPackageOwner {
    pub(super) fn install_revision(
        &self,
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let mut revision = Self::revision_metadata(grant, artifact)?;
        let saved = self.store.package_revision(
            revision.tenant_id,
            &revision.package_id,
            &revision.revision,
        );
        if let Some(saved) = saved? {
            if saved.dependencies == revision.dependencies
                && Self::decode::<araphor_analysis_sdk::Package>(&saved.descriptor)?
                    == artifact.descriptor
                && saved.decode_artifact()? == *artifact
            {
                return Ok(saved);
            }
        }
        revision.artifact = super::super::storage::StoredArtifact::encode(artifact)?;
        Ok(revision)
    }

    #[cfg(test)]
    pub(super) fn revision(
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let mut revision = Self::revision_metadata(grant, artifact)?;
        revision.artifact = super::super::storage::StoredArtifact::encode(artifact)?;
        Ok(revision)
    }

    fn revision_metadata(
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let descriptor = artifact.descriptor_bytes()?;
        let dependencies: BTreeSet<_> = artifact
            .descriptor
            .exports
            .iter()
            .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
            .filter(|dependency| dependency.package != artifact.descriptor.id)
            .map(|dependency| (dependency.package.clone(), dependency.revision.clone()))
            .collect();
        let revision = PackageRevisionV1 {
            tenant_id: grant.selection.tenant_id,
            package_id: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            descriptor,
            artifact: Vec::new(),
            dependencies: dependencies
                .into_iter()
                .map(|(package_id, revision)| PackageRevisionRefV1 {
                    package_id,
                    revision,
                })
                .collect(),
        };
        Ok(revision)
    }

    pub(in crate::package) fn load_bundle(
        &self,
        tenant: [u8; 16],
        root: &PackageRefV1,
    ) -> Result<PackageBundleV1> {
        let mut pending = vec![root.clone()];
        let mut seen = BTreeSet::new();
        let mut artifacts = Vec::new();
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
            artifacts.push(record.decode_artifact()?);
            pending.extend(
                record
                    .dependencies
                    .into_iter()
                    .map(|dependency| PackageRefV1 {
                        package_id: dependency.package_id,
                        revision: dependency.revision,
                    }),
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tests::{bundle, Fixture, TestResult};
    use crate::package::PackageImplementationV1;

    #[test]
    fn revision_retry_and_collision() -> TestResult {
        let fixture = Fixture::new()?;
        let artifact = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count")
            .artifacts
            .remove(0);
        let saved = AnalysisPackageOwner::revision(&fixture.grant, &artifact)?;
        fixture
            .store
            .install_package(std::slice::from_ref(&saved), || Ok(()))?;
        let before = *fixture.store.subscribe_revision().borrow();
        assert_eq!(
            fixture.owner.install_revision(&fixture.grant, &artifact)?,
            saved
        );
        let changed = bundle("1", "SELECT 2::BIGINT UNSIGNED AS count")
            .artifacts
            .remove(0);
        let conflicting = fixture.owner.install_revision(&fixture.grant, &changed)?;
        assert_ne!(conflicting, saved);
        assert!(matches!(
            fixture.store.install_package(&[conflicting], || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(
            fixture
                .store
                .package_revision(saved.tenant_id, &saved.package_id, &saved.revision)?,
            Some(saved)
        );
        assert_eq!(*fixture.store.subscribe_revision().borrow(), before);
        Ok(())
    }

    #[tokio::test]
    async fn large_package_roundtrip() -> TestResult {
        let fixture = Fixture::new()?;
        let mut package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
        let artifact = &mut package.artifacts[0];
        artifact.implementations = vec![PackageImplementationV1::Python {
            export: "count".into(),
            artifact: vec![255; 33 * 1024 * 1024],
        }];
        let saved = AnalysisPackageOwner::revision(&fixture.grant, artifact)?;
        assert!(saved.artifact.len() > 32 * 1024 * 1024);
        let response = fixture.install(package.clone(), None).await?;
        assert!(!response.exports[0].active);
        assert!(matches!(
            response.exports[0].readiness,
            crate::package::PackageReadinessV1::Unsupported { .. }
        ));
        let before = *fixture.store.subscribe_revision().borrow();
        assert_eq!(
            fixture
                .owner
                .install_revision(&fixture.grant, &package.artifacts[0])?,
            saved
        );
        assert_eq!(*fixture.store.subscribe_revision().borrow(), before);
        drop(saved);
        let fixture = fixture.reopen()?;
        let restored = fixture.owner.load_bundle([1; 16], &package.root)?;
        assert_eq!(restored.artifacts, package.artifacts);
        let digest = restored.digest()?;
        let bytes = restored.encode()?;
        assert!(bytes.len() > 32 * 1024 * 1024);
        drop(restored);
        let restored = PackageBundleV1::from_bytes(&bytes)?;
        assert_eq!(restored.artifacts, package.artifacts);
        assert_eq!(restored.digest()?, digest);
        Ok(())
    }
}
