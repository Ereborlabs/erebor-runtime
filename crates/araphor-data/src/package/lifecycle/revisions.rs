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
        let (mut revision, encoded) = Self::revision_encoding(grant, artifact)?;
        let saved = self.store.package_revision(
            revision.tenant_id,
            &revision.package_id,
            &revision.revision,
        );
        let bytes = if matches!(&saved, Ok(Some(_))) {
            encoded.check_encoding()?;
            None
        } else {
            Some(Self::encode(&encoded)?)
        };
        if let Some(saved) = saved? {
            if saved.dependencies == revision.dependencies
                && Self::decode::<araphor_analysis_sdk::Package>(&saved.descriptor)?
                    == artifact.descriptor
                && Self::decode::<PackageArtifactV1>(&saved.artifact)? == *artifact
            {
                return Ok(saved);
            }
        }
        revision.artifact = match bytes {
            Some(bytes) => bytes,
            None => Self::encode(&encoded)?,
        };
        Ok(revision)
    }

    #[cfg(test)]
    pub(super) fn revision(
        grant: &PackageGrantV1,
        artifact: &PackageArtifactV1,
    ) -> Result<PackageRevisionV1> {
        let (mut revision, encoded) = Self::revision_encoding(grant, artifact)?;
        revision.artifact = Self::encode(&encoded)?;
        Ok(revision)
    }

    fn revision_encoding<'a>(
        grant: &PackageGrantV1,
        artifact: &'a PackageArtifactV1,
    ) -> Result<(
        PackageRevisionV1,
        super::super::bundle::ArtifactEncoding<'a>,
    )> {
        let encoded = artifact.encoding(false)?;
        let dependencies: BTreeSet<_> = artifact
            .descriptor
            .dependencies
            .iter()
            .filter(|dependency| dependency.package != artifact.descriptor.id)
            .map(|dependency| (dependency.package.clone(), dependency.revision.clone()))
            .collect();
        let revision = PackageRevisionV1 {
            tenant_id: grant.selection.tenant_id,
            package_id: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            descriptor: encoded.descriptor.get().as_bytes().to_vec(),
            artifact: Vec::new(),
            dependencies: dependencies
                .into_iter()
                .map(|(package_id, revision)| PackageRevisionRefV1 {
                    package_id,
                    revision,
                })
                .collect(),
        };
        Ok((revision, encoded))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tests::{bundle, Fixture, TestResult};
    use crate::package::PackageImplementationV1;

    #[test]
    fn revision_retry_and_collision() -> TestResult {
        let fixture = Fixture::new()?;
        let artifact = bundle("1", "SELECT 1::UBIGINT AS count")
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
        let changed = bundle("1", "SELECT 2::UBIGINT AS count")
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

    #[test]
    fn revision_retry_preserves_encoding_bound() -> TestResult {
        let fixture = Fixture::new()?;
        let mut artifact = bundle("1", "SELECT 1::UBIGINT AS count")
            .artifacts
            .remove(0);
        artifact.implementations = vec![PackageImplementationV1::Python {
            export: "count".into(),
            artifact: vec![0; MAX_PACKAGE_BYTES / 2],
        }];
        let saved = AnalysisPackageOwner::revision(&fixture.grant, &artifact)?;
        assert!(saved.artifact.len() > MAX_PACKAGE_BYTES);
        assert!(saved.artifact.len() <= crate::analysis::MAX_PACKAGE_BYTES);
        fixture
            .store
            .install_package(std::slice::from_ref(&saved), || Ok(()))?;
        let before = *fixture.store.subscribe_revision().borrow();
        assert_eq!(
            fixture.owner.install_revision(&fixture.grant, &artifact)?,
            saved
        );
        assert_eq!(*fixture.store.subscribe_revision().borrow(), before);
        Ok(())
    }

    #[test]
    fn revision_candidate_error_precedes_saved_decode() -> TestResult {
        let fixture = Fixture::new()?;
        let mut artifact = bundle("1", "SELECT 1::UBIGINT AS count")
            .artifacts
            .remove(0);
        let mut saved = AnalysisPackageOwner::revision(&fixture.grant, &artifact)?;
        saved.artifact = b"{".to_vec();
        fixture
            .store
            .install_package(std::slice::from_ref(&saved), || Ok(()))?;
        let before = *fixture.store.subscribe_revision().borrow();
        artifact.implementations = vec![PackageImplementationV1::Python {
            export: "count".into(),
            artifact: vec![0; MAX_PACKAGE_BYTES],
        }];
        let error = fixture
            .owner
            .install_revision(&fixture.grant, &artifact)
            .err()
            .ok_or("oversize revision accepted")?;
        assert!(matches!(error, crate::Error::PackageEncoding { source, .. }
            if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge)));
        assert_eq!(*fixture.store.subscribe_revision().borrow(), before);
        assert_eq!(
            fixture
                .store
                .package_revision(saved.tenant_id, &saved.package_id, &saved.revision)?,
            Some(saved)
        );
        Ok(())
    }
}
