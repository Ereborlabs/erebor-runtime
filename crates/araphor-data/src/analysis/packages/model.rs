use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageRevisionRefV1 {
    pub package_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageRevisionV1 {
    pub tenant_id: [u8; 16],
    pub package_id: String,
    pub revision: String,
    pub descriptor: Vec<u8>,
    pub artifact: Vec<u8>,
    pub dependencies: Vec<PackageRevisionRefV1>,
}

impl PackageRevisionV1 {
    pub(in crate::analysis) fn validate_installation(
        revisions: &[Self],
        root: &std::path::Path,
    ) -> crate::Result<()> {
        if revisions.is_empty() {
            return crate::AnalysisStore::reject_path(root, "the package closure is empty");
        }
        let tenant = revisions[0].tenant_id;
        let mut keys = std::collections::BTreeSet::new();
        for package in revisions {
            if package.tenant_id != tenant
                || package.package_id.is_empty()
                || package.package_id.len() > 256
                || package.revision.is_empty()
                || package.revision.len() > 4096
                || package.descriptor.is_empty()
                || package.artifact.is_empty()
                || !keys.insert((&package.package_id, &package.revision))
            {
                return crate::AnalysisStore::reject_path(root, "the package closure is invalid");
            }
        }
        for package in revisions {
            package.decode_artifact()?;
        }
        Ok(())
    }

    pub fn from_artifact(
        artifact: &crate::PackageArtifactV1,
        tenant_id: [u8; 16],
    ) -> crate::Result<Self> {
        let dependencies = Self::dependency_keys(&artifact.descriptor);
        Ok(Self {
            tenant_id,
            package_id: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            descriptor: artifact.descriptor_bytes()?,
            artifact: Vec::new(),
            dependencies: dependencies
                .into_iter()
                .map(|(package_id, revision)| PackageRevisionRefV1 {
                    package_id: package_id.into(),
                    revision: revision.into(),
                })
                .collect(),
        })
    }

    pub fn from_bundle(
        bundle: &crate::PackageBundle,
        tenant: [u8; 16],
    ) -> crate::Result<Vec<Self>> {
        if tenant == [0; 16] {
            return Err(crate::PackageErrorCodeV1::Invalid.error("package revision tenant"));
        }
        let bundle = bundle.bundle();
        bundle
            .artifacts
            .iter()
            .map(|artifact| {
                let mut revision = Self::from_artifact(artifact, tenant)?;
                revision.artifact = artifact.encode()?;
                Ok(revision)
            })
            .collect()
    }

    pub fn decode_artifact(&self) -> crate::Result<crate::PackageArtifactV1> {
        use snafu::ResultExt as _;
        let descriptor: araphor_analysis_sdk::Package =
            serde_json::from_slice(&self.descriptor).context(crate::PackageEncodingSnafu)?;
        let artifact = crate::PackageArtifactV1::from_bytes(&self.artifact)?;
        if artifact.descriptor != descriptor {
            return Err(crate::PackageErrorCodeV1::Invalid.error("retained package descriptor"));
        }
        if descriptor.id != self.package_id || descriptor.revision != self.revision {
            return Err(crate::PackageErrorCodeV1::Invalid.error("retained package key"));
        }
        let declared = Self::dependency_keys(&descriptor);
        let retained = self
            .dependencies
            .iter()
            .map(|dependency| (dependency.package_id.as_str(), dependency.revision.as_str()))
            .collect::<std::collections::BTreeSet<_>>();
        if declared != retained || retained.len() != self.dependencies.len() {
            return Err(crate::PackageErrorCodeV1::Invalid.error("retained package dependencies"));
        }
        Ok(artifact)
    }

    pub(in crate::analysis) fn closure(
        tenant: [u8; 16],
        root: &crate::PackageRefV1,
        control: &crate::AnalysisReadControl,
        mut read: impl FnMut([u8; 16], &str, &str) -> crate::Result<Option<Self>>,
    ) -> crate::Result<(Vec<Self>, Vec<crate::PackageArtifactV1>)> {
        let mut pending = vec![root.clone()];
        let mut seen = std::collections::BTreeSet::new();
        let mut artifacts = Vec::new();
        let mut rows = Vec::new();
        while let Some(reference) = pending.pop() {
            control.check()?;
            if !seen.insert(reference.clone()) {
                continue;
            }
            let retained =
                read(tenant, &reference.package_id, &reference.revision)?.ok_or_else(|| {
                    crate::PackageErrorCodeV1::Missing.error("installed image artifact")
                })?;
            artifacts.push(
                retained
                    .decode_artifact()
                    .map_err(crate::Error::stored_artifact)?,
            );
            pending.extend(
                retained
                    .dependencies
                    .iter()
                    .map(|dependency| crate::PackageRefV1 {
                        package_id: dependency.package_id.clone(),
                        revision: dependency.revision.clone(),
                    }),
            );
            rows.push(retained);
        }
        artifacts.sort_by_key(crate::PackageArtifactV1::reference);
        rows.sort_by(|left, right| {
            (&left.package_id, &left.revision).cmp(&(&right.package_id, &right.revision))
        });
        control.check()?;
        Ok((rows, artifacts))
    }

    fn dependency_keys(
        descriptor: &araphor_analysis_sdk::Package,
    ) -> std::collections::BTreeSet<(&str, &str)> {
        descriptor
            .exports
            .iter()
            .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
            .filter(|dependency| dependency.package != descriptor.id)
            .map(|dependency| (dependency.package.as_str(), dependency.revision.as_str()))
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageResultRefV1 {
    pub result_id: String,
    pub commit_revision: u64,
}
