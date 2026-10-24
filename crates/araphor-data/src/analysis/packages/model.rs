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
    pub fn from_artifact(
        artifact: &crate::PackageArtifactV1,
        tenant_id: [u8; 16],
    ) -> crate::Result<Self> {
        let dependencies = artifact
            .descriptor
            .exports
            .iter()
            .flat_map(|model| model.dependencies().map(|(_, dependency)| dependency))
            .filter(|dependency| dependency.package != artifact.descriptor.id)
            .map(|dependency| (dependency.package.clone(), dependency.revision.clone()))
            .collect::<std::collections::BTreeSet<_>>();
        Ok(Self {
            tenant_id,
            package_id: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            descriptor: artifact.descriptor_bytes()?,
            artifact: Vec::new(),
            dependencies: dependencies
                .into_iter()
                .map(|(package_id, revision)| PackageRevisionRefV1 {
                    package_id,
                    revision,
                })
                .collect(),
        })
    }

    pub fn from_bundle(
        bundle: &crate::PackageBundleV1,
        tenant: [u8; 16],
    ) -> crate::Result<Vec<Self>> {
        if tenant == [0; 16] {
            return Err(crate::PackageErrorCodeV1::Invalid.error("package revision tenant"));
        }
        bundle.validate()?;
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
        Ok(artifact)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageResultRefV1 {
    pub result_id: String,
    pub commit_revision: u64,
}
