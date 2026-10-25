use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};

use crate::{PackageRefV1, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactIdentityV1 {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl PackageArtifactIdentityV1 {
    pub fn allocated_bytes(&self) -> usize {
        self.digest.capacity()
            + self.closure_digest.as_ref().map_or(0, String::capacity)
            + self.platform.as_ref().map_or(0, String::capacity)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImageV1 {
    pub root: PackageRefV1,
    pub digest: String,
    pub artifacts: Vec<PackageImageArtifactV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImageArtifactV1 {
    pub descriptor: sdk::Package,
    pub implementations: Vec<PackageImageImplementationV1>,
    pub fixtures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImageImplementationV1 {
    pub exports: Vec<String>,
    pub target: String,
    pub artifact: Option<PackageArtifactIdentityV1>,
}

impl crate::PackageBundleV1 {
    pub fn metadata(&self) -> Result<PackageImageV1> {
        let digest = self.validated_layout()?.digest();
        self.metadata_from(digest)
    }

    fn metadata_from(&self, digest: String) -> Result<PackageImageV1> {
        let mut artifacts = self.artifacts.iter().collect::<Vec<_>>();
        artifacts.sort_by(|left, right| {
            (&left.descriptor.id, &left.descriptor.revision)
                .cmp(&(&right.descriptor.id, &right.descriptor.revision))
        });
        Ok(PackageImageV1 {
            root: self.root.clone(),
            digest,
            artifacts: artifacts
                .into_iter()
                .map(|artifact| {
                    Ok(PackageImageArtifactV1 {
                        descriptor: artifact.descriptor.clone(),
                        implementations: artifact
                            .implementations
                            .iter()
                            .map(|implementation| {
                                Ok(PackageImageImplementationV1 {
                                    exports: implementation.exports().to_vec(),
                                    target: implementation.target().into(),
                                    artifact: implementation.identity()?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?,
                        fixtures: artifact
                            .fixtures
                            .iter()
                            .map(|fixture| fixture.name.clone())
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl crate::PackageBundle {
    pub fn metadata(&self) -> Result<PackageImageV1> {
        self.bundle().metadata_from(self.digest().into())
    }
}
