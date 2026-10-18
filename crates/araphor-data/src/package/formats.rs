use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledRefV1 {
    pub package_id: String,
    pub export: String,
    pub revision: String,
    pub generation: u64,
    pub root: super::PackageRefV1,
    pub parameters: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<super::PackageArtifactIdentityV1>,
}
