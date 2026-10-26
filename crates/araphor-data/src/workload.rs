use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
mod tests;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainerKindV1 {
    Init,
    Sidecar,
    Application,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
/// Captures the exact workload and scheduler facts that can enter a target snapshot.
pub struct WorkloadTargetFactV1 {
    pub node_id: String,
    pub workload_binding_generation_digest: String,
    pub execution_set_id: String,
    pub cluster_uid: String,
    pub namespace_uid: String,
    pub controller_uid: String,
    pub service_account_uid: String,
    pub pod_uid: String,
    pub container_id: String,
    pub container_name: String,
    pub container_kind: ContainerKindV1,
    pub image_digest: String,
    pub pod_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub kubernetes: Option<KubernetesWorkloadIdentityV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetContextV1 {
    pub workload: WorkloadTargetFactV1,
    pub workload_digest_valid: bool,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub signed_profile_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesWorkloadIdentityV1 {
    pub namespace_name: String,
    #[serde(default)]
    pub pod_name: String,
    pub profile_id: String,
    pub policy_source_revision_id: String,
    pub binding_id: String,
    pub protected_scope_id: String,
    pub workload_selector_id: String,
    pub kubernetes_node_name: String,
    pub kubernetes_node_uid: String,
    pub node_boot_id: String,
    pub label_epoch: u64,
}

impl KubernetesWorkloadIdentityV1 {
    pub fn authority_binding_id(pod_uid: &str, container_name: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-BINDING-V1\0",
            pod_uid.as_bytes(),
            container_name.as_bytes(),
        ])
    }

    pub fn runtime_binding_id(authority_binding_id: &str, container_id: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-RUNTIME-BINDING-V1\0",
            authority_binding_id.as_bytes(),
            container_id.as_bytes(),
        ])
    }

    pub fn valid_container_id(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    }

    fn derived_uuid(parts: &[&[u8]]) -> String {
        let digest = Sha256::digest(parts.concat());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
    }
}
