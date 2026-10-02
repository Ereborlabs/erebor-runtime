use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
