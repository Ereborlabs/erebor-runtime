use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptorConfig {
    pub runtime_btf_path: PathBuf,
    pub lease_path: PathBuf,
    pub pin_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeControlConfig {
    pub endpoint: String,
    pub server_name: String,
    pub ca_path: PathBuf,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    #[serde(default = "default_reconnect_minimum_ms")]
    pub reconnect_minimum_ms: u64,
    #[serde(default = "default_reconnect_maximum_ms")]
    pub reconnect_maximum_ms: u64,
    #[serde(default = "default_control_clock_skew_ns")]
    pub maximum_clock_skew_ns: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservationConfig {
    pub socket_path: PathBuf,
    pub allowed_uid: u32,
    pub cgroup_scope: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdmissionConfig {
    pub socket_path: PathBuf,
    #[serde(default = "default_runtime_admission_request_bytes")]
    pub maximum_request_bytes: usize,
    #[serde(default = "default_runtime_admission_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    pub tenant_id: String,
    pub source_id: String,
    #[serde(default = "default_evidence_record_bytes")]
    pub maximum_record_bytes: u64,
    #[serde(default = "default_evidence_retained_bytes")]
    pub maximum_retained_bytes: u64,
    #[serde(default = "default_evidence_retained_records")]
    pub maximum_retained_records: usize,
    #[serde(default = "default_evidence_batch_records")]
    pub maximum_batch_records: usize,
    #[serde(default = "default_evidence_control_delay_ms")]
    pub maximum_control_delay_ms: u64,
    #[serde(default = "default_evidence_reader_queue_records")]
    pub maximum_reader_queue_records: usize,
    #[serde(default)]
    pub capacity_policy: crate::EvidenceWalCapacityPolicyV1,
}

impl From<&EvidenceConfig> for crate::EvidenceWalLimits {
    fn from(config: &EvidenceConfig) -> Self {
        Self {
            maximum_record_bytes: config.maximum_record_bytes,
            maximum_retained_bytes: config.maximum_retained_bytes,
            maximum_retained_records: config.maximum_retained_records,
            maximum_batch_records: config.maximum_batch_records,
            capacity_policy: config.capacity_policy,
        }
    }
}

impl EvidenceConfig {
    pub(crate) fn identities(
        &self,
    ) -> crate::Result<(
        erebor_interceptor_abi::Id128V1,
        erebor_interceptor_abi::Id128V1,
    )> {
        let parse = |value: &str| {
            uuid::Uuid::parse_str(value)
                .map(|uuid| (*uuid.as_bytes()).into())
                .map_err(|error| {
                    InvalidConfigurationSnafu {
                        reason: format!("evidence identity is invalid: {error}"),
                    }
                    .build()
                })
        };
        Ok((parse(&self.tenant_id)?, parse(&self.source_id)?))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRuntimeConfig {
    pub socket_path: PathBuf,
    pub effect_controller_cgroup_path: PathBuf,
    #[serde(default = "default_runtime_reconciliation_ms")]
    pub reconciliation_interval_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCandidateConfig {
    pub artifact_path: PathBuf,
    pub public_key_path: PathBuf,
    #[serde(default)]
    pub rollback_authorization_path: Option<PathBuf>,
    #[serde(default)]
    pub rollback_public_key_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeAuthorizationConfig {
    pub tenant_id: String,
    pub cluster_uid: String,
    pub trust_domain_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub public_key_path: PathBuf,
    pub sequence_epoch: u64,
    pub valid_from_utc_ns: i64,
    pub valid_until_utc_ns: i64,
    #[serde(default = "default_authorization_clock_skew_ns")]
    pub maximum_clock_skew_ns: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDecommissionConfig {
    pub cluster_uid: String,
    pub signing_key_id: String,
    pub public_key_path: PathBuf,
    pub runtime_integration_owner: String,
    pub runtime_hook_directory: PathBuf,
    pub containerd_config_directory: PathBuf,
    pub containerd_drop_in_directory: String,
    pub runtime_services: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactDeviceConfig {
    pub device_class_id: String,
    pub device_type: ExactDeviceType,
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactDeviceType {
    Character,
    Block,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFileObjectConfig {
    pub profile_generation_ref_id: u64,
    pub exact_object_key_id: u64,
    pub object_class_id: String,
    pub mount_namespace_inode: u32,
    pub mount_id_unique: u64,
    pub filesystem_device: u32,
    pub inode: u64,
    pub inode_generation: u64,
    #[serde(default)]
    pub device: Option<ExactDeviceConfig>,
    pub canonical_component_hex: Vec<String>,
    pub mount_relative_component_count: u16,
    pub mount_root_filesystem_device: u32,
    pub mount_root_inode: u64,
    pub selected_mount_id_unique: u64,
    pub mount_snapshot_digest_id: u64,
    pub mount_topology_generation: u64,
    pub mount_view_root_pid: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKindV1 {
    Init,
    Sidecar,
    Application,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBindingConfig {
    pub binding_id: String,
    #[serde(default)]
    pub scheduled_binding_authority_id: Option<String>,
    #[serde(default)]
    pub scheduled_target_digest: Option<String>,
    pub execution_set_id: String,
    pub protected_scope_id: String,
    pub workload_selector_id: String,
    pub profile_id: String,
    pub container_id: String,
    pub namespace: String,
    #[serde(default)]
    pub cluster_uid: String,
    #[serde(default)]
    pub namespace_uid: String,
    #[serde(default)]
    pub controller_uid: String,
    #[serde(default)]
    pub service_account_uid: String,
    #[serde(default)]
    pub pod_labels: BTreeMap<String, String>,
    pub pod_uid: String,
    pub sandbox_id: String,
    pub container_name: String,
    pub image_digest: String,
    pub container_kind: ContainerKindV1,
    pub container_generation: u64,
    #[serde(default)]
    pub root_cgroup_path: Option<PathBuf>,
    pub lifecycle_generation: u64,
    pub active_profile_generation_ref_id: u64,
    pub initial_role_id: u32,
    pub external_role_id: u32,
    #[serde(default)]
    pub arm_initial_root: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    #[serde(default)]
    pub kubernetes_node_name: Option<String>,
    pub state_directory: PathBuf,
    pub interceptor: InterceptorConfig,
    pub control: NodeControlConfig,
    #[serde(default)]
    pub evidence: Option<EvidenceConfig>,
    #[serde(default)]
    pub runtime_observation: Option<RuntimeObservationConfig>,
    #[serde(default)]
    pub runtime_admission: Option<RuntimeAdmissionConfig>,
    #[serde(default)]
    pub container_runtime: Option<ContainerRuntimeConfig>,
    #[serde(default)]
    pub workload_bindings: Vec<WorkloadBindingConfig>,
    #[serde(default)]
    pub policy_candidates: Vec<PolicyCandidateConfig>,
    #[serde(default)]
    pub administrative_authorization: Option<AdministrativeAuthorizationConfig>,
    #[serde(default)]
    pub decommission: Option<NodeDecommissionConfig>,
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let config = Self::read(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_with_kubernetes_runtime_identity(path: &Path, node_name: String) -> Result<Self> {
        Self::load_with_kubernetes_runtime_identity_using(
            path,
            node_name,
            current_effect_controller_cgroup_path,
        )
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        serde_json::from_slice(&bytes).context(JsonSnafu { path })
    }

    fn load_with_kubernetes_runtime_identity_using(
        path: &Path,
        node_name: String,
        resolve_effect_controller_cgroup: impl FnOnce() -> Result<PathBuf>,
    ) -> Result<Self> {
        // The scheduler-derived Node name must exist before admission constraints are validated.
        let mut config = Self::read(path)?;
        config
            .bind_kubernetes_runtime_identity_using(node_name, resolve_effect_controller_cgroup)?;
        Ok(config)
    }

    fn bind_kubernetes_runtime_identity_using(
        &mut self,
        node_name: String,
        resolve_effect_controller_cgroup: impl FnOnce() -> Result<PathBuf>,
    ) -> Result<()> {
        // Downward API supplies the scheduler-selected node name; configuration cannot override it.
        self.kubernetes_node_name = Some(node_name);
        if let Some(runtime) = self.container_runtime.as_mut() {
            // Scope CRI inspection to this DaemonSet Pod instead of the host cgroup root.
            runtime.effect_controller_cgroup_path = resolve_effect_controller_cgroup()?;
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            mithril_control::node_id_is_valid(&self.node_id),
            InvalidConfigurationSnafu {
                reason: "node_id must be a bounded path-safe identity",
            }
        );
        ensure!(
            self.kubernetes_node_name
                .as_deref()
                .is_none_or(kubernetes_node_name_is_valid),
            InvalidConfigurationSnafu {
                reason: "kubernetes_node_name must be a valid DNS subdomain when it is set",
            }
        );
        if let Some(evidence) = &self.evidence {
            let limits = crate::EvidenceWalLimits::from(evidence);
            ensure!(
                canonical_uuid(&evidence.tenant_id)
                    && canonical_uuid(&evidence.source_id)
                    && limits.validate().is_ok()
                    && evidence.maximum_control_delay_ms > 0
                    && (1..=1_000_000).contains(&evidence.maximum_reader_queue_records),
                InvalidConfigurationSnafu {
                    reason:
                        "evidence requires canonical identities, consistent WAL bounds, and a reader queue capacity from 1 to 1000000 records",
                }
            );
        }
        ensure!(
            self.control.endpoint.starts_with("https://") && !self.control.server_name.is_empty(),
            InvalidConfigurationSnafu {
                reason: "Control endpoint must use HTTPS and have an explicit server name",
            }
        );
        ensure!(
            self.control.reconnect_minimum_ms > 0
                && self.control.reconnect_maximum_ms >= self.control.reconnect_minimum_ms
                && (0..=300_000_000_000).contains(&self.control.maximum_clock_skew_ns),
            InvalidConfigurationSnafu {
                reason: "Control reconnect or clock-skew bounds are invalid",
            }
        );
        if let Some(runtime) = &self.runtime_observation {
            ensure!(
                runtime.cgroup_scope.starts_with('/')
                    && !runtime.cgroup_scope.split('/').any(|part| part == ".."),
                InvalidConfigurationSnafu {
                    reason: "Runtime observation cgroup_scope must be an absolute clean path",
                }
            );
        }
        if let Some(runtime) = &self.container_runtime {
            ensure!(
                runtime.socket_path.is_absolute()
                    && runtime.effect_controller_cgroup_path.is_absolute()
                    && runtime.effect_controller_cgroup_path != Path::new("/sys/fs/cgroup")
                    && runtime.reconciliation_interval_ms > 0,
                InvalidConfigurationSnafu {
                    reason: "container runtime requires absolute CRI and effect-controller cgroup paths plus a nonzero fallback reconciliation interval",
                }
            );
        }
        if let Some(decommission) = &self.decommission {
            ensure!(
                canonical_uuid(&decommission.cluster_uid)
                    && (1..=128).contains(&decommission.signing_key_id.len())
                    && (1..=253).contains(&decommission.runtime_integration_owner.len())
                    && !decommission
                        .runtime_integration_owner
                        .contains(['\r', '\n'])
                    && !decommission.containerd_drop_in_directory.is_empty()
                    && decommission.containerd_drop_in_directory.len() <= 255
                    && Path::new(&decommission.containerd_drop_in_directory)
                        .components()
                        .count()
                        == 1
                    && (1..=8).contains(&decommission.runtime_services.len())
                    && decommission.runtime_services.iter().all(|service| {
                        !service.is_empty()
                            && service.len() <= 253
                            && service
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@".contains(&byte))
                    })
                    && [
                        &decommission.public_key_path,
                        &decommission.runtime_hook_directory,
                        &decommission.containerd_config_directory,
                    ]
                    .into_iter()
                    .all(|path| clean_absolute_path(path)),
                InvalidConfigurationSnafu {
                    reason: "decommission requires one canonical cluster, key, owner, and path set",
                }
            );
        }
        if let Some(admission) = &self.runtime_admission {
            ensure!(
                admission.socket_path.is_absolute()
                    && (1_024..=1_048_576).contains(&admission.maximum_request_bytes)
                    && (100..=30_000).contains(&admission.timeout_ms)
                    && self.kubernetes_node_name.is_some()
                    && self.container_runtime.is_some(),
                InvalidConfigurationSnafu {
                    reason: "runtime admission requires CRI, a Kubernetes Node name, an absolute socket path, and bounded request and timeout limits",
                }
            );
        }
        let mut binding_ids = BTreeSet::new();
        let mut execution_set_ids = BTreeSet::new();
        let mut container_ids = BTreeSet::new();
        for binding in &self.workload_bindings {
            // Scheduled authority is complete or absent; partial authority cannot reach runtime gate.
            ensure!(
                match (
                    binding.scheduled_binding_authority_id.as_deref(),
                    binding.scheduled_target_digest.as_deref(),
                ) {
                    (None, None) => true,
                    (Some(authority), Some(digest)) => {
                        self.runtime_admission.is_some()
                            && canonical_uuid(authority)
                            && is_sha256(digest)
                            && (binding.container_id.starts_with("scheduled:")
                                && binding.binding_id == authority
                                || !binding.container_id.starts_with("scheduled:")
                                    && binding.binding_id
                                        == crate::runtime_admission::ScheduledRuntimeBindingV1::runtime_binding_id(
                                            authority,
                                            &binding.container_id,
                                        ))
                    }
                    (Some(_), None) | (None, Some(_)) => false,
                },
                InvalidConfigurationSnafu {
                    reason: "scheduled workload bindings require complete signed authority and deterministic runtime identity",
                }
            );
            // Any Kubernetes field opts the binding into validation of the complete identity set.
            let kubernetes_identity_is_set = !binding.cluster_uid.is_empty()
                || !binding.namespace_uid.is_empty()
                || !binding.controller_uid.is_empty()
                || !binding.service_account_uid.is_empty()
                || !binding.pod_labels.is_empty();
            ensure!(
                (32..=128).contains(&binding.container_id.len())
                    && (1..=253).contains(&binding.namespace.len())
                    && (1..=64).contains(&binding.pod_uid.len())
                    && (1..=128).contains(&binding.sandbox_id.len())
                    && (1..=253).contains(&binding.container_name.len())
                    && !binding.image_digest.is_empty()
                    && binding.container_generation > 0
                    && binding.lifecycle_generation > 0
                    && binding.active_profile_generation_ref_id > 0
                    && binding.initial_role_id > 0
                    && binding.external_role_id > 0
                    && !binding.workload_selector_id.is_empty(),
                InvalidConfigurationSnafu {
                    reason: "Workload bindings require nonempty container identity and nonzero generations and roles",
                }
            );
            ensure!(
                !kubernetes_identity_is_set
                    || (canonical_uuid(&binding.cluster_uid)
                        && canonical_uuid(&binding.namespace_uid)
                        && canonical_uuid(&binding.controller_uid)
                        && canonical_uuid(&binding.service_account_uid)
                        && canonical_uuid(&binding.pod_uid)
                        && binding.pod_labels.len() <= 256
                        && binding.pod_labels.iter().all(|(key, value)| {
                            !key.is_empty()
                                && key.len() <= 253
                                && value.len() <= 4_096
                        })),
                InvalidConfigurationSnafu {
                    reason: "Kubernetes workload targets require complete canonical identities and bounded Pod labels",
                }
            );
            ensure!(
                self.container_runtime.is_some()
                    || (self.runtime_admission.is_some()
                        && binding.scheduled_binding_authority_id.is_some())
                    || binding.root_cgroup_path.is_some(),
                InvalidConfigurationSnafu {
                    reason: "non-CRI workload bindings require root_cgroup_path",
                }
            );
            ensure!(
                binding_ids.insert(&binding.binding_id)
                    && execution_set_ids.insert(&binding.execution_set_id)
                    && container_ids.insert(&binding.container_id),
                InvalidConfigurationSnafu {
                    reason:
                        "workload binding, execution-set, and container identities must be unique",
                }
            );
        }
        let mut candidate_paths = BTreeSet::new();
        for candidate in &self.policy_candidates {
            ensure!(
                candidate.artifact_path.is_absolute()
                    && candidate.public_key_path.is_absolute()
                    && candidate
                        .rollback_authorization_path
                        .as_ref()
                        .is_none_or(|path| path.is_absolute())
                    && candidate
                        .rollback_public_key_path
                        .as_ref()
                        .is_none_or(|path| path.is_absolute())
                    && candidate.rollback_authorization_path.is_some()
                        == candidate.rollback_public_key_path.is_some()
                    && candidate_paths.insert(&candidate.artifact_path),
                InvalidConfigurationSnafu {
                    reason: "policy candidates need unique absolute artifact and public-key paths and a complete optional rollback proof/key pair",
                }
            );
        }
        ensure!(
            self.policy_candidates.is_empty() || self.evidence.is_some(),
            InvalidConfigurationSnafu {
                reason: "effect policy requires a durable evidence owner",
            }
        );
        if let Some(authorization) = &self.administrative_authorization {
            ensure!(
                canonical_uuid(&authorization.tenant_id)
                    && canonical_uuid(&authorization.cluster_uid)
                    && canonical_uuid(&authorization.trust_domain_id)
                    && canonical_uuid(&authorization.issuer_id)
                    && (1..=128).contains(&authorization.key_id.len())
                    && !authorization.key_id.chars().any(char::is_whitespace)
                    && authorization.public_key_path.is_absolute()
                    && authorization.sequence_epoch > 0
                    && authorization.valid_from_utc_ns < authorization.valid_until_utc_ns
                    && (0..=300_000_000_000).contains(&authorization.maximum_clock_skew_ns),
                InvalidConfigurationSnafu {
                    reason: "administrative authorization needs canonical identities, one key, and a bounded validity window",
                }
            );
        }
        Ok(())
    }
}

fn kubernetes_node_name_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

const fn default_runtime_reconciliation_ms() -> u64 {
    2_000
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn unified_cgroup_path(cgroups: &str) -> Option<&str> {
    // Accept one non-root cgroup2 path so the node cannot silently broaden CRI scope.
    let mut paths = cgroups.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = paths.next()?;
    (paths.next().is_none()
        && path.starts_with('/')
        && path != "/"
        && !Path::new(path).components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }))
    .then_some(path)
}

fn current_effect_controller_cgroup_path() -> Result<PathBuf> {
    let source_path = Path::new("/proc/self/cgroup");
    let cgroups = fs::read_to_string(source_path).context(IoSnafu { path: source_path })?;
    let relative = unified_cgroup_path(&cgroups).ok_or_else(|| {
        InvalidConfigurationSnafu {
            reason: "Kubernetes node process has no unique non-root unified cgroup".to_owned(),
        }
        .build()
    })?;
    let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    fs::canonicalize(&path).context(IoSnafu { path: &path })
}

impl NodeControlConfig {
    #[must_use]
    pub const fn reconnect_minimum(&self) -> Duration {
        Duration::from_millis(self.reconnect_minimum_ms)
    }

    #[must_use]
    pub const fn reconnect_maximum(&self) -> Duration {
        Duration::from_millis(self.reconnect_maximum_ms)
    }
}

const fn default_reconnect_minimum_ms() -> u64 {
    100
}

const fn default_reconnect_maximum_ms() -> u64 {
    5_000
}

const fn default_control_clock_skew_ns() -> i64 {
    30_000_000_000
}

const fn default_runtime_admission_request_bytes() -> usize {
    64 * 1_024
}

const fn default_runtime_admission_timeout_ms() -> u64 {
    10_000
}

const fn default_authorization_clock_skew_ns() -> i64 {
    300_000_000_000
}

const fn default_evidence_record_bytes() -> u64 {
    mithril_control::MAX_EVIDENCE_RECORD_BYTES as u64
}

const fn default_evidence_retained_bytes() -> u64 {
    256 * 1_024 * 1_024
}

const fn default_evidence_retained_records() -> usize {
    10_000
}

const fn default_evidence_batch_records() -> usize {
    mithril_control::DEFAULT_EVIDENCE_BATCH_RECORDS
}

const fn default_evidence_control_delay_ms() -> u64 {
    30_000
}

const fn default_evidence_reader_queue_records() -> usize {
    65_535
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value)
}

fn clean_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().as_encoded_bytes().len() <= 4_096
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{
        unified_cgroup_path, ContainerKindV1, EvidenceConfig, InterceptorConfig, NodeConfig,
        NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn evidence_capacity_policy_defaults_to_block_and_accepts_retain(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base = serde_json::json!({
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "source_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        });
        let block: EvidenceConfig = serde_json::from_value(base.clone())?;
        assert_eq!(
            block.capacity_policy,
            crate::EvidenceWalCapacityPolicyV1::Block
        );
        assert_eq!(block.maximum_reader_queue_records, 65_535);

        let mut retain = base;
        retain["capacity_policy"] = serde_json::json!("RETAIN");
        retain["maximum_reader_queue_records"] = serde_json::json!(4_096);
        let retain: EvidenceConfig = serde_json::from_value(retain)?;
        assert_eq!(
            retain.capacity_policy,
            crate::EvidenceWalCapacityPolicyV1::Retain
        );
        assert_eq!(retain.maximum_reader_queue_records, 4_096);
        Ok(())
    }

    fn config() -> NodeConfig {
        NodeConfig {
            node_id: "node-a".to_owned(),
            kubernetes_node_name: None,
            state_directory: PathBuf::from("/tmp/mithril-node-test"),
            interceptor: InterceptorConfig {
                runtime_btf_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
                lease_path: PathBuf::from("/tmp/mithril-node-test/owner.lock"),
                pin_root: PathBuf::from("/sys/fs/bpf/mithril-node-test"),
            },
            control: NodeControlConfig {
                endpoint: "https://127.0.0.1:7443".to_owned(),
                server_name: "mithril-control".to_owned(),
                ca_path: PathBuf::from("/tmp/ca.pem"),
                certificate_path: PathBuf::from("/tmp/node.pem"),
                private_key_path: PathBuf::from("/tmp/node-key.pem"),
                reconnect_minimum_ms: 100,
                reconnect_maximum_ms: 5_000,
                maximum_clock_skew_ns: 30_000_000_000,
            },
            evidence: Some(EvidenceConfig {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                maximum_record_bytes: 128 * 1_024,
                maximum_retained_bytes: 16 * 1_024 * 1_024,
                maximum_retained_records: 10_000,
                maximum_batch_records: 256,
                maximum_control_delay_ms: 30_000,
                maximum_reader_queue_records: 65_535,
                capacity_policy: crate::EvidenceWalCapacityPolicyV1::Block,
            }),
            runtime_observation: None,
            runtime_admission: None,
            container_runtime: None,
            workload_bindings: vec![WorkloadBindingConfig {
                binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                scheduled_binding_authority_id: None,
                scheduled_target_digest: None,
                execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                workload_selector_id: "worker".to_owned(),
                profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                container_id: "a".repeat(64),
                namespace: "default".to_owned(),
                cluster_uid: String::new(),
                namespace_uid: String::new(),
                controller_uid: String::new(),
                service_account_uid: String::new(),
                pod_labels: BTreeMap::new(),
                pod_uid: "configured-scope".to_owned(),
                sandbox_id: "configured-scope".to_owned(),
                container_name: "worker".to_owned(),
                image_digest: "sha256:image".to_owned(),
                container_kind: ContainerKindV1::Application,
                container_generation: 1,
                root_cgroup_path: Some(PathBuf::from("/sys/fs/cgroup/test")),
                lifecycle_generation: 1,
                active_profile_generation_ref_id: 1,
                initial_role_id: 1,
                external_role_id: 2,
                arm_initial_root: false,
            }],
            policy_candidates: Vec::new(),
            administrative_authorization: None,
            decommission: None,
        }
    }

    #[test]
    fn kubernetes_outage_control_clock_skew_defaults_and_is_bounded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let control: NodeControlConfig = serde_json::from_value(serde_json::json!({
            "endpoint": "https://mithril-control:8443",
            "server_name": "mithril-control",
            "ca_path": "/etc/mithril/identity/ca.pem",
            "certificate_path": "/etc/mithril/identity/node.pem",
            "private_key_path": "/etc/mithril/identity/node-key.pem"
        }))?;
        assert_eq!(control.maximum_clock_skew_ns, 30_000_000_000);

        let mut invalid = config();
        invalid.control.maximum_clock_skew_ns = 300_000_000_001;
        assert!(invalid.validate().is_err());
        Ok(())
    }

    #[test]
    fn configured_cgroup_binding_does_not_require_cri() -> crate::Result<()> {
        let config = config();
        config.validate()
    }

    #[test]
    fn container_runtime_defaults_to_bounded_inventory_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime: super::ContainerRuntimeConfig = serde_json::from_value(serde_json::json!({
            "socket_path": "/run/containerd/containerd.sock",
            "effect_controller_cgroup_path": "/sys/fs/cgroup/mithril-node"
        }))?;

        assert_eq!(runtime.reconciliation_interval_ms, 2_000);
        Ok(())
    }

    #[test]
    fn scheduler_node_name_is_bound_before_runtime_admission_validation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("node.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "node_id": "node-a",
                "state_directory": "/var/lib/mithril",
                "interceptor": {
                    "runtime_btf_path": "/sys/kernel/btf/vmlinux",
                    "lease_path": "/run/erebor-interceptor/owner.lock",
                    "pin_root": "/sys/fs/bpf/mithril"
                },
                "control": {
                    "endpoint": "https://mithril-control:8443",
                    "server_name": "mithril-control",
                    "ca_path": "/etc/mithril/identity/ca.pem",
                    "certificate_path": "/etc/mithril/identity/node.pem",
                    "private_key_path": "/etc/mithril/identity/node-key.pem"
                },
                "runtime_admission": {
                    "socket_path": "/run/mithril/runtime-admission.sock"
                },
                "container_runtime": {
                    "socket_path": "/run/containerd/containerd.sock",
                    "effect_controller_cgroup_path": "/sys/fs/cgroup/config-placeholder"
                }
            }))?,
        )?;

        assert!(NodeConfig::load(&path).is_err());
        let loaded = NodeConfig::load_with_kubernetes_runtime_identity_using(
            &path,
            "worker-a.example".to_owned(),
            || Ok(PathBuf::from("/sys/fs/cgroup/kubepods/mithril-node")),
        )?;

        assert_eq!(
            loaded.kubernetes_node_name.as_deref(),
            Some("worker-a.example")
        );
        assert_eq!(
            loaded
                .container_runtime
                .as_ref()
                .map(|runtime| runtime.effect_controller_cgroup_path.as_path()),
            Some(std::path::Path::new("/sys/fs/cgroup/kubepods/mithril-node"))
        );
        Ok(())
    }

    #[test]
    fn node_accepts_no_workload_bindings() -> crate::Result<()> {
        let mut config = config();
        config.workload_bindings.clear();
        config.validate()
    }

    #[test]
    fn cri_binding_resolves_its_cgroup_locally() -> crate::Result<()> {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            effect_controller_cgroup_path: PathBuf::from("/sys/fs/cgroup/mithril-node"),
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings[0].root_cgroup_path = None;
        config.validate()
    }

    #[test]
    fn effect_controller_cgroup_must_be_absolute_and_non_root() {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            effect_controller_cgroup_path: PathBuf::from("mithril-node"),
            reconciliation_interval_ms: 2_000,
        });
        assert!(config.validate().is_err());

        if let Some(runtime) = config.container_runtime.as_mut() {
            runtime.effect_controller_cgroup_path = PathBuf::from("/sys/fs/cgroup");
        }
        assert!(config.validate().is_err());
    }

    #[test]
    fn kubernetes_effect_controller_requires_one_non_root_unified_cgroup() {
        assert_eq!(
            unified_cgroup_path("5:cpu:/legacy\n0::/kubepods/pod-a/node\n"),
            Some("/kubepods/pod-a/node")
        );
        assert_eq!(unified_cgroup_path("0::/\n"), None);
        assert_eq!(unified_cgroup_path("0::/a\n0::/b\n"), None);
        assert_eq!(unified_cgroup_path("0::relative\n"), None);
    }

    #[test]
    fn non_cri_binding_requires_an_exact_cgroup() {
        let mut config = config();
        config.workload_bindings[0].root_cgroup_path = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn node_identity_and_evidence_bounds_match_control() {
        for node_id in [".", "..", "node/a", "node\\a"] {
            let mut config = config();
            config.node_id = node_id.to_owned();
            assert!(config.validate().is_err());
        }

        let mut record_config = config();
        if let Some(evidence) = &mut record_config.evidence {
            evidence.maximum_record_bytes = mithril_control::MAX_EVIDENCE_RECORD_BYTES as u64 + 1;
        }
        assert!(record_config.validate().is_err());

        let mut batch_config = config();
        if let Some(evidence) = &mut batch_config.evidence {
            evidence.maximum_batch_records = 4_096;
        }
        assert!(batch_config.validate().is_ok());
    }

    #[test]
    fn rollback_configuration_requires_its_proof_and_key_together() {
        let mut config = config();
        config.policy_candidates.push(PolicyCandidateConfig {
            artifact_path: PathBuf::from("/tmp/profile.json"),
            public_key_path: PathBuf::from("/tmp/profile-key.hex"),
            rollback_authorization_path: Some(PathBuf::from("/tmp/rollback.json")),
            rollback_public_key_path: None,
        });
        assert!(config.validate().is_err());

        config.policy_candidates[0].rollback_public_key_path =
            Some(PathBuf::from("/tmp/rollback-key.hex"));
        assert!(config.validate().is_ok());
    }
}
