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
}

impl From<&EvidenceConfig> for crate::EvidenceWalLimits {
    fn from(config: &EvidenceConfig) -> Self {
        Self {
            maximum_record_bytes: config.maximum_record_bytes,
            maximum_retained_bytes: config.maximum_retained_bytes,
            maximum_retained_records: config.maximum_retained_records,
            maximum_batch_records: config.maximum_batch_records,
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
    #[serde(default)]
    pub containerd_event_socket_path: Option<PathBuf>,
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
    pub inode_generation: u32,
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
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        let config: Self = serde_json::from_slice(&bytes).context(JsonSnafu { path })?;
        config.validate()?;
        Ok(config)
    }

    pub fn bind_kubernetes_runtime_identity(&mut self, node_name: String) -> Result<()> {
        self.kubernetes_node_name = Some(node_name);
        if let Some(runtime) = self.container_runtime.as_mut() {
            let source_path = Path::new("/proc/self/cgroup");
            let cgroups = fs::read_to_string(source_path).context(IoSnafu { path: source_path })?;
            let relative = unified_cgroup_path(&cgroups).ok_or_else(|| {
                InvalidConfigurationSnafu {
                    reason: "Kubernetes node process has no unique non-root unified cgroup"
                        .to_owned(),
                }
                .build()
            })?;
            let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
            runtime.effect_controller_cgroup_path =
                fs::canonicalize(&path).context(IoSnafu { path: &path })?;
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
                    && evidence.maximum_control_delay_ms > 0,
                InvalidConfigurationSnafu {
                    reason:
                        "evidence requires canonical identities and consistent nonzero WAL bounds",
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
                && self.control.reconnect_maximum_ms >= self.control.reconnect_minimum_ms,
            InvalidConfigurationSnafu {
                reason: "Control reconnect bounds are invalid",
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
                    && runtime
                        .containerd_event_socket_path
                        .as_ref()
                        .is_none_or(|path| path.is_absolute())
                    && runtime.reconciliation_interval_ms > 0,
                InvalidConfigurationSnafu {
                    reason: "container runtime requires absolute CRI, effect-controller cgroup, and optional containerd-event socket paths plus a nonzero reconciliation interval",
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
                                        == crate::runtime_admission::runtime_binding_id(
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

    pub(crate) fn reconciliation_interval(&self) -> Duration {
        Duration::from_millis(
            self.container_runtime
                .as_ref()
                .map_or_else(default_runtime_reconciliation_ms, |runtime| {
                    runtime.reconciliation_interval_ms
                }),
        )
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unified_cgroup_path(cgroups: &str) -> Option<&str> {
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

const fn default_runtime_reconciliation_ms() -> u64 {
    2_000
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
    100_000
}

const fn default_evidence_batch_records() -> usize {
    mithril_control::MAX_EVIDENCE_BATCH_RECORDS
}

const fn default_evidence_control_delay_ms() -> u64 {
    30_000
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        unified_cgroup_path, ContainerKindV1, EvidenceConfig, InterceptorConfig, NodeConfig,
        NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
    };

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
            },
            evidence: Some(EvidenceConfig {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                maximum_record_bytes: 128 * 1_024,
                maximum_retained_bytes: 16 * 1_024 * 1_024,
                maximum_retained_records: 10_000,
                maximum_batch_records: 256,
                maximum_control_delay_ms: 30_000,
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
        }
    }

    #[test]
    fn configured_cgroup_binding_does_not_require_cri() -> crate::Result<()> {
        let config = config();
        config.validate()?;
        assert_eq!(config.reconciliation_interval(), Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn kernel_reconciliation_runs_without_workload_bindings() -> crate::Result<()> {
        let mut config = config();
        config.workload_bindings.clear();
        config.validate()?;
        assert_eq!(config.reconciliation_interval(), Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn cri_binding_resolves_its_cgroup_locally() -> crate::Result<()> {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            effect_controller_cgroup_path: PathBuf::from("/sys/fs/cgroup/mithril-node"),
            containerd_event_socket_path: Some(PathBuf::from("/run/containerd/containerd.sock")),
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings[0].root_cgroup_path = None;
        config.validate()
    }

    #[test]
    fn containerd_event_socket_must_be_absolute() {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            effect_controller_cgroup_path: PathBuf::from("/sys/fs/cgroup/mithril-node"),
            containerd_event_socket_path: Some(PathBuf::from("containerd.sock")),
            reconciliation_interval_ms: 2_000,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn effect_controller_cgroup_must_be_absolute_and_non_root() {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            effect_controller_cgroup_path: PathBuf::from("mithril-node"),
            containerd_event_socket_path: None,
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
            evidence.maximum_batch_records = mithril_control::MAX_EVIDENCE_BATCH_RECORDS + 1;
        }
        assert!(batch_config.validate().is_err());
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
