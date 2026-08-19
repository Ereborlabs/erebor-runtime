use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use erebor_interceptor_abi::{MAX_CANONICAL_COMPONENT_BYTES_V1, MAX_CANONICAL_PATH_COMPONENTS_V1};
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRuntimeConfig {
    pub socket_path: PathBuf,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKindV1 {
    Init,
    Sidecar,
    Application,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBindingConfig {
    pub binding_id: String,
    pub execution_set_id: String,
    pub protected_scope_id: String,
    pub workload_selector_id: String,
    pub profile_id: String,
    pub container_id: String,
    pub namespace: String,
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
    pub state_directory: PathBuf,
    pub interceptor: InterceptorConfig,
    pub control: NodeControlConfig,
    #[serde(default)]
    pub evidence: Option<EvidenceConfig>,
    #[serde(default)]
    pub runtime_observation: Option<RuntimeObservationConfig>,
    #[serde(default)]
    pub container_runtime: Option<ContainerRuntimeConfig>,
    #[serde(default)]
    pub workload_bindings: Vec<WorkloadBindingConfig>,
    #[serde(default)]
    pub policy_candidates: Vec<PolicyCandidateConfig>,
    #[serde(default)]
    pub exact_file_objects: Vec<ExactFileObjectConfig>,
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

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.node_id.is_empty() && !self.node_id.chars().any(char::is_whitespace),
            InvalidConfigurationSnafu {
                reason: "node_id must be nonempty and contain no whitespace",
            }
        );
        if let Some(evidence) = &self.evidence {
            ensure!(
                canonical_uuid(&evidence.tenant_id)
                    && canonical_uuid(&evidence.source_id)
                    && evidence.maximum_record_bytes > 0
                    && evidence.maximum_retained_bytes >= evidence.maximum_record_bytes
                    && evidence.maximum_retained_records > 0
                    && evidence.maximum_batch_records > 0
                    && evidence.maximum_batch_records <= evidence.maximum_retained_records
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
                    && runtime
                        .containerd_event_socket_path
                        .as_ref()
                        .is_none_or(|path| path.is_absolute())
                    && runtime.reconciliation_interval_ms > 0,
                InvalidConfigurationSnafu {
                    reason: "container runtime requires absolute CRI and optional containerd-event socket paths plus a nonzero reconciliation interval",
                }
            );
        }
        let mut binding_ids = BTreeSet::new();
        let mut execution_set_ids = BTreeSet::new();
        let mut container_ids = BTreeSet::new();
        for binding in &self.workload_bindings {
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
                self.container_runtime.is_some() || binding.root_cgroup_path.is_some(),
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
        let mut exact_object_ids = BTreeSet::new();
        let mut exact_kernel_objects = BTreeSet::new();
        for object in &self.exact_file_objects {
            ensure!(
                object.profile_generation_ref_id > 0
                    && object.exact_object_key_id > 0
                    && object.exact_object_key_id < (1_u64 << 63)
                    && !object.object_class_id.is_empty()
                    && object.mount_namespace_inode > 0
                    && object.mount_id_unique > 0
                    && object.inode > 0
                    && (object.inode_generation > 0 || object.device.is_some())
                    && object
                        .device
                        .as_ref()
                        .is_none_or(|device| !device.device_class_id.is_empty())
                    && !object.canonical_component_hex.is_empty()
                    && object.canonical_component_hex.len()
                        <= MAX_CANONICAL_PATH_COMPONENTS_V1
                    && usize::from(object.mount_relative_component_count)
                        <= object.canonical_component_hex.len()
                    && object.mount_root_inode > 0
                    && object.selected_mount_id_unique > 0
                    && object.mount_snapshot_digest_id > 0
                    && object.mount_topology_generation > 0
                    && object.mount_view_root_pid > 0
                    && object.canonical_component_hex.iter().all(|component| {
                        hex::decode(component).is_ok_and(|bytes| {
                            !bytes.is_empty()
                                && bytes.len() <= MAX_CANONICAL_COMPONENT_BYTES_V1
                                && !bytes.contains(&0)
                                && bytes.as_slice() != b"."
                                && bytes.as_slice() != b".."
                        })
                    })
                    && exact_object_ids.insert((
                        object.profile_generation_ref_id,
                        object.exact_object_key_id,
                    ))
                    && exact_kernel_objects.insert((
                        object.profile_generation_ref_id,
                        object.mount_namespace_inode,
                        object.mount_id_unique,
                        object.filesystem_device,
                        object.inode,
                        object.inode_generation,
                    )),
                InvalidConfigurationSnafu {
                    reason: "exact file-object bindings need unique IDs and unique nonzero kernel identities",
                }
            );
        }
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

const fn default_authorization_clock_skew_ns() -> i64 {
    300_000_000_000
}

const fn default_evidence_record_bytes() -> u64 {
    128 * 1_024
}

const fn default_evidence_retained_bytes() -> u64 {
    256 * 1_024 * 1_024
}

const fn default_evidence_retained_records() -> usize {
    100_000
}

const fn default_evidence_batch_records() -> usize {
    256
}

const fn default_evidence_control_delay_ms() -> u64 {
    30_000
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        ContainerKindV1, EvidenceConfig, ExactFileObjectConfig, InterceptorConfig, NodeConfig,
        NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
    };

    fn config() -> NodeConfig {
        NodeConfig {
            node_id: "node-a".to_owned(),
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
            container_runtime: None,
            workload_bindings: vec![WorkloadBindingConfig {
                binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                workload_selector_id: "worker".to_owned(),
                profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                container_id: "a".repeat(64),
                namespace: "default".to_owned(),
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
            exact_file_objects: Vec::new(),
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
            containerd_event_socket_path: Some(PathBuf::from("containerd.sock")),
            reconciliation_interval_ms: 2_000,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_cri_binding_requires_an_exact_cgroup() {
        let mut config = config();
        config.workload_bindings[0].root_cgroup_path = None;
        assert!(config.validate().is_err());
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

    #[test]
    fn exact_object_ids_and_kernel_identities_are_one_to_one() {
        let mut config = config();
        config.exact_file_objects = vec![exact_object(7, 11), exact_object(7, 12)];
        assert!(config.validate().is_err());

        config.exact_file_objects = vec![exact_object(7, 11), exact_object(8, 11)];
        assert!(config.validate().is_err());
    }

    fn exact_object(exact_object_key_id: u64, inode: u64) -> ExactFileObjectConfig {
        ExactFileObjectConfig {
            profile_generation_ref_id: 1,
            exact_object_key_id,
            object_class_id: "DATASET_INPUT".to_owned(),
            mount_namespace_inode: 10,
            mount_id_unique: 20,
            filesystem_device: 30,
            inode,
            inode_generation: 1,
            device: None,
            canonical_component_hex: ["var", "run", "secret"]
                .map(|component| hex::encode(component.as_bytes()))
                .to_vec(),
            mount_relative_component_count: 3,
            mount_root_filesystem_device: 30,
            mount_root_inode: 2,
            selected_mount_id_unique: 20,
            mount_snapshot_digest_id: 40,
            mount_topology_generation: 1,
            mount_view_root_pid: 1,
        }
    }
}
