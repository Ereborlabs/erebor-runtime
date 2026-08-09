use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
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
pub struct ContainerRuntimeConfig {
    pub socket_path: PathBuf,
    #[serde(default = "default_runtime_reconciliation_ms")]
    pub reconciliation_interval_ms: u64,
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
    pub profile_id: String,
    pub container_id: String,
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
    pub runtime_observation: Option<RuntimeObservationConfig>,
    #[serde(default)]
    pub container_runtime: Option<ContainerRuntimeConfig>,
    #[serde(default)]
    pub workload_bindings: Vec<WorkloadBindingConfig>,
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
                    && runtime.reconciliation_interval_ms > 0,
                InvalidConfigurationSnafu {
                    reason: "container runtime requires an absolute socket path and a nonzero reconciliation interval",
                }
            );
        }
        let mut binding_ids = BTreeSet::new();
        let mut execution_set_ids = BTreeSet::new();
        let mut container_ids = BTreeSet::new();
        for binding in &self.workload_bindings {
            ensure!(
                (32..=128).contains(&binding.container_id.len())
                    && (1..=64).contains(&binding.pod_uid.len())
                    && (1..=128).contains(&binding.sandbox_id.len())
                    && (1..=253).contains(&binding.container_name.len())
                    && !binding.image_digest.is_empty()
                    && binding.container_generation > 0
                    && binding.lifecycle_generation > 0
                    && binding.active_profile_generation_ref_id > 0
                    && binding.initial_role_id > 0
                    && binding.external_role_id > 0,
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
        Ok(())
    }

    pub(crate) fn binding_reconciliation_interval(&self) -> Option<Duration> {
        (!self.workload_bindings.is_empty()).then(|| {
            Duration::from_millis(
                self.container_runtime
                    .as_ref()
                    .map_or_else(default_runtime_reconciliation_ms, |runtime| {
                        runtime.reconciliation_interval_ms
                    }),
            )
        })
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        ContainerKindV1, InterceptorConfig, NodeConfig, NodeControlConfig, WorkloadBindingConfig,
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
            runtime_observation: None,
            container_runtime: None,
            workload_bindings: vec![WorkloadBindingConfig {
                binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                container_id: "a".repeat(64),
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
        }
    }

    #[test]
    fn configured_cgroup_binding_does_not_require_cri() -> crate::Result<()> {
        let config = config();
        config.validate()?;
        assert_eq!(
            config.binding_reconciliation_interval(),
            Some(Duration::from_secs(2))
        );
        Ok(())
    }

    #[test]
    fn cri_binding_resolves_its_cgroup_locally() -> crate::Result<()> {
        let mut config = config();
        config.container_runtime = Some(super::ContainerRuntimeConfig {
            socket_path: PathBuf::from("/run/containerd/containerd.sock"),
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings[0].root_cgroup_path = None;
        config.validate()
    }

    #[test]
    fn non_cri_binding_requires_an_exact_cgroup() {
        let mut config = config();
        config.workload_bindings[0].root_cgroup_path = None;
        assert!(config.validate().is_err());
    }
}
