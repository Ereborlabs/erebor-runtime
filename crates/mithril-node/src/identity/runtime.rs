use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::{ContainerState, ContainerStatusRequest, ListContainersRequest, VersionRequest};
use procfs::process::Process;
use snafu::{ensure, ResultExt as _};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::error::{
    ContainerRuntimeProcessSnafu, ContainerRuntimeRpcSnafu, ContainerRuntimeTransportSnafu,
    IdentityStateSnafu,
};
use crate::{Result, WorkloadBindingConfig};

const POD_UID_LABEL: &str = "io.kubernetes.pod.uid";
const CONTAINER_NAME_LABEL: &str = "io.kubernetes.container.name";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeContainerState {
    Created,
    Running,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeContainerIdentity {
    pub full_container_id: String,
    pub pod_uid: String,
    pub sandbox_id: String,
    pub container_name: String,
    pub image_digest: String,
    pub generation: u64,
    pub cgroup_path: PathBuf,
    pub state: RuntimeContainerState,
}

impl RuntimeContainerIdentity {
    pub(super) fn resolve(&self, configured: &WorkloadBindingConfig) -> WorkloadBindingConfig {
        let mut resolved = configured.clone();
        resolved.root_cgroup_path = Some(self.cgroup_path.clone());
        resolved.arm_initial_root =
            configured.arm_initial_root && self.state == RuntimeContainerState::Created;
        resolved
    }

    pub(super) fn same_lifetime_as(&self, other: &Self) -> bool {
        self.full_container_id == other.full_container_id
            && self.pod_uid == other.pod_uid
            && self.sandbox_id == other.sandbox_id
            && self.container_name == other.container_name
            && self.image_digest == other.image_digest
            && self.generation == other.generation
            && self.cgroup_path == other.cgroup_path
    }
}

pub(super) struct ContainerRuntimeInventory {
    client: RuntimeServiceClient<Channel>,
    cgroup_root: PathBuf,
}

impl ContainerRuntimeInventory {
    pub(super) async fn connect(socket_path: &Path, cgroup_root: &Path) -> Result<Self> {
        let socket_path = socket_path.to_path_buf();
        let channel = Endpoint::from_static("http://[::]")
            .connect_with_connector(service_fn(move |_: Uri| {
                let socket_path = socket_path.clone();
                async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
            }))
            .await
            .context(ContainerRuntimeTransportSnafu)?;
        let mut client = RuntimeServiceClient::new(channel);
        client
            .version(VersionRequest {
                version: "0.1.0".to_owned(),
            })
            .await
            .context(ContainerRuntimeRpcSnafu)?;
        Ok(Self {
            client,
            cgroup_root: cgroup_root.to_path_buf(),
        })
    }

    pub(super) async fn snapshot(
        &mut self,
        configured: &[WorkloadBindingConfig],
    ) -> Result<Vec<RuntimeContainerIdentity>> {
        let expected: BTreeMap<&str, &WorkloadBindingConfig> = configured
            .iter()
            .map(|binding| (binding.container_id.as_str(), binding))
            .collect();
        let listed = self
            .client
            .list_containers(ListContainersRequest { filter: None })
            .await
            .context(ContainerRuntimeRpcSnafu)?
            .into_inner()
            .containers;
        let mut seen = BTreeSet::new();
        let mut identities = Vec::with_capacity(expected.len());
        for container in listed {
            let Some(expected) = expected.get(container.id.as_str()) else {
                continue;
            };
            ensure!(
                seen.insert(container.id.clone()),
                IdentityStateSnafu {
                    reason: format!("CRI returned duplicate container `{}`", container.id),
                }
            );
            if runtime_state(container.state).is_none() {
                continue;
            }
            if let Some(identity) = self.inspect(container, expected).await? {
                identities.push(identity);
            }
        }
        identities.sort_by(|left, right| left.full_container_id.cmp(&right.full_container_id));
        Ok(identities)
    }

    async fn inspect(
        &mut self,
        container: k8s_cri::v1::Container,
        expected: &WorkloadBindingConfig,
    ) -> Result<Option<RuntimeContainerIdentity>> {
        let response = match self
            .client
            .container_status(ContainerStatusRequest {
                container_id: expected.container_id.clone(),
                verbose: true,
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(source) if source.code() == tonic::Code::NotFound => return Ok(None),
            Err(source) => Err(source).context(ContainerRuntimeRpcSnafu)?,
        };
        let status = response.status.ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "CRI returned no status for container `{}`",
                    expected.container_id
                ),
            }
            .build()
        })?;
        let metadata = status.metadata.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "CRI returned no metadata for container `{}`",
                    expected.container_id
                ),
            }
            .build()
        })?;
        let generation = u64::try_from(status.created_at).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("CRI container creation time is invalid: {error}"),
            }
            .build()
        })?;
        let pod_uid = status.labels.get(POD_UID_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("CRI status is missing `{POD_UID_LABEL}`"),
            }
            .build()
        })?;
        let container_name = status.labels.get(CONTAINER_NAME_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("CRI status is missing `{CONTAINER_NAME_LABEL}`"),
            }
            .build()
        })?;
        let Some(status_state) = runtime_state(status.state) else {
            return Ok(None);
        };
        ensure!(
            status.id == expected.container_id
                && generation == expected.container_generation
                && pod_uid == &expected.pod_uid
                && container.pod_sandbox_id == expected.sandbox_id
                && container_name == &expected.container_name
                && metadata.name == expected.container_name
                && status.image_ref == expected.image_digest,
            IdentityStateSnafu {
                reason: format!(
                    "CRI identity for `{}` differs from its workload binding",
                    expected.container_id
                ),
            }
        );
        let cgroup_path = cgroup_path_from_info(&response.info, &self.cgroup_root)?;
        Ok(Some(RuntimeContainerIdentity {
            full_container_id: status.id,
            pod_uid: pod_uid.clone(),
            sandbox_id: container.pod_sandbox_id,
            container_name: container_name.clone(),
            image_digest: status.image_ref,
            generation,
            cgroup_path,
            state: status_state,
        }))
    }
}

const fn runtime_state(raw: i32) -> Option<RuntimeContainerState> {
    if raw == ContainerState::ContainerCreated as i32 {
        Some(RuntimeContainerState::Created)
    } else if raw == ContainerState::ContainerRunning as i32 {
        Some(RuntimeContainerState::Running)
    } else {
        None
    }
}

fn cgroup_path_from_info(
    info: &std::collections::HashMap<String, String>,
    cgroup_root: &Path,
) -> Result<PathBuf> {
    let json = info.get("info").ok_or_else(|| {
        IdentityStateSnafu {
            reason: "CRI verbose status has no `info` runtime record".to_owned(),
        }
        .build()
    })?;
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("CRI verbose runtime info is invalid JSON: {error}"),
        }
        .build()
    })?;
    let raw = match runtime_cgroup_source(&value)? {
        RuntimeCgroupSource::Path(raw) => raw,
        RuntimeCgroupSource::Process(pid) => {
            let process = Process::new(pid).context(ContainerRuntimeProcessSnafu { pid })?;
            let groups = process
                .cgroups()
                .context(ContainerRuntimeProcessSnafu { pid })?;
            groups
                .0
                .iter()
                .find(|group| group.hierarchy == 0 && group.controllers.is_empty())
                .map(|group| group.pathname.clone())
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!("container process {pid} has no unified cgroup"),
                    }
                    .build()
                })?
        }
    };
    let relative = parse_cgroup_path(&raw)?;
    let relative = relative.strip_prefix("/").map_err(|error| {
        IdentityStateSnafu {
            reason: format!("CRI cgroup path `{raw}` is not absolute: {error}"),
        }
        .build()
    })?;
    ensure!(
        !relative.as_os_str().is_empty(),
        IdentityStateSnafu {
            reason: "CRI container cgroup cannot be the cgroup root",
        }
    );
    Ok(cgroup_root.join(relative))
}

#[derive(Debug, Eq, PartialEq)]
enum RuntimeCgroupSource {
    Path(String),
    Process(i32),
}

fn runtime_cgroup_source(value: &serde_json::Value) -> Result<RuntimeCgroupSource> {
    if let Some(path) = value
        .pointer("/runtimeSpec/linux/cgroupsPath")
        .and_then(serde_json::Value::as_str)
    {
        return Ok(RuntimeCgroupSource::Path(path.to_owned()));
    }
    value
        .get("pid")
        .and_then(serde_json::Value::as_i64)
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .map(RuntimeCgroupSource::Process)
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "CRI verbose status has neither a cgroup path nor a live PID".to_owned(),
            }
            .build()
        })
}

fn parse_cgroup_path(raw: &str) -> Result<PathBuf> {
    if raw.starts_with('/') && raw != "/" && !raw.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Ok(PathBuf::from(raw));
    }
    let parts: Vec<&str> = raw.split(':').collect();
    ensure!(
        parts.len() == 3
            && !parts
                .iter()
                .any(|part| part.is_empty() || part.contains('/')),
        IdentityStateSnafu {
            reason: format!("CRI cgroup path `{raw}` is not absolute or systemd-formatted"),
        }
    );
    let slice = systemd_slice_path(parts[0])?;
    let name = if parts[2].ends_with(".slice") {
        parts[2].to_owned()
    } else {
        format!("{}-{}.scope", parts[1], parts[2])
    };
    Ok(slice.join(name))
}

fn systemd_slice_path(slice: &str) -> Result<PathBuf> {
    ensure!(
        slice.ends_with(".slice") && slice != ".slice",
        IdentityStateSnafu {
            reason: format!("CRI cgroup slice `{slice}` is invalid"),
        }
    );
    if slice == "-.slice" {
        return Ok(PathBuf::from("/"));
    }
    let mut path = PathBuf::from("/");
    let mut prefix = String::new();
    for component in slice.trim_end_matches(".slice").split('-') {
        ensure!(
            !component.is_empty(),
            IdentityStateSnafu {
                reason: format!("CRI cgroup slice `{slice}` is invalid"),
            }
        );
        prefix.push_str(component);
        path.push(format!("{prefix}.slice"));
        prefix.push('-');
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use k8s_cri::v1::ContainerState;

    use super::{
        parse_cgroup_path, runtime_cgroup_source, runtime_state, RuntimeCgroupSource,
        RuntimeContainerIdentity, RuntimeContainerState,
    };
    use crate::{ContainerKindV1, WorkloadBindingConfig};

    #[test]
    fn cri_paths_accept_cgroupfs_and_expand_systemd_shapes() -> crate::Result<()> {
        assert_eq!(
            parse_cgroup_path("/kubepods/pod/container")?,
            PathBuf::from("/kubepods/pod/container")
        );
        assert_eq!(
            parse_cgroup_path("kubepods-burstable-pod123.slice:cri-containerd:abc")?,
            PathBuf::from(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc.scope"
            )
        );
        assert!(parse_cgroup_path("relative/path").is_err());
        assert!(parse_cgroup_path("/").is_err());
        assert!(parse_cgroup_path("/kubepods/../escape").is_err());
        Ok(())
    }

    #[test]
    fn cri_inventory_accepts_only_created_or_running_containers() {
        assert_eq!(
            runtime_state(ContainerState::ContainerCreated as i32),
            Some(RuntimeContainerState::Created)
        );
        assert_eq!(
            runtime_state(ContainerState::ContainerRunning as i32),
            Some(RuntimeContainerState::Running)
        );
        assert_eq!(runtime_state(ContainerState::ContainerExited as i32), None);
        assert_eq!(runtime_state(ContainerState::ContainerUnknown as i32), None);
    }

    #[test]
    fn cri_cgroup_source_accepts_oci_paths_and_cri_dockerd_pids() -> crate::Result<()> {
        assert_eq!(
            runtime_cgroup_source(&serde_json::json!({
                "runtimeSpec": { "linux": { "cgroupsPath": "/kubepods/pod/container" } },
                "pid": 11
            }))?,
            RuntimeCgroupSource::Path("/kubepods/pod/container".to_owned())
        );
        assert_eq!(
            runtime_cgroup_source(&serde_json::json!({ "pid": 42 }))?,
            RuntimeCgroupSource::Process(42)
        );
        assert!(runtime_cgroup_source(&serde_json::json!({ "pid": 0 })).is_err());
        Ok(())
    }

    #[test]
    fn cri_running_container_resolves_local_cgroup_conservatively() {
        let configured = WorkloadBindingConfig {
            binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: "a".repeat(64),
            pod_uid: "pod-a".to_owned(),
            sandbox_id: "sandbox-a".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: "sha256:image-a".to_owned(),
            container_kind: ContainerKindV1::Application,
            container_generation: 7,
            root_cgroup_path: None,
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: true,
        };
        let identity = RuntimeContainerIdentity {
            full_container_id: configured.container_id.clone(),
            pod_uid: configured.pod_uid.clone(),
            sandbox_id: configured.sandbox_id.clone(),
            container_name: configured.container_name.clone(),
            image_digest: configured.image_digest.clone(),
            generation: configured.container_generation,
            cgroup_path: PathBuf::from("/sys/fs/cgroup/workload"),
            state: RuntimeContainerState::Running,
        };

        let resolved = identity.resolve(&configured);
        assert_eq!(
            resolved.root_cgroup_path.as_ref(),
            Some(&identity.cgroup_path)
        );
        assert!(!resolved.arm_initial_root);

        let mut created = identity;
        created.state = RuntimeContainerState::Created;
        assert!(created.resolve(&configured).arm_initial_root);
        assert!(created.same_lifetime_as(&RuntimeContainerIdentity {
            state: RuntimeContainerState::Running,
            ..created.clone()
        }));
    }
}
