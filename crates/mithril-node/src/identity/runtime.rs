use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::{
    ContainerFilter, ContainerState, ContainerStatusRequest, ListContainersRequest, VersionRequest,
};
use snafu::{ensure, ResultExt as _};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::error::{ContainerRuntimeRpcSnafu, ContainerRuntimeTransportSnafu, IdentityStateSnafu};
use crate::{Result, WorkloadBindingConfig};

const POD_UID_LABEL: &str = "io.kubernetes.pod.uid";
const CONTAINER_NAME_LABEL: &str = "io.kubernetes.container.name";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeContainerIdentity {
    pub full_container_id: String,
    pub pod_uid: String,
    pub sandbox_id: String,
    pub container_name: String,
    pub image_digest: String,
    pub generation: u64,
    pub cgroup_path: PathBuf,
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

    pub(super) async fn validate(
        &mut self,
        expected: &WorkloadBindingConfig,
    ) -> Result<RuntimeContainerIdentity> {
        let listed = self
            .client
            .list_containers(ListContainersRequest {
                filter: Some(ContainerFilter {
                    id: expected.container_id.clone(),
                    ..ContainerFilter::default()
                }),
            })
            .await
            .context(ContainerRuntimeRpcSnafu)?
            .into_inner()
            .containers;
        let mut exact = listed
            .into_iter()
            .filter(|container| container.id == expected.container_id);
        let container = exact.next().ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "CRI has no exact live container `{}`",
                    expected.container_id
                ),
            }
            .build()
        })?;
        ensure!(
            exact.next().is_none()
                && container.state == ContainerState::ContainerRunning as i32
                && container.pod_sandbox_id == expected.sandbox_id,
            IdentityStateSnafu {
                reason: format!(
                    "CRI container `{}` is duplicated, stopped, or in another sandbox",
                    expected.container_id
                ),
            }
        );

        let response = self
            .client
            .container_status(ContainerStatusRequest {
                container_id: expected.container_id.clone(),
                verbose: true,
            })
            .await
            .context(ContainerRuntimeRpcSnafu)?
            .into_inner();
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
        ensure!(
            status.id == expected.container_id
                && status.state == ContainerState::ContainerRunning as i32
                && generation == expected.container_generation
                && pod_uid == &expected.pod_uid
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
        Ok(RuntimeContainerIdentity {
            full_container_id: status.id,
            pod_uid: pod_uid.clone(),
            sandbox_id: container.pod_sandbox_id,
            container_name: container_name.clone(),
            image_digest: status.image_ref,
            generation,
            cgroup_path,
        })
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
    let raw = value
        .pointer("/runtimeSpec/linux/cgroupsPath")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "CRI verbose status has no runtimeSpec.linux.cgroupsPath".to_owned(),
            }
            .build()
        })?;
    let relative = parse_cgroup_path(raw)?;
    Ok(cgroup_root.join(relative.strip_prefix("/").unwrap_or(&relative)))
}

fn parse_cgroup_path(raw: &str) -> Result<PathBuf> {
    if raw.starts_with('/') && !raw.split('/').any(|part| part == "..") {
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

    use super::parse_cgroup_path;

    #[test]
    fn accepts_absolute_and_expands_systemd_cgroup_paths() -> crate::Result<()> {
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
        Ok(())
    }
}
