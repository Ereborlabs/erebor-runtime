use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use containerd_client::services::v1::{events_client::EventsClient, SubscribeRequest};
use hyper_util::rt::TokioIo;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::{
    Container, ContainerState, ContainerStatusRequest, ContainerStatusResponse,
    ListContainersRequest, VersionRequest,
};
use procfs::process::Process;
use snafu::{ensure, ResultExt as _};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::error::{
    ContainerRuntimeProcessSnafu, ContainerRuntimeRpcSnafu, ContainerRuntimeTransportSnafu,
    IdentityStateSnafu, IoSnafu,
};
use crate::{ContainerRuntimeConfig, Result, WorkloadBindingConfig};

const POD_UID_LABEL: &str = "io.kubernetes.pod.uid";
const CONTAINER_NAME_LABEL: &str = "io.kubernetes.container.name";
const POD_NAMESPACE_LABEL: &str = "io.kubernetes.pod.namespace";
const CONTAINERD_KUBERNETES_NAMESPACE_FILTER: &str = "namespace==k8s.io";
const EVENT_RECONNECT_MINIMUM: Duration = Duration::from_secs(5);
const EVENT_RECONNECT_MAXIMUM: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeContainerState {
    Created,
    Running,
}

#[derive(Clone, Debug)]
pub struct CriRuntimeContainerObservationV1 {
    pub listed: Container,
    pub status: ContainerStatusResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeContainerIdentity {
    pub full_container_id: String,
    pub namespace: String,
    pub pod_uid: String,
    pub sandbox_id: String,
    pub container_name: String,
    pub image_digest: String,
    pub generation: u64,
    pub cgroup_path: PathBuf,
    pub init_pid: u32,
    pub working_directory: PathBuf,
    pub path_entries: Vec<PathBuf>,
    pub state: RuntimeContainerState,
}

impl RuntimeContainerIdentity {
    pub(super) fn resolve(
        &self,
        configured: &WorkloadBindingConfig,
    ) -> Result<WorkloadBindingConfig> {
        let mut resolved = configured.clone();
        if configured.container_id.starts_with("scheduled:") {
            let authority = configured
                .scheduled_binding_authority_id
                .as_deref()
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "scheduled runtime binding has no signed authority".to_owned(),
                    }
                    .build()
                })?;
            ensure!(
                self.state == RuntimeContainerState::Running
                    && configured.binding_id == authority
                    && authority
                        == crate::runtime_admission::ScheduledRuntimeBindingV1::authority_binding_id(
                            &configured.pod_uid,
                            &configured.container_name,
                        )
                    && configured.root_cgroup_path.is_none()
                    && configured.arm_initial_root
                    && self.matches_scheduled(configured),
                IdentityStateSnafu {
                    reason: "running CRI identity differs from its signed scheduled target",
                }
            );
            resolved.binding_id =
                crate::runtime_admission::ScheduledRuntimeBindingV1::runtime_binding_id(
                    authority,
                    &self.full_container_id,
                );
            resolved.container_id.clone_from(&self.full_container_id);
            resolved.sandbox_id.clone_from(&self.sandbox_id);
            resolved.container_generation = self.generation;
        }
        resolved.root_cgroup_path = Some(self.cgroup_path.clone());
        resolved.arm_initial_root =
            configured.arm_initial_root && self.state == RuntimeContainerState::Created;
        Ok(resolved)
    }

    pub(super) fn matches_scheduled(&self, configured: &WorkloadBindingConfig) -> bool {
        configured.container_id.starts_with("scheduled:")
            && self.state == RuntimeContainerState::Running
            && self.namespace == configured.namespace
            && self.pod_uid == configured.pod_uid
            && self.container_name == configured.container_name
            && self.image_digest == configured.image_digest
    }

    pub(super) fn accepts_observed_lifetime(&self, observed: &Self) -> bool {
        self.full_container_id == observed.full_container_id
            && self.namespace == observed.namespace
            && self.pod_uid == observed.pod_uid
            && self.sandbox_id == observed.sandbox_id
            && self.container_name == observed.container_name
            && self.image_digest == observed.image_digest
            && self.generation == observed.generation
            && self.cgroup_path == observed.cgroup_path
            && (self.init_pid == observed.init_pid
                || (self.state == RuntimeContainerState::Created
                    && self.init_pid == 0
                    && observed.state == RuntimeContainerState::Running
                    && observed.init_pid > 0))
            && self.working_directory == observed.working_directory
            && self.path_entries == observed.path_entries
    }
}

pub(super) struct ContainerRuntimeInventory {
    client: RuntimeServiceClient<Channel>,
    cgroup_root: PathBuf,
    runtime_socket_path: PathBuf,
    event_stream: Option<tonic::Streaming<containerd_client::types::Envelope>>,
    fallback_scan_interval: Duration,
    event_reconnect_delay: Duration,
    event_reconnect_at: tokio::time::Instant,
}

impl ContainerRuntimeInventory {
    pub(super) async fn connect(
        runtime: &ContainerRuntimeConfig,
        cgroup_root: &Path,
    ) -> Result<Self> {
        let socket_path = runtime.socket_path.clone();
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
            runtime_socket_path: runtime.socket_path.clone(),
            event_stream: None,
            fallback_scan_interval: Duration::from_millis(runtime.reconciliation_interval_ms),
            event_reconnect_delay: EVENT_RECONNECT_MINIMUM,
            event_reconnect_at: tokio::time::Instant::now(),
        })
    }

    pub(super) async fn wait_for_change(&mut self) {
        let fallback_at = tokio::time::Instant::now() + self.fallback_scan_interval;
        loop {
            if let Some(events) = self.event_stream.as_mut() {
                match tokio::time::timeout_at(fallback_at, events.message()).await {
                    Err(_) => return,
                    Ok(Ok(Some(event)))
                        if matches!(
                            event.topic.as_str(),
                            "/containers/create"
                                | "/containers/update"
                                | "/containers/delete"
                                | "/tasks/create"
                                | "/tasks/start"
                                | "/tasks/delete"
                                | "/tasks/exit"
                        ) =>
                    {
                        return
                    }
                    Ok(Ok(Some(_event))) => continue,
                    Ok(Ok(None) | Err(_)) => {
                        self.event_stream = None;
                        self.event_reconnect_delay = EVENT_RECONNECT_MINIMUM;
                        self.event_reconnect_at =
                            tokio::time::Instant::now() + self.event_reconnect_delay;
                        return;
                    }
                }
            }
            let now = tokio::time::Instant::now();
            if now >= self.event_reconnect_at {
                if self.subscribe_to_runtime_events().await {
                    self.event_reconnect_delay = EVENT_RECONNECT_MINIMUM;
                    self.event_reconnect_at = now;
                    return;
                }
                self.event_reconnect_at = now + self.event_reconnect_delay;
                self.event_reconnect_delay = self
                    .event_reconnect_delay
                    .saturating_mul(2)
                    .min(EVENT_RECONNECT_MAXIMUM);
            }
            let wake_at = fallback_at.min(self.event_reconnect_at);
            tokio::time::sleep_until(wake_at).await;
            if wake_at == fallback_at {
                return;
            }
        }
    }

    async fn subscribe_to_runtime_events(&mut self) -> bool {
        let Ok(channel) = containerd_client::connect(&self.runtime_socket_path).await else {
            return false;
        };
        let mut client = EventsClient::new(channel);
        let Ok(response) = client
            .subscribe(SubscribeRequest {
                filters: vec![CONTAINERD_KUBERNETES_NAMESPACE_FILTER.to_owned()],
            })
            .await
        else {
            return false;
        };
        self.event_stream = Some(response.into_inner());
        true
    }

    pub(super) async fn snapshot(
        &mut self,
        configured: &[WorkloadBindingConfig],
    ) -> Result<Vec<RuntimeContainerIdentity>> {
        let expected: BTreeMap<&str, &WorkloadBindingConfig> = configured
            .iter()
            .filter(|binding| !binding.container_id.starts_with("scheduled:"))
            .map(|binding| (binding.container_id.as_str(), binding))
            .collect();
        let listed = self
            .client
            .list_containers(ListContainersRequest { filter: None })
            .await
            .context(ContainerRuntimeRpcSnafu)?
            .into_inner()
            .containers;
        let mut observations = Vec::with_capacity(expected.len());
        for container in listed {
            let selected = expected.contains_key(container.id.as_str())
                || scheduled_recovery_target(&container, configured)?.is_some();
            if !selected {
                continue;
            }
            if let Some(observation) = self.observe(container).await? {
                observations.push(observation);
            }
        }
        runtime_identities_from_observations(observations, configured, &self.cgroup_root)
    }

    pub(super) async fn inspect_created_for_admission(
        &mut self,
        expected: &WorkloadBindingConfig,
    ) -> Result<RuntimeContainerIdentity> {
        // Query CRI directly; hook annotations alone are not runtime identity proof.
        let listed = self
            .client
            .list_containers(ListContainersRequest { filter: None })
            .await
            .context(ContainerRuntimeRpcSnafu)?
            .into_inner()
            .containers
            .into_iter()
            .filter(|container| container.id == expected.container_id)
            .collect::<Vec<_>>();
        ensure!(
            listed.len() == 1
                && listed[0].state == ContainerState::ContainerCreated as i32
                && listed[0].pod_sandbox_id == expected.sandbox_id,
            IdentityStateSnafu {
                reason: "runtime admission container is not one exact Created CRI record",
            }
        );
        let container = listed.into_iter().next().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission lost its CRI container".to_owned(),
            }
            .build()
        })?;
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
                reason: "runtime admission CRI response has no status".to_owned(),
            }
            .build()
        })?;
        let metadata = status.metadata.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission CRI status has no metadata".to_owned(),
            }
            .build()
        })?;
        let generation = u64::try_from(status.created_at)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "runtime admission CRI creation time is invalid".to_owned(),
                }
                .build()
            })?;
        let pod_uid = status.labels.get(POD_UID_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission CRI status has no Pod UID".to_owned(),
            }
            .build()
        })?;
        let namespace = status.labels.get(POD_NAMESPACE_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission CRI status has no namespace".to_owned(),
            }
            .build()
        })?;
        let container_name = status.labels.get(CONTAINER_NAME_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission CRI status has no container name".to_owned(),
            }
            .build()
        })?;
        ensure!(
            status.id == expected.container_id
                && status.state == ContainerState::ContainerCreated as i32
                && namespace == &expected.namespace
                && pod_uid == &expected.pod_uid
                && container_name == &expected.container_name
                && metadata.name == expected.container_name
                && status.image_ref.ends_with(&expected.image_digest),
            IdentityStateSnafu {
                reason: "runtime admission CRI identity differs from signed workload material",
            }
        );
        // Runtime admission verifies this CRI cgroup while the initial task is held.
        let process = runtime_process_from_info(
            &response.info,
            &self.cgroup_root,
            RuntimeContainerState::Created,
        )?;
        ensure!(
            process.init_pid == 0,
            IdentityStateSnafu {
                reason: "runtime admission CRI record already has a running initial process",
            }
        );
        if let Some(expected_cgroup) = expected.root_cgroup_path.as_ref() {
            ensure!(
                fs::canonicalize(&process.cgroup_path).context(IoSnafu {
                    path: &process.cgroup_path,
                })? == fs::canonicalize(expected_cgroup).context(IoSnafu {
                    path: expected_cgroup,
                })?,
                IdentityStateSnafu {
                    reason: "runtime admission CRI cgroup differs from the held initial process",
                }
            );
        }
        Ok(RuntimeContainerIdentity {
            full_container_id: status.id,
            namespace: namespace.clone(),
            pod_uid: pod_uid.clone(),
            sandbox_id: container.pod_sandbox_id,
            container_name: container_name.clone(),
            image_digest: expected.image_digest.clone(),
            generation,
            cgroup_path: process.cgroup_path,
            init_pid: process.init_pid,
            working_directory: process.working_directory,
            path_entries: process.path_entries,
            state: RuntimeContainerState::Created,
        })
    }

    async fn observe(
        &mut self,
        container: k8s_cri::v1::Container,
    ) -> Result<Option<CriRuntimeContainerObservationV1>> {
        let requested_container_id = container.id.clone();
        let response = match self
            .client
            .container_status(ContainerStatusRequest {
                container_id: requested_container_id.clone(),
                verbose: true,
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(source) if source.code() == tonic::Code::NotFound => return Ok(None),
            Err(source) => Err(source).context(ContainerRuntimeRpcSnafu)?,
        };
        Ok(Some(CriRuntimeContainerObservationV1 {
            listed: container,
            status: response,
        }))
    }
}

pub(super) fn runtime_identities_from_observations(
    observations: Vec<CriRuntimeContainerObservationV1>,
    configured: &[WorkloadBindingConfig],
    cgroup_root: &Path,
) -> Result<Vec<RuntimeContainerIdentity>> {
    let expected: BTreeMap<&str, &WorkloadBindingConfig> = configured
        .iter()
        .filter(|binding| !binding.container_id.starts_with("scheduled:"))
        .map(|binding| (binding.container_id.as_str(), binding))
        .collect();
    let mut seen = BTreeSet::new();
    let mut identities = Vec::with_capacity(observations.len());
    for observation in observations {
        let container = observation.listed;
        let expected = match expected.get(container.id.as_str()) {
            Some(expected) => Some(*expected),
            None => scheduled_recovery_target(&container, configured)?,
        };
        let Some(expected) = expected else {
            continue;
        };
        ensure!(
            seen.insert(container.id.clone()),
            IdentityStateSnafu {
                reason: format!("CRI returned duplicate container `{}`", container.id),
            }
        );
        if runtime_state_for_reconciliation(container.state, expected.container_generation)
            .is_none()
        {
            continue;
        }
        let requested_container_id = container.id.clone();
        let response = observation.status;
        let status = response.status.ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "CRI returned no status for container `{}`",
                    requested_container_id
                ),
            }
            .build()
        })?;
        let metadata = status.metadata.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "CRI returned no metadata for container `{}`",
                    requested_container_id
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
        let namespace = status.labels.get(POD_NAMESPACE_LABEL).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("CRI status is missing `{POD_NAMESPACE_LABEL}`"),
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
            continue;
        };
        let scheduled = expected.container_id.starts_with("scheduled:");
        ensure!(
            status.id == requested_container_id
                && namespace == &expected.namespace
                && pod_uid == &expected.pod_uid
                && container_name == &expected.container_name
                && metadata.name == expected.container_name
                && status.image_ref.ends_with(&expected.image_digest)
                && if scheduled {
                    status_state == RuntimeContainerState::Running
                } else {
                    status.id == expected.container_id
                        && generation == expected.container_generation
                        && container.pod_sandbox_id == expected.sandbox_id
                },
            IdentityStateSnafu {
                reason: format!(
                    "CRI identity for `{}` differs from its workload binding",
                    requested_container_id
                ),
            }
        );
        let runtime = runtime_process_from_info(&response.info, cgroup_root, status_state)?;
        identities.push(RuntimeContainerIdentity {
            full_container_id: status.id,
            namespace: namespace.clone(),
            pod_uid: pod_uid.clone(),
            sandbox_id: container.pod_sandbox_id,
            container_name: container_name.clone(),
            image_digest: expected.image_digest.clone(),
            generation,
            cgroup_path: runtime.cgroup_path,
            init_pid: runtime.init_pid,
            working_directory: runtime.working_directory,
            path_entries: runtime.path_entries,
            state: status_state,
        });
    }
    identities.sort_by(|left, right| left.full_container_id.cmp(&right.full_container_id));
    Ok(identities)
}

pub(super) fn scheduled_recovery_target<'a>(
    container: &Container,
    configured: &'a [WorkloadBindingConfig],
) -> Result<Option<&'a WorkloadBindingConfig>> {
    if container.state != ContainerState::ContainerRunning as i32 {
        return Ok(None);
    }
    let matches = configured
        .iter()
        .filter(|binding| {
            binding.container_id.starts_with("scheduled:")
                && container
                    .labels
                    .get(POD_NAMESPACE_LABEL)
                    .is_some_and(|namespace| namespace == &binding.namespace)
                && container
                    .labels
                    .get(POD_UID_LABEL)
                    .is_some_and(|pod_uid| pod_uid == &binding.pod_uid)
                && container
                    .labels
                    .get(CONTAINER_NAME_LABEL)
                    .is_some_and(|name| name == &binding.container_name)
                && container
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.name == binding.container_name)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() <= 1,
        IdentityStateSnafu {
            reason: format!(
                "running CRI container `{}` matches more than one signed scheduled target",
                container.id
            ),
        }
    );
    Ok(matches.into_iter().next())
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

const fn runtime_state_for_reconciliation(
    raw: i32,
    configured_generation: u64,
) -> Option<RuntimeContainerState> {
    let state = runtime_state(raw);
    // The ordered OCI hooks own Created records until preparation binds the generation.
    if matches!(state, Some(RuntimeContainerState::Created)) && configured_generation == 0 {
        None
    } else {
        state
    }
}

struct RuntimeProcessIdentity {
    cgroup_path: PathBuf,
    init_pid: u32,
    working_directory: PathBuf,
    path_entries: Vec<PathBuf>,
}

fn runtime_process_from_info(
    info: &std::collections::HashMap<String, String>,
    cgroup_root: &Path,
    state: RuntimeContainerState,
) -> Result<RuntimeProcessIdentity> {
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
    let init_pid = value
        .get("pid")
        .and_then(serde_json::Value::as_i64)
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or_default();
    ensure!(
        state == RuntimeContainerState::Created || init_pid > 0,
        IdentityStateSnafu {
            reason: "running CRI container has no live init PID".to_owned(),
        }
    );
    let working_directory = value
        .pointer("/runtimeSpec/process/cwd")
        .and_then(serde_json::Value::as_str)
        .filter(|path| path.starts_with('/'))
        .map(PathBuf::from)
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "CRI verbose status has no absolute container working directory".to_owned(),
            }
            .build()
        })?;
    let environment = value
        .pointer("/runtimeSpec/process/env")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "CRI verbose status has no container process environment".to_owned(),
            }
            .build()
        })?;
    let path = environment
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find_map(|entry| entry.strip_prefix("PATH="))
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "CRI verbose status has no effective PATH".to_owned(),
            }
            .build()
        })?;
    let path_entries = path
        .split(':')
        .map(|entry| {
            let entry = if entry.is_empty() { "." } else { entry };
            let entry = Path::new(entry);
            let absolute = if entry.is_absolute() {
                entry.to_path_buf()
            } else {
                working_directory.join(entry)
            };
            ensure!(
                absolute.is_absolute()
                    && !absolute
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir)),
                IdentityStateSnafu {
                    reason: "CRI effective PATH contains a non-canonical entry",
                }
            );
            Ok(absolute)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        path_entries.len() <= 64,
        IdentityStateSnafu {
            reason: "CRI effective PATH exceeds 64 entries",
        }
    );
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
    Ok(RuntimeProcessIdentity {
        cgroup_path: cgroup_root.join(relative),
        init_pid,
        working_directory,
        path_entries,
    })
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
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use containerd_client::types::Envelope;
    use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
    use k8s_cri::v1::{Container, ContainerMetadata, ContainerState};
    use tonic::codec::{Codec, ProstCodec};
    use tonic::transport::Endpoint;

    use super::{
        parse_cgroup_path, runtime_cgroup_source, runtime_state, runtime_state_for_reconciliation,
        scheduled_recovery_target, ContainerRuntimeInventory, RuntimeCgroupSource,
        RuntimeContainerIdentity, RuntimeContainerState, CONTAINER_NAME_LABEL, POD_NAMESPACE_LABEL,
        POD_UID_LABEL,
    };
    use crate::{ContainerKindV1, WorkloadBindingConfig};

    #[derive(Debug)]
    struct QuietEventBody;

    impl tonic::codegen::Body for QuietEventBody {
        type Data = tonic::codegen::Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    fn quiet_event_stream() -> tonic::Streaming<Envelope> {
        let mut codec = ProstCodec::<Envelope, Envelope>::default();
        tonic::Streaming::new_response(
            codec.decoder(),
            QuietEventBody,
            tonic::codegen::http::StatusCode::OK,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn connected_quiet_event_stream_uses_inventory_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let channel = Endpoint::from_static("http://[::]").connect_lazy();
        let directory = tempfile::tempdir()?;
        let mut inventory = ContainerRuntimeInventory {
            client: RuntimeServiceClient::new(channel),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            runtime_socket_path: directory.path().join("unused.sock"),
            event_stream: Some(quiet_event_stream()),
            fallback_scan_interval: Duration::from_millis(1),
            event_reconnect_delay: super::EVENT_RECONNECT_MINIMUM,
            event_reconnect_at: tokio::time::Instant::now(),
        };

        tokio::time::timeout(Duration::from_millis(100), inventory.wait_for_change()).await?;
        assert!(inventory.event_stream.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_event_api_uses_backoff_and_inventory_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let channel = Endpoint::from_static("http://[::]").connect_lazy();
        let directory = tempfile::tempdir()?;
        let mut inventory = ContainerRuntimeInventory {
            client: RuntimeServiceClient::new(channel),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            runtime_socket_path: directory.path().join("absent.sock"),
            event_stream: None,
            fallback_scan_interval: Duration::from_millis(1),
            event_reconnect_delay: super::EVENT_RECONNECT_MINIMUM,
            event_reconnect_at: tokio::time::Instant::now(),
        };

        tokio::time::timeout(Duration::from_millis(100), inventory.wait_for_change()).await?;
        assert_eq!(
            inventory.event_reconnect_delay,
            super::EVENT_RECONNECT_MINIMUM.saturating_mul(2)
        );
        Ok(())
    }

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
    fn cri_inventory_separates_admission_owned_created_records() {
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
        assert_eq!(
            runtime_state_for_reconciliation(ContainerState::ContainerCreated as i32, 0),
            None
        );
        assert_eq!(
            runtime_state_for_reconciliation(ContainerState::ContainerCreated as i32, 7),
            Some(RuntimeContainerState::Created)
        );
        assert_eq!(
            runtime_state_for_reconciliation(ContainerState::ContainerRunning as i32, 0),
            Some(RuntimeContainerState::Running)
        );
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
            namespace: configured.namespace.clone(),
            pod_uid: configured.pod_uid.clone(),
            sandbox_id: configured.sandbox_id.clone(),
            container_name: configured.container_name.clone(),
            image_digest: configured.image_digest.clone(),
            generation: configured.container_generation,
            cgroup_path: PathBuf::from("/sys/fs/cgroup/workload"),
            init_pid: 42,
            working_directory: PathBuf::from("/workspace"),
            path_entries: vec![PathBuf::from("/usr/bin")],
            state: RuntimeContainerState::Running,
        };

        let resolved = identity
            .resolve(&configured)
            .expect("resolve running container");
        assert_eq!(
            resolved.root_cgroup_path.as_ref(),
            Some(&identity.cgroup_path)
        );
        assert!(!resolved.arm_initial_root);

        let mut created = identity;
        created.state = RuntimeContainerState::Created;
        created.init_pid = 0;
        assert!(
            created
                .resolve(&configured)
                .expect("resolve created container")
                .arm_initial_root
        );
        assert!(
            created.accepts_observed_lifetime(&RuntimeContainerIdentity {
                init_pid: 42,
                state: RuntimeContainerState::Running,
                ..created.clone()
            })
        );
    }

    #[test]
    fn cri_running_container_resolves_one_signed_scheduled_target() -> crate::Result<()> {
        let authority = crate::runtime_admission::ScheduledRuntimeBindingV1::authority_binding_id(
            "pod-a", "worker",
        );
        let configured = WorkloadBindingConfig {
            binding_id: authority.clone(),
            scheduled_binding_authority_id: Some(authority.clone()),
            scheduled_target_digest: Some("f".repeat(64)),
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: format!("scheduled:{}", "d".repeat(64)),
            namespace: "default".to_owned(),
            cluster_uid: String::new(),
            namespace_uid: String::new(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::new(),
            pod_uid: "pod-a".to_owned(),
            sandbox_id: format!("scheduled:{}", "e".repeat(64)),
            container_name: "worker".to_owned(),
            image_digest: "sha256:image-a".to_owned(),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: None,
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: true,
        };
        let container_id = "a".repeat(64);
        let sandbox_id = "b".repeat(64);
        let container = Container {
            id: container_id.clone(),
            pod_sandbox_id: sandbox_id.clone(),
            metadata: Some(ContainerMetadata {
                name: "worker".to_owned(),
                attempt: 0,
            }),
            image_ref: "sha256:local-content-id".to_owned(),
            state: ContainerState::ContainerRunning as i32,
            labels: [
                (POD_NAMESPACE_LABEL.to_owned(), "default".to_owned()),
                (POD_UID_LABEL.to_owned(), "pod-a".to_owned()),
                (CONTAINER_NAME_LABEL.to_owned(), "worker".to_owned()),
            ]
            .into_iter()
            .collect(),
            ..Container::default()
        };
        assert_eq!(
            scheduled_recovery_target(&container, std::slice::from_ref(&configured))?
                .map(|binding| binding.binding_id.as_str()),
            Some(authority.as_str())
        );

        let identity = RuntimeContainerIdentity {
            full_container_id: container_id.clone(),
            namespace: configured.namespace.clone(),
            pod_uid: configured.pod_uid.clone(),
            sandbox_id: sandbox_id.clone(),
            container_name: configured.container_name.clone(),
            image_digest: configured.image_digest.clone(),
            generation: 42,
            cgroup_path: PathBuf::from("/sys/fs/cgroup/workload"),
            init_pid: 7,
            working_directory: PathBuf::from("/"),
            path_entries: vec![PathBuf::from("/bin")],
            state: RuntimeContainerState::Running,
        };
        let resolved = identity.resolve(&configured)?;
        assert_eq!(resolved.container_id, container_id);
        assert_eq!(resolved.sandbox_id, sandbox_id);
        assert_eq!(resolved.container_generation, 42);
        assert_eq!(
            resolved.binding_id,
            crate::runtime_admission::ScheduledRuntimeBindingV1::runtime_binding_id(
                &authority,
                &resolved.container_id,
            )
        );
        assert_eq!(
            resolved.root_cgroup_path,
            Some(PathBuf::from("/sys/fs/cgroup/workload"))
        );
        assert!(!resolved.arm_initial_root);
        Ok(())
    }
}
