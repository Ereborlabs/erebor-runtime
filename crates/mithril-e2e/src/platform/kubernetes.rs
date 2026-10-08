use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{TaskCoordinateStateV1, TaskCoordinateV1};
use erebor_runtime_client::{AraphorClient, AraphorProfile};
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{
    Namespace, Node, PersistentVolumeClaim, Pod, Secret, ServiceAccount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config, ResourceExt as _};
use mithril_control::{
    ControlConfig, ControlPlane, KubernetesConditionStatusV1, PolicySignerTrustV1, TraceAcceptedV1,
    TraceAccessV1, TraceBatchV1, TraceOwner, TraceRecipeV1, TraceRequestV1, TraceTerminalReasonV1,
    TrustGenerationV1, WorkloadProtectionException, WorkloadProtectionExceptionStateV1,
    WorkloadProtectionPolicy, KUBERNETES_LABEL_EPOCH_ANNOTATION, KUBERNETES_NODE_BOOT_ANNOTATION,
    KUBERNETES_NODE_ID_ANNOTATION, KUBERNETES_NODE_UID_ANNOTATION, KUBERNETES_NOT_READY_TAINT,
    KUBERNETES_PROFILE_ANNOTATION, KUBERNETES_READY_LABEL, KUBERNETES_SOURCE_ANNOTATION,
};
use mithril_node::{
    NativeIdentityInspector, NativeTaskSnapshotV1, NodeConfig, RuntimeAdmissionClient,
    RuntimeIntegrationDecommissionV1, RuntimeIntegrationOwner, RuntimeRecoveryMountInputV1,
};
use prost::Message as _;
use serde_json::{json, Value};
use snafu::ResultExt as _;
use zerocopy::TryFromBytes as _;

use super::kubernetes_approval::KubernetesApproval;
use super::lifecycle::{enter, LifecycleGuard};
use super::{policy_path, GroupActor, Platform, Task, TestResult};
use crate::control_fixture::MtlsFixture;
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::physical::{
    wait_for, wait_for_async, wait_stable, ProbeCgroup, ProbeDirectory, ProbeFile,
};
use crate::process::ProcessFixture;

struct PodCapture {
    control: ControlPlane,
    traces: TraceOwner,
    directory: PathBuf,
    namespace: String,
    pod_name: String,
    tenant_id: [u8; 16],
    query_profile: AraphorProfile,
}

const READY_LIMIT: Duration = Duration::from_secs(180);
const STOP_LIMIT: Duration = Duration::from_secs(120);
const SELECTOR: &str = "mithril.erebor.dev/pid-reuse";
const ACTOR: &str = "pid-reuse";
const CONTAINER: &str = "worker";
const NODE_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

mod actor;
#[cfg(test)]
mod graph_notification;

pub(crate) struct Kubernetes {
    lifecycle: Option<LifecycleGuard<'static, KubernetesState>>,
}

pub(crate) struct KubernetesState {
    namespace: String,
    scenario: String,
    work_path: PathBuf,
    work: Option<ProbeDirectory>,
    directories: Vec<ProbeDirectory>,
    move_group: Option<ProbeCgroup>,
    groups: Vec<ProbeCgroup>,
    work_up: bool,
    actor_name: String,
    actor_id: Option<String>,
    actor_pid: Option<u32>,
    actor_cgroup: Option<PathBuf>,
    labels: super::Labels,
    policies: BTreeMap<super::Labels, String>,
    actors: BTreeMap<super::Labels, u32>,
    policy_name: Option<String>,
    root: PathBuf,
    out: Option<ProbeDirectory>,
    state_path: PathBuf,
    identity_path: PathBuf,
    config_path: PathBuf,
    control_path: PathBuf,
    values_path: PathBuf,
    pin_path: PathBuf,
    lease_path: PathBuf,
    socket_path: PathBuf,
    observation_path: PathBuf,
    seccomp_path: PathBuf,
    kube_path: PathBuf,
    helm_path: PathBuf,
    k3s_path: PathBuf,
    exec_path: PathBuf,
    node_image: String,
    control_image: String,
    actor_image: String,
    actor_python: String,
    actor_entry: String,
    system: String,
    token: String,
    node_name: String,
    client: Client,
    runtime: tokio::runtime::Runtime,
    tls: MtlsFixture,
    inspector: NativeIdentityInspector,
    reader: KernelStateReader,
    approval: Mutex<KubernetesApproval>,
    state: Option<ProbeDirectory>,
    identity: Option<ProbeDirectory>,
    config: Option<ProbeFile>,
    control_file: Option<ProbeFile>,
    values: Option<ProbeFile>,
    pin: Option<ProbeDirectory>,
    lease: Option<ProbeFile>,
    socket: Option<ProbeFile>,
    observation: Option<ProbeFile>,
    seccomp: Option<ProbeFile>,
    system_up: bool,
    helm_up: bool,
    hook_up: bool,
    runtime_up: bool,
}

impl Deref for Kubernetes {
    type Target = KubernetesState;

    fn deref(&self) -> &Self::Target {
        match self.lifecycle.as_ref().and_then(LifecycleGuard::get) {
            Some(state) => state,
            None => unreachable!("the Kubernetes lifecycle is closed"),
        }
    }
}

impl DerefMut for Kubernetes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.lifecycle.as_mut().and_then(LifecycleGuard::get_mut) {
            Some(state) => state,
            None => unreachable!("the Kubernetes lifecycle is closed"),
        }
    }
}

impl KubernetesState {
    fn approval(&self) -> TestResult<MutexGuard<'_, KubernetesApproval>> {
        self.approval
            .lock()
            .map_err(|error| format!("Kubernetes approval state is poisoned: {error}").into())
    }

    fn approve_entry(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.ready_node()?;
        let mut approval = self.approval()?;
        approval.start_forward(&self.runtime, &self.system)?;
        approval.approve(
            &self.runtime,
            &self.work_path,
            &self.namespace,
            command,
            args,
        )
    }

    fn diagnostics(&self) -> String {
        let pod = self.pod().map(|pod| pod.status);
        let logs = self.logs(&self.namespace, &format!("pod/{}", self.actor_name));
        let node = self.logs(&self.system, "daemonset/mithril-node");
        let control = self.logs(&self.system, "deployment/mithril-control");
        let previous = self.log_history(&self.system, "deployment/mithril-control", true);
        let status = self
            .runtime
            .block_on(
                Api::<Pod>::namespaced(self.client.clone(), &self.system).list(
                    &ListParams::default()
                        .labels("app.kubernetes.io/name=mithril-control")
                        .limit(2),
                ),
            )
            .map(|list| {
                list.items
                    .into_iter()
                    .map(|pod| (pod.metadata.name, pod.metadata.uid, pod.status))
                    .collect::<Vec<_>>()
            });
        let events = self.snapshot().map(|mut snapshot| {
            snapshot.recent_effects.reverse();
            snapshot.recent_effects.truncate(16);
            snapshot.recent_effects
        });
        format!("Pod: {pod:?}; logs: {logs:?}; Node logs: {node:?}; Control status: {status:?}; Control logs: {control:?}; Previous Control logs: {previous:?}; effects: {events:?}")
    }

    fn fixture(&self, name: &str) -> PathBuf {
        self.root
            .join("crates/mithril-e2e/fixtures/kubernetes")
            .join(name)
    }

    fn resource(namespace: &str, kind: &str, name: &str) -> PathBuf {
        PathBuf::from(format!("kubernetes/{namespace}/{kind}/{name}"))
    }

    fn set(document: &mut Value, path: &str, value: Value) -> TestResult<()> {
        let target = document
            .pointer_mut(path)
            .ok_or_else(|| format!("the checked fixture has no {path}"))?;
        *target = value;
        Ok(())
    }

    fn path(name: &'static str, default: &str) -> TestResult<PathBuf> {
        Ok(env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default)))
    }

    fn required(name: &'static str) -> TestResult<String> {
        env::var(name).map_err(|_| format!("{name} is not set").into())
    }

    fn run(command: &mut Command, operation: &str) -> TestResult<String> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!(
                "{operation} failed with {}; stdout: {:?}; stderr: {:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    fn require_image(k3s: &Path, image: &str) -> TestResult<()> {
        let mut command = Command::new(k3s);
        command.args(["crictl", "inspecti", image]);
        Self::run(&mut command, "verify prepared Kubernetes image")
            .map(|_| ())
            .map_err(|source| {
                format!("Kubernetes infrastructure did not prepare image {image}: {source}").into()
            })
    }

    fn logs(&self, namespace: &str, target: &str) -> TestResult<String> {
        self.log_history(namespace, target, false)
    }

    fn log_history(&self, namespace: &str, target: &str, previous: bool) -> TestResult<String> {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .args(["--kubeconfig"])
            .arg(&self.kube_path)
            .args(["-n", namespace, "logs", target])
            .args(["--all-containers=true", "--tail=200"]);
        if previous {
            command.arg("--previous");
        }
        Self::run(&mut command, "read Kubernetes logs")
    }

    fn logs_for(&self, name: &str) -> TestResult<String> {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube_path)
            .args(["-n", &self.namespace, "logs", &self.actor_name, "-c", name]);
        Self::run(&mut command, "read Kubernetes actor logs")
    }

    fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        super::observation::Observation::new(self.observation_path.clone()).snapshot()
    }

    fn install_exception(&mut self, bytes: &[u8], path: &Path) -> TestResult<()> {
        let mut resource: WorkloadProtectionException = serde_json::from_slice(bytes)?;
        let name = resource
            .metadata
            .name
            .clone()
            .ok_or("the exception fixture has no metadata.name")?;
        let pod = self.pod()?;
        resource.metadata = ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(self.namespace.clone()),
            ..ObjectMeta::default()
        };
        resource.spec.policy_ref.name = self
            .policy_name
            .clone()
            .ok_or("the exception has no installed policy")?;
        resource.spec.target.pod.name = self.actor_name.clone();
        resource.spec.target.pod.uid = pod.metadata.uid.ok_or("the actor Pod has no UID")?;
        resource.spec.target.container_name = CONTAINER.to_owned();
        let resources =
            Api::<WorkloadProtectionException>::namespaced(self.client.clone(), &self.namespace);
        self.runtime
            .block_on(resources.create(&PostParams::default(), &resource))?;
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            path,
            "Kubernetes exception activation",
            READY_LIMIT,
            || {
                let current = match self.runtime.block_on(resources.get(&name)) {
                    Ok(current) => current,
                    Err(source) => {
                        return InvalidInputSnafu {
                            path,
                            reason: format!("Kubernetes exception read failed: {source}"),
                        }
                        .fail();
                    }
                };
                *last.borrow_mut() = format!("{:?}", current.status);
                Ok(current
                    .status
                    .is_some_and(|status| {
                        status.state == WorkloadProtectionExceptionStateV1::Active
                    })
                    .then_some(()))
            },
            || format!("last exception status: {}", last.borrow()),
        )?)
    }

    fn cgroup(pid: u32) -> TestResult<PathBuf> {
        let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
        let state = fs::read_to_string(&path)?;
        let relative = state
            .lines()
            .find_map(|line| line.split_once("::").map(|(_, path)| path))
            .ok_or("the Kubernetes actor has no unified cgroup")?;
        let cgroup = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        if !cgroup.is_dir() {
            return Err(format!(
                "the Kubernetes actor cgroup is missing: {}",
                cgroup.display()
            )
            .into());
        }
        Ok(cgroup)
    }

    fn pod(&self) -> TestResult<Pod> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.namespace);
        Ok(self.runtime.block_on(pods.get(&self.actor_name))?)
    }

    fn container_id(&self) -> TestResult<String> {
        self.container_id_for(CONTAINER)
    }

    fn container_id_for(&self, name: &str) -> TestResult<String> {
        Self::member_status(&self.pod()?, name)
            .and_then(|status| status.container_id.clone())
            .and_then(|id| id.strip_prefix("containerd://").map(str::to_owned))
            .ok_or_else(|| format!("Kubernetes container {name} has no containerd ID").into())
    }

    fn member_status<'a>(
        pod: &'a Pod,
        name: &str,
    ) -> Option<&'a k8s_openapi::api::core::v1::ContainerStatus> {
        let status = pod.status.as_ref()?;
        status
            .init_container_statuses
            .as_ref()
            .into_iter()
            .flat_map(|items| items.iter())
            .chain(
                status
                    .container_statuses
                    .as_ref()
                    .into_iter()
                    .flat_map(|items| items.iter()),
            )
            .chain(
                status
                    .ephemeral_container_statuses
                    .as_ref()
                    .into_iter()
                    .flat_map(|items| items.iter()),
            )
            .find(|item| item.name == name)
    }

    fn runtime_id(&self) -> TestResult<String> {
        let mut command = Command::new(&self.k3s_path);
        command.args([
            "crictl",
            "ps",
            "--quiet",
            "--no-trunc",
            "--namespace",
            &self.namespace,
            "--name",
            CONTAINER,
        ]);
        let output = Self::run(&mut command, "find the running Kubernetes actor")?;
        let ids = output.lines().collect::<Vec<_>>();
        match ids.as_slice() {
            [id] => Ok((*id).to_owned()),
            _ => Err(format!("expected one running Kubernetes actor, found {ids:?}").into()),
        }
    }

    fn inspect_pid(&self, id: &str) -> TestResult<u32> {
        let mut command = Command::new(&self.k3s_path);
        command.args(["crictl", "inspect", id]);
        let output = Self::run(&mut command, "inspect the Kubernetes actor")?;
        let value: Value = serde_json::from_str(&output)?;
        value
            .pointer("/info/pid")
            .and_then(Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| "CRI did not return a live actor PID".into())
    }

    fn wait_control(&self) -> TestResult<()> {
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.system, "deployment", "mithril-control");
        Ok(wait_for(
            &path,
            "Control Deployment readiness",
            READY_LIMIT,
            || match self.runtime.block_on(deployments.get("mithril-control")) {
                Ok(deployment) => {
                    *last.borrow_mut() = format!("{:?}", deployment.status);
                    Ok((deployment
                        .status
                        .as_ref()
                        .and_then(|status| status.available_replicas)
                        == Some(1))
                    .then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || {
                format!(
                    "last Deployment state: {}; logs: {:?}",
                    last.borrow(),
                    self.logs(&self.system, "deployment/mithril-control")
                        .unwrap_or_else(|source| source.to_string())
                )
            },
        )?)
    }

    fn wait_node(&self) -> TestResult<()> {
        let sets = Api::<DaemonSet>::namespaced(self.client.clone(), &self.system);
        let admission =
            RuntimeAdmissionClient::new(self.socket_path.clone(), Duration::from_secs(1))?;
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.system, "daemonset", "mithril-node");
        Ok(wait_for(
            &path,
            "Node DaemonSet readiness",
            READY_LIMIT,
            || match self.runtime.block_on(sets.get("mithril-node")) {
                Ok(set) => {
                    let ready = set.status.as_ref().is_some_and(|status| {
                        status.desired_number_scheduled == 1
                            && status.number_ready == 1
                            && status.number_unavailable.unwrap_or_default() == 0
                    });
                    let live = ready && self.runtime.block_on(admission.available());
                    *last.borrow_mut() = format!("{:?}; admission live: {live}", set.status);
                    Ok(live.then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || {
                format!(
                    "last DaemonSet state: {}; logs: {:?}",
                    last.borrow(),
                    self.logs(&self.system, "daemonset/mithril-node")
                        .unwrap_or_else(|source| source.to_string())
                )
            },
        )?)
    }

    fn ready_node(&self) -> TestResult<()> {
        let nodes = Api::<Node>::all(self.client.clone());
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource("", "node", &self.node_name);
        let task_map = self.pin_path.join("maps/task_labels");
        Ok(wait_stable(
            &path,
            "authenticated Node readiness",
            READY_LIMIT,
            7,
            || match self.runtime.block_on(nodes.get(&self.node_name)) {
                Ok(node) => {
                    *last.borrow_mut() = format!("{:?}", node.metadata);
                    let labels = node.metadata.labels.unwrap_or_default();
                    let notes = node.metadata.annotations.unwrap_or_default();
                    let tainted = node
                        .spec
                        .and_then(|spec| spec.taints)
                        .unwrap_or_default()
                        .iter()
                        .any(|taint| taint.key == KUBERNETES_NOT_READY_TAINT);
                    let boot = notes
                        .get(KUBERNETES_NODE_BOOT_ANNOTATION)
                        .is_some_and(|value| {
                            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        });
                    let epoch = notes
                        .get(KUBERNETES_LABEL_EPOCH_ANNOTATION)
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|value| value > 0);
                    let ready = labels.get(KUBERNETES_READY_LABEL).map(String::as_str)
                        == Some("true")
                        && notes.get(KUBERNETES_NODE_ID_ANNOTATION).map(String::as_str)
                            == Some(NODE_ID)
                        && notes.get(KUBERNETES_NODE_UID_ANNOTATION) == node.metadata.uid.as_ref()
                        && boot
                        && epoch
                        && !tainted
                        && task_map.is_file();
                    Ok(ready)
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(false)
                }
            },
            || {
                let node = self
                    .logs(&self.system, "daemonset/mithril-node")
                    .unwrap_or_else(|source| source.to_string());
                format!(
                    "last Node state: {}; task map {} exists: {}; Node logs: {node}",
                    last.borrow(),
                    task_map.display(),
                    task_map.is_file()
                )
            },
        )?)
    }

    fn ca_bundle(path: &Path) -> TestResult<String> {
        let mut command = Command::new("/usr/bin/base64");
        command.args(["-w", "0"]).arg(path);
        Ok(Self::run(&mut command, "encode the admission CA")?
            .trim()
            .to_owned())
    }

    fn write_inputs(&self) -> TestResult<()> {
        fs::copy(&self.tls.files.ca, self.identity_path.join("ca.pem"))?;
        fs::copy(
            &self.tls.files.node_certificate,
            self.identity_path.join("node.pem"),
        )?;
        fs::copy(
            &self.tls.files.node_key,
            self.identity_path.join("node-key.pem"),
        )?;

        let policy_dir = self.root.join("crates/mithril-e2e/fixtures/mithril-policy");
        fs::copy(
            policy_dir.join("test-public-key.hex"),
            self.identity_path.join("administrative-public-key.hex"),
        )?;
        let public_key = fs::read_to_string(policy_dir.join("test-public-key.hex"))?;
        let trust = TrustGenerationV1 {
            generation: 1,
            bundle_digest: String::new(),
            policy_issuer_sequence_epoch: 1,
            policy_signers: vec![PolicySignerTrustV1 {
                signing_key_id: "effect-observation-test-key".to_owned(),
                ed25519_public_key_hex: public_key.trim().to_owned(),
                revoked: false,
            }],
        }
        .with_computed_bundle_digest();
        let server_name = format!("mithril-control.{}.svc", self.system);
        let mut node: Value =
            serde_json::from_slice(&fs::read(self.fixture("pid-reuse-node-v1.json"))?)?;
        for (path, value) in [
            (
                "/interceptor/lease_path",
                Value::String(self.lease_path.display().to_string()),
            ),
            (
                "/interceptor/pin_root",
                Value::String(self.pin_path.display().to_string()),
            ),
            (
                "/control/endpoint",
                Value::String(format!("https://{server_name}:8443")),
            ),
            ("/control/server_name", Value::String(server_name)),
            (
                "/runtime_admission/socket_path",
                Value::String(self.socket_path.display().to_string()),
            ),
            (
                "/runtime_observation/socket_path",
                Value::String(self.observation_path.display().to_string()),
            ),
        ] {
            Self::set(&mut node, path, value)?;
        }
        fs::write(&self.config_path, serde_json::to_vec_pretty(&node)?)?;
        NodeConfig::load_with_kubernetes_runtime_identity(
            &self.config_path,
            self.node_name.clone(),
        )?;

        let mut control: Value =
            serde_json::from_slice(&fs::read(self.fixture("pid-reuse-control-v1.json"))?)?;
        for (path, value) in [
            (
                "/allowed_nodes/0/certificate_sha256",
                Value::String(self.tls.node_digest()),
            ),
            ("/trust", serde_json::to_value(trust)?),
            (
                "/kubernetes_nodes/daemon_set_namespace",
                Value::String(self.system.clone()),
            ),
            (
                "/client/auth/oidc/issuer_url",
                Value::String(self.approval()?.issuer()),
            ),
            (
                "/client/administrative/node_ids_by_kubernetes_name",
                serde_json::to_value(BTreeMap::from([(self.node_name.clone(), NODE_ID)]))?,
            ),
        ] {
            Self::set(&mut control, path, value)?;
        }
        fs::write(&self.control_path, serde_json::to_vec_pretty(&control)?)?;
        ControlConfig::load(&self.control_path)?;

        let node_selector = BTreeMap::from([(SELECTOR.to_owned(), self.token.clone())]);
        let control_selector =
            BTreeMap::from([("kubernetes.io/hostname".to_owned(), self.node_name.clone())]);
        let mut values: Value =
            serde_saphyr::from_slice(&fs::read(self.fixture("pid-reuse-values-v1.yaml"))?)?;
        for (path, value) in [
            ("/node/image", Value::String(self.node_image.clone())),
            (
                "/node/configHostPath",
                Value::String(self.config_path.display().to_string()),
            ),
            (
                "/node/identityHostPath",
                Value::String(self.identity_path.display().to_string()),
            ),
            (
                "/node/stateHostPath",
                Value::String(self.state_path.display().to_string()),
            ),
            ("/node/nodeSelector", serde_json::to_value(node_selector)?),
            (
                "/node/runtimeHook/socketPath",
                Value::String(self.socket_path.display().to_string()),
            ),
            ("/control/image", Value::String(self.control_image.clone())),
            (
                "/control/nodeSelector",
                serde_json::to_value(control_selector)?,
            ),
            (
                "/control/admission/caBundle",
                Value::String(Self::ca_bundle(&self.tls.files.ca)?),
            ),
            (
                "/control/administrativeExec/webhookCABundle",
                Value::String(Self::ca_bundle(self.approval()?.ca())?),
            ),
        ] {
            Self::set(&mut values, path, value)?;
        }
        fs::write(&self.values_path, serde_saphyr::to_string(&values)?)?;
        Ok(())
    }

    fn create_system(&mut self) -> TestResult<()> {
        let namespaces = Api::<Namespace>::all(self.client.clone());
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(self.system.clone()),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        };
        self.runtime
            .block_on(namespaces.create(&PostParams::default(), &namespace))?;
        self.system_up = true;

        let config = fs::read_to_string(&self.control_path)?;
        let signing = fs::read_to_string(
            self.root
                .join("crates/mithril-e2e/fixtures/mithril-policy/test-signing-key.hex"),
        )?;
        let seal =
            fs::read_to_string(self.root.join(
                "crates/mithril-e2e/fixtures/mithril-policy/observe-profile-seal-request.json",
            ))?;
        let mut data = BTreeMap::from([
            ("control.json".to_owned(), config),
            ("policy-signing-key".to_owned(), signing),
            ("profile-seal-request.json".to_owned(), seal),
            ("ca.pem".to_owned(), fs::read_to_string(&self.tls.files.ca)?),
            (
                "tls.crt".to_owned(),
                fs::read_to_string(&self.tls.files.server_certificate)?,
            ),
            (
                "tls.key".to_owned(),
                fs::read_to_string(&self.tls.files.server_key)?,
            ),
        ]);
        data.extend(self.approval()?.secrets()?);
        let secrets = Api::<Secret>::namespaced(self.client.clone(), &self.system);
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("mithril-control-config".to_owned()),
                ..ObjectMeta::default()
            },
            string_data: Some(data),
            ..Secret::default()
        };
        self.runtime
            .block_on(secrets.create(&PostParams::default(), &secret))?;

        let admission = Secret {
            metadata: ObjectMeta {
                name: Some("mithril-admission-tls".to_owned()),
                ..ObjectMeta::default()
            },
            string_data: Some(BTreeMap::from([
                (
                    "tls.crt".to_owned(),
                    fs::read_to_string(&self.tls.files.server_certificate)?,
                ),
                (
                    "tls.key".to_owned(),
                    fs::read_to_string(&self.tls.files.server_key)?,
                ),
            ])),
            type_: Some("kubernetes.io/tls".to_owned()),
            ..Secret::default()
        };
        self.runtime
            .block_on(secrets.create(&PostParams::default(), &admission))?;

        let claim: PersistentVolumeClaim =
            serde_saphyr::from_slice(&fs::read(self.fixture("pid-reuse-pvc-v1.yaml"))?)?;
        let claims = Api::<PersistentVolumeClaim>::namespaced(self.client.clone(), &self.system);
        self.runtime
            .block_on(claims.create(&PostParams::default(), &claim))?;
        Ok(())
    }

    fn create_work(&mut self) -> TestResult<()> {
        let namespaces = Api::<Namespace>::all(self.client.clone());
        let mut namespace = Namespace::default();
        namespace.metadata.name = Some(self.namespace.clone());
        self.runtime
            .block_on(namespaces.create(&PostParams::default(), &namespace))?;
        self.work_up = true;
        let accounts = Api::<ServiceAccount>::namespaced(self.client.clone(), &self.namespace);
        let path = Self::resource(&self.namespace, "serviceaccount", "default");
        wait_for(
            &path,
            "default ServiceAccount readiness",
            READY_LIMIT,
            || {
                self.runtime
                    .block_on(accounts.get_opt("default"))
                    .map(|account| account.map(|_| ()))
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: &path,
                            reason: source.to_string(),
                        }
                        .build()
                    })
            },
            || "the default ServiceAccount is absent".to_owned(),
        )?;
        Ok(())
    }

    fn wait_policy(&self, active: u32) -> TestResult<()> {
        let name = self
            .policy_name
            .as_deref()
            .ok_or("the policy is not installed")?;
        let policies =
            Api::<WorkloadProtectionPolicy>::namespaced(self.client.clone(), &self.namespace);
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.namespace, "workloadprotectionpolicy", name);
        Ok(wait_for(
            &path,
            "policy readiness",
            READY_LIMIT,
            || match self.runtime.block_on(policies.get(name)) {
                Ok(policy) => {
                    *last.borrow_mut() = format!("{:?}", policy.status);
                    let generation = policy.metadata.generation.unwrap_or_default() as u64;
                    let ready = policy.status.as_ref().is_some_and(|status| {
                        let condition = |name| {
                            status.conditions.iter().any(|condition| {
                                condition.condition_type == name
                                    && condition.status == KubernetesConditionStatusV1::True
                                    && condition.observed_generation == generation
                            })
                        };
                        status.observed_generation == generation
                            && condition("Accepted")
                            && condition("Compiled")
                            && status.rollout.desired == active
                            && status.rollout.active == active
                            && status.rollout.updating == 0
                            && status.rollout.failed == 0
                    });
                    Ok(ready.then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || format!("last policy status: {}", last.borrow()),
        )?)
    }

    fn delete_ns(&self, name: &str) -> TestResult<()> {
        let namespaces = Api::<Namespace>::all(self.client.clone());
        match self
            .runtime
            .block_on(namespaces.delete(name, &DeleteParams::default()))
        {
            Ok(_) => {}
            Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
            Err(source) => return Err(source.into()),
        }
        Ok(wait_for(
            Path::new(name),
            "Kubernetes namespace deletion",
            STOP_LIMIT,
            || {
                let absent = self
                    .runtime
                    .block_on(namespaces.get_opt(name))
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: Path::new(name),
                            reason: source.to_string(),
                        }
                        .build()
                    })?
                    .is_none();
                Ok(absent.then_some(()))
            },
            || format!("namespace {name} still exists"),
        )?)
    }

    fn retain(failed: &mut Option<Box<dyn std::error::Error>>, result: TestResult<()>) {
        if failed.is_none() {
            *failed = result.err();
        }
    }

    fn wait_sockets(&self) -> TestResult<()> {
        wait_for(
            &self.seccomp_path,
            "Node runtime socket cleanup",
            STOP_LIMIT,
            || Ok((!self.socket_path.exists() && !self.seccomp_path.exists()).then_some(())),
            || {
                format!(
                    "admission socket exists: {}; seccomp socket exists: {}",
                    self.socket_path.exists(),
                    self.seccomp_path.exists(),
                )
            },
        )?;
        Ok(())
    }

    fn stop_node(&mut self) -> TestResult<()> {
        if !self.hook_up {
            return Ok(());
        }
        let nodes = Api::<Node>::all(self.client.clone());
        let patch = json!({"metadata": {"labels": {(SELECTOR): null}}});
        self.runtime.block_on(nodes.patch(
            &self.node_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        ))?;
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.system);
        let params = ListParams::default().labels("app.kubernetes.io/name=mithril-node");
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.system, "pod", "mithril-node");
        wait_for(
            &path,
            "Node Pod stop",
            STOP_LIMIT,
            || match self.runtime.block_on(pods.list(&params)) {
                Ok(list) => {
                    let state = list
                        .items
                        .iter()
                        .map(|pod| pod.name_any())
                        .collect::<Vec<_>>();
                    let stopped = state.is_empty();
                    *last.borrow_mut() = format!("{state:?}");
                    Ok(stopped.then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || format!("remaining Node Pods: {}", last.borrow()),
        )?;
        self.wait_sockets()?;
        self.hook_up = false;
        Ok(())
    }

    fn wait_api(&self) -> TestResult<()> {
        let nodes = Api::<Node>::all(self.client.clone());
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            &self.kube_path,
            "Kubernetes API after runtime restart",
            READY_LIMIT,
            || match self.runtime.block_on(nodes.get(&self.node_name)) {
                Ok(node) => {
                    *last.borrow_mut() = format!("{:?}", node.status);
                    Ok(Some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || format!("last Node state: {}", last.borrow()),
        )?)
    }

    fn running_id(&self, id: &str) -> TestResult<()> {
        let mut command = Command::new(&self.k3s_path);
        command.args(["crictl", "inspect", id]);
        let output = Self::run(&mut command, "inspect the running actor")?;
        let state: Value = serde_json::from_str(&output)?;
        if state.pointer("/status/state").and_then(Value::as_str) != Some("CONTAINER_RUNNING") {
            return Err(format!("the Kubernetes actor is not running: {state}").into());
        }
        Ok(())
    }

    fn task_from(&self, pid: u32, snapshot: NativeTaskSnapshotV1) -> TestResult<Task> {
        let bytes = self
            .reader
            .lookup("task_coordinates", &snapshot.task_cookie.to_ne_bytes())?
            .ok_or("task coordinate is missing")?;
        let coordinate = TaskCoordinateV1::try_read_from_bytes(&bytes)
            .map_err(|source| format!("task coordinate is invalid: {source}"))?;
        Ok(Task {
            pid,
            ns_pid: ProcessFixture::namespace_pid(pid)?,
            snapshot,
            coordinate,
        })
    }

    fn start_entry(&self, program: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        let member = self.container_id_for(CONTAINER)?;
        let group = Self::cgroup(self.inspect_pid(&member)?)?;
        let kube = self.approval()?.kubeconfig().map(Path::to_owned);
        let mut command = if let Some(kube) = kube {
            let mut command = Command::new(&self.exec_path);
            command
                .arg("--kubeconfig")
                .arg(kube)
                .arg("--namespace")
                .arg(&self.namespace)
                .arg("--pod")
                .arg(&self.actor_name)
                .arg("--container")
                .arg(CONTAINER);
            command
        } else {
            let mut command = Command::new(&self.k3s_path);
            command
                .arg("kubectl")
                .arg("--kubeconfig")
                .arg(&self.kube_path)
                .args([
                    "-n",
                    &self.namespace,
                    "exec",
                    "-i",
                    &self.actor_name,
                    "-c",
                    CONTAINER,
                    "--",
                ]);
            command
        };
        command.arg(program).args(args);
        let procs = group.join("cgroup.procs");
        let before = fs::read_to_string(&procs)?
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u32>, _>>()?;
        let mut actor =
            ProcessFixture::spawn(&mut command, Path::new(program)).map_err(|source| {
                let logs = self
                    .logs(&self.system, "daemonset/mithril-node")
                    .unwrap_or_else(|error| error.to_string());
                format!("{source}; Node logs: {logs}")
            })?;
        let pid = actor.wait_group_task(&group, &before, program, "Kubernetes exec host PID")?;
        if !self.hook_up {
            let input_path = PathBuf::from(format!("/proc/{pid}/fd/0"));
            let input = File::options()
                .write(true)
                .open(&input_path)
                .context(IoSnafu { path: &input_path })?;
            actor.set_input(input);
        }
        actor.set_actor(pid)?;
        self.approval()?.clear();
        Ok(actor)
    }

    fn reset(&mut self, name: &str) -> TestResult<()> {
        if self.work_up || self.work.is_some() || self.move_group.is_some() {
            return Err("the previous Kubernetes scenario is not clean".into());
        }
        self.namespace = format!("mithril-work-{name}-{}", self.token);
        self.scenario = name.to_owned();
        self.work_path = self.work_path.with_file_name("actor");
        self.work = Some(ProbeDirectory::create(&self.work_path)?);
        self.actor_name = ACTOR.to_owned();
        self.create_work()
    }

    fn clean_test(&mut self) -> TestResult<()> {
        let mut failed = None;
        Self::retain(
            &mut failed,
            self.approval().map(|mut approval| approval.clear()),
        );
        if self.work_up {
            Self::retain(&mut failed, self.delete_ns(&self.namespace));
        }
        if self.hook_up {
            let last = RefCell::new(String::from("<absent>"));
            Self::retain(
                &mut failed,
                wait_for(
                    &self.state_path,
                    "scenario retirement",
                    READY_LIMIT,
                    || {
                        let status = mithril_node::policy_delivery_status(&self.state_path)
                            .context(NodeSnafu)?;
                        *last.borrow_mut() = format!("{status:?}");
                        Ok((status.active_target_count == 0
                            && status.scheduled_binding_count == 0
                            && status.runtime_binding_count == 0
                            && !status.activation_pending)
                            .then_some(()))
                    },
                    || format!("last policy delivery: {}", last.borrow()),
                )
                .map_err(Into::into),
            );
        }
        if let Some(source) = failed {
            return Err(source);
        }
        self.work_up = false;
        for group in self
            .move_group
            .take()
            .into_iter()
            .chain(self.groups.drain(..))
        {
            Self::retain(&mut failed, group.cleanup().map_err(Into::into));
        }
        for directory in self
            .work
            .take()
            .into_iter()
            .chain(self.directories.drain(..))
        {
            Self::retain(&mut failed, directory.cleanup().map_err(Into::into));
        }
        self.actor_id = None;
        self.actor_pid = None;
        self.actor_cgroup = None;
        self.policy_name = None;
        self.labels.clear();
        self.policies.clear();
        self.actors.clear();
        match failed {
            Some(source) => Err(source),
            None => Ok(()),
        }
    }

    fn tear_down(&mut self) -> TestResult<()> {
        let mut failed = self.clean_test().err();
        if self.hook_up {
            Self::retain(&mut failed, self.stop_node());
        }
        if self.runtime_up {
            let input = RuntimeIntegrationDecommissionV1 {
                owner: format!("{}/mithril", self.system),
                hook_directory: PathBuf::from("/usr/libexec/oci/hooks.d"),
                containerd_config_directory: PathBuf::from(
                    "/var/lib/rancher/k3s/agent/etc/containerd",
                ),
                containerd_drop_in_directory: "config-v3.toml.d".to_owned(),
                runtime_services: vec!["k3s".to_owned()],
            };
            Self::retain(
                &mut failed,
                RuntimeIntegrationOwner::decommission(&input)
                    .map(|_| ())
                    .map_err(Into::into),
            );
            Self::retain(&mut failed, self.wait_api());
            self.runtime_up = false;
        }
        Self::retain(
            &mut failed,
            self.approval().and_then(|mut approval| approval.stop()),
        );
        if self.helm_up {
            let mut command = Command::new(&self.helm_path);
            command
                .args(["--kubeconfig"])
                .arg(&self.kube_path)
                .args(["uninstall", "mithril", "--namespace", &self.system])
                .args(["--wait", "--timeout", "2m"]);
            Self::retain(
                &mut failed,
                Self::run(&mut command, "uninstall Mithril").map(|_| ()),
            );
            self.helm_up = false;
        }
        if self.system_up {
            Self::retain(&mut failed, self.delete_ns(&self.system));
            self.system_up = false;
        }
        if let Some(state) = self.state.take() {
            Self::retain(&mut failed, state.cleanup().map_err(Into::into));
        }
        if let Some(identity) = self.identity.take() {
            Self::retain(&mut failed, identity.cleanup().map_err(Into::into));
        }
        if let Some(config) = self.config.take() {
            Self::retain(&mut failed, config.cleanup().map_err(Into::into));
        }
        if let Some(control) = self.control_file.take() {
            Self::retain(&mut failed, control.cleanup().map_err(Into::into));
        }
        if let Some(values) = self.values.take() {
            Self::retain(&mut failed, values.cleanup().map_err(Into::into));
        }
        if let Some(pin) = self.pin.take() {
            Self::retain(&mut failed, pin.cleanup().map_err(Into::into));
        }
        if let Some(lease) = self.lease.take() {
            Self::retain(&mut failed, lease.cleanup().map_err(Into::into));
        }
        if let Some(socket) = self.socket.take() {
            Self::retain(&mut failed, socket.cleanup().map_err(Into::into));
        }
        if let Some(observation) = self.observation.take() {
            Self::retain(&mut failed, observation.cleanup().map_err(Into::into));
        }
        if let Some(seccomp) = self.seccomp.take() {
            Self::retain(&mut failed, seccomp.cleanup().map_err(Into::into));
        }
        if let Some(out) = self.out.take() {
            Self::retain(&mut failed, out.cleanup().map_err(Into::into));
        }
        match failed {
            Some(source) => Err(source),
            None => Ok(()),
        }
    }
}

impl Kubernetes {
    fn close(&mut self) -> TestResult<()> {
        let Some(mut lifecycle) = self.lifecycle.take() else {
            return Ok(());
        };
        match lifecycle.get_mut() {
            Some(state) => state.clean_test(),
            None => Ok(()),
        }
    }
}

impl Platform for Kubernetes {
    fn source(&self) -> &Path {
        &self.root
    }

    fn setup(name: &str) -> TestResult<Self> {
        erebor_telemetry::init_test_logging();
        let mut lifecycle = enter::<KubernetesState>(KubernetesState::tear_down)?;
        if lifecycle.get().is_some() {
            let state = lifecycle
                .get_mut()
                .ok_or("the Kubernetes lifecycle is empty")?;
            state.reset(name)?;
            return Ok(Self {
                lifecycle: Some(lifecycle),
            });
        }
        let root = fs::canonicalize(KubernetesState::path("MITHRIL_TEST_ROOT", ".")?)?;
        let base = KubernetesState::path("MITHRIL_TEST_OUTPUT", "")?;
        if base.as_os_str().is_empty() || !base.is_absolute() || base.is_file() {
            return Err(format!(
                "MITHRIL_TEST_OUTPUT must name an absolute directory: {}",
                base.display()
            )
            .into());
        }
        fs::create_dir_all(&base)?;
        let out = base.join(name);
        if out.exists() {
            return Err(format!("the scenario output path exists: {}", out.display()).into());
        }
        let out_dir = ProbeDirectory::create(&out)?;
        let work_path = out.join("actor");
        let state_path = out.join("node");
        let identity_path = out.join("identity");
        let state = ProbeDirectory::create(&state_path)?;
        let identity = ProbeDirectory::create(&identity_path)?;
        let config_path = out.join("node.json");
        let control_path = out.join("control.json");
        let values_path = out.join("values.yaml");
        let config = ProbeFile::new(&config_path);
        let control_file = ProbeFile::new(&control_path);
        let values = ProbeFile::new(&values_path);

        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos();
        let token = format!("{}-{stamp}", std::process::id());
        let system = format!("mithril-pid-{token}");
        let namespace = format!("mithril-work-{name}-{token}");
        let pin_path = PathBuf::from(format!("/sys/fs/bpf/mithril-pid-{token}"));
        let lease_path = PathBuf::from(format!("/run/erebor-interceptor/mithril-pid-{token}.lock"));
        let socket_path = PathBuf::from(format!("/run/mithril/mithril-pid-{token}.sock"));
        let observation_path = socket_path.with_extension("observation.sock");
        let seccomp_path = socket_path.with_extension("seccomp.sock");
        for path in [
            &pin_path,
            &lease_path,
            &socket_path,
            &observation_path,
            &seccomp_path,
        ] {
            if path.exists() {
                return Err(
                    format!("the Kubernetes fixture path exists: {}", path.display()).into(),
                );
            }
        }
        let pin = ProbeDirectory::new(&pin_path);
        let lease = ProbeFile::new(&lease_path);
        let socket = ProbeFile::new(&socket_path);
        let observation = ProbeFile::new(&observation_path);
        let seccomp = ProbeFile::new(&seccomp_path);
        let kube_path =
            KubernetesState::path("MITHRIL_TEST_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")?;
        let helm_path = KubernetesState::path("MITHRIL_TEST_HELM", "/usr/local/bin/helm")?;
        let k3s_path = KubernetesState::path("MITHRIL_TEST_K3S", "/usr/local/bin/k3s")?;
        let exec_path = env::var_os("MITHRIL_TEST_KUBE_EXEC")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target/debug/mithril-kube-exec"));
        for path in [&kube_path, &helm_path, &k3s_path, &exec_path] {
            if !path.is_file() {
                return Err(format!(
                    "the Kubernetes fixture input is missing: {}",
                    path.display()
                )
                .into());
            }
        }
        let node_image = KubernetesState::required("MITHRIL_TEST_NODE_IMAGE")?;
        let control_image = KubernetesState::required("MITHRIL_TEST_CONTROL_IMAGE")?;
        let actor_image = KubernetesState::required("MITHRIL_TEST_ACTOR_IMAGE")?;
        let actor_python = env::var("MITHRIL_TEST_ACTOR_PYTHON")
            .unwrap_or_else(|_| "/usr/local/bin/python3".to_owned());
        let actor_entry = env::var("MITHRIL_TEST_ACTOR_ENTRY")
            .unwrap_or_else(|_| "/usr/local/bin/python".to_owned());
        let digest = actor_image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            });
        if digest.is_none() {
            return Err(
                "MITHRIL_TEST_ACTOR_IMAGE must be pinned by a lowercase SHA-256 digest".into(),
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let kubeconfig = Kubeconfig::read_from(&kube_path)?;
        let kube = runtime.block_on(Config::from_custom_kubeconfig(
            kubeconfig,
            &KubeConfigOptions::default(),
        ))?;
        let client = runtime.block_on(async { Client::try_from(kube) })?;
        let nodes = Api::<Node>::all(client.clone());
        let node_name = match env::var("MITHRIL_TEST_NODE_NAME") {
            Ok(name) => {
                runtime.block_on(nodes.get(&name))?;
                name
            }
            Err(_) => {
                let mut list = runtime.block_on(nodes.list(&ListParams::default()))?.items;
                if list.len() != 1 {
                    return Err(format!(
                        "the Kubernetes PID-reuse test needs one Node, found {}",
                        list.len()
                    )
                    .into());
                }
                list.pop()
                    .map(|node| node.name_any())
                    .ok_or("the Kubernetes cluster has no Node")?
            }
        };
        let node = runtime.block_on(nodes.get(&node_name))?;
        let node_ip = node
            .status
            .and_then(|status| status.addresses)
            .and_then(|addresses| {
                addresses
                    .into_iter()
                    .find(|address| address.type_ == "InternalIP")
            })
            .map(|address| address.address)
            .ok_or("the Kubernetes Node has no InternalIP")?;
        let server_name = format!("mithril-control.{system}.svc");
        let approval =
            KubernetesApproval::new(&root, &kube_path, &k3s_path, node_ip, &server_name)?;
        let tls = MtlsFixture::kubernetes(&server_name)?;
        let inspector = NativeIdentityInspector::new(&pin_path);
        let reader = KernelStateReader::new(&pin_path);
        let mut fixture = KubernetesState {
            namespace,
            scenario: name.to_owned(),
            work: Some(ProbeDirectory::create(&work_path)?),
            work_path,
            directories: Vec::new(),
            move_group: None,
            groups: Vec::new(),
            work_up: false,
            actor_name: ACTOR.to_owned(),
            actor_id: None,
            actor_pid: None,
            actor_cgroup: None,
            labels: super::Labels::new(),
            policies: BTreeMap::new(),
            actors: BTreeMap::new(),
            policy_name: None,
            root,
            out: Some(out_dir),
            state_path,
            identity_path,
            config_path,
            control_path,
            values_path,
            pin_path,
            lease_path,
            socket_path,
            observation_path,
            seccomp_path,
            kube_path,
            helm_path,
            k3s_path,
            exec_path,
            node_image,
            control_image,
            actor_image,
            actor_python,
            actor_entry,
            system,
            token,
            node_name,
            client,
            runtime,
            tls,
            inspector,
            reader,
            approval: Mutex::new(approval),
            state: Some(state),
            identity: Some(identity),
            config: Some(config),
            control_file: Some(control_file),
            values: Some(values),
            pin: Some(pin),
            lease: Some(lease),
            socket: Some(socket),
            observation: Some(observation),
            seccomp: Some(seccomp),
            system_up: false,
            helm_up: false,
            hook_up: false,
            runtime_up: false,
        };
        fixture.write_inputs()?;
        fixture.create_work()?;
        lifecycle.put(fixture);
        Ok(Self {
            lifecycle: Some(lifecycle),
        })
    }

    fn start_control(&mut self) -> TestResult<()> {
        if self.helm_up {
            return self.wait_control();
        }
        let state: &mut KubernetesState = self;
        state.approval()?.start_oidc(&state.runtime)?;
        KubernetesState::require_image(&self.k3s_path, &self.control_image)?;
        KubernetesState::require_image(&self.k3s_path, &self.node_image)?;
        self.create_system()?;
        let chart = self.root.join("packaging/mithril/helm");
        let mut command = Command::new(&self.helm_path);
        command
            .args(["--kubeconfig"])
            .arg(&self.kube_path)
            .args(["upgrade", "--install", "mithril"])
            .arg(&chart)
            .args(["--namespace", &self.system, "--values"])
            .arg(&self.values_path);
        KubernetesState::run(&mut command, "install Mithril Control")?;
        self.helm_up = true;
        self.wait_control()
    }

    fn start_node(&mut self) -> TestResult<()> {
        if self.hook_up {
            return self.wait_node();
        }
        self.runtime_up = true;
        let nodes = Api::<Node>::all(self.client.clone());
        let patch = json!({"metadata": {"labels": {(SELECTOR): self.token}}});
        self.runtime.block_on(nodes.patch(
            &self.node_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        ))?;
        self.hook_up = true;
        self.wait_node()
    }

    fn stop_node(&mut self) -> TestResult<()> {
        KubernetesState::stop_node(self)
    }

    fn install_policy(&mut self, fixture: &str) -> TestResult<super::Labels> {
        let path = policy_path(&self.root, fixture)?;
        let bytes = fs::read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if value.get("kind").and_then(Value::as_str) == Some("WorkloadProtectionException") {
            self.install_exception(&bytes, &path)?;
            return Ok(self.labels.clone());
        }
        let mut policy: WorkloadProtectionPolicy = serde_json::from_slice(&bytes)?;
        let labels = super::policy_labels(&policy)?;
        let fixture_name = policy
            .metadata
            .name
            .clone()
            .ok_or("the policy fixture has no metadata.name")?;
        let name = self.policies.get(&labels).cloned().unwrap_or(fixture_name);
        policy.metadata = ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(self.namespace.clone()),
            ..ObjectMeta::default()
        };
        if policy.spec.containers.is_empty() {
            return Err("the policy has no container".into());
        }
        for image in policy
            .spec
            .containers
            .iter_mut()
            .flat_map(|container| &mut container.images)
        {
            if image.starts_with("fixture/python@") {
                image.clone_from(&self.actor_image);
            }
        }
        for rule in policy
            .spec
            .roles
            .iter_mut()
            .flat_map(|role| &mut role.execution)
        {
            match rule.path.as_str() {
                "/usr/bin/python3" => rule.path.clone_from(&self.actor_python),
                "/work/bin/python" => rule.path.clone_from(&self.actor_entry),
                _ => {}
            }
        }
        let policies =
            Api::<WorkloadProtectionPolicy>::namespaced(self.client.clone(), &self.namespace);
        if let Some(current) = self.policies.get(&labels) {
            self.runtime.block_on(policies.patch(
                current,
                &PatchParams::default(),
                &Patch::Merge(&policy),
            ))?;
        } else {
            self.runtime
                .block_on(policies.create(&PostParams::default(), &policy))?;
        }
        self.policy_name = Some(name.clone());
        self.policies.insert(labels.clone(), name);
        let active =
            u32::from(self.hook_up && self.actors.get(&labels).is_some_and(|count| *count > 0));
        self.wait_policy(active)?;
        Ok(labels)
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        let active = u32::from(
            self.actors
                .get(&self.labels)
                .is_some_and(|count| *count > 0),
        );
        self.wait_policy(active)
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.ready_node()
    }

    fn start_actor(
        &mut self,
        name: &str,
        extra: &[&str],
        labels: &super::Labels,
    ) -> TestResult<ProcessFixture> {
        let actor = GroupActor {
            name: CONTAINER,
            script: Some(name),
            args: extra,
            kind: mithril_control::ContainerKindV1::Application,
        };
        let mut group = self.start_actor_group(&[actor], labels, |_, _| Ok(()))?;
        Ok(group.remove(0).0)
    }

    fn start_actor_group<F>(
        &mut self,
        actors: &[GroupActor<'_>],
        labels: &super::Labels,
        before_app: F,
    ) -> TestResult<Vec<(ProcessFixture, PathBuf)>>
    where
        F: FnOnce(&mut Self, &mut Vec<(ProcessFixture, PathBuf)>) -> TestResult<()>,
    {
        self.start_group(actors, labels, before_app)
    }
    fn add_actor(&self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        self.start_entry(command, args)
    }

    fn approve(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.approve_entry(command, args)
    }

    fn actor_tasks(&self) -> TestResult<Vec<u32>> {
        let group = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Kubernetes actor has no recorded cgroup")?;
        let path = group.join("cgroup.procs");
        let mut tasks = fs::read_to_string(&path)
            .context(IoSnafu { path: &path })?
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u32>, _>>()?;
        tasks.sort_unstable();
        Ok(tasks)
    }

    fn workload_ready(&self) -> TestResult<bool> {
        Ok(self
            .pod()?
            .status
            .and_then(|status| status.conditions)
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            }))
    }

    fn wait_workload_ready(&self) -> TestResult<()> {
        let last = RefCell::new(false);
        let path = KubernetesState::resource(&self.namespace, "pod", ACTOR);
        Ok(wait_for(
            &path,
            "actor Pod readiness",
            READY_LIMIT,
            || {
                let ready = self.workload_ready().map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                *last.borrow_mut() = ready;
                Ok(ready.then_some(()))
            },
            || {
                format!(
                    "last readiness: {}; Pod state: {:?}",
                    last.borrow(),
                    self.pod().map(|pod| pod.status)
                )
            },
        )?)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        let expected = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Kubernetes actor has no recorded cgroup")?;
        let procs = expected.join("cgroup.procs");
        fs::write(&procs, pid.to_string()).context(IoSnafu { path: &procs })?;
        let actual = KubernetesState::cgroup(pid)?;
        if &actual != expected {
            return Err(format!(
                "the Kubernetes actor is in {}; expected {}",
                actual.display(),
                expected.display()
            )
            .into());
        }
        Ok(())
    }

    fn stage(&mut self) -> TestResult<()> {
        let pod = self.pod()?;
        let notes = pod.metadata.annotations.unwrap_or_default();
        let profile = notes
            .get(KUBERNETES_PROFILE_ANNOTATION)
            .filter(|value| !value.is_empty());
        let source = notes
            .get(KUBERNETES_SOURCE_ANNOTATION)
            .filter(|value| !value.is_empty());
        let id = self.container_id()?;
        let expected = self
            .actor_id
            .as_deref()
            .ok_or("the Kubernetes actor has no recorded container ID")?;
        if profile.is_none() || source.is_none() || id != expected {
            return Err(format!(
                "the admitted Pod has profile={profile:?}, source={source:?}, container={id}"
            )
            .into());
        }
        self.running_id(expected)
    }

    fn admit(&mut self, pid: u32) -> TestResult<()> {
        if self.actor_pid != Some(pid) {
            return Err("the admitted PID is not the Kubernetes actor".into());
        }
        self.wait_policy(1)?;
        self.runtime.block_on(wait_for_async(
            &self.pin_path,
            "Kubernetes actor activation",
            READY_LIMIT,
            || self.inspector.snapshot(pid).context(NodeSnafu),
            || format!("PID {pid} has no published identity"),
        ))?;
        Ok(())
    }

    fn running(&mut self, pid: u32) -> TestResult<()> {
        let expected = self
            .actor_id
            .as_deref()
            .ok_or("the Kubernetes actor has no recorded container ID")?;
        if self.actor_pid != Some(pid) || self.container_id()? != expected {
            return Err("the preexisting Kubernetes actor changed identity".into());
        }
        self.running_id(expected)?;
        self.wait_policy(1)
    }

    fn health(&self) -> TestResult<mithril_node::ReconciliationReportV1> {
        Ok(self.inspector.health()?)
    }

    fn move_task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        let path = PathBuf::from(format!("/sys/fs/cgroup/{}-move", self.namespace));
        let group = ProbeCgroup::create(&path)?;
        group.move_in(pid)?;
        self.move_group = Some(group);
        let last = RefCell::new(String::from("<absent>"));
        let snapshot = self.runtime.block_on(wait_for_async(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let snapshot = self.inspector.snapshot(pid).context(NodeSnafu)?;
                if let Some(value) = snapshot.as_ref() {
                    *last.borrow_mut() = format!("{value:?}");
                }
                Ok(snapshot.filter(|value| {
                    value.coordinate_state == TaskCoordinateStateV1::FailClosedUnknown as u8
                }))
            },
            || format!("PID {pid}; last identity: {}", last.borrow()),
        ))?;
        self.task_from(pid, snapshot)
    }

    fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        let snapshot = self.runtime.block_on(wait_for_async(
            &self.pin_path,
            name,
            READY_LIMIT,
            || self.inspector.snapshot(pid).context(NodeSnafu),
            || format!("PID {pid} has no published identity"),
        ))?;
        self.task_from(pid, snapshot)
    }

    fn wait_exec(
        &mut self,
        actor: &mut ProcessFixture,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        let last = RefCell::new(String::from("<absent>"));
        let snapshot = match actor.wait_path(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let snapshot = match self.inspector.snapshot(pid) {
                    Ok(snapshot) => snapshot,
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        return Ok(None);
                    }
                };
                if let Some(value) = snapshot.as_ref() {
                    *last.borrow_mut() = format!("{value:?}");
                }
                Ok(snapshot.filter(|value| {
                    value.task_cookie == cookie
                        && value.active_execution_id != before.snapshot.active_execution_id
                }))
            },
            || format!("PID {pid}; last identity: {}", last.borrow()),
        ) {
            Ok(value) => value,
            Err(source) => {
                return Err(format!("{source}; actor stderr: {:?}", actor.stderr()?).into());
            }
        };
        self.task_from(pid, snapshot)
    }

    fn recovered(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        let last = RefCell::new(String::from("<absent>"));
        let snapshot = self.runtime.block_on(wait_for_async(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let snapshot = match self.inspector.snapshot(pid) {
                    Ok(snapshot) => snapshot,
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        return Ok(None);
                    }
                };
                if let Some(value) = snapshot.as_ref() {
                    *last.borrow_mut() = format!("{value:?}");
                }
                Ok(snapshot.filter(|value| {
                    value
                        .runtime_binding
                        .as_ref()
                        .is_some_and(|binding| binding.lifecycle_state == "active_recovered")
                        && value
                            .recovered_container_activation
                            .as_ref()
                            .is_some_and(|recovery| recovery.phase == "complete")
                }))
            },
            || format!("PID {pid}; last identity: {}", last.borrow()),
        ))?;
        self.task_from(pid, snapshot)
    }

    fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        KubernetesState::snapshot(self)
    }

    fn maps(&self) -> (&Path, &KernelStateReader) {
        (&self.pin_path, &self.reader)
    }

    fn work(&self) -> &Path {
        &self.work_path
    }

    fn stop(&mut self) -> TestResult<()> {
        self.close()
    }
}

impl Drop for Kubernetes {
    fn drop(&mut self) {
        let _result = self.close();
    }
}

impl Kubernetes {
    fn capture_command(&self, target: &str, args: &[&str]) -> Command {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube_path)
            .args(["-n", &self.system, "exec", target, "--"])
            .args(args);
        command
    }

    fn capture_runtime(&self, target: &str, executable: &str, bundled: bool) -> TestResult<String> {
        let script = if bundled {
            "LD_LIBRARY_PATH=/qualification/runtime/lib /usr/bin/ldd \"$1\""
        } else {
            "/usr/bin/ldd \"$1\""
        };
        let output = self
            .capture_command(target, &["/bin/sh", "-ec", script, "preflight", executable])
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        if !output.status.success()
            || stdout.contains("not found")
            || stderr.contains("not found")
            || !stdout.contains("libc.so.6")
        {
            return Err(format!(
                "container runtime preflight failed for {executable}: {stdout}; {stderr}"
            )
            .into());
        }
        Ok(stdout)
    }

    fn capture_rollout(&self, target: &str) -> TestResult<()> {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube_path)
            .args([
                "-n",
                &self.system,
                "rollout",
                "status",
                target,
                "--timeout=180s",
            ]);
        KubernetesState::run(&mut command, "wait for the qualification rollout")?;
        Ok(())
    }

    fn capture_library(name: &str) -> bool {
        name.contains(".so")
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')
            })
            && ![
                "libc.so.6",
                "libm.so.6",
                "libgcc_s.so.1",
                "ld-linux-x86-64.so.2",
            ]
            .contains(&name)
    }

    fn capture_bundle() -> TestResult<(PathBuf, Vec<String>)> {
        let directory = fs::canonicalize(KubernetesState::required("MITHRIL_TRACE_RUNTIME")?)?;
        if std::env::consts::ARCH != "x86_64"
            || !directory
                .join("bpftrace")
                .symlink_metadata()?
                .file_type()
                .is_file()
        {
            return Err("the Pod fixture requires an x86-64 regular bpftrace executable".into());
        }
        let mut libraries = Vec::new();
        for entry in fs::read_dir(directory.join("lib"))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "a runtime library name is not UTF-8")?;
            if !entry.file_type()?.is_file() || !Self::capture_library(&name) {
                return Err(
                    format!("the runtime bundle has an unsupported library: {name}").into(),
                );
            }
            libraries.push(name);
        }
        if libraries.len() > 64 {
            return Err("the runtime bundle exceeds 64 backend dependencies".into());
        }
        libraries.sort();
        let expected = std::iter::once("bpftrace".to_owned())
            .chain(libraries.iter().map(|name| format!("lib/{name}")))
            .collect::<BTreeSet<_>>();
        let manifest = fs::read_to_string(directory.join("SHA256SUMS"))?;
        if manifest.len() > 16 * 1024 {
            return Err("the runtime checksum manifest exceeds its bound".into());
        }
        let mut recorded = BTreeSet::new();
        for line in manifest.lines() {
            let (digest, name) = line
                .split_once("  ")
                .ok_or("the runtime checksum line is invalid")?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !expected.contains(name)
                || !recorded.insert(name.to_owned())
            {
                return Err(
                    "the runtime checksum manifest has an invalid or duplicate file".into(),
                );
            }
        }
        if recorded != expected {
            return Err("the runtime checksum manifest is incomplete".into());
        }
        let mut command = Command::new("/usr/bin/sha256sum");
        command
            .current_dir(&directory)
            .args(["--check", "--strict", "--status", "SHA256SUMS"]);
        KubernetesState::run(&mut command, "verify the read-only runtime bundle")?;
        Ok((directory, libraries))
    }

    fn configure_capture(&self, config: &mithril_node::NodeTraceConfigV1) -> TestResult<()> {
        if config.executable != Path::new("/usr/bin/bpftrace") {
            return Err("the Pod fixture requires the /usr/bin/bpftrace path".into());
        }
        config.validate()?;
        let mut node: Value = serde_json::from_slice(&fs::read(&self.config_path)?)?;
        node["diagnostics"] = serde_json::to_value(config)?;
        fs::write(&self.config_path, serde_json::to_vec_pretty(&node)?)?;
        NodeConfig::load_with_kubernetes_runtime_identity(
            &self.config_path,
            self.node_name.clone(),
        )?;
        Ok(())
    }

    fn capture_installer(
        set: &DaemonSet,
        mounts: &[RuntimeRecoveryMountInputV1],
    ) -> TestResult<Vec<String>> {
        let installer = set
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .and_then(|spec| spec.init_containers.as_ref())
            .and_then(|containers| {
                containers
                    .iter()
                    .find(|item| item.name == "install-runtime-gate")
            })
            .ok_or("the task Node has no runtime-gate installer")?;
        let command = installer
            .command
            .as_ref()
            .ok_or("the runtime-gate installer has no command")?;
        if command != &["/usr/local/bin/mithril-oci-hook", "install"] {
            return Err("the task Node has an unexpected runtime-gate installer".into());
        }
        let mut input = installer
            .args
            .as_ref()
            .ok_or("the runtime-gate installer has no arguments")?
            .iter();
        let mut args = Vec::with_capacity(input.len() + mounts.len());
        while let Some(arg) = input.next() {
            // The retained gate requires separate identity options and values.
            if matches!(
                arg.as_str(),
                "--node-read-only-mount"
                    | "--node-read-write-mount"
                    | "--runtime-cli-arg"
                    | "--runtime-service"
            ) {
                let value = input
                    .next()
                    .filter(|value| !value.is_empty() && !value.starts_with('-'))
                    .ok_or("the runtime-gate installer list option has no value")?;
                args.push(format!("{arg}={value}"));
            } else {
                args.push(arg.clone());
            }
        }
        for mount in mounts {
            let source = mount
                .source
                .to_str()
                .ok_or("a runtime mount source is not UTF-8")?;
            let destination = mount
                .destination
                .to_str()
                .ok_or("a runtime mount destination is not UTF-8")?;
            if !mount.read_only
                || !mount.source.is_absolute()
                || !mount.destination.is_absolute()
                || source.contains(['=', '\0', '\r', '\n'])
                || destination.contains(['=', '\0', '\r', '\n'])
            {
                return Err("the fixture runtime mount is not an exact read-only bind".into());
            }
            args.push(format!("--node-read-only-mount={source}={destination}"));
        }
        let count = args
            .iter()
            .filter(|arg| {
                matches!(
                    arg.split('=').next(),
                    Some("--node-read-only-mount" | "--node-read-write-mount")
                )
            })
            .count();
        if !(1..=32).contains(&count)
            || command.len() + args.len() > 64
            || args.iter().any(|arg| arg.is_empty() || arg.len() > 4096)
        {
            return Err(
                "the task Node exceeds the production recovery mount or argument bound".into(),
            );
        }
        Ok(args)
    }

    fn mount_capture(&self, bundle: &Path, cpus: usize) -> TestResult<()> {
        let directory = self.state_path.with_file_name("capture");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770))?;
        rustix::fs::chown(
            &directory,
            Some(rustix::process::Uid::from_raw(65532)),
            Some(rustix::process::Gid::from_raw(65532)),
        )?;
        let sets = Api::<DaemonSet>::namespaced(self.client.clone(), &self.system);
        let args = Self::capture_installer(
            &self.runtime.block_on(sets.get("mithril-node"))?,
            &[
                RuntimeRecoveryMountInputV1 {
                    source: bundle.to_owned(),
                    destination: "/qualification/runtime".into(),
                    read_only: true,
                },
                RuntimeRecoveryMountInputV1 {
                    source: bundle.join("bpftrace"),
                    destination: "/usr/bin/bpftrace".into(),
                    read_only: true,
                },
            ],
        )?;
        self.runtime.block_on(sets.patch("mithril-node", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {
                "volumes": [
                    {"name": "qualification-runtime", "hostPath": {"path": bundle, "type": "Directory"}},
                    {"name": "qualification-backend", "hostPath": {"path": bundle.join("bpftrace"), "type": "File"}}
                ],
                "initContainers": [{"name": "install-runtime-gate", "args": args}],
                "containers": [{"name": "mithril-node", "resources": {
                    "requests": {"cpu": "100m"}, "limits": {"cpu": cpus.to_string()}},
                    "volumeMounts": [
                        {"name": "qualification-runtime", "mountPath": "/qualification/runtime", "readOnly": true},
                        {"name": "qualification-backend", "mountPath": "/usr/bin/bpftrace", "readOnly": true}
                    ]}]
            }}}
        }))))?;
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        self.runtime.block_on(deployments.patch("mithril-control", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {
                "volumes": [
                    {"name": "qualification-test", "hostPath": {"path": std::env::current_exe()?, "type": "File"}},
                    {"name": "qualification-capture", "hostPath": {"path": directory, "type": "Directory"}}
                ],
                "containers": [{"name": "mithril-control", "volumeMounts": [
                    {"name": "qualification-test", "mountPath": "/qualification/test", "readOnly": true},
                    {"name": "qualification-capture", "mountPath": "/qualification/capture"}
                ]}]
            }}}
        }))))?;
        self.capture_rollout("deployment/mithril-control")
    }

    fn prepare_runtime(&self, bundle: &Path, libraries: &[String]) -> TestResult<Value> {
        let closure = self.capture_runtime("daemonset/mithril-node", "/usr/bin/bpftrace", true)?;
        let mut mounts = Vec::new();
        let mut volumes = Vec::new();
        let mut recovery = Vec::new();
        for library in libraries {
            if !closure.contains(&format!("/qualification/runtime/lib/{library} ")) {
                continue;
            }
            let path = format!("/usr/lib/x86_64-linux-gnu/{library}");
            let output = self
                .capture_command(
                    "daemonset/mithril-node",
                    &["/bin/sh", "-ec", "test -e \"$1\"", "preflight", &path],
                )
                .output()?;
            match output.status.code() {
                Some(0) => {}
                Some(1) => {
                    let name = format!("qualification-library-{}", mounts.len());
                    let source = bundle.join("lib").join(library);
                    volumes
                        .push(json!({"name": name, "hostPath": {"path": source, "type": "File"}}));
                    mounts.push(json!({"name": name, "mountPath": path, "readOnly": true}));
                    recovery.push(RuntimeRecoveryMountInputV1 {
                        source,
                        destination: path.into(),
                        read_only: true,
                    });
                }
                _ => return Err("the Node base-library check failed".into()),
            }
        }
        if !mounts.is_empty() {
            let sets = Api::<DaemonSet>::namespaced(self.client.clone(), &self.system);
            let args = Self::capture_installer(
                &self.runtime.block_on(sets.get("mithril-node"))?,
                &recovery,
            )?;
            self.runtime.block_on(sets.patch(
                "mithril-node",
                &PatchParams::default(),
                &Patch::Strategic(json!({
                    "spec": {"template": {"spec": {"volumes": volumes,
                        "initContainers": [{"name": "install-runtime-gate", "args": args}],
                        "containers": [{"name": "mithril-node", "volumeMounts": mounts}]}}}
                })),
            ))?;
            self.capture_rollout("daemonset/mithril-node")?;
            self.wait_node()?;
        }
        Ok(json!({
            "node": self.capture_runtime("daemonset/mithril-node", "/usr/local/bin/mithril-node", false)?,
            "backend": self.capture_runtime("daemonset/mithril-node", "/usr/bin/bpftrace", false)?,
            "control_child": self.capture_runtime("deployment/mithril-control", "/qualification/test", false)?,
            "mounted_libraries": mounts,
        }))
    }

    fn start_capture(&self) -> TestResult<()> {
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        self.runtime.block_on(deployments.patch("mithril-control", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {"containers": [{"name": "mithril-control",
                "command": ["/qualification/test"],
                "args": ["platform::kubernetes::observability_pod_child", "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                "env": [
                    {"name": "MITHRIL_TRACE_DIRECTORY", "value": "/qualification/capture"},
                    {"name": "MITHRIL_TRACE_NAMESPACE", "value": self.namespace},
                    {"name": "MITHRIL_TRACE_POD", "value": self.actor_name}
                ]
            }]}}}
        }))))?;
        self.capture_rollout("deployment/mithril-control")?;
        self.wait_node()
    }

    fn capture_input(&self, name: &str, record: &impl serde::Serialize) -> TestResult<()> {
        let path = self.state_path.with_file_name("capture").join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn capture_record(&self, name: &str) -> TestResult<Value> {
        let path = self.state_path.with_file_name("capture").join(name);
        Ok(wait_for(
            &path,
            "Control capture result",
            READY_LIMIT,
            || {
                if !path.is_file() {
                    return Ok(None);
                }
                let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
                serde_json::from_slice(&bytes).map(Some).map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: format!("invalid Control capture record: {source}"),
                    }
                    .build()
                })
            },
            || self.diagnostics(),
        )?)
    }

    fn capture_ack(&self, result: &Value, sequence: u64) -> TestResult<Value> {
        let terminal: mithril_control::TraceTerminalV1 =
            serde_json::from_value(result["terminal"].clone())?;
        terminal.validate()?;
        if terminal.last_sequence < sequence {
            return Err("the terminal does not cover the output after the query error".into());
        }
        let directory = self
            .state_path
            .join("diagnostics")
            .join(hex::encode(terminal.execution_id));
        let path = directory.join("ack.json");
        let ack = wait_for(
            &path,
            "Node durable diagnostic acknowledgement",
            READY_LIMIT,
            || {
                let file = match File::open(&path) {
                    Ok(file) => file,
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(None);
                    }
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                let mut bytes = Vec::new();
                file.take(4097)
                    .read_to_end(&mut bytes)
                    .context(IoSnafu { path: &path })?;
                if bytes.len() > 4096 {
                    return Err(InvalidInputSnafu {
                        path: &path,
                        reason: "the Node acknowledgement exceeds its byte bound",
                    }
                    .build());
                }
                let ack: mithril_control::TraceTerminalV1 = serde_json::from_slice(&bytes)
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: &path,
                            reason: format!("invalid Node acknowledgement: {source}"),
                        }
                        .build()
                    })?;
                if ack != terminal {
                    return Err(InvalidInputSnafu {
                        path: &path,
                        reason: "the Node acknowledgement differs from the Control terminal",
                    }
                    .build());
                }
                let output = directory.join("output.jsonl");
                if fs::metadata(&output)
                    .context(IoSnafu { path: &output })?
                    .len()
                    != 0
                {
                    return Ok(None);
                }
                Ok(Some(ack))
            },
            || self.diagnostics(),
        )?;
        Ok(serde_json::to_value(ack)?)
    }

    fn capture_denial(&mut self, actor: &mut ProcessFixture, name: &str) -> TestResult<Value> {
        actor.send(b"/fixtures/policy_replace.py\n")?;
        let text = actor.wait_text(&self.work_path.join(name).join("0.json"), "protected read")?;
        let result: (i32, usize) = serde_json::from_str(&text)?;
        if result != (libc::EACCES, 0) {
            return Err(format!("the protected read changed its physical decision: {text}").into());
        }
        let task = self.task(actor.id(), "protected Pod reader")?;
        let path = self.pin_path.clone();
        let event = wait_for(
            &path,
            "protected read evidence",
            READY_LIMIT,
            || {
                let snapshot = self
                    .snapshot()
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu { path: &path })?;
                Ok(snapshot.recent_effects.into_iter().find(|event| {
                    task.matches_effect(
                        event,
                        "EXACT_POLICY_DENY",
                        erebor_interceptor_abi::KernelEffectFamilyV1::File,
                        erebor_interceptor_abi::KernelEffectOperationV1::OpenRead,
                        -libc::EACCES,
                    )
                }))
            },
            || self.diagnostics(),
        )?;
        actor.ensure_running("protected Pod reader")?;
        Ok(json!({"errno": result.0, "size": result.1, "event": {
            "reason": event.reason, "kernel_result": event.kernel_result,
            "effect_family": event.effect_family, "operation": event.operation,
            "task_cookie": event.task_cookie, "binding_id": event.binding_id,
            "profile_generation_ref_id": event.profile_generation_ref_id,
            "source_sequence": event.source_sequence,
        }}))
    }

    fn capture_cleanup(
        &self,
        expected: &crate::observability::OwnedResources,
        observed: &crate::observability::ResourceSnapshot,
    ) -> TestResult<()> {
        let last = RefCell::new(None);
        wait_stable(
            &self.pin_path,
            "diagnostic BPF cleanup",
            READY_LIMIT,
            2,
            || {
                let actual = crate::observability::ResourceSnapshot::read()
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu {
                        path: &self.pin_path,
                    })?;
                let owned = crate::observability::ResourceSnapshot::owned(&self.pin_path)
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu {
                        path: &self.pin_path,
                    })?;
                let complete = actual.cleanup_matches(expected, observed, &owned)
                    && observed
                        .absent()
                        .map_err(|error| std::io::Error::other(error.to_string()))
                        .context(IoSnafu {
                            path: &self.pin_path,
                        })?;
                *last.borrow_mut() = Some((actual, owned));
                Ok(complete)
            },
            || {
                format!(
                    "expected={expected:?}, observed={observed:?}, actual={:?}",
                    last.borrow()
                )
            },
        )?;
        Ok(())
    }

    fn capture_resources(
        &self,
        initial: &crate::observability::ResourceSnapshot,
        expected: &crate::observability::OwnedResources,
    ) -> TestResult<crate::observability::ResourceSnapshot> {
        if crate::observability::ResourceSnapshot::owned(&self.pin_path)? != *expected {
            return Err("the real capture changed enforcement resources".into());
        }
        crate::observability::ResourceSnapshot::failed_opens(initial)
    }

    fn capture_identity(&self, accepted: &Value, uid: &str) -> TestResult<()> {
        let target = &accepted["request"]["targets"][0];
        let group = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Pod has no real cgroup")?;
        if target["fact"]["pod_uid"].as_str() != Some(uid)
            || target["fact"]["kubernetes"]["pod_name"].as_str() != Some(ACTOR)
            || target["runtime_container_id"].as_str() != self.actor_id.as_deref()
            || target["cgroup_id"].as_u64() != Some(fs::metadata(group)?.ino())
        {
            return Err("Control did not freeze the actual Pod, CRI container, and cgroup".into());
        }
        Ok(())
    }

    fn capture_exit(actor: &mut ProcessFixture) -> TestResult<()> {
        actor.stop()?;
        Ok(())
    }

    fn delete_capture(&mut self, actor: &mut ProcessFixture) -> TestResult<()> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.namespace);
        let original = self
            .pod()?
            .metadata
            .uid
            .ok_or("the original Pod has no UID")?;
        self.runtime.block_on(pods.delete(
            &self.actor_name,
            &DeleteParams {
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(original.clone()),
                    resource_version: None,
                }),
                grace_period_seconds: Some(1),
                ..DeleteParams::default()
            },
        ))?;
        wait_for(
            &self.work_path,
            "original Pod deletion",
            STOP_LIMIT,
            || match self.runtime.block_on(pods.get(&self.actor_name)) {
                Err(kube::Error::Api(response)) if response.code == 404 => Ok(Some(())),
                Ok(pod) if pod.metadata.uid.as_deref() == Some(&original) => Ok(None),
                Ok(_) => Err(InvalidInputSnafu {
                    path: &self.work_path,
                    reason: "the Pod name changed before deletion completed",
                }
                .build()),
                Err(source) => Err(std::io::Error::other(source.to_string())).context(IoSnafu {
                    path: &self.work_path,
                }),
            },
            || self.diagnostics(),
        )?;
        Self::capture_exit(actor)?;
        self.actor_id = None;
        self.actor_pid = None;
        self.actor_cgroup = None;
        self.actors.clear();
        self.wait_policy(0)
    }

    fn qualify_pods() -> TestResult<()> {
        let test_admission = super::shared::Shared::test_admission()?;
        let proof = PathBuf::from(KubernetesState::required("MITHRIL_TRACE_PROOF")?);
        if proof.exists() || !proof.is_absolute() {
            return Err("the Pod proof must name a new absolute file".into());
        }
        let (bundle, libraries) = Self::capture_bundle()?;
        let config = if test_admission {
            super::shared::Shared::capture_config(
                &bundle.join("bpftrace"),
                PathBuf::from("/usr/bin/bpftrace"),
                std::thread::available_parallelism()?.get(),
                1,
            )?
        } else {
            serde_json::from_slice(&fs::read(KubernetesState::required(
                "MITHRIL_TRACE_CONFIG",
            )?)?)?
        };
        use sha2::Digest as _;
        let digest: [u8; 32] = sha2::Sha256::digest(fs::read(bundle.join("bpftrace"))?).into();
        if digest != config.qualification.executable_sha256 {
            return Err("the bundled backend differs from its pinned configuration".into());
        }
        let mut env = Self::setup("observability-pods")?;
        let capture = env.state_path.with_file_name("capture");
        let result = (|| {
            env.configure_capture(&config)?;
            env.start_control()?;
            env.mount_capture(&bundle, config.qualification.logical_cpus)?;
            let labels = env.install_policy("multi_policy_deny.json")?;
            env.start_node()?;
            let preflight = env.prepare_runtime(&bundle, &libraries)?;
            env.start_capture()?;
            env.node_ready()?;
            let mut actor = env.start_actor("read_path.py", &["before"], &labels)?;
            env.wait_workload_ready()?;
            env.running(actor.id())?;
            let initial = crate::observability::ResourceSnapshot::capture_baseline()?;
            let enforcement = crate::observability::ResourceSnapshot::owned(&env.pin_path)?;
            let original_uid = env
                .pod()?
                .metadata
                .uid
                .ok_or("the original Pod has no UID")?;
            env.capture_input(
                "start-0.json",
                &json!({"pod_uid": original_uid, "request_id": uuid::Uuid::new_v4().as_bytes()}),
            )?;
            let original = env.capture_record("ready-0.json")?;
            env.capture_identity(&original, &original_uid)?;
            let active = env.capture_resources(&initial, &enforcement)?;
            env.capture_record("query-failed-0.json")?;
            let before = env.capture_denial(&mut actor, "before")?;
            let mut failure = env.capture_record("query-after-0.json")?;
            env.delete_capture(&mut actor)?;
            let completed = env.capture_record("done-0.json")?;
            let sequence = failure["post_failure_sequence"]
                .as_u64()
                .ok_or("the query case has no new output sequence")?;
            failure["node_acknowledgement"] = env.capture_ack(&completed, sequence)?;
            failure["post_failure_acknowledged"] = json!(true);
            env.capture_cleanup(&enforcement, &active)?;

            let mut actor = env.start_actor("read_path.py", &["after"], &labels)?;
            env.wait_workload_ready()?;
            env.running(actor.id())?;
            let baseline = crate::observability::ResourceSnapshot::capture_baseline()?;
            let replacement_uid = env
                .pod()?
                .metadata
                .uid
                .ok_or("the replacement Pod has no UID")?;
            if replacement_uid == original_uid || env.actor_name != ACTOR {
                return Err("the fixture did not replace the same Pod name with a new UID".into());
            }
            env.capture_input(
                "start-1.json",
                &json!({"pod_uid": replacement_uid, "request_id": uuid::Uuid::new_v4().as_bytes()}),
            )?;
            let replacement = env.capture_record("ready-1.json")?;
            env.capture_identity(&replacement, &replacement_uid)?;
            let active_after = env.capture_resources(&baseline, &enforcement)?;
            let after = env.capture_denial(&mut actor, "after")?;
            env.capture_input("stop-1.json", &json!({"stop": true}))?;
            let mut record = env.capture_record("result.json")?;
            env.capture_cleanup(&enforcement, &active_after)?;
            let pods = Api::<Pod>::namespaced(env.client.clone(), &env.system);
            let control =
                env.runtime
                    .block_on(pods.list(
                        &ListParams::default().labels("app.kubernetes.io/name=mithril-control"),
                    ))?
                    .items;
            if control.len() != 1
                || control[0]
                    .status
                    .as_ref()
                    .and_then(|status| status.container_statuses.as_ref())
                    .is_none_or(|statuses| statuses.len() != 1 || statuses[0].restart_count != 0)
            {
                return Err("the finite Control child restarted during the case".into());
            }
            record["physical"] = json!(true);
            record["query_failure"] = failure;
            record["physical_denials"] = json!([before, after]);
            record["runtime_preflight"] = preflight;
            if test_admission {
                record["diagnostic_admission"] = json!("synthetic-test-only");
                record["performance_qualified"] = json!(false);
                record["performance_claim"] = json!(false);
            } else {
                record["diagnostic_admission"] = json!("qualified-config");
                record["qualification"] = serde_json::to_value(config)?;
            }
            record["enforcement_resources_unchanged"] = json!(true);
            record["cleanup_observed"] = json!(true);
            record["diagnostic_resources"] =
                json!({"original": active, "replacement": active_after});
            record["resources"] = json!({"initial": enforcement, "final": crate::observability::ResourceSnapshot::owned(&env.pin_path)?});
            actor.stop()?;
            let finish = env.state_path.with_file_name("capture").join("finish.json");
            let temporary = finish.with_extension("tmp");
            fs::write(
                &temporary,
                serde_json::to_vec_pretty(&json!({"finish": true}))?,
            )?;
            Self::capture_finish(&mut env, &temporary, &finish, |env| env.clean_test())?;
            fs::write(proof, serde_json::to_vec_pretty(&record)?)?;
            Ok(())
        })();
        Self::capture_result(&capture, result, || env.snapshot())
    }

    fn capture_result(
        path: &Path,
        result: TestResult<()>,
        snapshot: impl FnOnce() -> TestResult<MithrilObservationSnapshot>,
    ) -> TestResult<()> {
        if let Err(error) = &result {
            if path.exists() {
                let (name, bytes) = match snapshot() {
                    Ok(snapshot) => ("node-snapshot.pb", snapshot.encode_to_vec()),
                    Err(source) => ("node-snapshot-error.txt", source.to_string().into_bytes()),
                };
                for (name, bytes) in [
                    ("capture-failure.txt", error.to_string().into_bytes()),
                    (name, bytes),
                ] {
                    let file = path.join(name);
                    if let Err(source) = fs::write(&file, bytes) {
                        erebor_telemetry::warn!(
                            "capture diagnostics could not be retained",
                            path = %file.display(),
                            error = %source,
                        );
                    }
                }
                let retained = path
                    .parent()
                    .ok_or("the capture directory has no parent")?
                    .with_extension("capture-failed");
                if retained.exists() {
                    return Err(format!(
                        "{error}; the retained capture directory already exists: {}",
                        retained.display()
                    )
                    .into());
                }
                fs::rename(path, &retained).map_err(|source| {
                    format!(
                        "{error}; capture evidence could not be retained at {}: {source}",
                        retained.display()
                    )
                })?;
                erebor_telemetry::info!(
                    "retained failed capture evidence",
                    path = %retained.display()
                );
            }
        }
        result
    }

    fn capture_finish<P: Platform>(
        env: &mut P,
        temporary: &Path,
        finish: &Path,
        retire: impl FnOnce(&mut P) -> TestResult<()>,
    ) -> TestResult<()> {
        retire(env)?;
        env.stop_node()?;
        env.stop()?;
        fs::rename(temporary, finish)?;
        Ok(())
    }
}

impl PodCapture {
    fn now() -> TestResult<u64> {
        Ok(u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        )?)
    }

    fn write(&self, name: &str, record: &impl serde::Serialize) -> TestResult<()> {
        let path = self.directory.join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    async fn input(&self, name: &str) -> TestResult<Value> {
        let path = self.directory.join(name);
        let deadline = Instant::now() + READY_LIMIT;
        loop {
            match fs::read(&path) {
                Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(source.into()),
            }
            if Instant::now() >= deadline {
                return Err(format!("capture input is absent: {}", path.display()).into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn submit(&self, input: &Value) -> TestResult<TraceAcceptedV1> {
        let uid = input["pod_uid"]
            .as_str()
            .ok_or("capture input has no Pod UID")?;
        let request_id: [u8; 16] = serde_json::from_value(input["request_id"].clone())?;
        let deadline = Instant::now() + READY_LIMIT;
        loop {
            let facts = self
                .control
                .kubernetes_workload_inventory()
                .into_iter()
                .filter(|fact| {
                    fact.pod_uid == uid
                        && fact.container_name == CONTAINER
                        && fact.kubernetes.as_ref().is_some_and(|identity| {
                            identity.namespace_name == self.namespace
                                && identity.pod_name == self.pod_name
                        })
                })
                .collect::<Vec<_>>();
            if facts.len() > 1 {
                return Err("capture inventory has more than one matching container".into());
            }
            if !facts.is_empty() {
                let grant = TraceAccessV1 {
                    tenant_id: self.tenant_id,
                    principal: "pod-qualification".to_owned(),
                    valid_until_unix_ns: Self::now()? + 900_000_000_000,
                    revoked: false,
                };
                let participants = self.control.resolve_trace_targets(facts, &grant).await?;
                if let [participant] = participants.as_slice() {
                    if let Some(target) = &participant.target {
                        let request = TraceRequestV1 {
                            tenant_id: self.tenant_id,
                            request_id,
                            source: TraceRecipeV1::FailedOpens.manifest()?.source,
                            targets: vec![target.clone()],
                            unresolved: Vec::new(),
                            collection_seconds: 120,
                            selection: None,
                            finding_reference: None,
                        };
                        self.control.accept_trace(request, grant.clone())?;
                        return Ok(self
                            .traces
                            .read(self.tenant_id, request_id, &grant, Self::now()?)?
                            .1);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err("Control did not resolve the live Pod through Node".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn output(&self, accepted: &TraceAcceptedV1) -> TestResult<Vec<TraceBatchV1>> {
        let mut after = 0;
        let mut retained = Vec::new();
        loop {
            let page = self.traces.output(
                self.tenant_id,
                accepted.request.request_id,
                0,
                &accepted.access,
                Self::now()?,
                after,
            )?;
            let last = page
                .iter()
                .rev()
                .find_map(|batch| batch.frames.last().map(|frame| frame.sequence));
            let terminal = page.iter().any(|batch| batch.terminal.is_some());
            retained.extend(page);
            if terminal || last.is_none() {
                return Ok(retained);
            }
            let next = last.ok_or("capture page has no sequence")?;
            if next <= after || next > 4096 {
                return Err("capture output did not advance within its frame bound".into());
            }
            after = next;
        }
    }

    fn receipt(
        &self,
        accepted: &TraceAcceptedV1,
    ) -> TestResult<araphor_data::TraceOutputReceiptV1> {
        let data = self
            .control
            .analysis_store()
            .ok_or("capture store is absent")?;
        let execution = accepted.execution_id(0)?;
        let (_, intent) = data
            .trace_intent(self.tenant_id, accepted.request.request_id)?
            .ok_or("capture intent is absent")?;
        let binding = intent
            .bindings
            .iter()
            .find(|binding| binding.identity.execution_id == execution)
            .ok_or("capture binding is absent")?;
        Ok(data
            .trace_receipt(&binding.identity)?
            .ok_or("capture receipt is absent")?)
    }

    async fn query_capture(&self, accepted: &TraceAcceptedV1) -> TestResult<Value> {
        let before = self.receipt(accepted)?;
        let prefix = self.output(accepted)?;
        let prior = prefix
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= before.last_sequence)
            .collect::<Vec<_>>();
        if before.terminal.is_some()
            || prefix.iter().any(|batch| batch.terminal.is_some())
            || prior.last().map(|frame| frame.sequence) != Some(before.last_sequence)
        {
            return Err("the query case has no active durable capture prefix".into());
        }
        let client = AraphorClient::connect(self.query_profile.clone()).await?;
        let mut failure =
            crate::observability::ObservabilityQualification::query_failure(&client).await?;
        let baseline = self.receipt(accepted)?;
        let retained = self.output(accepted)?;
        let current = retained
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= before.last_sequence)
            .collect::<Vec<_>>();
        let data = self
            .control
            .analysis_store()
            .ok_or("capture store is absent")?;
        if baseline.terminal.is_some()
            || baseline.identity != before.identity
            || baseline.last_sequence < before.last_sequence
            || retained.iter().any(|batch| batch.terminal.is_some())
            || current != prior
            || !data.storage_health()?.write_ready
            || self
                .traces
                .read(
                    self.tenant_id,
                    accepted.request.request_id,
                    &accepted.access,
                    Self::now()?,
                )?
                .1
                != *accepted
        {
            return Err("the public query error changed the capture or durable prefix".into());
        }
        let count = retained
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= baseline.last_sequence)
            .filter_map(|frame| TraceRecipeV1::FailedOpens.measurements(frame))
            .flatten()
            .filter(|row| row.errno == -i64::from(libc::EACCES))
            .map(|row| row.count)
            .max()
            .unwrap_or(0);
        failure["prefix_sequence"] = json!(baseline.last_sequence);
        failure["prefix_revision"] = json!(baseline.commit_revision);
        failure["prefix_output_bytes"] = json!(baseline.output_bytes);
        failure["prefix_count"] = json!(count);
        failure["capture_active"] = json!(true);
        failure["prefix_unchanged"] = json!(true);
        failure["writer_ready"] = json!(true);
        self.write("query-failed-0.json", &failure)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let receipt = self.receipt(accepted)?;
            let output = self.output(accepted)?;
            if receipt.terminal.is_some()
                || output.iter().any(|batch| batch.terminal.is_some())
                || receipt.identity != baseline.identity
            {
                return Err("capture stopped before new output after the query error".into());
            }
            let next = output
                .iter()
                .flat_map(|batch| &batch.frames)
                .filter(|frame| {
                    frame.sequence > baseline.last_sequence
                        && frame.sequence <= receipt.last_sequence
                })
                .find_map(|frame| {
                    TraceRecipeV1::FailedOpens
                        .measurements(frame)?
                        .into_iter()
                        .find(|row| row.errno == -i64::from(libc::EACCES) && row.count > count)
                        .map(|row| (frame.sequence, row.count))
                });
            if let Some((sequence, count)) = next {
                if receipt.commit_revision <= baseline.commit_revision
                    || receipt.output_bytes <= baseline.output_bytes
                    || !data.storage_health()?.write_ready
                {
                    return Err("new capture output has no advanced durable receipt".into());
                }
                failure["post_failure_sequence"] = json!(sequence);
                failure["post_failure_revision"] = json!(receipt.commit_revision);
                failure["post_failure_output_bytes"] = json!(receipt.output_bytes);
                failure["post_failure_count"] = json!(count);
                failure["durable_receipt_advanced"] = json!(true);
                self.write("query-after-0.json", &failure)?;
                return Ok(failure);
            }
            if Instant::now() >= deadline {
                return Err("capture has no new denied-open output after the query error".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn ready(&self, accepted: &TraceAcceptedV1) -> TestResult<()> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let output = self.output(accepted)?;
            if output.iter().flat_map(|batch| &batch.frames).any(|frame| {
                frame.kind == mithril_control::TraceFrameKindV1::Diagnostic
                    && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
            }) {
                return Ok(());
            }
            if output.iter().any(|batch| batch.terminal.is_some()) || Instant::now() >= deadline {
                return Err("Node capture did not provide the real attachment notification".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn terminal(
        &self,
        accepted: &TraceAcceptedV1,
        reason: TraceTerminalReasonV1,
    ) -> TestResult<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = self.output(accepted)?;
            if let Some(terminal) = output.iter().find_map(|batch| batch.terminal.as_ref()) {
                let execution = accepted.execution_id(0)?;
                let attachments = output
                    .iter()
                    .flat_map(|batch| &batch.frames)
                    .filter(|frame| {
                        frame.kind == mithril_control::TraceFrameKindV1::Diagnostic
                            && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                    })
                    .count();
                if terminal.reason != reason
                    || terminal.execution_id != execution
                    || attachments != 1
                    || !terminal.output_incomplete
                    || terminal.kernel_lost_events.is_some()
                    || terminal.cleanup == mithril_control::TraceCleanupV1::Failed
                    || output.iter().any(|batch| batch.execution_id != execution)
                {
                    return Err(
                        format!("Node capture has an unexpected terminal: {terminal:?}").into(),
                    );
                }
                if self
                    .traces
                    .read(
                        self.tenant_id,
                        accepted.request.request_id,
                        &accepted.access,
                        Self::now()?,
                    )?
                    .1
                    != *accepted
                {
                    return Err("the frozen accepted trace intent changed".into());
                }
                if !output
                    .iter()
                    .flat_map(|batch| &batch.frames)
                    .filter_map(|frame| TraceRecipeV1::FailedOpens.measurements(frame))
                    .flatten()
                    .any(|row| row.errno == -i64::from(libc::EACCES) && row.count > 0)
                {
                    return Err("the reviewed capture has no denied-open measurement".into());
                }
                let receipt = self.receipt(accepted)?;
                if receipt.terminal.as_ref() != Some(terminal)
                    || receipt.last_sequence != terminal.last_sequence
                {
                    return Err("the retained terminal differs from its durable receipt".into());
                }
                return Ok(json!({
                    "accepted": accepted, "output": output, "terminal": terminal,
                    "attachment_notifications": attachments,
                    "receipt": {"identity": receipt.identity, "last_sequence": receipt.last_sequence,
                        "output_bytes": receipt.output_bytes, "commit_revision": receipt.commit_revision},
                }));
            }
            if Instant::now() >= deadline {
                return Err("Node capture has no retained terminal within the bound".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn capture(&self) -> TestResult<()> {
        let original = self.submit(&self.input("start-0.json").await?).await?;
        self.ready(&original).await?;
        self.write("ready-0.json", &original)?;
        self.query_capture(&original).await?;
        let original_result = self
            .terminal(&original, TraceTerminalReasonV1::TargetChanged)
            .await?;
        self.write("done-0.json", &original_result)?;

        let replacement = self.submit(&self.input("start-1.json").await?).await?;
        let first = &original.request.targets[0];
        let second = &replacement.request.targets[0];
        if first.fact.pod_uid == second.fact.pod_uid
            || first.runtime_container_id == second.runtime_container_id
            || first.cgroup_id == second.cgroup_id
            || first.root_cgroup_live_interval_id == second.root_cgroup_live_interval_id
        {
            return Err("the replacement request reused the original target lifetime".into());
        }
        self.ready(&replacement).await?;
        self.write("ready-1.json", &replacement)?;
        self.input("stop-1.json").await?;
        self.traces.cancel(
            self.tenant_id,
            replacement.request.request_id,
            &replacement.access,
            Self::now()?,
            false,
        )?;
        let replacement_result = self
            .terminal(&replacement, TraceTerminalReasonV1::Cancelled)
            .await?;
        self.control
            .accept_trace(original.request.clone(), original.access.clone())?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        if serde_json::to_value(self.output(&original)?)? != original_result["output"] {
            return Err("the original execution acquired output after Pod replacement".into());
        }
        self.write("result.json", &json!({
            "schema_version": 1, "case": "owned-pod-replacement", "result": "PASS",
            "original": original_result, "replacement": replacement_result,
            "original_retry": true, "original_output_unchanged": true,
            "discovery_enabled": false, "performance_claim": false,
            "storage": self.control.analysis_store().ok_or("capture store is absent")?.storage_health()?,
        }))?;
        self.input("finish.json").await?;
        Ok(())
    }

    async fn run_child() -> TestResult<()> {
        let config = ControlConfig::load(Path::new("/etc/mithril/control.json"))?;
        let policy = config
            .kubernetes_policy
            .as_ref()
            .ok_or("the fixture has no policy owner")?
            .clone();
        let signing: [u8; 32] =
            hex::decode(fs::read_to_string(&policy.signer.signing_key_path)?.trim())?
                .try_into()
                .map_err(|_| "the fixture signer is not 32 bytes")?;
        let mut parts = config.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        parts.control = parts.control.with_trace_signer(
            policy.signer.signing_key_id,
            policy.signer.distribution_sequence_epoch,
            ed25519_dalek::SigningKey::from_bytes(&signing),
        )?;
        let directory = PathBuf::from(KubernetesState::required("MITHRIL_TRACE_DIRECTORY")?);
        let tenant_id = *uuid::Uuid::parse_str(&policy.tenant_id)?.as_bytes();
        let tls = MtlsFixture::in_directory(tempfile::tempdir_in(&directory)?, false)?;
        let provider =
            crate::control_fixture::oidc::OidcFixture::start(&tls.files, "pod-query-qualification")
                .await?;
        let mut client = parts
            .client
            .take()
            .ok_or("the fixture has no shared client listener")?;
        let client_ca = client
            .auth
            .oidc
            .ca_path
            .clone()
            .ok_or("the fixture has no client TLS trust file")?;
        client.auth = provider.auth(&client.auth.origin, Some(tenant_id), tls.files.ca.clone());
        client.investigation = Some(mithril_control::ClientGrpcConfig::default());
        let mut credential = tempfile::NamedTempFile::new_in(&directory)?;
        credential.write_all(b"fixture-access")?;
        let query_profile = AraphorProfile {
            endpoint: format!("https://localhost:{}", client.listen.port()),
            tenant_id: uuid::Uuid::from_bytes(tenant_id).to_string(),
            credential_file: credential.path().to_path_buf(),
            ca_file: Some(client_ca),
        };
        let owner = Self {
            traces: TraceOwner::new(
                parts
                    .control
                    .analysis_store()
                    .ok_or("capture store is absent")?,
            ),
            control: parts.control,
            directory,
            namespace: KubernetesState::required("MITHRIL_TRACE_NAMESPACE")?,
            pod_name: KubernetesState::required("MITHRIL_TRACE_POD")?,
            tenant_id,
            query_profile,
        };
        let policies = owner
            .control
            .policy_desired_state()
            .ok_or("the fixture has no policy controller")?;
        let nodes = parts
            .kubernetes_nodes
            .ok_or("the fixture has no Node controller")?;
        let admission = parts
            .kubernetes_admission
            .ok_or("the fixture has no admission listener")?;
        let result = tokio::select! {
            result = owner.capture() => result,
            result = mithril_control::serve(parts.listen, &parts.tls, owner.control.clone(), std::future::pending::<()>()) => {
                result?; Err("the Control listener stopped before fixture completion".into())
            },
            _ = policies.clone().run_kubernetes(owner.control.clone()) => Err("the policy controller stopped".into()),
            _ = nodes.clone().run_kubernetes(owner.control.clone()) => Err("the Node controller stopped".into()),
            result = mithril_control::KubernetesAdmissionOwner::serve(admission, owner.control.clone(), policies, nodes, std::future::pending::<()>()) => {
                result?; Err("the admission listener stopped".into())
            },
            result = async {
                mithril_control::ClientListener::load(client, owner.control.clone()).await?
                    .serve(std::future::pending::<()>()).await
            } => {
                result?; Err("the shared client listener stopped".into())
            },
            _ = tokio::time::sleep(Duration::from_secs(900)) => Err("the Control fixture exceeded its lifetime".into()),
        };
        let stopped = provider.shutdown().await;
        result?;
        stopped?;
        Ok(())
    }
}

#[test]
fn observability_capture_cleanup() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    for failed in [false, true] {
        let path = directory
            .path()
            .join(if failed { "failed" } else { "success" });
        let out = ProbeDirectory::create(&path)?;
        let capture = path.join("capture");
        fs::create_dir(&capture)?;
        fs::write(capture.join("ready-1.json"), b"retained capture prefix")?;
        fs::write(path.join("unrelated"), b"scenario input")?;
        let result = Kubernetes::capture_result(
            &capture,
            if failed {
                Err("the capture child failed".into())
            } else {
                Ok(())
            },
            || {
                assert!(failed, "successful capture read failure diagnostics");
                Ok(MithrilObservationSnapshot::default())
            },
        );
        assert_eq!(result.is_err(), failed);
        if let Err(error) = result {
            assert_eq!(error.to_string(), "the capture child failed");
        }
        drop(out);
        assert!(!path.exists());
        let retained = path.with_extension("capture-failed");
        assert_eq!(retained.exists(), failed);
        if failed {
            assert_eq!(
                fs::read(retained.join("ready-1.json"))?,
                b"retained capture prefix"
            );
            assert!(!retained.join("unrelated").exists());
        }
    }
    Ok(())
}

#[test]
fn observability_startup_failure() -> TestResult<()> {
    use erebor_runtime_ipc::v1::MithrilEffectObservation;

    let directory = tempfile::tempdir()?;
    let error = "Kubernetes actor worker exited with code 1; Fatal Python error: Failed to import encodings module; PermissionError: [Errno 13] Permission denied: '/usr/local/lib/python3.13/encodings/aliases.py'";
    // These event fields are test input, not a measured cause.
    let event = MithrilEffectObservation {
        reason: "EXACT_POLICY_DENY".to_owned(),
        kernel_result: -libc::EACCES,
        source_sequence: 1,
        source_cpu_id: 2,
        operation_argument: 7,
        execution_approval_trace_stage: u32::from(
            erebor_interceptor_abi::EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1,
        ),
        ..Default::default()
    };
    let mut snapshot = MithrilObservationSnapshot {
        cgroup_scope: "/".to_owned(),
        effect_health_available: true,
        unresolved_effects: 3,
        evidence_errors: 4,
        recent_effects: vec![event.clone()],
        ..Default::default()
    };
    snapshot
        .recent_effects
        .extend((2..=1024).map(|sequence| MithrilEffectObservation {
            reason: "APPLICATION_DEFAULT_ALLOW".to_owned(),
            kernel_result: 0,
            source_sequence: sequence,
            ..event.clone()
        }));
    assert!(snapshot
        .recent_effects
        .iter()
        .rev()
        .take(16)
        .all(|event| event.kernel_result == 0));
    for available in [true, false] {
        let path = directory
            .path()
            .join(if available { "observed" } else { "unavailable" });
        let out = ProbeDirectory::create(&path)?;
        let capture = path.join("capture");
        fs::create_dir(&capture)?;
        let result = Kubernetes::capture_result(&capture, Err(error.into()), || {
            if available {
                Ok(snapshot.clone())
            } else {
                Err("the Node observation socket is unavailable".into())
            }
        });
        assert_eq!(
            result
                .err()
                .ok_or("the startup failure succeeded")?
                .to_string(),
            error
        );
        drop(out);
        let retained = path.with_extension("capture-failed");
        assert!(!path.exists());
        assert_eq!(
            fs::read_to_string(retained.join("capture-failure.txt"))?,
            error
        );
        for name in ["start-0.json", "ready-0.json", "result.json"] {
            assert!(!retained.join(name).exists());
        }
        if available {
            let bytes = fs::read(retained.join("node-snapshot.pb"))?;
            assert_eq!(
                MithrilObservationSnapshot::decode(bytes.as_slice())?,
                snapshot
            );
            assert!(!retained.join("node-snapshot-error.txt").exists());
        } else {
            assert!(!retained.join("node-snapshot.pb").exists());
            assert_eq!(
                fs::read_to_string(retained.join("node-snapshot-error.txt"))?,
                "the Node observation socket is unavailable"
            );
        }
    }
    Ok(())
}

#[test]
fn observability_pod_finish() -> TestResult<()> {
    struct CapturePlatform {
        finish: PathBuf,
        reader: KernelStateReader,
        retired: bool,
        node_stopped: bool,
        closed: bool,
        fail_stop: bool,
    }

    impl Platform for CapturePlatform {
        fn source(&self) -> &Path {
            &self.finish
        }

        fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
            Err("the shutdown double has no observation snapshot".into())
        }

        fn maps(&self) -> (&Path, &KernelStateReader) {
            (&self.finish, &self.reader)
        }

        fn stop_node(&mut self) -> TestResult<()> {
            if self.finish.exists() || self.closed || !self.retired {
                return Err("Node stop needs live Control, a held guard and retired work".into());
            }
            if self.fail_stop {
                return Err("Node stop failed".into());
            }
            self.node_stopped = true;
            Ok(())
        }

        fn stop(&mut self) -> TestResult<()> {
            if self.finish.exists() || !self.node_stopped {
                return Err("the guard closes before Node stop".into());
            }
            self.closed = true;
            Ok(())
        }
    }

    for failure in [None, Some("retirement"), Some("node")] {
        let directory = tempfile::tempdir()?;
        let temporary = directory.path().join("finish.tmp");
        let finish = directory.path().join("finish.json");
        fs::write(&temporary, b"{\"finish\":true}")?;
        let mut env = CapturePlatform {
            finish: finish.clone(),
            reader: KernelStateReader::new(directory.path()),
            retired: false,
            node_stopped: false,
            closed: false,
            fail_stop: failure == Some("node"),
        };
        let result = Kubernetes::capture_finish(&mut env, &temporary, &finish, |env| {
            if failure == Some("retirement") {
                return Err("scenario retirement failed".into());
            }
            if env.closed || env.node_stopped || env.finish.exists() {
                return Err("scenario retirement needs live Node and Control".into());
            }
            env.retired = true;
            Ok(())
        });
        if failure.is_none() {
            result?;
            assert!(env.retired && env.node_stopped && env.closed);
            assert_eq!(fs::read(&finish)?, b"{\"finish\":true}");
            assert!(!temporary.exists());
        } else {
            assert!(result.is_err());
            assert!(!env.node_stopped && !env.closed && !finish.exists());
            assert!(temporary.exists());
            assert_eq!(env.retired, failure == Some("node"));
        }
    }
    Ok(())
}

#[test]
fn observability_pod_exec_exit() -> TestResult<()> {
    let path = Path::new("/bin/cat");
    let mut command = Command::new(path);
    let mut remote = ProcessFixture::spawn(&mut command, path)?;
    let mut actor = ProcessFixture::spawn(&mut command, path)?;
    let transport_pid = actor.id();
    let remote_pid = remote.id();
    actor.set_actor(remote_pid)?;
    actor.set_exit_probe(|| Ok(None));
    remote.close();
    assert!(remote
        .wait_exit("remote Pod actor", Duration::from_secs(2))?
        .success());
    remote.stop()?;
    assert!(!Path::new(&format!("/proc/{remote_pid}")).exists());
    actor.ensure_running("local exec transport with open stdin")?;
    assert!(Path::new(&format!("/proc/{transport_pid}")).exists());
    Kubernetes::capture_exit(&mut actor)?;
    assert!(!Path::new(&format!("/proc/{transport_pid}")).exists());
    Ok(())
}

#[test]
fn observability_runtime_mount_args() -> TestResult<()> {
    let chart_pairs = [
        ("--owner", "mithril-pid-test/mithril"),
        ("--hook-host-directory", "/usr/libexec/oci/hooks.d"),
        (
            "--containerd-host-directory",
            "/var/lib/rancher/k3s/agent/etc/containerd",
        ),
        ("--containerd-drop-in-directory", "config-v3.toml.d"),
        ("--runtime-cli-host-path", "/usr/local/bin/k3s"),
        ("--runtime-cli-arg", "ctr"),
        ("--runtime-cli-arg", "oci"),
        ("--runtime-cli-arg", "spec"),
        ("--runtime-service", "k3s"),
        ("--socket", "/run/mithril/mithril-pid-test.sock"),
        ("--timeout-ms", "4000"),
        ("--runtime-timeout-seconds", "5"),
        (
            "--log-filter",
            "info,mithril_node::node=debug,mithril_node::policy=debug",
        ),
        ("--decommission-state-directory", "/var/lib/mithril"),
        ("--control-read-only-mount", "/etc/mithril"),
        ("--control-read-write-mount", "/var/lib/mithril-control"),
        ("--control-read-only-mount", "/etc/mithril/admission-tls"),
        (
            "--node-read-only-mount",
            "/qualification/node.json=/etc/mithril/node.json",
        ),
        (
            "--node-read-only-mount",
            "/qualification/identity=/etc/mithril/identity",
        ),
        ("--node-read-only-mount", "/sys/kernel/btf=/sys/kernel/btf"),
        (
            "--node-read-only-mount",
            "/sys/kernel/tracing=/sys/kernel/tracing",
        ),
        ("--node-read-only-mount", "/sys/fs/cgroup=/sys/fs/cgroup"),
        (
            "--node-read-only-mount",
            "/run/k3s/containerd=/run/k3s/containerd",
        ),
        ("--node-read-write-mount", "/sys/fs/bpf=/sys/fs/bpf"),
        (
            "--node-read-write-mount",
            "/qualification/node=/var/lib/mithril",
        ),
        ("--node-read-write-mount", "/run/mithril=/run/mithril"),
        (
            "--node-read-write-mount",
            "/run/erebor-interceptor=/run/erebor-interceptor",
        ),
        (
            "--node-read-write-mount",
            "/usr/libexec/oci/hooks.d=/host-hook-bin",
        ),
        (
            "--node-read-write-mount",
            "/var/lib/rancher/k3s/agent/etc/containerd=/host-containerd",
        ),
    ];
    let chart_args = chart_pairs
        .iter()
        .flat_map(|(option, value)| [(*option).to_owned(), (*value).to_owned()])
        .collect::<Vec<_>>();
    let fixture = |args: &[String]| {
        serde_json::from_value::<DaemonSet>(json!({
            "spec": {"selector": {}, "template": {"spec": {
                "containers": [], "initContainers": [{
                    "name": "install-runtime-gate",
                    "command": ["/usr/local/bin/mithril-oci-hook", "install"],
                    "args": args,
                }]
            }}}
        }))
    };
    let backend_mounts = [
        RuntimeRecoveryMountInputV1 {
            source: "/qualification-input/runtime".into(),
            destination: "/qualification/runtime".into(),
            read_only: true,
        },
        RuntimeRecoveryMountInputV1 {
            source: "/qualification-input/runtime/bpftrace".into(),
            destination: "/usr/bin/bpftrace".into(),
            read_only: true,
        },
    ];
    let libraries = (0..19)
        .map(|index| RuntimeRecoveryMountInputV1 {
            source: format!("/qualification-input/runtime/lib/libtest-{index}.so.1").into(),
            destination: format!("/usr/lib/x86_64-linux-gnu/libtest-{index}.so.1").into(),
            read_only: true,
        })
        .collect::<Vec<_>>();
    let initial = Kubernetes::capture_installer(&fixture(&chart_args)?, &backend_mounts)?;
    let full = Kubernetes::capture_installer(&fixture(&initial)?, &libraries[..18])?;
    assert_eq!(full.len() + 2, 64);
    assert_eq!(
        full.iter()
            .filter(|arg| arg.starts_with("--node-read-only-mount=")
                || arg.starts_with("--node-read-write-mount="))
            .count(),
        32
    );
    assert_eq!(&full[..initial.len()], initial);
    assert_eq!(Kubernetes::capture_installer(&fixture(&full)?, &[])?, full);
    assert!(Kubernetes::capture_installer(&fixture(&initial)?, &libraries).is_err());
    let mut extra_arg = full.clone();
    extra_arg.push("--runtime-service=k3s".to_owned());
    assert!(Kubernetes::capture_installer(&fixture(&extra_arg)?, &[]).is_err());

    let base_args = [
        "--owner",
        "mithril-pid-test/mithril",
        "--hook-host-directory",
        "/usr/libexec/oci/hooks.d",
        "--containerd-host-directory",
        "/var/lib/rancher/k3s/agent/etc/containerd",
        "--containerd-drop-in-directory",
        "config-v3.toml.d",
        "--runtime-cli-host-path",
        "/usr/local/bin/k3s",
        "--runtime-cli-arg=ctr",
        "--runtime-cli-arg=oci",
        "--runtime-cli-arg=spec",
        "--runtime-service=k3s",
        "--socket",
        "/run/mithril/mithril-pid-test.sock",
        "--timeout-ms",
        "4000",
        "--runtime-timeout-seconds",
        "5",
        "--log-filter",
        "info,mithril_node::node=debug,mithril_node::policy=debug",
        "--decommission-state-directory",
        "/var/lib/mithril",
        "--control-read-only-mount",
        "/etc/mithril",
        "--control-read-write-mount",
        "/var/lib/mithril-control",
        "--control-read-only-mount",
        "/etc/mithril/admission-tls",
        "--node-read-only-mount=/qualification/node.json=/etc/mithril/node.json",
        "--node-read-only-mount=/qualification/identity=/etc/mithril/identity",
        "--node-read-only-mount=/sys/kernel/btf=/sys/kernel/btf",
        "--node-read-only-mount=/sys/kernel/tracing=/sys/kernel/tracing",
        "--node-read-only-mount=/sys/fs/cgroup=/sys/fs/cgroup",
        "--node-read-only-mount=/run/k3s/containerd=/run/k3s/containerd",
        "--node-read-write-mount=/sys/fs/bpf=/sys/fs/bpf",
        "--node-read-write-mount=/qualification/node=/var/lib/mithril",
        "--node-read-write-mount=/run/mithril=/run/mithril",
        "--node-read-write-mount=/run/erebor-interceptor=/run/erebor-interceptor",
        "--node-read-write-mount=/usr/libexec/oci/hooks.d=/host-hook-bin",
        "--node-read-write-mount=/var/lib/rancher/k3s/agent/etc/containerd=/host-containerd",
    ]
    .map(str::to_owned)
    .to_vec();
    let mut expected = base_args.clone();
    expected.extend([
        "--node-read-only-mount=/qualification-input/runtime=/qualification/runtime".to_owned(),
        "--node-read-only-mount=/qualification-input/runtime/bpftrace=/usr/bin/bpftrace".to_owned(),
    ]);
    assert_eq!(initial, expected);
    let mut repeated = chart_args.clone();
    repeated.extend(
        [
            "--runtime-cli-arg",
            "ctr",
            "--runtime-cli-arg=--address=/run/k3s/containerd/containerd.sock",
            "--runtime-service",
            "k3s",
            "--runtime-service=k3s",
        ]
        .map(str::to_owned),
    );
    let mut expected = base_args;
    expected.extend([
        "--runtime-cli-arg=ctr".to_owned(),
        "--runtime-cli-arg=--address=/run/k3s/containerd/containerd.sock".to_owned(),
        "--runtime-service=k3s".to_owned(),
        "--runtime-service=k3s".to_owned(),
    ]);
    assert_eq!(
        Kubernetes::capture_installer(&fixture(&repeated)?, &[])?,
        expected
    );

    for option in [
        "--node-read-only-mount",
        "--node-read-write-mount",
        "--runtime-cli-arg",
        "--runtime-service",
    ] {
        for value in [None, Some(""), Some("--socket"), Some("-x")] {
            let mut invalid = chart_args.clone();
            invalid.push(option.to_owned());
            invalid.extend(value.map(str::to_owned));
            assert!(
                Kubernetes::capture_installer(&fixture(&invalid)?, &[]).is_err(),
                "{option}: {value:?}"
            );
        }
    }
    let option = "--node-read-only-mount";
    let value = format!(
        "/bundle/{}=/runtime",
        "a".repeat(4096 - option.len() - 1 - "/bundle/=/runtime".len())
    );
    let mut bounded = chart_args;
    bounded.extend([option.to_owned(), value]);
    let compact = Kubernetes::capture_installer(&fixture(&bounded)?, &[])?;
    assert_eq!(
        compact.last().ok_or("the compact mount is absent")?.len(),
        4096
    );
    bounded
        .last_mut()
        .ok_or("the mount value is absent")?
        .push('a');
    assert!(Kubernetes::capture_installer(&fixture(&bounded)?, &[]).is_err());
    Ok(())
}

#[test]
fn observability_runtime_library_names() {
    for name in ["libstdc++.so.6", "libLLVM-18.so.1", "libbpf.so.1"] {
        assert!(Kubernetes::capture_library(name), "{name}");
    }
    for name in [
        "../libstdc++.so.6",
        "libstdc++.so.6/child",
        "libstdc++.so.6;command",
        "libstdc++.so.6\n",
        "libstdc++.so.6 ",
        "$(command).so",
        "bpftrace",
        "libc.so.6",
        "libm.so.6",
        "libgcc_s.so.1",
        "ld-linux-x86-64.so.2",
    ] {
        assert!(!Kubernetes::capture_library(name), "{name}");
    }
}

#[tokio::test]
#[ignore = "requires the qualification Control container and its task-owned inputs"]
async fn observability_pod_child() -> TestResult<()> {
    erebor_telemetry::init_test_logging();
    PodCapture::run_child().await
}

#[test]
#[ignore = "requires an isolated Kubernetes host, reviewed backend, and explicit diagnostic admission"]
fn observability_pod_replacement() -> TestResult<()> {
    super::test_lifecycle::<Kubernetes, _>("observability-pods", Kubernetes::qualify_pods)
}
