use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{TaskCoordinateStateV1, TaskCoordinateV1};
use erebor_runtime_client::MithrilObservationClient;
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
    ControlConfig, KubernetesConditionStatusV1, PolicySignerTrustV1, TrustGenerationV1,
    WorkloadProtectionException, WorkloadProtectionExceptionStateV1, WorkloadProtectionPolicy,
    KUBERNETES_LABEL_EPOCH_ANNOTATION, KUBERNETES_NODE_BOOT_ANNOTATION,
    KUBERNETES_NODE_ID_ANNOTATION, KUBERNETES_NODE_UID_ANNOTATION, KUBERNETES_NOT_READY_TAINT,
    KUBERNETES_PROFILE_ANNOTATION, KUBERNETES_READY_LABEL, KUBERNETES_SOURCE_ANNOTATION,
};
use mithril_node::{
    NativeIdentityInspector, NativeTaskSnapshotV1, NodeConfig, RuntimeAdmissionClient,
    RuntimeIntegrationDecommissionV1, RuntimeIntegrationOwner,
};
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

const READY_LIMIT: Duration = Duration::from_secs(180);
const STOP_LIMIT: Duration = Duration::from_secs(120);
const SELECTOR: &str = "mithril.erebor.dev/pid-reuse";
const ACTOR: &str = "pid-reuse";
const CONTAINER: &str = "worker";
const NODE_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

mod actor;

pub(crate) struct Kubernetes {
    lifecycle: Option<LifecycleGuard<'static, KubernetesState>>,
}

pub(crate) struct KubernetesState {
    namespace: String,
    work_path: PathBuf,
    work: Option<ProbeDirectory>,
    directories: Vec<ProbeDirectory>,
    move_group: Option<ProbeCgroup>,
    groups: Vec<ProbeCgroup>,
    work_up: bool,
    post_sleep: Option<i64>,
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
    approval: KubernetesApproval,
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
    fn approve_entry(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.ready_node()?;
        self.approval.start_forward(&self.runtime, &self.system)?;
        self.approval.approve(
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
        let events = self.snapshot().map(|mut snapshot| {
            snapshot.recent_effects.reverse();
            snapshot.recent_effects.truncate(16);
            snapshot.recent_effects
        });
        format!("Pod: {pod:?}; logs: {logs:?}; Node logs: {node:?}; effects: {events:?}")
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
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .args(["--kubeconfig"])
            .arg(&self.kube_path)
            .args(["-n", namespace, "logs", target])
            .args(["--all-containers=true", "--tail=200"]);
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
        let client = MithrilObservationClient::new(self.observation_path.clone(), "/".to_owned());
        Ok(self.runtime.block_on(client.snapshot())?)
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
                        .fail()
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
                "/administrative_exec/oidc_issuer_url",
                Value::String(self.approval.issuer()),
            ),
            (
                "/administrative_exec/node_ids_by_kubernetes_name",
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
                Value::String(Self::ca_bundle(self.approval.ca())?),
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
        data.extend(self.approval.secrets()?);
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

    fn start_entry(&mut self, program: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        let group = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Kubernetes actor has no recorded cgroup")?;
        let mut command = if let Some(kube) = self.approval.kubeconfig() {
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
        let pid = actor.wait_group_task(group, &before, program, "Kubernetes exec host PID")?;
        if !self.hook_up {
            let input_path = PathBuf::from(format!("/proc/{pid}/fd/0"));
            let input = File::options()
                .write(true)
                .open(&input_path)
                .context(IoSnafu { path: &input_path })?;
            actor.set_input(input);
        }
        actor.set_actor(pid)?;
        self.approval.clear();
        Ok(actor)
    }

    fn reset(&mut self, name: &str) -> TestResult<()> {
        if self.work_up || self.work.is_some() || self.move_group.is_some() {
            return Err("the previous Kubernetes scenario is not clean".into());
        }
        self.namespace = format!("mithril-work-{name}-{}", self.token);
        self.work_path = self.work_path.with_file_name("actor");
        self.work = Some(ProbeDirectory::create(&self.work_path)?);
        self.actor_name = ACTOR.to_owned();
        self.create_work()
    }

    fn clean_test(&mut self) -> TestResult<()> {
        let mut failed = None;
        self.approval.clear();
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
        self.post_sleep = None;
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
        Self::retain(&mut failed, self.approval.stop());
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
            work: Some(ProbeDirectory::create(&work_path)?),
            work_path,
            directories: Vec::new(),
            move_group: None,
            groups: Vec::new(),
            work_up: false,
            post_sleep: None,
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
            approval,
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
        state.approval.start_oidc(&state.runtime)?;
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
        let active = if self.hook_up {
            self.actors.get(&labels).copied().unwrap_or(0)
        } else {
            0
        };
        self.wait_policy(active)?;
        Ok(labels)
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        self.wait_policy(self.actors.get(&self.labels).copied().unwrap_or(0))
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
        };
        let mut group =
            self.start_actor_group("pid-reuse-pod-v1.yaml", &[actor], labels, |_, _| Ok(()))?;
        Ok(group.remove(0).0)
    }

    fn start_actor_group<F>(
        &mut self,
        manifest: &str,
        actors: &[GroupActor<'_>],
        labels: &super::Labels,
        before_app: F,
    ) -> TestResult<Vec<(ProcessFixture, PathBuf)>>
    where
        F: FnOnce(&mut Self, &mut Vec<(ProcessFixture, PathBuf)>) -> TestResult<()>,
    {
        self.start_group(manifest, actors, labels, before_app)
    }
    fn add_actor(&mut self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        self.start_entry(command, args)
    }

    fn approve(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.approve_entry(command, args)
    }

    fn post_start_sleep(&mut self, delay: Duration) -> TestResult<()> {
        let seconds = i64::try_from(delay.as_secs())?;
        if seconds == 0 || delay.subsec_nanos() != 0 || seconds.checked_add(10).is_none() {
            return Err("the native post-start sleep must use positive whole seconds".into());
        }
        if self.actor_id.is_some() || self.post_sleep.replace(seconds).is_some() {
            return Err("the native post-start sleep is already configured or running".into());
        }
        Ok(())
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
