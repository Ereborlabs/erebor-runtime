use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::TaskCoordinateV1;
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
    WorkloadProtectionPolicy, KUBERNETES_LABEL_EPOCH_ANNOTATION, KUBERNETES_NODE_BOOT_ANNOTATION,
    KUBERNETES_NODE_ID_ANNOTATION, KUBERNETES_NODE_UID_ANNOTATION, KUBERNETES_NOT_READY_TAINT,
    KUBERNETES_PROFILE_ANNOTATION, KUBERNETES_READY_LABEL, KUBERNETES_SOURCE_ANNOTATION,
};
use mithril_node::{
    NativeIdentityInspector, NodeConfig, RuntimeIntegrationDecommissionV1, RuntimeIntegrationOwner,
};
use serde_json::{json, Value};
use snafu::ResultExt as _;
use zerocopy::TryFromBytes as _;

use super::{Platform, Task, TestResult};
use crate::control_fixture::MtlsFixture;
use crate::error::{InvalidInputSnafu, NodeSnafu};
use crate::physical::{wait_for, wait_for_async, ProbeDirectory, ProbeFile};
use crate::process::ProcessFixture;

const READY_LIMIT: Duration = Duration::from_secs(180);
const STOP_LIMIT: Duration = Duration::from_secs(120);
const SELECTOR: &str = "mithril.erebor.dev/pid-reuse";
const ACTOR: &str = "pid-reuse";
const CONTAINER: &str = "worker";

pub(crate) struct Kubernetes {
    root: PathBuf,
    out: PathBuf,
    work_path: PathBuf,
    state_path: PathBuf,
    identity_path: PathBuf,
    config_path: PathBuf,
    control_path: PathBuf,
    values_path: PathBuf,
    pin_path: PathBuf,
    lease_path: PathBuf,
    socket_path: PathBuf,
    kube_path: PathBuf,
    helm_path: PathBuf,
    k3s_path: PathBuf,
    node_image: String,
    control_image: String,
    actor_image: String,
    actor_python: String,
    system: String,
    namespace: String,
    token: String,
    node_name: String,
    client: Client,
    runtime: tokio::runtime::Runtime,
    tls: MtlsFixture,
    inspector: NativeIdentityInspector,
    reader: KernelStateReader,
    work: Option<ProbeDirectory>,
    state: Option<ProbeDirectory>,
    identity: Option<ProbeDirectory>,
    config: Option<ProbeFile>,
    control_file: Option<ProbeFile>,
    values: Option<ProbeFile>,
    pin: Option<ProbeDirectory>,
    lease: Option<ProbeFile>,
    socket: Option<ProbeFile>,
    system_up: bool,
    work_up: bool,
    helm_up: bool,
    hook_up: bool,
    actor_id: Option<String>,
    actor_pid: Option<u32>,
    actor_cgroup: Option<PathBuf>,
}

impl Kubernetes {
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
        Ok(self.runtime.block_on(pods.get(ACTOR))?)
    }

    fn container_id(&self) -> TestResult<String> {
        self.pod()?
            .status
            .and_then(|status| status.container_statuses)
            .and_then(|statuses| statuses.into_iter().find(|status| status.name == CONTAINER))
            .and_then(|status| status.container_id)
            .and_then(|id| id.strip_prefix("containerd://").map(str::to_owned))
            .ok_or_else(|| "the Kubernetes actor has no containerd ID".into())
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
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.system, "daemonset", "mithril-node");
        Ok(wait_for(
            &path,
            "Node DaemonSet readiness",
            READY_LIMIT,
            || match self.runtime.block_on(sets.get("mithril-node")) {
                Ok(set) => {
                    *last.borrow_mut() = format!("{:?}", set.status);
                    let ready = set.status.is_some_and(|status| {
                        status.desired_number_scheduled == 1
                            && status.number_ready == 1
                            && status.number_unavailable.unwrap_or_default() == 0
                    });
                    Ok(ready.then_some(()))
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
        Ok(wait_for(
            &path,
            "authenticated Node readiness",
            READY_LIMIT,
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
                            == Some("node-a")
                        && notes.get(KUBERNETES_NODE_UID_ANNOTATION) == node.metadata.uid.as_ref()
                        && boot
                        && epoch
                        && !tainted;
                    Ok(ready.then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || format!("last Node state: {}", last.borrow()),
        )?)
    }

    fn ca_bundle(&self) -> TestResult<String> {
        let mut command = Command::new("/usr/bin/base64");
        command.args(["-w", "0"]).arg(&self.tls.files.ca);
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
        ] {
            Self::set(&mut control, path, value)?;
        }
        fs::write(&self.control_path, serde_json::to_vec_pretty(&control)?)?;
        ControlConfig::load(&self.control_path)?;

        let node_selector = BTreeMap::from([(SELECTOR.to_owned(), self.token.clone())]);
        let control_selector =
            BTreeMap::from([("kubernetes.io/hostname".to_owned(), self.node_name.clone())]);
        let values = json!({
            "node": {
                "image": self.node_image,
                "configHostPath": self.config_path,
                "identityHostPath": self.identity_path,
                "stateHostPath": self.state_path,
                "nodeSelector": node_selector,
                "runtimeHook": {
                    "socketPath": self.socket_path,
                },
            },
            "control": {
                "image": self.control_image,
                "nodeSelector": control_selector,
                "admission": {
                    "caBundle": self.ca_bundle()?,
                },
            },
        });
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
        let data = BTreeMap::from([
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

    fn wait_policy(&self, active: u32) -> TestResult<()> {
        let policies =
            Api::<WorkloadProtectionPolicy>::namespaced(self.client.clone(), &self.namespace);
        let last = RefCell::new(String::from("<absent>"));
        let path = Self::resource(&self.namespace, "workloadprotectionpolicy", "pid-reuse");
        Ok(wait_for(
            &path,
            "PID-reuse policy readiness",
            READY_LIMIT,
            || match self.runtime.block_on(policies.get("pid-reuse")) {
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

    fn close(&mut self) -> TestResult<()> {
        let mut failed = None;
        if self.work_up {
            Self::retain(&mut failed, self.delete_ns(&self.namespace));
            self.work_up = false;
        }
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
            let nodes = Api::<Node>::all(self.client.clone());
            let patch = json!({"metadata": {"labels": {(SELECTOR): null}}});
            Self::retain(
                &mut failed,
                self.runtime
                    .block_on(nodes.patch(
                        &self.node_name,
                        &PatchParams::default(),
                        &Patch::Merge(&patch),
                    ))
                    .map(|_| ())
                    .map_err(Into::into),
            );
            Self::retain(&mut failed, self.delete_ns(&self.system));
            self.system_up = false;
        }
        if self.hook_up {
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
            self.hook_up = false;
        }
        if let Some(work) = self.work.take() {
            Self::retain(&mut failed, work.cleanup().map_err(Into::into));
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
        match failed {
            Some(source) => Err(source),
            None => Ok(()),
        }
    }
}

impl Platform for Kubernetes {
    fn setup(_name: &str) -> TestResult<Self> {
        erebor_telemetry::init_test_logging();
        let root = fs::canonicalize(Self::path("MITHRIL_TEST_ROOT", ".")?)?;
        let out = Self::path("MITHRIL_TEST_OUTPUT", "")?;
        if out.as_os_str().is_empty() || !out.is_absolute() || out.exists() {
            return Err(format!(
                "MITHRIL_TEST_OUTPUT must name a fresh absolute path: {}",
                out.display()
            )
            .into());
        }
        fs::create_dir_all(&out)?;
        let work_path = out.join("actor");
        let state_path = out.join("node");
        let identity_path = out.join("identity");
        let work = ProbeDirectory::create(&work_path)?;
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
        let namespace = format!("mithril-work-{token}");
        let pin_path = PathBuf::from(format!("/sys/fs/bpf/mithril-pid-{token}"));
        let lease_path = PathBuf::from(format!("/run/erebor-interceptor/mithril-pid-{token}.lock"));
        let socket_path = PathBuf::from(format!("/run/mithril/mithril-pid-{token}.sock"));
        for path in [&pin_path, &lease_path, &socket_path] {
            if path.exists() {
                return Err(
                    format!("the Kubernetes fixture path exists: {}", path.display()).into(),
                );
            }
        }
        let pin = ProbeDirectory::new(&pin_path);
        let lease = ProbeFile::new(&lease_path);
        let socket = ProbeFile::new(&socket_path);
        let kube_path = Self::path("MITHRIL_TEST_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")?;
        let helm_path = Self::path("MITHRIL_TEST_HELM", "/usr/local/bin/helm")?;
        let k3s_path = Self::path("MITHRIL_TEST_K3S", "/usr/local/bin/k3s")?;
        for path in [&kube_path, &helm_path, &k3s_path] {
            if !path.is_file() {
                return Err(format!(
                    "the Kubernetes fixture input is missing: {}",
                    path.display()
                )
                .into());
            }
        }
        let node_image = Self::required("MITHRIL_TEST_NODE_IMAGE")?;
        let control_image = Self::required("MITHRIL_TEST_CONTROL_IMAGE")?;
        let actor_image = Self::required("MITHRIL_TEST_ACTOR_IMAGE")?;
        let actor_python = env::var("MITHRIL_TEST_ACTOR_PYTHON")
            .unwrap_or_else(|_| "/usr/local/bin/python3".to_owned());
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
        let server_name = format!("mithril-control.{system}.svc");
        let tls = MtlsFixture::kubernetes(&server_name)?;
        let inspector = NativeIdentityInspector::new(&pin_path);
        let reader = KernelStateReader::new(&pin_path);
        let fixture = Self {
            root,
            out,
            work_path,
            state_path,
            identity_path,
            config_path,
            control_path,
            values_path,
            pin_path,
            lease_path,
            socket_path,
            kube_path,
            helm_path,
            k3s_path,
            node_image,
            control_image,
            actor_image,
            actor_python,
            system,
            namespace,
            token,
            node_name,
            client,
            runtime,
            tls,
            inspector,
            reader,
            work: Some(work),
            state: Some(state),
            identity: Some(identity),
            config: Some(config),
            control_file: Some(control_file),
            values: Some(values),
            pin: Some(pin),
            lease: Some(lease),
            socket: Some(socket),
            system_up: false,
            work_up: false,
            helm_up: false,
            hook_up: false,
            actor_id: None,
            actor_pid: None,
            actor_cgroup: None,
        };
        fixture.write_inputs()?;
        Ok(fixture)
    }

    fn start_control(&mut self) -> TestResult<()> {
        self.create_system()?;
        let chart = self.root.join("packaging/mithril/helm");
        let base = self.fixture("pid-reuse-values-v1.yaml");
        let mut command = Command::new(&self.helm_path);
        command
            .args(["--kubeconfig"])
            .arg(&self.kube_path)
            .args(["upgrade", "--install", "mithril"])
            .arg(&chart)
            .args(["--namespace", &self.system, "--values"])
            .arg(base)
            .arg("--values")
            .arg(&self.values_path);
        Self::run(&mut command, "install Mithril Control")?;
        self.helm_up = true;
        self.wait_control()
    }

    fn start_node(&mut self) -> TestResult<()> {
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

    fn install_policy(&mut self) -> TestResult<()> {
        self.ready_node()?;
        let namespaces = Api::<Namespace>::all(self.client.clone());
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(self.namespace.clone()),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        };
        self.runtime
            .block_on(namespaces.create(&PostParams::default(), &namespace))?;
        self.work_up = true;

        let accounts = Api::<ServiceAccount>::namespaced(self.client.clone(), &self.namespace);
        let account = Self::resource(&self.namespace, "serviceaccount", "default");
        wait_for(
            &account,
            "default ServiceAccount readiness",
            READY_LIMIT,
            || {
                let present = self
                    .runtime
                    .block_on(accounts.get_opt("default"))
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: &self.values_path,
                            reason: source.to_string(),
                        }
                        .build()
                    })?
                    .is_some()
                    .then_some(());
                Ok(present)
            },
            || "the default ServiceAccount is absent".to_owned(),
        )?;

        let path = self
            .root
            .join("crates/mithril-e2e/fixtures/mithril-policy/pid-reuse-policy-v1.json");
        let mut policy: WorkloadProtectionPolicy = serde_json::from_slice(&fs::read(&path)?)?;
        policy.metadata = ObjectMeta {
            name: Some("pid-reuse".to_owned()),
            namespace: Some(self.namespace.clone()),
            ..ObjectMeta::default()
        };
        let container = policy
            .spec
            .containers
            .first_mut()
            .ok_or("the PID-reuse policy has no container")?;
        container.images = vec![self.actor_image.clone()];
        let role = policy
            .spec
            .roles
            .iter_mut()
            .find(|role| role.name == "worker")
            .ok_or("the PID-reuse policy has no worker role")?;
        let execution = role
            .execution
            .iter_mut()
            .find(|rule| rule.name == "python")
            .ok_or("the PID-reuse policy has no Python rule")?;
        execution.path.clone_from(&self.actor_python);
        let policies =
            Api::<WorkloadProtectionPolicy>::namespaced(self.client.clone(), &self.namespace);
        self.runtime
            .block_on(policies.create(&PostParams::default(), &policy))?;
        self.wait_policy(0)
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.ready_node()
    }

    fn start_actor(&mut self, name: &str, extra: &[&str]) -> TestResult<ProcessFixture> {
        if self.actor_id.is_some() {
            return Err("the Kubernetes actor is already running".into());
        }
        let script = ProcessFixture::script(&self.root, name)?;
        let fixtures = script
            .parent()
            .ok_or("the actor fixture has no parent directory")?;
        let mut args = vec![format!("/fixtures/{name}"), "/work".to_owned()];
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        let mut pod: Pod =
            serde_saphyr::from_slice(&fs::read(self.fixture("pid-reuse-pod-v1.yaml"))?)?;
        pod.metadata.namespace = Some(self.namespace.clone());
        let spec = pod.spec.as_mut().ok_or("the actor Pod has no spec")?;
        spec.node_selector = Some(BTreeMap::from([(
            "kubernetes.io/hostname".to_owned(),
            self.node_name.clone(),
        )]));
        let container = spec
            .containers
            .iter_mut()
            .find(|container| container.name == CONTAINER)
            .ok_or("the actor Pod has no worker container")?;
        container.image = Some(self.actor_image.clone());
        container.command = Some(vec![self.actor_python.clone()]);
        container.args = Some(args);
        let volumes = spec
            .volumes
            .as_mut()
            .ok_or("the actor Pod has no volumes")?;
        for (name, path) in [("fixtures", fixtures), ("work", self.work_path.as_path())] {
            let source = volumes
                .iter_mut()
                .find(|volume| volume.name == name)
                .and_then(|volume| volume.host_path.as_mut())
                .ok_or_else(|| format!("the actor Pod has no {name} hostPath"))?;
            source.path = path.display().to_string();
        }
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.namespace);
        self.runtime
            .block_on(pods.create(&PostParams::default(), &pod))?;

        let last = RefCell::new(String::from("<absent>"));
        wait_for(
            &script,
            "Kubernetes PID-reuse actor readiness",
            READY_LIMIT,
            || match self.logs(&self.namespace, &format!("pod/{ACTOR}")) {
                Ok(logs) => {
                    *last.borrow_mut() = logs.clone();
                    Ok(logs
                        .lines()
                        .any(|line| line == "native-fixture-ready")
                        .then_some(()))
                }
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || {
                let pod = self
                    .pod()
                    .map(|pod| format!("{:?}", pod.status))
                    .unwrap_or_else(|source| source.to_string());
                format!("last Pod state: {pod}; last logs: {:?}", last.borrow())
            },
        )?;
        let id = self.container_id()?;
        let pid = self.inspect_pid(&id)?;
        let cgroup = Self::cgroup(pid)?;

        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .args(["--kubeconfig"])
            .arg(&self.kube_path)
            .args([
                "-n",
                &self.namespace,
                "attach",
                "-i",
                ACTOR,
                "-c",
                CONTAINER,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn()?;
        let mut actor = ProcessFixture::new(child, &script);
        actor.set_init(pid)?;
        actor.ensure_running("Kubernetes actor attach")?;
        self.actor_id = Some(id);
        self.actor_pid = Some(pid);
        self.actor_cgroup = Some(cgroup);
        Ok(actor)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        let expected = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Kubernetes actor has no recorded cgroup")?;
        let actual = Self::cgroup(pid)?;
        if self.actor_pid != Some(pid) || &actual != expected {
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
        let mut command = Command::new(&self.k3s_path);
        command.args(["crictl", "inspect", expected]);
        let output = Self::run(&mut command, "read the staged CRI actor")?;
        let inspect: Value = serde_json::from_str(&output)?;
        if inspect.pointer("/status/state").and_then(Value::as_str) != Some("CONTAINER_RUNNING") {
            return Err(format!("the staged CRI actor is not running: {inspect}").into());
        }
        Ok(())
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

    fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        let snapshot = self.runtime.block_on(wait_for_async(
            &self.pin_path,
            name,
            READY_LIMIT,
            || self.inspector.snapshot(pid).context(NodeSnafu),
            || format!("PID {pid} has no published identity"),
        ))?;
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

    fn work(&self) -> &Path {
        &self.work_path
    }

    fn output(&self) -> &Path {
        &self.out
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
