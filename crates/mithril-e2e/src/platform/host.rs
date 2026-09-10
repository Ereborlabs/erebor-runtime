use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{
    CreatedByEdgeV1, IdentityRuntimeConfigV1, ReferenceTombstoneStateV1, TaskCoordinateStateV1,
    TaskCoordinateV1, TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use k8s_cri::v1::ContainerState;
use mithril_control::{
    lower_kubernetes_policy, workload_target_fact_digest, AllowedNodeIdentity,
    ContainerKindV1 as ControlContainerKind, ControlPlane, ControlStore,
    KubernetesWorkloadIdentityV1, PolicyDesiredStateConfigV1, PolicyDesiredStateOwner,
    PolicySignerConfigV1, PolicySignerTrustV1, PolicySourceRevisionV1, PolicySourceStateV1,
    TrustGenerationV1, WorkloadProtectionPolicy, WorkloadTargetFactV1,
};
use mithril_node::{
    AdministrativeAuthorizationConfig, ContainerKindV1, ContainerRuntimeConfig, EvidenceConfig,
    EvidenceWalCapacityPolicyV1, InterceptorConfig, NativeIdentityInspector, NodeChassis,
    NodeConfig, NodeReadinessV1, RuntimeAdmissionClient, RuntimeAdmissionConfig,
    RuntimeAdmissionOperationV1, RuntimeAdmissionRequestV1, ScheduledRuntimeBindingV1,
    WorkloadBindingConfig, CONTAINER_NAME_ANNOTATION, IMAGE_NAME_ANNOTATION,
    POD_NAMESPACE_ANNOTATION, POD_UID_ANNOTATION, POLICY_SOURCE_REVISION_ANNOTATION,
    PROFILE_ID_ANNOTATION, SANDBOX_ID_ANNOTATION,
};
use snafu::{ensure, ResultExt as _};
use tokio::sync::watch;
use zerocopy::TryFromBytes as _;

use super::{CriFixture, Platform, Task, TestResult, Thread};
use crate::control_fixture::{ControlServerFixture, MtlsFixture};
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu};
use crate::physical::{wait_for, wait_for_async, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::process::ProcessFixture;
use crate::runtime_input::runtime_observation;

const READY_LIMIT: Duration = Duration::from_secs(30);
const TENANT_ID: &str = "00000000-0000-0001-0000-000000000002";
const CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const POD_UID: &str = "99999999-9999-4999-8999-999999999999";
const NODE_UID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

pub(crate) struct Host {
    root: PathBuf,
    out: PathBuf,
    work_path: PathBuf,
    state_path: PathBuf,
    cgroup_path: PathBuf,
    node_path: PathBuf,
    pin_path: PathBuf,
    lease_path: PathBuf,
    cri_path: PathBuf,
    admit_path: PathBuf,
    work: Option<ProbeDirectory>,
    state: Option<ProbeDirectory>,
    cgroup: Option<ProbeCgroup>,
    node_cgroup: Option<ProbeCgroup>,
    pin: Option<ProbeDirectory>,
    lease: Option<ProbeFile>,
    tls: MtlsFixture,
    control: Option<ControlServerFixture>,
    plane: Option<ControlPlane>,
    policy: Option<PolicyDesiredStateOwner>,
    binding: Option<WorkloadBindingConfig>,
    revision: Option<String>,
    cri: Option<CriFixture>,
    node_stop: Option<watch::Sender<bool>>,
    node_task: Option<thread::JoinHandle<mithril_node::Result<()>>>,
    ready: Option<watch::Receiver<NodeReadinessV1>>,
    init_pid: Option<u32>,
    inspector: NativeIdentityInspector,
    reader: KernelStateReader,
    runtime: tokio::runtime::Runtime,
}

impl Host {
    fn path(name: &'static str) -> TestResult<PathBuf> {
        env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} is not set").into())
    }

    fn binding(&self) -> TestResult<&WorkloadBindingConfig> {
        self.binding
            .as_ref()
            .ok_or_else(|| "the policy is not installed".into())
    }

    fn coordinate(&self, task: u64) -> crate::Result<Option<TaskCoordinateV1>> {
        let Some(bytes) = self
            .reader
            .lookup("task_coordinates", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        TaskCoordinateV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: &self.pin_path,
                    reason: format!("task coordinate is invalid: {source}"),
                }
                .build()
            })
    }

    fn edge(&self, task: u64) -> crate::Result<Option<CreatedByEdgeV1>> {
        let Some(bytes) = self
            .reader
            .lookup("created_by_edges", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        CreatedByEdgeV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: &self.pin_path,
                    reason: format!("creator edge is invalid: {source}"),
                }
                .build()
            })
    }

    fn tombstone(&self, task: u64) -> crate::Result<Option<TaskReferenceTombstoneV1>> {
        let Some(bytes) = self
            .reader
            .lookup("task_reference_tombstones", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        TaskReferenceTombstoneV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: &self.pin_path,
                    reason: format!("task tombstone is invalid: {source}"),
                }
                .build()
            })
    }

    pub(super) fn source(&self) -> &Path {
        &self.root
    }

    pub(super) fn cgroup(&self) -> &Path {
        &self.cgroup_path
    }

    fn request(
        &self,
        operation: RuntimeAdmissionOperationV1,
        pid: Option<u32>,
    ) -> TestResult<RuntimeAdmissionRequestV1> {
        let binding = self.binding()?;
        let revision = self
            .revision
            .as_ref()
            .ok_or("the policy revision is not installed")?;
        Ok(RuntimeAdmissionRequestV1 {
            operation,
            container_id: binding.container_id.clone(),
            initial_pid: pid,
            cgroup_path: (operation == RuntimeAdmissionOperationV1::StageRuntimeFacts)
                .then(|| self.cgroup_path.clone()),
            oci_bundle: None,
            oci_root_fd: None,
            annotations: BTreeMap::from([
                (
                    POD_NAMESPACE_ANNOTATION.to_owned(),
                    binding.namespace.clone(),
                ),
                (POD_UID_ANNOTATION.to_owned(), binding.pod_uid.clone()),
                (
                    CONTAINER_NAME_ANNOTATION.to_owned(),
                    binding.container_name.clone(),
                ),
                (
                    IMAGE_NAME_ANNOTATION.to_owned(),
                    format!("fixture@{}", binding.image_digest),
                ),
                (SANDBOX_ID_ANNOTATION.to_owned(), binding.sandbox_id.clone()),
                (PROFILE_ID_ANNOTATION.to_owned(), binding.profile_id.clone()),
                (
                    POLICY_SOURCE_REVISION_ANNOTATION.to_owned(),
                    revision.clone(),
                ),
            ]),
        })
    }

    fn close(&mut self) -> TestResult<()> {
        if let Some(stop) = self.node_stop.take() {
            stop.send_replace(true);
        }
        if let Some(task) = self.node_task.as_ref() {
            wait_for(
                &self.pin_path,
                "Node shutdown",
                READY_LIMIT,
                || Ok(task.is_finished().then_some(())),
                || "the Node thread is still running".to_owned(),
            )?;
        }
        if let Some(task) = self.node_task.take() {
            task.join()
                .map_err(|_panic| "Node thread panicked")?
                .context(NodeSnafu)?;
        }
        self.ready.take();
        if let Some(control) = self.control.take() {
            self.runtime.block_on(control.shutdown())?;
        }
        if let Some(mut cri) = self.cri.take() {
            cri.stop()?;
        }
        self.plane.take();
        self.policy.take();
        self.binding.take();
        self.revision.take();
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.cleanup()?;
        }
        if let Some(cgroup) = self.node_cgroup.take() {
            cgroup.cleanup()?;
        }
        if let Some(work) = self.work.take() {
            work.cleanup()?;
        }
        if let Some(state) = self.state.take() {
            state.cleanup()?;
        }
        if let Some(pin) = self.pin.take() {
            pin.cleanup()?;
        }
        if let Some(lease) = self.lease.take() {
            lease.cleanup()?;
        }
        Ok(())
    }
}

impl Platform for Host {
    fn setup(_name: &str) -> TestResult<Self> {
        erebor_telemetry::init_test_logging();
        let root = Self::path("MITHRIL_TEST_ROOT")?;
        let out = Self::path("MITHRIL_TEST_OUTPUT")?;
        let pin_path = Self::path("MITHRIL_TEST_PIN")?;
        let lease_path = Self::path("MITHRIL_TEST_LEASE")?;
        let cgroup_path = Self::path("MITHRIL_TEST_CGROUP")?;
        let node_name = format!(
            "{}-node",
            cgroup_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("the test cgroup has no file name")?
        );
        let node_path = cgroup_path.with_file_name(node_name);
        let cri_path = out.join("cri.sock");
        let admit_path = out.join("admission.sock");
        ensure!(
            !out.exists() || out.is_dir(),
            InvalidInputSnafu {
                path: &out,
                reason: "the scenario output path is not a directory",
            }
        );
        fs::create_dir_all(&out).context(IoSnafu { path: &out })?;
        let work_path = out.join("actor");
        let state_path = out.join("node");
        let work = ProbeDirectory::create(&work_path)?;
        let state = ProbeDirectory::create(&state_path)?;
        let cgroup = ProbeCgroup::create(&cgroup_path)?;
        let mut node_cgroup = ProbeCgroup::create(&node_path)?;
        node_cgroup.enter()?;
        let inspector = NativeIdentityInspector::new(&pin_path);
        let reader = KernelStateReader::new(&pin_path);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            root,
            out,
            work_path,
            state_path,
            cgroup_path,
            node_path,
            pin_path: pin_path.clone(),
            lease_path: lease_path.clone(),
            cri_path,
            admit_path,
            work: Some(work),
            state: Some(state),
            cgroup: Some(cgroup),
            node_cgroup: Some(node_cgroup),
            pin: Some(ProbeDirectory::new(&pin_path)),
            lease: Some(ProbeFile::new(&lease_path)),
            tls: MtlsFixture::new(false)?,
            control: None,
            plane: None,
            policy: None,
            binding: None,
            revision: None,
            cri: None,
            node_stop: None,
            node_task: None,
            ready: None,
            init_pid: None,
            inspector,
            reader,
            runtime,
        })
    }

    fn start_control(&mut self) -> TestResult<()> {
        let root = self.root.join("crates/mithril-e2e/fixtures/mithril-policy");
        let store = ControlStore::open(self.tls.path().join("control-store"))?;
        let policy = PolicyDesiredStateOwner::open(
            PolicyDesiredStateConfigV1 {
                tenant_id: TENANT_ID.to_owned(),
                cluster_uid: CLUSTER_UID.to_owned(),
                signer: PolicySignerConfigV1 {
                    signing_key_id: "effect-observation-test-key".to_owned(),
                    signing_key_path: root.join("test-signing-key.hex"),
                    seal_request_path: root.join("observe-profile-seal-request.json"),
                    distribution_sequence_epoch: 1,
                    candidate_validity_ns: 900_000_000_000,
                },
            },
            store.clone(),
        )?;
        let public_key = fs::read_to_string(root.join("test-public-key.hex"))?;
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
        let control = ControlPlane::with_control_store(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: self.tls.node_digest(),
                tenant_id: TENANT_ID.to_owned(),
            }],
            trust,
            store,
        )?
        .with_policy_desired_state(policy.clone());
        self.control = Some(self.runtime.block_on(self.tls.start(control.clone()))?);
        self.plane = Some(control);
        self.policy = Some(policy);
        Ok(())
    }

    fn start_node(&mut self) -> TestResult<()> {
        let server = self.control.as_ref().ok_or("Control is not running")?;
        self.cri = Some(CriFixture::start(&self.cri_path)?);
        let config = NodeConfig {
            node_id: "node-a".to_owned(),
            kubernetes_node_name: Some("node-a".to_owned()),
            state_directory: self.state_path.clone(),
            interceptor: InterceptorConfig {
                runtime_btf_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
                lease_path: self.lease_path.clone(),
                pin_root: self.pin_path.clone(),
            },
            control: self.tls.node_config(server.address()),
            evidence: Some(EvidenceConfig {
                tenant_id: TENANT_ID.to_owned(),
                source_id: "66666666-6666-4666-8666-666666666666".to_owned(),
                maximum_record_bytes: 128 * 1_024,
                maximum_retained_bytes: 16 * 1_024 * 1_024,
                maximum_retained_records: 10_000,
                maximum_batch_records: 256,
                maximum_control_delay_ms: 30_000,
                maximum_reader_queue_records: 262_144,
                capacity_policy: EvidenceWalCapacityPolicyV1::Block,
            }),
            runtime_observation: None,
            runtime_admission: Some(RuntimeAdmissionConfig {
                socket_path: self.admit_path.clone(),
                trusted_start_hook_path: env::current_exe()?,
                maximum_request_bytes: 64 * 1_024,
                timeout_ms: 5_000,
            }),
            container_runtime: Some(ContainerRuntimeConfig {
                socket_path: self.cri_path.clone(),
                effect_controller_cgroup_path: self.node_path.clone(),
                reconciliation_interval_ms: 60_000,
            }),
            workload_bindings: Vec::new(),
            policy_candidates: Vec::new(),
            administrative_authorization: Some(AdministrativeAuthorizationConfig {
                tenant_id: TENANT_ID.to_owned(),
                cluster_uid: CLUSTER_UID.to_owned(),
                trust_domain_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                key_id: "effect-observation-test-key".to_owned(),
                public_key_path: self
                    .root
                    .join("crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex"),
                sequence_epoch: 1,
                valid_from_utc_ns: 1_767_225_600_000_000_000,
                valid_until_utc_ns: 1_893_456_000_000_000_000,
                maximum_clock_skew_ns: 300_000_000_000,
            }),
            decommission: None,
        };
        let (stop, receiver) = watch::channel(false);
        let (started, ready) = mpsc::sync_channel(1);
        let task = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| mithril_node::Error::Io {
                    path: PathBuf::from("Node fixture runtime"),
                    source,
                    location: snafu::Location::default(),
                })?;
            runtime.block_on(async move {
                match NodeChassis::start(config).await {
                    Ok(node) => {
                        let _result = started.send(Ok(node.readiness()));
                        node.run(receiver).await
                    }
                    Err(source) => {
                        let _result = started.send(Err(source.to_string()));
                        Err(source)
                    }
                }
            })
        });
        self.node_stop = Some(stop);
        self.node_task = Some(task);
        self.ready = Some(
            ready
                .recv_timeout(READY_LIMIT)
                .map_err(|source| format!("Node start did not report readiness: {source}"))?
                .map_err(std::io::Error::other)?,
        );
        Ok(())
    }

    fn install_policy(&mut self) -> TestResult<()> {
        let ready = self.ready.as_ref().ok_or("Node is not running")?;
        let task = self.node_task.as_ref().ok_or("Node is not running")?;
        let last = RefCell::new(String::from("<absent>"));
        wait_for(
            &self.pin_path,
            "Node Control connection",
            READY_LIMIT,
            || {
                let value = *ready.borrow();
                *last.borrow_mut() = format!("{value:?}");
                ensure!(
                    !task.is_finished(),
                    InvalidInputSnafu {
                        path: &self.pin_path,
                        reason: "Node exited before its Control connection",
                    }
                );
                Ok(value.control_ready.then_some(()))
            },
            || format!("last readiness: {}", last.borrow()),
        )?;

        let plane = self.plane.as_ref().ok_or("Control is not running")?;
        plane.bind_kubernetes_node_session("node-a", NODE_UID)?;
        let session = wait_for(
            &self.pin_path,
            "ready Kubernetes Node session",
            READY_LIMIT,
            || {
                Ok(plane
                    .ready_kubernetes_node_sessions(READY_LIMIT)
                    .into_iter()
                    .find(|session| session.node_id == "node-a"))
            },
            || "Control has no ready Kubernetes Node session".to_owned(),
        )?;

        let path = self
            .root
            .join("crates/mithril-e2e/fixtures/mithril-policy/pid-reuse-policy-v1.json");
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        let resource: WorkloadProtectionPolicy =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
        let document = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
        let source = PolicySourceRevisionV1::from_resource(
            &resource,
            &document,
            TENANT_ID,
            CLUSTER_UID,
            NAMESPACE_UID,
            PolicySourceStateV1::Accepted,
        )?;
        let profile_id = document.metadata.profile_id.clone();
        let scope_id = document.protected_universe.protected_scope_ids[0].clone();
        let selector_id = document.workload_selectors[0].workload_selector_id.clone();
        let authority = ScheduledRuntimeBindingV1::authority_binding_id(POD_UID, "worker");
        let mut target = WorkloadTargetFactV1 {
            node_id: session.node_id.clone(),
            workload_binding_generation_digest: String::new(),
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            cluster_uid: CLUSTER_UID.to_owned(),
            namespace_uid: NAMESPACE_UID.to_owned(),
            controller_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
            service_account_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
            pod_uid: POD_UID.to_owned(),
            container_id: format!("scheduled:{}", "a".repeat(64)),
            container_name: "worker".to_owned(),
            container_kind: ControlContainerKind::Application,
            image_digest: format!("sha256:{}", "b".repeat(64)),
            pod_labels: BTreeMap::from([(
                "app.kubernetes.io/name".to_owned(),
                "pid-reuse".to_owned(),
            )]),
            kubernetes: Some(KubernetesWorkloadIdentityV1 {
                namespace_name: "default".to_owned(),
                pod_name: "pid-reuse".to_owned(),
                profile_id: profile_id.clone(),
                policy_source_revision_id: source.policy_source_revision_id.clone(),
                binding_id: authority.clone(),
                protected_scope_id: scope_id.clone(),
                workload_selector_id: selector_id.clone(),
                kubernetes_node_name: session.kubernetes_node_name,
                kubernetes_node_uid: session.kubernetes_node_uid,
                node_boot_id: hex::encode(session.node_boot_id),
                label_epoch: session.label_epoch,
            }),
        };
        target.workload_binding_generation_digest = workload_target_fact_digest(&target)?;
        ensure!(
            plane.replace_kubernetes_workload_inventory(vec![target.clone()])?,
            InvalidInputSnafu {
                path: &path,
                reason: "Control did not accept the PID-reuse workload inventory",
            }
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64;
        let policy = self
            .policy
            .as_ref()
            .ok_or("Control policy is not running")?;
        let result = policy.reconcile(&resource, NAMESPACE_UID, &[target.clone()], now)?;
        ensure!(
            result.bundles.len() == 1,
            InvalidInputSnafu {
                path: &path,
                reason: "Control did not produce one PID-reuse policy bundle",
            }
        );

        let container_id = "a".repeat(64);
        self.revision = Some(source.policy_source_revision_id);
        self.binding = Some(WorkloadBindingConfig {
            binding_id: ScheduledRuntimeBindingV1::runtime_binding_id(&authority, &container_id),
            scheduled_binding_authority_id: Some(authority),
            scheduled_target_digest: Some(target.workload_binding_generation_digest),
            execution_set_id: target.execution_set_id,
            protected_scope_id: scope_id,
            workload_selector_id: selector_id,
            profile_id,
            container_id,
            namespace: "default".to_owned(),
            cluster_uid: CLUSTER_UID.to_owned(),
            namespace_uid: NAMESPACE_UID.to_owned(),
            controller_uid: target.controller_uid,
            service_account_uid: target.service_account_uid,
            pod_labels: target.pod_labels,
            pod_uid: POD_UID.to_owned(),
            sandbox_id: "d".repeat(64),
            container_name: "worker".to_owned(),
            image_digest: target.image_digest,
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: Some(self.cgroup_path.clone()),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: true,
        });
        Ok(())
    }

    fn node_ready(&mut self) -> TestResult<()> {
        let ready = self.ready.as_ref().ok_or("Node is not running")?;
        let task = self.node_task.as_ref().ok_or("Node is not running")?;
        let last = RefCell::new(String::from("<absent>"));
        wait_for(
            &self.pin_path,
            "Node readiness",
            READY_LIMIT,
            || {
                let value = *ready.borrow();
                *last.borrow_mut() = format!("{value:?}");
                ensure!(
                    !task.is_finished(),
                    InvalidInputSnafu {
                        path: &self.pin_path,
                        reason: "Node exited before readiness",
                    }
                );
                Ok((value.kernel_ready
                    && value.identity_ready
                    && value.control_ready
                    && value.admission_ready
                    && value.effect_prevention_claims_enabled)
                    .then_some(()))
            },
            || {
                let delivery = mithril_node::policy_delivery_status(&self.state_path)
                    .map_or_else(|error| error.to_string(), |status| format!("{status:?}"));
                format!(
                    "last readiness: {}; policy delivery: {delivery}",
                    last.borrow()
                )
            },
        )?;
        Ok(())
    }

    fn start_actor(&mut self, name: &str, extra: &[&str]) -> TestResult<ProcessFixture> {
        ensure!(
            self.init_pid.is_none(),
            InvalidInputSnafu {
                path: &self.work_path,
                reason: "the initial actor is already running",
            }
        );
        let mut args = vec![self.work_path.clone().into_os_string()];
        args.extend(extra.iter().map(OsString::from));
        let mut actor = ProcessFixture::pidns(&self.root, name, args)?;
        let pid = actor.wait_child(actor.id(), "PID namespace root")?;
        actor.set_init(pid)?;
        self.init_pid = Some(pid);
        Ok(actor)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        let path = self.cgroup_path.join("cgroup.procs");
        fs::write(&path, pid.to_string()).context(IoSnafu { path: &path })?;
        Ok(())
    }

    fn stage(&mut self) -> TestResult<()> {
        let value = runtime_observation(self.binding()?, 0, ContainerState::ContainerCreated)?;
        self.cri.as_ref().ok_or("CRI is not running")?.set(value)?;
        let client = RuntimeAdmissionClient::new(self.admit_path.clone(), READY_LIMIT)?;
        let request = self.request(RuntimeAdmissionOperationV1::StageRuntimeFacts, None)?;
        let response = self.runtime.block_on(client.submit(&request))?;
        ensure!(
            response.allowed && response.reason_code == "RUNTIME_FACTS_STAGING",
            InvalidInputSnafu {
                path: &self.admit_path,
                reason: format!("Node rejected runtime staging: {response:?}"),
            }
        );
        Ok(())
    }

    fn admit(&mut self, pid: u32) -> TestResult<()> {
        let client = RuntimeAdmissionClient::new(self.admit_path.clone(), READY_LIMIT)?;
        let request = self.request(RuntimeAdmissionOperationV1::PrepareContainer, Some(pid))?;
        let response = self.runtime.block_on(client.submit(&request))?;
        ensure!(
            response.allowed && response.reason_code == "ACTIVE_POLICY_AND_BINDING_VERIFIED",
            InvalidInputSnafu {
                path: &self.admit_path,
                reason: format!("Node rejected runtime preparation: {response:?}"),
            }
        );
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
            .lookup("task_coordinates", &snapshot.task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?
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

    fn next_id(&self) -> TestResult<u64> {
        let bytes = self
            .reader
            .lookup("identity_config", &0_u32.to_ne_bytes())
            .context(InterceptorSnafu)?
            .ok_or("identity runtime configuration is missing")?;
        Ok(IdentityRuntimeConfigV1::try_read_from_bytes(&bytes)
            .map_err(|source| format!("identity runtime configuration is invalid: {source}"))?
            .next_id)
    }

    fn thread(&mut self, pid: u32, ns_tid: u32, task: u64, name: &str) -> TestResult<Thread> {
        let last = RefCell::new(String::from("coordinate=<absent>; edge=<absent>"));
        Ok(wait_for(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let coordinate = self.coordinate(task)?;
                let edge = self.edge(task)?;
                *last.borrow_mut() = format!("coordinate={coordinate:?}; edge={edge:?}");
                Ok(coordinate.zip(edge).map(|(coordinate, edge)| Thread {
                    pid,
                    ns_tid,
                    coordinate,
                    edge,
                }))
            },
            || format!("task cookie {task}; last state: {}", last.borrow()),
        )?)
    }

    fn task_exit(&mut self, task: u64, name: &str) -> TestResult<TaskCoordinateV1> {
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let Some(value) = self.coordinate(task)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = format!("{value:?}");
                Ok((value.state == TaskCoordinateStateV1::Exited).then_some(value))
            },
            || format!("task cookie {task}; last coordinate: {}", last.borrow()),
        )?)
    }

    fn task_release(&mut self, task: u64, name: &str) -> TestResult<TaskReferenceTombstoneV1> {
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            &self.pin_path,
            name,
            READY_LIMIT,
            || {
                let Some(value) = self.tombstone(task)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = format!("{value:?}");
                Ok((value.task_free_observed == 1
                    && value.released_bits == TASK_REFERENCE_ALL_V1
                    && value.state == ReferenceTombstoneStateV1::Released)
                    .then_some(value))
            },
            || format!("task cookie {task}; last tombstone: {}", last.borrow()),
        )?)
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

impl Drop for Host {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
