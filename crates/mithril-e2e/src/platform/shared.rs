use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{TaskCoordinateStateV1, TaskCoordinateV1};
use erebor_runtime_client::MithrilObservationClient;
use erebor_runtime_ipc::v1::{
    MithrilObservationSnapshot, RuntimeAdmissionDecision, RuntimeAdmissionEntriesRequest,
    RuntimeAdmissionPrepareRequest, RuntimeAdmissionStageRequest,
};
use k8s_cri::v1::ContainerState;
use mithril_control::{
    lower_kubernetes_policy, workload_target_fact_digest, AdministrativeApprovalConfigV1,
    AdministrativeApprovalOwner, AdministrativeExecRequestV1, AllowedNodeIdentity,
    ContainerKindV1 as ControlContainerKind, ControlPlane, ControlStore, KubernetesPolicyModeV1,
    KubernetesWorkloadIdentityV1, PolicyDesiredStateConfigV1, PolicyDesiredStateOwner,
    PolicySignerConfigV1, PolicySignerTrustV1, PolicySourceRevisionV1, PolicySourceStateV1,
    TrustGenerationV1, WorkloadProtectionException, WorkloadProtectionExceptionStateV1,
    WorkloadProtectionPolicy, WorkloadTargetFactV1,
};
use mithril_node::{
    AdministrativeAuthorizationConfig, ContainerKindV1, ContainerRuntimeConfig, EvidenceConfig,
    EvidenceWalCapacityPolicyV1, InterceptorConfig, NativeIdentityInspector, NativeTaskSnapshotV1,
    NodeChassis, NodeConfig, NodeReadinessV1, RuntimeAdmissionClient, RuntimeAdmissionConfig,
    RuntimeObservationConfig, ScheduledRuntimeBindingV1, WorkloadBindingConfig,
    CONTAINER_NAME_ANNOTATION, IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION, POD_UID_ANNOTATION,
    POLICY_SOURCE_REVISION_ANNOTATION, PROFILE_ID_ANNOTATION, SANDBOX_ID_ANNOTATION,
};
use snafu::{ensure, ResultExt as _};
use tokio::sync::watch;
use zerocopy::TryFromBytes as _;

use super::lifecycle::{enter, LifecycleGuard};
use super::{policy_path, CriFixture, Task, TestResult};
use crate::control_fixture::{ControlServerFixture, MtlsFixture};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{
    wait_for, wait_for_async, wait_stable, ProbeCgroup, ProbeDirectory, ProbeFile,
};
use crate::process::ProcessFixture;
use crate::runtime_input::runtime_observation;

const READY_LIMIT: Duration = Duration::from_secs(30);
const NODE_START_LIMIT: Duration = Duration::from_secs(60);
const TENANT_ID: &str = "00000000-0000-0001-0000-000000000002";
const CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const POD_UID: &str = "99999999-9999-4999-8999-999999999999";
const NODE_UID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NODE_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const POLICY_UID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

pub(super) struct SharedState {
    root: PathBuf,
    out: PathBuf,
    out_dir: Option<ProbeDirectory>,
    work_path: PathBuf,
    state_path: PathBuf,
    cgroup_path: PathBuf,
    node_path: PathBuf,
    pin_path: PathBuf,
    lease_path: PathBuf,
    cri_path: PathBuf,
    admit_path: PathBuf,
    observation_path: PathBuf,
    work: Option<ProbeDirectory>,
    state: Option<ProbeDirectory>,
    admit: Option<ProbeDirectory>,
    cgroup: Option<ProbeCgroup>,
    node_cgroup: Option<ProbeCgroup>,
    pin: Option<ProbeDirectory>,
    lease: Option<ProbeFile>,
    tls: MtlsFixture,
    control: Option<ControlServerFixture>,
    plane: Option<ControlPlane>,
    policy: Option<PolicyDesiredStateOwner>,
    policy_generation: i64,
    resource: Option<WorkloadProtectionPolicy>,
    policy_path: Option<PathBuf>,
    binding: Option<WorkloadBindingConfig>,
    target: Option<WorkloadTargetFactV1>,
    revision: Option<String>,
    cri: Option<CriFixture>,
    node_stop: Option<watch::Sender<bool>>,
    node_task: Option<thread::JoinHandle<mithril_node::Result<()>>>,
    ready: Option<watch::Receiver<NodeReadinessV1>>,
    inspector: NativeIdentityInspector,
    reader: KernelStateReader,
    runtime: tokio::runtime::Runtime,
    hook_path: PathBuf,
}

pub(super) struct Shared {
    lifecycle: Option<LifecycleGuard<'static, SharedState>>,
}

impl Deref for Shared {
    type Target = SharedState;

    fn deref(&self) -> &Self::Target {
        match self.lifecycle.as_ref().and_then(LifecycleGuard::get) {
            Some(state) => state,
            None => unreachable!("the shared lifecycle is closed"),
        }
    }
}

impl DerefMut for Shared {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.lifecycle.as_mut().and_then(LifecycleGuard::get_mut) {
            Some(state) => state,
            None => unreachable!("the shared lifecycle is closed"),
        }
    }
}

impl SharedState {
    fn path(name: &'static str) -> TestResult<PathBuf> {
        env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} is not set").into())
    }

    fn reset(&mut self) -> TestResult<()> {
        ensure!(
            self.work.is_none() && self.cgroup.is_none(),
            InvalidInputSnafu {
                path: &self.out,
                reason: "the previous scenario is not clean",
            }
        );
        let work = ProbeDirectory::create(&self.work_path)?;
        let bin = self.work_path.join("bin");
        fs::create_dir(&bin)?;
        fs::copy(fs::canonicalize("/usr/bin/python3")?, bin.join("python"))?;
        self.work = Some(work);
        self.cgroup = Some(ProbeCgroup::create(&self.cgroup_path)?);
        self.resource = None;
        self.policy_path = None;
        self.binding = None;
        self.target = None;
        self.revision = None;
        Ok(())
    }

    fn binding(&self) -> TestResult<&WorkloadBindingConfig> {
        self.binding
            .as_ref()
            .ok_or_else(|| "the policy is not installed".into())
    }

    pub(super) fn cgroup(&self) -> &Path {
        &self.cgroup_path
    }

    pub(super) fn move_out(&self, pid: u32) -> TestResult<()> {
        self.node_cgroup
            .as_ref()
            .ok_or("the Node cgroup is not owned")?
            .move_out(pid)?;
        Ok(())
    }

    pub(super) fn set_hook(&mut self, path: &Path) {
        self.hook_path = path.to_owned();
    }

    pub(super) fn admit_path(&self) -> &Path {
        &self.admit_path
    }

    pub(super) fn actor_id(&self) -> TestResult<String> {
        if let Some(binding) = &self.binding {
            return Ok(binding.container_id.clone());
        }
        let generation = self
            .policy_generation
            .checked_add(1)
            .ok_or("the test policy generation overflowed")?;
        Ok(format!("{generation:064x}"))
    }

    pub(super) fn has_policy(&self) -> bool {
        self.binding.is_some()
    }

    pub(super) fn annotations(&self) -> TestResult<BTreeMap<String, String>> {
        let binding = self.binding()?;
        let revision = self
            .revision
            .as_ref()
            .ok_or("the policy revision is not installed")?;
        Ok(BTreeMap::from([
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
        ]))
    }

    pub(super) fn observe(&mut self) -> TestResult<()> {
        self.observe_state(0, ContainerState::ContainerCreated)
            .map(|_revision| ())
    }

    fn observe_state(&mut self, pid: u32, state: ContainerState) -> TestResult<u64> {
        let value = runtime_observation(self.binding()?, pid, state)?;
        self.cri.as_ref().ok_or("CRI is not running")?.set(value)
    }

    pub(super) fn stage_request(&self) -> TestResult<RuntimeAdmissionStageRequest> {
        Ok(RuntimeAdmissionStageRequest {
            container_id: self.binding()?.container_id.clone(),
            annotations: self.annotations()?.into_iter().collect(),
            cgroup_path: self.cgroup_path.as_os_str().as_bytes().to_vec(),
        })
    }

    pub(super) fn stage(&self) -> TestResult<RuntimeAdmissionDecision> {
        let request = self.stage_request()?;
        let client = RuntimeAdmissionClient::new(self.admit_path.clone(), READY_LIMIT)?;
        Ok(self.runtime.block_on(client.stage_runtime_facts(request))?)
    }

    pub(super) fn prepare(&self, pid: u32) -> TestResult<RuntimeAdmissionDecision> {
        let request = RuntimeAdmissionPrepareRequest {
            container_id: self.binding()?.container_id.clone(),
            annotations: self.annotations()?.into_iter().collect(),
            initial_pid: pid,
        };
        let client = RuntimeAdmissionClient::new(self.admit_path.clone(), READY_LIMIT)?;
        Ok(self.runtime.block_on(client.prepare_container(request))?)
    }

    pub(super) fn entries(&self, bundle: &Path, fd: u32) -> TestResult<RuntimeAdmissionDecision> {
        let request = RuntimeAdmissionEntriesRequest {
            container_id: self.binding()?.container_id.clone(),
            annotations: self.annotations()?.into_iter().collect(),
            oci_bundle: bundle.as_os_str().as_bytes().to_vec(),
            oci_root_fd: fd,
        };
        let client = RuntimeAdmissionClient::new(self.admit_path.clone(), READY_LIMIT)?;
        Ok(self
            .runtime
            .block_on(client.prepare_declared_entries(request))?)
    }

    pub(super) fn node_running(&self) -> bool {
        self.node_task.is_some()
    }

    pub(super) fn protected(&self) -> bool {
        self.node_running() && self.binding.is_some()
    }

    fn wait_task_exec(
        &mut self,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        let last = RefCell::new(String::from("<absent>"));
        let snapshot = wait_for(
            &self.pin_path,
            name,
            READY_LIMIT,
            || Ok(self.exec_snapshot(pid, cookie, before, &last)),
            || format!("PID {pid}; last identity: {}", last.borrow()),
        )?;
        self.task_from(pid, snapshot)
    }

    fn exec_snapshot(
        &self,
        pid: u32,
        cookie: u64,
        before: &Task,
        last: &RefCell<String>,
    ) -> Option<NativeTaskSnapshotV1> {
        let snapshot = match self.inspector.snapshot(pid) {
            Ok(snapshot) => snapshot,
            Err(source) => {
                *last.borrow_mut() = source.to_string();
                return None;
            }
        };
        if let Some(value) = snapshot.as_ref() {
            *last.borrow_mut() = format!("{value:?}");
        }
        snapshot.filter(|value| {
            value.task_cookie == cookie
                && value.active_execution_id != before.snapshot.active_execution_id
        })
    }

    fn retire(&mut self) -> TestResult<()> {
        if let Some(cri) = self.cri.as_ref() {
            cri.clear()?;
        }
        if let (Some(plane), Some(policy), Some(resource)) = (
            self.plane.as_ref(),
            self.policy.as_ref(),
            self.resource.as_ref(),
        ) {
            plane.replace_kubernetes_workload_inventory(Vec::new())?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64;
            policy.reconcile(resource, NAMESPACE_UID, &[], now)?;
            if self.node_task.is_some() {
                let last = RefCell::new(String::from("<absent>"));
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
                )?;
            }
        }
        self.resource = None;
        self.binding = None;
        self.target = None;
        self.revision = None;
        Ok(())
    }

    fn clean_test(&mut self) -> TestResult<()> {
        self.retire()?;
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.cleanup()?;
        }
        if let Some(work) = self.work.take() {
            work.cleanup()?;
        }
        Ok(())
    }

    pub(super) fn stop_node(&mut self) -> TestResult<()> {
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
        let seccomp = self.admit_path.with_extension("seccomp.sock");
        if self.admit_path.exists() || seccomp.exists() {
            return Err(format!(
                "Node shutdown left runtime sockets: admission={}, seccomp={}",
                self.admit_path.exists(),
                seccomp.exists(),
            )
            .into());
        }
        self.ready.take();
        Ok(())
    }

    fn tear_down(&mut self) -> TestResult<()> {
        self.clean_test()?;
        self.stop_node()?;
        if let Some(control) = self.control.take() {
            self.runtime.block_on(control.shutdown())?;
        }
        if let Some(mut cri) = self.cri.take() {
            cri.stop()?;
        }
        self.plane.take();
        self.policy.take();
        if let Some(cgroup) = self.node_cgroup.take() {
            cgroup.cleanup()?;
        }
        if let Some(admit) = self.admit.take() {
            admit.cleanup()?;
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
        if let Some(out) = self.out_dir.take() {
            out.cleanup()?;
        }
        Ok(())
    }

    fn task_from(&self, pid: u32, snapshot: NativeTaskSnapshotV1) -> TestResult<Task> {
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

    fn read_task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        let snapshot = self.runtime.block_on(wait_for_async(
            &self.pin_path,
            name,
            READY_LIMIT,
            || self.inspector.snapshot(pid).context(NodeSnafu),
            || format!("PID {pid} has no published identity"),
        ))?;
        self.task_from(pid, snapshot)
    }
}

impl Shared {
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

impl Shared {
    pub(super) fn source(&self) -> &Path {
        &self.root
    }

    pub(super) fn setup(_name: &str) -> TestResult<Self> {
        erebor_telemetry::init_test_logging();
        let mut lifecycle = enter::<SharedState>(SharedState::tear_down)?;
        if lifecycle.get().is_some() {
            let state = lifecycle.get_mut().ok_or("the shared lifecycle is empty")?;
            state.reset()?;
            return Ok(Self {
                lifecycle: Some(lifecycle),
            });
        }
        let root = SharedState::path("MITHRIL_TEST_ROOT")?;
        let out = SharedState::path("MITHRIL_TEST_OUTPUT")?;
        let pin_path = SharedState::path("MITHRIL_TEST_PIN")?;
        let lease_path = SharedState::path("MITHRIL_TEST_LEASE")?;
        let cgroup_path = SharedState::path("MITHRIL_TEST_CGROUP")?;
        let node_name = format!(
            "{}-node",
            cgroup_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("the test cgroup has no file name")?
        );
        let node_path = cgroup_path.with_file_name(node_name);
        let cri_path = out.join("cri.sock");
        let admit_dir = out.join("admission");
        let admit_path = admit_dir.join("runtime.sock");
        let observation_path = out.join("observation.sock");
        let out_dir = ProbeDirectory::create(&out)?;
        let work_path = out.join("actor");
        let state_path = out.join("node");
        let work = ProbeDirectory::create(&work_path)?;
        let bin = work_path.join("bin");
        fs::create_dir(&bin)?;
        fs::copy(fs::canonicalize("/usr/bin/python3")?, bin.join("python"))?;
        let state = ProbeDirectory::create(&state_path)?;
        let admit = ProbeDirectory::create(&admit_dir)?;
        let cgroup = ProbeCgroup::create(&cgroup_path)?;
        let mut node_cgroup = ProbeCgroup::create(&node_path)?;
        node_cgroup.enter()?;
        let inspector = NativeIdentityInspector::new(&pin_path);
        let reader = KernelStateReader::new(&pin_path);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        lifecycle.put(SharedState {
            root,
            out,
            out_dir: Some(out_dir),
            work_path,
            state_path,
            cgroup_path,
            node_path,
            pin_path: pin_path.clone(),
            lease_path: lease_path.clone(),
            cri_path,
            admit_path,
            observation_path,
            work: Some(work),
            state: Some(state),
            admit: Some(admit),
            cgroup: Some(cgroup),
            node_cgroup: Some(node_cgroup),
            pin: Some(ProbeDirectory::new(&pin_path)),
            lease: Some(ProbeFile::new(&lease_path)),
            tls: MtlsFixture::new(false)?,
            control: None,
            plane: None,
            policy: None,
            policy_generation: 0,
            resource: None,
            policy_path: None,
            binding: None,
            target: None,
            revision: None,
            cri: None,
            node_stop: None,
            node_task: None,
            ready: None,
            inspector,
            reader,
            runtime,
            hook_path: env::current_exe()?,
        });
        Ok(Self {
            lifecycle: Some(lifecycle),
        })
    }

    pub(super) fn start_control(&mut self) -> TestResult<()> {
        if self.control.is_some() {
            return Ok(());
        }
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
                node_id: NODE_ID.to_owned(),
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

    pub(super) fn start_node(&mut self) -> TestResult<()> {
        if let Some(task) = self.node_task.as_ref() {
            if self.ready.is_some() && !task.is_finished() {
                return Ok(());
            }
            self.stop_node()?;
        }
        if self.cri.is_none() {
            self.cri = Some(CriFixture::start(&self.cri_path)?);
        }
        let config = self.node_config()?;
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
        match ready.recv_timeout(NODE_START_LIMIT) {
            Ok(Ok(receiver)) => {
                self.ready = Some(receiver);
                Ok(())
            }
            outcome => {
                let reason = match outcome {
                    Ok(Err(source)) => format!("Node start failed: {source}"),
                    Err(source) => format!("Node start did not report readiness: {source}"),
                    Ok(Ok(_receiver)) => unreachable!("the ready result was handled"),
                };
                match self.stop_node() {
                    Ok(()) => Err(reason.into()),
                    Err(source) => Err(format!("{reason}; Node cleanup failed: {source}").into()),
                }
            }
        }
    }

    fn node_config(&self) -> TestResult<NodeConfig> {
        let address = self
            .control
            .as_ref()
            .ok_or("Control is not running")?
            .address();
        Ok(NodeConfig {
            node_id: NODE_ID.to_owned(),
            kubernetes_node_name: Some("node-a".to_owned()),
            state_directory: self.state_path.clone(),
            interceptor: InterceptorConfig {
                runtime_btf_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
                lease_path: self.lease_path.clone(),
                pin_root: self.pin_path.clone(),
            },
            control: self.tls.node_config(address),
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
            runtime_observation: Some(RuntimeObservationConfig {
                socket_path: self.observation_path.clone(),
                allowed_uid: 0,
                cgroup_scope: "/".to_owned(),
            }),
            runtime_admission: Some(RuntimeAdmissionConfig {
                socket_path: self.admit_path.clone(),
                trusted_start_hook_path: self.hook_path.clone(),
                maximum_request_bytes: 64 * 1_024,
                timeout_ms: 5_000,
            }),
            container_runtime: Some(ContainerRuntimeConfig {
                socket_path: self.cri_path.clone(),
                effect_controller_cgroup_path: self.node_path.clone(),
                reconciliation_interval_ms: 10,
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
        })
    }

    pub(super) fn install_policy(&mut self, name: &str) -> TestResult<()> {
        let path = policy_path(&self.root, name)?;
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
        if value.get("kind").and_then(serde_json::Value::as_str)
            == Some("WorkloadProtectionException")
        {
            return self.install_exception(&bytes, &path);
        }
        let mut resource: WorkloadProtectionPolicy =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
        if self
            .resource
            .as_ref()
            .is_some_and(|current| current.spec == resource.spec)
        {
            return Ok(());
        }
        self.policy_generation = self
            .policy_generation
            .checked_add(1)
            .ok_or("the test policy generation overflowed")?;
        resource.metadata.name = Some("scenario".to_owned());
        resource.metadata.namespace = Some("default".to_owned());
        resource.metadata.uid = Some(POLICY_UID.to_owned());
        resource.metadata.generation = Some(self.policy_generation);
        resource.metadata.resource_version = Some(self.policy_generation.to_string());
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64;
        self.resource = Some(resource);
        self.policy_path = Some(path);
        if self.node_task.is_some() {
            self.sync_policy()?;
        } else {
            let policy = self
                .policy
                .as_ref()
                .ok_or("Control policy is not running")?;
            let resource = self
                .resource
                .as_ref()
                .ok_or("the policy is not installed")?;
            let path = self
                .policy_path
                .as_ref()
                .ok_or("the policy path is not installed")?;
            let result = policy.reconcile(resource, NAMESPACE_UID, &[], now)?;
            ensure!(
                result.bundles.is_empty(),
                InvalidInputSnafu {
                    path,
                    reason: "Control produced a policy bundle without a workload target",
                }
            );
            self.revision = Some(result.source_revision.policy_source_revision_id);
        }
        Ok(())
    }

    fn install_exception(&mut self, bytes: &[u8], path: &Path) -> TestResult<()> {
        let mut resource: WorkloadProtectionException =
            serde_json::from_slice(bytes).context(JsonSnafu { path })?;
        resource.spec.policy_ref.name = "scenario".to_owned();
        resource.spec.target.pod.name = "pid-reuse".to_owned();
        resource.spec.target.pod.uid = POD_UID.to_owned();
        resource.spec.target.container_name = "worker".to_owned();
        let target = self
            .target
            .clone()
            .ok_or("the exception has no active workload target")?;
        let policy = self
            .policy
            .as_ref()
            .ok_or("Control policy is not running")?
            .clone();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64;
        let result = policy.reconcile_exception(&resource, NAMESPACE_UID, &[target], now)?;
        let candidate = result.candidate;
        let store = policy.store();
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            path,
            "exception activation",
            READY_LIMIT,
            || {
                let state = store
                    .exception_rollout_state(
                        &candidate.candidate_content_id,
                        &candidate.exact_target.node_id,
                    )
                    .context(PolicySnafu)?;
                *last.borrow_mut() = format!("{state:?}");
                Ok(state
                    .is_some_and(|state| state.state == WorkloadProtectionExceptionStateV1::Active)
                    .then_some(()))
            },
            || format!("last exception rollout: {}", last.borrow()),
        )?)
    }

    pub(super) fn sync_policy(&mut self) -> TestResult<()> {
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
                    .find(|session| session.node_id == NODE_ID))
            },
            || "Control has no ready Kubernetes Node session".to_owned(),
        )?;

        let path = self
            .policy_path
            .as_ref()
            .ok_or("the policy is not installed")?;
        let resource = self
            .resource
            .as_ref()
            .ok_or("the policy is not installed")?;
        let document = lower_kubernetes_policy(resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
        let source = PolicySourceRevisionV1::from_resource(
            resource,
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
        plane.replace_kubernetes_workload_inventory(vec![target.clone()])?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64;
        let policy = self
            .policy
            .as_ref()
            .ok_or("Control policy is not running")?
            .clone();
        let result = policy.reconcile(resource, NAMESPACE_UID, &[target.clone()], now)?;
        ensure!(
            result.bundles.len() == 1,
            InvalidInputSnafu {
                path: &path,
                reason: "Control did not produce one PID-reuse policy bundle",
            }
        );

        let generation = u64::try_from(self.policy_generation)?;
        let container_id = format!("{generation:064x}");
        let revision = source.policy_source_revision_id;
        let digest = target.workload_binding_generation_digest.clone();
        self.wait_policy(&revision, &digest)?;
        let (_, ack) = policy
            .store()
            .active_policy_for_workload(&revision, &digest)?
            .ok_or("Control has no active policy for the test workload")?;
        let profile_generation = ack
            .profile_generation_ref_id
            .ok_or("the active policy has no profile generation reference")?;
        self.revision = Some(revision.clone());
        self.target = Some(target.clone());
        self.binding = Some(WorkloadBindingConfig {
            binding_id: ScheduledRuntimeBindingV1::runtime_binding_id(&authority, &container_id),
            scheduled_binding_authority_id: Some(authority),
            scheduled_target_digest: Some(digest.clone()),
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
            container_generation: generation,
            root_cgroup_path: Some(self.cgroup_path.clone()),
            lifecycle_generation: generation,
            active_profile_generation_ref_id: profile_generation,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: true,
        });
        Ok(())
    }

    fn wait_policy(&self, revision: &str, digest: &str) -> TestResult<()> {
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            &self.state_path,
            "test policy readiness",
            READY_LIMIT,
            || {
                let status =
                    mithril_node::policy_delivery_status(&self.state_path).context(NodeSnafu)?;
                let active = status.active_targets.iter().any(|target| {
                    target.policy_source_revision_id == revision
                        && target.workload_binding_generation_digest == digest
                });
                let ready = active
                    && status.active_target_count == 1
                    && !status.active_targets_truncated
                    && status.scheduled_binding_count + status.runtime_binding_count == 1
                    && !status.activation_pending
                    && status.control_acknowledged;
                *last.borrow_mut() = format!("{status:?}");
                Ok(ready.then_some(()))
            },
            || {
                format!(
                    "expected revision {revision} and target {digest}; last delivery: {}",
                    last.borrow()
                )
            },
        )?)
    }

    pub(super) fn node_ready(&mut self) -> TestResult<()> {
        let ready = self.ready.as_ref().ok_or("Node is not running")?;
        let task = self.node_task.as_ref().ok_or("Node is not running")?;
        let prevention = self
            .resource
            .as_ref()
            .is_none_or(|policy| policy.spec.mode != KubernetesPolicyModeV1::Observe);
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_stable(
            &self.pin_path,
            "Node readiness",
            READY_LIMIT,
            7,
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
                Ok(value.kernel_ready
                    && value.identity_ready
                    && value.control_ready
                    && value.admission_ready
                    && value.effect_prevention_claims_enabled == prevention)
            },
            || {
                let delivery = mithril_node::policy_delivery_status(&self.state_path)
                    .map_or_else(|error| error.to_string(), |status| format!("{status:?}"));
                format!(
                    "expected prevention claims {prevention}; last readiness: {}; policy delivery: {delivery}",
                    last.borrow()
                )
            },
        )?)
    }

    pub(super) fn approve(&self, command: &str, args: &[&str]) -> TestResult<()> {
        let plane = self.plane.clone().ok_or("Control is not running")?;
        let binding = self.binding()?.clone();
        let role = self
            .resource
            .as_ref()
            .and_then(|policy| {
                policy
                    .spec
                    .containers
                    .iter()
                    .find(|container| container.names.contains(&binding.container_name))
            })
            .map(|container| container.administrative_entry.role.clone())
            .ok_or("installed policy has no administrative role for the target container")?;
        let key = self
            .root
            .join("crates/mithril-e2e/fixtures/mithril-policy/test-signing-key.hex");
        let config = AdministrativeApprovalConfigV1 {
            state_directory: self.state_path.join("administrative-approval"),
            tenant_id: TENANT_ID.to_owned(),
            cluster_uid: CLUSTER_UID.to_owned(),
            trust_domain_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
            key_id: "effect-observation-test-key".to_owned(),
            private_key_path: key,
            sequence_epoch: 1,
            authorization_lifetime_seconds: 120,
        };
        let argv = std::iter::once(command)
            .chain(args.iter().copied())
            .map(|arg| arg.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let request = AdministrativeExecRequestV1 {
            node_id: NODE_ID.to_owned(),
            namespace: binding.namespace.as_bytes().to_vec(),
            pod_uid: binding.pod_uid.as_bytes().to_vec(),
            container_name: binding.container_name.as_bytes().to_vec(),
            full_container_id: binding.container_id.as_bytes().to_vec(),
            container_generation: binding.container_generation,
            argv: argv.clone(),
            stream_flags: 0,
            approved_role_id: role,
        };
        let owner = AdministrativeApprovalOwner::load(&config, plane)?;
        let principal = erebor_interceptor_abi::Id128V1::new(1, 1);
        let last = RefCell::new(String::from("<absent>"));
        let resolution = wait_for(
            &self.pin_path,
            "administrative target resolution",
            READY_LIMIT,
            || match self.runtime.block_on(owner.resolve(&request)) {
                Ok(resolution) => Ok(Some(resolution)),
                Err(source) => {
                    *last.borrow_mut() = source.to_string();
                    Ok(None)
                }
            },
            || format!("last resolution: {}", last.borrow()),
        )?;
        let pending = owner.request_resolved(principal, request, resolution)?;
        let credential = owner.approve(pending.request_id, principal)?;
        let authenticated = owner.authenticate_credential(&credential.credential)?;
        let target = owner.admission_target(
            credential.approval_id,
            authenticated.principal_id,
            pending.request_id.to_be_bytes().to_vec(),
            binding.namespace.into_bytes(),
            binding.pod_uid.into_bytes(),
            binding.container_name.into_bytes(),
            binding.container_id.into_bytes(),
            argv,
            0,
        )?;
        let result = self
            .runtime
            .block_on(owner.admit(credential.approval_id, target))?;
        ensure!(
            result.armed,
            InvalidInputSnafu {
                path: &self.pin_path,
                reason: "Node did not arm the administrative execution slot",
            }
        );
        Ok(())
    }

    pub(super) fn place(&mut self, pid: u32) -> TestResult<()> {
        let path = self.cgroup_path.join("cgroup.procs");
        fs::write(&path, pid.to_string()).context(IoSnafu { path: &path })?;
        Ok(())
    }

    pub(super) fn running(&mut self, pid: u32) -> TestResult<()> {
        let revision = self.observe_state(pid, ContainerState::ContainerRunning)?;
        self.cri
            .as_ref()
            .ok_or("CRI is not running")?
            .wait_seen(revision)
    }

    pub(super) fn health(&self) -> TestResult<mithril_node::ReconciliationReportV1> {
        Ok(self.inspector.health()?)
    }

    pub(super) fn move_task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        SharedState::move_out(self, pid)?;
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

    pub(super) fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.read_task(pid, name)
    }

    pub(super) fn wait_exec(
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
            || Ok(self.exec_snapshot(pid, cookie, before, &last)),
            || format!("PID {pid}; last identity: {}", last.borrow()),
        ) {
            Ok(value) => value,
            Err(source) => {
                return Err(format!("{source}; actor stderr: {:?}", actor.stderr()?).into());
            }
        };
        self.task_from(pid, snapshot)
    }

    pub(super) fn wait_pid_exec(
        &mut self,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        self.wait_task_exec(pid, cookie, before, name)
    }

    pub(super) fn recovered(&mut self, pid: u32, name: &str) -> TestResult<Task> {
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

    pub(super) fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        let client = MithrilObservationClient::new(self.observation_path.clone(), "/".to_owned());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(runtime.block_on(client.snapshot())?)
    }

    pub(super) fn maps(&self) -> (&Path, &KernelStateReader) {
        (&self.pin_path, &self.reader)
    }

    pub(super) fn work(&self) -> &Path {
        &self.work_path
    }

    pub(super) fn output(&self) -> &Path {
        &self.out
    }

    pub(super) fn stop(&mut self) -> TestResult<()> {
        self.close()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        let _result = self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::env;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use mithril_node::RuntimeAdmissionClient;
    use rustix::process::{kill_process, Pid, Signal};

    use super::{Shared, READY_LIMIT};
    use crate::physical::{wait_for, ProbeFile};
    use crate::platform::{test_lifecycle, CriFixture, Host, TestResult};
    use crate::process::ProcessFixture;

    #[test]
    #[ignore = "requires its physical test environment"]
    fn live_node_stall_is_closed() -> TestResult<()> {
        test_lifecycle::<Host, _>("live-node-stall", || {
            let mut env = Shared::setup("live-node-stall")?;
            env.start_control()?;
            env.start_node()?;
            env.install_policy("actor_policy.json")?;
            env.node_ready()?;
            env.observe()?;
            let request = env.stage_request()?;

            let cri = env.cri.as_ref().ok_or("CRI is not running")?;
            let before = cri.delay_list(Duration::from_secs(8))?;
            wait_for(
                &env.cri_path,
                "delayed CRI inventory",
                READY_LIMIT,
                || Ok((cri.delayed_lists() > before).then_some(())),
                || format!("last delayed CRI call: {}", cri.delayed_lists()),
            )?;

            let socket = env.admit_path.clone();
            // Keep the client deadline below Node's deadline to test the transport timeout.
            let client = RuntimeAdmissionClient::new(socket.clone(), Duration::from_secs(4))?;
            assert!(env.runtime.block_on(client.available()));
            let result = env
                .runtime
                .block_on(client.stage_runtime_facts(request.clone()));
            cri.delay_list(Duration::ZERO)?;
            let error = match result {
                Err(error) => error,
                Ok(response) => {
                    return Err(format!(
                        "the live Node answered during a blocked CRI read: {response:?}"
                    )
                    .into())
                }
            };
            assert!(
                error
                    .to_string()
                    .contains("runtime admission endpoint exceeded its fail-closed timeout"),
                "{error}"
            );
            assert!(socket.exists());
            let last = RefCell::new(String::from("<none>"));
            let recovered = wait_for(
                &socket,
                "admission recovery after CRI delay",
                READY_LIMIT,
                || match env
                    .runtime
                    .block_on(client.stage_runtime_facts(request.clone()))
                {
                    Ok(response) => Ok(Some(response)),
                    Err(error) => {
                        *last.borrow_mut() = error.to_string();
                        Ok(None)
                    }
                },
                || format!("last admission result: {}", last.borrow()),
            )?;
            assert!(recovered.allowed, "{recovered:?}");
            env.stop()
        })
    }

    #[test]
    #[ignore = "requires its physical test environment"]
    fn startup_sigterm_is_recoverable() -> TestResult<()> {
        test_lifecycle::<Host, _>("node-startup-signal", || {
            let mut env = Shared::setup("startup-signal")?;
            env.start_control()?;
            let socket = ProbeFile::new(&env.cri_path);
            let blocked = UnixListener::bind(&env.cri_path)?;
            let config = env.output().join("node.json");
            fs::write(&config, serde_json::to_vec_pretty(&env.node_config()?)?)?;
            let bin = env::var_os("MITHRIL_BIN_DIRECTORY")
                .map(PathBuf::from)
                .unwrap_or_else(|| env.source().join("target/debug"))
                .join("mithril-node");
            env.move_out(std::process::id())?;
            let group = env.node_path.clone();
            let start = || {
                let mut node = ProcessFixture::held_cgroup(
                    &bin,
                    [OsStr::new("--config"), config.as_os_str()],
                    &group,
                    Path::new("/"),
                    std::process::id(),
                )?;
                node.release()?;
                Ok::<_, crate::Error>(node)
            };
            let mut node = start()?;
            let map = env.pin_path.join("maps/identity_config");
            node.wait_path(
                &map,
                "Node startup BPF attachment",
                READY_LIMIT,
                || Ok(map.exists().then_some(())),
                || "the identity map is absent".to_owned(),
            )?;
            let pid = Pid::from_raw(i32::try_from(node.id())?)
                .ok_or("mithril-node has an invalid PID")?;
            kill_process(pid, Signal::TERM)?;
            let status = node.wait_exit("Node startup termination", READY_LIMIT)?;
            let stderr = node.stderr()?;
            assert!(
                status.success()
                    && env.pin_path.join("maps").is_dir()
                    && env.pin_path.join("links").is_dir(),
                "{status}; retained pin root: {}; stderr: {stderr}",
                env.pin_path.display()
            );
            drop(blocked);
            socket.cleanup()?;
            env.cri = Some(CriFixture::start(&env.cri_path)?);
            let stale = UnixListener::bind(&env.admit_path)?;
            drop(stale);
            let health = mithril_node::RuntimeAdmissionClient::new(
                env.admit_path.clone(),
                Duration::from_millis(100),
            )?;
            assert!(env.admit_path.exists() && !env.runtime.block_on(health.available()));
            let mut recovered = start()?;
            recovered.wait_path(
                &env.admit_path,
                "recovered Node admission readiness",
                READY_LIMIT,
                || Ok(env.runtime.block_on(health.available()).then_some(())),
                || {
                    format!(
                        "live admission unavailable; path exists: {}",
                        env.admit_path.exists()
                    )
                },
            )?;
            let pid = Pid::from_raw(i32::try_from(recovered.id())?)
                .ok_or("recovered mithril-node has an invalid PID")?;
            kill_process(pid, Signal::TERM)?;
            let status = recovered.wait_exit("recovered Node shutdown", READY_LIMIT)?;
            let stderr = recovered.stderr()?;
            assert!(status.success(), "{status}; stderr: {stderr}");
            env.stop()
        })
    }
}
