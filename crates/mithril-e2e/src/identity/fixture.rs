use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor::{KernelHost, KernelHostConfig, KernelHostOwner};
use k8s_cri::v1::ContainerState;
use mithril_control::PolicyArtifactOwner;
use mithril_node::{
    ContainerKindV1, EvidenceConfig, EvidenceWalCapacityPolicyV1, InterceptorConfig,
    NativeSecurityStateOwner, NodeConfig, NodeControlConfig, NodePolicyGenerationOwner,
    PolicyCandidateConfig, WorkloadBindingConfig, WorkloadBindingOwner,
};
use snafu::ResultExt as _;

use super::invalid_state;
use crate::error::{InterceptorSnafu, IoSnafu, NodeSnafu, PolicySnafu};
use crate::physical::{boot_identity, ProbeDirectory, ProbeFile};
use crate::platform::actor_script;
use crate::process::ProcessFixture;
use crate::runtime_input::runtime_observation;
use crate::Result;

pub(super) struct IdentityFixture {
    host: Option<KernelHost>,
    policy: Option<NodePolicyGenerationOwner>,
    actor: Option<ProcessFixture>,
    state: Option<ProbeDirectory>,
    lease: Option<ProbeFile>,
}

impl IdentityFixture {
    pub(super) fn start(group: &Path, pin: &Path) -> Result<Self> {
        let root = Self::path("MITHRIL_TEST_ROOT")?;
        let out = Self::path("MITHRIL_TEST_OUTPUT")?;
        let lease_path = Self::path("MITHRIL_TEST_LEASE")?;
        let lease = ProbeFile::new(&lease_path);
        let state = ProbeDirectory::create(&out.join("clone-policy"))?;
        let policy_root = root.join("crates/mithril-e2e/fixtures/mithril-policy");
        let artifact = state.path().join("profile.json");
        PolicyArtifactOwner::default()
            .compile_and_sign(
                &policy_root.join("identity-policy-v1.yaml"),
                &policy_root.join("observe-profile-seal-request.json"),
                &policy_root.join("test-signing-key.hex"),
                &artifact,
            )
            .context(PolicySnafu)?;
        let binding = Self::binding(group);
        let config = Self::config(
            state.path(),
            pin,
            &lease_path,
            &policy_root,
            artifact,
            &binding,
        );
        let (boot, node) = boot_identity()?;
        let host = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            &lease_path,
            Some(pin.to_path_buf()),
            boot,
            1,
        ))
        .start()
        .context(InterceptorSnafu)?;
        let script = actor_script(&root, "ready.py")?;
        let actor = ProcessFixture::python(&script, std::iter::empty::<&str>())?;
        let actor_pid = actor.id();
        let mut fixture = Self {
            host: Some(host),
            policy: None,
            actor: Some(actor),
            state: Some(state),
            lease: Some(lease),
        };
        fs::write(group.join("cgroup.procs"), actor_pid.to_string())
            .context(IoSnafu { path: group })?;
        let mut bindings = WorkloadBindingOwner::system(node, 1).context(NodeSnafu)?;
        let policy = NodePolicyGenerationOwner::load_and_install_for_bindings(
            &config,
            fixture.host()?,
            &bindings,
            node,
            1,
        )
        .context(NodeSnafu)?;
        fixture.policy = Some(policy);
        let observed = runtime_observation(&binding, 0, ContainerState::ContainerCreated)?;
        bindings
            .publish_held_activated_root(fixture.host()?, &binding, actor_pid, &observed)
            .context(NodeSnafu)?;
        let identity = NativeSecurityStateOwner::new(node, 1);
        identity
            .activate_held_initial_admission(fixture.host()?, false)
            .context(NodeSnafu)?;
        identity
            .activate_prepared_runtime_roots(fixture.host()?, false)
            .context(NodeSnafu)?;
        Ok(fixture)
    }

    fn host(&mut self) -> Result<&mut KernelHost> {
        self.host
            .as_mut()
            .ok_or_else(|| invalid_state("identity host is not running"))
    }

    fn path(name: &'static str) -> Result<PathBuf> {
        std::env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| invalid_state(format!("{name} is not set")))
    }

    fn binding(group: &Path) -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            scheduled_binding_authority_id: None,
            scheduled_target_digest: None,
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            container_id: "c".repeat(64),
            namespace: "default".to_owned(),
            cluster_uid: String::new(),
            namespace_uid: String::new(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::new(),
            pod_uid: "identity-pod".to_owned(),
            sandbox_id: "identity-sandbox".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: "sha256:identity-fixture-image".to_owned(),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: Some(group.to_path_buf()),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: true,
        }
    }

    fn config(
        state: &Path,
        pin: &Path,
        lease: &Path,
        policy: &Path,
        artifact: PathBuf,
        binding: &WorkloadBindingConfig,
    ) -> NodeConfig {
        let mut scheduled = binding.clone();
        scheduled.container_id = format!("scheduled:{}", binding.container_id);
        scheduled.container_generation = 0;
        scheduled.root_cgroup_path = None;
        NodeConfig {
            node_id: "mithril-identity-test".to_owned(),
            kubernetes_node_name: None,
            state_directory: state.to_path_buf(),
            interceptor: InterceptorConfig {
                runtime_btf_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
                lease_path: lease.to_path_buf(),
                pin_root: pin.to_path_buf(),
            },
            control: NodeControlConfig {
                endpoint: "https://127.0.0.1".to_owned(),
                server_name: "localhost".to_owned(),
                ca_path: PathBuf::new(),
                certificate_path: PathBuf::new(),
                private_key_path: PathBuf::new(),
                reconnect_minimum_ms: 100,
                reconnect_maximum_ms: 5_000,
                maximum_clock_skew_ns: 30_000_000_000,
            },
            evidence: Some(EvidenceConfig {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
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
            runtime_admission: None,
            container_runtime: None,
            workload_bindings: vec![scheduled],
            policy_candidates: vec![PolicyCandidateConfig {
                artifact_path: artifact,
                public_key_path: policy.join("test-public-key.hex"),
                rollback_authorization_path: None,
                rollback_public_key_path: None,
            }],
            administrative_authorization: None,
            decommission: None,
        }
    }

    pub(super) fn stop(mut self) -> Result<()> {
        self.close()
    }

    fn close(&mut self) -> Result<()> {
        if let Some(mut actor) = self.actor.take() {
            actor.stop()?;
        }
        self.policy.take();
        if let Some(host) = self.host.take() {
            host.shutdown().context(InterceptorSnafu)?;
        }
        if let Some(lease) = self.lease.take() {
            lease.cleanup()?;
        }
        if let Some(state) = self.state.take() {
            state.cleanup()?;
        }
        Ok(())
    }
}

impl Drop for IdentityFixture {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
