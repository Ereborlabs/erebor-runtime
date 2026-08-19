use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use erebor_interceptor::{EffectObservationReader, KernelHost};
use erebor_interceptor_abi::{
    KernelEffectFamilyV1, KernelEffectOperationV1, MountSecurityViewStateV1, MountTopologyStateV1,
};
use mithril_node::{
    ContainerKindV1, EffectObservationHealth, EffectObservationStore, EvidenceConfig,
    InterceptorConfig, NodeConfig, NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
};
use snafu::{ensure, ResultExt as _};
use zerocopy::TryFromBytes as _;

use super::PROFILE_GENERATION_REF_ID;
use crate::error::{CommandSnafu, InterceptorSnafu, InvalidInputSnafu, IoSnafu};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(5);

pub(super) fn effect_node_config(
    state_directory: &Path,
    pin_root: &Path,
    lease_path: &Path,
    manual: &Path,
    artifact_path: PathBuf,
    bindings: Vec<WorkloadBindingConfig>,
    exact_file_objects: Vec<mithril_node::ExactFileObjectConfig>,
) -> NodeConfig {
    NodeConfig {
        node_id: "mithril-effect-test".to_owned(),
        state_directory: state_directory.to_path_buf(),
        interceptor: InterceptorConfig {
            runtime_btf_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
            lease_path: lease_path.to_path_buf(),
            pin_root: pin_root.to_path_buf(),
        },
        control: NodeControlConfig {
            endpoint: "https://127.0.0.1".to_owned(),
            server_name: "localhost".to_owned(),
            ca_path: PathBuf::new(),
            certificate_path: PathBuf::new(),
            private_key_path: PathBuf::new(),
            reconnect_minimum_ms: 100,
            reconnect_maximum_ms: 5_000,
        },
        evidence: Some(EvidenceConfig {
            tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            source_id: "66666666-6666-4666-8666-666666666666".to_owned(),
            maximum_record_bytes: 128 * 1_024,
            maximum_retained_bytes: 16 * 1_024 * 1_024,
            maximum_retained_records: 10_000,
            maximum_batch_records: 256,
            maximum_control_delay_ms: 30_000,
        }),
        runtime_observation: None,
        container_runtime: None,
        workload_bindings: bindings,
        policy_candidates: vec![PolicyCandidateConfig {
            artifact_path,
            public_key_path: manual.join("test-public-key.hex"),
            rollback_authorization_path: None,
            rollback_public_key_path: None,
        }],
        exact_file_objects,
        administrative_authorization: None,
    }
}

pub(super) fn effect_binding(cgroup_path: &Path) -> WorkloadBindingConfig {
    effect_binding_with_identity(
        cgroup_path,
        "99999999-9999-4999-8999-999999999999",
        'c',
        "worker",
        false,
    )
}

pub(super) fn effect_peer_binding(cgroup_path: &Path) -> WorkloadBindingConfig {
    effect_binding_with_identity(
        cgroup_path,
        "99999999-9999-4999-8999-999999999998",
        'd',
        "peer",
        true,
    )
}

pub(super) fn effect_propagation_binding(cgroup_path: &Path) -> WorkloadBindingConfig {
    effect_binding_with_identity(
        cgroup_path,
        "99999999-9999-4999-8999-999999999997",
        'e',
        "propagation-peer",
        false,
    )
}

pub(super) fn effect_binding_with_identity(
    cgroup_path: &Path,
    binding_id: &str,
    container_id_byte: char,
    container_name: &str,
    arm_initial_root: bool,
) -> WorkloadBindingConfig {
    WorkloadBindingConfig {
        binding_id: binding_id.to_owned(),
        execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
        protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        workload_selector_id: "worker".to_owned(),
        profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        container_id: container_id_byte.to_string().repeat(64),
        namespace: "default".to_owned(),
        pod_uid: "observation-pod".to_owned(),
        sandbox_id: "observation-sandbox".to_owned(),
        container_name: container_name.to_owned(),
        image_digest: "sha256:effect-fixture-image".to_owned(),
        container_kind: ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: Some(cgroup_path.to_path_buf()),
        lifecycle_generation: 1,
        active_profile_generation_ref_id: PROFILE_GENERATION_REF_ID,
        initial_role_id: 1,
        external_role_id: 2,
        arm_initial_root,
    }
}

pub(super) fn observation_health(
    host: &KernelHost,
    store: &EffectObservationStore,
) -> Result<EffectObservationHealth> {
    let bytes = host
        .lookup_map("effect_observation_health", &0_u32.to_ne_bytes())
        .context(InterceptorSnafu)?;
    Ok(store.health(bytes.as_deref()))
}

pub(super) fn health_delta(
    later: EffectObservationHealth,
    earlier: EffectObservationHealth,
) -> EffectObservationHealth {
    EffectObservationHealth {
        attempted: later.attempted.saturating_sub(earlier.attempted),
        suppressed: later.suppressed.saturating_sub(earlier.suppressed),
        requested: later.requested.saturating_sub(earlier.requested),
        emitted: later.emitted.saturating_sub(earlier.emitted),
        lost: later.lost.saturating_sub(earlier.lost),
        classifier_miss_count: later
            .classifier_miss_count
            .saturating_sub(earlier.classifier_miss_count),
        unresolved: later.unresolved.saturating_sub(earlier.unresolved),
        decoder_errors: later.decoder_errors.saturating_sub(earlier.decoder_errors),
        evidence_errors: later
            .evidence_errors
            .saturating_sub(earlier.evidence_errors),
    }
}

pub(super) fn mount_view_is_dirty(host: &KernelHost, mount_namespace_inode: u32) -> Result<bool> {
    Ok(mount_state(
        host,
        "mount_security_views",
        &mount_namespace_inode.to_ne_bytes(),
    )?
    .state
        == MountTopologyStateV1::Dirty)
}

pub(super) fn global_mount_view_is_dirty(host: &KernelHost) -> Result<bool> {
    let key = 0_u32.to_ne_bytes();
    let mutation = mount_counter(host, "mount_global_mutation_epoch", &key)?;
    let clean = mount_counter(host, "mount_global_clean_epoch", &key)?;
    let pending = mount_counter(host, "mount_global_pending_mutations", &key)?;
    Ok(mutation != clean || pending != 0)
}

pub(super) fn mount_views_are_clean(
    host: &KernelHost,
    mount_namespaces: &BTreeSet<u32>,
) -> Result<bool> {
    let global_key = 0_u32.to_ne_bytes();
    let global_epoch = mount_counter(host, "mount_global_mutation_epoch", &global_key)?;
    let global_clean = mount_counter(host, "mount_global_clean_epoch", &global_key)?;
    let global_pending = mount_counter(host, "mount_global_pending_mutations", &global_key)?;
    if mount_namespaces.is_empty()
        || global_epoch == 0
        || global_clean != global_epoch
        || global_pending != 0
    {
        return Ok(false);
    }
    for mount_namespace_inode in mount_namespaces {
        let key = mount_namespace_inode.to_ne_bytes();
        let view = mount_state(host, "mount_security_views", &key)?;
        if view.state != MountTopologyStateV1::Clean
            || view.topology_generation != global_epoch
            || view.snapshot_digest_id == 0
            || view.pending_mutations != 0
            || view.transition_version == 0
            || mount_counter(host, "mount_mutation_epochs", &key)? != global_epoch
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mount_counter(host: &KernelHost, map: &str, key: &[u8]) -> Result<u64> {
    let bytes = host
        .lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: Path::new(map),
                reason: "protected mount topology has no global counter",
            }
            .build()
        })?;
    let value: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
        InvalidInputSnafu {
            path: Path::new(map),
            reason: "global mount counter has an invalid ABI value",
        }
        .build()
    })?;
    Ok(u64::from_ne_bytes(value))
}

fn mount_state(host: &KernelHost, map: &str, key: &[u8]) -> Result<MountSecurityViewStateV1> {
    let bytes = host
        .lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: Path::new(map),
                reason: "protected mount topology has no security state",
            }
            .build()
        })?;
    let view = MountSecurityViewStateV1::try_read_from_bytes(&bytes).map_err(|error| {
        InvalidInputSnafu {
            path: Path::new(map),
            reason: format!("mount security state has an invalid ABI value: {error}"),
        }
        .build()
    })?;
    Ok(view)
}

pub(super) fn wait_for_reason(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected: &str,
) -> Result<()> {
    wait_for_observation(reader, store, marker, expected, None, None)
}

pub(super) fn wait_for_effect(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected_reason: &str,
    expected_effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
) -> Result<()> {
    wait_for_observation(
        reader,
        store,
        marker,
        expected_reason,
        Some((
            u32::from(expected_effect.0 as u16),
            u32::from(expected_effect.1 as u16),
        )),
        None,
    )
}

pub(super) fn wait_for_exact_effect(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected_reason: &str,
    expected_effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
    exact_object_key_id: u64,
    operation_argument: Option<u32>,
) -> Result<()> {
    wait_for_observation(
        reader,
        store,
        marker,
        expected_reason,
        Some((
            u32::from(expected_effect.0 as u16),
            u32::from(expected_effect.1 as u16),
        )),
        Some(ObjectExpectation::Exact {
            exact_object_key_id,
            operation_argument,
        }),
    )
}

pub(super) fn wait_for_unsupported_effect(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected_reason: &str,
    expected_effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
) -> Result<()> {
    wait_for_observation(
        reader,
        store,
        marker,
        expected_reason,
        Some((
            u32::from(expected_effect.0 as u16),
            u32::from(expected_effect.1 as u16),
        )),
        Some(ObjectExpectation::Unsupported),
    )
}

pub(super) fn wait_for_exact_io_uring_effect(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected_reason: &str,
    exact_object_key_id: u64,
) -> Result<()> {
    wait_for_observation(
        reader,
        store,
        marker,
        expected_reason,
        Some((
            u32::from(KernelEffectFamilyV1::File as u16),
            u32::from(KernelEffectOperationV1::Read as u16),
        )),
        Some(ObjectExpectation::IoUringRead {
            exact_object_key_id,
        }),
    )
}

#[derive(Clone, Copy, Debug)]
enum ObjectExpectation {
    Exact {
        exact_object_key_id: u64,
        operation_argument: Option<u32>,
    },
    IoUringRead {
        exact_object_key_id: u64,
    },
    Unsupported,
}

fn wait_for_observation(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: u64,
    expected_reason: &str,
    expected_effect: Option<(u32, u32)>,
    expected_object: Option<ObjectExpectation>,
) -> Result<()> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        reader
            .poll(Duration::from_millis(50))
            .context(InterceptorSnafu)?;
        if store.recent_since(marker).iter().any(|event| {
            observation_matches(
                &event.reason,
                event.effect_family,
                event.operation,
                expected_reason,
                expected_effect,
            ) && object_matches(event, expected_object)
        }) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: format!(
                    "timed out waiting for reason {expected_reason}, effect {expected_effect:?}, and object {expected_object:?}; observed {:?}",
                    store
                        .recent_since(marker)
                        .iter()
                        .map(|event| {
                            (
                                event.reason.as_str(),
                                event.effect_family,
                                event.operation,
                                event.operation_argument,
                                event.exact_object_key_id,
                                event.composite_atom_id,
                                event.mount_namespace_inode,
                                event.mount_id_unique,
                                event.filesystem_device,
                                event.inode,
                                event.inode_generation,
                            )
                        })
                        .collect::<Vec<_>>()
                ),
            }
        );
    }
}

fn object_matches(
    event: &erebor_runtime_ipc::v1::MithrilEffectObservation,
    expected: Option<ObjectExpectation>,
) -> bool {
    match expected {
        None => true,
        Some(ObjectExpectation::Exact {
            exact_object_key_id: expected_key,
            operation_argument: expected_argument,
        }) => {
            event.exact_object_key_id == expected_key
                && expected_argument.is_none_or(|argument| event.operation_argument == argument)
        }
        Some(ObjectExpectation::IoUringRead {
            exact_object_key_id,
        }) => {
            event.exact_object_key_id == exact_object_key_id
                && event.io_uring_ring_id != "00000000000000000000000000000000"
                && event.io_uring_ring_generation == 1
                && event.io_uring_submission_sequence > 0
                && event.io_uring_user_data == 0x4d49_5448_5249_4c01
                && event.io_uring_file_offset == 0
                && event.io_uring_buffer_address != 0
                && event.io_uring_file_cookie != 0
                && event.io_uring_executor_pid_tgid != 0
                && event.io_uring_byte_length == 1
                && event.io_uring_sqe_index < 2
                && event.io_uring_request_flags & 16 != 0
                && event.io_uring_rw_flags == 0
                && event.io_uring_opcode == 22
        }
        Some(ObjectExpectation::Unsupported) => {
            event.exact_object_key_id == 0 && event.composite_atom_id == 0
        }
    }
}

fn observation_matches(
    reason: &str,
    effect_family: u32,
    operation: u32,
    expected_reason: &str,
    expected_effect: Option<(u32, u32)>,
) -> bool {
    reason == expected_reason
        && expected_effect.is_none_or(|expected| expected == (effect_family, operation))
}

pub(super) fn inode_generation(pid: u32, path: &Path) -> Result<u32> {
    let host_path = PathBuf::from(format!("/proc/{pid}/root")).join(
        path.strip_prefix("/").map_err(|error| {
            InvalidInputSnafu {
                path,
                reason: format!("effect path is not absolute: {error}"),
            }
            .build()
        })?,
    );
    let output = Command::new("lsattr")
        .arg("-v")
        .arg(&host_path)
        .output()
        .context(IoSnafu {
            path: Path::new("lsattr"),
        })?;
    ensure!(
        output.status.success(),
        CommandSnafu {
            program: "lsattr",
            reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .split_ascii_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    ensure!(
        value > 0,
        InvalidInputSnafu {
            path: host_path,
            reason: "filesystem did not expose a nonzero inode generation through lsattr -v",
        }
    );
    Ok(value)
}

pub(super) struct ExternalMountNamespace {
    namespace: File,
}

impl ExternalMountNamespace {
    pub(super) fn acquire(pid: u32) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{pid}/ns/mnt"));
        Ok(Self {
            namespace: File::open(&path).context(IoSnafu { path: &path })?,
        })
    }

    pub(super) fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        self.run(["mount", "--bind"], [source, target])
    }

    pub(super) fn unmount(&self, target: &Path) -> Result<()> {
        self.run(["umount", "--"], [target])
    }

    pub(super) fn mount_setattr(&self, target: &Path, read_only: bool) -> Result<()> {
        let executable = std::env::current_exe().context(IoSnafu {
            path: Path::new("current executable"),
        })?;
        let flags = rustix::io::fcntl_getfd(&self.namespace)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        rustix::io::fcntl_setfd(&self.namespace, flags - rustix::io::FdFlags::CLOEXEC)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        let output = Command::new(executable)
            .arg("mount-setattr")
            .arg("--namespace")
            .arg(format!("/proc/self/fd/{}", self.namespace.as_raw_fd()))
            .arg("--path")
            .arg(target)
            .arg("--read-only")
            .arg(read_only.to_string())
            .output();
        rustix::io::fcntl_setfd(&self.namespace, flags)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        let output = output.context(IoSnafu {
            path: Path::new("mount_setattr helper"),
        })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "mithril-effect-test mount-setattr",
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        Ok(())
    }

    fn run<const A: usize, const P: usize>(
        &self,
        command: [&str; A],
        paths: [&Path; P],
    ) -> Result<()> {
        let flags = rustix::io::fcntl_getfd(&self.namespace)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        rustix::io::fcntl_setfd(&self.namespace, flags - rustix::io::FdFlags::CLOEXEC)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        let output = Command::new("nsenter")
            .arg(format!(
                "--mount=/proc/self/fd/{}",
                self.namespace.as_raw_fd()
            ))
            .arg("--")
            .args(command)
            .args(paths)
            .output();
        rustix::io::fcntl_setfd(&self.namespace, flags)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?;
        let output = output.context(IoSnafu {
            path: Path::new("nsenter"),
        })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "nsenter",
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mithril_control::{
        CompiledPhysicalResultV1, EffectFamilyV1, PolicyArtifactOwner, PolicyCompiler,
        PolicyDocumentV1, ProfileModeV1,
    };
    use mithril_node::EffectObservationHealth;

    use super::{health_delta, object_matches, observation_matches, ObjectExpectation};

    #[test]
    fn exact_observation_match_rejects_the_same_reason_from_another_hook() {
        assert!(observation_matches(
            "EXACT_POLICY_DENY",
            2,
            3,
            "EXACT_POLICY_DENY",
            Some((2, 3)),
        ));
        assert!(!observation_matches(
            "EXACT_POLICY_DENY",
            1,
            3,
            "EXACT_POLICY_DENY",
            Some((2, 3)),
        ));
        assert!(!observation_matches(
            "EXACT_POLICY_DENY",
            2,
            4,
            "EXACT_POLICY_DENY",
            Some((2, 3)),
        ));
        assert!(observation_matches(
            "EXACT_POLICY_DENY",
            1,
            3,
            "EXACT_POLICY_DENY",
            None,
        ));
    }

    #[test]
    fn object_match_requires_the_selected_exact_or_unsupported_identity() {
        let exact = Some(ObjectExpectation::Exact {
            exact_object_key_id: 13,
            operation_argument: Some(2_147_767_344),
        });
        let mut event = erebor_runtime_ipc::v1::MithrilEffectObservation {
            exact_object_key_id: 13,
            composite_atom_id: 99,
            operation_argument: 2_147_767_344,
            ..Default::default()
        };
        assert!(object_matches(&event, exact));
        event.exact_object_key_id = 12;
        assert!(!object_matches(&event, exact));
        event.exact_object_key_id = 13;
        event.operation_argument = 0;
        assert!(!object_matches(&event, exact));
        event.exact_object_key_id = 0;
        event.composite_atom_id = 0;
        assert!(object_matches(&event, Some(ObjectExpectation::Unsupported)));
        event.composite_atom_id = 1;
        assert!(!object_matches(
            &event,
            Some(ObjectExpectation::Unsupported)
        ));
        event.composite_atom_id = 0;
        event.exact_object_key_id = 1;
        assert!(!object_matches(
            &event,
            Some(ObjectExpectation::Unsupported)
        ));
    }

    #[test]
    fn io_uring_match_requires_exact_worker_request_identity() {
        let expectation = Some(ObjectExpectation::IoUringRead {
            exact_object_key_id: 7,
        });
        let mut event = erebor_runtime_ipc::v1::MithrilEffectObservation {
            exact_object_key_id: 7,
            io_uring_ring_id: "00000000000000010000000000000002".to_owned(),
            io_uring_ring_generation: 1,
            io_uring_submission_sequence: 3,
            io_uring_user_data: 0x4d49_5448_5249_4c01,
            io_uring_file_offset: 0,
            io_uring_buffer_address: 4,
            io_uring_file_cookie: 5,
            io_uring_executor_pid_tgid: 6,
            io_uring_byte_length: 1,
            io_uring_sqe_index: 0,
            io_uring_request_flags: 16,
            io_uring_rw_flags: 0,
            io_uring_opcode: 22,
            ..Default::default()
        };
        assert!(object_matches(&event, expectation));
        event.io_uring_request_flags = 0;
        assert!(!object_matches(&event, expectation));
        event.io_uring_request_flags = 16;
        event.io_uring_file_cookie = 0;
        assert!(!object_matches(&event, expectation));
    }

    #[test]
    fn health_delta_preserves_ring_accounting() {
        let before = EffectObservationHealth {
            attempted: 10,
            suppressed: 0,
            requested: 10,
            emitted: 8,
            lost: 2,
            classifier_miss_count: 0,
            unresolved: 1,
            decoder_errors: 0,
            evidence_errors: 0,
        };
        let after = EffectObservationHealth {
            attempted: 25,
            suppressed: 0,
            requested: 25,
            emitted: 17,
            lost: 8,
            classifier_miss_count: 0,
            unresolved: 3,
            decoder_errors: 0,
            evidence_errors: 0,
        };
        let delta = health_delta(after, before);
        assert_eq!(delta.attempted, delta.suppressed + delta.requested);
        assert_eq!(delta.requested, delta.emitted + delta.lost);
        assert_eq!(delta.lost, 6);
    }

    #[test]
    fn enforcement_fixture_is_a_verified_protect_artifact() -> Result<(), Box<dyn std::error::Error>>
    {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let policy_fixture = repository.join("crates/mithril-e2e/fixtures/mithril-policy");
        let policy_source = policy_fixture.join("protect-policy-v1.yaml");
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("enforcement-profile.json");
        let owner = PolicyArtifactOwner::default();
        owner.compile_and_sign(
            &policy_source,
            &policy_fixture.join("observe-profile-seal-request.json"),
            &policy_fixture.join("test-signing-key.hex"),
            &artifact_path,
        )?;
        let artifact =
            owner.load_verified(&artifact_path, &policy_fixture.join("test-public-key.hex"))?;

        assert_eq!(artifact.compiled_profile.mode, ProfileModeV1::Protect);
        let cells = &artifact.compiled_profile.compiled_cells;
        assert_eq!(
            cells
                .iter()
                .filter(|cell| cell.physical_result == CompiledPhysicalResultV1::DenyEffect)
                .count(),
            11
        );
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["allow-manual-exec-read"]
                && cell.key.effect_family == EffectFamilyV1::File
                && cell.key.operation_id == "OPEN_READ"
                && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
        }));
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["deny-manual-exec"]
                && cell.key.effect_family == EffectFamilyV1::Exec
                && cell.key.operation_id == "EXECUTE"
                && cell.physical_result == CompiledPhysicalResultV1::DenyEffect
        }));
        for operation in ["MMAP_READ", "MMAP_WRITE"] {
            assert!(cells.iter().any(|cell| {
                cell.source_rule_ids == ["allow-manual-exec-allowed-read"]
                    && cell.key.effect_family == EffectFamilyV1::File
                    && cell.key.operation_id == operation
                    && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
            }));
        }
        for operation in ["EXECUTE", "MMAP_EXEC", "MPROTECT"] {
            assert!(cells.iter().any(|cell| {
                cell.source_rule_ids == ["allow-manual-exec-allowed"]
                    && cell.key.effect_family == EffectFamilyV1::Exec
                    && cell.key.operation_id == operation
                    && cell.key.object_selector == "EXACT:12"
                    && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
            }));
        }
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["allow-labeled-target-signal-zero"]
                && cell.key.effect_family == EffectFamilyV1::Privilege
                && cell.key.operation_id == "SIGNAL_0"
                && cell.key.object_selector == "SECURITY:PROCESS:runtime-external"
                && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
        }));
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["deny-labeled-target-signal"]
                && cell.key.effect_family == EffectFamilyV1::Privilege
                && cell.key.operation_id == "SIGNAL"
                && cell.key.object_selector == "SECURITY:PROCESS:runtime-external"
                && cell.physical_result == CompiledPhysicalResultV1::DenyEffect
        }));
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["deny-labeled-target-ptrace"]
                && cell.key.effect_family == EffectFamilyV1::Privilege
                && cell.key.operation_id == "PTRACE"
                && cell.key.object_selector == "SECURITY:PROCESS:runtime-external"
                && cell.physical_result == CompiledPhysicalResultV1::DenyEffect
        }));
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["allow-ptmx-device-ioctl"]
                && cell.key.effect_family == EffectFamilyV1::Device
                && cell.key.operation_id == "IOCTL"
                && cell.key.object_selector == "DEVICE:PTMX_DEVICE:2147767344"
                && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
        }));
        assert!(cells.iter().any(|cell| {
            cell.source_rule_ids == ["deny-zero-device-ioctl"]
                && cell.key.effect_family == EffectFamilyV1::Device
                && cell.key.operation_id == "IOCTL"
                && cell.key.object_selector == "DEVICE:ZERO_DEVICE:2147767344"
                && cell.physical_result == CompiledPhysicalResultV1::DenyEffect
        }));
        assert_eq!(
            artifact
                .compiled_profile
                .compiled_cells
                .iter()
                .filter(|cell| cell.consuming_exception_id.is_some())
                .count(),
            2
        );
        for (exception_id, expected_digest) in [
            (
                "bounded-secret-write-open",
                "eb7614f22732c8edcac2e55060444472180eb11ab3e34a9ea10c3514d8d16fb3",
            ),
            (
                "expired-benign-write-open",
                "d30e1be8582242608dda1b298fdf0a1e593bf54750f7e6497b3a6009d6965c9d",
            ),
        ] {
            let cell = cells
                .iter()
                .find(|cell| cell.consuming_exception_id.as_deref() == Some(exception_id))
                .ok_or("protect fixture has no expected exception cell")?;
            assert_eq!(
                cell.key.digest(&artifact.compiled_profile.profile_id)?,
                expected_digest
            );
        }
        Ok(())
    }

    #[test]
    fn checked_in_enforcement_manual_policy_matches_the_automated_fixture() -> crate::Result<()> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path =
            repository.join("crates/mithril-e2e/fixtures/mithril-policy/protect-policy-v1.yaml");
        let source = std::fs::read(&path).map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;
        let document =
            PolicyDocumentV1::parse(&path, &source).map_err(|source| crate::Error::Policy {
                source,
                location: snafu::location!(),
            })?;
        let compiled =
            PolicyCompiler
                .compile(&document)
                .map_err(|source| crate::Error::Policy {
                    source,
                    location: snafu::location!(),
                })?;
        assert_eq!(compiled.mode, ProfileModeV1::Protect);
        assert_eq!(compiled.compiled_cells.len(), 37);
        assert_eq!(
            compiled
                .compiled_cells
                .iter()
                .filter(|cell| cell.physical_result == CompiledPhysicalResultV1::DenyEffect)
                .count(),
            11
        );
        assert_eq!(
            compiled
                .compiled_cells
                .iter()
                .filter(|cell| {
                    cell.key.effect_family == EffectFamilyV1::Privilege
                        && cell.key.operation_id == "IO_URING_SETUP"
                        && cell.key.object_selector == "DEFAULT"
                        && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
                })
                .count(),
            10
        );
        assert_eq!(
            compiled
                .compiled_cells
                .iter()
                .filter(|cell| cell.consuming_exception_id.is_some())
                .count(),
            2
        );
        Ok(())
    }
}
