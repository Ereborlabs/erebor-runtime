use std::mem::{offset_of, size_of};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use erebor_interceptor::{EffectObservationReader, KernelHost};
use erebor_interceptor_abi::{MountSecurityViewStateV1, MountTopologyStateV1};
use mithril_node::{
    ContainerKindV1, EffectObservationHealth, EffectObservationStore, InterceptorConfig,
    NodeConfig, NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
};
use snafu::{ensure, ResultExt as _};

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
    binding: WorkloadBindingConfig,
    exact_object: mithril_node::ExactFileObjectConfig,
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
        runtime_observation: None,
        container_runtime: None,
        workload_bindings: vec![binding],
        policy_candidates: vec![PolicyCandidateConfig {
            artifact_path,
            public_key_path: manual.join("test-public-key.hex"),
        }],
        exact_file_objects: vec![exact_object],
    }
}

pub(super) fn effect_binding(cgroup_path: &Path) -> WorkloadBindingConfig {
    WorkloadBindingConfig {
        binding_id: "99999999-9999-4999-8999-999999999999".to_owned(),
        execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
        protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        workload_selector_id: "worker".to_owned(),
        profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        container_id: "c".repeat(64),
        pod_uid: "phase3-pod".to_owned(),
        sandbox_id: "phase3-sandbox".to_owned(),
        container_name: "worker".to_owned(),
        image_digest: "sha256:phase3-image".to_owned(),
        container_kind: ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: Some(cgroup_path.to_path_buf()),
        lifecycle_generation: 1,
        active_profile_generation_ref_id: PROFILE_GENERATION_REF_ID,
        initial_role_id: 1,
        external_role_id: 2,
        arm_initial_root: false,
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
        emitted: later.emitted.saturating_sub(earlier.emitted),
        lost: later.lost.saturating_sub(earlier.lost),
        unresolved: later.unresolved.saturating_sub(earlier.unresolved),
        decoder_errors: later.decoder_errors.saturating_sub(earlier.decoder_errors),
    }
}

pub(super) fn mount_view_is_dirty(host: &KernelHost, mount_namespace_inode: u64) -> Result<bool> {
    let bytes = host
        .lookup_map("mount_security_views", &mount_namespace_inode.to_ne_bytes())
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: Path::new("mount_security_views"),
                reason: "protected mount namespace has no security state",
            }
            .build()
        })?;
    ensure!(
        bytes.len() == size_of::<MountSecurityViewStateV1>(),
        InvalidInputSnafu {
            path: Path::new("mount_security_views"),
            reason: "mount security state has the wrong ABI size",
        }
    );
    Ok(bytes[offset_of!(MountSecurityViewStateV1, state)] == MountTopologyStateV1::Dirty as u8)
}

pub(super) fn wait_for_reason(
    reader: &EffectObservationReader,
    store: &EffectObservationStore,
    marker: usize,
    expected: &str,
) -> Result<()> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        reader
            .poll(Duration::from_millis(50))
            .context(InterceptorSnafu)?;
        if store
            .recent()
            .get(marker..)
            .is_some_and(|events| events.iter().any(|event| event.reason == expected))
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: format!(
                    "timed out waiting for reason {expected}; observed {:?}",
                    store
                        .recent()
                        .get(marker..)
                        .unwrap_or_default()
                        .iter()
                        .map(|event| event.reason.as_str())
                        .collect::<Vec<_>>()
                ),
            }
        );
    }
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

pub(super) fn external_bind_mount(pid: u32, source: &Path, target: &Path) -> Result<()> {
    run_nsenter_mount(pid, &["mount", "--bind"], source, target)
}

pub(super) fn external_unmount(pid: u32, target: &Path) -> Result<()> {
    let output = Command::new("nsenter")
        .args([
            "--target",
            &pid.to_string(),
            "--mount",
            "--",
            "umount",
            "--",
        ])
        .arg(target)
        .output()
        .context(IoSnafu {
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

fn run_nsenter_mount(pid: u32, command: &[&str], source: &Path, target: &Path) -> Result<()> {
    let output = Command::new("nsenter")
        .args(["--target", &pid.to_string(), "--mount", "--"])
        .args(command)
        .arg(source)
        .arg(target)
        .output()
        .context(IoSnafu {
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

#[cfg(test)]
mod tests {
    use mithril_node::EffectObservationHealth;

    use super::health_delta;

    #[test]
    fn health_delta_preserves_ring_accounting() {
        let before = EffectObservationHealth {
            attempted: 10,
            emitted: 8,
            lost: 2,
            unresolved: 1,
            decoder_errors: 0,
        };
        let after = EffectObservationHealth {
            attempted: 25,
            emitted: 17,
            lost: 8,
            unresolved: 3,
            decoder_errors: 0,
        };
        let delta = health_delta(after, before);
        assert_eq!(delta.attempted, delta.emitted + delta.lost);
        assert_eq!(delta.lost, 6);
    }
}
