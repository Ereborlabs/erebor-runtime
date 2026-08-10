use std::mem::{offset_of, size_of};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use erebor_interceptor::{EffectObservationReader, KernelHost};
use erebor_interceptor_abi::{MountSecurityViewStateV1, MountTopologyStateV1};
use mithril_control::{
    compiled_key_digest, BlastRadiusLimitV1, ExactExceptionSubjectSelectorV1,
    ExceptionConsumptionScopeV1, ExceptionV1, LocalObjectSelectorV1, PermittedAuthorityDeltaV1,
    PolicyCompiler, PolicyDispositionV1, PolicyDocumentV1, ProfileCandidateArtifactV1,
    ProfileModeV1, ProfileSealRequestV1, RuleMatchV1,
};
use mithril_node::{
    ContainerKindV1, EffectObservationHealth, EffectObservationStore, InterceptorConfig,
    NodeConfig, NodeControlConfig, PolicyCandidateConfig, WorkloadBindingConfig,
};
use snafu::{ensure, ResultExt as _};

use super::PROFILE_GENERATION_REF_ID;
use crate::error::{
    CommandSnafu, InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, PolicySnafu,
};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(5);

pub(super) fn compile_phase4_artifact(
    source_path: &Path,
    seal_request_path: &Path,
    signing_key_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let source = std::fs::read(source_path).context(IoSnafu { path: source_path })?;
    let mut document = PolicyDocumentV1::parse(source_path, &source).context(PolicySnafu)?;
    document.rollout.desired_profile_mode = ProfileModeV1::Protect;
    document
        .protected_universe
        .object_class_ids
        .push("MANUAL_BENIGN".to_owned());
    document.protected_universe.object_class_ids.sort();
    let mut benign_classifier = document.classifier_bindings[0].clone();
    benign_classifier.classifier_binding_id = "manual-benign".to_owned();
    benign_classifier.object_class_id = "MANUAL_BENIGN".to_owned();
    document.classifier_bindings.push(benign_classifier);
    let mut benign_allow = document.rules[0].clone();
    benign_allow.rule_id = "allow-manual-benign-read".to_owned();
    benign_allow.requested_disposition = PolicyDispositionV1::Allow;
    benign_allow.errno = None;
    benign_allow.finding = None;
    benign_allow.exception_ids.clear();
    let RuleMatchV1::LocalPreEffect(benign_effect) = &mut benign_allow.rule_match else {
        return InvalidInputSnafu {
            path: source_path,
            reason: "Phase 4 benign control is not a local pre-effect rule",
        }
        .fail();
    };
    benign_effect.operation_ids = ["MMAP_READ", "OPEN_READ", "READ"]
        .map(str::to_owned)
        .to_vec();
    benign_effect.object = LocalObjectSelectorV1::ObjectClasses {
        object_class_ids: vec!["MANUAL_BENIGN".to_owned()],
    };
    document.rules.push(benign_allow);
    let mut bounded_allow = document.rules[0].clone();
    bounded_allow.rule_id = "allow-bounded-secret-write-open".to_owned();
    bounded_allow.requested_disposition = PolicyDispositionV1::Allow;
    bounded_allow.errno = None;
    bounded_allow.finding = None;
    bounded_allow.exception_ids.clear();
    let RuleMatchV1::LocalPreEffect(deny_effect) = &mut document.rules[0].rule_match else {
        return InvalidInputSnafu {
            path: source_path,
            reason: "Phase 4 fixture needs one local pre-effect rule",
        }
        .fail();
    };
    deny_effect.operation_ids = ["MMAP_READ", "OPEN_READ", "READ"]
        .map(str::to_owned)
        .to_vec();
    let RuleMatchV1::LocalPreEffect(allow_effect) = &mut bounded_allow.rule_match else {
        return InvalidInputSnafu {
            path: source_path,
            reason: "Phase 4 bounded allow is not a local pre-effect rule",
        }
        .fail();
    };
    allow_effect.operation_ids = vec!["OPEN_WRITE".to_owned()];
    let bounded_rule_index = document.rules.len();
    document.rules.push(bounded_allow);
    let preliminary = PolicyCompiler.compile(&document).context(PolicySnafu)?;
    let allow_cell = preliminary
        .compiled_cells
        .iter()
        .find(|cell| {
            cell.source_rule_ids == ["allow-bounded-secret-write-open"]
                && cell.key.operation_id == "OPEN_WRITE"
        })
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: source_path,
                reason: "Phase 4 fixture did not compile its bounded write-open cell",
            }
            .build()
        })?;
    let exception_id = "bounded-secret-write-open";
    let allow_cell_digest =
        compiled_key_digest(document.profile_id(), &allow_cell.key).context(PolicySnafu)?;
    document.exceptions.push(ExceptionV1 {
        exception_id: exception_id.to_owned(),
        exception_instance_id: "88888888-8888-4888-8888-888888888889".to_owned(),
        changed_rule_ids: vec!["allow-bounded-secret-write-open".to_owned()],
        exact_subject: ExactExceptionSubjectSelectorV1 {
            protected_scope_ids: vec![allow_cell.key.protected_scope_id.clone()],
            execution_set_ids: vec![allow_cell.key.execution_set_id.clone()],
            entry_kind_ids: vec![allow_cell.key.entry_kind],
            role_ids: vec![allow_cell.key.role_id.clone()],
            immutable_definition_digests: vec![],
            exact_compiled_key_digests: vec![allow_cell_digest.clone()],
        },
        authority_delta: PermittedAuthorityDeltaV1 {
            from_physical_result: "DENY_ERRNO".to_owned(),
            to_physical_result: "ALLOW_EFFECT".to_owned(),
            added_or_removed_operation_cells: vec![allow_cell_digest],
            added_or_removed_transition_cells: vec![],
            maximum_blast_radius: BlastRadiusLimitV1::Local {
                permitted_target_selector_ids: vec![],
                process_count: 1,
                execution_set_count: 1,
                socket_count: 1,
                node_count: 1,
            },
        },
        approver_principal_id: "99999999-9999-4999-8999-999999999999".to_owned(),
        approval_proof_digest: "a".repeat(64),
        closed_reason_code: "BOUNDED_SECRET_WRITE_OPEN".to_owned(),
        valid_from_utc_ns: 1,
        valid_until_utc_ns: i64::MAX,
        consumption_scope: ExceptionConsumptionScopeV1::PerTargetNode,
        maximum_uses: 2,
        maximum_lifetime_ns: 60 * 60 * 1_000_000_000,
    });
    document.rules[bounded_rule_index]
        .exception_ids
        .push(exception_id.to_owned());
    let compiled = PolicyCompiler.compile(&document).context(PolicySnafu)?;
    let request: ProfileSealRequestV1 =
        serde_json::from_slice(&std::fs::read(seal_request_path).context(IoSnafu {
            path: seal_request_path,
        })?)
        .context(JsonSnafu {
            path: seal_request_path,
        })?;
    let key_text = std::fs::read_to_string(signing_key_path).context(IoSnafu {
        path: signing_key_path,
    })?;
    let key_bytes: [u8; 32] = hex::decode(key_text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: signing_key_path,
                reason: "Phase 4 signing key must be exactly 32 lowercase-hex bytes",
            }
            .build()
        })?;
    let artifact = ProfileCandidateArtifactV1::sign(
        &document,
        compiled,
        request,
        &SigningKey::from_bytes(&key_bytes),
    )
    .context(PolicySnafu)?;
    let bytes = serde_json::to_vec_pretty(&artifact).context(JsonSnafu { path: output_path })?;
    std::fs::write(output_path, bytes).context(IoSnafu { path: output_path })
}

pub(super) fn effect_node_config(
    state_directory: &Path,
    pin_root: &Path,
    lease_path: &Path,
    manual: &Path,
    artifact_path: PathBuf,
    binding: WorkloadBindingConfig,
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
        runtime_observation: None,
        container_runtime: None,
        workload_bindings: vec![binding],
        policy_candidates: vec![PolicyCandidateConfig {
            artifact_path,
            public_key_path: manual.join("test-public-key.hex"),
        }],
        exact_file_objects,
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

pub(super) fn mount_view_is_dirty(host: &KernelHost, mount_namespace_inode: u32) -> Result<bool> {
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
    use std::path::PathBuf;

    use mithril_control::{
        compiled_key_digest, CompiledPhysicalResultV1, PolicyArtifactOwner, PolicyCompiler,
        PolicyDocumentV1, ProfileModeV1,
    };
    use mithril_node::EffectObservationHealth;

    use super::{compile_phase4_artifact, health_delta};

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

    #[test]
    fn phase4_fixture_is_a_verified_protect_artifact() -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manual = repository.join("examples/mithril-phase3-manual");
        let directory = tempfile::tempdir()?;
        let artifact_path = directory.path().join("phase4-profile.json");
        compile_phase4_artifact(
            &manual.join("policy-v1.yaml"),
            &manual.join("seal-request.json"),
            &manual.join("test-signing-key.hex"),
            &artifact_path,
        )?;
        let artifact = PolicyArtifactOwner::default()
            .load_verified(&artifact_path, &manual.join("test-public-key.hex"))?;

        assert_eq!(artifact.compiled_profile.mode, ProfileModeV1::Protect);
        assert_eq!(
            artifact
                .compiled_profile
                .compiled_cells
                .iter()
                .filter(|cell| cell.physical_result == CompiledPhysicalResultV1::DenyEffect)
                .count(),
            3
        );
        assert_eq!(
            artifact
                .compiled_profile
                .compiled_cells
                .iter()
                .filter(|cell| cell.consuming_exception_id.is_some())
                .count(),
            1
        );
        let exception_cell = artifact
            .compiled_profile
            .compiled_cells
            .iter()
            .find(|cell| cell.consuming_exception_id.is_some())
            .ok_or("Phase 4 fixture has no exception cell")?;
        assert_eq!(
            compiled_key_digest(&artifact.compiled_profile.profile_id, &exception_cell.key)?,
            "eb7614f22732c8edcac2e55060444472180eb11ab3e34a9ea10c3514d8d16fb3"
        );
        Ok(())
    }

    #[test]
    fn checked_in_phase4_manual_policy_matches_the_automated_fixture() -> crate::Result<()> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = repository.join("examples/mithril-phase4-manual/policy-v1.yaml");
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
        assert_eq!(compiled.compiled_cells.len(), 7);
        assert_eq!(
            compiled
                .compiled_cells
                .iter()
                .filter(|cell| cell.physical_result == CompiledPhysicalResultV1::DenyEffect)
                .count(),
            3
        );
        assert_eq!(
            compiled
                .compiled_cells
                .iter()
                .filter(|cell| cell.consuming_exception_id.is_some())
                .count(),
            1
        );
        Ok(())
    }
}
