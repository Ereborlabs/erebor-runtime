mod child;
mod mailbox;
mod support;

use std::fs;
use std::mem::{offset_of, size_of};
use std::path::{Path, PathBuf};
use std::time::Duration;

use erebor_interceptor::{EffectObservationReader, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1, KernelEffectFamilyV1,
    KernelEffectOperationV1,
};
use mithril_control::PolicyArtifactOwner;
use mithril_node::{
    EffectObservationHealth, EffectObservationStore, ExactFileObjectResolver,
    NativeSecurityStateOwner, NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use self::child::{EffectProcessFixture, HardClosedOperation};
use self::support::{
    compile_phase4_artifact, effect_binding, effect_node_config, external_bind_mount,
    external_unmount, health_delta, inode_generation, mount_view_is_dirty, observation_health,
    wait_for_reason,
};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

pub use child::run_effect_child;

pub(super) const PROFILE_GENERATION_REF_ID: u64 = 1;
pub(super) const EXACT_OBJECT_KEY_ID: u64 = 7;
pub(super) const BENIGN_OBJECT_KEY_ID: u64 = 8;
pub(super) const EXEC_OBJECT_KEY_ID: u64 = 9;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EffectHealthV1 {
    pub attempted: u64,
    pub emitted: u64,
    pub lost: u64,
    pub unresolved: u64,
    pub decoder_errors: u64,
}

impl From<EffectObservationHealth> for EffectHealthV1 {
    fn from(value: EffectObservationHealth) -> Self {
        Self {
            attempted: value.attempted,
            emitted: value.emitted,
            lost: value.lost,
            unresolved: value.unresolved,
            decoder_errors: value.decoder_errors,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub protect_mode: bool,
    pub exact_open_observed: bool,
    pub exact_open_denied_before_effect: bool,
    pub inherited_fd_read_denied: bool,
    pub file_mmap_denied: bool,
    pub benign_read_allowed: bool,
    pub exec_hard_closed: bool,
    pub anonymous_exec_hard_closed: bool,
    pub file_create_hard_closed: bool,
    pub file_setattr_hard_closed: bool,
    pub file_truncate_hard_closed: bool,
    pub file_unlink_hard_closed: bool,
    pub file_link_hard_closed: bool,
    pub file_rename_hard_closed: bool,
    pub ipc_hard_closed: bool,
    pub ptrace_hard_closed: bool,
    pub signal_hard_closed: bool,
    pub namespace_privilege_hard_closed: bool,
    pub device_ioctl_hard_closed: bool,
    pub bpf_hard_closed: bool,
    pub self_protection_hard_closed: bool,
    pub bounded_exception_maximum_uses: u32,
    pub bounded_exception_n_allows: bool,
    pub bounded_exception_n_plus_one_denied: bool,
    pub bounded_exception_expiry_denied: bool,
    pub bounded_exception_restart_preserved: bool,
    pub hard_link_alias_denied: bool,
    pub bind_alias_canonicalized: bool,
    pub protected_mount_race_denied: bool,
    pub external_mount_replacement_failed_closed: bool,
    pub exact_object_restored_after_reconciliation: bool,
    pub baseline_average_open_ns: u64,
    pub observed_average_open_ns: u64,
    pub measured_opens: u32,
    pub saturation_opens: u32,
    pub pre_saturation_health: EffectHealthV1,
    pub saturated_health: EffectHealthV1,
    pub saturation_preserved_network_denial: bool,
    pub saturation_preserved_benign_allow: bool,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub fixture_root_removed: bool,
}

pub struct EffectTestRunner {
    repo_root: PathBuf,
}

fn require_hard_close(
    fixture: &mut EffectProcessFixture,
    reader: &EffectObservationReader,
    observations: &EffectObservationStore,
    operation: HardClosedOperation,
    expected_reason: &str,
    expected_effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
    label: &str,
) -> Result<()> {
    let marker = observations.recent().len();
    ensure!(
        fixture.hard_closed(operation)?.denied(),
        InvalidInputSnafu {
            path: Path::new("live effect state"),
            reason: format!("{label} was not physically hard-closed"),
        }
    );
    wait_for_reason(reader, observations, marker, expected_reason)?;
    let recent = observations.recent();
    let observed = recent.get(marker..).unwrap_or_default();
    ensure!(
        observed.iter().any(|event| {
            event.reason == expected_reason
                && event.effect_family == u32::from(expected_effect.0 as u16)
                && event.operation == u32::from(expected_effect.1 as u16)
        }),
        InvalidInputSnafu {
            path: Path::new("effect_observations"),
            reason: format!(
                "{label} expected reason {expected_reason} at family {} operation {}; observed {:?}",
                expected_effect.0 as u16,
                expected_effect.1 as u16,
                observed
                    .iter()
                    .map(|event| (&event.reason, event.effect_family, event.operation))
                    .collect::<Vec<_>>()
            ),
        }
    );
    Ok(())
}

impl EffectTestRunner {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn physical_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        cgroup_path: &Path,
        measured_opens: u32,
        saturation_opens: u32,
        protect: bool,
    ) -> Result<EffectPhysicalProbeBundleV1> {
        ensure!(
            measured_opens > 0 && saturation_opens >= 30_000,
            InvalidInputSnafu {
                path: output_directory,
                reason:
                    "measured_opens must be nonzero and saturation_opens must be at least 30000",
            }
        );
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the dedicated effect-test pin root and lease must not already exist",
            }
        );
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let fixture_root = output_directory.join("effect-runtime");
        ensure!(
            !fixture_root.exists(),
            InvalidInputSnafu {
                path: &fixture_root,
                reason: "the effect-test runtime directory must not already exist",
            }
        );
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let fixture_cleanup = ProbeDirectory::new(&fixture_root);
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let cgroup_cleanup = ProbeCgroup::create(cgroup_path)?;
        let cgroup_path = cgroup_cleanup.path().to_path_buf();

        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: &self.repo_root,
        })?;
        let manual = repo_root.join("examples/mithril-phase3-manual");
        let artifact_path = fixture_root.join("profile.json");
        if protect {
            compile_phase4_artifact(
                &manual.join("policy-v1.yaml"),
                &manual.join("seal-request.json"),
                &manual.join("test-signing-key.hex"),
                &artifact_path,
            )?;
        } else {
            PolicyArtifactOwner::default()
                .compile_and_sign(
                    &manual.join("policy-v1.yaml"),
                    &manual.join("seal-request.json"),
                    &manual.join("test-signing-key.hex"),
                    &artifact_path,
                )
                .context(PolicySnafu)?;
        }

        let (boot_id, node_boot_id) = boot_identity()?;
        let kernel_config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        );
        let mut host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let binding = effect_binding(&cgroup_path);
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut host)
            .context(NodeSnafu)?;

        let mut fixture = EffectProcessFixture::start(&fixture_root)?;
        let paths = fixture.setup()?;
        let create_target = paths.mutation_root.join("forbidden-create");
        let setattr_target = paths.mutation_root.join("setattr-target");
        let truncate_target = paths.mutation_root.join("truncate-target");
        let unlink_target = paths.mutation_root.join("unlink-target");
        let mutation_source = paths.mutation_root.join("mutation-source");
        let link_target = paths.mutation_root.join("link-target");
        let rename_target = paths.mutation_root.join("rename-target");
        fixture.prepare_mount_race(&paths.source, &paths.mount_target, 8)?;
        fixture.prepare_hard_closed(&truncate_target, &paths.exec_target)?;
        let exec_inode_generation = inode_generation(fixture.pid(), &paths.exec_target)?;
        ensure!(
            fixture.hard_closed(HardClosedOperation::Exec)?.allowed,
            InvalidInputSnafu {
                path: &paths.exec_target,
                reason: "executable control failed before effect policy activation",
            }
        );
        if protect {
            fixture.prepare_write_race(&paths.secret, 8)?;
        }
        fs::write(cgroup_path.join("cgroup.procs"), fixture.pid().to_string()).context(
            IoSnafu {
                path: cgroup_path.join("cgroup.procs"),
            },
        )?;
        let baseline = fixture.open_many(&paths.secret, measured_opens)?;
        ensure!(
            baseline.denied == 0
                && baseline.other_errors == 0
                && baseline.allowed == measured_opens,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "baseline file opens failed before effect observation was enabled",
            }
        );
        if protect {
            fixture.prepare_file(&paths.secret)?;
        }
        let secret_inode_generation = inode_generation(fixture.pid(), &paths.secret)?;
        let exact_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.secret,
            PROFILE_GENERATION_REF_ID,
            EXACT_OBJECT_KEY_ID,
            "MANUAL_SECRET".to_owned(),
            secret_inode_generation,
        )
        .context(NodeSnafu)?;
        let benign_inode_generation = inode_generation(fixture.pid(), &paths.benign)?;
        let benign_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.benign,
            PROFILE_GENERATION_REF_ID,
            BENIGN_OBJECT_KEY_ID,
            "MANUAL_BENIGN".to_owned(),
            benign_inode_generation,
        )
        .context(NodeSnafu)?;
        let exec_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.exec_target,
            PROFILE_GENERATION_REF_ID,
            EXEC_OBJECT_KEY_ID,
            "MANUAL_EXEC".to_owned(),
            exec_inode_generation,
        )
        .context(NodeSnafu)?;
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &manual,
            artifact_path,
            binding.clone(),
            vec![exact_object.clone(), benign_object, exec_object],
        );

        host.shutdown().context(InterceptorSnafu)?;
        let mut host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let mut recovered_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        recovered_bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        let mut policy =
            NodePolicyGenerationOwner::load_and_install(&node_config, &host, node_boot_id, 1)
                .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        let observations = EffectObservationStore::default();
        let sink = observations.clone();
        let mut reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;

        if protect {
            let exception_marker = observations.recent().len();
            let exception_race = fixture.write_race(&paths.secret, 8)?;
            ensure!(
                exception_race.allowed == 2
                    && exception_race.denied == 6
                    && exception_race.other_errors == 0,
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: format!(
                        "concurrent bounded exception did not allow exactly N=2 uses: {exception_race:?}"
                    ),
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                exception_marker,
                "EXACT_POLICY_ALLOW",
            )?;
            wait_for_reason(
                &reader,
                &observations,
                exception_marker,
                "EXCEPTION_UNAVAILABLE",
            )?;
            let exception_events = observations.recent();
            let exception_events = exception_events.get(exception_marker..).unwrap_or_default();
            ensure!(
                exception_events
                    .iter()
                    .filter(|event| event.reason == "EXACT_POLICY_ALLOW")
                    .count()
                    == 2
                    && exception_events
                        .iter()
                        .filter(|event| event.reason == "EXCEPTION_UNAVAILABLE")
                        .count()
                        == 6,
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "concurrent bounded-exception evidence did not match N and N+1",
                }
            );
            let mut key = [0_u8; 16];
            key[..8].copy_from_slice(&PROFILE_GENERATION_REF_ID.to_ne_bytes());
            key[8..12].copy_from_slice(&1_u32.to_ne_bytes());
            let exception = host
                .lookup_map("exception_runtime_states", &key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: "bounded exception state disappeared after consumption",
                    }
                    .build()
                })?;
            ensure!(
                exception.len() == size_of::<ExceptionRuntimeStateV1>()
                    && u32::from_ne_bytes(
                        exception[offset_of!(ExceptionRuntimeStateV1, consumed_uses)
                            ..offset_of!(ExceptionRuntimeStateV1, consumed_uses) + 4]
                            .try_into()
                            .unwrap_or_default()
                    ) == 2
                    && exception[offset_of!(ExceptionRuntimeStateV1, state)]
                        == ExceptionRuntimeStateKindV1::Exhausted as u8,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "bounded exception did not finish in exact exhausted state",
                }
            );

            drop(reader);
            host.shutdown().context(InterceptorSnafu)?;
            host = KernelHostOwner::new(kernel_config.clone())
                .start()
                .context(InterceptorSnafu)?;
            policy =
                NodePolicyGenerationOwner::load_and_install(&node_config, &host, node_boot_id, 1)
                    .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate_with_effect_policy(&mut host, true)
                .context(NodeSnafu)?;
            let sink = observations.clone();
            reader = host
                .effect_observation_reader(move |bytes| {
                    sink.record_bytes(bytes);
                    0
                })
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("exception_runtime_states", &key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(exception.as_slice()),
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "loader restart changed the exhausted exception state",
                }
            );
            let restart_marker = observations.recent().len();
            ensure!(
                fixture.open_write(&paths.secret)?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "loader restart revived an exhausted bounded exception",
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                restart_marker,
                "EXCEPTION_UNAVAILABLE",
            )?;

            let mut expired_fixture = exception.clone();
            expired_fixture[offset_of!(ExceptionRuntimeStateV1, lock)
                ..offset_of!(ExceptionRuntimeStateV1, lock) + 4]
                .copy_from_slice(&0_u32.to_ne_bytes());
            expired_fixture[offset_of!(ExceptionRuntimeStateV1, consumed_uses)
                ..offset_of!(ExceptionRuntimeStateV1, consumed_uses) + 4]
                .copy_from_slice(&0_u32.to_ne_bytes());
            expired_fixture[offset_of!(ExceptionRuntimeStateV1, deadline_boottime_ns)
                ..offset_of!(ExceptionRuntimeStateV1, deadline_boottime_ns) + 8]
                .copy_from_slice(&0_u64.to_ne_bytes());
            expired_fixture[offset_of!(ExceptionRuntimeStateV1, state)] =
                ExceptionRuntimeStateKindV1::Active as u8;
            host.update_map("exception_runtime_states", &key, &expired_fixture)
                .context(InterceptorSnafu)?;
            let expiry_marker = observations.recent().len();
            ensure!(
                fixture.open_write(&paths.secret)?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "an expired bounded exception allowed a write-open",
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                expiry_marker,
                "EXCEPTION_UNAVAILABLE",
            )?;
            let expired = host
                .lookup_map("exception_runtime_states", &key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: "expired exception state disappeared",
                    }
                    .build()
                })?;
            ensure!(
                expired[offset_of!(ExceptionRuntimeStateV1, state)]
                    == ExceptionRuntimeStateKindV1::Expired as u8
                    && u32::from_ne_bytes(
                        expired[offset_of!(ExceptionRuntimeStateV1, consumed_uses)
                            ..offset_of!(ExceptionRuntimeStateV1, consumed_uses) + 4]
                            .try_into()
                            .unwrap_or_default()
                    ) == 0,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "expired exception was consumed or did not enter EXPIRED state",
                }
            );

            let inherited_marker = observations.recent().len();
            ensure!(
                fixture.read_prepared()?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "a descriptor acquired before activation bypassed the read decision",
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                inherited_marker,
                "EXACT_POLICY_DENY",
            )?;
            let mmap_marker = observations.recent().len();
            ensure!(
                fixture.mmap_prepared()?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "a descriptor acquired before activation bypassed the mmap decision",
                }
            );
            wait_for_reason(&reader, &observations, mmap_marker, "EXACT_POLICY_DENY")?;
        }

        let benign_marker = observations.recent().len();
        ensure!(
            fixture.read(&paths.benign)?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "the exact benign control did not remain readable",
            }
        );
        wait_for_reason(&reader, &observations, benign_marker, "EXACT_POLICY_ALLOW")?;

        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Exec,
            "EXACT_POLICY_DENY",
            (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
            "executable image",
        )?;
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::AnonymousExec,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Exec,
                KernelEffectOperationV1::Mprotect,
            ),
            "anonymous executable memory",
        )?;
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Create {
                path: create_target.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Create),
            "file creation",
        )?;
        ensure!(
            !create_target.exists(),
            InvalidInputSnafu {
                path: &create_target,
                reason: "denied creation left a filesystem object behind",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Setattr {
                path: setattr_target.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Setattr),
            "file attribute mutation",
        )?;
        ensure!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(&setattr_target)
                    .context(IoSnafu {
                        path: &setattr_target,
                    })?
                    .permissions()
            ) & 0o777
                == 0o600,
            InvalidInputSnafu {
                path: &setattr_target,
                reason: "denied chmod changed the file mode",
            }
        );
        let truncate_length = fs::metadata(&truncate_target)
            .context(IoSnafu {
                path: &truncate_target,
            })?
            .len();
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Truncate,
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Setattr),
            "file truncation",
        )?;
        ensure!(
            fs::metadata(&truncate_target)
                .context(IoSnafu {
                    path: &truncate_target,
                })?
                .len()
                == truncate_length,
            InvalidInputSnafu {
                path: &truncate_target,
                reason: "denied truncate changed the file length",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Unlink {
                path: unlink_target.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Unlink),
            "file unlink",
        )?;
        ensure!(
            unlink_target.exists(),
            InvalidInputSnafu {
                path: &unlink_target,
                reason: "denied unlink removed its target",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Link {
                source: mutation_source.clone(),
                target: link_target.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Link),
            "hard-link creation",
        )?;
        ensure!(
            !link_target.exists(),
            InvalidInputSnafu {
                path: &link_target,
                reason: "denied link created its target",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Rename {
                source: mutation_source.clone(),
                target: rename_target.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Rename),
            "file rename",
        )?;
        ensure!(
            mutation_source.exists() && !rename_target.exists(),
            InvalidInputSnafu {
                path: &rename_target,
                reason: "denied rename changed the source or target",
            }
        );
        for (operation, effect, label) in [
            (
                HardClosedOperation::Ipc,
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
                "SysV IPC access",
            ),
            (
                HardClosedOperation::Ptrace,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Ptrace,
                ),
                "ptrace process control",
            ),
            (
                HardClosedOperation::Signal,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Signal,
                ),
                "signal process control",
            ),
            (
                HardClosedOperation::Namespace,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Capability,
                ),
                "namespace privilege",
            ),
            (
                HardClosedOperation::Ioctl,
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                "device ioctl",
            ),
            (
                HardClosedOperation::Bpf,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Capability,
                ),
                "BPF map creation",
            ),
        ] {
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                operation,
                "UNSUPPORTED_OBJECT",
                effect,
                label,
            )?;
        }
        let protected_link = pin_root.join("links/erebor_identity_file_open");
        ensure!(
            protected_link.exists(),
            InvalidInputSnafu {
                path: &protected_link,
                reason: "the self-protection fixture link is not pinned",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::SelfProtect {
                path: protected_link.clone(),
            },
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Unlink),
            "Mithril BPF-link removal",
        )?;
        ensure!(
            protected_link.exists(),
            InvalidInputSnafu {
                path: &protected_link,
                reason: "denied self-protection attack removed the BPF link pin",
            }
        );

        let original_marker = observations.recent().len();
        let original = fixture.open(&paths.secret)?;
        if original.allowed == protect {
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            return InvalidInputSnafu {
                path: &paths.secret,
                reason: format!(
                    "exact file decision did not match protect={protect}; observed {:?}; expected file (mount_namespace={},mount_id={},device={},inode={},generation={},object={}); mount view dirty={}",
                    observations
                        .recent()
                        .get(original_marker..)
                        .unwrap_or_default()
                        .iter()
                        .map(|event| format!(
                            "{}(mount_namespace={},mount_id={},device={},inode={},generation={},object={},composite={})",
                            event.reason,
                            event.mount_namespace_inode,
                            event.mount_id_unique,
                            event.filesystem_device,
                            event.inode,
                            event.inode_generation,
                            event.exact_object_key_id,
                            event.composite_atom_id,
                        ))
                        .collect::<Vec<_>>(),
                    exact_object.mount_namespace_inode,
                    exact_object.mount_id_unique,
                    exact_object.filesystem_device,
                    exact_object.inode,
                    exact_object.inode_generation,
                    exact_object.exact_object_key_id,
                    mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?
                ),
            }
            .fail();
        }
        wait_for_reason(
            &reader,
            &observations,
            original_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
        )?;

        let hard_link_marker = observations.recent().len();
        let hard_link = fixture.open(&paths.hard_link)?;
        ensure!(
            hard_link.denied(),
            InvalidInputSnafu {
                path: &paths.hard_link,
                reason: "hard-link alias inherited the original path decision",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            hard_link_marker,
            "UNRESOLVED_OBJECT",
        )?;

        let bind_marker = observations.recent().len();
        ensure!(
            fixture.open(&paths.bind_alias)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.bind_alias,
                reason: "later bind alias did not preserve the exact policy result",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            bind_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
        )?;

        let mount_marker = observations.recent().len();
        let mount_race = fixture.mount_race(&paths.source, &paths.mount_target, 8)?;
        ensure!(
            mount_race.allowed == 0 && mount_race.denied == 8 && mount_race.other_errors == 0,
            InvalidInputSnafu {
                path: &paths.mount_target,
                reason: "one or more protected mount attempts escaped hard safety",
            }
        );
        wait_for_reason(&reader, &observations, mount_marker, "UNSUPPORTED_OBJECT")?;
        policy.reconcile_mount_views(&host).context(NodeSnafu)?;
        let reconciled_marker = observations.recent().len();
        ensure!(
            fixture.open(&paths.secret)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "failed protected mounts left the exact path permanently unavailable",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            reconciled_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
        )?;

        external_bind_mount(fixture.pid(), &paths.benign, &paths.secret)?;
        ensure!(
            mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?,
            InvalidInputSnafu {
                path: &paths.secret,
                reason:
                    "an external mount-namespace mutation did not mark the protected view DIRTY",
            }
        );
        let replacement_marker = observations.recent().len();
        ensure!(
            fixture.open(&paths.secret)?.denied(),
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "a replaced exact path was physically allowed while its topology was DIRTY",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            replacement_marker,
            "UNRESOLVED_OBJECT",
        )?;
        ensure!(
            policy.reconcile_mount_views(&host).is_err(),
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "reconciliation accepted a different object mounted over the exact path",
            }
        );
        external_unmount(fixture.pid(), &paths.secret)?;
        policy.reconcile_mount_views(&host).context(NodeSnafu)?;
        let restored_marker = observations.recent().len();
        ensure!(
            fixture.open(&paths.secret)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.secret,
                reason:
                    "the exact object did not recover after the hostile replacement was removed",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            restored_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
        )?;

        let before_latency = observation_health(&host, &observations)?;
        let observed = fixture.open_many(&paths.secret, measured_opens)?;
        ensure!(
            observed.other_errors == 0
                && if protect {
                    observed.denied == measured_opens && observed.allowed == 0
                } else {
                    observed.denied == 0 && observed.allowed == measured_opens
                },
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "latency sample did not preserve the selected policy mode",
            }
        );
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let pre_saturation = observation_health(&host, &observations)?;
        ensure!(
            health_delta(pre_saturation, before_latency).lost == 0
                && health_delta(pre_saturation, before_latency).attempted
                    == health_delta(pre_saturation, before_latency).emitted,
            InvalidInputSnafu {
                path: Path::new("effect_observation_health"),
                reason: "bounded latency measurement lost effect observations",
            }
        );

        let saturation = fixture.open_many(&paths.secret, saturation_opens)?;
        ensure!(
            saturation.other_errors == 0
                && if protect {
                    saturation.denied == saturation_opens && saturation.allowed == 0
                } else {
                    saturation.denied == 0 && saturation.allowed == saturation_opens
                },
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "ring saturation changed the selected policy result",
            }
        );
        let network = fixture.connect()?;
        ensure!(
            network.denied(),
            InvalidInputSnafu {
                path: Path::new("127.0.0.1:9"),
                reason: "ring saturation changed the unsupported-network hard denial",
            }
        );
        let benign_after_saturation = fixture.read(&paths.benign)?;
        ensure!(
            benign_after_saturation.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "ring saturation changed the exact benign allow decision",
            }
        );
        let saturated = observation_health(&host, &observations)?;
        let saturation_delta = health_delta(saturated, pre_saturation);
        ensure!(
            saturation_delta.lost > 0
                && saturation_delta.attempted
                    == saturation_delta
                        .emitted
                        .saturating_add(saturation_delta.lost),
            InvalidInputSnafu {
                path: Path::new("effect_observation_health"),
                reason: "ring saturation did not preserve exact attempted=emitted+lost accounting",
            }
        );

        fixture.stop()?;
        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        cgroup_cleanup.cleanup()?;
        fixture_cleanup.cleanup()?;
        ensure!(
            !pin_root.exists()
                && !lease_path.exists()
                && !cgroup_path.exists()
                && !fixture_root.exists(),
            InvalidInputSnafu {
                path: output_directory,
                reason: "the effect probe left a pin root, cgroup, or mount fixture behind",
            }
        );

        Ok(EffectPhysicalProbeBundleV1 {
            schema_version: 1,
            protect_mode: protect,
            exact_open_observed: true,
            exact_open_denied_before_effect: protect,
            inherited_fd_read_denied: protect,
            file_mmap_denied: protect,
            benign_read_allowed: true,
            exec_hard_closed: true,
            anonymous_exec_hard_closed: true,
            file_create_hard_closed: true,
            file_setattr_hard_closed: true,
            file_truncate_hard_closed: true,
            file_unlink_hard_closed: true,
            file_link_hard_closed: true,
            file_rename_hard_closed: true,
            ipc_hard_closed: true,
            ptrace_hard_closed: true,
            signal_hard_closed: true,
            namespace_privilege_hard_closed: true,
            device_ioctl_hard_closed: true,
            bpf_hard_closed: true,
            self_protection_hard_closed: true,
            bounded_exception_maximum_uses: if protect { 2 } else { 0 },
            bounded_exception_n_allows: protect,
            bounded_exception_n_plus_one_denied: protect,
            bounded_exception_expiry_denied: protect,
            bounded_exception_restart_preserved: protect,
            hard_link_alias_denied: true,
            bind_alias_canonicalized: true,
            protected_mount_race_denied: true,
            external_mount_replacement_failed_closed: true,
            exact_object_restored_after_reconciliation: true,
            baseline_average_open_ns: baseline.average_ns(),
            observed_average_open_ns: observed.average_ns(),
            measured_opens,
            saturation_opens,
            pre_saturation_health: pre_saturation.into(),
            saturated_health: saturated.into(),
            saturation_preserved_network_denial: true,
            saturation_preserved_benign_allow: true,
            pin_root_removed: true,
            lease_removed: true,
            cgroup_removed: true,
            fixture_root_removed: true,
        })
    }

    pub fn write_json<T: Serialize>(&self, output: &Path, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value).context(JsonSnafu { path: output })?;
        fs::write(output, bytes).context(IoSnafu { path: output })
    }
}
