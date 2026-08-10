mod child;
mod mailbox;
mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use mithril_control::PolicyArtifactOwner;
use mithril_node::{
    EffectObservationHealth, EffectObservationStore, ExactFileObjectResolver,
    NativeSecurityStateOwner, NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use self::child::EffectProcessFixture;
use self::support::{
    effect_binding, effect_node_config, external_bind_mount, external_unmount, health_delta,
    inode_generation, mount_view_is_dirty, observation_health, wait_for_reason,
};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

pub use child::run_effect_child;

pub(super) const PROFILE_GENERATION_REF_ID: u64 = 1;
pub(super) const EXACT_OBJECT_KEY_ID: u64 = 7;

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
    pub exact_open_observed: bool,
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
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub fixture_root_removed: bool,
}

pub struct EffectTestRunner {
    repo_root: PathBuf,
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
        PolicyArtifactOwner::default()
            .compile_and_sign(
                &manual.join("policy-v1.yaml"),
                &manual.join("seal-request.json"),
                &manual.join("test-signing-key.hex"),
                &artifact_path,
            )
            .context(PolicySnafu)?;

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
        fs::write(cgroup_path.join("cgroup.procs"), fixture.pid().to_string()).context(
            IoSnafu {
                path: cgroup_path.join("cgroup.procs"),
            },
        )?;
        let paths = fixture.setup()?;
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
        fixture.prepare_mount_race(&paths.source, &paths.mount_target, 8)?;

        let inode_generation = inode_generation(fixture.pid(), &paths.secret)?;
        let exact_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.secret,
            PROFILE_GENERATION_REF_ID,
            EXACT_OBJECT_KEY_ID,
            "MANUAL_SECRET".to_owned(),
            inode_generation,
        )
        .context(NodeSnafu)?;
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &manual,
            artifact_path,
            binding.clone(),
            exact_object.clone(),
        );

        host.shutdown().context(InterceptorSnafu)?;
        let mut host = KernelHostOwner::new(kernel_config)
            .start()
            .context(InterceptorSnafu)?;
        let mut recovered_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        recovered_bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        let policy =
            NodePolicyGenerationOwner::load_and_install(&node_config, &host, node_boot_id, 1)
                .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_with_effect_observation(&mut host, true)
            .context(NodeSnafu)?;
        let observations = EffectObservationStore::default();
        let sink = observations.clone();
        let reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;

        let original_marker = observations.recent().len();
        let original = fixture.open(&paths.secret)?;
        if !original.allowed {
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            return InvalidInputSnafu {
                path: &paths.secret,
                reason: format!(
                    "observe-only exact file decision changed the physical result; observed {:?}; expected file (mount_namespace={},mount_id={},device={},inode={},generation={},object={}); mount view dirty={}",
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
        wait_for_reason(&reader, &observations, original_marker, "WOULD_DENY")?;

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
            fixture.open(&paths.bind_alias)?.allowed,
            InvalidInputSnafu {
                path: &paths.bind_alias,
                reason: "later bind alias did not preserve the observe-only physical result",
            }
        );
        wait_for_reason(&reader, &observations, bind_marker, "WOULD_DENY")?;

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
            fixture.open(&paths.secret)?.allowed,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "failed protected mounts left the exact path permanently unavailable",
            }
        );
        wait_for_reason(&reader, &observations, reconciled_marker, "WOULD_DENY")?;

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
            fixture.open(&paths.secret)?.allowed,
            InvalidInputSnafu {
                path: &paths.secret,
                reason:
                    "the exact object did not recover after the hostile replacement was removed",
            }
        );
        wait_for_reason(&reader, &observations, restored_marker, "WOULD_DENY")?;

        let before_latency = observation_health(&host, &observations)?;
        let observed = fixture.open_many(&paths.secret, measured_opens)?;
        ensure!(
            observed.denied == 0
                && observed.other_errors == 0
                && observed.allowed == measured_opens,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "observe-only latency sample changed file-open results",
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
            saturation.denied == 0
                && saturation.other_errors == 0
                && saturation.allowed == saturation_opens,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "ring saturation changed observe-only file-open results",
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
            exact_open_observed: true,
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
