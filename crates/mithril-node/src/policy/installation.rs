use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{Id128V1, PolicyGenerationModeV1};
use mithril_control::{
    AntiRollbackStore, PolicyArtifactOwner, ProfileCandidateArtifactV1,
    RollbackAuthorizationArtifactV1, ValidatedProfileCandidateV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use super::{
    build_process_generation_migrations, current_boottime_ns, current_utc_ns, install_rows,
    mount_epoch_from, parse_id, preflight_policy_map_capacity, prepare_declared_entry_requests,
    reconcile_generation_retirement, reconcile_pending_activations,
    retire_undeclared_entry_requests, stable_node_id, ExceptionAuthorityOwner, GenerationBinding,
    GenerationHandleAllocator, GenerationSemantics, LoweredGeneration, MeasuredMountRouteV1,
    NodeDiscoveryContextCatalog, NodePolicyGenerationOwner, ProfileActivation,
};
use crate::error::{IdentityStateSnafu, InterceptorSnafu, PolicySnafu};
use crate::exact_object::ExactFileObjectView;
use crate::{ExactFileObjectConfig, NodeConfig, Result};

struct Candidate {
    artifact: ProfileCandidateArtifactV1,
    rollback: Option<(RollbackAuthorizationArtifactV1, VerifyingKey)>,
}

pub(super) struct Candidates {
    artifacts: BTreeMap<String, Candidate>,
}

impl Candidates {
    pub(super) fn load(config: &NodeConfig) -> Result<Self> {
        let owner = PolicyArtifactOwner::default();
        let now_utc_ns = current_utc_ns()?;
        let mut artifacts = BTreeMap::new();
        for candidate in &config.policy_candidates {
            let artifact = owner
                .load_verified_at(
                    &candidate.artifact_path,
                    &candidate.public_key_path,
                    now_utc_ns,
                )
                .context(PolicySnafu)?;
            let rollback = match (
                candidate.rollback_authorization_path.as_deref(),
                candidate.rollback_public_key_path.as_deref(),
            ) {
                (Some(artifact_path), Some(public_key_path)) => Some(
                    owner
                        .load_verified_rollback(artifact_path, public_key_path)
                        .context(PolicySnafu)?,
                ),
                (None, None) => None,
                _ => unreachable!("NodeConfig validation requires a complete rollback pair"),
            };
            ensure!(
                artifacts
                    .insert(
                        artifact.header.profile_id.clone(),
                        Candidate { artifact, rollback }
                    )
                    .is_none(),
                IdentityStateSnafu {
                    reason: "one node candidate is allowed per profile ID",
                }
            );
        }
        Ok(Self { artifacts })
    }

    pub(super) fn artifact(&self, profile_id: &str) -> Option<&ProfileCandidateArtifactV1> {
        self.artifacts
            .get(profile_id)
            .map(|candidate| &candidate.artifact)
    }

    fn validate_time(&self, now_utc_ns: i64) -> Result<()> {
        for candidate in self.artifacts.values() {
            candidate
                .artifact
                .validate_time(now_utc_ns)
                .context(PolicySnafu)?;
        }
        Ok(())
    }
}

pub(super) struct PolicyInput {
    pub(super) candidates: Candidates,
    pub(super) measured: PolicyMeasurements,
    pub(super) semantics: BTreeMap<u64, GenerationSemantics>,
    pub(super) deferred: BTreeSet<String>,
}

#[derive(Clone, Default)]
pub(super) struct BindingMeasurements {
    pub(super) objects: Vec<ExactFileObjectConfig>,
    pub(super) routes: Vec<MeasuredMountRouteV1>,
}

#[derive(Default)]
pub(super) struct PolicyMeasurements {
    pub(super) bindings: BTreeMap<String, BindingMeasurements>,
    pub(super) views: BTreeMap<u32, ExactFileObjectView>,
}

#[derive(Clone)]
pub(super) struct MountRootReconciliation {
    pub(super) configured: ExactFileObjectConfig,
    pub(super) canonical_path: PathBuf,
}

pub(super) fn same_exact_file(left: &ExactFileObjectConfig, right: &ExactFileObjectConfig) -> bool {
    left.mount_namespace_inode == right.mount_namespace_inode
        && left.mount_id_unique == right.mount_id_unique
        && left.filesystem_device == right.filesystem_device
        && left.inode == right.inode
        && left.inode_generation == right.inode_generation
}

struct ProfileBindings<'a> {
    candidate: &'a Candidate,
    activation: ProfileActivation,
    bindings: Vec<GenerationBinding<'a>>,
}

struct ProfileOperation {
    candidate: ValidatedProfileCandidateV1,
    activation: ProfileActivation,
    generation: LoweredGeneration,
}

impl NodePolicyGenerationOwner {
    pub(super) fn install(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        input: PolicyInput,
    ) -> Result<Self> {
        let PolicyInput {
            candidates,
            mut measured,
            mut semantics,
            deferred,
        } = input;
        let platform_scope_digest = format!(
            "{:x}",
            Sha256::digest(
                [
                    host.manifest().preflight.kernel_release.as_bytes(),
                    host.manifest().preflight.runtime_btf_sha256.as_bytes(),
                    host.manifest().object_sha256.as_bytes(),
                ]
                .concat()
            )
        );
        let now_utc_ns = current_utc_ns()?;
        let now_boottime_ns = current_boottime_ns()?;
        candidates.validate_time(now_utc_ns)?;
        let mut rollback =
            AntiRollbackStore::load(config.state_directory.join("policy-anti-rollback-v1.json"))
                .context(PolicySnafu)?;
        reconcile_pending_activations(host, &mut rollback, node_boot_id, label_epoch)?;
        let mut profiles = BTreeMap::<Id128V1, ProfileBindings<'_>>::new();
        let mut context = NodeDiscoveryContextCatalog::default();
        let node_id = stable_node_id(&config.node_id)?;
        for binding in &config.workload_bindings {
            let candidate = candidates
                .artifacts
                .get(&binding.profile_id)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "binding `{}` has no verified candidate for profile `{}`",
                            binding.binding_id, binding.profile_id
                        ),
                    }
                    .build()
                })?;
            let artifact = &candidate.artifact;
            let profile_id = parse_id("profile_id", &binding.profile_id)?;
            let profile = match profiles.entry(profile_id) {
                Entry::Vacant(entry) => {
                    let mut activation = ProfileActivation {
                        generation: binding.active_profile_generation_ref_id,
                        bindings: BTreeMap::new(),
                    };
                    activation
                        .add_binding(parse_id("binding_id", &binding.binding_id)?, binding)?;
                    entry.insert(ProfileBindings {
                        candidate,
                        activation,
                        bindings: Vec::new(),
                    })
                }
                Entry::Occupied(entry) => {
                    let profile = entry.into_mut();
                    profile
                        .activation
                        .add_binding(parse_id("binding_id", &binding.binding_id)?, binding)?;
                    profile
                }
            };
            let measurements = measured.bindings.get(&binding.binding_id);
            let objects = measurements
                .map(|record| record.objects.as_slice())
                .unwrap_or_default();
            let routes = measurements
                .map(|record| record.routes.as_slice())
                .unwrap_or_default();
            profile.bindings.push(GenerationBinding {
                config: binding,
                objects,
                routes,
                deferred: deferred.contains(&binding.binding_id) && measurements.is_none(),
            });
            context.add_verified_binding(artifact, binding, objects, node_boot_id);
        }
        let mut profiles = profiles.into_values().collect::<Vec<_>>();
        profiles.sort_by_key(|profile| profile.activation.generation);
        ensure!(
            profiles
                .windows(2)
                .all(|pair| pair[0].activation.generation != pair[1].activation.generation),
            IdentityStateSnafu {
                reason: "one generation handle cannot name different candidate artifacts",
            }
        );
        let profiles = profiles
            .into_iter()
            .map(|profile| {
                let candidate = profile.candidate;
                Ok(ProfileOperation {
                    candidate: rollback
                        .validate(
                            &candidate.artifact,
                            candidate.rollback.as_ref().map(|(proof, key)| (proof, key)),
                            &platform_scope_digest,
                            now_utc_ns,
                        )
                        .context(PolicySnafu)?,
                    generation: LoweredGeneration::compile(
                        &candidate.artifact,
                        profile.activation.generation,
                        &profile.bindings,
                        node_boot_id,
                        node_id,
                        label_epoch,
                        now_utc_ns,
                        now_boottime_ns,
                    )?,
                    activation: profile.activation,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let requests = profiles
            .iter()
            .flat_map(|profile| profile.generation.requests.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut generation_allocator = GenerationHandleAllocator::load(
            config.state_directory.join("generation-handles-v1.json"),
            host,
            node_boot_id,
            label_epoch,
        )?;
        for profile in &profiles {
            let generation = &profile.generation;
            generation_allocator.reserve(&generation.descriptor)?;
            if let Some(existing) = semantics.insert(
                generation.descriptor.profile_generation_ref_id,
                generation.semantics.clone(),
            ) {
                ensure!(
                    existing == generation.semantics,
                    IdentityStateSnafu {
                        reason: "one generation handle has different retained semantics",
                    }
                );
            }
        }
        let mut profile_order = profiles.iter().collect::<Vec<_>>();
        profile_order.sort_by_key(|profile| profile.generation.descriptor.profile_id);
        let migrations = build_process_generation_migrations(
            profile_order.iter().map(|profile| {
                (
                    &profile.generation.descriptor.profile_id,
                    &profile.activation,
                )
            }),
            &semantics,
        )?;
        preflight_policy_map_capacity(
            host,
            profiles.iter().map(|profile| &profile.generation),
            profile_order.iter().map(|profile| {
                (
                    &profile.generation.descriptor.profile_id,
                    &profile.activation,
                )
            }),
            &migrations,
        )?;
        let mount_roots = profiles
            .iter()
            .flat_map(|profile| profile.generation.mount_reconciliation.iter().cloned())
            .collect::<Vec<_>>();
        measured.prepare_views(&mount_roots)?;
        let mut authority =
            ExceptionAuthorityOwner::load(&config.state_directory, node_id, node_boot_id)?;
        prepare_declared_entry_requests(host, &requests)?;
        authority.restore_receipts(host)?;
        measured.install_barrier(host, &mount_roots)?;
        for profile in &profiles {
            let generation = &profile.generation;
            generation.install(host, &mut authority, now_utc_ns, now_boottime_ns)?;
            generation.probe_staged_rows(host)?;
        }
        install_rows(host, "process_generation_migrations", &migrations)?;
        for profile in profile_order {
            profile.activation.publish(
                host,
                &profile.generation.descriptor.profile_id,
                &mut rollback,
                &profile.candidate,
                node_boot_id,
                label_epoch,
            )?;
        }
        authority.reconcile(host, now_utc_ns)?;
        let retirement_pending = reconcile_generation_retirement(host, node_boot_id, label_epoch)?;
        let mut generation_semantics = BTreeMap::new();
        for (generation, semantics) in semantics {
            if host
                .lookup_map("profile_generation_descriptors", &generation.to_ne_bytes())
                .context(InterceptorSnafu)?
                .is_some()
            {
                generation_semantics.insert(generation, semantics);
            }
        }
        retire_undeclared_entry_requests(host, &requests)?;
        let administrative_plans = profiles
            .iter()
            .flat_map(|profile| profile.generation.administrative_plans.iter().cloned())
            .collect();
        let dynamic_rows =
            Self::dynamic_generation_rows(profiles.iter().map(|profile| &profile.generation));
        let owner = Self {
            node_boot_id,
            label_epoch,
            prevention_enabled: profiles.iter().any(|profile| {
                profile.generation.descriptor.mode == PolicyGenerationModeV1::Protect
            }),
            administrative_plans,
            measured,
            generation_semantics,
            discovery_context: Arc::new(context),
            dynamic_rows,
            exception_authority: Mutex::new(authority),
            retirement_pending: AtomicBool::new(retirement_pending),
        };
        let publication: Result<()> = (|| {
            for profile in &profiles {
                profile.generation.install_entry_admissions(host)?;
            }
            Ok(())
        })();
        if publication.is_err() {
            for profile in &profiles {
                profile.generation.revoke_entry_admissions(host)?;
            }
        }
        publication?;
        Ok(owner)
    }
}

impl PolicyMeasurements {
    fn install_barrier(&self, host: &KernelHost, roots: &[MountRootReconciliation]) -> Result<()> {
        let key = 0_u32.to_ne_bytes();
        let zero = 0_u64.to_ne_bytes();
        let topology_generation = roots
            .iter()
            .map(|root| root.configured.mount_topology_generation)
            .max()
            .unwrap_or(1)
            .max(1);
        if host
            .lookup_map("mount_global_mutation_epoch", &key)
            .context(InterceptorSnafu)?
            .is_none()
        {
            host.update_map(
                "mount_global_mutation_epoch",
                &key,
                &topology_generation.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?;
        }
        for map in ["mount_global_clean_epoch", "mount_global_pending_mutations"] {
            if host
                .lookup_map(map, &key)
                .context(InterceptorSnafu)?
                .is_none()
            {
                host.update_map(map, &key, &zero)
                    .context(InterceptorSnafu)?;
            }
        }
        for map in [
            "canonical_mount_cache_generation",
            "mount_global_activity_sequence",
            "mount_global_ambiguous_epoch",
        ] {
            if host
                .lookup_map(map, &key)
                .context(InterceptorSnafu)?
                .is_none()
            {
                host.update_map(map, &key, &1_u64.to_ne_bytes())
                    .context(InterceptorSnafu)?;
            }
        }
        let epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &key)?;
        let clean = mount_epoch_from(host, "mount_global_clean_epoch", &key)?;
        let pending = mount_epoch_from(host, "mount_global_pending_mutations", &key)?;
        ensure!(
            epoch != 0
                && clean <= epoch
                && pending == 0
                && mount_epoch_from(host, "canonical_mount_cache_generation", &key)? != 0
                && mount_epoch_from(host, "mount_global_activity_sequence", &key)? != 0
                && mount_epoch_from(host, "mount_global_ambiguous_epoch", &key)? != 0,
            IdentityStateSnafu {
                reason: "global mount security barrier readback is invalid",
            }
        );
        Ok(())
    }

    fn validate_view(
        view: &ExactFileObjectView,
        planned: &MountRootReconciliation,
        retained: bool,
    ) -> Result<()> {
        let configured = &planned.configured;
        let resolved = view.resolve(
            &planned.canonical_path,
            configured.profile_generation_ref_id,
            configured.exact_object_key_id,
            configured.object_class_id.clone(),
            configured.inode_generation,
            configured
                .device
                .as_ref()
                .map(|device| device.device_class_id.clone()),
        )?;
        ensure!(
            same_exact_file(configured, &resolved)
                && resolved.canonical_component_hex == configured.canonical_component_hex
                && resolved.mount_relative_component_count == configured.mount_relative_component_count
                && (retained
                    || resolved.mount_snapshot_digest_id == configured.mount_snapshot_digest_id),
            IdentityStateSnafu {
                reason: format!(
                    "mount view differs from exact authority for {}: retained={retained}, configured mount/inode={}/{}, resolved mount/inode={}/{}",
                    planned.canonical_path.display(),
                    configured.mount_id_unique,
                    configured.inode,
                    resolved.mount_id_unique,
                    resolved.inode,
                ),
            }
        );
        Ok(())
    }

    fn prepare_views(&mut self, roots: &[MountRootReconciliation]) -> Result<()> {
        let roots = roots.iter().map(|root| {
            (
                root.configured.mount_namespace_inode,
                root.configured.mount_view_root_pid,
                Some(root),
            )
        });
        let routes = self
            .bindings
            .values()
            .flat_map(|record| &record.routes)
            .map(|route| {
                (
                    route.route.mount_namespace_inode,
                    route.mount_view_root_pid,
                    None,
                )
            });
        let mut held = BTreeMap::new();
        for (namespace, root_pid, root) in roots.chain(routes) {
            let (pid, retained, view) = match held.entry(namespace) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let retained = self.views.remove(&namespace);
                    let was_retained = retained.is_some();
                    let view = match retained {
                        Some(view) => view,
                        None => ExactFileObjectView::acquire(root_pid)?,
                    };
                    ensure!(
                        view.mount_namespace_inode()? == namespace,
                        IdentityStateSnafu {
                            reason:
                                "held mount namespace differs from the configured security view",
                        }
                    );
                    entry.insert((root_pid, was_retained, view))
                }
            };
            ensure!(
                *pid == root_pid,
                IdentityStateSnafu {
                    reason: "one mount security view has multiple live root processes",
                }
            );
            if let Some(root) = root {
                Self::validate_view(view, root, *retained)?;
            }
        }
        self.views = held
            .into_iter()
            .map(|(namespace, (_, _, view))| (namespace, view))
            .collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use snafu::OptionExt as _;

    use super::*;

    #[test]
    fn mount_views_keep_identity() -> Result<()> {
        let pid = std::process::id();
        let view = ExactFileObjectView::acquire(pid)?;
        let namespace = view.mount_namespace_inode()?;
        let measured = MeasuredMountRouteV1 {
            binding_id: "test-binding".to_owned(),
            mount_view_root_pid: pid,
            mount_topology_generation: 1,
            // Handle preparation reads only the namespace and root PID.
            route: crate::exact_object::LiveMountRootRouteV1 {
                mount_namespace_inode: namespace,
                mountpoint_components: Vec::new(),
                filesystem_device: 0,
                root_inode: 0,
                selected_mount_id_unique: 0,
                mount_snapshot_digest_id: 0,
            },
        };
        let mut inputs = PolicyMeasurements {
            bindings: BTreeMap::from([(
                measured.binding_id.clone(),
                BindingMeasurements {
                    routes: vec![measured.clone(), measured],
                    ..BindingMeasurements::default()
                },
            )]),
            ..PolicyMeasurements::default()
        };

        // Repeated routes share one handle, on both initial preparation and reuse.
        inputs.prepare_views(&[])?;
        assert_eq!(inputs.views.len(), 1);
        assert_eq!(inputs.views[&namespace].mount_namespace_inode()?, namespace);
        inputs.prepare_views(&[])?;
        assert_eq!(inputs.views.len(), 1);

        inputs
            .bindings
            .get_mut("test-binding")
            .context(IdentityStateSnafu {
                reason: "test binding has no measurements",
            })?
            .routes[1]
            .mount_view_root_pid = pid + 1;
        let error = inputs
            .prepare_views(&[])
            .err()
            .context(IdentityStateSnafu {
                reason: "unequal root processes were accepted for one mount view",
            })?;
        assert!(error.to_string().contains("multiple live root processes"));

        let routes = &mut inputs
            .bindings
            .get_mut("test-binding")
            .context(IdentityStateSnafu {
                reason: "test binding has no measurements",
            })?
            .routes;
        routes.truncate(1);
        routes[0].route.mount_namespace_inode ^= 1;
        let error = inputs
            .prepare_views(&[])
            .err()
            .context(IdentityStateSnafu {
                reason: "a different mount namespace was accepted",
            })?;
        assert!(error.to_string().contains("held mount namespace differs"));
        Ok(())
    }
}
