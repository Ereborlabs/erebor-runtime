use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::sync::{atomic::AtomicBool, Mutex};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{DeclaredEntryRequestV1, Id128V1, PolicyGenerationModeV1};
use mithril_control::{AntiRollbackStore, PolicyArtifactOwner, ValidatedProfileCandidateV1};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::IntoBytes as _;

use super::{
    activate_profile, add_binding_activation, build_process_generation_migrations,
    current_boottime_ns, current_utc_ns, entry_admission_path_selector_ids,
    install_global_mount_barrier, install_rows, parse_id, preflight_policy_map_capacity,
    prepare_declared_entry_requests, reconcile_generation_retirement,
    reconcile_pending_activations, retire_undeclared_entry_requests, stable_node_id,
    validate_mount_view, ExceptionAuthorityOwner, GenerationHandleAllocator, GenerationRows,
    GenerationSemantics, LoweredGeneration, MeasuredExactObjectV1, MeasuredMountRouteV1,
    MountRootReconciliation, NodePolicyGenerationOwner, ProfileActivation,
};
use crate::error::{IdentityStateSnafu, InterceptorSnafu, PolicySnafu};
use crate::exact_object::ExactFileObjectView;
use crate::{NodeConfig, Result};

#[derive(Default)]
pub(super) struct PolicyMeasurements {
    pub(super) objects: Vec<MeasuredExactObjectV1>,
    pub(super) routes: Vec<MeasuredMountRouteV1>,
    pub(super) views: BTreeMap<u32, ExactFileObjectView>,
    pub(super) resolved: BTreeSet<String>,
}

struct PreparedProfile {
    id: Id128V1,
    activation: ProfileActivation,
    candidate: ValidatedProfileCandidateV1,
}

pub(super) struct PreparedPolicy {
    node_boot_id: Id128V1,
    label_epoch: u64,
    now_utc_ns: i64,
    now_boottime_ns: u64,
    measured: PolicyMeasurements,
    generations: BTreeMap<u64, LoweredGeneration>,
    profiles: Vec<PreparedProfile>,
    semantics: BTreeMap<u64, GenerationSemantics>,
    migrations: GenerationRows,
    requests: BTreeSet<Vec<u8>>,
    mount_roots: Vec<MountRootReconciliation>,
    rollback: AntiRollbackStore,
    authority: ExceptionAuthorityOwner,
}

impl PreparedPolicy {
    pub(super) fn prepare(
        config: &NodeConfig,
        host: &KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        mut measured: PolicyMeasurements,
        mut semantics: BTreeMap<u64, GenerationSemantics>,
        deferred: BTreeSet<String>,
    ) -> Result<Self> {
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
        let artifact_owner = PolicyArtifactOwner::default();
        let mut artifacts = BTreeMap::new();
        let now_utc_ns = current_utc_ns()?;
        let now_boottime_ns = current_boottime_ns()?;
        for candidate in &config.policy_candidates {
            let artifact = artifact_owner
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
                    artifact_owner
                        .load_verified_rollback(artifact_path, public_key_path)
                        .context(PolicySnafu)?,
                ),
                (None, None) => None,
                _ => unreachable!("NodeConfig validation requires a complete rollback pair"),
            };
            ensure!(
                artifacts
                    .insert(artifact.header.profile_id.clone(), (artifact, rollback))
                    .is_none(),
                IdentityStateSnafu {
                    reason: "one node candidate is allowed per profile ID",
                }
            );
        }
        let mut rollback =
            AntiRollbackStore::load(config.state_directory.join("policy-anti-rollback-v1.json"))
                .context(PolicySnafu)?;
        reconcile_pending_activations(host, &mut rollback, node_boot_id, label_epoch)?;
        let mut generations = BTreeMap::<u64, LoweredGeneration>::new();
        let mut activations = BTreeMap::<Id128V1, ProfileActivation>::new();
        let mut validated = BTreeMap::<Id128V1, ValidatedProfileCandidateV1>::new();
        let mut declared_entry_requests = BTreeSet::new();
        let node_id = stable_node_id(&config.node_id)?;
        for binding in &config.workload_bindings {
            let (artifact, rollback_authorization) =
                artifacts.get(&binding.profile_id).ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "binding `{}` has no verified candidate for profile `{}`",
                            binding.binding_id, binding.profile_id
                        ),
                    }
                    .build()
                })?;
            let profile_id = parse_id("profile_id", &binding.profile_id)?;
            if let std::collections::btree_map::Entry::Vacant(entry) = validated.entry(profile_id) {
                entry.insert(
                    rollback
                        .validate(
                            artifact,
                            rollback_authorization
                                .as_ref()
                                .map(|(proof, key)| (proof, key)),
                            &platform_scope_digest,
                            now_utc_ns,
                        )
                        .context(PolicySnafu)?,
                );
            }
            let binding_id = parse_id("binding_id", &binding.binding_id)?;
            add_binding_activation(&mut activations, profile_id, binding_id, binding)?;
            for selector_id in entry_admission_path_selector_ids(artifact, binding)? {
                let selector = artifact
                    .policy_document
                    .path_selectors
                    .iter()
                    .find(|selector| selector.path_selector_id == selector_id)
                    .context(IdentityStateSnafu {
                        reason: "entry admission lost its declared request path",
                    })?;
                let request =
                    DeclaredEntryRequestV1::from_path(selector.path_expression().as_bytes())
                        .context(IdentityStateSnafu {
                            reason: "entry admission request path exceeds the kernel bound",
                        })?;
                declared_entry_requests.insert(request.as_bytes().to_vec());
            }
            let measured_for_binding = measured
                .objects
                .iter()
                .filter(|measured| measured.binding_id == binding.binding_id)
                .map(|measured| measured.object.clone())
                .collect::<Vec<_>>();
            let binding_routes = measured
                .routes
                .iter()
                .filter(|measured| measured.binding_id == binding.binding_id)
                .cloned()
                .collect::<Vec<_>>();
            let lowered = LoweredGeneration::for_binding_with_mount_routes(
                artifact,
                binding,
                &measured_for_binding,
                &binding_routes,
                node_boot_id,
                node_id,
                label_epoch,
                now_utc_ns,
                now_boottime_ns,
                deferred.contains(&binding.binding_id)
                    && !measured.resolved.contains(&binding.binding_id),
            )?;
            match generations.get_mut(&binding.active_profile_generation_ref_id) {
                Some(existing) => existing.merge(lowered)?,
                None => {
                    generations.insert(binding.active_profile_generation_ref_id, lowered);
                }
            }
        }
        let mut generation_allocator = GenerationHandleAllocator::load(
            config.state_directory.join("generation-handles-v1.json"),
            host,
            node_boot_id,
            label_epoch,
        )?;
        for generation in generations.values() {
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
        let process_generation_migrations =
            build_process_generation_migrations(&activations, &semantics)?;
        preflight_policy_map_capacity(
            host,
            &generations,
            &activations,
            &process_generation_migrations,
        )?;
        let mount_roots = generations
            .values()
            .flat_map(|generation| generation.mount_reconciliation.iter().cloned())
            .collect::<Vec<_>>();
        measured.prepare_views(&mount_roots)?;
        let authority =
            ExceptionAuthorityOwner::load(&config.state_directory, node_id, node_boot_id)?;
        let profiles = activations
            .into_iter()
            .map(|(id, activation)| {
                let candidate = validated.remove(&id).context(IdentityStateSnafu {
                    reason: "profile activation has no validated candidate",
                })?;
                Ok(PreparedProfile {
                    id,
                    activation,
                    candidate,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            node_boot_id,
            label_epoch,
            now_utc_ns,
            now_boottime_ns,
            measured,
            generations,
            profiles,
            semantics,
            migrations: process_generation_migrations,
            requests: declared_entry_requests,
            mount_roots,
            rollback,
            authority,
        })
    }

    pub(super) fn publish(mut self, host: &mut KernelHost) -> Result<NodePolicyGenerationOwner> {
        // Publish dependencies before activation. Each generation verifies and probes its rows.
        prepare_declared_entry_requests(host, &self.requests)?;
        self.authority.restore_receipts(host)?;
        install_global_mount_barrier(host, &self.mount_roots)?;
        for generation in self.generations.values() {
            generation.install(
                host,
                &mut self.authority,
                self.now_utc_ns,
                self.now_boottime_ns,
            )?;
            generation.probe_staged_rows(host)?;
        }
        install_rows(host, "process_generation_migrations", &self.migrations)?;
        for profile in &self.profiles {
            activate_profile(
                host,
                &profile.id,
                &profile.activation,
                &mut self.rollback,
                &profile.candidate,
                self.node_boot_id,
                self.label_epoch,
            )?;
        }
        self.finish(host)
    }

    fn finish(mut self, host: &KernelHost) -> Result<NodePolicyGenerationOwner> {
        self.authority.reconcile(host, self.now_utc_ns)?;
        let retirement_pending =
            reconcile_generation_retirement(host, self.node_boot_id, self.label_epoch)?;
        let mut generation_semantics = BTreeMap::new();
        for (generation, semantics) in self.semantics {
            if host
                .lookup_map("profile_generation_descriptors", &generation.to_ne_bytes())
                .context(InterceptorSnafu)?
                .is_some()
            {
                generation_semantics.insert(generation, semantics);
            }
        }
        retire_undeclared_entry_requests(host, &self.requests)?;
        let administrative_plans = self
            .generations
            .values()
            .flat_map(|generation| generation.administrative_plans.iter().cloned())
            .collect();
        let administrative_required = self
            .generations
            .values()
            .any(|generation| generation.administrative_required);
        let dynamic_rows = NodePolicyGenerationOwner::dynamic_generation_rows(&self.generations);
        let owner = NodePolicyGenerationOwner {
            node_boot_id: self.node_boot_id,
            label_epoch: self.label_epoch,
            mount_view_handles: self.measured.views,
            prevention_enabled: self
                .generations
                .values()
                .any(|generation| generation.descriptor.mode == PolicyGenerationModeV1::Protect),
            administrative_required,
            administrative_plans,
            measured_exact_objects: self.measured.objects,
            measured_mount_routes: self.measured.routes,
            resolved_path_binding_ids: self.measured.resolved,
            generation_semantics,
            dynamic_rows,
            exception_authority: Mutex::new(self.authority),
            retirement_pending: AtomicBool::new(retirement_pending),
        };
        let publication: Result<()> = (|| {
            for generation in self.generations.values() {
                generation.install_entry_admissions(host)?;
            }
            Ok(())
        })();
        if publication.is_err() {
            for generation in self.generations.values() {
                generation.revoke_entry_admissions(host)?;
            }
        }
        publication?;
        Ok(owner)
    }
}

impl PolicyMeasurements {
    fn prepare_views(&mut self, roots: &[MountRootReconciliation]) -> Result<()> {
        let roots = roots.iter().map(|root| {
            (
                root.mount_namespace_inode,
                root.configured.mount_view_root_pid,
                Some(root),
            )
        });
        let routes = self.routes.iter().map(|route| {
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
                validate_mount_view(view, root, *retained)?;
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
            routes: vec![measured.clone(), measured],
            ..PolicyMeasurements::default()
        };

        // Repeated routes share one handle, on both initial preparation and reuse.
        inputs.prepare_views(&[])?;
        assert_eq!(inputs.views.len(), 1);
        assert_eq!(inputs.views[&namespace].mount_namespace_inode()?, namespace);
        inputs.prepare_views(&[])?;
        assert_eq!(inputs.views.len(), 1);

        inputs.routes[1].mount_view_root_pid = pid + 1;
        let error = inputs
            .prepare_views(&[])
            .err()
            .context(IdentityStateSnafu {
                reason: "unequal root processes were accepted for one mount view",
            })?;
        assert!(error.to_string().contains("multiple live root processes"));

        inputs.routes.truncate(1);
        inputs.routes[0].route.mount_namespace_inode ^= 1;
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
