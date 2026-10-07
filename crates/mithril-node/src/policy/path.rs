use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

use erebor_interceptor_abi::{
    CanonicalMountRootKeyV1, CanonicalMountRootV1, CanonicalPathComponentV1,
    MountSecurityViewStateV1, MountTopologyStateV1, PathGraphStateKeyV1, PathGraphTerminalV1,
    PathGraphTransitionKeyV1, PathGraphTransitionV1, PathTreeDenyKeyV1,
    MAX_CANONICAL_COMPONENT_BYTES_V1, MAX_CANONICAL_ROUTE_STATES_V1,
};
use mithril_control::{
    CanonicalPathGraphV1, CompiledOperationV1, PathPatternV1, PathSelectorTargetV1,
    PathTreeDenyPatternV1, ProfileCandidateArtifactV1,
};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::IntoBytes as _;

use crate::error::{IdentityStateSnafu, PolicySnafu};
use crate::{ExactFileObjectConfig, Result, WorkloadBindingConfig};

use super::{
    handles, parse_id, GenerationPlan, LoweredGeneration, MeasuredMountRouteV1,
    MountRootReconciliation, NativeTable, LINUX_CAPABILITY_SELECTOR_PREFIX,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MountRouteIdentity {
    mount_namespace_inode: u32,
    filesystem_device: u32,
    root_inode: u64,
    topology_generation: u64,
}

#[derive(Default)]
struct MountRoutePlan {
    states: BTreeSet<u32>,
    mount_view_root_pid: u32,
    selected_mount_id_unique: u64,
    snapshot_digest_id: u64,
    has_known_route: bool,
}

impl MountRoutePlan {
    pub(super) fn merge(
        &mut self,
        state: Option<u32>,
        mount_view_root_pid: u32,
        selected_mount_id_unique: u64,
        snapshot_digest_id: u64,
        has_known_route: bool,
    ) -> Result<()> {
        ensure!(
            self.mount_view_root_pid != 0
                || (mount_view_root_pid > 0 && selected_mount_id_unique > 0),
            IdentityStateSnafu {
                reason: "known mount route has no live view or unique mount",
            }
        );
        ensure!(
            self.mount_view_root_pid == 0
                || (self.mount_view_root_pid == mount_view_root_pid
                    && selected_mount_id_unique > 0),
            IdentityStateSnafu {
                reason: "one mount source has unequal live security views",
            }
        );
        ensure!(
            self.snapshot_digest_id == 0
                || snapshot_digest_id == 0
                || self.snapshot_digest_id == snapshot_digest_id,
            IdentityStateSnafu {
                reason: "one mount source has unequal topology snapshots",
            }
        );
        self.states.extend(state);
        self.selected_mount_id_unique = if self.mount_view_root_pid == 0 {
            selected_mount_id_unique
        } else {
            self.selected_mount_id_unique.min(selected_mount_id_unique)
        };
        self.mount_view_root_pid = mount_view_root_pid;
        self.snapshot_digest_id = self.snapshot_digest_id.max(snapshot_digest_id);
        self.has_known_route |= has_known_route;
        Ok(())
    }
}

impl GenerationPlan {
    pub(super) fn add_mount_namespace_guard(
        &mut self,
        mount_namespace_inode: u32,
        topology_generation: u64,
    ) -> Result<()> {
        let key = mount_namespace_inode.to_ne_bytes();
        let view = MountSecurityViewStateV1 {
            topology_generation,
            snapshot_digest_id: 0,
            pending_mutations: 0,
            state: MountTopologyStateV1::Dirty,
            reserved: [0; 7],
            transition_version: 1,
        };
        self.insert(NativeTable::MountView, key, view.as_bytes())?;
        self.insert(
            NativeTable::MountEpoch,
            key,
            topology_generation.to_ne_bytes(),
        )?;
        self.insert(NativeTable::MountLock, key, 0_u32.to_ne_bytes())?;
        Ok(())
    }

    pub(super) fn add_mount_namespace_guards<'a>(
        &mut self,
        objects: impl IntoIterator<Item = &'a ExactFileObjectConfig>,
    ) -> Result<()> {
        for object in objects {
            self.add_mount_namespace_guard(
                object.mount_namespace_inode,
                object.mount_topology_generation,
            )?;
        }
        Ok(())
    }
}

impl LoweredGeneration {
    pub(super) fn composite_handles(
        artifact: &ProfileCandidateArtifactV1,
    ) -> BTreeMap<String, u64> {
        let mut handles = artifact
            .policy_document
            .protected_universe
            .object_class_ids
            .iter()
            .map(|id| format!("CLASS:{id}"))
            .chain(
                artifact
                    .compiled_profile
                    .compiled_cells
                    .iter()
                    .map(|cell| cell.key.object_selector.clone()),
            )
            .filter(|id| {
                !id.starts_with("PATH:") && !id.starts_with(LINUX_CAPABILITY_SELECTOR_PREFIX)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index as u64 + 1))
            .collect::<BTreeMap<_, _>>();
        for selector in &artifact.policy_document.path_selectors {
            let object_class = format!("CLASS:{}", selector.object_class_id);
            let handle = handles[&object_class];
            handles.insert(format!("PATH:{}", selector.path_selector_id), handle);
        }
        handles
    }

    pub(super) fn linux_capability(
        cell: &mithril_control::CompiledDecisionCellV1,
    ) -> Result<Option<u32>> {
        let Some(value) = cell
            .key
            .object_selector
            .strip_prefix(LINUX_CAPABILITY_SELECTOR_PREFIX)
        else {
            return Ok(None);
        };
        let capability = value.parse::<u32>().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("invalid compiled Linux capability `{value}`: {error}"),
            }
            .build()
        })?;
        ensure!(
            capability <= 40,
            IdentityStateSnafu {
                reason: format!("unsupported compiled Linux capability `{capability}`"),
            }
        );
        Ok(Some(capability))
    }

    pub(super) fn compile_path_graph(
        artifact: &ProfileCandidateArtifactV1,
    ) -> Result<mithril_control::DeterministicPathGraphV1> {
        let mut patterns = Vec::new();
        for selector in &artifact.policy_document.path_selectors {
            let components = selector
                .target
                .pattern_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?;
            patterns.push(PathPatternV1 {
                rule_id: selector.path_selector_id.clone(),
                components,
                candidate_object_class_id: selector.object_class_id.clone(),
                physical_result_id: format!("CLASS:{}", selector.object_class_id),
                overrides_rule_ids: Vec::new(),
            });
        }
        let path_tree_denies = artifact
            .policy_document
            .path_tree_deny_floors
            .iter()
            .map(|floor| {
                let mut operations = floor
                    .operation_ids
                    .iter()
                    .map(|operation| {
                        CompiledOperationV1::try_from(operation.as_str())
                            .map(|operation| operation.kernel_id as u16)
                            .map_err(|_| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "path-tree rule has unknown operation `{operation}`"
                                    ),
                                }
                                .build()
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                operations.sort_unstable();
                let components = PathSelectorTargetV1::Path {
                    path_pattern: floor.path.clone(),
                }
                .pattern_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?;
                Ok(PathTreeDenyPatternV1 {
                    role_id: floor.role_id.clone(),
                    components,
                    operations,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let graph = CanonicalPathGraphV1::compile_with_path_tree_denies_and_precedence(
            artifact.header.profile_id.as_str(),
            &patterns,
            &path_tree_denies,
            artifact.policy_document.path_pattern_precedence,
        )
        .context(PolicySnafu)?;
        let graph = graph
            .determinize(artifact.header.profile_id.as_str())
            .context(PolicySnafu)?;
        Ok(graph)
    }

    #[cfg(test)]
    pub(super) fn lower_path_tables(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        objects: &[&ExactFileObjectConfig],
        measured_mount_routes: &[MeasuredMountRouteV1],
        composite_handles: &BTreeMap<String, u64>,
        role_handles: &BTreeMap<String, u32>,
    ) -> Result<(GenerationPlan, Vec<MountRootReconciliation>)> {
        let graph = Self::compile_path_graph(artifact)?;
        let mut tables = GenerationPlan::for_graph(
            artifact,
            &graph,
            binding.active_profile_generation_ref_id,
            composite_handles,
            role_handles,
        )?;
        let reconciliation = tables.add_paths(&graph, binding, objects, measured_mount_routes)?;
        Ok((tables, reconciliation))
    }
}

impl GenerationPlan {
    pub(super) fn for_graph(
        artifact: &ProfileCandidateArtifactV1,
        graph: &mithril_control::DeterministicPathGraphV1,
        generation: u64,
        composite_handles: &BTreeMap<String, u64>,
        role_handles: &BTreeMap<String, u32>,
    ) -> Result<Self> {
        let mut tables = Self::default();
        for transition in &graph.exact_transitions {
            let component = path_component(&transition.component)?;
            let key = PathGraphTransitionKeyV1 {
                profile_generation_ref_id: generation,
                current_state_id: transition.current_state_id,
                component,
                reserved: 0,
            };
            let value = PathGraphTransitionV1 {
                next_state_id: transition.next_state_id,
                reserved: 0,
            };
            tables.insert(NativeTable::PathExact, key.as_bytes(), value.as_bytes())?;
        }
        for transition in &graph.wildcard_transitions {
            let key = PathGraphStateKeyV1 {
                profile_generation_ref_id: generation,
                state_id: transition.current_state_id,
                reserved: 0,
            };
            let value = PathGraphTransitionV1 {
                next_state_id: transition.next_state_id,
                reserved: 0,
            };
            tables.insert(NativeTable::PathWildcard, key.as_bytes(), value.as_bytes())?;
        }
        let rule_handles = handles(
            graph
                .terminals
                .iter()
                .map(|terminal| terminal.rule_id.as_str()),
        );
        for terminal in &graph.terminals {
            let selector = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| selector.path_selector_id == terminal.rule_id)
                .context(IdentityStateSnafu {
                    reason: format!("path terminal has unknown selector `{}`", terminal.rule_id),
                })?;
            let composite_atom_id = *composite_handles
                .get(&format!("PATH:{}", terminal.rule_id))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "path terminal has no composite atom for `{}`",
                            terminal.rule_id
                        ),
                    }
                    .build()
                })?;
            let value = PathGraphTerminalV1 {
                composite_atom_id,
                rule_numeric_id: rule_handles[&terminal.rule_id],
                exact_object_required: u8::from(selector.requires_exact_object()),
                reserved: [0; 3],
            };
            let key = PathGraphStateKeyV1 {
                profile_generation_ref_id: generation,
                state_id: terminal.state_id,
                reserved: 0,
            };
            ensure!(
                !tables[NativeTable::PathTerminal].contains_key(key.as_bytes()),
                IdentityStateSnafu {
                    reason: "deterministic path state has multiple exact terminals",
                }
            );
            tables.insert(NativeTable::PathTerminal, key.as_bytes(), value.as_bytes())?;
        }
        for floor in &graph.path_tree_deny_floors {
            let active_role_id = *role_handles.get(&floor.role_id).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!("path-tree denial has unknown role `{}`", floor.role_id),
                }
                .build()
            })?;
            let key = PathTreeDenyKeyV1 {
                profile_generation_ref_id: generation,
                state_id: floor.state_id,
                active_role_id,
            };
            tables.insert(
                NativeTable::PathTreeDenial,
                key.as_bytes(),
                floor.operation_mask.to_ne_bytes(),
            )?;
        }
        Ok(tables)
    }

    pub(super) fn add_paths(
        &mut self,
        graph: &mithril_control::DeterministicPathGraphV1,
        binding: &WorkloadBindingConfig,
        objects: &[&ExactFileObjectConfig],
        measured_mount_routes: &[MeasuredMountRouteV1],
    ) -> Result<Vec<MountRootReconciliation>> {
        let mut reconciliation = Vec::new();
        let mut route_plans = BTreeMap::<MountRouteIdentity, MountRoutePlan>::new();
        for measured in measured_mount_routes {
            ensure!(
                measured.binding_id == binding.binding_id
                    && measured.mount_topology_generation > 0
                    && measured.route.mount_namespace_inode > 0
                    && measured.route.root_inode > 0,
                IdentityStateSnafu {
                    reason: "known mount route differs from its workload binding",
                }
            );
            let identity = MountRouteIdentity {
                mount_namespace_inode: measured.route.mount_namespace_inode,
                filesystem_device: measured.route.filesystem_device,
                root_inode: measured.route.root_inode,
                topology_generation: measured.mount_topology_generation,
            };
            route_plans.entry(identity).or_default().merge(
                graph.state_after(&measured.route.mountpoint_components),
                measured.mount_view_root_pid,
                measured.route.selected_mount_id_unique,
                measured.route.mount_snapshot_digest_id,
                true,
            )?;
        }
        for object in objects {
            let components = object
                .canonical_component_hex
                .iter()
                .map(|component| {
                    hex::decode(component).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!(
                                "measured canonical path component is invalid: {error}"
                            ),
                        }
                        .build()
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            reconciliation.push(MountRootReconciliation {
                configured: (*object).clone(),
                canonical_path: canonical_path(&components),
            });
            let prefix_len = components
                .len()
                .checked_sub(usize::from(object.mount_relative_component_count))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "mount-relative path count exceeds the canonical path".to_owned(),
                    }
                    .build()
                })?;
            let identity = MountRouteIdentity {
                mount_namespace_inode: object.mount_namespace_inode,
                filesystem_device: object.mount_root_filesystem_device,
                root_inode: object.mount_root_inode,
                topology_generation: object.mount_topology_generation,
            };
            route_plans.entry(identity).or_default().merge(
                graph.state_after(&components[..prefix_len]),
                object.mount_view_root_pid,
                object.selected_mount_id_unique,
                object.mount_snapshot_digest_id,
                false,
            )?;
        }
        self.add_mount_namespace_guards(objects.iter().copied())?;
        let binding_id = parse_id("binding_id", &binding.binding_id)?;
        for (identity, plan) in route_plans {
            ensure!(
                plan.states.len() <= MAX_CANONICAL_ROUTE_STATES_V1,
                IdentityStateSnafu {
                    reason: format!(
                        "one mount source exceeds {MAX_CANONICAL_ROUTE_STATES_V1} policy path routes"
                    ),
                }
            );
            ensure!(
                plan.has_known_route || !plan.states.is_empty(),
                IdentityStateSnafu {
                    reason: "canonical mount prefix is absent from its path graph",
                }
            );
            self.add_mount_namespace_guard(
                identity.mount_namespace_inode,
                identity.topology_generation,
            )?;
            let root_key = CanonicalMountRootKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                mount_namespace_inode: identity.mount_namespace_inode,
                binding_id,
                topology_generation: if plan.has_known_route {
                    0
                } else {
                    identity.topology_generation
                },
                filesystem_device: identity.filesystem_device,
                root_inode: identity.root_inode,
            };
            let mut root = CanonicalMountRootV1 {
                selected_mount_id_unique: plan.selected_mount_id_unique,
                snapshot_digest_id: plan.snapshot_digest_id,
                graph_prefix_state_count: plan.states.len() as u32,
                ..CanonicalMountRootV1::default()
            };
            for (slot, state) in root.graph_prefix_state_ids.iter_mut().zip(plan.states) {
                *slot = state;
            }
            self.insert(NativeTable::MountRoot, root_key.as_bytes(), root.as_bytes())?;
        }
        Ok(reconciliation)
    }
}

fn path_component(bytes: &[u8]) -> Result<CanonicalPathComponentV1> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CANONICAL_COMPONENT_BYTES_V1 && !bytes.contains(&0),
        IdentityStateSnafu {
            reason: "canonical path component is invalid",
        }
    );
    let mut component = CanonicalPathComponentV1 {
        length: bytes.len() as u16,
        ..CanonicalPathComponentV1::default()
    };
    component.bytes[..bytes.len()].copy_from_slice(bytes);
    Ok(component)
}

fn canonical_path(components: &[Vec<u8>]) -> PathBuf {
    let mut path = PathBuf::from("/");
    for component in components {
        path.push(OsStr::from_bytes(component));
    }
    path
}
