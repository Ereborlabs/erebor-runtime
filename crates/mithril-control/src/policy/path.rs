use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::PolicyValidationSnafu;
use crate::Result;

pub const MAX_CANONICAL_COMPONENTS_V1: usize = 64;
pub const MAX_COMPONENT_BYTES_V1: usize = 255;
pub const MAX_PATH_GRAPH_STATES_V1: usize = 4096;

pub type DentryIdV1 = u64;
pub type MountIdUniqueV1 = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MountTopologyStateV1 {
    Clean,
    Dirty,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DentryRecordV1 {
    pub dentry_id: DentryIdV1,
    pub parent_dentry_id: DentryIdV1,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MountRecordV1 {
    pub mount_id_unique: MountIdUniqueV1,
    pub root_dentry_id: DentryIdV1,
    pub parent_mount_id_unique: Option<MountIdUniqueV1>,
    pub mountpoint_dentry_id: Option<DentryIdV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MountSecurityViewV1 {
    pub mount_view_id: String,
    pub topology_epoch: u64,
    pub topology_state: MountTopologyStateV1,
    pub root_mount_id_unique: MountIdUniqueV1,
    pub dentries: BTreeMap<DentryIdV1, DentryRecordV1>,
    pub mounts: BTreeMap<MountIdUniqueV1, MountRecordV1>,
}

impl MountSecurityViewV1 {
    pub fn validate(&self) -> Result<()> {
        let id = &self.mount_view_id;
        ensure_path(
            id,
            self.topology_epoch > 0 && self.mounts.contains_key(&self.root_mount_id_unique),
            "PATH_VIEW_ROOT",
            "mount view needs a nonzero epoch and represented root mount",
        )?;
        for (key, mount) in &self.mounts {
            ensure_path(
                id,
                *key == mount.mount_id_unique
                    && self.dentries.contains_key(&mount.root_dentry_id)
                    && match (mount.parent_mount_id_unique, mount.mountpoint_dentry_id) {
                        (None, None) => *key == self.root_mount_id_unique,
                        (Some(parent), Some(point)) => {
                            self.mounts.contains_key(&parent) && self.dentries.contains_key(&point)
                        }
                        _ => false,
                    },
                "PATH_VIEW_MOUNT",
                "mount records must have exact keys, roots, and paired parent/mountpoint links",
            )?;
        }
        for (key, dentry) in &self.dentries {
            ensure_path(
                id,
                *key == dentry.dentry_id
                    && !dentry.name.contains(&0)
                    && dentry.name.len() <= MAX_COMPONENT_BYTES_V1
                    && (dentry.parent_dentry_id == dentry.dentry_id
                        || self.dentries.contains_key(&dentry.parent_dentry_id)),
                "PATH_VIEW_DENTRY",
                "dentry records must have exact keys, bounded names, and represented parents",
            )?;
        }
        Ok(())
    }

    pub fn canonical_components(
        &self,
        target_dentry_id: DentryIdV1,
        entered_mount_id_unique: MountIdUniqueV1,
    ) -> CanonicalPathResultV1 {
        if self.validate().is_err() {
            return CanonicalPathResultV1::Unresolved {
                reason: PathUnresolvedReasonV1::InvalidSnapshot,
            };
        }
        if self.topology_state != MountTopologyStateV1::Clean {
            return CanonicalPathResultV1::Unresolved {
                reason: PathUnresolvedReasonV1::DirtyTopology,
            };
        }
        if !self.mounts.contains_key(&entered_mount_id_unique) {
            return CanonicalPathResultV1::Unresolved {
                reason: PathUnresolvedReasonV1::MountOutsideView,
            };
        }
        let mut current = target_dentry_id;
        let mut current_mount = entered_mount_id_unique;
        let mut reversed = Vec::new();
        let mut visited = BTreeSet::new();
        for _ in 0..=MAX_CANONICAL_COMPONENTS_V1 {
            if !visited.insert((current, current_mount)) {
                return CanonicalPathResultV1::Unresolved {
                    reason: PathUnresolvedReasonV1::Cycle,
                };
            }
            let Some(dentry) = self.dentries.get(&current) else {
                return CanonicalPathResultV1::Unresolved {
                    reason: PathUnresolvedReasonV1::DentryOutsideView,
                };
            };
            let oldest = self
                .mounts
                .values()
                .filter(|mount| mount.root_dentry_id == current)
                .min_by_key(|mount| mount.mount_id_unique);
            if let Some(selected) = oldest {
                if selected.mount_id_unique == self.root_mount_id_unique {
                    reversed.reverse();
                    return CanonicalPathResultV1::Resolved {
                        components: reversed,
                        selected_root_mount_id_unique: selected.mount_id_unique,
                    };
                }
                let (Some(parent_mount), Some(mountpoint)) = (
                    selected.parent_mount_id_unique,
                    selected.mountpoint_dentry_id,
                ) else {
                    return CanonicalPathResultV1::Unresolved {
                        reason: PathUnresolvedReasonV1::InvalidSnapshot,
                    };
                };
                current = mountpoint;
                current_mount = parent_mount;
                continue;
            }
            if dentry.parent_dentry_id == current {
                return CanonicalPathResultV1::Unresolved {
                    reason: PathUnresolvedReasonV1::RequiredRootUnreachable,
                };
            }
            if dentry.name.is_empty() || dentry.name.len() > MAX_COMPONENT_BYTES_V1 {
                return CanonicalPathResultV1::Unresolved {
                    reason: PathUnresolvedReasonV1::ComponentBound,
                };
            }
            reversed.push(dentry.name.clone());
            if reversed.len() > MAX_CANONICAL_COMPONENTS_V1 {
                return CanonicalPathResultV1::Unresolved {
                    reason: PathUnresolvedReasonV1::DepthBound,
                };
            }
            current = dentry.parent_dentry_id;
        }
        CanonicalPathResultV1::Unresolved {
            reason: PathUnresolvedReasonV1::DepthBound,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalPathResultV1 {
    Resolved {
        components: Vec<Vec<u8>>,
        selected_root_mount_id_unique: MountIdUniqueV1,
    },
    Unresolved {
        reason: PathUnresolvedReasonV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathUnresolvedReasonV1 {
    DirtyTopology,
    InvalidSnapshot,
    MountOutsideView,
    DentryOutsideView,
    RequiredRootUnreachable,
    ComponentBound,
    DepthBound,
    Cycle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathPatternComponentV1 {
    Exact(Vec<u8>),
    Wildcard,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPatternV1 {
    pub rule_id: String,
    pub components: Vec<PathPatternComponentV1>,
    pub candidate_object_class_id: String,
    pub physical_result_id: String,
    pub overrides_rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPathGraphV1 {
    states: Vec<PathGraphStateV1>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PathGraphStateV1 {
    exact: BTreeMap<Vec<u8>, usize>,
    wildcard: Option<usize>,
    terminal: Option<PathTerminalV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathTerminalV1 {
    rule_id: String,
    candidate_object_class_id: String,
    physical_result_id: String,
    overrides_rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathCandidateV1 {
    pub rule_id: String,
    pub candidate_object_class_id: String,
    pub canonical_components: Vec<Vec<u8>>,
}

impl CanonicalPathGraphV1 {
    pub fn compile(policy_id: &str, patterns: &[PathPatternV1]) -> Result<Self> {
        let mut graph = Self {
            states: vec![PathGraphStateV1::default()],
        };
        for pattern in patterns {
            ensure_path(
                policy_id,
                !pattern.components.is_empty()
                    && pattern.components.len() <= MAX_CANONICAL_COMPONENTS_V1,
                "PATH_PATTERN_DEPTH",
                "path patterns must be nonempty and within the component bound",
            )?;
            graph.insert(policy_id, pattern)?;
        }
        for (index, left) in patterns.iter().enumerate() {
            for right in &patterns[index + 1..] {
                if !patterns_overlap(left, right)
                    || (left.physical_result_id == right.physical_result_id
                        && left.candidate_object_class_id == right.candidate_object_class_id)
                {
                    continue;
                }
                ensure_path(
                    policy_id,
                    left.overrides_rule_ids.contains(&right.rule_id)
                        || right.overrides_rule_ids.contains(&left.rule_id),
                    "PATH_TERMINAL_CONFLICT",
                    "an overlapping terminal with unequal authority needs one exact override",
                )?;
            }
        }
        Ok(graph)
    }

    pub fn candidate(&self, components: &[Vec<u8>]) -> Option<PathCandidateV1> {
        let mut active = BTreeSet::from([0_usize]);
        for component in components {
            let mut next = BTreeSet::new();
            for state_id in active {
                let state = self.states.get(state_id)?;
                if let Some(exact) = state.exact.get(component) {
                    next.insert(*exact);
                }
                if let Some(wildcard) = state.wildcard {
                    next.insert(wildcard);
                }
            }
            active = next;
            if active.is_empty() {
                return None;
            }
        }
        let terminals = active
            .iter()
            .filter_map(|state| self.states.get(*state)?.terminal.as_ref())
            .collect::<Vec<_>>();
        let terminal = terminals.iter().find(|candidate| {
            terminals.iter().all(|other| {
                candidate.rule_id == other.rule_id
                    || (candidate.physical_result_id == other.physical_result_id
                        && candidate.candidate_object_class_id == other.candidate_object_class_id)
                    || candidate.overrides_rule_ids.contains(&other.rule_id)
            })
        })?;
        Some(PathCandidateV1 {
            rule_id: terminal.rule_id.clone(),
            candidate_object_class_id: terminal.candidate_object_class_id.clone(),
            canonical_components: components.to_vec(),
        })
    }

    fn insert(&mut self, policy_id: &str, pattern: &PathPatternV1) -> Result<()> {
        let mut state_id = 0;
        for component in &pattern.components {
            let existing = match component {
                PathPatternComponentV1::Exact(bytes) => {
                    ensure_path(
                        policy_id,
                        !bytes.is_empty()
                            && bytes.len() <= MAX_COMPONENT_BYTES_V1
                            && !bytes.contains(&0)
                            && bytes.as_slice() != b"."
                            && bytes.as_slice() != b"..",
                        "PATH_COMPONENT",
                        "exact components must be bounded non-special Linux d_name bytes",
                    )?;
                    self.states[state_id].exact.get(bytes).copied()
                }
                PathPatternComponentV1::Wildcard => self.states[state_id].wildcard,
            };
            let next = if let Some(existing) = existing {
                existing
            } else {
                ensure_path(
                    policy_id,
                    self.states.len() < MAX_PATH_GRAPH_STATES_V1,
                    "PATH_GRAPH_CAPACITY",
                    "path graph exceeds the verified state capacity",
                )?;
                let next = self.states.len();
                self.states.push(PathGraphStateV1::default());
                match component {
                    PathPatternComponentV1::Exact(bytes) => {
                        self.states[state_id].exact.insert(bytes.clone(), next);
                    }
                    PathPatternComponentV1::Wildcard => {
                        self.states[state_id].wildcard = Some(next);
                    }
                }
                next
            };
            state_id = next;
        }
        let incoming = PathTerminalV1 {
            rule_id: pattern.rule_id.clone(),
            candidate_object_class_id: pattern.candidate_object_class_id.clone(),
            physical_result_id: pattern.physical_result_id.clone(),
            overrides_rule_ids: pattern.overrides_rule_ids.clone(),
        };
        match &self.states[state_id].terminal {
            None => self.states[state_id].terminal = Some(incoming),
            Some(existing)
                if existing.physical_result_id == incoming.physical_result_id
                    && existing.candidate_object_class_id == incoming.candidate_object_class_id => {
            }
            Some(existing) if pattern.overrides_rule_ids.contains(&existing.rule_id) => {
                self.states[state_id].terminal = Some(incoming);
            }
            Some(_) => {}
        }
        Ok(())
    }
}

fn patterns_overlap(left: &PathPatternV1, right: &PathPatternV1) -> bool {
    left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| match (left, right) {
                (PathPatternComponentV1::Exact(left), PathPatternComponentV1::Exact(right)) => {
                    left == right
                }
                _ => true,
            })
}

fn ensure_path(policy_id: &str, condition: bool, code: &'static str, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        PolicyValidationSnafu {
            policy_id,
            code,
            reason,
        }
        .fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dentry(id: u64, parent: u64, name: &[u8]) -> DentryRecordV1 {
        DentryRecordV1 {
            dentry_id: id,
            parent_dentry_id: parent,
            name: name.to_vec(),
        }
    }

    fn bind_alias_view() -> MountSecurityViewV1 {
        MountSecurityViewV1 {
            mount_view_id: "worker-view".to_owned(),
            topology_epoch: 7,
            topology_state: MountTopologyStateV1::Clean,
            root_mount_id_unique: 1,
            dentries: [
                (1, dentry(1, 1, b"")),
                (2, dentry(2, 1, b"var")),
                (3, dentry(3, 2, b"run")),
                (4, dentry(4, 3, b"secrets")),
                (5, dentry(5, 4, b"service")),
                (6, dentry(6, 1, b"work")),
                (7, dentry(7, 6, b"input")),
                (8, dentry(8, 7, b"job-42")),
                (20, dentry(20, 20, b"")),
                (21, dentry(21, 20, b"config.json")),
            ]
            .into_iter()
            .collect(),
            mounts: [
                (
                    1,
                    MountRecordV1 {
                        mount_id_unique: 1,
                        root_dentry_id: 1,
                        parent_mount_id_unique: None,
                        mountpoint_dentry_id: None,
                    },
                ),
                (
                    41,
                    MountRecordV1 {
                        mount_id_unique: 41,
                        root_dentry_id: 20,
                        parent_mount_id_unique: Some(1),
                        mountpoint_dentry_id: Some(5),
                    },
                ),
                (
                    92,
                    MountRecordV1 {
                        mount_id_unique: 92,
                        root_dentry_id: 20,
                        parent_mount_id_unique: Some(1),
                        mountpoint_dentry_id: Some(8),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn later_bind_alias_resolves_through_oldest_mount() {
        let result = bind_alias_view().canonical_components(21, 92);
        assert_eq!(
            result,
            CanonicalPathResultV1::Resolved {
                components: ["var", "run", "secrets", "service", "config.json"]
                    .map(|component| component.as_bytes().to_vec())
                    .to_vec(),
                selected_root_mount_id_unique: 1,
            }
        );
    }

    #[test]
    fn dirty_topology_never_resolves() {
        let mut view = bind_alias_view();
        view.topology_state = MountTopologyStateV1::Dirty;
        assert_eq!(
            view.canonical_components(21, 92),
            CanonicalPathResultV1::Unresolved {
                reason: PathUnresolvedReasonV1::DirtyTopology,
            }
        );
    }

    #[test]
    fn graph_matches_original_not_later_alias() -> crate::Result<()> {
        let graph = CanonicalPathGraphV1::compile(
            "test",
            &[PathPatternV1 {
                rule_id: "allow-later-alias".to_owned(),
                components: ["work", "input"]
                    .map(|value| PathPatternComponentV1::Exact(value.as_bytes().to_vec()))
                    .into_iter()
                    .chain([
                        PathPatternComponentV1::Wildcard,
                        PathPatternComponentV1::Exact(b"config.json".to_vec()),
                    ])
                    .collect(),
                candidate_object_class_id: "DATASET_INPUT".to_owned(),
                physical_result_id: "ALLOW_EFFECT".to_owned(),
                overrides_rule_ids: Vec::new(),
            }],
        )?;
        let CanonicalPathResultV1::Resolved { components, .. } =
            bind_alias_view().canonical_components(21, 92)
        else {
            return Err(crate::Error::PolicyValidation {
                policy_id: "test".to_owned(),
                code: "PATH_TEST",
                reason: "fixture did not resolve".to_owned(),
                location: snafu::Location::default(),
            });
        };
        assert_eq!(graph.candidate(&components), None);
        Ok(())
    }
}
