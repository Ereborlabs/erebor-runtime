use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityResult {
    Inserted,
    Updated,
    DeniedAtCapacity,
    DeniedMissingParent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeJoinResult {
    Joined,
    RejectedUnauthenticated,
    RejectedIncomplete,
    RejectedReplay,
}

pub struct RuntimeJoin {
    seen_sequences: BTreeSet<u64>,
    initial_roots: HashMap<String, String>,
}

impl RuntimeJoin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen_sequences: BTreeSet::new(),
            initial_roots: HashMap::new(),
        }
    }

    pub fn join_initial_root(
        &mut self,
        authenticated: bool,
        sequence: u64,
        container_id: &str,
        cgroup_id: &str,
    ) -> RuntimeJoinResult {
        if !authenticated {
            return RuntimeJoinResult::RejectedUnauthenticated;
        }
        if container_id.is_empty() || cgroup_id.is_empty() {
            return RuntimeJoinResult::RejectedIncomplete;
        }
        if !self.seen_sequences.insert(sequence) {
            return RuntimeJoinResult::RejectedReplay;
        }
        self.initial_roots
            .insert(container_id.to_owned(), cgroup_id.to_owned());
        RuntimeJoinResult::Joined
    }

    #[must_use]
    pub fn cgroup_for(&self, container_id: &str) -> Option<&str> {
        self.initial_roots.get(container_id).map(String::as_str)
    }
}

impl Default for RuntimeJoin {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecCommitResult {
    Staged,
    Committed,
    DeniedMissingStage,
    DeniedAtCapacity,
}

pub struct ExecStateMap {
    capacity: usize,
    staged: BTreeSet<(u64, u64)>,
}

impl ExecStateMap {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            staged: BTreeSet::new(),
        }
    }

    pub fn stage(&mut self, task_cookie: u64, exec_nonce: u64) -> ExecCommitResult {
        if self.staged.len() == self.capacity {
            return ExecCommitResult::DeniedAtCapacity;
        }
        self.staged.insert((task_cookie, exec_nonce));
        ExecCommitResult::Staged
    }

    pub fn commit(&mut self, task_cookie: u64, exec_nonce: u64) -> ExecCommitResult {
        if self.staged.remove(&(task_cookie, exec_nonce)) {
            ExecCommitResult::Committed
        } else {
            ExecCommitResult::DeniedMissingStage
        }
    }
}

pub struct RenameDecisionPoint;

impl RenameDecisionPoint {
    #[must_use]
    pub const fn decide(
        prior_result: Decision,
        source_object: u64,
        destination_object: u64,
    ) -> (Decision, u64, u64) {
        (prior_result, source_object, destination_object)
    }
}

pub struct AuthoritativeMap<K, V> {
    capacity: usize,
    entries: HashMap<K, V>,
}

impl<K, V> AuthoritativeMap<K, V>
where
    K: Eq + Hash,
{
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> CapacityResult {
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = value;
            return CapacityResult::Updated;
        }
        if self.entries.len() == self.capacity {
            return CapacityResult::DeniedAtCapacity;
        }
        self.entries.insert(key, value);
        CapacityResult::Inserted
    }

    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicGeneration {
    active: BTreeMap<String, Decision>,
}

impl AtomicGeneration {
    #[must_use]
    pub fn new(active: BTreeMap<String, Decision>) -> Self {
        Self { active }
    }

    #[must_use]
    pub fn publish(
        &mut self,
        candidate: impl IntoIterator<Item = (String, Decision)>,
        capacity: usize,
    ) -> CapacityResult {
        let mut staged = BTreeMap::new();
        for (key, decision) in candidate {
            if staged.len() == capacity && !staged.contains_key(&key) {
                return CapacityResult::DeniedAtCapacity;
            }
            staged.insert(key, decision);
        }
        self.active = staged;
        CapacityResult::Inserted
    }

    #[must_use]
    pub fn decision(&self, key: &str) -> Option<Decision> {
        self.active.get(key).copied()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCoverage {
    Healthy { epoch: u64 },
    Gapped { epoch: u64, lost: u64 },
}

impl SourceCoverage {
    #[must_use]
    pub const fn lose(self, count: u64) -> Self {
        let epoch = match self {
            Self::Healthy { epoch } | Self::Gapped { epoch, .. } => epoch,
        };
        Self::Gapped { epoch, lost: count }
    }

    #[must_use]
    pub const fn physical_result(self, installed: Decision) -> Decision {
        installed
    }
}

pub struct TaskStorage {
    labels: AuthoritativeMap<u64, u128>,
}

impl TaskStorage {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            labels: AuthoritativeMap::new(capacity),
        }
    }

    pub fn install_root(&mut self, task_cookie: u64, label: u128) -> CapacityResult {
        self.labels.insert(task_cookie, label)
    }

    pub fn task_alloc(&mut self, parent_cookie: u64, child_cookie: u64) -> CapacityResult {
        let Some(label) = self.labels.get(&parent_cookie).copied() else {
            return CapacityResult::DeniedMissingParent;
        };
        self.labels.insert(child_cookie, label)
    }

    #[must_use]
    pub fn first_protected_effect(&self, task_cookie: u64) -> Decision {
        if self.labels.get(&task_cookie).is_some() {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountGraph {
    roots: HashMap<u64, Vec<MountAttachment>>,
    mutation_epoch: u64,
    pending_mutations: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountAttachment {
    mount_id_unique: u64,
    mountpoint: String,
}

impl MountGraph {
    #[must_use]
    pub fn new() -> Self {
        Self {
            roots: HashMap::new(),
            mutation_epoch: 1,
            pending_mutations: 0,
        }
    }

    pub fn add_attachment(
        &mut self,
        root_dentry_id: u64,
        mount_id_unique: u64,
        mountpoint: impl Into<String>,
    ) {
        self.roots
            .entry(root_dentry_id)
            .or_default()
            .push(MountAttachment {
                mount_id_unique,
                mountpoint: mountpoint.into(),
            });
    }

    pub fn begin_mutation(&mut self) {
        self.mutation_epoch = self.mutation_epoch.saturating_add(1);
        self.pending_mutations = self.pending_mutations.saturating_add(1);
    }

    pub fn finish_mutation(&mut self) -> bool {
        if self.pending_mutations == 0 {
            return false;
        }
        self.pending_mutations -= 1;
        true
    }

    #[must_use]
    pub const fn stable_epoch(&self) -> Option<u64> {
        if self.pending_mutations == 0 {
            Some(self.mutation_epoch)
        } else {
            None
        }
    }

    #[must_use]
    pub fn canonical_path(&self, root_dentry_id: u64, relative_path: &str) -> Option<String> {
        self.stable_epoch()?;
        let oldest = self
            .roots
            .get(&root_dentry_id)?
            .iter()
            .min_by_key(|mount| mount.mount_id_unique)?;
        Some(format!(
            "{}/{}",
            oldest.mountpoint.trim_end_matches('/'),
            relative_path.trim_start_matches('/')
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDnsName(String);

impl BoundedDnsName {
    #[must_use]
    pub fn parse(labels: &[&str], maximum_labels: usize, maximum_bytes: usize) -> Option<Self> {
        if labels.is_empty()
            || labels.len() > maximum_labels
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return None;
        }
        let name = labels.join(".").to_ascii_lowercase();
        (name.len() <= maximum_bytes).then_some(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MountGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchResult {
    Decision(Decision),
    NoMatch,
    BoundExceeded,
    ConflictingTerminals,
}

pub struct ComponentGraph {
    maximum_components: usize,
    maximum_component_bytes: usize,
    rules: Vec<(Vec<String>, Decision)>,
}

impl ComponentGraph {
    #[must_use]
    pub fn new(maximum_components: usize, maximum_component_bytes: usize) -> Self {
        Self {
            maximum_components,
            maximum_component_bytes,
            rules: Vec::new(),
        }
    }

    #[must_use]
    pub fn add_rule(&mut self, pattern: &str, decision: Decision) -> MatchResult {
        let components = split_components(pattern);
        if self.exceeds_bound(&components) {
            return MatchResult::BoundExceeded;
        }
        self.rules.push((components, decision));
        MatchResult::Decision(decision)
    }

    #[must_use]
    pub fn decide(&self, path: &str) -> MatchResult {
        let components = split_components(path);
        if self.exceeds_bound(&components) {
            return MatchResult::BoundExceeded;
        }
        let mut matched = self.rules.iter().filter_map(|(pattern, decision)| {
            (pattern.len() == components.len()
                && pattern
                    .iter()
                    .zip(&components)
                    .all(|(expected, actual)| expected == "*" || expected == actual))
            .then_some(*decision)
        });
        let Some(first) = matched.next() else {
            return MatchResult::NoMatch;
        };
        if matched.any(|decision| decision != first) {
            MatchResult::ConflictingTerminals
        } else {
            MatchResult::Decision(first)
        }
    }

    fn exceeds_bound(&self, components: &[String]) -> bool {
        components.len() > self.maximum_components
            || components
                .iter()
                .any(|component| component.len() > self.maximum_component_bytes)
    }
}

fn split_components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        AtomicGeneration, AuthoritativeMap, BoundedDnsName, CapacityResult, ComponentGraph,
        Decision, ExecCommitResult, ExecStateMap, MatchResult, MountGraph, RenameDecisionPoint,
        RuntimeJoin, RuntimeJoinResult, SourceCoverage, TaskStorage,
    };

    #[test]
    fn source_ka_capacity_n_plus_one_denies_without_corrupting_existing_rows() {
        let mut map = AuthoritativeMap::new(2);
        assert_eq!(map.insert("a", Decision::Allow), CapacityResult::Inserted);
        assert_eq!(map.insert("b", Decision::Deny), CapacityResult::Inserted);
        assert_eq!(
            map.insert("c", Decision::Allow),
            CapacityResult::DeniedAtCapacity
        );
        assert_eq!(map.get(&"a"), Some(&Decision::Allow));
        assert_eq!(map.get(&"b"), Some(&Decision::Deny));
    }

    #[test]
    fn source_ka_partial_publication_keeps_the_complete_old_generation() {
        let mut active = BTreeMap::new();
        active.insert(String::from("control"), Decision::Allow);
        let mut generation = AtomicGeneration::new(active);
        let candidate = [
            (String::from("control"), Decision::Allow),
            (String::from("hostile"), Decision::Deny),
        ];
        assert_eq!(
            generation.publish(candidate, 1),
            CapacityResult::DeniedAtCapacity
        );
        assert_eq!(generation.decision("control"), Some(Decision::Allow));
        assert_eq!(generation.decision("hostile"), None);
    }

    #[test]
    fn source_ka_reader_loss_never_changes_an_installed_deny() {
        let coverage = SourceCoverage::Healthy { epoch: 7 }.lose(3);
        assert_eq!(coverage, SourceCoverage::Gapped { epoch: 7, lost: 3 });
        assert_eq!(coverage.physical_result(Decision::Deny), Decision::Deny);
    }

    #[test]
    fn jailer_task_alloc_copies_parent_before_first_child_effect() {
        let mut storage = TaskStorage::new(2);
        assert_eq!(storage.install_root(10, 99), CapacityResult::Inserted);
        assert_eq!(storage.task_alloc(10, 11), CapacityResult::Inserted);
        assert_eq!(storage.first_protected_effect(11), Decision::Allow);
        assert_eq!(storage.task_alloc(11, 12), CapacityResult::DeniedAtCapacity);
        assert_eq!(storage.first_protected_effect(12), Decision::Deny);
    }

    #[test]
    fn meta_bind_alias_resolves_through_the_oldest_mount() {
        let mut graph = MountGraph::new();
        graph.add_attachment(77, 41, "/var/run/secrets/service");
        graph.add_attachment(77, 92, "/work/input/job-42");
        assert_eq!(
            graph.canonical_path(77, "config.json").as_deref(),
            Some("/var/run/secrets/service/config.json")
        );
        assert_eq!(graph.canonical_path(88, "config.json"), None);
    }

    #[test]
    fn meta_mutation_guard_requires_one_stable_live_snapshot() {
        let mut graph = MountGraph::new();
        graph.add_attachment(77, 41, "/var/run/secrets/service");
        let initial_epoch = graph.stable_epoch();
        graph.begin_mutation();
        graph.add_attachment(77, 92, "/work/input/job-42");
        assert_eq!(graph.stable_epoch(), None);
        assert_eq!(graph.canonical_path(77, "config.json"), None);
        assert!(graph.finish_mutation());
        assert!(graph.stable_epoch() > initial_epoch);
        assert_eq!(
            graph.canonical_path(77, "config.json").as_deref(),
            Some("/var/run/secrets/service/config.json")
        );
    }

    #[test]
    fn source_ka_dns_bounds_never_truncate_to_a_name() {
        let name = BoundedDnsName::parse(&["Api", "fixture", "test"], 4, 64);
        assert_eq!(
            name.as_ref().map(BoundedDnsName::as_str),
            Some("api.fixture.test")
        );
        assert!(BoundedDnsName::parse(&["api", "fixture", "test"], 2, 64).is_none());
        assert!(BoundedDnsName::parse(&["bad_label", "test"], 4, 64).is_none());
    }

    #[test]
    fn bounded_component_graph_never_truncates_or_chooses_conflicting_authority() {
        let mut graph = ComponentGraph::new(5, 16);
        assert_eq!(
            graph.add_rule("/work/input/*/config.json", Decision::Allow),
            MatchResult::Decision(Decision::Allow)
        );
        assert_eq!(
            graph.add_rule("/work/input/job-42/config.json", Decision::Deny),
            MatchResult::Decision(Decision::Deny)
        );
        assert_eq!(
            graph.decide("/work/input/job-42/config.json"),
            MatchResult::ConflictingTerminals
        );
        assert_eq!(
            graph.decide("/one/two/three/four/five/six"),
            MatchResult::BoundExceeded
        );
    }

    #[test]
    fn source_tg_runtime_join_accepts_only_authenticated_complete_fresh_roots() {
        let mut join = RuntimeJoin::new();
        assert_eq!(
            join.join_initial_root(false, 1, "container-a", "cgroup-a"),
            RuntimeJoinResult::RejectedUnauthenticated
        );
        assert_eq!(
            join.join_initial_root(true, 1, "container-a", ""),
            RuntimeJoinResult::RejectedIncomplete
        );
        assert_eq!(
            join.join_initial_root(true, 1, "container-a", "cgroup-a"),
            RuntimeJoinResult::Joined
        );
        assert_eq!(
            join.join_initial_root(true, 1, "container-b", "cgroup-b"),
            RuntimeJoinResult::RejectedReplay
        );
        assert_eq!(join.cgroup_for("container-a"), Some("cgroup-a"));
    }

    #[test]
    fn source_tg_exec_map_requires_one_exact_stage_even_for_non_leader_exec() {
        let mut map = ExecStateMap::new(1);
        assert_eq!(map.stage(41, 7), ExecCommitResult::Staged);
        assert_eq!(map.commit(41, 7), ExecCommitResult::Committed);
        assert_eq!(map.commit(41, 7), ExecCommitResult::DeniedMissingStage);
        assert_eq!(map.stage(42, 8), ExecCommitResult::Staged);
        assert_eq!(map.stage(43, 9), ExecCommitResult::DeniedAtCapacity);
    }

    #[test]
    fn source_tg_path_rename_preserves_prior_denial_and_argument_order() {
        assert_eq!(
            RenameDecisionPoint::decide(Decision::Deny, 10, 20),
            (Decision::Deny, 10, 20)
        );
        assert_eq!(
            RenameDecisionPoint::decide(Decision::Allow, 10, 20),
            (Decision::Allow, 10, 20)
        );
    }
}
