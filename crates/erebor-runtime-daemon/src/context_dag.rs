use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_context::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextPin, ContextRepository, ContextTreeEntryKind, ForkParentAppend, ForkTarget, ScopeRef,
    Snapshot, TreeEdit,
};
use erebor_runtime_core::SessionSpec;
use erebor_runtime_session::SessionRepository;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::InvalidRequestSnafu, Result};

pub(crate) mod delivery;

pub(super) const CONTEXT_DIRECTORY: &str = "context";
pub(super) const CONTEXT_DAG_METADATA_PREFIX: &str = "erebor/context-dag";
pub(super) const CONTEXT_DAG_EDGE_SCHEMA_VERSION: u32 = 1;
pub(super) const MAX_CONTEXT_DAG_DEPTH: u8 = 16;

/// Opens the one daemon-owned context repository for a root session. A child
/// session follows its checked parent pin until it reaches that root, so it
/// never creates a second repository under its own session directory.
pub(crate) struct SessionContextResolver {
    state_root: PathBuf,
}

/// The execution claim on a checked parent-to-child scope edge. It describes
/// attribution only; it does not change the scope's containment semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextExecutionBinding {
    NativeLogical,
    DaemonPhysical,
}

impl ContextExecutionBinding {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NativeLogical => "native-logical",
            Self::DaemonPhysical => "daemon-physical",
        }
    }
}

/// The bounded daemon input required to create one immutable child scope.
/// There is no child identity beyond `child_scope` and no mutable graph state.
#[derive(Clone, Debug)]
pub(crate) struct ContextChildForkRequest {
    parent_context: ContextPin,
    child_scope: ScopeRef,
    execution_binding: ContextExecutionBinding,
    source_identity: Option<String>,
    source_tool_use_id: Option<String>,
    selected_parent_context: bool,
}

impl ContextChildForkRequest {
    pub(crate) fn new(
        parent_context: ContextPin,
        child_scope: ScopeRef,
        execution_binding: ContextExecutionBinding,
        source_identity: Option<String>,
        source_tool_use_id: Option<String>,
    ) -> Result<Self> {
        if source_identity
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 256 || value.contains('\0'))
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "context child source identity must be non-empty, bounded, and NUL-free",
                ),
            }
            .fail();
        }
        if source_tool_use_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 128 || value.contains('\0'))
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "context child source tool use ID must be non-empty, bounded, and NUL-free",
                ),
            }
            .fail();
        }
        Ok(Self {
            parent_context,
            child_scope,
            execution_binding,
            source_identity,
            source_tool_use_id,
            selected_parent_context: false,
        })
    }

    /// Make the child start from precisely the immutable blobs selected by its
    /// checked parent pin, rather than the whole causal tree.
    pub(crate) fn select_parent_context(&mut self) {
        self.selected_parent_context = true;
    }
}

/// The one durable relationship fact retained in the parent's scope tree.
/// It is written in the same checked transaction that creates the child ref.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ContextChildEdge {
    pub(super) schema_version: u32,
    pub(super) parent_context: ContextPin,
    pub(super) child_scope: String,
    pub(super) depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_tool_use_id: Option<String>,
    pub(super) execution_binding: ContextExecutionBinding,
}

/// One durable scope node returned to a session owner. The context repository
/// remains authoritative; this is a read-only projection of its refs and
/// checked parent-edge facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextScopeGraphNode {
    scope: ScopeRef,
    parent_scope: Option<ScopeRef>,
    head_commit: erebor_runtime_context::ContextObjectId,
    fork_parent_commit: Option<erebor_runtime_context::ContextObjectId>,
    source_identity: Option<String>,
    source_tool_use_id: Option<String>,
    execution_binding: Option<ContextExecutionBinding>,
    depth: u8,
}

impl ContextScopeGraphNode {
    #[must_use]
    pub(crate) const fn scope(&self) -> &ScopeRef {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn parent_scope(&self) -> Option<&ScopeRef> {
        self.parent_scope.as_ref()
    }

    #[must_use]
    pub(crate) const fn head_commit(&self) -> erebor_runtime_context::ContextObjectId {
        self.head_commit
    }

    #[must_use]
    pub(crate) const fn fork_parent_commit(
        &self,
    ) -> Option<erebor_runtime_context::ContextObjectId> {
        self.fork_parent_commit
    }

    #[must_use]
    pub(crate) fn source_identity(&self) -> Option<&str> {
        self.source_identity.as_deref()
    }

    #[must_use]
    pub(crate) fn source_tool_use_id(&self) -> Option<&str> {
        self.source_tool_use_id.as_deref()
    }

    #[must_use]
    pub(crate) const fn execution_binding(&self) -> Option<ContextExecutionBinding> {
        self.execution_binding
    }

    #[must_use]
    pub(crate) const fn depth(&self) -> u8 {
        self.depth
    }
}

/// One durable, scope-owned activity rendered beneath its branch. This is a
/// compact daemon projection of authenticated context facts, never a client
/// read of the root-owned repository or a raw context-blob dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextScopeGraphActivity {
    scope: ScopeRef,
    path: String,
    summary: String,
    tool_use_id: Option<String>,
}

impl ContextScopeGraphActivity {
    #[must_use]
    pub(crate) const fn scope(&self) -> &ScopeRef {
        &self.scope
    }

    #[must_use]
    pub(crate) fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub(crate) fn tool_use_id(&self) -> Option<&str> {
        self.tool_use_id.as_deref()
    }
}

struct ContextScopeGraphActivitySummary {
    summary: String,
    tool_use_id: Option<String>,
}

/// Serializes durable scope topology in one root session repository. This is
/// deliberately not a graph registry: refs and checked edge blobs are the
/// complete retained graph.
pub(crate) struct ContextDagCoordinator {
    pub(super) repository: Arc<ContextRepository>,
    pub(super) root_scope: ScopeRef,
    pub(super) mutation_lock: Mutex<()>,
}

impl ContextDagCoordinator {
    pub(crate) fn new(repository: Arc<ContextRepository>, root_scope: ScopeRef) -> Result<Self> {
        repository.scope_head(&root_scope).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("context DAG root scope is unavailable: {error}"),
            }
            .build()
        })?;
        Ok(Self {
            repository,
            root_scope,
            mutation_lock: Mutex::new(()),
        })
    }

    /// Create a contained child ref from an exact, validated parent decision.
    /// The child ref and the parent-side edge fact either advance together or
    /// neither becomes visible.
    pub(crate) fn admit_child(&self, request: ContextChildForkRequest) -> Result<()> {
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            InvalidRequestSnafu {
                reason: String::from("context DAG coordinator mutation lock is poisoned"),
            }
            .build()
        })?;
        let parent_scope = request.parent_context.scope().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("child parent context has an invalid scope: {error}"),
            }
            .build()
        })?;
        if parent_scope == request.child_scope {
            return InvalidRequestSnafu {
                reason: String::from("a context child scope must differ from its direct parent"),
            }
            .fail();
        }
        self.repository
            .validate_pin(&request.parent_context)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("child parent context does not validate: {error}"),
                }
                .build()
            })?;
        let parent_depth = self.scope_depth(&parent_scope, &mut HashSet::new())?;
        let depth = parent_depth.checked_add(1).ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("context DAG depth overflow"),
            }
            .build()
        })?;
        if depth > MAX_CONTEXT_DAG_DEPTH {
            return InvalidRequestSnafu {
                reason: format!("context DAG depth exceeds {MAX_CONTEXT_DAG_DEPTH}"),
            }
            .fail();
        }
        let parent_head = self.repository.scope_head(&parent_scope).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not read parent scope head: {error}"),
            }
            .build()
        })?;
        let causal_commit = request.parent_context.commit().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("child parent context has an invalid commit: {error}"),
            }
            .build()
        })?;
        if !self
            .repository
            .is_ancestor(causal_commit, parent_head)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not verify parent causal ancestry: {error}"),
                }
                .build()
            })?
        {
            return InvalidRequestSnafu {
                reason: String::from("parent decision pin is not retained by its parent scope"),
            }
            .fail();
        }
        let edge_path = Self::edge_path(&request.child_scope);
        if self
            .repository
            .read_commit_blob(parent_head, &edge_path)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not inspect the parent edge path: {error}"),
                }
                .build()
            })?
            .is_some()
        {
            return InvalidRequestSnafu {
                reason: format!(
                    "child scope `{}` already has an admitted edge",
                    request.child_scope
                ),
            }
            .fail();
        }
        let fork_target = if request.selected_parent_context {
            self.selected_parent_context_tree(&request.parent_context)?
        } else {
            ForkTarget::reuse_causal_commit()
        };
        let edge = ContextChildEdge {
            schema_version: CONTEXT_DAG_EDGE_SCHEMA_VERSION,
            parent_context: request.parent_context,
            child_scope: request.child_scope.to_string(),
            depth,
            source_identity: request.source_identity,
            source_tool_use_id: request.source_tool_use_id,
            execution_binding: request.execution_binding,
        };
        let edge_bytes = serde_json::to_vec(&edge).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not encode context child edge: {error}"),
            }
            .build()
        })?;
        let parent_tree = self
            .repository
            .create_tree_from_commit(
                parent_head,
                Snapshot::new(vec![TreeEdit::blob(edge_path, edge_bytes).map_err(
                    |error| {
                        InvalidRequestSnafu {
                            reason: format!("could not construct context child edge: {error}"),
                        }
                        .build()
                    },
                )?])
                .map_err(|error| {
                    InvalidRequestSnafu {
                        reason: format!("could not construct context child edge snapshot: {error}"),
                    }
                    .build()
                })?,
            )
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not construct parent context result tree: {error}"),
                }
                .build()
            })?;
        self.repository
            .fork_scope(
                causal_commit,
                request.child_scope,
                fork_target,
                Some(ForkParentAppend::new(
                    parent_scope,
                    parent_head,
                    parent_tree,
                    "Admit contained context child",
                )),
            )
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not atomically admit context child: {error}"),
                }
                .build()
            })?;
        Ok(())
    }

    /// Return the complete durable scope topology rooted at this coordinator.
    /// Every non-root scope is revalidated through its retained parent edge so
    /// a graph display cannot hide malformed or reparented context state.
    pub(crate) fn graph(
        &self,
    ) -> Result<(Vec<ContextScopeGraphNode>, Vec<ContextScopeGraphActivity>)> {
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            InvalidRequestSnafu {
                reason: String::from("context DAG coordinator mutation lock is poisoned"),
            }
            .build()
        })?;
        let scopes = self.repository.scope_refs().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not enumerate context scopes: {error}"),
            }
            .build()
        })?;
        let mut nodes = Vec::with_capacity(scopes.len());
        let mut activities = Vec::new();
        for scope in scopes {
            let head_commit = self.repository.scope_head(&scope).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not read context scope `{scope}`: {error}"),
                }
                .build()
            })?;
            if scope == self.root_scope {
                activities.extend(self.scope_activities(&scope, head_commit, None)?);
                nodes.push(ContextScopeGraphNode {
                    scope,
                    parent_scope: None,
                    head_commit,
                    fork_parent_commit: None,
                    source_identity: None,
                    source_tool_use_id: None,
                    execution_binding: None,
                    depth: 0,
                });
                continue;
            }
            let edge = self.direct_edge(&scope)?;
            let parent_scope = edge.parent_context.scope().map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("context edge has an invalid parent scope: {error}"),
                }
                .build()
            })?;
            let fork_parent_commit = edge.parent_context.commit().map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("context edge has an invalid parent commit: {error}"),
                }
                .build()
            })?;
            let depth = self.scope_depth(&scope, &mut HashSet::new())?;
            activities.extend(self.scope_activities(
                &scope,
                head_commit,
                Some(fork_parent_commit),
            )?);
            nodes.push(ContextScopeGraphNode {
                scope,
                parent_scope: Some(parent_scope),
                head_commit,
                fork_parent_commit: Some(fork_parent_commit),
                source_identity: edge.source_identity,
                source_tool_use_id: edge.source_tool_use_id,
                execution_binding: Some(edge.execution_binding),
                depth,
            });
        }
        if !nodes.iter().any(|node| node.scope == self.root_scope) {
            return InvalidRequestSnafu {
                reason: String::from("context DAG root scope disappeared"),
            }
            .fail();
        }
        nodes.sort_by(|left, right| {
            left.depth
                .cmp(&right.depth)
                .then_with(|| left.scope.as_str().cmp(right.scope.as_str()))
        });
        activities.sort_by(|left, right| {
            left.scope
                .as_str()
                .cmp(right.scope.as_str())
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok((nodes, activities))
    }

    fn scope_activities(
        &self,
        scope: &ScopeRef,
        head_commit: erebor_runtime_context::ContextObjectId,
        fork_parent_commit: Option<erebor_runtime_context::ContextObjectId>,
    ) -> Result<Vec<ContextScopeGraphActivity>> {
        let head_blobs = self.commit_blobs(head_commit)?;
        let parent_blobs = fork_parent_commit
            .map_or_else(|| Ok(BTreeMap::new()), |commit| self.commit_blobs(commit))?;
        let mut activities = Vec::new();
        for (path, object) in head_blobs {
            if parent_blobs.get(&path) == Some(&object) {
                continue;
            }
            let Some(activity) = self.activity_summary(scope, &path, object)? else {
                continue;
            };
            activities.push(ContextScopeGraphActivity {
                scope: scope.clone(),
                path,
                summary: activity.summary,
                tool_use_id: activity.tool_use_id,
            });
        }
        Ok(activities)
    }

    fn commit_blobs(
        &self,
        commit: erebor_runtime_context::ContextObjectId,
    ) -> Result<BTreeMap<String, erebor_runtime_context::ContextObjectId>> {
        let tree = self.repository.read_commit(commit).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not inspect context graph commit `{commit}`: {error}"),
            }
            .build()
        })?;
        let mut blobs = BTreeMap::new();
        self.collect_tree_blobs(tree.tree(), "", &mut blobs)?;
        Ok(blobs)
    }

    fn collect_tree_blobs(
        &self,
        tree: erebor_runtime_context::ContextObjectId,
        prefix: &str,
        blobs: &mut BTreeMap<String, erebor_runtime_context::ContextObjectId>,
    ) -> Result<()> {
        let tree = self.repository.read_tree(tree).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not inspect context graph tree: {error}"),
            }
            .build()
        })?;
        for entry in tree.entries() {
            let name = std::str::from_utf8(entry.name()).map_err(|_error| {
                InvalidRequestSnafu {
                    reason: String::from("context graph tree path is not UTF-8"),
                }
                .build()
            })?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            match entry.kind() {
                ContextTreeEntryKind::Tree => {
                    self.collect_tree_blobs(entry.object(), &path, blobs)?;
                }
                ContextTreeEntryKind::Blob => {
                    blobs.insert(path, entry.object());
                }
                ContextTreeEntryKind::Commit => {
                    return InvalidRequestSnafu {
                        reason: String::from("context graph tree unexpectedly contains a commit"),
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }

    fn activity_summary(
        &self,
        scope: &ScopeRef,
        path: &str,
        object: erebor_runtime_context::ContextObjectId,
    ) -> Result<Option<ContextScopeGraphActivitySummary>> {
        const HOOK_PREFIX: &str = "agents/codex/hooks/";
        const PHYSICAL_EFFECT_PREFIX: &str = "agents/codex/physical-effects/";
        const CONTEXT_DAG_PREFIX: &str = "erebor/context-dag/";
        if !path.starts_with(HOOK_PREFIX)
            && !path.starts_with(PHYSICAL_EFFECT_PREFIX)
            && !path.starts_with(CONTEXT_DAG_PREFIX)
        {
            return Ok(None);
        }
        let object = self.repository.read_object(object).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not read retained context activity `{path}`: {error}"),
            }
            .build()
        })?;
        let record: serde_json::Value =
            serde_json::from_slice(object.bytes()).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "retained context activity `{path}` is not valid JSON: {error}"
                    ),
                }
                .build()
            })?;
        if path.starts_with(PHYSICAL_EFFECT_PREFIX) {
            return self
                .physical_effect_summary(scope, path, &record)
                .map(|summary| {
                    Some(ContextScopeGraphActivitySummary {
                        summary,
                        tool_use_id: None,
                    })
                });
        }
        if path.starts_with(CONTEXT_DAG_PREFIX) {
            return self
                .delivery_graph_activity_summary(scope, path, &record)
                .map(|summary| {
                    summary.map(|summary| ContextScopeGraphActivitySummary {
                        summary,
                        tool_use_id: None,
                    })
                });
        }
        let native = record.get("native").unwrap_or(&record);
        let event = native
            .get("hook_event_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("hook");
        let (summary, tool_use_id) = match event {
            "UserPromptSubmit" | "user_prompt_submit" => {
                let thread = Self::activity_string(native, &["session_id", "sessionId"]);
                let turn = Self::activity_string(native, &["turn_id", "turnId"]);
                (format!("turn {thread}/{turn}"), None)
            }
            "PreToolUse" | "pre_tool_use" => {
                let tool = Self::activity_token(native, &["tool_name", "toolName"]);
                let tool_use_id = native
                    .get("tool_use_id")
                    .or_else(|| native.get("toolUseId"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned);
                let input = native.get("tool_input").or_else(|| native.get("toolInput"));
                let command = input
                    .and_then(|input| input.get("command"))
                    .and_then(serde_json::Value::as_str);
                if let Some(command) = command.filter(|command| !command.is_empty()) {
                    (
                        format!("tool {tool} command={}", Self::quoted_activity(command)),
                        tool_use_id,
                    )
                } else if matches!(tool.as_str(), "erebor_delegate" | "erebor-delegate") {
                    let child_thread = input.map_or_else(
                        || String::from("unknown"),
                        |input| Self::activity_string(input, &["child_thread_id", "childThreadId"]),
                    );
                    let child_turn = input.map_or_else(
                        || String::from("unknown"),
                        |input| Self::activity_string(input, &["child_turn_id", "childTurnId"]),
                    );
                    (
                        format!("logical fork {child_thread}/{child_turn}"),
                        tool_use_id,
                    )
                } else {
                    (format!("tool {tool}"), tool_use_id)
                }
            }
            "PostToolUse" | "post_tool_use" => {
                let tool_use = Self::activity_string(native, &["tool_use_id", "toolUseId"]);
                (format!("tool completed {tool_use}"), None)
            }
            other => (format!("hook {other}"), None),
        };
        Ok(Some(ContextScopeGraphActivitySummary {
            summary,
            tool_use_id,
        }))
    }

    fn physical_effect_summary(
        &self,
        scope: &ScopeRef,
        path: &str,
        record: &serde_json::Value,
    ) -> Result<String> {
        if record
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
            || record.get("source").and_then(serde_json::Value::as_str)
                != Some("erebor_guarded_physical_effect")
            || record.get("kind").and_then(serde_json::Value::as_str) != Some("physical-effect")
        {
            return InvalidRequestSnafu {
                reason: format!("retained physical effect `{path}` has an invalid record shape"),
            }
            .fail();
        }
        let effect = record.get("effect").ok_or_else(|| {
            InvalidRequestSnafu {
                reason: format!("retained physical effect `{path}` omits its effect"),
            }
            .build()
        })?;
        let lease_scope = effect
            .pointer("/lease/scope_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!("retained physical effect `{path}` omits its lease scope"),
                }
                .build()
            })?;
        let source_scope = record
            .pointer("/source_context/scope_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!(
                        "retained physical effect `{path}` omits its causal source context"
                    ),
                }
                .build()
            })?;
        let operation_scope = effect
            .pointer("/lease/operation_scope")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        if source_scope != lease_scope || operation_scope.unwrap_or(lease_scope) != scope.as_str() {
            return InvalidRequestSnafu {
                reason: format!(
                    "retained physical effect `{path}` is not bound to its containing context scope"
                ),
            }
            .fail();
        }
        let allowed = effect
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!("retained physical effect `{path}` omits its decision"),
                }
                .build()
            })?;
        let operation = effect
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!("retained physical effect `{path}` omits its operation"),
                }
                .build()
            })?;
        let pid = effect
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!("retained physical effect `{path}` omits its process ID"),
                }
                .build()
            })?;
        let tool_name = effect
            .pointer("/lease/tool_name")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!(
                        "retained physical effect `{path}` omits its originating tool name"
                    ),
                }
                .build()
            })?;
        let tool_use_id = effect
            .pointer("/lease/tool_use_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: format!(
                        "retained physical effect `{path}` omits its originating tool use ID"
                    ),
                }
                .build()
            })?;
        let verdict = if allowed { "allowed" } else { "denied" };
        let target = if operation == "process_exec" {
            let executable = effect
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    InvalidRequestSnafu {
                        reason: format!(
                            "retained physical effect `{path}` omits its process executable"
                        ),
                    }
                    .build()
                })?;
            format!("exec {}", Self::activity_token_text(executable))
        } else {
            format!("effect {}", Self::activity_token_text(operation))
        };
        Ok(format!(
            "{target} {verdict} pid={pid} via {} {}",
            Self::activity_token_text(tool_name),
            Self::activity_token_text(tool_use_id)
        ))
    }

    fn activity_string(value: &serde_json::Value, names: &[&str]) -> String {
        names
            .iter()
            .find_map(|name| value.get(*name).and_then(serde_json::Value::as_str))
            .map_or_else(|| String::from("unknown"), Self::quoted_activity)
    }

    fn activity_token(value: &serde_json::Value, names: &[&str]) -> String {
        names
            .iter()
            .find_map(|name| value.get(*name).and_then(serde_json::Value::as_str))
            .filter(|value| !value.is_empty())
            .map_or_else(|| String::from("unknown"), Self::activity_token_text)
    }

    fn activity_token_text(value: &str) -> String {
        if value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-/".contains(character))
        {
            value.to_owned()
        } else {
            Self::quoted_activity(value)
        }
    }

    fn activity_scope_label(scope: &ScopeRef) -> String {
        let label = scope.as_str().rsplit('/').next().unwrap_or(scope.as_str());
        let mut shortened = label.chars().take(24).collect::<String>();
        if label.chars().nth(24).is_some() {
            shortened.push('…');
        }
        shortened
    }

    fn quoted_activity(value: &str) -> String {
        const MAX_ACTIVITY_VALUE_CHARS: usize = 160;
        let mut shortened = value
            .chars()
            .take(MAX_ACTIVITY_VALUE_CHARS)
            .collect::<String>();
        if value.chars().nth(MAX_ACTIVITY_VALUE_CHARS).is_some() {
            shortened.push('…');
        }
        format!("{shortened:?}")
    }

    fn selected_parent_context_tree(&self, parent: &ContextPin) -> Result<ForkTarget> {
        let selected = self
            .repository
            .read_pinned_context(parent)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not read selected parent context: {error}"),
                }
                .build()
            })?;
        let edits = selected
            .selected_blobs()
            .iter()
            .map(|blob| {
                TreeEdit::blob(blob.path(), blob.bytes()).map_err(|error| {
                    InvalidRequestSnafu {
                        reason: format!("could not select parent context blob: {error}"),
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let tree = self
            .repository
            .create_tree(Snapshot::new(edits).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not construct selected parent context tree: {error}"),
                }
                .build()
            })?)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not create selected parent context tree: {error}"),
                }
                .build()
            })?;
        Ok(ForkTarget::selected_tree(
            tree,
            "Freeze selected parent context for child",
        ))
    }

    /// Verify the durable ancestry and parent-edge chain for one contained
    /// scope. It never infers a relationship from a process, session record,
    /// or App Server thread identifier.
    #[cfg(test)]
    pub(crate) fn verify_scope(&self, scope: &ScopeRef) -> Result<()> {
        self.scope_depth(scope, &mut HashSet::new())
            .map(|_depth| ())
    }

    pub(super) fn scope_depth(
        &self,
        scope: &ScopeRef,
        visited: &mut HashSet<String>,
    ) -> Result<u8> {
        if scope == &self.root_scope {
            return Ok(0);
        }
        if !visited.insert(scope.to_string()) {
            return InvalidRequestSnafu {
                reason: format!("context edge cycle includes scope `{scope}`"),
            }
            .fail();
        }
        let edge = self.direct_edge(scope)?;
        let parent_scope = edge.parent_context.scope().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("context edge has an invalid parent scope: {error}"),
            }
            .build()
        })?;
        if &parent_scope == scope {
            return InvalidRequestSnafu {
                reason: format!("context edge makes scope `{scope}` its own parent"),
            }
            .fail();
        }
        self.repository
            .validate_pin(&edge.parent_context)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("context edge has an invalid parent pin: {error}"),
                }
                .build()
            })?;
        let parent_depth = self.scope_depth(&parent_scope, visited)?;
        let expected_depth = parent_depth.checked_add(1).ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("context edge depth overflow"),
            }
            .build()
        })?;
        if edge.schema_version != CONTEXT_DAG_EDGE_SCHEMA_VERSION
            || edge.depth != expected_depth
            || edge.depth > MAX_CONTEXT_DAG_DEPTH
        {
            return InvalidRequestSnafu {
                reason: format!(
                    "context edge for scope `{scope}` has inconsistent depth or schema"
                ),
            }
            .fail();
        }
        let child_head = self.repository.scope_head(scope).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not read context child scope `{scope}`: {error}"),
            }
            .build()
        })?;
        let causal_commit = edge.parent_context.commit().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("context edge has an invalid parent commit: {error}"),
            }
            .build()
        })?;
        if !self
            .repository
            .is_ancestor(causal_commit, child_head)
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not verify context child ancestry: {error}"),
                }
                .build()
            })?
        {
            return InvalidRequestSnafu {
                reason: format!("context child scope `{scope}` is not causal from its parent pin"),
            }
            .fail();
        }
        Ok(edge.depth)
    }

    pub(super) fn direct_edge(&self, child: &ScopeRef) -> Result<ContextChildEdge> {
        let edge_path = Self::edge_path(child);
        let mut found = None;
        for candidate_parent in self.repository.scope_refs().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not enumerate context scopes: {error}"),
            }
            .build()
        })? {
            let head = self
                .repository
                .scope_head(&candidate_parent)
                .map_err(|error| {
                    InvalidRequestSnafu {
                        reason: format!(
                            "could not inspect context scope `{candidate_parent}`: {error}"
                        ),
                    }
                    .build()
                })?;
            let Some(blob) =
                self.repository
                    .read_commit_blob(head, &edge_path)
                    .map_err(|error| {
                        InvalidRequestSnafu {
                            reason: format!("could not read context edge metadata: {error}"),
                        }
                        .build()
                    })?
            else {
                continue;
            };
            let edge: ContextChildEdge = serde_json::from_slice(blob.bytes()).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("context edge metadata is invalid JSON: {error}"),
                }
                .build()
            })?;
            let declared_parent = edge.parent_context.scope().map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("context edge metadata has an invalid parent scope: {error}"),
                }
                .build()
            })?;
            if edge.child_scope != child.as_str() || declared_parent != candidate_parent {
                continue;
            }
            if found.replace(edge).is_some() {
                return InvalidRequestSnafu {
                    reason: format!(
                        "context child scope `{child}` has multiple direct parent edges"
                    ),
                }
                .fail();
            }
        }
        found.ok_or_else(|| {
            InvalidRequestSnafu {
                reason: format!("context child scope `{child}` has no direct parent edge"),
            }
            .build()
        })
    }

    pub(super) fn edge_path(child_scope: &ScopeRef) -> String {
        let digest = Sha256::digest(child_scope.as_str().as_bytes());
        format!("{CONTEXT_DAG_METADATA_PREFIX}/edges/{digest:x}.json")
    }
}

impl SessionContextResolver {
    pub(crate) fn new(state_root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: state_root.into(),
        }
    }

    pub(crate) fn resolve(&self, spec: &SessionSpec) -> Result<Arc<ContextRepository>> {
        self.resolve_with_seen(spec, &mut HashSet::new())
    }

    fn resolve_with_seen(
        &self,
        spec: &SessionSpec,
        seen_sessions: &mut HashSet<String>,
    ) -> Result<Arc<ContextRepository>> {
        let session_id = spec.session_id().as_str();
        if !seen_sessions.insert(session_id.to_owned()) {
            return InvalidRequestSnafu {
                reason: format!("context parent cycle includes session `{session_id}`"),
            }
            .fail();
        }
        let Some(parent_context) = spec.parent_context() else {
            return self.open_or_initialize_root(spec);
        };
        let parent_scope = parent_context.scope().map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("invalid child parent context: {error}"),
            }
            .build()
        })?;
        if parent_scope.session_id() == session_id {
            return InvalidRequestSnafu {
                reason: String::from("a child context must name a different parent session"),
            }
            .fail();
        }
        let parent = SessionRepository::new(&self.state_root)
            .load(spec.owner().uid(), parent_scope.session_id())
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "could not resolve parent session `{}` for context recovery: {error}",
                        parent_scope.session_id()
                    ),
                }
                .build()
            })?;
        let repository = self.resolve_with_seen(parent.spec(), seen_sessions)?;
        repository.validate_pin(parent_context).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("child parent context does not validate: {error}"),
            }
            .build()
        })?;
        Ok(repository)
    }

    fn open_or_initialize_root(&self, spec: &SessionSpec) -> Result<Arc<ContextRepository>> {
        let record = SessionRepository::new(&self.state_root)
            .load(spec.owner().uid(), spec.session_id().as_str())
            .map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!(
                        "could not resolve root session `{}` for context recovery: {error}",
                        spec.session_id().as_str()
                    ),
                }
                .build()
            })?;
        let artifact = record.context_artifact().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: format!(
                    "root session `{}` has no owned context artifact",
                    spec.session_id().as_str()
                ),
            }
            .build()
        })?;
        if artifact.path() != Path::new(CONTEXT_DIRECTORY) {
            return InvalidRequestSnafu {
                reason: format!(
                    "root session `{}` has an unsupported context artifact path `{}`",
                    spec.session_id().as_str(),
                    artifact.path().display()
                ),
            }
            .fail();
        }
        let path = self
            .state_root
            .join("users")
            .join(spec.owner().uid().to_string())
            .join("sessions")
            .join(spec.session_id().as_str())
            .join(CONTEXT_DIRECTORY);
        let repository = if path.exists() {
            ContextRepository::open(&path, DaemonContextMetadata)
        } else {
            ContextRepository::init(&path, DaemonContextMetadata)
        }
        .map_err(|error| {
            InvalidRequestSnafu {
                reason: format!(
                    "could not open the daemon-owned root context repository `{}`: {error}",
                    path.display()
                ),
            }
            .build()
        })?;
        Ok(Arc::new(repository))
    }
}

struct DaemonContextMetadata;

impl CommitMetadataSource for DaemonContextMetadata {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs() as i64);
        let time = CommitTime::new(seconds, 0)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
        let signature = CommitSignature::new("erebord", "erebord@localhost", time)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
        Ok(CommitMetadata::new(signature.clone(), signature))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        error::Error,
        path::PathBuf,
        sync::Arc,
    };

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, ContextPin, ContextPinSelection, ContextRepository, ScopeRef, Snapshot,
        TreeEdit,
    };
    use erebor_runtime_core::{
        ActiveSessionSignalKind, DaemonFailureMode, ImmutableIdentity, OutputPlan,
        OutputStreamRequirements, RunnerCapabilityDocument, RunnerId, SafePathBinding,
        SafePathKind, SessionAdmission, SessionOwner, SessionSpec, WorkloadPrivilegePlan,
    };
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::SessionRepository;

    use super::{
        delivery::{ContextDeliveryKind, ContextDeliveryMode, ContextDeliveryPublication},
        ContextChildForkRequest, ContextDagCoordinator, ContextExecutionBinding,
    };

    type RootFixture = (
        tempfile::TempDir,
        Arc<ContextRepository>,
        ScopeRef,
        ContextPin,
    );

    fn root_fixture() -> Result<RootFixture, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        let root = ScopeRef::root("parent-session")?;
        repository.initialize_root(
            "parent-session",
            Snapshot::default(),
            "Initialize parent context root",
        )?;
        let pin = repository.pin_scope_head(root.clone(), &[])?.pin().clone();
        Ok((temporary, repository, root, pin))
    }

    fn request(
        parent_context: ContextPin,
        child_scope: ScopeRef,
        binding: ContextExecutionBinding,
    ) -> Result<ContextChildForkRequest, Box<dyn Error>> {
        Ok(ContextChildForkRequest::new(
            parent_context,
            child_scope,
            binding,
            Some(String::from("codex-v1:test")),
            None,
        )?)
    }

    fn session_spec(
        state_root: &std::path::Path,
        session_id: &str,
        parent_context: Option<ContextPin>,
    ) -> Result<SessionSpec, Box<dyn Error>> {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let runner_capability = RunnerCapabilityDocument::new(
            RunnerId::new("linux-host")?,
            "linux-host-v1",
            "1",
            "linux",
            "x86_64",
            true,
            true,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
            ]),
            false,
            true,
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue]),
            BTreeMap::new(),
        )?;
        Ok(SessionSpec::new(SessionAdmission {
            session_id: SessionId::new(session_id),
            parent_context,
            owner: SessionOwner::new(1000, 1000),
            workload_privileges: WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 512, 0)?,
            command: vec![String::from("/usr/bin/agent")],
            package: None,
            package_configuration: None,
            installation: None,
            adapter: None,
            policy_inputs: vec![ImmutableIdentity::new("root-policy", digest)?],
            policy_set: ImmutableIdentity::new("policy-set", digest)?,
            runner_capability,
            workspace: SafePathBinding::new(
                PathBuf::from("/workspace"),
                1,
                2,
                1,
                1000,
                1000,
                SafePathKind::Directory,
            )?,
            executable: Some(
                SafePathBinding::new(
                    PathBuf::from("/usr/bin/agent"),
                    1,
                    3,
                    1,
                    0,
                    0,
                    SafePathKind::Executable,
                )?
                .with_content_sha256(String::from(digest))?,
            ),
            script_interpreters: Vec::new(),
            container_image: None,
            environment: Vec::new(),
            secret_references: Vec::new(),
            filesystem_projections: Vec::new(),
            endpoint_projections: Vec::new(),
            output: OutputPlan::new(
                state_root
                    .join("users")
                    .join("1000")
                    .join("sessions")
                    .join(session_id)
                    .join("output"),
                1024,
                512,
                64,
                OutputStreamRequirements::required(),
            )?,
            evidence_requirements: Vec::new(),
            tty: false,
            terminal_size: None,
            detached: true,
            daemon_failure_mode: DaemonFailureMode::Terminate,
            loss_grace_seconds: 10,
            root_configuration_generation: 1,
            created_at_unix_ms: 1,
        })?)
    }

    #[test]
    fn child_session_resolves_the_root_artifact_without_output_context_repository(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = SessionRepository::new(temporary.path());
        let root_spec = session_spec(temporary.path(), "root-session", None)?;
        repository.create(root_spec.clone())?;
        let resolver = super::SessionContextResolver::new(temporary.path());
        let root_context = resolver.resolve(&root_spec)?;
        let root_scope = ScopeRef::root("root-session")?;
        root_context.initialize_root("root-session", Snapshot::default(), "Initialize root")?;
        let root_pin = root_context.pin_scope_head(root_scope, &[])?.pin().clone();
        let child_spec = session_spec(temporary.path(), "child-session", Some(root_pin))?;
        let child_record = repository.create(child_spec.clone())?;

        let child_context = resolver.resolve(&child_spec)?;

        assert!(child_record.context_artifact().is_none());
        assert_eq!(child_context.path(), root_context.path());
        assert!(!temporary
            .path()
            .join("users")
            .join("1000")
            .join("sessions")
            .join("child-session")
            .join("context")
            .exists());
        assert!(!root_spec.output().root().join("codex-context").exists());
        Ok(())
    }

    #[test]
    fn atomically_forks_siblings_and_a_grandchild_from_exact_parent_pins(
    ) -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, root, root_pin) = root_fixture()?;
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root.clone())?;
        let child_b = ScopeRef::root("child-b")?;
        let child_c = ScopeRef::root("child-c")?;

        coordinator.admit_child(request(
            root_pin.clone(),
            child_b.clone(),
            ContextExecutionBinding::DaemonPhysical,
        )?)?;
        coordinator.admit_child(request(
            root_pin.clone(),
            child_c.clone(),
            ContextExecutionBinding::NativeLogical,
        )?)?;
        let child_b_pin = repository
            .pin_scope_head(child_b.clone(), &[])?
            .pin()
            .clone();
        let grandchild = ScopeRef::root("grandchild-d")?;
        coordinator.admit_child(request(
            child_b_pin.clone(),
            grandchild.clone(),
            ContextExecutionBinding::DaemonPhysical,
        )?)?;

        for scope in [&child_b, &child_c, &grandchild] {
            coordinator.verify_scope(scope)?;
        }
        assert!(repository.is_ancestor(root_pin.commit()?, repository.scope_head(&child_b)?)?);
        assert!(repository.is_ancestor(root_pin.commit()?, repository.scope_head(&child_c)?)?);
        assert!(repository.is_ancestor(child_b_pin.commit()?, repository.scope_head(&grandchild)?)?);
        let root_head = repository.scope_head(&root)?;
        let edge_path = ContextDagCoordinator::edge_path(&child_b);
        assert!(repository
            .read_commit_blob(root_head, &edge_path)?
            .is_some());
        assert_eq!(repository.scope_refs()?.len(), 4);
        Ok(())
    }

    #[test]
    fn graph_returns_the_complete_checked_scope_topology() -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, root, root_pin) = root_fixture()?;
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root.clone())?;
        let child = ScopeRef::scope("parent-session", "child")?;
        coordinator.admit_child(request(
            root_pin,
            child.clone(),
            ContextExecutionBinding::NativeLogical,
        )?)?;
        let child_head = repository.scope_head(&child)?;
        let physical_effect = serde_json::json!({
            "schema_version": 1,
            "source": "erebor_guarded_physical_effect",
            "kind": "physical-effect",
            "source_context": {"scope_ref": child.as_str()},
            "effect": {
                "allowed": true,
                "operation": "process_exec",
                "pid": 123,
                "ppid": 42,
                "executable": "/bin/ls",
                "argv": ["/bin/ls"],
                "lease": {
                    "id": "lease-1",
                    "scope_ref": child.as_str(),
                    "item_node_stream": "item",
                    "decision_head": "head",
                    "codex_session_id": "thread",
                    "turn_id": "turn",
                    "tool_use_id": "tool",
                    "tool_name": "bash",
                    "operation_scope": serde_json::Value::Null,
                },
            },
        });
        repository.append_snapshot(
            child.clone(),
            child_head,
            Snapshot::new(vec![TreeEdit::blob(
                "agents/codex/hooks/00000000000000000001-pre-tool-use.json",
                br#"{"native":{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":{"command":"ls"}}}"#.to_vec(),
            )?, TreeEdit::blob(
                "agents/codex/physical-effects/00000000000000000001.json",
                serde_json::to_vec(&physical_effect)?,
            )?])?,
            "Record governed command",
        )?;
        let child_pin = repository.pin_scope_head(child.clone(), &[])?.pin().clone();
        let grandchild = ScopeRef::scope("parent-session", "grandchild")?;
        coordinator.admit_child(request(
            child_pin,
            grandchild.clone(),
            ContextExecutionBinding::DaemonPhysical,
        )?)?;

        let (graph, activities) = coordinator.graph()?;
        assert_eq!(graph.len(), 3);
        let root_node = graph
            .iter()
            .find(|node| node.scope() == &root)
            .ok_or("missing root graph node")?;
        assert_eq!(root_node.depth(), 0);
        assert!(root_node.parent_scope().is_none());
        let child_node = graph
            .iter()
            .find(|node| node.scope() == &child)
            .ok_or("missing child graph node")?;
        assert_eq!(child_node.parent_scope(), Some(&root));
        assert_eq!(child_node.depth(), 1);
        assert_eq!(
            child_node.execution_binding(),
            Some(ContextExecutionBinding::NativeLogical)
        );
        assert_eq!(child_node.source_identity(), Some("codex-v1:test"));
        let grandchild_node = graph
            .iter()
            .find(|node| node.scope() == &grandchild)
            .ok_or("missing grandchild graph node")?;
        assert_eq!(grandchild_node.parent_scope(), Some(&child));
        assert_eq!(grandchild_node.depth(), 2);
        assert_eq!(
            grandchild_node.execution_binding(),
            Some(ContextExecutionBinding::DaemonPhysical)
        );
        assert!(grandchild_node.fork_parent_commit().is_some());
        assert_eq!(activities.len(), 2);
        assert_eq!(activities[0].scope(), &child);
        assert_eq!(activities[0].summary(), "tool bash command=\"ls\"");
        assert_eq!(activities[1].scope(), &child);
        assert_eq!(
            activities[1].summary(),
            "exec /bin/ls allowed pid=123 via bash tool"
        );
        Ok(())
    }

    #[test]
    fn graph_keeps_tool_caused_operations_and_parent_merges_durable() -> Result<(), Box<dyn Error>>
    {
        let (_temporary, repository, root, _root_pin) = root_fixture()?;
        let hook_head = repository.append_snapshot(
            root.clone(),
            repository.scope_head(&root)?,
            Snapshot::new(vec![TreeEdit::blob(
                "agents/codex/hooks/00000000000000000001-pre-tool-use.json",
                br#"{"native":{"hook_event_name":"PreToolUse","tool_use_id":"q-tool","tool_name":"bash","tool_input":{"command":"sleep 1","erebor_operation_key":"fixture-q"}}}"#.to_vec(),
            )?])?,
            "Record q admission hook",
        )?;
        let parent_pin = repository
            .pin_commit(root.clone(), hook_head, &[])?
            .pin()
            .clone();
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root.clone())?;
        let operation = ScopeRef::scope("parent-session", "codex-operation-fixture-q")?;
        coordinator.admit_child(ContextChildForkRequest::new(
            parent_pin,
            operation.clone(),
            ContextExecutionBinding::NativeLogical,
            Some(String::from("codex-v1:operation:fixture-q")),
            Some(String::from("q-tool")),
        )?)?;
        let published = coordinator.publish_delivery(ContextDeliveryPublication::new(
            operation.clone(),
            1,
            ContextDeliveryKind::Result,
            ContextDeliveryMode::Queue,
            b"q partial".to_vec(),
        )?)?;
        coordinator.receive_delivery(
            &root,
            published.delivery_path(),
            published.delivery_commit(),
            published.expected_parent_head(),
        )?;

        let (nodes, activities) = coordinator.graph()?;
        let operation_node = nodes
            .iter()
            .find(|node| node.scope() == &operation)
            .ok_or("missing operation graph node")?;
        assert_eq!(operation_node.source_tool_use_id(), Some("q-tool"));
        assert!(activities.iter().any(|activity| {
            activity.scope() == &root
                && activity.tool_use_id() == Some("q-tool")
                && activity.summary() == "tool bash command=\"sleep 1\""
        }));
        assert!(activities.iter().any(|activity| {
            activity.scope() == &operation && activity.summary() == "delivery result #1 queued"
        }));
        assert!(activities.iter().any(|activity| {
            activity.scope() == &root
                && activity.summary() == "merge received delivery #1 from codex-operation-fixture-…"
        }));
        Ok(())
    }

    #[test]
    fn selected_parent_context_forks_only_the_pinned_blobs() -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, root, root_pin) = root_fixture()?;
        repository.append_snapshot(
            root.clone(),
            root_pin.commit()?,
            Snapshot::new(vec![
                TreeEdit::blob(
                    "agents/codex/app-server/prompts/00000000000000000001.json",
                    br#"{"request":{"prompt":"selected"}}"#.to_vec(),
                )?,
                TreeEdit::blob(
                    "agents/codex/app-server/prompts/00000000000000000002.json",
                    br#"{"request":{"prompt":"excluded"}}"#.to_vec(),
                )?,
                TreeEdit::blob(
                    "agents/codex/hooks/audit.json",
                    br#"{"audit":true}"#.to_vec(),
                )?,
            ])?,
            "Record parent prompts and audit",
        )?;
        let parent = repository
            .pin_scope_head(
                root.clone(),
                &[ContextPinSelection::blob(
                    "agents/codex/app-server/prompts/00000000000000000001.json",
                )],
            )?
            .pin()
            .clone();
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root)?;
        let child = ScopeRef::root("selected-child")?;
        let mut child_request = request(
            parent,
            child.clone(),
            ContextExecutionBinding::DaemonPhysical,
        )?;
        child_request.select_parent_context();
        coordinator.admit_child(child_request)?;

        let child_head = repository.scope_head(&child)?;
        assert!(repository
            .read_commit_blob(
                child_head,
                "agents/codex/app-server/prompts/00000000000000000001.json",
            )?
            .is_some());
        assert!(repository
            .read_commit_blob(
                child_head,
                "agents/codex/app-server/prompts/00000000000000000002.json",
            )?
            .is_none());
        assert!(repository
            .read_commit_blob(child_head, "agents/codex/hooks/audit.json")?
            .is_none());
        coordinator.verify_scope(&child)?;
        Ok(())
    }

    #[test]
    fn rejects_foreign_roots_duplicate_children_and_reparenting() -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, root, root_pin) = root_fixture()?;
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root.clone())?;
        let foreign = ScopeRef::scope("parent-session", "foreign")?;
        repository.create_scope(
            foreign.clone(),
            erebor_runtime_context::ScopeStart::existing_commit(root_pin.commit()?),
        )?;
        let foreign_pin = repository.pin_scope_head(foreign, &[])?.pin().clone();
        assert!(coordinator
            .admit_child(request(
                foreign_pin,
                ScopeRef::root("foreign-child")?,
                ContextExecutionBinding::NativeLogical,
            )?)
            .is_err());

        let child_b = ScopeRef::root("child-b")?;
        let child_c = ScopeRef::root("child-c")?;
        coordinator.admit_child(request(
            root_pin.clone(),
            child_b.clone(),
            ContextExecutionBinding::NativeLogical,
        )?)?;
        coordinator.admit_child(request(
            root_pin,
            child_c.clone(),
            ContextExecutionBinding::NativeLogical,
        )?)?;
        let child_c_pin = repository
            .pin_scope_head(child_c.clone(), &[])?
            .pin()
            .clone();
        let child_c_head = repository.scope_head(&child_c)?;

        assert!(coordinator
            .admit_child(request(
                child_c_pin,
                child_b.clone(),
                ContextExecutionBinding::NativeLogical,
            )?)
            .is_err());
        assert_eq!(repository.scope_head(&child_c)?, child_c_head);
        coordinator.verify_scope(&child_b)?;
        Ok(())
    }

    #[test]
    fn enforces_the_bounded_containment_depth_without_creating_an_extra_ref(
    ) -> Result<(), Box<dyn Error>> {
        let (_temporary, repository, root, mut parent_pin) = root_fixture()?;
        let coordinator = ContextDagCoordinator::new(Arc::clone(&repository), root)?;
        let mut last_child = None;
        for depth in 1..=16 {
            let child = ScopeRef::root(format!("child-depth-{depth}"))?;
            coordinator.admit_child(request(
                parent_pin,
                child.clone(),
                ContextExecutionBinding::NativeLogical,
            )?)?;
            parent_pin = repository.pin_scope_head(child.clone(), &[])?.pin().clone();
            last_child = Some(child);
        }
        let extra = ScopeRef::root("child-depth-17")?;
        assert!(coordinator
            .admit_child(request(
                parent_pin,
                extra.clone(),
                ContextExecutionBinding::NativeLogical,
            )?)
            .is_err());
        assert!(repository.scope_head(&extra).is_err());
        coordinator.verify_scope(&last_child.ok_or("missing deepest child")?)?;
        Ok(())
    }

    struct FixedMetadataSource;

    impl CommitMetadataSource for FixedMetadataSource {
        fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
            let time = CommitTime::new(1_700_000_000, 0)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            let signature = CommitSignature::new("Erebor", "runtime@example.test", time)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            Ok(CommitMetadata::new(signature.clone(), signature))
        }
    }
}
