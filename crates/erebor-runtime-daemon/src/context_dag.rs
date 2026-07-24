use std::{
    collections::HashSet,
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_context::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextPin, ContextRepository, ForkParentAppend, ForkTarget, ScopeRef, Snapshot, TreeEdit,
};
use erebor_runtime_core::SessionSpec;
use erebor_runtime_session::SessionRepository;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::InvalidRequestSnafu, Result};

const CONTEXT_DIRECTORY: &str = "context";
const CONTEXT_DAG_METADATA_PREFIX: &str = "erebor/context-dag";
const CONTEXT_DAG_EDGE_SCHEMA_VERSION: u32 = 1;
const MAX_CONTEXT_DAG_DEPTH: u8 = 16;

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

/// The bounded daemon input required to create one immutable child scope.
/// There is no child identity beyond `child_scope` and no mutable graph state.
#[derive(Clone, Debug)]
pub(crate) struct ContextChildForkRequest {
    parent_context: ContextPin,
    child_scope: ScopeRef,
    execution_binding: ContextExecutionBinding,
    source_identity: Option<String>,
    selected_parent_context: bool,
}

impl ContextChildForkRequest {
    pub(crate) fn new(
        parent_context: ContextPin,
        child_scope: ScopeRef,
        execution_binding: ContextExecutionBinding,
        source_identity: Option<String>,
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
        Ok(Self {
            parent_context,
            child_scope,
            execution_binding,
            source_identity,
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
struct ContextChildEdge {
    schema_version: u32,
    parent_context: ContextPin,
    child_scope: String,
    depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_identity: Option<String>,
    execution_binding: ContextExecutionBinding,
}

/// Serializes durable scope topology in one root session repository. This is
/// deliberately not a graph registry: refs and checked edge blobs are the
/// complete retained graph.
pub(crate) struct ContextDagCoordinator {
    repository: Arc<ContextRepository>,
    root_scope: ScopeRef,
    mutation_lock: Mutex<()>,
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

    fn selected_parent_context_tree(&self, parent: &ContextPin) -> Result<ForkTarget> {
        let selected = self.repository.read_pinned_context(parent).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("could not read selected parent context: {error}"),
            }
            .build()
        })?;
        let edits = selected
            .selected_blobs()
            .iter()
            .map(|blob| TreeEdit::blob(blob.path(), blob.bytes()).map_err(|error| {
                InvalidRequestSnafu {
                    reason: format!("could not select parent context blob: {error}"),
                }
                .build()
            }))
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

    fn scope_depth(&self, scope: &ScopeRef, visited: &mut HashSet<String>) -> Result<u8> {
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

    fn direct_edge(&self, child: &ScopeRef) -> Result<ContextChildEdge> {
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

    fn edge_path(child_scope: &ScopeRef) -> String {
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

    use super::{ContextChildForkRequest, ContextDagCoordinator, ContextExecutionBinding};

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
                TreeEdit::blob("agents/codex/hooks/audit.json", br#"{"audit":true}"#.to_vec())?,
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
