use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use erebor_runtime_context::{
    ContextObjectId, ContextPin, ContextPinSelection, ContextRepository, ContextTreeEntryKind,
    ScopeRef, ScopeStart, Snapshot, TreeEdit,
};
use erebor_runtime_ipc::v1::HookEventKind;
use erebor_runtime_packages::CodexFrozenContextMode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::CodexSessionError;

const PROMPT_PREFIX: &str = "agents/codex/app-server/prompts/";

/// Exact App Server facts that may be used to bind a Codex invocation. The
/// binding is only created by the owned transport after it has durably written
/// the originating prompt node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexScopeContextBinding {
    thread_id: String,
    turn_id: String,
    scope_ref: String,
    item_node_stream: String,
    decision_head: String,
}

impl CodexScopeContextBinding {
    pub(crate) fn new(
        thread_id: String,
        turn_id: String,
        scope_ref: String,
        item_node_stream: String,
        decision_head: String,
    ) -> Self {
        Self {
            thread_id,
            turn_id,
            scope_ref,
            item_node_stream,
            decision_head,
        }
    }

    pub(crate) fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub(crate) fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub(crate) fn scope_ref(&self) -> &str {
        &self.scope_ref
    }

    pub(crate) fn item_node_stream(&self) -> &str {
        &self.item_node_stream
    }

    pub(crate) fn decision_head(&self) -> &str {
        &self.decision_head
    }
}

#[derive(Default)]
struct CodexContextDagState {
    root: Option<CodexContextScope>,
    scopes: HashMap<String, CodexContextScope>,
    bindings: HashMap<(String, String), CodexScopeContextBinding>,
    next_prompt: u64,
    next_hook_event: u64,
}

struct CodexContextScope {
    reference: ScopeRef,
    head: ContextObjectId,
}

/// Serializes all durable Codex context writes. The App Server transport owns
/// prompt creation; authenticated hook facts are separate immutable blobs that
/// may use an existing exact prompt scope, but never create or select a prompt.
pub(crate) struct CodexContextDag {
    repository: Arc<ContextRepository>,
    session_id: String,
    state: Mutex<CodexContextDagState>,
}

impl CodexContextDag {
    pub(crate) fn new(repository: Arc<ContextRepository>, session_id: &str) -> Self {
        Self {
            repository,
            session_id: session_id.to_owned(),
            state: Mutex::new(CodexContextDagState::default()),
        }
    }

    /// Every authenticated Codex App Server thread is assigned a distinct
    /// named scope in the shared daemon-owned repository. A thread identifier
    /// is only a same-session routing key here; it does not by itself create a
    /// trusted child-agent edge or child session.
    pub(crate) fn ensure_prompt_scope(&self, scope_key: &str) -> Result<String, CodexSessionError> {
        let mut state = self.lock_state()?;
        let scope_id = format!(
            "codex-app-server-{}",
            &Self::digest(scope_key.as_bytes())[..20]
        );
        let reference =
            ScopeRef::scope(self.session_id.clone(), scope_id).map_err(Self::context_error)?;
        if !state.scopes.contains_key(reference.as_str()) {
            let root_head = self.root_head_locked(&mut state)?;
            let head = self
                .repository
                .create_scope(reference.clone(), ScopeStart::existing_commit(root_head))
                .map_err(Self::context_error)?;
            state.scopes.insert(
                reference.as_str().to_owned(),
                CodexContextScope {
                    reference: reference.clone(),
                    head,
                },
            );
        }
        Ok(reference.as_str().to_owned())
    }

    pub(crate) fn append_prompt(
        &self,
        scope_ref: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<String, CodexSessionError> {
        let mut state = self.lock_state()?;
        state.next_prompt = state.next_prompt.saturating_add(1);
        let path = format!("{PROMPT_PREFIX}{:020}.json", state.next_prompt);
        self.append_named_scope_locked(&mut state, scope_ref, &path, bytes, message)?;
        Ok(path)
    }

    pub(crate) fn bind_prompt(
        &self,
        thread_id: String,
        turn_id: String,
        scope_ref: &str,
        item_node_stream: String,
    ) -> Result<CodexScopeContextBinding, CodexSessionError> {
        let mut state = self.lock_state()?;
        let scope =
            state
                .scopes
                .get(scope_ref)
                .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                    reason: format!("Codex prompt scope `{scope_ref}` was not registered"),
                    location: snafu::Location::default(),
                })?;
        let binding = CodexScopeContextBinding::new(
            thread_id,
            turn_id,
            scope.reference.as_str().to_owned(),
            item_node_stream,
            scope.head.to_string(),
        );
        state.bindings.insert(
            (binding.thread_id.clone(), binding.turn_id.clone()),
            binding.clone(),
        );
        Ok(binding)
    }

    pub(crate) fn exact_binding(
        &self,
        thread_id: &str,
        turn_id: &str,
    ) -> Result<Option<CodexScopeContextBinding>, CodexSessionError> {
        let state = self.lock_state()?;
        Ok(state
            .bindings
            .get(&(thread_id.to_owned(), turn_id.to_owned()))
            .cloned())
    }

    /// Select one immutable, model-visible prompt projection from the exact
    /// parent pin. The projection pin retains only prompt blobs; hook and DAG
    /// evidence remain causal/audit facts, never child model context.
    pub(crate) fn frozen_prompt_projection(
        &self,
        parent: &ContextPin,
        mode: CodexFrozenContextMode,
        last_turns: u32,
    ) -> Result<ContextPin, CodexSessionError> {
        self.repository
            .validate_pin(parent)
            .map_err(Self::context_error)?;
        let scope = parent.scope().map_err(Self::context_error)?;
        let commit = parent.commit().map_err(Self::context_error)?;
        let mut paths = Vec::new();
        self.collect_prompt_paths(
            self.repository
                .read_commit(commit)
                .map_err(Self::context_error)?
                .tree(),
            "",
            &mut paths,
        )?;
        paths.sort();
        let selected = match mode {
            CodexFrozenContextMode::None => Vec::new(),
            CodexFrozenContextMode::All => paths,
            CodexFrozenContextMode::LastTurns => {
                let count = usize::try_from(last_turns).map_err(|_error| {
                    CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "Codex frozen-context turn count does not fit this host",
                        ),
                        location: snafu::Location::default(),
                    }
                })?;
                if count == 0 {
                    return Err(CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "Codex frozen-context last_turns has no matching prompt history",
                        ),
                        location: snafu::Location::default(),
                    });
                }
                let start = paths.len().saturating_sub(count);
                paths.split_off(start)
            }
        };
        self.repository
            .pin_commit(
                scope,
                commit,
                &selected
                    .iter()
                    .map(|path| ContextPinSelection::blob(path.clone()))
                    .collect::<Vec<_>>(),
            )
            .map(|context| context.pin().clone())
            .map_err(Self::context_error)
    }

    /// Render a checked frozen prompt projection for Codex's existing
    /// `SessionStart` hook result. No filesystem, argv, environment, or second
    /// workload-to-daemon channel carries this model context.
    pub(crate) fn render_frozen_prompt_context(
        repository: &ContextRepository,
        projection: &ContextPin,
    ) -> Result<Option<String>, CodexSessionError> {
        let selected = repository
            .read_pinned_context(projection)
            .map_err(Self::context_error)?;
        if selected.selected_blobs().is_empty() {
            return Ok(None);
        }
        let prompts = selected
            .selected_blobs()
            .iter()
            .map(|blob| {
                if !blob.path().starts_with(PROMPT_PREFIX) {
                    return Err(CodexSessionError::IncompatibleProfile {
                        reason: format!(
                            "Codex frozen-context projection selected non-prompt path `{}`",
                            blob.path()
                        ),
                        location: snafu::Location::default(),
                    });
                }
                let record: Value = serde_json::from_slice(blob.bytes()).map_err(|error| {
                    CodexSessionError::IncompatibleProfile {
                        reason: format!("Codex frozen-context prompt is not valid JSON: {error}"),
                        location: snafu::Location::default(),
                    }
                })?;
                record.get("request").cloned().ok_or_else(|| {
                    CodexSessionError::IncompatibleProfile {
                        reason: String::from("Codex frozen-context prompt omitted its request"),
                        location: snafu::Location::default(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string(&json!({
            "schema_version": 1,
            "source": "erebor_frozen_codex_prompt_projection",
            "prompts": prompts,
        }))
        .map(Some)
        .map_err(|error| CodexSessionError::IncompatibleProfile {
            reason: format!("could not encode Codex frozen prompt projection: {error}"),
            location: snafu::Location::default(),
        })
    }

    pub(crate) fn record_authenticated_hook(
        &self,
        kind: HookEventKind,
        payload: &Value,
        observer: Value,
    ) -> Result<ContextPin, CodexSessionError> {
        let mut state = self.lock_state()?;
        state.next_hook_event += 1;
        let thread_id = Self::event_string(
            payload,
            &["session_id", "sessionId", "thread_id", "threadId"],
        );
        let turn_id = Self::event_string(payload, &["turn_id", "turnId"]);
        let binding =
            thread_id
                .as_deref()
                .zip(turn_id.as_deref())
                .and_then(|(thread_id, turn_id)| {
                    state
                        .bindings
                        .get(&(thread_id.to_owned(), turn_id.to_owned()))
                        .cloned()
                });
        let path = format!(
            "agents/codex/hooks/{:020}-{}-{}.json",
            state.next_hook_event,
            Self::hook_name(kind),
            &Self::digest(&serde_json::to_vec(payload).unwrap_or_default())[..20],
        );
        let detail = json!({
            "schema_version": 1,
            "source": "authenticated_codex_hook_broker",
            "event_kind": Self::hook_name(kind),
            "native": payload,
            "observer": observer,
            "context_binding": binding.as_ref().map_or_else(
                || json!({
                    "status": "unmatched",
                    "thread_id": thread_id,
                    "turn_id": turn_id,
                }),
                |binding| json!({
                    "status": "exact",
                    "thread_id": binding.thread_id(),
                    "turn_id": binding.turn_id(),
                    "scope_ref": binding.scope_ref(),
                    "item_node_stream": binding.item_node_stream(),
                    "decision_head": binding.decision_head(),
                }),
            ),
        });
        let bytes = serde_json::to_vec_pretty(&detail).map_err(|error| {
            CodexSessionError::IncompatibleProfile {
                reason: format!("could not encode authenticated Codex hook context: {error}"),
                location: snafu::Location::default(),
            }
        })?;
        let message = format!("Record authenticated Codex {} hook", Self::hook_name(kind));
        if let Some(binding) = binding {
            self.append_named_scope_locked(&mut state, binding.scope_ref(), &path, bytes, &message)
        } else {
            self.append_root_locked(&mut state, &path, bytes, &message)
        }
    }

    fn root_head_locked(
        &self,
        state: &mut CodexContextDagState,
    ) -> Result<ContextObjectId, CodexSessionError> {
        if let Some(root) = state.root.as_ref() {
            return Ok(root.head);
        }
        let reference = ScopeRef::root(self.session_id.clone()).map_err(Self::context_error)?;
        let head = match self.repository.scope_head(&reference) {
            Ok(head) => head,
            Err(erebor_runtime_context::ContextRepositoryError::ScopeNotFound { .. }) => self
                .repository
                .initialize_root(
                    self.session_id.clone(),
                    Snapshot::default(),
                    "Initialize brokered Codex App Server context root",
                )
                .map_err(Self::context_error)?,
            Err(source) => return Err(Self::context_error(source)),
        };
        state.root = Some(CodexContextScope { reference, head });
        Ok(head)
    }

    fn append_root_locked(
        &self,
        state: &mut CodexContextDagState,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextPin, CodexSessionError> {
        self.root_head_locked(state)?;
        let root = state
            .root
            .as_mut()
            .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                reason: String::from("Codex context root disappeared after initialization"),
                location: snafu::Location::default(),
            })?;
        root.head = self.append_snapshot(&root.reference, root.head, path, bytes, message)?;
        self.pin(&root.reference, path)
    }

    fn append_named_scope_locked(
        &self,
        state: &mut CodexContextDagState,
        scope_ref: &str,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextPin, CodexSessionError> {
        let scope = state.scopes.get_mut(scope_ref).ok_or_else(|| {
            CodexSessionError::IncompatibleProfile {
                reason: format!("Codex context scope `{scope_ref}` was not registered"),
                location: snafu::Location::default(),
            }
        })?;
        scope.head = self.append_snapshot(&scope.reference, scope.head, path, bytes, message)?;
        self.pin(&scope.reference, path)
    }

    fn append_snapshot(
        &self,
        scope: &ScopeRef,
        head: ContextObjectId,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextObjectId, CodexSessionError> {
        let snapshot = Snapshot::new(vec![
            TreeEdit::blob(path, bytes).map_err(Self::context_error)?
        ])
        .map_err(Self::context_error)?;
        self.repository
            .append_snapshot(scope.clone(), head, snapshot, message)
            .map_err(Self::context_error)
    }

    fn collect_prompt_paths(
        &self,
        tree: ContextObjectId,
        prefix: &str,
        paths: &mut Vec<String>,
    ) -> Result<(), CodexSessionError> {
        for entry in self
            .repository
            .read_tree(tree)
            .map_err(Self::context_error)?
            .entries()
        {
            let name = std::str::from_utf8(entry.name()).map_err(|_error| {
                CodexSessionError::IncompatibleProfile {
                    reason: String::from("Codex context tree contains a non-UTF-8 path"),
                    location: snafu::Location::default(),
                }
            })?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            match entry.kind() {
                ContextTreeEntryKind::Tree => {
                    self.collect_prompt_paths(entry.object(), &path, paths)?
                }
                ContextTreeEntryKind::Blob if path.starts_with(PROMPT_PREFIX) => paths.push(path),
                ContextTreeEntryKind::Blob | ContextTreeEntryKind::Commit => {}
            }
        }
        Ok(())
    }

    fn pin(&self, scope: &ScopeRef, path: &str) -> Result<ContextPin, CodexSessionError> {
        self.repository
            .pin_scope_head(scope.clone(), &[ContextPinSelection::blob(path)])
            .map(|pinned| pinned.pin().clone())
            .map_err(Self::context_error)
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, CodexContextDagState>, CodexSessionError> {
        self.state
            .lock()
            .map_err(|_error| CodexSessionError::ContextDagStateLock {
                location: snafu::Location::default(),
            })
    }

    fn event_string(payload: &Value, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            payload
                .get(*name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn hook_name(kind: HookEventKind) -> &'static str {
        match kind {
            HookEventKind::SessionStart => "session-start",
            HookEventKind::UserPromptSubmit => "user-prompt-submit",
            HookEventKind::PreToolUse => "pre-tool-use",
            HookEventKind::PermissionRequest => "permission-request",
            HookEventKind::PostToolUse => "post-tool-use",
            HookEventKind::SubagentStart => "subagent-start",
            HookEventKind::SubagentStop => "subagent-stop",
            HookEventKind::Stop => "stop",
            HookEventKind::Unspecified => "unspecified",
        }
    }

    fn context_error(
        source: impl Into<Box<erebor_runtime_context::ContextRepositoryError>>,
    ) -> CodexSessionError {
        CodexSessionError::ContextDag {
            source: source.into(),
            location: snafu::Location::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime,
    };
    use erebor_runtime_packages::CodexFrozenContextMode;
    use serde_json::json;

    use super::{CodexContextDag, PROMPT_PREFIX};

    #[test]
    fn every_authenticated_hook_kind_is_an_immutable_dag_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-1", Default::default(), "Initialize session root")?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-1");
        let scope_ref = dag.ensure_prompt_scope("thread-1")?;
        let prompt_path = dag.append_prompt(
            &scope_ref,
            br#"{"source":"test"}"#.to_vec(),
            "Record test prompt",
        )?;
        let binding = dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &scope_ref,
            prompt_path,
        )?;

        let events = [
            (
                erebor_runtime_ipc::v1::HookEventKind::SessionStart,
                json!({}),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::UserPromptSubmit,
                hook_payload(),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
                hook_payload(),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::PermissionRequest,
                hook_payload(),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::PostToolUse,
                hook_payload(),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::SubagentStart,
                hook_payload(),
            ),
            (
                erebor_runtime_ipc::v1::HookEventKind::SubagentStop,
                hook_payload(),
            ),
            (erebor_runtime_ipc::v1::HookEventKind::Stop, hook_payload()),
            (
                erebor_runtime_ipc::v1::HookEventKind::Unspecified,
                hook_payload(),
            ),
        ];
        for (kind, payload) in events {
            let pin = dag.record_authenticated_hook(kind, &payload, json!({"hook_pid": 7}))?;
            repository.validate_pin(&pin)?;
            if kind == erebor_runtime_ipc::v1::HookEventKind::SessionStart {
                assert_eq!(pin.scope_ref(), "refs/scopes/session-1/root");
            } else {
                assert_eq!(pin.scope_ref(), binding.scope_ref());
            }
            let scope = repository
                .scope_refs()?
                .into_iter()
                .find(|scope| scope.as_str() == pin.scope_ref())
                .ok_or("missing pinned scope")?;
            let pinned = repository.pin_scope_head(
                scope,
                &[erebor_runtime_context::ContextPinSelection::blob(
                    pin.used_paths().first().ok_or("missing hook event path")?,
                )],
            )?;
            let detail: serde_json::Value = serde_json::from_slice(
                pinned
                    .selected_blobs()
                    .first()
                    .ok_or("missing hook event blob")?
                    .bytes(),
            )?;
            assert_eq!(
                detail
                    .pointer("/source")
                    .and_then(serde_json::Value::as_str),
                Some("authenticated_codex_hook_broker")
            );
        }
        Ok(())
    }

    #[test]
    fn app_server_threads_have_distinct_scopes_and_project_only_prompt_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root(
            "session-threads",
            Default::default(),
            "Initialize session root",
        )?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-threads");

        let first = dag.ensure_prompt_scope("thread-1")?;
        let second = dag.ensure_prompt_scope("thread-2")?;

        assert_ne!(first, second);
        assert!(first.starts_with("refs/scopes/session-threads/scope/"));
        let path = dag.append_prompt(&first, Vec::new(), "Record test prompt")?;
        assert!(path.starts_with("agents/codex/app-server/prompts/"));
        assert!(!path.starts_with("erebor/context-dag/"));
        Ok(())
    }

    #[test]
    fn frozen_projection_selects_only_the_requested_prompt_history(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root(
            "session-projection",
            Default::default(),
            "Initialize session root",
        )?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-projection");
        let scope = dag.ensure_prompt_scope("thread-1")?;
        let mut paths = Vec::new();
        for prompt in ["first", "second", "third"] {
            paths.push(dag.append_prompt(
                &scope,
                serde_json::to_vec(&json!({
                    "request": {"prompt": prompt},
                    "internal": "must not be projected",
                }))?,
                "Record deterministic prompt",
            )?);
        }
        dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-3"),
            &scope,
            paths.last().ok_or("missing third prompt")?.clone(),
        )?;
        let parent = dag.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            &json!({"session_id": "thread-1", "turn_id": "turn-3"}),
            json!({"hook_pid": 7}),
        )?;

        let none = dag.frozen_prompt_projection(&parent, CodexFrozenContextMode::None, 0)?;
        assert!(none.used_paths().is_empty());
        assert_eq!(
            CodexContextDag::render_frozen_prompt_context(repository.as_ref(), &none)?,
            None
        );

        let all = dag.frozen_prompt_projection(&parent, CodexFrozenContextMode::All, 0)?;
        assert_eq!(all.used_paths(), paths.as_slice());
        let all_rendered =
            CodexContextDag::render_frozen_prompt_context(repository.as_ref(), &all)?
                .ok_or("all projection was not rendered")?;
        let all_json: serde_json::Value = serde_json::from_str(&all_rendered)?;
        assert_eq!(
            all_json
                .pointer("/prompts/0/prompt")
                .and_then(serde_json::Value::as_str),
            Some("first")
        );
        assert_eq!(
            all_json
                .pointer("/prompts/2/prompt")
                .and_then(serde_json::Value::as_str),
            Some("third")
        );
        assert!(!all_rendered.contains("must not be projected"));

        let last = dag.frozen_prompt_projection(&parent, CodexFrozenContextMode::LastTurns, 2)?;
        assert_eq!(last.used_paths(), &paths[1..]);
        let last_rendered =
            CodexContextDag::render_frozen_prompt_context(repository.as_ref(), &last)?
                .ok_or("last-turns projection was not rendered")?;
        let last_json: serde_json::Value = serde_json::from_str(&last_rendered)?;
        assert_eq!(
            last_json
                .pointer("/prompts/0/prompt")
                .and_then(serde_json::Value::as_str),
            Some("second")
        );
        assert_eq!(
            last_json
                .pointer("/prompts/1/prompt")
                .and_then(serde_json::Value::as_str),
            Some("third")
        );
        assert!(last
            .used_paths()
            .iter()
            .all(|path| path.starts_with(PROMPT_PREFIX)));
        Ok(())
    }

    fn hook_payload() -> serde_json::Value {
        json!({"session_id": "thread-1", "turn_id": "turn-1"})
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
