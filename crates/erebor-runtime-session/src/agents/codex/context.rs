use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use erebor_runtime_context::{
    ContextObjectId, ContextPin, ContextPinSelection, ContextRepository, ContextTreeEntryKind,
    ScopeRef, Snapshot, TreeEdit,
};
use erebor_runtime_ipc::v1::HookEventKind;
use erebor_runtime_packages::CodexFrozenContextMode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::context_operation::{ContextOperationAdmission, ContextOperationAdmissionHandler};

#[cfg(test)]
use erebor_runtime_context::ScopeStart;

use super::CodexSessionError;

const PROMPT_PREFIX: &str = "agents/codex/app-server/prompts/";
const MAX_SCOPE_APPEND_ATTEMPTS: usize = 8;

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
    next_physical_effect: u64,
}

struct CodexContextScope {
    reference: ScopeRef,
    head: ContextObjectId,
}

/// Serializes all durable Codex context writes. The App Server transport owns
/// prompt creation; authenticated hook facts are separate immutable blobs that
/// may use an existing exact prompt scope, but never create or select a prompt.
/// A governed terminal session has no App Server transport, so its authenticated
/// user-prompt turn binds to its already-owned root scope without creating a
/// prompt scope or projecting untrusted terminal data.
pub(crate) struct CodexContextDag {
    repository: Arc<ContextRepository>,
    session_id: String,
    operation_admissions: Mutex<Option<Arc<dyn ContextOperationAdmissionHandler>>>,
    state: Mutex<CodexContextDagState>,
}

impl CodexContextDag {
    pub(crate) fn new(repository: Arc<ContextRepository>, session_id: &str) -> Self {
        Self {
            repository,
            session_id: session_id.to_owned(),
            operation_admissions: Mutex::new(None),
            state: Mutex::new(CodexContextDagState::default()),
        }
    }

    /// Bind the one in-process daemon admission path used for all named Codex
    /// scopes. This is deliberately not a workload-facing protocol: App
    /// Server input reaches the daemon-owned adapter, which asks the daemon to
    /// atomically retain the exact parent-edge fact before it records a prompt.
    pub(crate) fn set_operation_admission_handler(
        &self,
        handler: Arc<dyn ContextOperationAdmissionHandler>,
    ) -> Result<(), CodexSessionError> {
        let mut installed = self.operation_admissions.lock().map_err(|_error| {
            CodexSessionError::ContextDagStateLock {
                location: snafu::Location::default(),
            }
        })?;
        if installed.is_some() {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from("Codex context-operation handler is already installed"),
                location: snafu::Location::default(),
            });
        }
        *installed = Some(handler);
        Ok(())
    }

    /// Every authenticated Codex App Server thread is assigned a distinct
    /// daemon-admitted scope in the shared repository. A thread identifier is
    /// only a same-session routing key here; it does not by itself create a
    /// trusted child-agent edge or child session.
    pub(crate) fn ensure_prompt_scope(&self, scope_key: &str) -> Result<String, CodexSessionError> {
        let mut state = self.lock_state()?;
        let operation_key = format!(
            "app-server-thread-{}",
            &Self::digest(scope_key.as_bytes())[..32]
        );
        let scope_id = format!(
            "codex-operation-{}",
            &Self::digest(operation_key.as_bytes())[..20]
        );
        let expected_reference =
            ScopeRef::scope(self.session_id.clone(), scope_id).map_err(Self::context_error)?;
        if state.scopes.contains_key(expected_reference.as_str()) {
            return Ok(expected_reference.as_str().to_owned());
        }
        self.root_head_locked(&mut state)?;
        let root_reference = state
            .root
            .as_ref()
            .map(|root| root.reference.clone())
            .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                reason: String::from("Codex context root was not initialized"),
                location: snafu::Location::default(),
            })?;
        let parent_context = self
            .repository
            .pin_scope_head(root_reference.clone(), &[])
            .map_err(Self::context_error)?
            .pin()
            .clone();
        let handler = self
            .operation_admissions
            .lock()
            .map_err(|_error| CodexSessionError::ContextDagStateLock {
                location: snafu::Location::default(),
            })?
            .clone();
        let reference = match handler {
            Some(handler) => handler
                .admit_operation(ContextOperationAdmission::new(
                    self.session_id.clone(),
                    parent_context.clone(),
                    operation_key,
                    None,
                ))
                .map_err(|reason| CodexSessionError::IncompatibleProfile {
                    reason: format!("daemon rejected Codex App Server scope admission: {reason}"),
                    location: snafu::Location::default(),
                })?,
            None => {
                #[cfg(test)]
                {
                    let parent_commit = parent_context.commit().map_err(Self::context_error)?;
                    match self.repository.scope_head(&expected_reference) {
                        Ok(_head) => {}
                        Err(erebor_runtime_context::ContextRepositoryError::ScopeNotFound {
                            ..
                        }) => {
                            self.repository
                                .create_scope(
                                    expected_reference.clone(),
                                    ScopeStart::existing_commit(parent_commit),
                                )
                                .map_err(Self::context_error)?;
                        }
                        Err(error) => return Err(Self::context_error(error)),
                    }
                    expected_reference.clone()
                }
                #[cfg(not(test))]
                {
                    return Err(CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "Codex App Server scope admission is not daemon-bound",
                        ),
                        location: snafu::Location::default(),
                    });
                }
            }
        };
        if reference != expected_reference {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from(
                    "daemon-admitted Codex App Server scope does not match its deterministic key",
                ),
                location: snafu::Location::default(),
            });
        }
        if reference.session_id() != self.session_id {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from(
                    "daemon-admitted Codex App Server scope belongs to another session",
                ),
                location: snafu::Location::default(),
            });
        }
        let head = self
            .repository
            .scope_head(&reference)
            .map_err(Self::context_error)?;
        let root_head = self
            .repository
            .scope_head(&root_reference)
            .map_err(Self::context_error)?;
        let current_root =
            state
                .root
                .as_mut()
                .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                    reason: String::from("Codex context root disappeared during scope admission"),
                    location: snafu::Location::default(),
                })?;
        current_root.head = root_head;
        state.scopes.insert(
            reference.as_str().to_owned(),
            CodexContextScope {
                reference: reference.clone(),
                head,
            },
        );
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

    /// Bind a daemon-admitted logical child scope to an exact Codex
    /// `(thread_id, turn_id)` pair. This is an in-session routing fact: it
    /// neither starts a child session nor projects a second hook socket or
    /// process guard.
    pub(crate) fn bind_admitted_scope(
        &self,
        thread_id: String,
        turn_id: String,
        reference: ScopeRef,
    ) -> Result<CodexScopeContextBinding, CodexSessionError> {
        if reference.session_id() != self.session_id {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from(
                    "daemon-admitted Codex logical scope belongs to another session",
                ),
                location: snafu::Location::default(),
            });
        }
        let mut state = self.lock_state()?;
        let key = (thread_id.clone(), turn_id.clone());
        if let Some(existing) = state.bindings.get(&key).cloned() {
            if existing.scope_ref() == reference.as_str() {
                return Ok(existing);
            }
            return Err(CodexSessionError::IncompatibleProfile {
                reason: format!(
                    "Codex thread `{thread_id}` turn `{turn_id}` is already bound to a different context scope"
                ),
                location: snafu::Location::default(),
            });
        }
        let head = self
            .repository
            .scope_head(&reference)
            .map_err(Self::context_error)?;
        state
            .scopes
            .entry(reference.as_str().to_owned())
            .or_insert(CodexContextScope {
                reference: reference.clone(),
                head,
            });
        let item_node_stream = format!(
            "agents/codex/logical-threads/{}.json",
            &Self::digest(format!("{thread_id}\0{turn_id}").as_bytes())[..20]
        );
        let binding = CodexScopeContextBinding::new(
            thread_id,
            turn_id,
            reference.as_str().to_owned(),
            item_node_stream,
            head.to_string(),
        );
        state.bindings.insert(key, binding.clone());
        Ok(binding)
    }

    /// Refresh the local append cursor for a scope whose ref the daemon
    /// advanced while atomically recording a child edge. The ref is still the
    /// source of truth; this cache only serializes later adapter-owned writes.
    pub(crate) fn refresh_scope_head(&self, context: &ContextPin) -> Result<(), CodexSessionError> {
        let scope = context.scope().map_err(Self::context_error)?;
        let head = self
            .repository
            .scope_head(&scope)
            .map_err(Self::context_error)?;
        let mut state = self.lock_state()?;
        if state
            .root
            .as_ref()
            .is_some_and(|root| root.reference == scope)
        {
            let root =
                state
                    .root
                    .as_mut()
                    .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                        reason: String::from("Codex context root disappeared while refreshing"),
                        location: snafu::Location::default(),
                    })?;
            root.head = head;
            return Ok(());
        }
        let named = state.scopes.get_mut(scope.as_str()).ok_or_else(|| {
            CodexSessionError::IncompatibleProfile {
                reason: format!("Codex context scope `{scope}` was not registered"),
                location: snafu::Location::default(),
            }
        })?;
        named.head = head;
        Ok(())
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

    /// Bind one authenticated terminal turn to this session's existing root
    /// scope. Unlike an App Server binding, this creates no named scope or
    /// model-visible prompt blob: terminal input is not an App Server prompt
    /// projection. It only gives a later authenticated pre-tool event an exact
    /// causal scope and immutable root head.
    pub(crate) fn bind_terminal_turn(
        &self,
        payload: &Value,
    ) -> Result<Option<CodexScopeContextBinding>, CodexSessionError> {
        let Some(thread_id) = Self::event_string(
            payload,
            &["session_id", "sessionId", "thread_id", "threadId"],
        ) else {
            return Ok(None);
        };
        let Some(turn_id) = Self::event_string(payload, &["turn_id", "turnId"]) else {
            return Ok(None);
        };
        let mut state = self.lock_state()?;
        if let Some(binding) = state
            .bindings
            .get(&(thread_id.clone(), turn_id.clone()))
            .cloned()
        {
            return Ok(Some(binding));
        }
        self.root_head_locked(&mut state)?;
        let root = state
            .root
            .as_ref()
            .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                reason: String::from("Codex terminal root context was not initialized"),
                location: snafu::Location::default(),
            })?;
        let item_node_stream = format!(
            "agents/codex/terminal/turns/{}.json",
            &Self::digest(format!("{thread_id}\0{turn_id}").as_bytes())[..20]
        );
        let binding = CodexScopeContextBinding::new(
            thread_id,
            turn_id,
            root.reference.as_str().to_owned(),
            item_node_stream,
            root.head.to_string(),
        );
        state.bindings.insert(
            (binding.thread_id.clone(), binding.turn_id.clone()),
            binding.clone(),
        );
        Ok(Some(binding))
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
            let is_root_binding = state
                .root
                .as_ref()
                .is_some_and(|root| root.reference.as_str() == binding.scope_ref());
            if is_root_binding {
                self.append_root_locked(&mut state, &path, bytes, &message)
            } else {
                self.append_named_scope_locked(
                    &mut state,
                    binding.scope_ref(),
                    &path,
                    bytes,
                    &message,
                )
            }
        } else {
            self.append_root_locked(&mut state, &path, bytes, &message)
        }
    }

    /// Retain an authenticated hook fact for an already-admitted operation in
    /// that operation's own scope. In particular, asynchronous output must
    /// never advance its owner's ref before the owner explicitly receives the
    /// bounded delivery.
    pub(crate) fn record_authenticated_operation_hook(
        &self,
        kind: HookEventKind,
        payload: &Value,
        observer: Value,
        operation_scope: &ScopeRef,
    ) -> Result<ContextPin, CodexSessionError> {
        if operation_scope.session_id() != self.session_id {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from(
                    "authenticated Codex operation hook belongs to another session scope",
                ),
                location: snafu::Location::default(),
            });
        }
        let mut state = self.lock_state()?;
        state.next_hook_event += 1;
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
            "context_binding": {
                "status": "admitted-operation",
                "scope_ref": operation_scope.as_str(),
            },
        });
        let bytes = serde_json::to_vec_pretty(&detail).map_err(|error| {
            CodexSessionError::IncompatibleProfile {
                reason: format!("could not encode authenticated Codex operation hook: {error}"),
                location: snafu::Location::default(),
            }
        })?;
        self.append_scope_locked(
            &mut state,
            operation_scope,
            &path,
            bytes,
            &format!(
                "Record authenticated Codex {} operation hook",
                Self::hook_name(kind)
            ),
        )
    }

    /// Retain one lease-validated process-guard observation in the source
    /// scope's Git history. The JSONL audit remains an operational sink; this
    /// record is the graph's sole source for physical execution activity.
    pub(crate) fn record_guarded_physical_effect(
        &self,
        source_context: &ContextPin,
        effect_scope: &ScopeRef,
        detail: Value,
    ) -> Result<ContextPin, CodexSessionError> {
        if effect_scope.session_id() != self.session_id {
            return Err(CodexSessionError::IncompatibleProfile {
                reason: String::from("guarded Codex physical effect belongs to another session"),
                location: snafu::Location::default(),
            });
        }
        self.repository
            .validate_pin(source_context)
            .map_err(Self::context_error)?;
        let mut state = self.lock_state()?;
        let head = self
            .repository
            .scope_head(effect_scope)
            .map_err(Self::context_error)?;
        state.next_physical_effect = state.next_physical_effect.saturating_add(1);
        let mut path_identity = head.to_string();
        path_identity.push('\0');
        path_identity.push_str(&Self::digest(
            &serde_json::to_vec(&detail).unwrap_or_default(),
        ));
        let path = format!(
            "agents/codex/physical-effects/{:020}-{}.json",
            state.next_physical_effect,
            &Self::digest(path_identity.as_bytes())[..20],
        );
        let bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "source": "erebor_guarded_physical_effect",
            "kind": "physical-effect",
            "source_context": source_context,
            "effect": detail,
        }))
        .map_err(|error| CodexSessionError::IncompatibleProfile {
            reason: format!("could not encode guarded Codex physical effect: {error}"),
            location: snafu::Location::default(),
        })?;
        self.append_scope_locked(
            &mut state,
            effect_scope,
            &path,
            bytes,
            "Record guarded Codex physical effect",
        )
    }

    /// Append one immutable fact to a scope that another daemon-owned writer
    /// may also advance, such as a child-delivery publisher. The cached head
    /// only accelerates local routing; the ref remains authoritative.
    fn append_scope_locked(
        &self,
        state: &mut CodexContextDagState,
        scope: &ScopeRef,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextPin, CodexSessionError> {
        let head = self.append_current_scope_snapshot(scope, path, bytes, message)?;
        if state
            .root
            .as_ref()
            .is_some_and(|root| root.reference == *scope)
        {
            let root =
                state
                    .root
                    .as_mut()
                    .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "Codex context root disappeared while recording a daemon scope fact",
                        ),
                        location: snafu::Location::default(),
                    })?;
            root.head = head;
        }
        if let Some(known_scope) = state.scopes.get_mut(scope.as_str()) {
            known_scope.head = head;
        }
        self.pin_commit(scope, head, path)
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
        let reference = state
            .root
            .as_ref()
            .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                reason: String::from("Codex context root disappeared after initialization"),
                location: snafu::Location::default(),
            })?
            .reference
            .clone();
        self.append_scope_locked(state, &reference, path, bytes, message)
    }

    fn append_named_scope_locked(
        &self,
        state: &mut CodexContextDagState,
        scope_ref: &str,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextPin, CodexSessionError> {
        let reference = state
            .scopes
            .get(scope_ref)
            .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                reason: format!("Codex context scope `{scope_ref}` was not registered"),
                location: snafu::Location::default(),
            })?
            .reference
            .clone();
        self.append_scope_locked(state, &reference, path, bytes, message)
    }

    fn append_current_scope_snapshot(
        &self,
        scope: &ScopeRef,
        path: &str,
        bytes: Vec<u8>,
        message: &str,
    ) -> Result<ContextObjectId, CodexSessionError> {
        let snapshot = Snapshot::new(vec![
            TreeEdit::blob(path, bytes).map_err(Self::context_error)?
        ])
        .map_err(Self::context_error)?;
        for attempt in 0..MAX_SCOPE_APPEND_ATTEMPTS {
            let head = self
                .repository
                .scope_head(scope)
                .map_err(Self::context_error)?;
            match self
                .repository
                .append_snapshot(scope.clone(), head, snapshot.clone(), message)
            {
                Ok(next_head) => return Ok(next_head),
                Err(erebor_runtime_context::ContextRepositoryError::StaleScopeHead { .. }) => {
                    if attempt + 1 == MAX_SCOPE_APPEND_ATTEMPTS {
                        return Err(CodexSessionError::IncompatibleProfile {
                            reason: format!(
                                "Codex context scope `{scope}` advanced too often while recording immutable evidence"
                            ),
                            location: snafu::Location::default(),
                        });
                    }
                    let current_head = self
                        .repository
                        .scope_head(scope)
                        .map_err(Self::context_error)?;
                    if self
                        .repository
                        .read_commit_blob(current_head, path)
                        .map_err(Self::context_error)?
                        .is_some()
                    {
                        return Err(CodexSessionError::IncompatibleProfile {
                            reason: format!(
                                "Codex context fact path `{path}` already exists after a concurrent scope advance"
                            ),
                            location: snafu::Location::default(),
                        });
                    }
                }
                Err(error) => return Err(Self::context_error(error)),
            }
        }
        unreachable!("bounded scope append retry must return from its final attempt")
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

    fn pin_commit(
        &self,
        scope: &ScopeRef,
        commit: ContextObjectId,
        path: &str,
    ) -> Result<ContextPin, CodexSessionError> {
        self.repository
            .pin_commit(scope.clone(), commit, &[ContextPinSelection::blob(path)])
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
    use std::sync::{Arc, Barrier, Mutex};

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, ScopeRef, Snapshot, TreeEdit,
    };
    use erebor_runtime_ipc::v1::HookEventKind;
    use erebor_runtime_packages::CodexFrozenContextMode;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use super::{CodexContextDag, CodexSessionError, PROMPT_PREFIX};
    use crate::context_operation::{ContextOperationAdmission, ContextOperationAdmissionHandler};

    struct RecordingAdmission {
        repository: Arc<erebor_runtime_context::ContextRepository>,
        admissions: Mutex<Vec<ContextOperationAdmission>>,
    }

    impl ContextOperationAdmissionHandler for RecordingAdmission {
        fn admit_operation(
            &self,
            admission: ContextOperationAdmission,
        ) -> Result<ScopeRef, String> {
            let digest = format!("{:x}", Sha256::digest(admission.operation_key().as_bytes()));
            let scope = ScopeRef::scope(
                admission.session_id(),
                format!("codex-operation-{}", &digest[..20]),
            )
            .map_err(|error| error.to_string())?;
            if self.repository.scope_head(&scope).is_err() {
                self.repository
                    .create_scope(
                        scope.clone(),
                        erebor_runtime_context::ScopeStart::existing_commit(
                            admission
                                .parent_context()
                                .commit()
                                .map_err(|error| error.to_string())?,
                        ),
                    )
                    .map_err(|error| error.to_string())?;
            }
            self.admissions
                .lock()
                .map_err(|_error| String::from("recording admissions lock is poisoned"))?
                .push(admission);
            Ok(scope)
        }
    }

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
    fn app_server_scope_requires_the_daemon_operation_admission_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-admission", Default::default(), "Initialize")?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-admission");
        let handler = Arc::new(RecordingAdmission {
            repository: Arc::clone(&repository),
            admissions: Mutex::new(Vec::new()),
        });
        dag.set_operation_admission_handler(
            Arc::clone(&handler) as Arc<dyn ContextOperationAdmissionHandler>
        )?;

        let scope = dag.ensure_prompt_scope("thread-1")?;
        assert!(scope.starts_with("refs/scopes/session-admission/scope/codex-operation-"));
        let admissions = handler
            .admissions
            .lock()
            .map_err(|_error| "recording admissions lock is poisoned")?;
        assert_eq!(admissions.len(), 1);
        assert_eq!(admissions[0].session_id(), "session-admission");
        assert_eq!(
            admissions[0].parent_context().scope_ref(),
            "refs/scopes/session-admission/root"
        );
        assert!(admissions[0]
            .operation_key()
            .starts_with("app-server-thread-"));
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
    fn hook_append_refreshes_a_named_scope_after_daemon_delivery_advances_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-delivery", Default::default(), "Initialize")?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-delivery");
        let scope_ref = dag.ensure_prompt_scope("thread-1")?;
        let prompt_path = dag.append_prompt(
            &scope_ref,
            br#"{\"prompt\":\"before delivery\"}"#.to_vec(),
            "Record prompt",
        )?;
        dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &scope_ref,
            prompt_path,
        )?;
        let scope = repository
            .scope_refs()?
            .into_iter()
            .find(|candidate| candidate.as_str() == scope_ref)
            .ok_or("named Codex scope was not created")?;
        let head = repository.scope_head(&scope)?;
        repository.append_snapshot(
            scope.clone(),
            head,
            Snapshot::new(vec![TreeEdit::blob(
                "deliveries/00000000000000000001.json",
                br#"{\"selected_text\":\"completed\"}"#.to_vec(),
            )?])?,
            "Publish child context delivery",
        )?;

        let hook = dag.record_authenticated_hook(
            HookEventKind::PreToolUse,
            &hook_payload(),
            json!({"hook_pid": 7}),
        )?;

        assert_eq!(hook.scope_ref(), scope_ref);
        let head = repository.scope_head(&scope)?;
        assert!(repository
            .read_commit_blob(
                head,
                hook.used_paths()
                    .first()
                    .ok_or("missing hook evidence path")?,
            )?
            .is_some());
        assert!(repository
            .read_commit_blob(head, "deliveries/00000000000000000001.json")?
            .is_some());
        Ok(())
    }

    #[test]
    fn authenticated_terminal_turn_binds_only_the_existing_root_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        let root =
            repository.initialize_root("session-terminal", Default::default(), "Initialize")?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-terminal");
        let payload = json!({"session_id": "terminal-thread", "turn_id": "terminal-turn"});

        let binding = dag
            .bind_terminal_turn(&payload)?
            .ok_or("terminal turn did not bind")?;

        assert_eq!(
            binding.scope_ref(),
            ScopeRef::root("session-terminal")?.as_str()
        );
        assert_eq!(binding.decision_head(), root.to_string());
        assert!(binding
            .item_node_stream()
            .starts_with("agents/codex/terminal/turns/"));
        let hook = dag.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::UserPromptSubmit,
            &payload,
            json!({"hook_pid": 7}),
        )?;
        assert_eq!(
            hook.scope_ref(),
            ScopeRef::root("session-terminal")?.as_str()
        );
        assert_eq!(
            repository.scope_refs()?,
            vec![ScopeRef::root("session-terminal")?]
        );
        assert_eq!(
            dag.exact_binding("terminal-thread", "terminal-turn")?,
            Some(binding)
        );
        Ok(())
    }

    #[test]
    fn guarded_physical_effect_is_retained_in_its_source_scope_git_history(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-effect", Default::default(), "Initialize")?;
        let dag = CodexContextDag::new(Arc::clone(&repository), "session-effect");
        let turn = json!({"session_id": "terminal-thread", "turn_id": "terminal-turn"});
        dag.bind_terminal_turn(&turn)?
            .ok_or("terminal turn did not bind")?;
        let source_context = dag.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            &turn,
            json!({"hook_pid": 7}),
        )?;
        let root = ScopeRef::root("session-effect")?;

        let effect = dag.record_guarded_physical_effect(
            &source_context,
            &root,
            json!({
                "allowed": true,
                "operation": "process_exec",
                "pid": 44,
                "ppid": 7,
                "executable": "/bin/ls",
                "argv": ["/bin/ls"],
                "lease": {
                    "id": "lease-1",
                    "scope_ref": root.as_str(),
                    "item_node_stream": "item",
                    "decision_head": "head",
                    "codex_session_id": "terminal-thread",
                    "turn_id": "terminal-turn",
                    "tool_use_id": "tool-1",
                    "tool_name": "bash",
                    "operation_scope": null,
                },
            }),
        )?;

        repository.validate_pin(&effect)?;
        let path = effect.used_paths().first().ok_or("missing effect path")?;
        assert!(path.starts_with("agents/codex/physical-effects/"));
        let retained = repository.read_pinned_context(&effect)?;
        let detail: Value = serde_json::from_slice(
            retained
                .selected_blobs()
                .first()
                .ok_or("missing effect blob")?
                .bytes(),
        )?;
        assert_eq!(
            detail.get("source").and_then(Value::as_str),
            Some("erebor_guarded_physical_effect")
        );
        assert_eq!(
            detail.pointer("/effect/executable").and_then(Value::as_str),
            Some("/bin/ls")
        );

        let recovered = CodexContextDag::new(Arc::clone(&repository), "session-effect");
        let recovered_effect = recovered.record_guarded_physical_effect(
            &source_context,
            &root,
            json!({
                "allowed": true,
                "operation": "process_exec",
                "pid": 44,
                "ppid": 7,
                "executable": "/bin/ls",
                "argv": ["/bin/ls"],
                "lease": {
                    "id": "lease-1",
                    "scope_ref": root.as_str(),
                    "item_node_stream": "item",
                    "decision_head": "head",
                    "codex_session_id": "terminal-thread",
                    "turn_id": "terminal-turn",
                    "tool_use_id": "tool-1",
                    "tool_name": "bash",
                    "operation_scope": null,
                },
            }),
        )?;
        assert_ne!(effect.used_paths(), recovered_effect.used_paths());
        let head = repository.scope_head(&root)?;
        for path in effect
            .used_paths()
            .iter()
            .chain(recovered_effect.used_paths())
        {
            assert!(repository.read_commit_blob(head, path)?.is_some());
        }
        Ok(())
    }

    #[test]
    fn concurrent_operation_hooks_and_physical_effects_serialize_one_operation_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const RECORDS_PER_WRITER: usize = 16;

        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        let root = repository.initialize_root(
            "session-concurrent-operation",
            Default::default(),
            "Initialize",
        )?;
        let operation =
            ScopeRef::scope("session-concurrent-operation", "codex-operation-concurrent")?;
        repository.create_scope(
            operation.clone(),
            erebor_runtime_context::ScopeStart::existing_commit(root),
        )?;
        let source_context = repository
            .pin_scope_head(operation.clone(), &[])?
            .pin()
            .clone();
        let dag = Arc::new(CodexContextDag::new(
            Arc::clone(&repository),
            "session-concurrent-operation",
        ));
        let start = Arc::new(Barrier::new(3));

        let hook_writer = {
            let dag = Arc::clone(&dag);
            let operation = operation.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || -> Result<(), CodexSessionError> {
                start.wait();
                for index in 0..RECORDS_PER_WRITER {
                    dag.record_authenticated_operation_hook(
                        HookEventKind::PostToolUse,
                        &json!({
                            "hook_event_name": "PostToolUse",
                            "tool_use_id": format!("operation-hook-{index}"),
                        }),
                        json!({"hook_pid": 7}),
                        &operation,
                    )?;
                }
                Ok(())
            })
        };
        let effect_writer = {
            let dag = Arc::clone(&dag);
            let operation = operation.clone();
            let source_context = source_context.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || -> Result<(), CodexSessionError> {
                start.wait();
                for index in 0..RECORDS_PER_WRITER {
                    dag.record_guarded_physical_effect(
                        &source_context,
                        &operation,
                        json!({
                            "allowed": true,
                            "operation": "process_exec",
                            "pid": index,
                            "lease": {"tool_use_id": format!("operation-effect-{index}")},
                        }),
                    )?;
                }
                Ok(())
            })
        };

        start.wait();
        hook_writer
            .join()
            .map_err(|_error| "operation hook writer panicked")??;
        effect_writer
            .join()
            .map_err(|_error| "physical-effect writer panicked")??;

        let head = repository.scope_head(&operation)?;
        assert_eq!(
            repository
                .list_commit_blobs_under(head, "agents/codex/hooks")?
                .len(),
            RECORDS_PER_WRITER
        );
        assert_eq!(
            repository
                .list_commit_blobs_under(head, "agents/codex/physical-effects")?
                .len(),
            RECORDS_PER_WRITER
        );
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
