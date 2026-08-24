use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::JsonlAuditSink;
use erebor_runtime_context::{ContextPin, ScopeRef};
use erebor_runtime_core::{AuditRecord, DurableAuditSink};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, EventId, ExecutionSurface, RiskLevel, RiskMetadata, RuntimeEvent,
    SessionId, TargetRef,
};
use erebor_runtime_ipc::v1::HookEventKind;
use erebor_runtime_packages::CodexFrozenContextMode;
use erebor_runtime_policy::Decision;
use erebor_telemetry::warn;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ContextOperationAdmission, ContextOperationAdmissionHandler};

use super::{CodexContextDag, CodexScopeContextBinding, CodexSessionError};

const LEASE_LIFETIME: Duration = Duration::from_secs(30);
const MAX_LOGICAL_FORK_LAST_TURNS: u32 = 64;

/// Kernel-observed identity of the Codex process that launched an authenticated
/// managed hook. It is kept outside the generic ptrace guard protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexLeaseRuntimeEvidence {
    pid: i64,
    process_start_time_ticks: u64,
    executable: String,
}

/// Enrolled profile identity for authenticated hook attribution.
#[derive(Clone, Debug)]
pub(crate) struct CodexInvocationLeaseProfile {
    id: String,
    terminal_root_context: bool,
}

impl CodexInvocationLeaseProfile {
    pub(crate) fn new(id: String) -> Self {
        Self {
            id,
            terminal_root_context: false,
        }
    }

    pub(crate) fn set_terminal_root_context(&mut self, enabled: bool) {
        self.terminal_root_context = enabled;
    }
}

impl CodexLeaseRuntimeEvidence {
    pub(crate) fn new(pid: i64, process_start_time_ticks: u64, executable: String) -> Self {
        Self {
            pid,
            process_start_time_ticks,
            executable,
        }
    }

    fn runtime_id(&self) -> String {
        format!(
            "linux:{}:{}:{}",
            self.pid, self.process_start_time_ticks, self.executable
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationLeaseState {
    Preparing,
    ResponseIssued,
    DispatchComplete,
    Closed,
}

impl InvocationLeaseState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::ResponseIssued => "response-issued",
            Self::DispatchComplete => "dispatch-complete",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EffectClass {
    Command,
    InProcessMutation,
    LogicalFork,
    Unsupported,
}

impl EffectClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::InProcessMutation => "in-process-mutation",
            Self::LogicalFork => "logical-fork",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InvocationIdentity {
    runtime_id: String,
    codex_session_id: String,
    turn_id: String,
    tool_use_id: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct HandoffLane {
    scope_ref: String,
    item_node_stream: String,
    tool_use_id: String,
    effect_class: EffectClass,
}

#[derive(Clone, Debug)]
enum InvocationCapability {
    Command {
        operation_key: Option<String>,
    },
    InProcessMutation,
    LogicalFork {
        child_thread_id: String,
        child_turn_id: String,
        frozen_context_mode: CodexFrozenContextMode,
        last_turns: u32,
    },
    Unsupported,
}

#[derive(Clone, Debug)]
struct InvocationKey {
    erebor_session_id: String,
    runtime_id: String,
    scope_ref: String,
    item_node_stream: String,
    decision_head: String,
    codex_session_id: String,
    turn_id: String,
    tool_use_id: String,
}

#[derive(Clone, Debug)]
struct InvocationLease {
    id: String,
    identity: InvocationIdentity,
    key: InvocationKey,
    tool_name: String,
    structured_input_sha256: String,
    effect_class: EffectClass,
    capability: InvocationCapability,
    state: InvocationLeaseState,
    runtime_pid: i64,
    hook_pid: i64,
    hook_profile_epoch: String,
    expires_at_millis: u128,
    context_pin: Option<ContextPin>,
    operation_scope: Option<ScopeRef>,
}

#[derive(Default)]
struct LeaseState {
    scopes: HashMap<(String, String), CodexScopeContextBinding>,
    leases: HashMap<String, InvocationLease>,
    identities: HashMap<InvocationIdentity, String>,
    lanes: HashMap<HandoffLane, String>,
    next_audit_sequence: u64,
}

/// Session-local owner for Codex invocation capabilities. It receives
/// authenticated hook facts for causal context and bounded operation delivery.
pub(crate) struct CodexInvocationLeaseOwner {
    session_id: String,
    actor: ActorIdentity,
    profile_id: String,
    terminal_root_context: bool,
    audit: Option<JsonlAuditSink>,
    context_dag: Mutex<Option<Arc<CodexContextDag>>>,
    operation_admissions: Mutex<Option<Arc<dyn ContextOperationAdmissionHandler>>>,
    state: Mutex<LeaseState>,
}

impl CodexInvocationLeaseOwner {
    pub(crate) fn new(
        session_id: &str,
        actor: ActorIdentity,
        profile: CodexInvocationLeaseProfile,
        audit_path: Option<PathBuf>,
    ) -> Self {
        Self {
            session_id: session_id.to_owned(),
            actor,
            profile_id: profile.id,
            terminal_root_context: profile.terminal_root_context,
            audit: audit_path.map(JsonlAuditSink::new),
            context_dag: Mutex::new(None),
            operation_admissions: Mutex::new(None),
            state: Mutex::new(LeaseState::default()),
        }
    }

    pub(crate) fn set_context_dag(
        &self,
        context_dag: Arc<CodexContextDag>,
    ) -> Result<(), CodexSessionError> {
        let mut attached =
            self.context_dag
                .lock()
                .map_err(|_error| CodexSessionError::ContextDagStateLock {
                    location: snafu::Location::default(),
                })?;
        *attached = Some(context_dag);
        Ok(())
    }

    pub(crate) fn context_dag(&self) -> Result<Option<Arc<CodexContextDag>>, CodexSessionError> {
        self.context_dag
            .lock()
            .map(|context_dag| context_dag.clone())
            .map_err(|_error| CodexSessionError::ContextDagStateLock {
                location: snafu::Location::default(),
            })
    }

    pub(crate) fn set_operation_admission_handler(
        &self,
        handler: Arc<dyn ContextOperationAdmissionHandler>,
    ) -> Result<(), CodexSessionError> {
        let mut installed = self.operation_admissions.lock().map_err(|_error| {
            CodexSessionError::InvocationLeaseStateLock {
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

    pub(crate) fn record_scope_context(
        &self,
        binding: CodexScopeContextBinding,
    ) -> Result<(), CodexSessionError> {
        let mut state = self.lock_state()?;
        state.scopes.insert(
            (binding.thread_id().to_owned(), binding.turn_id().to_owned()),
            binding,
        );
        Ok(())
    }

    pub(crate) fn record_authenticated_hook(
        &self,
        kind: HookEventKind,
        native_event_json: &[u8],
        runtime: CodexLeaseRuntimeEvidence,
        hook_pid: i64,
    ) -> Result<(), CodexSessionError> {
        let payload: Value = serde_json::from_slice(native_event_json).map_err(|error| {
            CodexSessionError::InvalidHookEvent {
                reason: format!(
                    "authenticated hook event could not be parsed for leasing: {error}"
                ),
                location: snafu::Location::default(),
            }
        })?;
        if kind == HookEventKind::UserPromptSubmit && self.terminal_root_context {
            if let Some(binding) = self.context_dag()?.map_or_else(
                || Ok(None),
                |context_dag| context_dag.bind_terminal_turn(&payload),
            )? {
                self.record_scope_context(binding)?;
            }
        }
        let operation_scope = if kind == HookEventKind::PostToolUse {
            self.operation_scope_for_post_tool_delivery(&payload, &runtime)?
        } else {
            None
        };
        let context_pin = operation_scope.as_ref().map_or_else(
            || self.record_hook_context(kind, &payload, &runtime, hook_pid),
            |operation_scope| {
                self.record_operation_hook_context(
                    kind,
                    &payload,
                    &runtime,
                    hook_pid,
                    operation_scope,
                )
            },
        )?;
        let mut state = self.lock_state()?;
        self.expire_locked(&mut state)?;
        if Self::cancelled(&payload) {
            self.close_matching_locked(
                &mut state,
                &payload,
                runtime,
                "hook-cancellation",
                context_pin.as_ref(),
            )?;
            return Ok(());
        }
        match kind {
            HookEventKind::PreToolUse => self.record_pre_tool_use_locked(
                &mut state,
                &payload,
                runtime,
                hook_pid,
                context_pin.as_ref(),
            ),
            HookEventKind::PermissionRequest => self.record_lifecycle_locked(
                &mut state,
                &payload,
                runtime,
                "permission-request",
                context_pin.as_ref(),
            ),
            HookEventKind::PostToolUse => self.record_post_tool_use_locked(
                &mut state,
                &payload,
                runtime,
                context_pin.as_ref(),
            ),
            HookEventKind::Stop => self.close_turn_locked(
                &mut state,
                &payload,
                runtime,
                "hook-stop",
                context_pin.as_ref(),
            ),
            HookEventKind::SessionStart
            | HookEventKind::UserPromptSubmit
            | HookEventKind::SubagentStart
            | HookEventKind::SubagentStop
            | HookEventKind::Unspecified => self.record_lifecycle_locked(
                &mut state,
                &payload,
                runtime,
                kind.name(),
                context_pin.as_ref(),
            ),
        }?;
        Ok(())
    }

    fn record_hook_context(
        &self,
        kind: HookEventKind,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
        hook_pid: i64,
    ) -> Result<Option<ContextPin>, CodexSessionError> {
        self.context_dag()?.as_ref().map_or_else(
            || Ok(None),
            |context_dag| {
                context_dag
                    .record_authenticated_hook(
                        kind,
                        payload,
                        serde_json::json!({
                            "runtime_pid": runtime.pid,
                            "runtime_start_time_ticks": runtime.process_start_time_ticks,
                            "runtime_executable": runtime.executable,
                            "hook_pid": hook_pid,
                        }),
                    )
                    .map(Some)
            },
        )
    }

    fn record_operation_hook_context(
        &self,
        kind: HookEventKind,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
        hook_pid: i64,
        operation_scope: &ScopeRef,
    ) -> Result<Option<ContextPin>, CodexSessionError> {
        self.context_dag()?.map_or_else(
            || {
                Err(CodexSessionError::IncompatibleProfile {
                    reason: String::from(
                        "Codex operation delivery has no daemon-owned context repository",
                    ),
                    location: snafu::Location::default(),
                })
            },
            |context_dag| {
                context_dag
                    .record_authenticated_operation_hook(
                        kind,
                        payload,
                        serde_json::json!({
                            "runtime_pid": runtime.pid,
                            "runtime_start_time_ticks": runtime.process_start_time_ticks,
                            "runtime_executable": runtime.executable,
                            "hook_pid": hook_pid,
                        }),
                        operation_scope,
                    )
                    .map(Some)
            },
        )
    }

    fn operation_scope_for_post_tool_delivery(
        &self,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
    ) -> Result<Option<ScopeRef>, CodexSessionError> {
        let Some(operation_key) = payload
            .pointer("/tool_response/erebor_delivery/operation_key")
            .and_then(Value::as_str)
            .filter(|key| !key.is_empty())
        else {
            return Ok(None);
        };
        let fields = InvocationIdentityFields::parse(payload).ok_or_else(|| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from(
                    "operation delivery must identify its exact Codex tool invocation",
                ),
                location: snafu::Location::default(),
            }
        })?;
        let identity = InvocationIdentity {
            runtime_id: runtime.runtime_id(),
            codex_session_id: fields.codex_session_id,
            turn_id: fields.turn_id,
            tool_use_id: fields.tool_use_id,
        };
        let mut state = self.lock_state()?;
        self.expire_locked(&mut state)?;
        let lease_id =
            state
                .identities
                .get(&identity)
                .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                    reason: String::from(
                        "operation delivery has no authenticated invocation lease",
                    ),
                    location: snafu::Location::default(),
                })?;
        let lease =
            state
                .leases
                .get(lease_id)
                .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                    reason: String::from("operation delivery invocation lease disappeared"),
                    location: snafu::Location::default(),
                })?;
        let InvocationCapability::Command {
            operation_key: Some(expected_key),
            ..
        } = &lease.capability
        else {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: String::from("operation delivery invocation is not an admitted command"),
                location: snafu::Location::default(),
            });
        };
        if expected_key != operation_key || lease.state == InvocationLeaseState::Closed {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: String::from(
                    "operation delivery does not match an active admitted command",
                ),
                location: snafu::Location::default(),
            });
        }
        lease
            .operation_scope
            .clone()
            .map(Some)
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("operation delivery has no daemon-created source scope"),
                location: snafu::Location::default(),
            })
    }

    fn record_pre_tool_use_locked(
        &self,
        state: &mut LeaseState,
        payload: &Value,
        runtime: CodexLeaseRuntimeEvidence,
        hook_pid: i64,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let Some(input) = InvocationInput::parse(payload) else {
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-invalid",
                None,
                payload,
                context_pin,
            );
        };
        let runtime_id = runtime.runtime_id();
        let identity = InvocationIdentity {
            runtime_id: runtime_id.clone(),
            codex_session_id: input.codex_session_id.clone(),
            turn_id: input.turn_id.clone(),
            tool_use_id: input.tool_use_id.clone(),
        };
        if let Some(existing) = state.identities.get(&identity) {
            let lease = state.leases.get(existing).cloned();
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-duplicate",
                lease.as_ref(),
                payload,
                context_pin,
            );
        }
        let (effect_class, capability) = InvocationCapability::from_input(&input);
        if effect_class == EffectClass::Unsupported {
            if input
                .tool_input
                .get("erebor_operation_key")
                .or_else(|| input.tool_input.get("ereborOperationKey"))
                .and_then(Value::as_str)
                .is_some_and(|operation_key| !operation_key.is_empty())
            {
                return Err(CodexSessionError::InvalidHookEvent {
                    reason: String::from(
                        "Codex operation source option is not a supported bounded command key",
                    ),
                    location: snafu::Location::default(),
                });
            }
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-unsupported-tool",
                None,
                payload,
                context_pin,
            );
        }
        let Some(context) =
            self.exact_scope_context(state, &input.codex_session_id, &input.turn_id)?
        else {
            if effect_class == EffectClass::LogicalFork {
                return Err(CodexSessionError::IncompatibleProfile {
                    reason: String::from(
                        "Codex logical fork has no exact authenticated parent thread/turn context",
                    ),
                    location: snafu::Location::default(),
                });
            }
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-no-exact-context",
                None,
                payload,
                context_pin,
            );
        };
        let context_pin = match &capability {
            InvocationCapability::LogicalFork {
                frozen_context_mode,
                last_turns,
                ..
            } => {
                let parent = context_pin.ok_or_else(|| CodexSessionError::IncompatibleProfile {
                    reason: String::from(
                        "Codex logical fork has no authenticated causal context to freeze",
                    ),
                    location: snafu::Location::default(),
                })?;
                let context_dag =
                    self.context_dag()?
                        .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                            reason: String::from(
                                "Codex logical fork has no daemon-owned context repository",
                            ),
                            location: snafu::Location::default(),
                        })?;
                Some(context_dag.frozen_prompt_projection(
                    parent,
                    *frozen_context_mode,
                    *last_turns,
                )?)
            }
            InvocationCapability::Command { .. }
            | InvocationCapability::InProcessMutation
            | InvocationCapability::Unsupported => context_pin.cloned(),
        };
        let mut logical_child_binding = None;
        let operation_scope = match &capability {
            InvocationCapability::Command {
                operation_key: Some(operation_key),
                ..
            } => {
                let parent_context =
                    context_pin
                        .clone()
                        .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                            reason: String::from(
                                "Codex operation has no authenticated causal context to pin",
                            ),
                            location: snafu::Location::default(),
                        })?;
                let handler = self
                    .operation_admissions
                    .lock()
                    .map_err(|_error| CodexSessionError::InvocationLeaseStateLock {
                        location: snafu::Location::default(),
                    })?
                    .clone()
                    .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                        reason: String::from("Codex operation admission is not daemon-bound"),
                        location: snafu::Location::default(),
                    })?;
                Some(
                    handler
                        .admit_operation(ContextOperationAdmission::new(
                            self.session_id.clone(),
                            parent_context.clone(),
                            operation_key.clone(),
                            Some(input.tool_use_id.clone()),
                        ))
                        .map_err(|reason| CodexSessionError::IncompatibleProfile {
                            reason: format!("daemon rejected Codex operation admission: {reason}"),
                            location: snafu::Location::default(),
                        })
                        .and_then(|scope| {
                            self.context_dag()?
                                .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                                    reason: String::from(
                                        "Codex operation has no daemon-owned context repository",
                                    ),
                                    location: snafu::Location::default(),
                                })?
                                .refresh_scope_head(&parent_context)?;
                            Ok(scope)
                        })?,
                )
            }
            InvocationCapability::Command {
                operation_key: None,
                ..
            }
            | InvocationCapability::InProcessMutation
            | InvocationCapability::Unsupported => None,
            InvocationCapability::LogicalFork {
                child_thread_id,
                child_turn_id,
                ..
            } => {
                let parent_context =
                    context_pin
                        .clone()
                        .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                            reason: String::from(
                                "Codex logical fork has no authenticated causal context to pin",
                            ),
                            location: snafu::Location::default(),
                        })?;
                let handler = self
                    .operation_admissions
                    .lock()
                    .map_err(|_error| CodexSessionError::InvocationLeaseStateLock {
                        location: snafu::Location::default(),
                    })?
                    .clone()
                    .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                        reason: String::from("Codex logical-fork admission is not daemon-bound"),
                        location: snafu::Location::default(),
                    })?;
                let digest = format!(
                    "{:x}",
                    Sha256::digest(format!("{child_thread_id}\0{child_turn_id}").as_bytes())
                );
                let key = format!("fork-{}", &digest[..32]);
                let scope = handler
                    .admit_operation(
                        ContextOperationAdmission::new(
                            self.session_id.clone(),
                            parent_context.clone(),
                            key,
                            Some(input.tool_use_id.clone()),
                        )
                        .select_parent_context(),
                    )
                    .map_err(|reason| CodexSessionError::IncompatibleProfile {
                        reason: format!("daemon rejected Codex logical-fork admission: {reason}"),
                        location: snafu::Location::default(),
                    })?;
                let context_dag =
                    self.context_dag()?
                        .ok_or_else(|| CodexSessionError::IncompatibleProfile {
                            reason: String::from(
                                "Codex logical fork has no daemon-owned context repository",
                            ),
                            location: snafu::Location::default(),
                        })?;
                context_dag.refresh_scope_head(&parent_context)?;
                logical_child_binding = Some(context_dag.bind_admitted_scope(
                    child_thread_id.clone(),
                    child_turn_id.clone(),
                    scope.clone(),
                )?);
                Some(scope)
            }
        };
        if let Some(binding) = logical_child_binding {
            state.scopes.insert(
                (binding.thread_id().to_owned(), binding.turn_id().to_owned()),
                binding,
            );
        }
        let lane = HandoffLane {
            scope_ref: context.scope_ref().to_owned(),
            item_node_stream: context.item_node_stream().to_owned(),
            tool_use_id: input.tool_use_id.clone(),
            effect_class,
        };
        if let Some(existing) = state.lanes.get(&lane) {
            let lease = state.leases.get(existing).cloned();
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-lane-busy",
                lease.as_ref(),
                payload,
                context_pin.as_ref(),
            );
        }

        let id = Self::lease_id(&identity);
        let input_sha256 = Self::digest_json(&input.tool_input);
        let mut lease = InvocationLease {
            id: id.clone(),
            identity: identity.clone(),
            key: InvocationKey {
                erebor_session_id: self.session_id.clone(),
                runtime_id,
                scope_ref: context.scope_ref().to_owned(),
                item_node_stream: context.item_node_stream().to_owned(),
                decision_head: context.decision_head().to_owned(),
                codex_session_id: input.codex_session_id,
                turn_id: input.turn_id,
                tool_use_id: input.tool_use_id,
            },
            tool_name: input.tool_name,
            structured_input_sha256: input_sha256,
            effect_class,
            capability,
            state: InvocationLeaseState::Preparing,
            runtime_pid: runtime.pid,
            hook_pid,
            hook_profile_epoch: self.profile_id.clone(),
            expires_at_millis: Self::now_millis() + LEASE_LIFETIME.as_millis(),
            context_pin,
            operation_scope,
        };
        self.record_transition_locked(
            state,
            &lease,
            "pre-tool-use-authenticated",
            lease.context_pin.as_ref(),
        )?;
        lease.state = InvocationLeaseState::ResponseIssued;
        self.record_transition_locked(
            state,
            &lease,
            "hook-response-issued",
            lease.context_pin.as_ref(),
        )?;
        state.lanes.insert(lane, id.clone());
        state.identities.insert(identity, id.clone());
        state.leases.insert(id, lease);
        Ok(())
    }

    fn exact_scope_context(
        &self,
        state: &LeaseState,
        thread_id: &str,
        turn_id: &str,
    ) -> Result<Option<CodexScopeContextBinding>, CodexSessionError> {
        if let Some(binding) = state
            .scopes
            .get(&(thread_id.to_owned(), turn_id.to_owned()))
            .cloned()
        {
            return Ok(Some(binding));
        }
        self.context_dag()?.map_or_else(
            || Ok(None),
            |context_dag| context_dag.exact_binding(thread_id, turn_id),
        )
    }

    fn record_post_tool_use_locked(
        &self,
        state: &mut LeaseState,
        payload: &Value,
        runtime: CodexLeaseRuntimeEvidence,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let Some(input) = InvocationIdentityFields::parse(payload) else {
            return self.record_hook_fact_locked(
                state,
                "post-tool-use-invalid",
                None,
                payload,
                context_pin,
            );
        };
        let identity = InvocationIdentity {
            runtime_id: runtime.runtime_id(),
            codex_session_id: input.codex_session_id,
            turn_id: input.turn_id,
            tool_use_id: input.tool_use_id,
        };
        let Some(lease_id) = state.identities.get(&identity).cloned() else {
            return self.record_hook_fact_locked(
                state,
                "post-tool-use-unmatched",
                None,
                payload,
                context_pin,
            );
        };
        let Some(lease) = state.leases.get_mut(&lease_id) else {
            return self.record_hook_fact_locked(
                state,
                "post-tool-use-missing",
                None,
                payload,
                context_pin,
            );
        };
        let transition = if lease.state != InvocationLeaseState::Closed {
            lease.state = InvocationLeaseState::DispatchComplete;
            Some(lease.clone())
        } else {
            None
        };
        if let Some(lease) = transition.as_ref() {
            self.record_transition_locked(state, lease, "post-tool-use", context_pin)?;
        }
        Ok(())
    }

    pub(crate) fn operation_delivery_scope(
        &self,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
        operation_key: &str,
    ) -> Result<ScopeRef, CodexSessionError> {
        let fields = InvocationIdentityFields::parse(payload).ok_or_else(|| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from(
                    "operation delivery must identify its exact Codex tool invocation",
                ),
                location: snafu::Location::default(),
            }
        })?;
        let identity = InvocationIdentity {
            runtime_id: runtime.runtime_id(),
            codex_session_id: fields.codex_session_id,
            turn_id: fields.turn_id,
            tool_use_id: fields.tool_use_id,
        };
        let state = self.lock_state()?;
        let lease_id =
            state
                .identities
                .get(&identity)
                .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                    reason: String::from(
                        "operation delivery has no authenticated invocation lease",
                    ),
                    location: snafu::Location::default(),
                })?;
        let lease =
            state
                .leases
                .get(lease_id)
                .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                    reason: String::from("operation delivery invocation lease disappeared"),
                    location: snafu::Location::default(),
                })?;
        let InvocationCapability::Command {
            operation_key: Some(expected_key),
            ..
        } = &lease.capability
        else {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: String::from("operation delivery invocation is not an admitted command"),
                location: snafu::Location::default(),
            });
        };
        if expected_key != operation_key || lease.state != InvocationLeaseState::DispatchComplete {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: String::from(
                    "operation delivery does not match a completed admitted command",
                ),
                location: snafu::Location::default(),
            });
        }
        lease
            .operation_scope
            .clone()
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("operation delivery has no daemon-created source scope"),
                location: snafu::Location::default(),
            })
    }

    /// Select the exact same-session source scope for a bounded delivery.
    /// A completed admitted command owns its dedicated operation scope; every
    /// other delivery is attributed to the authenticated Codex thread/turn
    /// that emitted it. No child session identity is involved.
    pub(crate) fn delivery_scope(
        &self,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
        operation_key: Option<&str>,
    ) -> Result<ScopeRef, CodexSessionError> {
        if let Some(operation_key) = operation_key {
            return self.operation_delivery_scope(payload, runtime, operation_key);
        }
        let fields = InvocationTurnFields::parse(payload).ok_or_else(|| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from("delivery must identify its exact Codex thread and turn"),
                location: snafu::Location::default(),
            }
        })?;
        let state = self.lock_state()?;
        let binding = self
            .exact_scope_context(&state, &fields.codex_session_id, &fields.turn_id)?
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("delivery has no exact admitted Codex context scope"),
                location: snafu::Location::default(),
            })?;
        ScopeRef::parse(binding.scope_ref().to_owned()).map_err(|error| {
            CodexSessionError::InvalidHookEvent {
                reason: format!("delivery scope reference is invalid: {error}"),
                location: snafu::Location::default(),
            }
        })
    }

    fn record_lifecycle_locked(
        &self,
        state: &mut LeaseState,
        payload: &Value,
        runtime: CodexLeaseRuntimeEvidence,
        fact: &str,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let matching = self.exact_lease_for_payload(state, payload, &runtime);
        self.record_hook_fact_locked(state, fact, matching.as_ref(), payload, context_pin)
    }

    fn exact_lease_for_payload(
        &self,
        state: &LeaseState,
        payload: &Value,
        runtime: &CodexLeaseRuntimeEvidence,
    ) -> Option<InvocationLease> {
        let fields = InvocationIdentityFields::parse(payload)?;
        let identity = InvocationIdentity {
            runtime_id: runtime.runtime_id(),
            codex_session_id: fields.codex_session_id,
            turn_id: fields.turn_id,
            tool_use_id: fields.tool_use_id,
        };
        state
            .identities
            .get(&identity)
            .and_then(|lease_id| state.leases.get(lease_id))
            .cloned()
    }

    fn close_all_locked(
        &self,
        state: &mut LeaseState,
        reason: &str,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let lease_ids = state.leases.keys().cloned().collect::<Vec<_>>();
        for lease_id in lease_ids {
            let Some(lease) = state.leases.get_mut(&lease_id) else {
                continue;
            };
            if lease.state == InvocationLeaseState::Closed {
                continue;
            }
            lease.state = InvocationLeaseState::Closed;
            let lease = lease.clone();
            self.record_transition_locked(state, &lease, reason, context_pin)?;
        }
        state.lanes.clear();
        Ok(())
    }

    fn close_matching_locked(
        &self,
        state: &mut LeaseState,
        payload: &Value,
        runtime: CodexLeaseRuntimeEvidence,
        reason: &str,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let Some(fields) = InvocationIdentityFields::parse(payload) else {
            return self.record_hook_fact_locked(state, reason, None, payload, context_pin);
        };
        let identity = InvocationIdentity {
            runtime_id: runtime.runtime_id(),
            codex_session_id: fields.codex_session_id,
            turn_id: fields.turn_id,
            tool_use_id: fields.tool_use_id,
        };
        let Some(lease_id) = state.identities.get(&identity).cloned() else {
            return self.record_hook_fact_locked(state, reason, None, payload, context_pin);
        };
        let Some(lease) = state.leases.get_mut(&lease_id) else {
            return self.record_hook_fact_locked(state, reason, None, payload, context_pin);
        };
        lease.state = InvocationLeaseState::Closed;
        let lease = lease.clone();
        self.record_transition_locked(state, &lease, reason, context_pin)?;
        state.lanes.retain(|_lane, id| id != &lease_id);
        Ok(())
    }

    fn close_turn_locked(
        &self,
        state: &mut LeaseState,
        payload: &Value,
        runtime: CodexLeaseRuntimeEvidence,
        reason: &str,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let Some(fields) = InvocationTurnFields::parse(payload) else {
            return self.record_hook_fact_locked(state, reason, None, payload, context_pin);
        };
        let runtime_id = runtime.runtime_id();
        let lease_ids = state
            .leases
            .iter()
            .filter(|(_lease_id, lease)| {
                lease.identity.runtime_id == runtime_id
                    && lease.identity.codex_session_id == fields.codex_session_id
                    && lease.identity.turn_id == fields.turn_id
                    && lease.state != InvocationLeaseState::Closed
            })
            .map(|(lease_id, _lease)| lease_id.clone())
            .collect::<Vec<_>>();
        if lease_ids.is_empty() {
            return self.record_hook_fact_locked(state, reason, None, payload, context_pin);
        }
        for lease_id in &lease_ids {
            let Some(lease) = state.leases.get_mut(lease_id) else {
                continue;
            };
            lease.state = InvocationLeaseState::Closed;
            let lease = lease.clone();
            self.record_transition_locked(state, &lease, reason, context_pin)?;
        }
        state
            .lanes
            .retain(|_lane, lease_id| !lease_ids.contains(lease_id));
        Ok(())
    }

    fn record_hook_fact_locked(
        &self,
        state: &mut LeaseState,
        fact: &str,
        lease: Option<&InvocationLease>,
        payload: &Value,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        self.record_audit_locked(
            state,
            fact,
            lease,
            serde_json::json!({"hook_payload": payload}),
            false,
            context_pin,
        )
    }

    fn record_transition_locked(
        &self,
        state: &mut LeaseState,
        lease: &InvocationLease,
        transition: &str,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        self.record_audit_locked(
            state,
            transition,
            Some(lease),
            serde_json::json!({"state": lease.state.as_str()}),
            lease.state == InvocationLeaseState::Closed,
            context_pin.or(lease.context_pin.as_ref()),
        )
    }

    fn record_audit_locked(
        &self,
        state: &mut LeaseState,
        fact: &str,
        lease: Option<&InvocationLease>,
        payload: Value,
        denied: bool,
        context_pin: Option<&ContextPin>,
    ) -> Result<(), CodexSessionError> {
        let Some(audit) = self.audit.as_ref() else {
            return Ok(());
        };
        state.next_audit_sequence += 1;
        let lease_payload = lease.map(|lease| {
            serde_json::json!({
                "lease_id": lease.id,
                "key": {
                    "erebor_session_id": lease.key.erebor_session_id,
                    "runtime_id": lease.key.runtime_id,
                    "scope_ref": lease.key.scope_ref,
                    "item_node_stream": lease.key.item_node_stream,
                    "decision_head": lease.key.decision_head,
                    "codex_session_id": lease.key.codex_session_id,
                    "turn_id": lease.key.turn_id,
                    "tool_use_id": lease.key.tool_use_id,
                },
                "tool_name": lease.tool_name,
                "structured_input_sha256": lease.structured_input_sha256,
                "effect_class": lease.effect_class.as_str(),
                "state": lease.state.as_str(),
                "runtime_pid": lease.runtime_pid,
                "hook_pid": lease.hook_pid,
                "profile_health_epoch": lease.hook_profile_epoch,
                "expires_at_millis": lease.expires_at_millis,
                "operation_scope": lease.operation_scope.as_ref().map(ToString::to_string),
            })
        });
        let event = RuntimeEvent {
            id: EventId::new(format!(
                "{}-codex-invocation-lease-{}",
                self.session_id, state.next_audit_sequence
            )),
            session_id: SessionId::new(self.session_id.clone()),
            actor: self.actor.clone(),
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ToolInvoke,
            target: lease.map(|lease| TargetRef {
                label: Some(lease.tool_name.clone()),
                uri: None,
            }),
            payload: serde_json::json!({
                "kind": "codex_invocation_lease_v1",
                "fact": fact,
                "lease": lease_payload,
                "detail": payload,
            }),
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("codex_invocation_lease")],
            },
            timestamp: format!("unix_millis:{}", Self::now_millis()),
        };
        let decision = if denied {
            Decision::Deny {
                reason: String::from("Codex invocation lease denied the physical effect"),
                rule_id: Some(String::from("erebor-codex-invocation-lease")),
            }
        } else {
            Decision::RequireApproval {
                reason: String::from("Codex invocation lease fact is not a policy allow"),
                rule_id: Some(String::from("erebor-codex-invocation-lease")),
                approval_id: None,
            }
        };
        audit
            .record_durable(&AuditRecord {
                event,
                policy_decision: decision.clone(),
                final_decision: decision,
                context_pin: context_pin.cloned(),
            })
            .map_err(|source| CodexSessionError::InvocationLeaseAudit {
                source,
                location: snafu::Location::default(),
            })
    }

    fn expire_locked(&self, state: &mut LeaseState) -> Result<(), CodexSessionError> {
        let now = Self::now_millis();
        let expired = state
            .leases
            .iter()
            .filter(|(_id, lease)| {
                lease.state != InvocationLeaseState::Closed && lease.expires_at_millis <= now
            })
            .map(|(id, _lease)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            let Some(lease) = state.leases.get_mut(&id) else {
                continue;
            };
            lease.state = InvocationLeaseState::Closed;
            let lease = lease.clone();
            self.record_transition_locked(state, &lease, "lease-expired", None)?;
        }
        state.lanes.retain(|_lane, id| {
            state
                .leases
                .get(id)
                .is_some_and(|lease| lease.state != InvocationLeaseState::Closed)
        });
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, LeaseState>, CodexSessionError> {
        self.state
            .lock()
            .map_err(|_error| CodexSessionError::InvocationLeaseStateLock {
                location: snafu::Location::default(),
            })
    }

    fn lease_id(identity: &InvocationIdentity) -> String {
        Self::digest_bytes(
            format!(
                "{}\0{}\0{}\0{}",
                identity.runtime_id,
                identity.codex_session_id,
                identity.turn_id,
                identity.tool_use_id
            )
            .as_bytes(),
        )
    }

    fn digest_json(value: &Value) -> String {
        Self::digest_bytes(&serde_json::to_vec(&Self::canonical_json(value)).unwrap_or_default())
    }

    fn canonical_json(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(Self::canonical_json).collect()),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::canonical_json(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn digest_bytes(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis())
    }

    fn cancelled(payload: &Value) -> bool {
        ["cancelled", "canceled", "is_cancelled", "isCanceled"]
            .iter()
            .any(|field| payload.get(*field).and_then(Value::as_bool) == Some(true))
    }
}

impl Drop for CodexInvocationLeaseOwner {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Err(error) = self.close_all_locked(&mut state, "runtime-exit", None) {
            warn!(error; "failed to durably close Codex invocation leases at runtime exit");
        }
    }
}

struct InvocationInput {
    codex_session_id: String,
    turn_id: String,
    tool_use_id: String,
    tool_name: String,
    tool_input: Value,
}

impl InvocationInput {
    fn parse(payload: &Value) -> Option<Self> {
        Some(Self {
            codex_session_id: Self::string(
                payload,
                &["session_id", "sessionId", "thread_id", "threadId"],
            )?,
            turn_id: Self::string(payload, &["turn_id", "turnId"])?,
            tool_use_id: Self::string(payload, &["tool_use_id", "toolUseId"])?,
            tool_name: Self::string(payload, &["tool_name", "toolName"])?,
            tool_input: payload
                .get("tool_input")
                .or_else(|| payload.get("toolInput"))?
                .clone(),
        })
    }

    fn string(payload: &Value, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            payload
                .get(*name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
    }
}

struct InvocationIdentityFields {
    codex_session_id: String,
    turn_id: String,
    tool_use_id: String,
}

struct InvocationTurnFields {
    codex_session_id: String,
    turn_id: String,
}

impl InvocationTurnFields {
    fn parse(payload: &Value) -> Option<Self> {
        Some(Self {
            codex_session_id: Self::string(
                payload,
                &["session_id", "sessionId", "thread_id", "threadId"],
            )?,
            turn_id: Self::string(payload, &["turn_id", "turnId"])?,
        })
    }

    fn string(payload: &Value, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            payload
                .get(*name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
    }
}

impl InvocationIdentityFields {
    fn parse(payload: &Value) -> Option<Self> {
        Some(Self {
            codex_session_id: Self::string(
                payload,
                &["session_id", "sessionId", "thread_id", "threadId"],
            )?,
            turn_id: Self::string(payload, &["turn_id", "turnId"])?,
            tool_use_id: Self::string(payload, &["tool_use_id", "toolUseId"])?,
        })
    }

    fn string(payload: &Value, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            payload
                .get(*name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
    }
}

impl InvocationCapability {
    fn from_input(input: &InvocationInput) -> (EffectClass, Self) {
        let tool = input.tool_name.to_ascii_lowercase();
        if matches!(tool.as_str(), "erebor_delegate" | "erebor-delegate") {
            let child_thread_id = input
                .tool_input
                .get("child_thread_id")
                .or_else(|| input.tool_input.get("childThreadId"))
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
                .map(str::to_owned);
            let child_turn_id = input
                .tool_input
                .get("child_turn_id")
                .or_else(|| input.tool_input.get("childTurnId"))
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
                .map(str::to_owned);
            let mode = input
                .tool_input
                .get("frozen_context_mode")
                .or_else(|| input.tool_input.get("frozenContextMode"))
                .and_then(Value::as_str)
                .and_then(|value| match value {
                    "none" => Some(CodexFrozenContextMode::None),
                    "all" => Some(CodexFrozenContextMode::All),
                    "last_turns" => Some(CodexFrozenContextMode::LastTurns),
                    _ => None,
                });
            let last_turns = input
                .tool_input
                .get("last_turns")
                .or_else(|| input.tool_input.get("lastTurns"))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
            if let (
                Some(child_thread_id),
                Some(child_turn_id),
                Some(frozen_context_mode),
                Some(last_turns),
            ) = (child_thread_id, child_turn_id, mode, last_turns)
            {
                let valid_turn_count = match frozen_context_mode {
                    CodexFrozenContextMode::LastTurns => {
                        (1..=MAX_LOGICAL_FORK_LAST_TURNS).contains(&last_turns)
                    }
                    CodexFrozenContextMode::None | CodexFrozenContextMode::All => last_turns == 0,
                };
                if valid_turn_count {
                    return (
                        EffectClass::LogicalFork,
                        Self::LogicalFork {
                            child_thread_id,
                            child_turn_id,
                            frozen_context_mode,
                            last_turns,
                        },
                    );
                }
            }
        }
        if matches!(tool.as_str(), "bash" | "shell" | "command")
            && input
                .tool_input
                .get("command")
                .and_then(Value::as_str)
                .filter(|command| !command.is_empty())
                .is_some()
        {
            let operation_key = match input
                .tool_input
                .get("erebor_operation_key")
                .or_else(|| input.tool_input.get("ereborOperationKey"))
            {
                None => None,
                Some(Value::String(key)) if key.is_empty() => None,
                Some(Value::String(key))
                    if key.len() <= 128
                        && key.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                        }) =>
                {
                    Some(key.clone())
                }
                Some(_) => return (EffectClass::Unsupported, Self::Unsupported),
            };
            return (EffectClass::Command, Self::Command { operation_key });
        }
        if matches!(tool.as_str(), "apply_patch" | "applypatch") {
            let mut targets = Self::patch_targets(&input.tool_input);
            targets.sort();
            targets.dedup();
            if !targets.is_empty() {
                return (EffectClass::InProcessMutation, Self::InProcessMutation);
            }
        }
        (EffectClass::Unsupported, Self::Unsupported)
    }

    fn patch_targets(input: &Value) -> Vec<String> {
        let direct = ["path", "file_path", "filePath"]
            .iter()
            .filter_map(|name| input.get(*name).and_then(Value::as_str))
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        let listed = input
            .get("paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        let patch = input
            .get("patch")
            .and_then(Value::as_str)
            .into_iter()
            .flat_map(|patch| {
                patch.lines().filter_map(|line| {
                    ["*** Add File: ", "*** Delete File: ", "*** Update File: "]
                        .iter()
                        .find_map(|prefix| line.strip_prefix(prefix))
                        .filter(|path| !path.is_empty())
                        .map(str::to_owned)
                })
            });
        direct.chain(listed).chain(patch).collect()
    }
}

trait HookEventKindName {
    fn name(self) -> &'static str;
}

impl HookEventKindName for HookEventKind {
    fn name(self) -> &'static str {
        match self {
            Self::SessionStart => "session-start",
            Self::UserPromptSubmit => "user-prompt-submit",
            Self::PreToolUse => "pre-tool-use",
            Self::PermissionRequest => "permission-request",
            Self::PostToolUse => "post-tool-use",
            Self::SubagentStart => "subagent-start",
            Self::SubagentStop => "subagent-stop",
            Self::Stop => "stop",
            Self::Unspecified => "unspecified",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        CodexContextDag, CodexInvocationLeaseOwner, CodexLeaseRuntimeEvidence,
        CodexScopeContextBinding, CodexSessionError, InvocationLeaseState,
    };
    use crate::{ContextOperationAdmission, ContextOperationAdmissionHandler};
    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, ScopeRef, ScopeStart,
    };

    struct RecordingOperationAdmission {
        scope: ScopeRef,
        admissions: Mutex<Vec<ContextOperationAdmission>>,
    }

    impl ContextOperationAdmissionHandler for RecordingOperationAdmission {
        fn admit_operation(
            &self,
            admission: ContextOperationAdmission,
        ) -> std::result::Result<ScopeRef, String> {
            self.admissions
                .lock()
                .map_err(|_error| String::from("operation admission lock poisoned"))?
                .push(admission);
            Ok(self.scope.clone())
        }
    }

    #[test]
    fn leases_are_exact_to_scope_and_tool_use_without_command_text(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = test_owner();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_scope_context(CodexScopeContextBinding::new(
            String::from("thread-2"),
            String::from("turn-1"),
            String::from("scope-b"),
            String::from("item-b"),
            String::from("head-b"),
        ))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-2").as_bytes(),
            runtime(),
            102,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            br#"{"hook_event_name":"PreToolUse","session_id":"thread-2","turn_id":"turn-1","tool_use_id":"tool-3","tool_name":"Bash","tool_input":{"command":"echo permitted"}}"#,
            runtime(),
            103,
        )?;
        let state = owner.state.lock().map_err(|_error| "lock")?;
        assert_eq!(state.leases.len(), 3);
        assert!(state
            .leases
            .values()
            .all(|lease| lease.key.scope_ref == "scope-a" || lease.key.scope_ref == "scope-b"));
        Ok(())
    }

    #[test]
    fn stop_closes_only_leases_in_its_exact_native_turn() -> Result<(), Box<dyn std::error::Error>>
    {
        let owner = test_owner();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_scope_context(binding_for("thread-2", "turn-1", "scope-b", "item-b"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event_for("thread-2", "turn-1", "tool-2").as_bytes(),
            runtime(),
            102,
        )?;

        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::Stop,
            stop_event("thread-1", "turn-1").as_bytes(),
            runtime(),
            103,
        )?;

        let state = owner.state.lock().map_err(|_error| "lock")?;
        assert_eq!(
            state
                .leases
                .values()
                .find(|lease| lease.key.scope_ref == "scope-a")
                .map(|lease| lease.state),
            Some(InvocationLeaseState::Closed)
        );
        assert_eq!(
            state
                .leases
                .values()
                .find(|lease| lease.key.scope_ref == "scope-b")
                .map(|lease| lease.state),
            Some(InvocationLeaseState::ResponseIssued)
        );
        Ok(())
    }

    #[test]
    fn lifecycle_audits_use_an_exact_lease_or_remain_unbound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let audit_path = root.path().join("audit.jsonl");
        let owner = CodexInvocationLeaseOwner::new(
            "session-test",
            test_actor(),
            test_profile(),
            Some(audit_path.clone()),
        );
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_scope_context(binding_for("thread-2", "turn-1", "scope-b", "item-b"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event_for("thread-2", "turn-1", "tool-2").as_bytes(),
            runtime(),
            102,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PermissionRequest,
            permission_event("thread-2", "turn-1", "tool-2").as_bytes(),
            runtime(),
            103,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PermissionRequest,
            permission_event("thread-3", "turn-1", "tool-3").as_bytes(),
            runtime(),
            104,
        )?;

        let records = erebor_runtime_audit::read_audit_records(audit_path)?;
        let exact = records
            .iter()
            .find(|record| {
                record
                    .event
                    .payload
                    .pointer("/fact")
                    .and_then(serde_json::Value::as_str)
                    == Some("permission-request")
                    && record
                        .event
                        .payload
                        .pointer("/detail/hook_payload/session_id")
                        .and_then(serde_json::Value::as_str)
                        == Some("thread-2")
            })
            .ok_or("missing exact permission lifecycle audit")?;
        assert_eq!(
            exact
                .event
                .payload
                .pointer("/lease/key/scope_ref")
                .and_then(serde_json::Value::as_str),
            Some("scope-b")
        );
        let unmatched = records
            .iter()
            .find(|record| {
                record
                    .event
                    .payload
                    .pointer("/fact")
                    .and_then(serde_json::Value::as_str)
                    == Some("permission-request")
                    && record
                        .event
                        .payload
                        .pointer("/detail/hook_payload/session_id")
                        .and_then(serde_json::Value::as_str)
                        == Some("thread-3")
            })
            .ok_or("missing unmatched permission lifecycle audit")?;
        assert!(unmatched
            .event
            .payload
            .pointer("/lease")
            .is_some_and(serde_json::Value::is_null));
        Ok(())
    }

    #[test]
    fn authenticated_hook_audit_records_pin_the_exact_dag_blob(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let audit_path = root.path().join("audit.jsonl");
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            root.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root(
            "session-test",
            Default::default(),
            "Initialize session root",
        )?;
        let context_dag = Arc::new(CodexContextDag::new(
            Arc::clone(&repository),
            "session-test",
        ));
        let scope_ref = context_dag.ensure_prompt_scope("thread-1")?;
        let prompt_path = context_dag.append_prompt(
            &scope_ref,
            br#"{"source":"test"}"#.to_vec(),
            "Record test prompt",
        )?;
        context_dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &scope_ref,
            prompt_path.clone(),
        )?;
        let owner = CodexInvocationLeaseOwner::new(
            "session-test",
            test_actor(),
            test_profile(),
            Some(audit_path.clone()),
        );
        owner.set_context_dag(context_dag)?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        let records = erebor_runtime_audit::read_audit_records(audit_path)?;
        let record = records
            .iter()
            .find(|record| {
                record
                    .event
                    .payload
                    .pointer("/fact")
                    .and_then(serde_json::Value::as_str)
                    == Some("pre-tool-use-authenticated")
            })
            .ok_or("missing PreToolUse audit fact")?;
        let pin = record.context_pin.as_ref().ok_or("missing context pin")?;
        assert_eq!(pin.scope_ref(), scope_ref);
        assert!(pin
            .used_paths()
            .iter()
            .all(|path| path.starts_with("agents/codex/hooks/")));
        repository.validate_pin(pin)?;
        Ok(())
    }

    #[test]
    fn operation_delivery_uses_only_its_admitted_scope_and_exact_lease(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            root.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root(
            "session-test",
            Default::default(),
            "Initialize session root",
        )?;
        let context_dag = Arc::new(CodexContextDag::new(
            Arc::clone(&repository),
            "session-test",
        ));
        let prompt_scope = context_dag.ensure_prompt_scope("thread-1")?;
        let prompt_path = context_dag.append_prompt(
            &prompt_scope,
            br#"{"request":{"prompt":"start q"}}"#.to_vec(),
            "Record test prompt",
        )?;
        context_dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &prompt_scope,
            prompt_path,
        )?;
        let operation_scope = ScopeRef::scope("session-test", "codex-operation-test")?;
        let root_scope = ScopeRef::root("session-test")?;
        repository.create_scope(
            operation_scope.clone(),
            ScopeStart::existing_commit(repository.scope_head(&root_scope)?),
        )?;
        let admissions = Arc::new(RecordingOperationAdmission {
            scope: operation_scope.clone(),
            admissions: Mutex::new(Vec::new()),
        });
        let owner =
            CodexInvocationLeaseOwner::new("session-test", test_actor(), test_profile(), None);
        owner.set_context_dag(context_dag)?;
        owner.set_operation_admission_handler(Arc::clone(&admissions) as Arc<_>)?;
        let pre = operation_command_event("operation-1");
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            pre.as_bytes(),
            runtime(),
            101,
        )?;
        let admitted = admissions
            .admissions
            .lock()
            .map_err(|_error| "operation admission lock poisoned")?;
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].session_id(), "session-test");
        assert_eq!(admitted[0].operation_key(), "fixture-q");
        assert_eq!(admitted[0].parent_context().scope_ref(), prompt_scope);
        let owner_scope = admitted[0].parent_context().scope()?;
        let owner_head_before_delivery = repository.scope_head(&owner_scope)?;
        let operation_head_before_delivery = repository.scope_head(&operation_scope)?;
        drop(admitted);
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("parallel-command").as_bytes(),
            runtime(),
            102,
        )?;
        let owner_head_after_parallel_hook = repository.scope_head(&owner_scope)?;
        assert_ne!(owner_head_after_parallel_hook, owner_head_before_delivery);
        assert_eq!(
            repository.scope_head(&operation_scope)?,
            operation_head_before_delivery
        );
        let post = String::from(
            r#"{"hook_event_name":"PostToolUse","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"operation-1","tool_response":{"status":"ok","erebor_delivery":{"sequence":1,"kind":"result","mode":"queue","selected_text":"partial","operation_key":"fixture-q"}}}"#,
        );
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PostToolUse,
            post.as_bytes(),
            runtime(),
            102,
        )?;
        assert_eq!(
            owner.operation_delivery_scope(
                &serde_json::from_str(&post)?,
                &runtime(),
                "fixture-q",
            )?,
            operation_scope
        );
        assert_eq!(
            repository.scope_head(&owner_scope)?,
            owner_head_after_parallel_hook
        );
        assert_ne!(
            repository.scope_head(&operation_scope)?,
            operation_head_before_delivery
        );
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::Stop,
            stop_event("thread-1", "turn-1").as_bytes(),
            runtime(),
            103,
        )?;
        assert!(owner
            .operation_delivery_scope(&serde_json::from_str(&post)?, &runtime(), "fixture-q")
            .is_err());
        Ok(())
    }

    #[test]
    fn unsupported_operation_source_override_is_rejected_before_command_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = owner_with_scope()?;
        let event = br#"{"hook_event_name":"PreToolUse","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"invalid-operation","tool_name":"Bash","tool_input":{"command":"ls","erebor_operation_key":"not/a-key"}}"#;
        assert!(matches!(
            owner.record_authenticated_hook(
                erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
                event,
                runtime(),
                101,
            ),
            Err(CodexSessionError::InvalidHookEvent { .. })
        ));
        assert!(owner
            .state
            .lock()
            .map_err(|_error| "lease state lock poisoned")?
            .leases
            .is_empty());
        Ok(())
    }

    #[test]
    fn non_effect_control_with_an_empty_command_key_is_retained_without_a_lease(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = owner_with_scope()?;
        let event = br#"{"hook_event_name":"PreToolUse","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"control-1","tool_name":"erebor_context_control","tool_input":{"command":"","erebor_operation_key":"","erebor_context_action":"list_agents"}}"#;

        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            event,
            runtime(),
            101,
        )?;

        assert!(owner
            .state
            .lock()
            .map_err(|_error| "lease state lock poisoned")?
            .leases
            .is_empty());
        Ok(())
    }

    #[test]
    fn logical_child_fork_binds_a_new_thread_without_a_child_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            root.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root(
            "session-test",
            Default::default(),
            "Initialize session root",
        )?;
        let context_dag = Arc::new(CodexContextDag::new(
            Arc::clone(&repository),
            "session-test",
        ));
        let scope_ref = context_dag.ensure_prompt_scope("thread-1")?;
        let prompt_path = context_dag.append_prompt(
            &scope_ref,
            br#"{"request":{"prompt":"delegate this context"}}"#.to_vec(),
            "Record test prompt",
        )?;
        let binding = context_dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &scope_ref,
            prompt_path.clone(),
        )?;
        let child_scope = ScopeRef::scope("session-test", "codex-operation-logical-child")?;
        assert_eq!(child_scope.session_id(), "session-test");
        repository.create_scope(
            child_scope.clone(),
            ScopeStart::existing_commit(
                repository.scope_head(&ScopeRef::parse(scope_ref.clone())?)?,
            ),
        )?;
        let admissions = Arc::new(RecordingOperationAdmission {
            scope: child_scope.clone(),
            admissions: Mutex::new(Vec::new()),
        });
        let owner =
            CodexInvocationLeaseOwner::new("session-test", test_actor(), test_profile(), None);
        owner.set_context_dag(context_dag)?;
        owner.set_operation_admission_handler(Arc::clone(&admissions) as Arc<_>)?;
        owner.record_scope_context(binding)?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            delegation_event().as_bytes(),
            runtime(),
            101,
        )?;
        let admitted = admissions
            .admissions
            .lock()
            .map_err(|_error| "logical-fork admission lock poisoned")?;
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].session_id(), "session-test");
        assert!(admitted[0].selects_parent_context());
        assert_eq!(admitted[0].parent_context().used_paths(), &[prompt_path]);
        drop(admitted);
        let delivery = serde_json::json!({
            "session_id": "child-thread",
            "turn_id": "child-turn",
        });
        assert_eq!(
            owner.delivery_scope(&delivery, &runtime(), None)?,
            child_scope
        );
        Ok(())
    }

    #[test]
    fn cancellation_closes_the_exact_lease_from_its_native_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = test_owner();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PermissionRequest,
            br#"{"hook_event_name":"PermissionRequest","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"tool-1","cancelled":true}"#,
            runtime(),
            101,
        )?;
        assert!(owner
            .state
            .lock()
            .map_err(|_error| "lock")?
            .leases
            .values()
            .all(|lease| lease.state == InvocationLeaseState::Closed));
        Ok(())
    }

    fn owner_with_scope() -> Result<CodexInvocationLeaseOwner, Box<dyn std::error::Error>> {
        let owner = test_owner();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        Ok(owner)
    }

    fn test_owner() -> CodexInvocationLeaseOwner {
        CodexInvocationLeaseOwner::new("session-test", test_actor(), test_profile(), None)
    }

    fn test_actor() -> erebor_runtime_events::ActorIdentity {
        erebor_runtime_events::ActorIdentity {
            id: String::from("agent-test"),
            kind: erebor_runtime_events::ActorKind::Agent,
        }
    }

    fn test_profile() -> super::CodexInvocationLeaseProfile {
        super::CodexInvocationLeaseProfile::new(String::from("profile-test"))
    }

    fn binding(scope_ref: &str, item_node_stream: &str) -> CodexScopeContextBinding {
        binding_for("thread-1", "turn-1", scope_ref, item_node_stream)
    }

    fn binding_for(
        thread_id: &str,
        turn_id: &str,
        scope_ref: &str,
        item_node_stream: &str,
    ) -> CodexScopeContextBinding {
        CodexScopeContextBinding::new(
            thread_id.to_owned(),
            turn_id.to_owned(),
            scope_ref.to_owned(),
            item_node_stream.to_owned(),
            format!("{scope_ref}-head"),
        )
    }

    fn runtime() -> CodexLeaseRuntimeEvidence {
        CodexLeaseRuntimeEvidence::new(42, 7, String::from("/opt/codex/codex"))
    }

    fn command_event(tool_use_id: &str) -> String {
        command_event_for("thread-1", "turn-1", tool_use_id)
    }

    fn command_event_for(thread_id: &str, turn_id: &str, tool_use_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"{thread_id}\",\"turn_id\":\"{turn_id}\",\"tool_use_id\":\"{tool_use_id}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"echo permitted\"}}}}"
        )
    }

    fn operation_command_event(tool_use_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"thread-1\",\"turn_id\":\"turn-1\",\"tool_use_id\":\"{tool_use_id}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"sleep 1\",\"erebor_operation_key\":\"fixture-q\"}}}}"
        )
    }

    fn permission_event(thread_id: &str, turn_id: &str, tool_use_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"PermissionRequest\",\"session_id\":\"{thread_id}\",\"turn_id\":\"{turn_id}\",\"tool_use_id\":\"{tool_use_id}\"}}"
        )
    }

    fn stop_event(thread_id: &str, turn_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"Stop\",\"session_id\":\"{thread_id}\",\"turn_id\":\"{turn_id}\"}}"
        )
    }

    fn delegation_event() -> String {
        String::from(
            r#"{"hook_event_name":"PreToolUse","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"delegate-1","tool_name":"erebor_delegate","tool_input":{"child_thread_id":"child-thread","child_turn_id":"child-turn","frozen_context_mode":"all","last_turns":0}}"#,
        )
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
