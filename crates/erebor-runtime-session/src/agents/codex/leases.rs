use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::JsonlAuditSink;
use erebor_runtime_context::ContextPin;
use erebor_runtime_core::{AuditRecord, DurableAuditSink};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_ipc::v1::{HookEventKind, InterceptionOperation, InterceptionRequest};
use erebor_runtime_policy::Decision;
use erebor_runtime_telemetry::warn;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{CodexContextDag, CodexScopeContextBinding, CodexSessionError};

const LEASE_LIFETIME: Duration = Duration::from_secs(30);
const BARRIER_UNAVAILABLE_RULE: &str =
    "erebor-codex-invocation-lease-hook-exit-ptrace-barrier-unavailable";

/// Kernel-observed identity of the Codex process that launched an authenticated
/// managed hook. It is kept outside the generic ptrace guard protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexLeaseRuntimeEvidence {
    pid: i64,
    process_start_time_ticks: u64,
    executable: String,
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
enum HookExitBarrier {
    Unavailable,
    #[cfg(test)]
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationLeaseState {
    Preparing,
    ResponseIssued,
    Armed,
    EffectBound,
    DispatchComplete,
    Closed,
}

impl InvocationLeaseState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::ResponseIssued => "response-issued",
            Self::Armed => "armed",
            Self::EffectBound => "effect-bound",
            Self::DispatchComplete => "dispatch-complete",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EffectClass {
    Command,
    InProcessMutation,
    Unsupported,
}

impl EffectClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::InProcessMutation => "in-process-mutation",
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
    effect_class: EffectClass,
}

#[derive(Clone, Debug)]
enum InvocationCapability {
    Command { command: String },
    InProcessMutation { targets: Vec<String> },
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
}

#[derive(Clone, Debug)]
struct BoundProcess {
    lease_id: String,
}

#[derive(Default)]
struct LeaseState {
    scopes: HashMap<(String, String), CodexScopeContextBinding>,
    leases: HashMap<String, InvocationLease>,
    identities: HashMap<InvocationIdentity, String>,
    lanes: HashMap<HandoffLane, String>,
    processes: HashMap<i64, BoundProcess>,
    bootstrap_processes: HashSet<i64>,
    next_audit_sequence: u64,
}

/// Session-local owner for Codex invocation capabilities. It receives
/// authenticated hook facts and is queried by the existing generic physical
/// interception router before any terminal or filesystem policy handler.
pub(crate) struct CodexInvocationLeaseOwner {
    session_id: String,
    actor: ActorIdentity,
    profile_id: String,
    profile_executable: String,
    trusted_profile_execs: Vec<String>,
    barrier: HookExitBarrier,
    audit: Option<JsonlAuditSink>,
    context_dag: Mutex<Option<Arc<CodexContextDag>>>,
    state: Mutex<LeaseState>,
}

impl CodexInvocationLeaseOwner {
    pub(crate) fn new(
        session_id: &str,
        actor_id: &str,
        actor_kind: ActorKind,
        profile_id: &str,
        profile_executable: String,
        trusted_profile_execs: Vec<String>,
        audit_path: Option<PathBuf>,
    ) -> Self {
        Self {
            session_id: session_id.to_owned(),
            actor: ActorIdentity {
                id: actor_id.to_owned(),
                kind: actor_kind,
            },
            profile_id: profile_id.to_owned(),
            profile_executable,
            trusted_profile_execs,
            barrier: HookExitBarrier::Unavailable,
            audit: audit_path.map(JsonlAuditSink::new),
            context_dag: Mutex::new(None),
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
        let context_pin = self.record_hook_context(kind, &payload, &runtime, hook_pid)?;
        let mut state = self.lock_state()?;
        self.expire_locked(&mut state)?;
        if Self::cancelled(&payload) {
            return self.close_matching_locked(
                &mut state,
                &payload,
                runtime,
                "hook-cancellation",
                context_pin.as_ref(),
            );
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
        }
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

    /// Returns a fail-closed decision for protected process/file effects, or
    /// `None` for a family this owner does not govern yet.
    pub(crate) fn physical_effect_decision(
        &self,
        request: &InterceptionRequest,
    ) -> Option<erebor_runtime_core::SurfaceInterceptionDecision> {
        match request.operation_family() {
            InterceptionOperation::ProcessExec
            | InterceptionOperation::FileOpen
            | InterceptionOperation::FileRead
            | InterceptionOperation::FileMutation => {}
            InterceptionOperation::SocketConnect | InterceptionOperation::Unspecified => {
                return None;
            }
        }
        match self.physical_effect_decision_inner(request) {
            Ok(decision) => Some(decision),
            Err(error) => Some(erebor_runtime_core::SurfaceInterceptionDecision::deny(
                "erebor-codex-invocation-lease-state-failure",
                format!("Codex invocation lease state is unavailable: {error}"),
            )),
        }
    }

    fn physical_effect_decision_inner(
        &self,
        request: &InterceptionRequest,
    ) -> Result<erebor_runtime_core::SurfaceInterceptionDecision, CodexSessionError> {
        let mut state = self.lock_state()?;
        self.expire_locked(&mut state)?;
        if self.barrier == HookExitBarrier::Unavailable {
            if self.allow_profile_bootstrap_exec(&mut state, request) {
                return self.record_physical_decision_locked(
                    &mut state,
                    None,
                    request,
                    true,
                    "erebor-codex-invocation-lease-profile-bootstrap",
                    "profile-pinned Codex or managed-hook bootstrap exec is not a tool effect",
                );
            }
            return self.record_physical_decision_locked(
                &mut state,
                None,
                request,
                false,
                BARRIER_UNAVAILABLE_RULE,
                "the current Codex profile has no verified hook-exit to ptrace physical-effect barrier",
            );
        }

        match request.operation_family() {
            InterceptionOperation::ProcessExec => {
                self.authorize_process_exec_locked(&mut state, request)
            }
            InterceptionOperation::FileOpen
            | InterceptionOperation::FileRead
            | InterceptionOperation::FileMutation => {
                self.authorize_file_operation_locked(&mut state, request)
            }
            InterceptionOperation::SocketConnect | InterceptionOperation::Unspecified => {
                unreachable!("unsupported interception family returned by physical gate")
            }
        }
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
        let Some(context) =
            self.exact_scope_context(state, &input.codex_session_id, &input.turn_id)?
        else {
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-no-exact-context",
                None,
                payload,
                context_pin,
            );
        };
        let (effect_class, capability) = InvocationCapability::from_input(&input);
        if effect_class == EffectClass::Unsupported {
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-unsupported-tool",
                None,
                payload,
                context_pin,
            );
        }
        let lane = HandoffLane {
            scope_ref: context.scope_ref().to_owned(),
            item_node_stream: context.item_node_stream().to_owned(),
            effect_class,
        };
        if let Some(existing) = state.lanes.get(&lane) {
            let lease = state.leases.get(existing).cloned();
            return self.record_hook_fact_locked(
                state,
                "pre-tool-use-lane-busy",
                lease.as_ref(),
                payload,
                context_pin,
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
            context_pin: context_pin.cloned(),
        };
        self.record_transition_locked(state, &lease, "pre-tool-use-authenticated", context_pin)?;
        lease.state = InvocationLeaseState::ResponseIssued;
        self.record_transition_locked(state, &lease, "hook-response-issued", context_pin)?;
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
        state.processes.clear();
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
        state
            .processes
            .retain(|_pid, binding| binding.lease_id != lease_id);
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
        state
            .processes
            .retain(|_pid, binding| !lease_ids.contains(&binding.lease_id));
        Ok(())
    }

    fn authorize_process_exec_locked(
        &self,
        state: &mut LeaseState,
        request: &InterceptionRequest,
    ) -> Result<erebor_runtime_core::SurfaceInterceptionDecision, CodexSessionError> {
        if let Some(binding) = state.processes.get(&request.pid) {
            let lease = state.leases.get(&binding.lease_id).cloned();
            return self.record_physical_decision_locked(
                state,
                lease.as_ref(),
                request,
                true,
                "erebor-codex-invocation-lease-bound-descendant",
                "process already retains its exact Codex invocation association",
            );
        }
        let candidates = state
            .leases
            .values()
            .filter(|lease| lease.effect_class == EffectClass::Command)
            .filter(|lease| lease.state == InvocationLeaseState::Armed)
            .filter(|lease| lease.runtime_pid == request.ppid)
            .filter(|lease| Self::command_launch_matches(lease, request))
            .map(|lease| lease.id.clone())
            .collect::<Vec<_>>();
        let [lease_id] = candidates.as_slice() else {
            return self.record_physical_decision_locked(
                state,
                None,
                request,
                false,
                "erebor-codex-invocation-lease-no-matching-command-handoff",
                "no exact armed Codex command lease matches this stopped launch",
            );
        };
        let Some(lease) = state.leases.get_mut(lease_id) else {
            return self.record_physical_decision_locked(
                state,
                None,
                request,
                false,
                "erebor-codex-invocation-lease-missing-command-handoff",
                "the matched Codex command lease disappeared before physical binding",
            );
        };
        lease.state = InvocationLeaseState::EffectBound;
        let lease = lease.clone();
        self.record_transition_locked(state, &lease, "process-root-bound", None)?;
        state.processes.insert(
            request.pid,
            BoundProcess {
                lease_id: lease_id.clone(),
            },
        );
        self.record_physical_decision_locked(
            state,
            Some(&lease),
            request,
            true,
            "erebor-codex-invocation-lease-command-bound",
            "stopped command child is bound to its exact Codex invocation lease",
        )
    }

    fn authorize_file_operation_locked(
        &self,
        state: &mut LeaseState,
        request: &InterceptionRequest,
    ) -> Result<erebor_runtime_core::SurfaceInterceptionDecision, CodexSessionError> {
        if let Some(binding) = state.processes.get(&request.pid) {
            let lease = state.leases.get(&binding.lease_id).cloned();
            return self.record_physical_decision_locked(
                state,
                lease.as_ref(),
                request,
                true,
                "erebor-codex-invocation-lease-descendant-file-effect",
                "bound command descendant retains its original invocation association",
            );
        }
        let path = request.file.as_ref().map(|file| file.path.as_str());
        let candidates = state
            .leases
            .values()
            .filter(|lease| lease.effect_class == EffectClass::InProcessMutation)
            .filter(|lease| {
                matches!(
                    lease.state,
                    InvocationLeaseState::Armed | InvocationLeaseState::EffectBound
                )
            })
            .filter(|lease| lease.runtime_pid == request.pid)
            .filter(|lease| Self::mutation_target_matches(lease, path))
            .map(|lease| lease.id.clone())
            .collect::<Vec<_>>();
        let [lease_id] = candidates.as_slice() else {
            return self.record_physical_decision_locked(
                state,
                None,
                request,
                false,
                "erebor-codex-invocation-lease-no-matching-file-capability",
                "no exact armed Codex mutation lease authorizes this file operation",
            );
        };
        let Some(lease) = state.leases.get_mut(lease_id) else {
            return self.record_physical_decision_locked(
                state,
                None,
                request,
                false,
                "erebor-codex-invocation-lease-missing-file-capability",
                "the matched Codex mutation lease disappeared before physical binding",
            );
        };
        let transition = if lease.state == InvocationLeaseState::Armed {
            lease.state = InvocationLeaseState::EffectBound;
            Some(lease.clone())
        } else {
            None
        };
        if let Some(lease) = transition.as_ref() {
            self.record_transition_locked(state, lease, "in-process-file-effect-bound", None)?;
        }
        let lease = state.leases.get(lease_id).cloned();
        self.record_physical_decision_locked(
            state,
            lease.as_ref(),
            request,
            true,
            "erebor-codex-invocation-lease-mutation-capability-bound",
            "Codex process file effect matches its exact mutation capability",
        )
    }

    fn command_launch_matches(lease: &InvocationLease, request: &InterceptionRequest) -> bool {
        let InvocationCapability::Command { command } = &lease.capability else {
            return false;
        };
        request
            .process_exec
            .as_ref()
            .map_or(request.argv.as_slice(), |process| process.argv.as_slice())
            .last()
            .is_some_and(|argument| argument == command)
    }

    fn allow_profile_bootstrap_exec(
        &self,
        state: &mut LeaseState,
        request: &InterceptionRequest,
    ) -> bool {
        if request.operation_family() != InterceptionOperation::ProcessExec {
            return false;
        }
        let executable = request
            .process_exec
            .as_ref()
            .map_or(request.executable.as_str(), |process| {
                process.executable.as_str()
            });
        if executable == self.profile_executable && state.bootstrap_processes.is_empty() {
            state.bootstrap_processes.insert(request.pid);
            return true;
        }
        if executable != self.profile_executable
            && self
                .trusted_profile_execs
                .iter()
                .any(|trusted| trusted == executable)
            && state.bootstrap_processes.contains(&request.ppid)
        {
            state.bootstrap_processes.insert(request.pid);
            return true;
        }
        false
    }

    fn mutation_target_matches(lease: &InvocationLease, path: Option<&str>) -> bool {
        let (InvocationCapability::InProcessMutation { targets }, Some(path)) =
            (&lease.capability, path)
        else {
            return false;
        };
        targets.iter().any(|target| target == path)
    }

    fn record_physical_decision_locked(
        &self,
        state: &mut LeaseState,
        lease: Option<&InvocationLease>,
        request: &InterceptionRequest,
        allowed: bool,
        rule_id: &str,
        reason: &str,
    ) -> Result<erebor_runtime_core::SurfaceInterceptionDecision, CodexSessionError> {
        let file = request.file.as_ref().map(|file| {
            serde_json::json!({
                "kind": file.kind,
                "path": file.path,
                "resolved_identity": file.resolved_identity.as_ref().map(|identity| {
                    serde_json::json!({"device": identity.device, "inode": identity.inode})
                }),
            })
        });
        self.record_audit_locked(
            state,
            "physical-effect",
            lease,
            serde_json::json!({
                "allowed": allowed,
                "rule_id": rule_id,
                "reason": reason,
                "operation": request.operation_family().name(),
                "pid": request.pid,
                "ppid": request.ppid,
                "executable": request.executable,
                "argv": request.argv,
                "file": file,
            }),
            !allowed,
            lease.and_then(|lease| lease.context_pin.as_ref()),
        )?;
        Ok(if allowed {
            erebor_runtime_core::SurfaceInterceptionDecision::allow(rule_id, reason)
        } else {
            erebor_runtime_core::SurfaceInterceptionDecision::deny(rule_id, reason)
        })
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
        state.processes.retain(|_pid, binding| {
            state
                .leases
                .get(&binding.lease_id)
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

    #[cfg(test)]
    fn with_verified_barrier() -> Self {
        let mut owner = Self::new(
            "session-test",
            "agent-test",
            ActorKind::Agent,
            "profile-test",
            String::from("/opt/codex/codex"),
            vec![String::from(
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            )],
            None,
        );
        owner.barrier = HookExitBarrier::Verified;
        owner
    }

    #[cfg(test)]
    fn arm_after_verified_hook_exit(&self, lease_id: &str) -> Result<(), CodexSessionError> {
        let mut state = self.lock_state()?;
        let Some(lease) = state.leases.get_mut(lease_id) else {
            return Ok(());
        };
        let transition = if lease.state == InvocationLeaseState::ResponseIssued {
            lease.state = InvocationLeaseState::Armed;
            Some(lease.clone())
        } else {
            None
        };
        if let Some(lease) = transition.as_ref() {
            self.record_transition_locked(&mut state, lease, "verified-hook-exit-barrier", None)?;
        }
        Ok(())
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
        if matches!(tool.as_str(), "bash" | "shell" | "command") {
            if let Some(command) = input
                .tool_input
                .get("command")
                .and_then(Value::as_str)
                .filter(|command| !command.is_empty())
            {
                return (
                    EffectClass::Command,
                    Self::Command {
                        command: command.to_owned(),
                    },
                );
            }
        }
        if matches!(tool.as_str(), "apply_patch" | "applypatch") {
            let mut targets = Self::patch_targets(&input.tool_input);
            targets.sort();
            targets.dedup();
            if !targets.is_empty() {
                return (
                    EffectClass::InProcessMutation,
                    Self::InProcessMutation { targets },
                );
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

trait InterceptionOperationName {
    fn name(self) -> &'static str;
}

impl InterceptionOperationName for InterceptionOperation {
    fn name(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileOpen => "file_open",
            Self::FileRead => "file_read",
            Self::FileMutation => "file_mutation",
            Self::SocketConnect => "socket_connect",
            Self::Unspecified => "unspecified",
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
    use erebor_runtime_core::SessionInterceptionDecision;
    use erebor_runtime_ipc::v1::{
        FileOperation, FileOperationKind, InterceptionOperation, InterceptionRequest,
        ProcessExecOperation,
    };

    use super::{
        CodexContextDag, CodexInvocationLeaseOwner, CodexLeaseRuntimeEvidence,
        CodexScopeContextBinding, InvocationLeaseState,
    };

    #[test]
    fn response_issued_lease_cannot_authorize_a_physical_effect_without_the_barrier(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = owner_with_scope()?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;

        let decision = owner
            .physical_effect_decision(&process_request(201, 42, "echo permitted"))
            .ok_or("missing decision")?;
        let (kind, rule_id, _reason, _mediation) = decision.into_parts();
        assert_eq!(kind, SessionInterceptionDecision::Deny);
        assert_eq!(
            rule_id,
            "erebor-codex-invocation-lease-hook-exit-ptrace-barrier-unavailable"
        );
        Ok(())
    }

    #[test]
    fn verified_barrier_binds_command_once_and_retains_descendant_after_post_tool_use(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = CodexInvocationLeaseOwner::with_verified_barrier();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        let lease_id = owner
            .state
            .lock()
            .map_err(|_error| "lock")?
            .leases
            .keys()
            .next()
            .cloned()
            .ok_or("lease missing")?;
        owner.arm_after_verified_hook_exit(&lease_id)?;

        let decision = owner
            .physical_effect_decision(&process_request(201, 42, "echo permitted"))
            .ok_or("missing command decision")?;
        assert_eq!(decision.into_parts().0, SessionInterceptionDecision::Allow);

        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PostToolUse,
            post_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        let state = owner.state.lock().map_err(|_error| "lock")?;
        assert_eq!(
            state.leases.get(&lease_id).map(|lease| lease.state),
            Some(InvocationLeaseState::DispatchComplete)
        );
        drop(state);

        let descendant = owner
            .physical_effect_decision(&process_request(201, 1, "python child.py"))
            .ok_or("missing descendant decision")?;
        assert_eq!(
            descendant.into_parts().0,
            SessionInterceptionDecision::Allow
        );
        let new_root = owner
            .physical_effect_decision(&process_request(202, 42, "echo permitted"))
            .ok_or("missing new root decision")?;
        assert_eq!(new_root.into_parts().0, SessionInterceptionDecision::Deny);
        Ok(())
    }

    #[test]
    fn mutation_capability_is_exact_and_post_tool_use_closes_new_in_process_effects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = CodexInvocationLeaseOwner::with_verified_barrier();
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            patch_event("patch-1").as_bytes(),
            runtime(),
            101,
        )?;
        let lease_id = owner
            .state
            .lock()
            .map_err(|_error| "lock")?
            .leases
            .keys()
            .next()
            .cloned()
            .ok_or("lease missing")?;
        owner.arm_after_verified_hook_exit(&lease_id)?;

        let allowed = owner
            .physical_effect_decision(&file_request(42, "workspace/allowed.txt"))
            .ok_or("missing allowed decision")?;
        assert_eq!(allowed.into_parts().0, SessionInterceptionDecision::Allow);
        let denied = owner
            .physical_effect_decision(&file_request(42, "workspace/other.txt"))
            .ok_or("missing denied decision")?;
        assert_eq!(denied.into_parts().0, SessionInterceptionDecision::Deny);

        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PostToolUse,
            patch_event("patch-1").as_bytes(),
            runtime(),
            101,
        )?;
        let after_post = owner
            .physical_effect_decision(&file_request(42, "workspace/allowed.txt"))
            .ok_or("missing post decision")?;
        assert_eq!(after_post.into_parts().0, SessionInterceptionDecision::Deny);
        Ok(())
    }

    #[test]
    fn lanes_are_exact_to_scope_and_do_not_select_by_command_text(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = CodexInvocationLeaseOwner::with_verified_barrier();
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
        assert_eq!(state.leases.len(), 2);
        assert!(state
            .leases
            .values()
            .all(|lease| lease.key.scope_ref == "scope-a" || lease.key.scope_ref == "scope-b"));
        Ok(())
    }

    #[test]
    fn stop_closes_only_leases_in_its_exact_native_turn() -> Result<(), Box<dyn std::error::Error>>
    {
        let owner = CodexInvocationLeaseOwner::with_verified_barrier();
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
            "agent-test",
            erebor_runtime_events::ActorKind::Agent,
            "profile-test",
            String::from("/opt/codex/codex"),
            vec![String::from(
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            )],
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
    fn durable_audit_keeps_hook_and_physical_denial_facts_separate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let audit_path = root.path().join("audit.jsonl");
        let owner = CodexInvocationLeaseOwner::new(
            "session-test",
            "agent-test",
            erebor_runtime_events::ActorKind::Agent,
            "profile-test",
            String::from("/opt/codex/codex"),
            vec![String::from(
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            )],
            Some(audit_path.clone()),
        );
        owner.record_scope_context(binding("refs/scopes/session-test/scope/a", "item-a"))?;
        owner.record_authenticated_hook(
            erebor_runtime_ipc::v1::HookEventKind::PreToolUse,
            command_event("tool-1").as_bytes(),
            runtime(),
            101,
        )?;
        let _decision = owner.physical_effect_decision(&process_request(201, 42, "echo permitted"));

        let records = erebor_runtime_audit::read_audit_records(audit_path)?;
        assert!(records.iter().any(|record| {
            record
                .event
                .payload
                .pointer("/fact")
                .and_then(serde_json::Value::as_str)
                == Some("pre-tool-use-authenticated")
                && record
                    .event
                    .payload
                    .pointer("/lease/key/scope_ref")
                    .and_then(serde_json::Value::as_str)
                    == Some("refs/scopes/session-test/scope/a")
        }));
        assert!(records.iter().any(|record| {
            record
                .event
                .payload
                .pointer("/fact")
                .and_then(serde_json::Value::as_str)
                == Some("physical-effect")
                && record
                    .event
                    .payload
                    .pointer("/detail/rule_id")
                    .and_then(serde_json::Value::as_str)
                    == Some("erebor-codex-invocation-lease-hook-exit-ptrace-barrier-unavailable")
        }));
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
        context_dag.append_prompt(
            &scope_ref,
            "agents/codex/app-server/prompts/prompt.json",
            br#"{"source":"test"}"#.to_vec(),
            "Record test prompt",
        )?;
        context_dag.bind_prompt(
            String::from("thread-1"),
            String::from("turn-1"),
            &scope_ref,
            String::from("agents/codex/app-server/prompts/prompt.json#item-1"),
        )?;
        let owner = CodexInvocationLeaseOwner::new(
            "session-test",
            "agent-test",
            erebor_runtime_events::ActorKind::Agent,
            "profile-test",
            String::from("/opt/codex/codex"),
            vec![String::from(
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            )],
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
    fn cancellation_closes_the_exact_lease_from_its_native_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = CodexInvocationLeaseOwner::with_verified_barrier();
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
        let owner = CodexInvocationLeaseOwner::new(
            "session-test",
            "agent-test",
            erebor_runtime_events::ActorKind::Agent,
            "profile-test",
            String::from("/opt/codex/codex"),
            vec![String::from(
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            )],
            None,
        );
        owner.record_scope_context(binding("scope-a", "item-a"))?;
        Ok(owner)
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

    fn patch_event(tool_use_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"thread-1\",\"turn_id\":\"turn-1\",\"tool_use_id\":\"{tool_use_id}\",\"tool_name\":\"apply_patch\",\"tool_input\":{{\"patch\":\"*** Update File: workspace/allowed.txt\\n@@\"}}}}"
        )
    }

    fn post_event(tool_use_id: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"thread-1\",\"turn_id\":\"turn-1\",\"tool_use_id\":\"{tool_use_id}\",\"tool_response\":{{\"status\":\"ok\"}}}}"
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

    fn process_request(pid: i64, ppid: i64, command: &str) -> InterceptionRequest {
        InterceptionRequest {
            pid,
            ppid,
            operation: InterceptionOperation::ProcessExec as i32,
            executable: String::from("/bin/sh"),
            argv: vec![
                String::from("/bin/sh"),
                String::from("-c"),
                command.to_owned(),
            ],
            process_exec: Some(ProcessExecOperation {
                executable: String::from("/bin/sh"),
                argv: vec![
                    String::from("/bin/sh"),
                    String::from("-c"),
                    command.to_owned(),
                ],
                ..ProcessExecOperation::default()
            }),
            ..InterceptionRequest::default()
        }
    }

    fn file_request(pid: i64, path: &str) -> InterceptionRequest {
        InterceptionRequest {
            pid,
            ppid: 1,
            operation: InterceptionOperation::FileMutation as i32,
            file: Some(FileOperation {
                kind: FileOperationKind::Mutation as i32,
                path: path.to_owned(),
                ..FileOperation::default()
            }),
            ..InterceptionRequest::default()
        }
    }
}
