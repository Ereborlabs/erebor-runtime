use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    CodexContextDag, CodexInvocationLeaseOwner, CodexPromptReconciliation, CodexSessionError,
};

pub const MAX_APP_SERVER_FRAME_BYTES: usize = 1024 * 1024;
const MAX_INFLIGHT_REQUESTS: usize = 128;

/// Daemon-owned state for the certified Codex App Server JSONL boundary.
///
/// It is deliberately not a listener: the daemon control service carries only
/// the typed App Server frame request, while the Linux runner remains the sole
/// parent of the workload's stdin/stdout descriptors.
pub struct CodexAppServerService {
    registrations: Mutex<HashMap<String, Arc<Mutex<CodexAppServerLedger>>>>,
}

impl Default for CodexAppServerService {
    fn default() -> Self {
        Self {
            registrations: Mutex::new(HashMap::new()),
        }
    }
}

pub struct CodexAppServerRegistration {
    session_id: String,
    ledger: Arc<Mutex<CodexAppServerLedger>>,
}

pub enum CodexAppServerInput {
    Forward(Vec<u8>),
    Deny(Vec<u8>),
}

impl CodexAppServerService {
    pub fn register(
        &self,
        registration: CodexAppServerRegistration,
    ) -> Result<(), CodexSessionError> {
        let mut registrations =
            self.registrations
                .lock()
                .map_err(|_error| CodexSessionError::InvalidHookEvent {
                    reason: String::from("Codex App Server registration table is unavailable"),
                    location: snafu::Location::default(),
                })?;
        if registrations
            .insert(registration.session_id.clone(), registration.ledger)
            .is_some()
        {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server session is already registered"),
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    pub fn unregister(&self, session_id: &str) -> Result<(), CodexSessionError> {
        self.registrations
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server registration table is unavailable"),
                location: snafu::Location::default(),
            })?
            .remove(session_id);
        Ok(())
    }

    pub fn accept_input(
        &self,
        session_id: &str,
        frame: &[u8],
    ) -> Result<CodexAppServerInput, CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let result = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .accept_input(frame);
        result
    }

    /// Removes a request recorded before an attempted stdin write when that
    /// write fails. A failed forward must not consume the bounded correlation
    /// ledger or later bind an unrelated response.
    pub fn abort_input(&self, session_id: &str, frame: &[u8]) -> Result<(), CodexSessionError> {
        let (_raw, payload) = parse_frame(frame)?;
        let Some(id) = payload.get("id") else {
            return Ok(());
        };
        let key = request_key(id)?;
        let ledger = self.ledger(session_id)?;
        ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .pending
            .remove(&key);
        Ok(())
    }

    pub fn observe_output(&self, session_id: &str, frame: &[u8]) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let result = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .observe_output(frame);
        result
    }

    /// Observes one durable stdout chunk before the daemon returns it through
    /// the App Server attachment. Chunks are reassembled into bounded JSONL
    /// frames and duplicate reads of an already-validated sequence are inert.
    pub fn observe_output_chunk(
        &self,
        session_id: &str,
        sequence: u64,
        chunk: &[u8],
    ) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let result = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .observe_output_chunk(sequence, chunk);
        result
    }

    fn ledger(
        &self,
        session_id: &str,
    ) -> Result<Arc<Mutex<CodexAppServerLedger>>, CodexSessionError> {
        self.registrations
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server registration table is unavailable"),
                location: snafu::Location::default(),
            })?
            .get(session_id)
            .cloned()
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server session is not registered"),
                location: snafu::Location::default(),
            })
    }
}

impl CodexAppServerRegistration {
    pub(super) fn new(
        session_id: impl Into<String>,
        context_dag: Arc<CodexContextDag>,
        reconciliation: Arc<CodexPromptReconciliation>,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        let session_id = session_id.into();
        Self {
            ledger: Arc::new(Mutex::new(CodexAppServerLedger::new(
                &session_id,
                context_dag,
                reconciliation,
                lease_owner,
            ))),
            session_id,
        }
    }
}

struct CodexAppServerLedger {
    session_id: String,
    context_dag: Arc<CodexContextDag>,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    pending: HashMap<String, PendingPrompt>,
    output: Vec<u8>,
    last_output_sequence: Option<u64>,
}

struct PendingPrompt {
    scope_ref: String,
    thread_id: Option<String>,
}

impl CodexAppServerLedger {
    fn new(
        session_id: &str,
        context_dag: Arc<CodexContextDag>,
        reconciliation: Arc<CodexPromptReconciliation>,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        Self {
            session_id: session_id.to_owned(),
            context_dag,
            reconciliation,
            lease_owner,
            pending: HashMap::new(),
            output: Vec::new(),
            last_output_sequence: None,
        }
    }

    fn accept_input(&mut self, frame: &[u8]) -> Result<CodexAppServerInput, CodexSessionError> {
        let (raw, payload) = parse_frame(frame)?;
        let object = payload
            .as_object()
            .ok_or_else(|| protocol_error("App Server JSON-RPC payload is not an object"))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(protocol_error("App Server JSON-RPC version must be 2.0"));
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                protocol_error(
                    "App Server client payload must be a JSON-RPC request or notification",
                )
            })?;
        let id = object.get("id").cloned();
        if method == "$/cancelRequest" {
            if let Some(cancelled_id) = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("id"))
            {
                self.pending.remove(&request_key(cancelled_id)?);
            }
            return Ok(CodexAppServerInput::Forward(frame.to_vec()));
        }
        if sensitive_method(method) {
            let id =
                id.ok_or_else(|| protocol_error("sensitive App Server methods require an id"))?;
            return Ok(CodexAppServerInput::Deny(denial(&id, method)?));
        }
        if let Some(id) = id {
            let key = request_key(&id)?;
            if self.pending.len() >= MAX_INFLIGHT_REQUESTS || self.pending.contains_key(&key) {
                return Err(protocol_error(
                    "App Server request ledger rejected the in-flight id",
                ));
            }
            if matches!(method, "turn/start" | "turn/steer") {
                let params = object.get("params").and_then(Value::as_object);
                let thread_id = params
                    .and_then(|params| params.get("threadId"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let scope_ref = self.context_dag.ensure_prompt_scope(
                    thread_id.as_deref().unwrap_or(&format!("request-{key}")),
                )?;
                let path = format!(
                    "agents/codex/app-server/prompts/{:x}.json",
                    Sha256::digest(raw.as_bytes())
                );
                let hook_count = self
                    .reconciliation
                    .matching_user_prompt_submit(thread_id.as_deref(), None)?
                    .len();
                let subagent_hook_count = self
                    .reconciliation
                    .matching_subagent_hook(Some(&self.session_id), thread_id.as_deref())?
                    .len();
                let record = json!({
                    "schema_version": 1,
                    "state": "pending",
                    "source": "daemon_owned_app_server",
                    "erebor_session_id": self.session_id,
                    "request_id": id,
                    "request": payload,
                    "authenticated_user_prompt_submit_count": hook_count,
                    "authenticated_subagent_hook_count": subagent_hook_count,
                });
                self.context_dag.append_prompt(
                    &scope_ref,
                    &path,
                    serde_json::to_vec_pretty(&record)
                        .map_err(|error| protocol_error(error.to_string()))?,
                    "Record Codex App Server prompt ingress",
                )?;
                self.pending.insert(
                    key,
                    PendingPrompt {
                        scope_ref,
                        thread_id,
                    },
                );
            } else {
                self.pending.insert(
                    key,
                    PendingPrompt {
                        scope_ref: String::new(),
                        thread_id: None,
                    },
                );
            }
        }
        Ok(CodexAppServerInput::Forward(frame.to_vec()))
    }

    fn observe_output(&mut self, frame: &[u8]) -> Result<(), CodexSessionError> {
        let (_raw, payload) = parse_frame(frame)?;
        let object = payload
            .as_object()
            .ok_or_else(|| protocol_error("App Server stdout is not a JSON object"))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(protocol_error(
                "App Server stdout JSON-RPC version must be 2.0",
            ));
        }
        let Some(id) = object.get("id") else {
            return Ok(());
        };
        let Some(prompt) = self.pending.remove(&request_key(id)?) else {
            return Ok(());
        };
        if prompt.scope_ref.is_empty() {
            return Ok(());
        }
        let turn_id = payload.pointer("/result/turnId").and_then(Value::as_str);
        if let (Some(thread_id), Some(turn_id)) = (prompt.thread_id.as_deref(), turn_id) {
            let binding = self.context_dag.bind_prompt(
                thread_id.to_owned(),
                turn_id.to_owned(),
                &prompt.scope_ref,
                format!("agents/codex/app-server/{thread_id}/{turn_id}"),
            )?;
            self.lease_owner.record_scope_context(binding)?;
        }
        Ok(())
    }

    fn observe_output_chunk(
        &mut self,
        sequence: u64,
        chunk: &[u8],
    ) -> Result<(), CodexSessionError> {
        if self
            .last_output_sequence
            .is_some_and(|last_sequence| sequence <= last_sequence)
        {
            return Ok(());
        }
        if self
            .last_output_sequence
            .is_some_and(|last_sequence| sequence > last_sequence.saturating_add(1))
            && !self.output.is_empty()
        {
            return Err(protocol_error(
                "Codex App Server output sequence skipped before a complete JSONL frame",
            ));
        }
        self.output.extend_from_slice(chunk);
        if self.output.len() > MAX_APP_SERVER_FRAME_BYTES {
            return Err(protocol_error(
                "Codex App Server output frame exceeds one MiB",
            ));
        }
        while let Some(end) = self.output.iter().position(|byte| *byte == b'\n') {
            let frame: Vec<u8> = self.output.drain(..=end).collect();
            self.observe_output(&frame)?;
        }
        self.last_output_sequence = Some(sequence);
        Ok(())
    }
}

fn parse_frame(frame: &[u8]) -> Result<(String, Value), CodexSessionError> {
    if frame.is_empty() || frame.len() > MAX_APP_SERVER_FRAME_BYTES || !frame.ends_with(b"\n") {
        return Err(protocol_error(
            "App Server input must be one bounded newline-delimited frame",
        ));
    }
    let raw = std::str::from_utf8(&frame[..frame.len() - 1])
        .map_err(|_error| protocol_error("App Server JSONL is not UTF-8"))?
        .trim_end_matches('\r')
        .to_owned();
    if raw.is_empty() {
        return Err(protocol_error("App Server JSONL frame is empty"));
    }
    let payload = serde_json::from_str(&raw)
        .map_err(|error| protocol_error(format!("App Server JSONL is invalid: {error}")))?;
    Ok((raw, payload))
}

fn request_key(id: &Value) -> Result<String, CodexSessionError> {
    if !matches!(id, Value::String(_) | Value::Number(_)) {
        return Err(protocol_error(
            "App Server request id must be a string or number",
        ));
    }
    serde_json::to_string(id).map_err(|error| protocol_error(error.to_string()))
}

fn denial(id: &Value, method: &str) -> Result<Vec<u8>, CodexSessionError> {
    let mut response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": id,
        "error": {"code": -32003, "message": format!("Erebor denied sensitive App Server method `{method}`")},
    })).map_err(|error| protocol_error(error.to_string()))?;
    response.push(b'\n');
    Ok(response)
}

fn sensitive_method(method: &str) -> bool {
    method == "thread/shellCommand"
        || method.starts_with("thread/inject")
        || method.starts_with("thread/realtime/")
        || method == "command/exec"
        || method.starts_with("command/exec/")
        || method == "process/spawn"
        || method.starts_with("process/")
        || method.starts_with("fs/")
        || method.starts_with("realtime/")
        || method.starts_with("injection/")
}

fn protocol_error(reason: impl Into<String>) -> CodexSessionError {
    CodexSessionError::AppServerTransportProtocol {
        reason: reason.into(),
        location: snafu::Location::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, ContextRepository,
    };
    use erebor_runtime_events::{ActorIdentity, ActorKind};
    use serde_json::Value;

    use super::{
        CodexAppServerInput, CodexAppServerRegistration, CodexAppServerService,
        MAX_APP_SERVER_FRAME_BYTES,
    };
    use crate::agents::codex::{
        CodexContextDag, CodexInvocationLeaseOwner, CodexInvocationLeaseProfile,
        CodexInvocationLeaseTrust, CodexPromptReconciliation,
    };

    #[test]
    fn structured_input_denies_sensitive_methods_without_forwarding()
    -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let input = registered.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"thread/shellCommand\"}\n",
        )?;
        let CodexAppServerInput::Deny(response) = input else {
            return Err("sensitive App Server request was forwarded".into());
        };
        let response: Value = serde_json::from_slice(&response)?;
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_i64),
            Some(-32003)
        );
        Ok(())
    }

    #[test]
    fn structured_output_reassembles_frames_and_binds_the_prompt_turn()
    -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let input = registered.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":\"request-1\",\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\"}}\n",
        )?;
        assert!(matches!(input, CodexAppServerInput::Forward(_)));
        registered.service.observe_output_chunk(
            "session-test",
            1,
            br#"{"jsonrpc":"2.0","id":"request-1","result":{"#,
        )?;
        registered
            .service
            .observe_output_chunk("session-test", 2, b"\"turnId\":\"turn-1\"}}\n")?;
        assert!(
            registered
                .context_dag
                .exact_binding("thread-1", "turn-1")?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn structured_input_rejects_unterminated_or_oversized_frames() {
        let unterminated = super::parse_frame(br#"{"jsonrpc":"2.0"}"#);
        assert!(unterminated.is_err());
        let oversized = vec![b'x'; MAX_APP_SERVER_FRAME_BYTES + 1];
        assert!(super::parse_frame(&oversized).is_err());
    }

    #[test]
    fn structured_output_rejects_non_protocol_stdout_before_it_can_be_exposed()
    -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        assert!(
            registered
                .service
                .observe_output_chunk("session-test", 1, b"not-json\n")
                .is_err()
        );
        assert!(
            registered
                .service
                .observe_output_chunk("session-test", 2, b"{\"jsonrpc\":\"1.0\"}\n")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn failed_forwards_and_json_rpc_cancellation_release_the_correlation_ledger()
    -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n";
        assert!(matches!(
            registered.service.accept_input("session-test", request)?,
            CodexAppServerInput::Forward(_)
        ));
        registered.service.abort_input("session-test", request)?;
        assert!(
            registered
                .service
                .ledger("session-test")?
                .lock()
                .map_err(|_error| "ledger lock is poisoned")?
                .pending
                .is_empty()
        );

        assert!(matches!(
            registered.service.accept_input("session-test", request)?,
            CodexAppServerInput::Forward(_)
        ));
        assert!(matches!(
            registered.service.accept_input(
                "session-test",
                b"{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{\"id\":1}}\n",
            )?,
            CodexAppServerInput::Forward(_)
        ));
        assert!(
            registered
                .service
                .ledger("session-test")?
                .lock()
                .map_err(|_error| "ledger lock is poisoned")?
                .pending
                .is_empty()
        );
        Ok(())
    }

    fn registered_service() -> Result<RegisteredService, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-test", Default::default(), "initialize")?;
        let context_dag = Arc::new(CodexContextDag::new(repository, "session-test"));
        let service = CodexAppServerService::default();
        service.register(CodexAppServerRegistration::new(
            "session-test",
            Arc::clone(&context_dag),
            Arc::new(CodexPromptReconciliation::default()),
            Arc::new(CodexInvocationLeaseOwner::new(
                "session-test",
                ActorIdentity {
                    id: String::from("agent-test"),
                    kind: ActorKind::Agent,
                },
                CodexInvocationLeaseProfile::new(
                    String::from("codex-test"),
                    String::from("/opt/codex/codex"),
                    Vec::new(),
                ),
                CodexInvocationLeaseTrust::default(),
                None,
            )),
        ))?;
        Ok(RegisteredService {
            _temporary: temporary,
            service,
            context_dag,
        })
    }

    struct RegisteredService {
        _temporary: tempfile::TempDir,
        service: CodexAppServerService,
        context_dag: Arc<CodexContextDag>,
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
