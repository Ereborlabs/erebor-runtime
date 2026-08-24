use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use serde_json::{json, Value};

use crate::DurableStreamStore;

use super::{
    CodexContextDag, CodexInvocationLeaseOwner, CodexPromptReconciliation, CodexSessionError,
};

pub const MAX_APP_SERVER_FRAME_BYTES: usize = 1024 * 1024;
pub const CODEX_APP_SERVER_OUTPUT_VALIDATION_EVENT: &str = "codex_app_server_output_validation_v1";
const MAX_INFLIGHT_REQUESTS: usize = 128;
const MAX_CANCELLED_REQUESTS: usize = MAX_INFLIGHT_REQUESTS;
const MAX_CACHED_OUTPUT_BYTES: usize = MAX_APP_SERVER_FRAME_BYTES * 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAppServerOutputChunk {
    sequence: u64,
    timestamp_unix_ms: u64,
    data: Vec<u8>,
}

impl CodexAppServerOutputChunk {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp_unix_ms(&self) -> u64 {
        self.timestamp_unix_ms
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Default)]
pub struct CodexAppServerOutputValidator {
    buffer: Vec<u8>,
    last_sequence: Option<u64>,
    failure: Option<String>,
}

impl CodexAppServerOutputValidator {
    pub fn observe_chunk(
        &mut self,
        sequence: u64,
        chunk: &[u8],
    ) -> Result<Vec<Vec<u8>>, CodexSessionError> {
        if let Some(reason) = &self.failure {
            return Err(protocol_error(reason.clone()));
        }
        if self
            .last_sequence
            .is_some_and(|last_sequence| sequence <= last_sequence)
        {
            return Ok(Vec::new());
        }
        let expected_sequence = self
            .last_sequence
            .map_or(1, |last_sequence| last_sequence.saturating_add(1));
        if sequence != expected_sequence {
            return self.fail("Codex App Server output sequence is not contiguous");
        }
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let frame: Vec<u8> = self.buffer.drain(..=end).collect();
            if let Err(error) = validate_output_frame(&frame) {
                self.failure = Some(error.to_string());
                return Err(error);
            }
            frames.push(frame);
        }
        if self.buffer.len() > MAX_APP_SERVER_FRAME_BYTES {
            return self.fail("Codex App Server output frame exceeds one MiB");
        }
        self.last_sequence = Some(sequence);
        Ok(frames)
    }

    pub fn finish(&mut self) -> Result<(), CodexSessionError> {
        if let Some(reason) = &self.failure {
            return Err(protocol_error(reason.clone()));
        }
        if self.buffer.is_empty() {
            Ok(())
        } else {
            self.fail("Codex App Server stdout ended before its final JSONL frame")
        }
    }

    pub fn observed_sequence(&self) -> Result<u64, CodexSessionError> {
        if let Some(reason) = &self.failure {
            Err(protocol_error(reason.clone()))
        } else {
            Ok(self.last_sequence.unwrap_or(0))
        }
    }

    fn fail<T>(&mut self, reason: impl Into<String>) -> Result<T, CodexSessionError> {
        let reason = reason.into();
        self.failure = Some(reason.clone());
        Err(protocol_error(reason))
    }
}

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

    pub fn is_registered(&self, session_id: &str) -> Result<bool, CodexSessionError> {
        Ok(self
            .registrations
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server registration table is unavailable"),
                location: snafu::Location::default(),
            })?
            .contains_key(session_id))
    }

    pub fn accept_input(
        &self,
        session_id: &str,
        frame: &[u8],
    ) -> Result<CodexAppServerInput, CodexSessionError> {
        self.transact_input(session_id, frame, |_frame| Ok(()))
    }

    pub fn transact_input(
        &self,
        session_id: &str,
        frame: &[u8],
        forward: impl FnOnce(&[u8]) -> Result<(), CodexSessionError>,
    ) -> Result<CodexAppServerInput, CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let mut ledger = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?;
        match ledger.prepare_input(frame)? {
            PreparedAppServerInput::Deny(response) => Ok(CodexAppServerInput::Deny(response)),
            PreparedAppServerInput::Forward { frame, mutation } => {
                if matches!(mutation, InputMutation::Pending { .. }) {
                    if let Err(error) = ledger.commit_input(mutation) {
                        ledger.output.failure = Some(error.to_string());
                        return Err(error);
                    }
                    if let Err(error) = forward(&frame) {
                        ledger.output.failure = Some(error.to_string());
                        return Err(error);
                    }
                } else {
                    if let Err(error) = forward(&frame) {
                        ledger.output.failure = Some(error.to_string());
                        return Err(error);
                    }
                    if let Err(error) = ledger.commit_input(mutation) {
                        ledger.output.failure = Some(error.to_string());
                        return Err(error);
                    }
                }
                Ok(CodexAppServerInput::Forward(frame))
            }
        }
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

    /// Observes one durable stdout chunk. Chunks are reassembled into bounded
    /// JSONL frames, and duplicate observations are inert.
    pub fn observe_output_chunk(
        &self,
        session_id: &str,
        sequence: u64,
        chunk: &[u8],
    ) -> Result<(), CodexSessionError> {
        self.observe_durable_output_chunk(session_id, sequence, 0, chunk)
    }

    pub fn observe_durable_output_chunk(
        &self,
        session_id: &str,
        sequence: u64,
        timestamp_unix_ms: u64,
        chunk: &[u8],
    ) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let result = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .observe_output_chunk(sequence, timestamp_unix_ms, chunk);
        result
    }

    pub fn observed_output_sequence(&self, session_id: &str) -> Result<u64, CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let ledger = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?;
        ledger.output.observed_sequence()
    }

    pub fn projected_output_after(
        &self,
        session_id: &str,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<Option<Vec<CodexAppServerOutputChunk>>, CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let ledger = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?;
        ledger.output.observed_sequence()?;
        Ok(ledger.projected_output_after(after_sequence, maximum_records))
    }

    pub fn durable_output_cursor(
        &self,
        session_id: &str,
    ) -> Result<Option<u64>, CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let cursor = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .durable_output_cursor;
        Ok(cursor)
    }

    pub fn record_durable_output_cursor(
        &self,
        session_id: &str,
        stdout_cursor: u64,
    ) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let mut ledger = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?;
        if ledger.output.observed_sequence()? != stdout_cursor {
            return Err(protocol_error(
                "Codex App Server durable output cursor does not match validated stdout",
            ));
        }
        ledger.durable_output_cursor = Some(stdout_cursor);
        Ok(())
    }

    pub fn finish_output(&self, session_id: &str) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let result = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?
            .finish_output();
        result
    }

    pub fn reject_output(
        &self,
        session_id: &str,
        reason: impl Into<String>,
    ) -> Result<(), CodexSessionError> {
        let ledger = self.ledger(session_id)?;
        let mut ledger = ledger
            .lock()
            .map_err(|_error| CodexSessionError::InvalidHookEvent {
                reason: String::from("Codex App Server ledger is unavailable"),
                location: snafu::Location::default(),
            })?;
        ledger.output.failure = Some(reason.into());
        Ok(())
    }

    pub fn validate_durable_output(
        &self,
        session_id: &str,
        stdout: &DurableStreamStore,
    ) -> Result<u64, CodexSessionError> {
        let page = stdout
            .read_after(0, usize::MAX)
            .map_err(|error| protocol_error(error.to_string()))?;
        if page.truncated_before_cursor() {
            return Err(protocol_error(
                "Codex App Server stdout rotated before completion validation",
            ));
        }
        for record in page.records() {
            self.observe_durable_output_chunk(
                session_id,
                record.sequence(),
                record.timestamp_unix_ms(),
                record.data(),
            )?;
        }
        self.finish_output(session_id)?;
        Ok(page.durable_cursor())
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
    used_request_ids: HashSet<String>,
    cancelled: VecDeque<String>,
    output: CodexAppServerOutputValidator,
    projected_output: VecDeque<CodexAppServerOutputChunk>,
    projected_output_bytes: usize,
    evicted_output_through: u64,
    durable_output_cursor: Option<u64>,
}

struct PendingPrompt {
    scope_ref: String,
    thread_id: Option<String>,
    prompt_path: Option<String>,
}

enum PreparedAppServerInput {
    Forward {
        frame: Vec<u8>,
        mutation: InputMutation,
    },
    Deny(Vec<u8>),
}

enum InputMutation {
    None,
    Cancel(String),
    Pending {
        key: String,
        request_id: Value,
        request: Value,
        thread_id: Option<String>,
        records_prompt: bool,
    },
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
            used_request_ids: HashSet::new(),
            cancelled: VecDeque::new(),
            output: CodexAppServerOutputValidator::default(),
            projected_output: VecDeque::new(),
            projected_output_bytes: 0,
            evicted_output_through: 0,
            durable_output_cursor: None,
        }
    }

    fn prepare_input(&self, frame: &[u8]) -> Result<PreparedAppServerInput, CodexSessionError> {
        if let Some(reason) = &self.output.failure {
            return Err(protocol_error(format!(
                "Codex App Server output validation failed: {reason}"
            )));
        }
        let (_raw, payload) = parse_frame(frame)?;
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
        if object.contains_key("result") || object.contains_key("error") {
            return Err(protocol_error(
                "App Server client request has an invalid JSON-RPC shape",
            ));
        }
        let id = object.get("id").cloned();
        let records_prompt = matches!(method, "turn/start" | "turn/steer");
        if records_prompt && id.is_none() {
            return Err(protocol_error(
                "App Server prompt requests require a correlation id",
            ));
        }
        if method == "$/cancelRequest" {
            let cancelled_id = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("id"))
                .ok_or_else(|| protocol_error("App Server cancellation has no request id"))?;
            let mutation = InputMutation::Cancel(request_key(cancelled_id)?);
            return Ok(PreparedAppServerInput::Forward {
                frame: frame.to_vec(),
                mutation,
            });
        }
        if sensitive_method(method)
            || peer_thread_method(method)
            || object.get("params").is_some_and(contains_peer_thread_claim)
        {
            let id = id.ok_or_else(|| protocol_error("denied App Server methods require an id"))?;
            return Ok(PreparedAppServerInput::Deny(denial(&id, method)?));
        }
        let mutation = if let Some(id) = id {
            let key = request_key(&id)?;
            if self.pending.len() >= MAX_INFLIGHT_REQUESTS || self.used_request_ids.contains(&key) {
                return Err(protocol_error(
                    "App Server request ledger rejected the in-flight id",
                ));
            }
            let thread_id = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("threadId"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            InputMutation::Pending {
                key,
                request_id: id,
                request: payload,
                thread_id,
                records_prompt,
            }
        } else {
            InputMutation::None
        };
        Ok(PreparedAppServerInput::Forward {
            frame: frame.to_vec(),
            mutation,
        })
    }

    fn commit_input(&mut self, mutation: InputMutation) -> Result<(), CodexSessionError> {
        match mutation {
            InputMutation::None => Ok(()),
            InputMutation::Cancel(key) => {
                if self.pending.remove(&key).is_some() {
                    self.cancelled.push_back(key);
                    while self.cancelled.len() > MAX_CANCELLED_REQUESTS {
                        if let Some(evicted) = self.cancelled.pop_front() {
                            self.used_request_ids.remove(&evicted);
                        }
                    }
                }
                Ok(())
            }
            InputMutation::Pending {
                key,
                request_id,
                request,
                thread_id,
                records_prompt,
            } => {
                let (scope_ref, prompt_path) = if records_prompt {
                    let scope_ref = self.context_dag.ensure_prompt_scope(
                        thread_id.as_deref().unwrap_or(&format!("request-{key}")),
                    )?;
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
                        "request_id": request_id,
                        "request": request,
                        "authenticated_user_prompt_submit_count": hook_count,
                        "authenticated_subagent_hook_count": subagent_hook_count,
                    });
                    let prompt_path = self.context_dag.append_prompt(
                        &scope_ref,
                        serde_json::to_vec_pretty(&record)
                            .map_err(|error| protocol_error(error.to_string()))?,
                        "Record Codex App Server prompt ingress",
                    )?;
                    (scope_ref, Some(prompt_path))
                } else {
                    (String::new(), None)
                };
                self.pending.insert(
                    key.clone(),
                    PendingPrompt {
                        scope_ref,
                        thread_id,
                        prompt_path,
                    },
                );
                self.used_request_ids.insert(key);
                Ok(())
            }
        }
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
        if let Some(method) = object.get("method") {
            if !method.is_string() || object.contains_key("result") || object.contains_key("error")
            {
                return Err(protocol_error(
                    "App Server notification has an invalid JSON-RPC shape",
                ));
            }
            if object.get("id").is_some() {
                return Err(protocol_error(
                    "App Server server-initiated requests are unsupported",
                ));
            }
            return Ok(());
        };
        let id = object
            .get("id")
            .ok_or_else(|| protocol_error("App Server response has no request id"))?;
        if object.contains_key("result") == object.contains_key("error") {
            return Err(protocol_error(
                "App Server response must contain exactly one result or error",
            ));
        }
        let key = request_key(id)?;
        let Some(prompt) = self.pending.remove(&key) else {
            if let Some(index) = self
                .cancelled
                .iter()
                .position(|cancelled| cancelled == &key)
            {
                self.cancelled.remove(index);
                self.used_request_ids.remove(&key);
                return Ok(());
            }
            return Err(protocol_error(
                "App Server response does not match an in-flight request",
            ));
        };
        self.used_request_ids.remove(&key);
        if object.contains_key("error") {
            return Ok(());
        }
        if prompt.scope_ref.is_empty() {
            return Ok(());
        }
        let thread_id = prompt
            .thread_id
            .as_deref()
            .ok_or_else(|| protocol_error("App Server prompt request has no thread id"))?;
        let turn_id = payload
            .pointer("/result/turnId")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error("App Server prompt response has no turn id"))?;
        let prompt_path = prompt
            .prompt_path
            .as_deref()
            .ok_or_else(|| protocol_error("App Server prompt has no durable context path"))?;
        let binding = self.context_dag.bind_prompt(
            thread_id.to_owned(),
            turn_id.to_owned(),
            &prompt.scope_ref,
            prompt_path.to_owned(),
        )?;
        self.lease_owner.record_scope_context(binding)?;
        Ok(())
    }

    fn observe_output_chunk(
        &mut self,
        sequence: u64,
        timestamp_unix_ms: u64,
        chunk: &[u8],
    ) -> Result<(), CodexSessionError> {
        let frames = self.output.observe_chunk(sequence, chunk)?;
        for frame in &frames {
            if let Err(error) = self.observe_output(frame) {
                self.output.failure = Some(error.to_string());
                return Err(error);
            }
        }
        if !frames.is_empty() {
            self.cache_projected_output(CodexAppServerOutputChunk {
                sequence,
                timestamp_unix_ms,
                data: frames.concat(),
            });
        }
        Ok(())
    }

    fn cache_projected_output(&mut self, output: CodexAppServerOutputChunk) {
        while self
            .projected_output_bytes
            .saturating_add(output.data.len())
            > MAX_CACHED_OUTPUT_BYTES
        {
            let Some(evicted) = self.projected_output.pop_front() else {
                self.evicted_output_through = self.evicted_output_through.max(output.sequence);
                return;
            };
            self.projected_output_bytes = self
                .projected_output_bytes
                .saturating_sub(evicted.data.len());
            self.evicted_output_through = self.evicted_output_through.max(evicted.sequence);
        }
        self.projected_output_bytes = self
            .projected_output_bytes
            .saturating_add(output.data.len());
        self.projected_output.push_back(output);
    }

    fn projected_output_after(
        &self,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Option<Vec<CodexAppServerOutputChunk>> {
        if after_sequence < self.evicted_output_through {
            return None;
        }
        Some(
            self.projected_output
                .iter()
                .filter(|output| output.sequence > after_sequence)
                .take(maximum_records.max(1))
                .cloned()
                .collect(),
        )
    }

    fn finish_output(&mut self) -> Result<(), CodexSessionError> {
        self.output.finish()?;
        if self.pending.is_empty() {
            Ok(())
        } else {
            self.output
                .fail("Codex App Server stopped with unresolved request ids")
        }
    }
}

fn validate_output_frame(frame: &[u8]) -> Result<(), CodexSessionError> {
    let (_raw, payload) = parse_frame(frame)?;
    let object = payload
        .as_object()
        .ok_or_else(|| protocol_error("App Server stdout is not a JSON object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(protocol_error(
            "App Server stdout JSON-RPC version must be 2.0",
        ));
    }
    Ok(())
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

fn peer_thread_method(method: &str) -> bool {
    method.starts_with("thread/") && method != "thread/start"
}

fn contains_peer_thread_claim(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "parentThreadId"
                        | "parent_thread_id"
                        | "forkedFromId"
                        | "forked_from_id"
                        | "ancestorThreadId"
                        | "ancestor_thread_id"
                )
            }) || object.values().any(contains_peer_thread_claim)
        }
        Value::Array(values) => values.iter().any(contains_peer_thread_claim),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
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
        CodexAppServerInput, CodexAppServerOutputValidator, CodexAppServerRegistration,
        CodexAppServerService, MAX_APP_SERVER_FRAME_BYTES,
    };
    use crate::agents::codex::{
        CodexContextDag, CodexInvocationLeaseOwner, CodexInvocationLeaseProfile,
        CodexPromptReconciliation,
    };
    use crate::{DurableStreamStore, StreamKind};

    #[test]
    fn structured_input_denies_sensitive_methods_without_forwarding(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
    fn peer_thread_operations_and_claims_are_denied_without_forwarding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        for method in [
            "thread/fork",
            "thread/resume",
            "thread/rollback",
            "thread/archive",
            "thread/list",
            "thread/read",
        ] {
            let mut frame =
                format!(r#"{{"jsonrpc":"2.0","id":"{method}","method":"{method}","params":{{}}}}"#);
            frame.push('\n');
            assert!(matches!(
                registered
                    .service
                    .accept_input("session-test", frame.as_bytes())?,
                CodexAppServerInput::Deny(_)
            ));
        }
        for claim in ["parentThreadId", "forkedFromId", "ancestorThreadId"] {
            let mut frame = format!(
                r#"{{"jsonrpc":"2.0","id":"{claim}","method":"turn/start","params":{{"threadId":"thread-1","{claim}":"peer-thread"}}}}"#
            );
            frame.push('\n');
            assert!(matches!(
                registered
                    .service
                    .accept_input("session-test", frame.as_bytes())?,
                CodexAppServerInput::Deny(_)
            ));
        }
        assert!(registered
            .service
            .ledger("session-test")?
            .lock()
            .map_err(|_error| "ledger lock is poisoned")?
            .pending
            .is_empty());
        assert!(registered
            .context_dag
            .exact_binding("thread-1", "peer-thread")?
            .is_none());
        Ok(())
    }

    #[test]
    fn failed_forward_retains_the_attributed_request() -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let request =
            b"{\"jsonrpc\":\"2.0\",\"id\":\"thread-start\",\"method\":\"thread/start\",\"params\":{}}\n";
        assert!(registered
            .service
            .transact_input("session-test", request, |_frame| {
                Err(super::protocol_error("injected stdin write failure"))
            })
            .is_err());
        assert!(registered
            .service
            .ledger("session-test")?
            .lock()
            .map_err(|_error| "ledger lock is poisoned")?
            .pending
            .contains_key("\"thread-start\""));
        Ok(())
    }

    #[test]
    fn structured_output_reassembles_frames_and_binds_the_prompt_turn(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        assert_eq!(
            registered
                .service
                .observed_output_sequence("session-test")?,
            1
        );
        registered
            .service
            .observe_output_chunk("session-test", 2, b"\"turnId\":\"turn-1\"}}\n")?;
        assert_eq!(
            registered
                .service
                .observed_output_sequence("session-test")?,
            2
        );
        assert!(registered
            .context_dag
            .exact_binding("thread-1", "turn-1")?
            .is_some());
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
    fn structured_input_rejects_mixed_requests_and_unowned_cancellation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for frame in [
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\",\"result\":{}}\n".as_slice(),
            b"{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{}}\n".as_slice(),
        ] {
            let registered = registered_service()?;
            assert!(registered
                .service
                .accept_input("session-test", frame)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn structured_output_rejects_non_protocol_stdout_before_it_can_be_exposed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        assert!(registered
            .service
            .observe_output_chunk("session-test", 1, b"not-json\n")
            .is_err());
        assert!(registered
            .service
            .observe_output_chunk("session-test", 2, b"{\"jsonrpc\":\"1.0\"}\n")
            .is_err());
        Ok(())
    }

    #[test]
    fn structured_output_requires_one_contiguous_durable_prefix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let high_first = registered_service()?;
        assert!(high_first
            .service
            .observe_output_chunk(
                "session-test",
                2,
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n",
            )
            .is_err());

        let gap = registered_service()?;
        gap.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n",
        )?;
        assert!(gap
            .service
            .observe_output_chunk(
                "session-test",
                3,
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n",
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn structured_output_failure_is_sticky_across_chunk_retries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        registered
            .service
            .observe_output_chunk("session-test", 1, b"x")?;
        let suffix = b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n";
        assert!(registered
            .service
            .observe_output_chunk("session-test", 2, suffix)
            .is_err());
        assert!(registered
            .service
            .observe_output_chunk("session-test", 2, suffix)
            .is_err());
        assert!(registered.service.finish_output("session-test").is_err());
        assert!(registered
            .service
            .observed_output_sequence("session-test")
            .is_err());
        let mut forwarded = false;
        assert!(registered
            .service
            .transact_input(
                "session-test",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
                |_frame| {
                    forwarded = true;
                    Ok(())
                },
            )
            .is_err());
        assert!(!forwarded);
        Ok(())
    }

    #[test]
    fn structured_output_tracks_processed_records_with_a_partial_tail(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        registered.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"first\"",
        )?;
        registered.service.observe_output_chunk(
            "session-test",
            2,
            b"}\n{\"jsonrpc\":\"2.0\",\"method\":\"second\"",
        )?;
        assert_eq!(
            registered
                .service
                .observed_output_sequence("session-test")?,
            2
        );
        registered
            .service
            .observe_output_chunk("session-test", 3, b"}\n")?;
        assert_eq!(
            registered
                .service
                .observed_output_sequence("session-test")?,
            3
        );
        Ok(())
    }

    #[test]
    fn output_projection_closes_frames_at_their_final_durable_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut validator = CodexAppServerOutputValidator::default();
        assert!(validator
            .observe_chunk(1, b"{\"jsonrpc\":\"2.0\",\"method\":\"first\"")?
            .is_empty());
        let frames =
            validator.observe_chunk(2, b"}\n{\"jsonrpc\":\"2.0\",\"method\":\"second\"")?;
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames.concat(),
            b"{\"jsonrpc\":\"2.0\",\"method\":\"first\"}\n"
        );
        let frames = validator.observe_chunk(3, b"}\n")?;
        assert_eq!(
            frames.concat(),
            b"{\"jsonrpc\":\"2.0\",\"method\":\"second\"}\n"
        );
        validator.finish()?;
        Ok(())
    }

    #[test]
    fn output_validator_bounds_each_frame_instead_of_the_read_chunk(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prefix = b"{\"jsonrpc\":\"2.0\",\"method\":\"";
        let suffix = b"\"}\n";
        let mut chunk = Vec::with_capacity(MAX_APP_SERVER_FRAME_BYTES + 8);
        chunk.extend_from_slice(prefix);
        chunk.resize(MAX_APP_SERVER_FRAME_BYTES - suffix.len(), b'x');
        chunk.extend_from_slice(suffix);
        chunk.extend_from_slice(b"{\"json");

        let frames = CodexAppServerOutputValidator::default().observe_chunk(1, &chunk)?;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), MAX_APP_SERVER_FRAME_BYTES);
        Ok(())
    }

    #[test]
    fn correlation_failure_cannot_publish_an_output_frontier(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        assert!(registered
            .service
            .observe_output_chunk(
                "session-test",
                1,
                b"{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}\n",
            )
            .is_err());
        assert!(registered
            .service
            .observed_output_sequence("session-test")
            .is_err());
        Ok(())
    }

    #[test]
    fn structured_output_requires_a_complete_final_jsonl_frame(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        registered.service.observe_output_chunk(
            "session-test",
            1,
            br#"{"jsonrpc":"2.0","method":"notice"}"#,
        )?;
        assert!(registered.service.finish_output("session-test").is_err());
        assert!(registered
            .service
            .observe_output_chunk("session-test", 2, b"\n")
            .is_err());

        let complete = registered_service()?;
        complete.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n",
        )?;
        complete.service.finish_output("session-test")?;
        Ok(())
    }

    #[test]
    fn completion_rejects_an_unanswered_app_server_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        assert!(matches!(
            registered.service.accept_input(
                "session-test",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
            )?,
            CodexAppServerInput::Forward(_)
        ));
        assert!(registered.service.finish_output("session-test").is_err());
        assert!(registered
            .service
            .observed_output_sequence("session-test")
            .is_err());
        Ok(())
    }

    #[test]
    fn completion_validation_reads_every_durable_output_page(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let output = tempfile::tempdir()?;
        let stdout = DurableStreamStore::open(
            output.path(),
            StreamKind::Stdout,
            2 * 1024 * 1024,
            2 * 1024 * 1024,
            true,
        )?;
        for timestamp in 0..300 {
            stdout.append(
                timestamp,
                "controller",
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n".to_vec(),
            )?;
        }

        registered
            .service
            .validate_durable_output("session-test", &stdout)?;
        assert_eq!(
            registered
                .service
                .ledger("session-test")?
                .lock()
                .map_err(|_error| "ledger lock is poisoned")?
                .output
                .last_sequence,
            Some(300)
        );
        Ok(())
    }

    #[test]
    fn prompt_ingress_precedes_forward_and_cancellation_bounds_late_responses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\"}}\n";
        assert!(registered
            .service
            .transact_input("session-test", request, |_frame| {
                Err(super::protocol_error("injected stdin write failure"))
            })
            .is_err());
        let ledger = registered.service.ledger("session-test")?;
        let ledger = ledger.lock().map_err(|_error| "ledger lock is poisoned")?;
        let pending = ledger.pending.get("1").ok_or("pending ingress is absent")?;
        assert!(pending.prompt_path.is_some());
        drop(ledger);

        let registered = registered_service()?;
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
        assert!(registered
            .service
            .ledger("session-test")?
            .lock()
            .map_err(|_error| "ledger lock is poisoned")?
            .pending
            .is_empty());
        assert!(registered
            .service
            .accept_input("session-test", request)
            .is_err());
        registered.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        )?;
        assert!(registered
            .service
            .observe_output_chunk(
                "session-test",
                2,
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn output_responses_require_shape_and_exact_correlation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let malformed = registered_service()?;
        malformed.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
        )?;
        assert!(malformed
            .service
            .observe_output_chunk("session-test", 1, b"{\"jsonrpc\":\"2.0\",\"id\":1}\n")
            .is_err());

        let unsolicited = registered_service()?;
        assert!(unsolicited
            .service
            .observe_output_chunk(
                "session-test",
                1,
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            )
            .is_err());

        let duplicate = registered_service()?;
        duplicate.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
        )?;
        duplicate.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        )?;
        assert!(duplicate
            .service
            .observe_output_chunk(
                "session-test",
                2,
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            )
            .is_err());

        let completed_reuse = registered_service()?;
        completed_reuse.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
        )?;
        completed_reuse.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        )?;
        assert!(matches!(
            completed_reuse.service.accept_input(
                "session-test",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"model/list\"}\n",
            )?,
            CodexAppServerInput::Forward(_)
        ));
        completed_reuse.service.observe_output_chunk(
            "session-test",
            2,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        )?;
        Ok(())
    }

    #[test]
    fn output_notifications_require_an_unmixed_string_method(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for frame in [
            b"{\"jsonrpc\":\"2.0\",\"method\":1}\n".as_slice(),
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\",\"result\":{}}\n".as_slice(),
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\",\"id\":1}\n".as_slice(),
        ] {
            let registered = registered_service()?;
            assert!(registered
                .service
                .observe_output_chunk("session-test", 1, frame)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn prompt_notifications_and_incomplete_prompt_responses_are_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registered = registered_service()?;
        for method in ["turn/start", "turn/steer"] {
            let frame =
                format!("{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{{}}}}\n");
            assert!(registered
                .service
                .accept_input("session-test", frame.as_bytes())
                .is_err());
        }

        let incomplete = registered_service()?;
        incomplete.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\"}}\n",
        )?;
        assert!(incomplete
            .service
            .observe_output_chunk(
                "session-test",
                1,
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            )
            .is_err());

        let error_response = registered_service()?;
        error_response.service.accept_input(
            "session-test",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\"}}\n",
        )?;
        error_response.service.observe_output_chunk(
            "session-test",
            1,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1,\"message\":\"failed\"}}\n",
        )?;
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
                CodexInvocationLeaseProfile::new(String::from("codex-test")),
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
