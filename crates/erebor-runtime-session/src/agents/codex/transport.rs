use std::{
    collections::HashMap,
    io::{self, Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

#[cfg(target_os = "linux")]
use std::os::{fd::AsFd, unix::net::UnixStream};

use erebor_runtime_core::{
    CodexProfileLayerConfig, LinuxHostSessionCommandOptions, LinuxHostSessionCommandPlan,
    SessionRunOutcome, SessionRunPlan, SessionRunnerKind,
};
#[cfg(target_os = "linux")]
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    CodexContextDag, CodexInvocationLeaseOwner, CodexPromptReconciliation, CodexSessionError,
};

const MAX_JSONL_FRAME_BYTES: usize = 1024 * 1024;
const MAX_INFLIGHT_REQUESTS: usize = 128;

/// Owns the parent-to-child stdio boundary for a profile explicitly certified
/// as a directly-launched Codex App Server.
pub(crate) struct CodexAppServerTransportBroker<'a> {
    profile: &'a CodexProfileLayerConfig,
    plan: &'a SessionRunPlan,
    context_dag: Arc<CodexContextDag>,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
}

impl<'a> CodexAppServerTransportBroker<'a> {
    pub(crate) fn configured_for(profile: &CodexProfileLayerConfig) -> bool {
        profile.app_server_transport.enabled
    }

    pub(crate) fn new(
        profile: &'a CodexProfileLayerConfig,
        plan: &'a SessionRunPlan,
        context_dag: Arc<CodexContextDag>,
        reconciliation: Arc<CodexPromptReconciliation>,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Result<Self, CodexSessionError> {
        if plan.runner().kind() != SessionRunnerKind::LinuxHost {
            return Err(Self::protocol_error(
                "an owned App Server transport requires the linux_host runner",
            ));
        }
        if !Self::is_app_server_stdio_command(plan.command()) {
            return Err(Self::protocol_error(
                "a brokered Codex profile must be launched as `codex app-server --stdio`",
            ));
        }
        Ok(Self {
            profile,
            plan,
            context_dag,
            reconciliation,
            lease_owner,
        })
    }

    pub(crate) fn run(
        &self,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionRunOutcome, CodexSessionError> {
        #[cfg(target_os = "linux")]
        {
            self.run_linux(environment, options)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (environment, options);
            Err(Self::protocol_error(
                "an owned App Server transport is available only on Linux",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn run_linux(
        &self,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionRunOutcome, CodexSessionError> {
        let launch =
            LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
                self.plan,
                environment,
                options,
            );
        let mut command = Command::new(launch.program());
        command
            .args(launch.args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for key in launch.removed_environment() {
            command.env_remove(key);
        }
        command.envs(launch.environment().iter().cloned());
        if let Some(current_dir) = launch.current_dir() {
            command.current_dir(current_dir);
        }

        let mut child =
            command
                .spawn()
                .map_err(|source| CodexSessionError::AppServerTransportIo {
                    operation: "starting the brokered Codex App Server",
                    source,
                    location: snafu::Location::default(),
                })?;
        let child_stdin = child.stdin.take().ok_or_else(|| {
            Self::protocol_error("brokered Codex App Server did not expose stdin")
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            Self::protocol_error("brokered Codex App Server did not expose stdout")
        })?;

        let output = Arc::new(Mutex::new(io::stdout()));
        let ledger = Mutex::new(PromptLedger::with_lease_owner(
            Arc::clone(&self.context_dag),
            self.plan.session_id().as_str(),
            &self.profile.id,
            Arc::clone(&self.reconciliation),
            Some(Arc::clone(&self.lease_owner)),
        ));
        let (shutdown_receiver, mut shutdown_sender) =
            UnixStream::pair().map_err(|source| CodexSessionError::AppServerTransportIo {
                operation: "creating the App Server output shutdown signal",
                source,
                location: snafu::Location::default(),
            })?;
        let output_result = std::thread::scope(|scope| {
            let output_for_child = Arc::clone(&output);
            let ledger_for_child = &ledger;
            let child_output = scope.spawn(move || {
                let result =
                    Self::relay_child_output(child_stdout, &output_for_child, ledger_for_child);
                if result.is_err() {
                    let _result = shutdown_sender.write_all(&[1]);
                }
                result
            });
            let input_result = Self::relay_client_input(
                io::stdin(),
                child_stdin,
                &output,
                &ledger,
                &shutdown_receiver,
            );
            let status = if input_result.is_err() {
                Self::terminate_child(&mut child)
            } else {
                Self::wait_for_child_or_output_failure(&mut child, &shutdown_receiver)
            };
            let child_result = child_output.join().map_err(|_error| {
                Self::protocol_error("Codex App Server output broker worker panicked")
            })?;
            child_result?;
            input_result?;
            status
        })?;

        if output_result.success() {
            Ok(SessionRunOutcome::new(
                SessionRunnerKind::LinuxHost,
                output_result.code(),
            ))
        } else {
            Err(CodexSessionError::AppServerTransportChildExit {
                code: output_result.code(),
                location: snafu::Location::default(),
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn relay_client_input(
        mut client_input: impl Read + AsFd,
        mut child_input: impl Write,
        output: &Arc<Mutex<io::Stdout>>,
        ledger: &Mutex<PromptLedger>,
        shutdown: &impl AsFd,
    ) -> Result<(), CodexSessionError> {
        let mut framer = JsonlFramer::default();
        let mut chunk = [0_u8; 8192];
        loop {
            Self::wait_for_client_input_or_output_failure(&client_input, shutdown)?;
            let read = client_input.read(&mut chunk).map_err(|source| {
                CodexSessionError::AppServerTransportIo {
                    operation: "reading App Server client stdin",
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            if read == 0 {
                break;
            }
            for frame in framer.push(&chunk[..read])? {
                let request = ClientRequest::parse(&frame)?;
                if let Some(method) = request.method.as_deref() {
                    if Self::is_sensitive_method(method) {
                        Self::write_denial(output, request.id.as_ref(), method)?;
                        continue;
                    }
                    let mut ledger = ledger.lock().map_err(|_error| {
                        Self::protocol_error("App Server prompt ledger lock is poisoned")
                    })?;
                    if Self::is_prompt_method(method) {
                        ledger.record_pending_prompt(&request, &frame)?;
                    } else if let Some(id) = request.id.as_ref() {
                        ledger.record_request(id)?;
                    }
                }
                child_input.write_all(&frame).map_err(|source| {
                    CodexSessionError::AppServerTransportIo {
                        operation: "forwarding App Server client JSONL to Codex",
                        source,
                        location: snafu::Location::default(),
                    }
                })?;
                child_input
                    .flush()
                    .map_err(|source| CodexSessionError::AppServerTransportIo {
                        operation: "flushing App Server client JSONL to Codex",
                        source,
                        location: snafu::Location::default(),
                    })?;
            }
        }
        framer.finish()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn wait_for_client_input_or_output_failure(
        client_input: &impl AsFd,
        shutdown: &impl AsFd,
    ) -> Result<(), CodexSessionError> {
        loop {
            let mut descriptors = [
                PollFd::new(client_input, PollFlags::IN),
                PollFd::new(shutdown, PollFlags::IN),
            ];
            poll(&mut descriptors, None).map_err(|source| {
                CodexSessionError::AppServerTransportIo {
                    operation: "waiting for App Server client input or child output failure",
                    source: io::Error::from(source),
                    location: snafu::Location::default(),
                }
            })?;
            if !descriptors[1].revents().is_empty() {
                return Err(Self::protocol_error(
                    "Codex App Server output validation failed; stopped forwarding client input",
                ));
            }
            if !descriptors[0].revents().is_empty() {
                return Ok(());
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_for_child_or_output_failure(
        child: &mut std::process::Child,
        shutdown: &impl AsFd,
    ) -> Result<std::process::ExitStatus, CodexSessionError> {
        let wait_interval = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        loop {
            if let Some(status) =
                child
                    .try_wait()
                    .map_err(|source| CodexSessionError::AppServerTransportIo {
                        operation: "checking the brokered Codex App Server exit status",
                        source,
                        location: snafu::Location::default(),
                    })?
            {
                return Ok(status);
            }
            let mut descriptors = [PollFd::new(shutdown, PollFlags::IN)];
            poll(&mut descriptors, Some(&wait_interval)).map_err(|source| {
                CodexSessionError::AppServerTransportIo {
                    operation: "waiting for Codex App Server output validation",
                    source: io::Error::from(source),
                    location: snafu::Location::default(),
                }
            })?;
            if !descriptors[0].revents().is_empty() {
                Self::terminate_child(child)?;
                return Err(Self::protocol_error(
                    "Codex App Server output validation failed before the child exited",
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn terminate_child(
        child: &mut std::process::Child,
    ) -> Result<std::process::ExitStatus, CodexSessionError> {
        if let Some(status) =
            child
                .try_wait()
                .map_err(|source| CodexSessionError::AppServerTransportIo {
                    operation: "checking the brokered Codex App Server before termination",
                    source,
                    location: snafu::Location::default(),
                })?
        {
            return Ok(status);
        }
        if let Err(source) = child.kill() {
            if source.kind() != io::ErrorKind::InvalidInput {
                return Err(CodexSessionError::AppServerTransportIo {
                    operation: "terminating the brokered Codex App Server",
                    source,
                    location: snafu::Location::default(),
                });
            }
        }
        child
            .wait()
            .map_err(|source| CodexSessionError::AppServerTransportIo {
                operation: "waiting for the terminated brokered Codex App Server",
                source,
                location: snafu::Location::default(),
            })
    }

    fn relay_child_output(
        mut child_output: impl Read,
        output: &Arc<Mutex<io::Stdout>>,
        ledger: &Mutex<PromptLedger>,
    ) -> Result<(), CodexSessionError> {
        let mut framer = JsonlFramer::default();
        let mut chunk = [0_u8; 8192];
        loop {
            let read = child_output.read(&mut chunk).map_err(|source| {
                CodexSessionError::AppServerTransportIo {
                    operation: "reading Codex App Server stdout",
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            if read == 0 {
                break;
            }
            for frame in framer.push(&chunk[..read])? {
                ledger
                    .lock()
                    .map_err(|_error| {
                        Self::protocol_error("App Server prompt ledger lock is poisoned")
                    })?
                    .record_codex_message(&frame)?;
                Self::write_frame(output, &frame)?;
            }
        }
        framer.finish()
    }

    fn write_denial(
        output: &Arc<Mutex<io::Stdout>>,
        id: Option<&Value>,
        method: &str,
    ) -> Result<(), CodexSessionError> {
        let Some(id) = id else {
            return Err(Self::protocol_error(
                "sensitive App Server methods must be JSON-RPC requests with an id",
            ));
        };
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32003,
                "message": format!("Erebor denied sensitive App Server method `{method}`")
            }
        });
        let mut frame = serde_json::to_vec(&response).map_err(|error| {
            Self::protocol_error(format!("could not encode App Server denial: {error}"))
        })?;
        frame.push(b'\n');
        Self::write_frame(output, &frame)
    }

    fn write_frame(output: &Arc<Mutex<io::Stdout>>, frame: &[u8]) -> Result<(), CodexSessionError> {
        let mut output = output
            .lock()
            .map_err(|_error| Self::protocol_error("App Server client stdout lock is poisoned"))?;
        output
            .write_all(frame)
            .and_then(|()| output.flush())
            .map_err(|source| CodexSessionError::AppServerTransportIo {
                operation: "writing App Server JSONL to the client",
                source,
                location: snafu::Location::default(),
            })
    }

    fn is_app_server_stdio_command(command: &[String]) -> bool {
        !command.is_empty()
            && command
                .iter()
                .skip(1)
                .any(|argument| argument == "app-server")
            && command.iter().skip(1).any(|argument| argument == "--stdio")
    }

    fn is_prompt_method(method: &str) -> bool {
        matches!(method, "turn/start" | "turn/steer")
    }

    fn is_sensitive_method(method: &str) -> bool {
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
}

#[derive(Default)]
struct JsonlFramer {
    pending: Vec<u8>,
}

impl JsonlFramer {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, CodexSessionError> {
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
            let frame = self.pending.drain(..=position).collect::<Vec<_>>();
            if frame.len() > MAX_JSONL_FRAME_BYTES {
                return Err(CodexAppServerTransportBroker::protocol_error(
                    "App Server JSONL frame exceeded the configured byte limit",
                ));
            }
            if frame.iter().any(|byte| !byte.is_ascii_whitespace()) {
                frames.push(frame);
            }
        }
        if self.pending.len() > MAX_JSONL_FRAME_BYTES {
            return Err(CodexAppServerTransportBroker::protocol_error(
                "App Server JSONL frame exceeded the configured byte limit",
            ));
        }
        Ok(frames)
    }

    fn finish(self) -> Result<(), CodexSessionError> {
        if self.pending.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(CodexAppServerTransportBroker::protocol_error(
                "App Server transport ended with an incomplete JSONL frame",
            ));
        }
        Ok(())
    }
}

struct ClientRequest {
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
    raw_line: String,
}

impl ClientRequest {
    fn parse(frame: &[u8]) -> Result<Self, CodexSessionError> {
        let raw_line = String::from_utf8(frame.to_vec()).map_err(|_error| {
            CodexAppServerTransportBroker::protocol_error("App Server JSONL is not UTF-8")
        })?;
        let payload: Value = serde_json::from_slice(Self::json_bytes(frame)).map_err(|error| {
            CodexAppServerTransportBroker::protocol_error(format!(
                "App Server JSONL frame is not valid JSON: {error}"
            ))
        })?;
        let object = payload.as_object().ok_or_else(|| {
            CodexAppServerTransportBroker::protocol_error(
                "App Server JSON-RPC payload is not an object",
            )
        })?;
        let method = object
            .get("method")
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    CodexAppServerTransportBroker::protocol_error(
                        "App Server JSON-RPC method is not a string",
                    )
                })
            })
            .transpose()?;
        Ok(Self {
            id: object.get("id").cloned(),
            method,
            params: object.get("params").cloned(),
            raw_line,
        })
    }

    fn json_bytes(frame: &[u8]) -> &[u8] {
        let without_newline = frame.strip_suffix(b"\n").unwrap_or(frame);
        without_newline
            .strip_suffix(b"\r")
            .unwrap_or(without_newline)
    }
}

struct PromptLedger {
    context_dag: Arc<CodexContextDag>,
    session_id: String,
    profile_id: String,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Option<Arc<CodexInvocationLeaseOwner>>,
    requests: HashMap<String, RequestKind>,
    prompts: HashMap<String, PromptNode>,
}

enum RequestKind {
    Other,
    Prompt(String),
}

#[derive(Clone)]
struct PromptNode {
    request_id: Value,
    scope_ref: String,
    path: String,
    raw_line: String,
    model_visible_content: Option<Value>,
    rich_ide_context: Option<Value>,
    attachments: Option<Value>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    item_id: Option<String>,
    child_agent_threads: Vec<String>,
}

impl PromptLedger {
    #[cfg(test)]
    fn new(
        context_dag: Arc<CodexContextDag>,
        session_id: &str,
        profile_id: &str,
        reconciliation: Arc<CodexPromptReconciliation>,
    ) -> Self {
        Self::with_lease_owner(context_dag, session_id, profile_id, reconciliation, None)
    }

    fn with_lease_owner(
        context_dag: Arc<CodexContextDag>,
        session_id: &str,
        profile_id: &str,
        reconciliation: Arc<CodexPromptReconciliation>,
        lease_owner: Option<Arc<CodexInvocationLeaseOwner>>,
    ) -> Self {
        Self {
            context_dag,
            session_id: session_id.to_owned(),
            profile_id: profile_id.to_owned(),
            reconciliation,
            lease_owner,
            requests: HashMap::new(),
            prompts: HashMap::new(),
        }
    }

    fn record_request(&mut self, id: &Value) -> Result<(), CodexSessionError> {
        let key = Self::request_key(id)?;
        if self.requests.len() == MAX_INFLIGHT_REQUESTS {
            return Err(CodexAppServerTransportBroker::protocol_error(
                "App Server request ledger reached its configured limit",
            ));
        }
        if self
            .requests
            .insert(key.clone(), RequestKind::Other)
            .is_some()
        {
            return Err(CodexAppServerTransportBroker::protocol_error(format!(
                "App Server reused in-flight request id {key}"
            )));
        }
        Ok(())
    }

    fn record_pending_prompt(
        &mut self,
        request: &ClientRequest,
        frame: &[u8],
    ) -> Result<(), CodexSessionError> {
        let id = request.id.as_ref().ok_or_else(|| {
            CodexAppServerTransportBroker::protocol_error(
                "turn/start and turn/steer must be JSON-RPC requests with an id",
            )
        })?;
        let key = Self::request_key(id)?;
        if self.requests.len() == MAX_INFLIGHT_REQUESTS {
            return Err(CodexAppServerTransportBroker::protocol_error(
                "App Server request ledger reached its configured limit",
            ));
        }
        if self.requests.contains_key(&key) {
            return Err(CodexAppServerTransportBroker::protocol_error(format!(
                "App Server reused in-flight request id {key}"
            )));
        }
        let thread_id = request
            .params
            .as_ref()
            .and_then(|params| params.get("threadId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let scope_key = thread_id
            .clone()
            .unwrap_or_else(|| format!("request-{key}"));
        let scope_ref = self.context_dag.ensure_prompt_scope(&scope_key)?;
        let node_id = Self::digest(frame);
        let node = PromptNode {
            request_id: id.clone(),
            scope_ref,
            path: format!("agents/codex/app-server/prompts/{node_id}.json"),
            raw_line: request.raw_line.clone(),
            model_visible_content: request
                .params
                .as_ref()
                .and_then(|params| params.get("input"))
                .cloned(),
            rich_ide_context: request
                .params
                .as_ref()
                .and_then(|params| {
                    params
                        .get("additionalContext")
                        .or_else(|| params.get("ideContext"))
                        .or_else(|| params.get("context"))
                })
                .cloned(),
            attachments: request.params.as_ref().and_then(Self::attachments),
            thread_id,
            turn_id: None,
            item_id: None,
            child_agent_threads: Vec::new(),
        };
        self.append_prompt_node(&node, "pending")?;
        self.requests
            .insert(key.clone(), RequestKind::Prompt(key.clone()));
        self.prompts.insert(key, node);
        Ok(())
    }

    fn record_codex_message(&mut self, frame: &[u8]) -> Result<(), CodexSessionError> {
        let payload: Value =
            serde_json::from_slice(ClientRequest::json_bytes(frame)).map_err(|error| {
                CodexAppServerTransportBroker::protocol_error(format!(
                    "Codex App Server stdout is not valid JSON: {error}"
                ))
            })?;
        let object = payload.as_object().ok_or_else(|| {
            CodexAppServerTransportBroker::protocol_error(
                "Codex App Server JSON-RPC payload is not an object",
            )
        })?;
        if object.get("method").is_none() {
            let Some(id) = object.get("id") else {
                return Ok(());
            };
            let key = Self::request_key(id)?;
            let Some(request) = self.requests.remove(&key) else {
                return Err(CodexAppServerTransportBroker::protocol_error(format!(
                    "Codex App Server response did not match an in-flight request id {key}"
                )));
            };
            if let RequestKind::Prompt(prompt_key) = request {
                self.bind_prompt(&prompt_key, &payload)?;
            }
        }
        if let Some(method) = object.get("method").and_then(Value::as_str) {
            if matches!(
                method,
                "thread/started" | "turn/started" | "item/started" | "item/completed"
            ) {
                self.bind_notification(&payload)?;
            }
            if method == "turn/completed" {
                self.refresh_hook_reconciliation()?;
            }
        }
        Ok(())
    }

    fn refresh_hook_reconciliation(&mut self) -> Result<(), CodexSessionError> {
        let nodes = self.prompts.values().cloned().collect::<Vec<_>>();
        for node in nodes {
            self.append_prompt_node(&node, "bound")?;
        }
        Ok(())
    }

    fn bind_prompt(&mut self, prompt_key: &str, payload: &Value) -> Result<(), CodexSessionError> {
        let facts = NativeFacts::from_payload(payload);
        let node = self.prompts.get_mut(prompt_key).ok_or_else(|| {
            CodexAppServerTransportBroker::protocol_error(
                "prompt request was missing from the App Server prompt ledger",
            )
        })?;
        node.thread_id = facts.thread_id.or_else(|| node.thread_id.clone());
        node.turn_id = facts.turn_id.or_else(|| node.turn_id.clone());
        node.item_id = facts.item_id.or_else(|| node.item_id.clone());
        let node = node.clone();
        self.append_prompt_node(&node, "bound")
    }

    fn bind_notification(&mut self, payload: &Value) -> Result<(), CodexSessionError> {
        let facts = NativeFacts::from_payload(payload);
        if let (Some(parent_thread_id), Some(child_thread_id)) =
            (&facts.parent_thread_id, &facts.thread_id)
        {
            let parent_matches = self
                .prompts
                .iter()
                .filter(|(_key, node)| node.thread_id.as_deref() == Some(parent_thread_id))
                .map(|(key, _node)| key.clone())
                .collect::<Vec<_>>();
            if let [parent_key] = parent_matches.as_slice() {
                let node = self.prompts.get_mut(parent_key).ok_or_else(|| {
                    CodexAppServerTransportBroker::protocol_error(
                        "matched parent prompt node disappeared",
                    )
                })?;
                if !node.child_agent_threads.contains(child_thread_id) {
                    node.child_agent_threads.push(child_thread_id.clone());
                    node.child_agent_threads.sort();
                }
                let node = node.clone();
                self.append_prompt_node(&node, "bound")?;
            }
        }
        let matching = self
            .prompts
            .iter()
            .filter(|(_key, node)| node.matches_exactly(&facts))
            .map(|(key, _node)| key.clone())
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Ok(());
        }
        let node = self.prompts.get_mut(&matching[0]).ok_or_else(|| {
            CodexAppServerTransportBroker::protocol_error("matched prompt node disappeared")
        })?;
        node.thread_id = facts.thread_id.or_else(|| node.thread_id.clone());
        node.turn_id = facts.turn_id.or_else(|| node.turn_id.clone());
        node.item_id = facts.item_id.or_else(|| node.item_id.clone());
        let node = node.clone();
        self.append_prompt_node(&node, "bound")
    }

    fn append_prompt_node(
        &mut self,
        node: &PromptNode,
        state: &str,
    ) -> Result<(), CodexSessionError> {
        let reconciliation = self
            .reconciliation
            .matching_user_prompt_submit(node.thread_id.as_deref(), node.turn_id.as_deref())?;
        let child_agents = node
            .child_agent_threads
            .iter()
            .map(|thread_id| {
                Ok(json!({
                    "thread_id": thread_id,
                    "authenticated_hook_count": self
                        .reconciliation
                        .matching_subagent_hook(Some(&self.session_id), Some(thread_id))?
                        .len(),
                }))
            })
            .collect::<Result<Vec<_>, CodexSessionError>>()?;
        let payload = json!({
            "schema_version": 1,
            "state": state,
            "source": "brokered_app_server_transport",
            "profile_id": self.profile_id,
            "erebor_session_id": self.session_id,
            "request_id": node.request_id,
            "original_request_jsonl": node.raw_line,
            "model_visible_request_content": Self::observation(&node.model_visible_content),
            "rich_ide_context": Self::observation(&node.rich_ide_context),
            "attachments": Self::observation(&node.attachments),
            "native": {
                "thread_id": node.thread_id,
                "turn_id": node.turn_id,
                "item_id": node.item_id,
            },
            "child_agents": child_agents,
            "hook_reconciliation": {
                "status": if reconciliation.is_empty() { "unmatched" } else { "exact" },
                "authenticated_user_prompt_submit_count": reconciliation.len(),
            },
        });
        let bytes = serde_json::to_vec_pretty(&payload).map_err(|error| {
            CodexAppServerTransportBroker::protocol_error(format!(
                "could not encode durable App Server prompt context: {error}"
            ))
        })?;
        self.context_dag.append_prompt(
            &node.scope_ref,
            &node.path,
            bytes,
            &format!("Record Codex App Server {state} prompt ingress"),
        )?;
        if let (Some(thread_id), Some(turn_id), Some(owner)) = (
            node.thread_id.as_ref(),
            node.turn_id.as_ref(),
            self.lease_owner.as_ref(),
        ) {
            let item_node_stream = node.item_id.as_ref().map_or_else(
                || node.path.clone(),
                |item_id| format!("{}#{item_id}", node.path),
            );
            let binding = self.context_dag.bind_prompt(
                thread_id.clone(),
                turn_id.clone(),
                &node.scope_ref,
                item_node_stream,
            )?;
            owner.record_scope_context(binding)?;
        }
        Ok(())
    }

    fn request_key(id: &Value) -> Result<String, CodexSessionError> {
        if matches!(
            id,
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_)
        ) {
            return Err(CodexAppServerTransportBroker::protocol_error(
                "App Server JSON-RPC request id must be a string or number",
            ));
        }
        serde_json::to_string(id).map_err(|error| {
            CodexAppServerTransportBroker::protocol_error(format!(
                "could not canonicalize App Server request id: {error}"
            ))
        })
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn observation(value: &Option<Value>) -> Value {
        value.as_ref().map_or_else(
            || json!({"status": "unavailable"}),
            |value| json!({"status": "observed", "value": value}),
        )
    }

    fn attachments(params: &Value) -> Option<Value> {
        params.get("attachments").cloned().or_else(|| {
            params
                .get("input")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter(|item| item.get("type").and_then(Value::as_str) != Some("text"))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .filter(|attachments| !attachments.is_empty())
                .map(Value::Array)
        })
    }
}

#[derive(Default)]
struct NativeFacts {
    thread_id: Option<String>,
    turn_id: Option<String>,
    item_id: Option<String>,
    parent_thread_id: Option<String>,
}

impl NativeFacts {
    fn from_payload(payload: &Value) -> Self {
        Self {
            thread_id: Self::string_at(
                payload,
                &["/params/threadId", "/params/thread/id", "/result/thread/id"],
            ),
            turn_id: Self::string_at(
                payload,
                &[
                    "/params/turnId",
                    "/params/turn/id",
                    "/result/turnId",
                    "/result/turn/id",
                ],
            ),
            item_id: Self::string_at(
                payload,
                &["/params/itemId", "/params/item/id", "/result/item/id"],
            ),
            parent_thread_id: Self::string_at(
                payload,
                &[
                    "/params/parentThreadId",
                    "/params/thread/parentThreadId",
                    "/result/thread/parentThreadId",
                ],
            ),
        }
    }

    fn string_at(payload: &Value, pointers: &[&str]) -> Option<String> {
        pointers.iter().find_map(|pointer| {
            payload
                .pointer(pointer)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
    }
}

impl PromptNode {
    fn matches_exactly(&self, facts: &NativeFacts) -> bool {
        let matches = [
            self.thread_id.as_deref().zip(facts.thread_id.as_deref()),
            self.turn_id.as_deref().zip(facts.turn_id.as_deref()),
            self.item_id.as_deref().zip(facts.item_id.as_deref()),
        ];
        matches.iter().any(Option::is_some)
            && matches
                .iter()
                .flatten()
                .all(|(expected, observed)| expected == observed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[cfg(target_os = "linux")]
    use std::{io, io::Write, os::unix::net::UnixStream, process::Command};

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime,
    };
    use serde_json::json;

    use super::{ClientRequest, JsonlFramer, PromptLedger};
    use crate::agents::codex::{CodexContextDag, CodexPromptReconciliation};

    #[test]
    fn jsonl_framer_preserves_fragmented_and_coalesced_frames(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut framer = JsonlFramer::default();
        assert!(framer.push(br#"{"id":1,"met"#)?.is_empty());
        let frames = framer.push(b"hod\":\"turn/start\"}\n{\"id\":2}\n")?;
        assert_eq!(
            frames,
            vec![
                b"{\"id\":1,\"method\":\"turn/start\"}\n".to_vec(),
                b"{\"id\":2}\n".to_vec()
            ]
        );
        framer.finish()?;
        Ok(())
    }

    #[test]
    fn prompt_is_durable_before_its_request_is_forwardable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temp.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-1", Default::default(), "Initialize session root")?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\",\"input\":[{\"type\":\"text\",\"text\":\"keep exact spacing\"}]}}\n";
        let request = ClientRequest::parse(frame)?;
        ledger.record_pending_prompt(&request, frame)?;

        assert!(ledger.prompts.contains_key("7"));
        assert!(ledger.requests.contains_key("7"));
        let node = ledger.prompts.get("7").ok_or("missing prompt")?;
        assert!(repository
            .scope_refs()?
            .iter()
            .any(|scope| scope.as_str() == node.scope_ref));
        Ok(())
    }

    #[test]
    fn duplicate_prompt_ids_and_sensitive_methods_are_not_forwardable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let duplicate = ClientRequest::parse(
            b"{\"id\":\"same\",\"method\":\"turn/start\",\"params\":{\"threadId\":\"t\"}}\n",
        )?;
        assert_eq!(duplicate.id, Some(json!("same")));
        let frame =
            b"{\"id\":\"same\",\"method\":\"turn/start\",\"params\":{\"threadId\":\"t\"}}\n";
        ledger.record_pending_prompt(&duplicate, frame)?;
        assert!(ledger.record_pending_prompt(&duplicate, frame).is_err());
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "command/exec"
        ));
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "command/exec/write"
        ));
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "fs/writeFile"
        ));
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "thread/shellCommand"
        ));
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "thread/inject_items"
        ));
        assert!(super::CodexAppServerTransportBroker::is_sensitive_method(
            "thread/realtime/appendText"
        ));
        assert!(!super::CodexAppServerTransportBroker::is_sensitive_method(
            "turn/start"
        ));
        Ok(())
    }

    #[test]
    fn invalid_framing_and_backpressure_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut framer = JsonlFramer::default();
        framer.push(br#"{"id":1}"#)?;
        assert!(framer.finish().is_err());
        assert!(ClientRequest::parse(b"{not-json}\n").is_err());

        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        for id in 0..super::MAX_INFLIGHT_REQUESTS {
            ledger.record_request(&json!(id))?;
        }
        assert!(ledger.record_request(&json!("overflow")).is_err());
        Ok(())
    }

    #[test]
    fn completed_requests_release_their_id_for_a_later_turn(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        ledger.record_request(&json!(17))?;
        ledger.record_codex_message(b"{\"id\":17,\"result\":{}}\n")?;
        ledger.record_request(&json!(17))?;
        Ok(())
    }

    #[test]
    fn steer_response_binds_the_current_codex_turn_id() -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let frame = b"{\"id\":22,\"method\":\"turn/steer\",\"params\":{\"threadId\":\"thread-1\",\"expectedTurnId\":\"turn-0\",\"input\":[{\"type\":\"text\",\"text\":\"steer\"}]}}\n";
        ledger.record_pending_prompt(&ClientRequest::parse(frame)?, frame)?;
        ledger.record_codex_message(b"{\"id\":22,\"result\":{\"turnId\":\"turn-1\"}}\n")?;

        assert_eq!(
            ledger
                .prompts
                .get("22")
                .ok_or("missing steer prompt")?
                .turn_id
                .as_deref(),
            Some("turn-1")
        );
        Ok(())
    }

    #[test]
    fn current_app_server_context_and_attachments_are_recorded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let frame = b"{\"id\":23,\"method\":\"turn/start\",\"params\":{\"threadId\":\"thread-1\",\"additionalContext\":{\"editor\":{\"uri\":\"file:///workspace/main.rs\"}},\"input\":[{\"type\":\"text\",\"text\":\"inspect this\"},{\"type\":\"localImage\",\"path\":\"/workspace/diagram.png\"}]}}\n";
        ledger.record_pending_prompt(&ClientRequest::parse(frame)?, frame)?;
        let node = ledger.prompts.get("23").ok_or("missing prompt")?;

        assert_eq!(
            node.rich_ide_context,
            Some(json!({"editor": {"uri": "file:///workspace/main.rs"}}))
        );
        assert_eq!(
            node.attachments,
            Some(json!([{"type": "localImage", "path": "/workspace/diagram.png"}]))
        );
        Ok(())
    }

    #[test]
    fn turn_interrupt_is_paired_without_creating_a_prompt() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let interrupt = ClientRequest::parse(
            b"{\"id\":24,\"method\":\"turn/interrupt\",\"params\":{\"threadId\":\"thread-1\",\"turnId\":\"turn-1\"}}\n",
        )?;

        ledger.record_request(interrupt.id.as_ref().ok_or("missing interrupt id")?)?;
        ledger.record_codex_message(b"{\"id\":24,\"result\":{}}\n")?;

        assert!(ledger.prompts.is_empty());
        assert!(!ledger.requests.contains_key("24"));
        Ok(())
    }

    #[test]
    fn app_server_parent_and_child_thread_facts_bind_a_child_agent_to_one_prompt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let mut ledger = PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        );
        let frame = b"{\"id\":31,\"method\":\"turn/start\",\"params\":{\"threadId\":\"parent-thread\",\"input\":[]}}\n";
        ledger.record_pending_prompt(&ClientRequest::parse(frame)?, frame)?;
        ledger.record_codex_message(
            b"{\"method\":\"thread/started\",\"params\":{\"thread\":{\"id\":\"child-thread\",\"parentThreadId\":\"parent-thread\"}}}\n",
        )?;

        assert_eq!(
            ledger
                .prompts
                .get("31")
                .ok_or("missing parent prompt")?
                .child_agent_threads,
            vec![String::from("child-thread")]
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_failure_signal_stops_client_forwarding() -> Result<(), Box<dyn std::error::Error>> {
        let (_client_writer, client_reader) = UnixStream::pair()?;
        let (shutdown_reader, mut shutdown_sender) = UnixStream::pair()?;
        shutdown_sender.write_all(&[1])?;
        let (_temp, repository) = initialized_repository()?;
        let reconciliation = Arc::new(CodexPromptReconciliation::default());
        let ledger = Mutex::new(PromptLedger::new(
            context_dag(&repository),
            "session-1",
            "profile-1",
            reconciliation,
        ));
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::new(Mutex::new(io::stdout()));

        assert!(super::CodexAppServerTransportBroker::relay_client_input(
            client_reader,
            SharedWriter(Arc::clone(&forwarded)),
            &output,
            &ledger,
            &shutdown_reader,
        )
        .is_err());
        assert!(forwarded
            .lock()
            .map_err(|_error| "forwarded buffer lock")?
            .is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_failure_signal_terminates_the_child_without_waiting_for_client_eof(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (shutdown_receiver, mut shutdown_sender) = UnixStream::pair()?;
        let mut child = Command::new("sleep").arg("30").spawn()?;
        shutdown_sender.write_all(&[1])?;

        assert!(
            super::CodexAppServerTransportBroker::wait_for_child_or_output_failure(
                &mut child,
                &shutdown_receiver,
            )
            .is_err()
        );
        assert!(child.try_wait()?.is_some());
        Ok(())
    }

    fn initialized_repository() -> Result<
        (
            tempfile::TempDir,
            Arc<erebor_runtime_context::ContextRepository>,
        ),
        Box<dyn std::error::Error>,
    > {
        let temp = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temp.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-1", Default::default(), "Initialize session root")?;
        Ok((temp, repository))
    }

    fn context_dag(
        repository: &Arc<erebor_runtime_context::ContextRepository>,
    ) -> Arc<CodexContextDag> {
        Arc::new(CodexContextDag::new(Arc::clone(repository), "session-1"))
    }

    struct FixedMetadataSource;

    #[cfg(target_os = "linux")]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    #[cfg(target_os = "linux")]
    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_error| io::Error::other("shared writer lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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
