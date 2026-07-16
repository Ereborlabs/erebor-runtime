//! Standalone, dependency-free IPC subset used by the Linux process guard.
//!
//! The guard is compiled directly with `rustc` into a static helper binary, so
//! it cannot link the normal prost-backed IPC crate without changing that build
//! model. Keep this module protocol-focused and mirrored by crate-level IPC
//! contract tests.

#![allow(dead_code)]

use std::{os::unix::net::UnixStream, path::Path, time::Duration};

mod codec;
mod decision;
mod envelope;
mod file;
mod request;
#[cfg(all(test, erebor_runtime_ipc_contract_tests))]
mod tests;

pub(super) use file::{FileIdentity, FileOperation, FileOperationKind};

use decision::{
    decode_guard_hello_ack, decode_guard_lifecycle_reply, decode_interception_decision,
};
use envelope::{read_envelope, write_envelope, Envelope, Header};
use request::{encode_guard_hello, encode_guard_lifecycle_event, encode_interception_request};

const INTERCEPTION_TOKEN_HEADER: &str = "interception_token";
const INTERCEPTION_SOURCE_PTRACE: i32 = 1;
const INTERCEPTION_SOURCE_SHIM: i32 = 2;
const INTERCEPTION_OPERATION_PROCESS_EXEC: i32 = 1;
const INTERCEPTION_OPERATION_FILE_OPEN: i32 = 2;
const INTERCEPTION_OPERATION_FILE_READ: i32 = 3;
const INTERCEPTION_OPERATION_FILE_MUTATION: i32 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeInterceptionEndpoint {
    pub(super) path: String,
    pub(super) token: String,
    pub(super) timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GuardHello {
    pub(super) session_id: String,
    pub(super) actor_id: String,
    pub(super) guard_pid: i64,
    pub(super) runner_kind: String,
    pub(super) platform: String,
    pub(super) capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterceptionRequest {
    pub(super) request_id: u64,
    pub(super) actor_id: String,
    pub(super) source: InterceptionSource,
    pub(super) pid: i64,
    pub(super) ppid: i64,
    pub(super) executable: String,
    pub(super) argv: Vec<String>,
    pub(super) cwd: String,
    pub(super) matched_handler_id: String,
    pub(super) timestamp: String,
    pub(super) operation: InterceptionOperation,
    pub(super) file: Option<FileOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterceptionDecision {
    pub(super) request_id: u64,
    pub(super) kind: InterceptionDecisionKind,
    pub(super) rule_id: String,
    pub(super) reason: String,
    pub(super) allow_exec_target: Option<String>,
    pub(super) deny_exit_code: Option<i32>,
    pub(super) mediate: Option<MediateDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GuardLifecycleEvent {
    pub(super) request_id: u64,
    pub(super) kind: GuardLifecycleEventKind,
    pub(super) pid: i64,
    pub(super) exec_history: Vec<String>,
    pub(super) parent_pid: i64,
    pub(super) child_pid: i64,
    pub(super) exited_successfully: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardLifecycleEventKind {
    Exec,
    Fork,
    Exit,
}

impl GuardLifecycleEventKind {
    const fn as_i32(self) -> i32 {
        match self {
            Self::Exec => 1,
            Self::Fork => 2,
            Self::Exit => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GuardLifecycleReply {
    pub(super) request_id: u64,
    pub(super) kind: GuardLifecycleReplyKind,
    pub(super) reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardLifecycleReplyKind {
    Ignore,
    Hold,
    Allow,
    Deny,
    Release,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterceptionDecisionKind {
    Allow,
    Deny,
    RequireApproval,
    Mediate,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterceptionSource {
    Ptrace,
    Shim,
}

impl InterceptionSource {
    const fn as_i32(self) -> i32 {
        match self {
            Self::Ptrace => INTERCEPTION_SOURCE_PTRACE,
            Self::Shim => INTERCEPTION_SOURCE_SHIM,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterceptionOperation {
    Unspecified,
    ProcessExec,
    FileOpen,
    FileRead,
    FileMutation,
}

impl InterceptionOperation {
    const fn as_i32(self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::ProcessExec => INTERCEPTION_OPERATION_PROCESS_EXEC,
            Self::FileOpen => INTERCEPTION_OPERATION_FILE_OPEN,
            Self::FileRead => INTERCEPTION_OPERATION_FILE_READ,
            Self::FileMutation => INTERCEPTION_OPERATION_FILE_MUTATION,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MediateDecision {
    pub(super) kind: String,
    pub(super) replacement_surface: String,
    pub(super) endpoint: String,
    pub(super) lease_id: String,
    pub(super) print_line: String,
    pub(super) keepalive: bool,
}

pub(super) struct RuntimeInterceptionConnection {
    stream: UnixStream,
    next_message_id: u64,
}

impl RuntimeInterceptionConnection {
    pub(super) fn connect(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
    ) -> Result<Self, String> {
        let mut stream = UnixStream::connect(Path::new(&endpoint.path)).map_err(|error| {
            format!(
                "failed to connect to Erebor runtime interception broker at {}: {error}",
                endpoint.path
            )
        })?;
        let timeout = Duration::from_millis(endpoint.timeout_ms);
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            format!("failed to set runtime interception broker read timeout: {error}")
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            format!("failed to set runtime interception broker write timeout: {error}")
        })?;

        let payload = encode_guard_hello(&hello);
        let mut envelope = Envelope {
            message_id: 1,
            correlation_id: 0,
            message_kind: String::from(request::KIND_GUARD_HELLO),
            payload,
            headers: Vec::new(),
        };
        envelope.headers.push(Header {
            key: String::from(INTERCEPTION_TOKEN_HEADER),
            value: endpoint.token.clone(),
        });
        write_envelope(&mut stream, &envelope)?;

        let response = read_envelope(&mut stream)?;
        if response.message_kind != decision::KIND_GUARD_HELLO_ACK {
            return Err(format!(
                "runtime interception broker returned unexpected response `{}` to GuardHello",
                response.message_kind
            ));
        }
        let ack = decode_guard_hello_ack(&response.payload)?;
        if !ack.accepted {
            return Err(format!(
                "runtime interception broker rejected guard hello: {}",
                ack.reason
            ));
        }

        Ok(Self {
            stream,
            next_message_id: 2,
        })
    }

    pub(super) fn request_interception(
        &mut self,
        request: &InterceptionRequest,
    ) -> Result<InterceptionDecision, String> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1);
        let envelope = Envelope {
            message_id,
            correlation_id: 1,
            message_kind: String::from(request::KIND_INTERCEPTION_REQUEST),
            payload: encode_interception_request(request),
            headers: Vec::new(),
        };
        write_envelope(&mut self.stream, &envelope)?;

        let response = read_envelope(&mut self.stream)?;
        if response.message_kind != decision::KIND_INTERCEPTION_DECISION {
            return Err(format!(
                "runtime interception broker returned unexpected response `{}` to InterceptionRequest",
                response.message_kind
            ));
        }
        decode_interception_decision(&response.payload)
    }

    pub(super) fn request_lifecycle(
        &mut self,
        event: &GuardLifecycleEvent,
    ) -> Result<GuardLifecycleReply, String> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1);
        let envelope = Envelope {
            message_id,
            correlation_id: 1,
            message_kind: String::from(request::KIND_GUARD_LIFECYCLE_EVENT),
            payload: encode_guard_lifecycle_event(event),
            headers: Vec::new(),
        };
        write_envelope(&mut self.stream, &envelope)?;

        let response = read_envelope(&mut self.stream)?;
        if response.message_kind != decision::KIND_GUARD_LIFECYCLE_REPLY {
            return Err(format!(
                "runtime interception broker returned unexpected response `{}` to GuardLifecycleEvent",
                response.message_kind
            ));
        }
        decode_guard_lifecycle_reply(&response.payload)
    }
}
