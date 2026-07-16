use std::{fmt, sync::Arc};

use erebor_runtime_core::{
    FileInterceptionOperationKind, FileInterceptionRequest, FileOperationSurfaceHandler,
    FileResolvedIdentity, ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
    SocketConnectInterceptionRequest, SocketConnectSurfaceHandler, SurfaceInterceptionDecision,
};
use erebor_runtime_ipc::v1::{
    operation_name, FileOperationKind, GuardLifecycleEvent, GuardLifecycleReply,
    GuardLifecycleReplyKind, InterceptionOperation, InterceptionRequest, SocketOperationKind,
};

use crate::agents::codex::CodexInvocationLeaseOwner;

#[derive(Debug)]
pub(super) struct SessionRegistration {
    pub(super) token: String,
    pub(super) broker_id: String,
    pub(super) router: SessionInterceptionRouter,
}

#[derive(Clone, Default)]
pub struct SessionInterceptionRouter {
    process_exec: Option<Arc<dyn ProcessExecSurfaceHandler>>,
    file_operation: Option<Arc<dyn FileOperationSurfaceHandler>>,
    socket_connect: Option<Arc<dyn SocketConnectSurfaceHandler>>,
    codex_invocation_lease_owner: Option<Arc<CodexInvocationLeaseOwner>>,
    lifecycle: Option<Arc<dyn GuardLifecycleHandler>>,
}

/// Session-owned interpretation of a generic process-guard lifecycle fact.
///
/// The Linux guard only observes process state and applies the reply. Agent
/// integrations recognize their own managed processes behind this broker seam.
pub(crate) trait GuardLifecycleHandler: Send + Sync {
    fn decide_guard_lifecycle(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply;
}

pub(super) enum RoutedInterception {
    Decision(SurfaceInterceptionDecision),
    Unrouted {
        rule_id: &'static str,
        reason: String,
    },
}

impl SessionInterceptionRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_process_exec_handler(
        mut self,
        handler: impl ProcessExecSurfaceHandler + 'static,
    ) -> Self {
        self.process_exec = Some(Arc::new(handler));
        self
    }

    #[must_use]
    pub fn with_file_operation_handler(
        mut self,
        handler: impl FileOperationSurfaceHandler + 'static,
    ) -> Self {
        self.file_operation = Some(Arc::new(handler));
        self
    }

    #[must_use]
    pub fn with_socket_connect_handler(
        mut self,
        handler: impl SocketConnectSurfaceHandler + 'static,
    ) -> Self {
        self.socket_connect = Some(Arc::new(handler));
        self
    }

    #[must_use]
    pub(crate) fn with_codex_invocation_lease_owner(
        mut self,
        owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        self.codex_invocation_lease_owner = Some(owner);
        self
    }

    #[must_use]
    pub(crate) fn with_guard_lifecycle_handler(
        mut self,
        handler: impl GuardLifecycleHandler + 'static,
    ) -> Self {
        self.lifecycle = Some(Arc::new(handler));
        self
    }

    pub(super) fn route_interception(&self, request: &InterceptionRequest) -> RoutedInterception {
        if let Some(decision) = self
            .codex_invocation_lease_owner
            .as_ref()
            .and_then(|owner| owner.physical_effect_decision(request))
        {
            return RoutedInterception::Decision(decision);
        }
        match request.operation_family() {
            InterceptionOperation::ProcessExec => self.route_process_exec(request),
            InterceptionOperation::FileOpen
            | InterceptionOperation::FileRead
            | InterceptionOperation::FileMutation => self.route_file_operation(request),
            InterceptionOperation::SocketConnect => self.route_socket_connect(request),
            InterceptionOperation::Unspecified => RoutedInterception::Unrouted {
                rule_id: "erebor-runtime-interception-broker-unspecified-operation",
                reason: String::from("interception request did not specify an operation family"),
            },
        }
    }

    pub(super) fn route_guard_lifecycle(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        self.lifecycle.as_ref().map_or_else(
            || GuardLifecycleReply {
                request_id: event.request_id,
                decision: GuardLifecycleReplyKind::Ignore as i32,
                reason: String::from("no managed lifecycle handler recognized this process"),
            },
            |handler| handler.decide_guard_lifecycle(event),
        )
    }

    fn route_process_exec(&self, request: &InterceptionRequest) -> RoutedInterception {
        let payload = request.process_exec.as_ref();
        let executable = payload
            .map(|operation| operation.executable.as_str())
            .filter(|executable| !executable.is_empty())
            .unwrap_or(&request.executable);
        let argv = payload
            .map(|operation| operation.argv.as_slice())
            .filter(|argv| !argv.is_empty())
            .unwrap_or(&request.argv);
        let matched_handler_id = payload
            .map(|operation| operation.matched_handler_id.as_str())
            .filter(|handler_id| !handler_id.is_empty())
            .unwrap_or(&request.matched_handler_id);
        let process_exec_request =
            ProcessExecInterceptionRequest::new(executable, argv, matched_handler_id);
        self.process_exec
            .as_ref()
            .map(|handler| {
                RoutedInterception::Decision(handler.decide_process_exec(&process_exec_request))
            })
            .unwrap_or_else(|| unrouted_operation("process_exec"))
    }

    fn route_file_operation(&self, request: &InterceptionRequest) -> RoutedInterception {
        let Some(file) = request.file.as_ref() else {
            return missing_payload(request.operation_family(), "file");
        };
        let Some(operation) = file_operation_kind(file.kind) else {
            return missing_payload(request.operation_family(), "file.kind");
        };
        if Some(operation) != file_operation_family(request.operation_family()) {
            return invalid_payload(
                request.operation_family(),
                "file.kind",
                "does not match operation family",
            );
        }
        let mut file_request = FileInterceptionRequest::new(
            operation,
            &file.path,
            &request.cwd,
            request.pid,
            request.ppid,
        );
        if let Some(identity) = file.resolved_identity.as_ref() {
            file_request = file_request
                .with_resolved_identity(FileResolvedIdentity::new(identity.device, identity.inode));
        }
        self.file_operation
            .as_ref()
            .map(|handler| {
                RoutedInterception::Decision(handler.decide_file_operation(&file_request))
            })
            .unwrap_or_else(|| unrouted_operation(operation.as_str()))
    }

    fn route_socket_connect(&self, request: &InterceptionRequest) -> RoutedInterception {
        let Some(socket) = request.socket.as_ref() else {
            return missing_payload(request.operation_family(), "socket");
        };
        if SocketOperationKind::try_from(socket.kind).ok() != Some(SocketOperationKind::Connect) {
            return missing_payload(request.operation_family(), "socket.kind");
        }
        let socket_request = SocketConnectInterceptionRequest::new(
            &socket.scheme,
            &socket.host,
            socket.port,
            &socket.path,
            &request.cwd,
            request.pid,
            request.ppid,
        );
        self.socket_connect
            .as_ref()
            .map(|handler| {
                RoutedInterception::Decision(handler.decide_socket_connect(&socket_request))
            })
            .unwrap_or_else(|| unrouted_operation("socket_connect"))
    }
}

fn file_operation_kind(kind: i32) -> Option<FileInterceptionOperationKind> {
    match FileOperationKind::try_from(kind).ok()? {
        FileOperationKind::Open => Some(FileInterceptionOperationKind::Open),
        FileOperationKind::Read => Some(FileInterceptionOperationKind::Read),
        FileOperationKind::Mutation => Some(FileInterceptionOperationKind::Mutation),
        FileOperationKind::Unspecified => None,
    }
}

fn file_operation_family(
    operation: InterceptionOperation,
) -> Option<FileInterceptionOperationKind> {
    match operation {
        InterceptionOperation::FileOpen => Some(FileInterceptionOperationKind::Open),
        InterceptionOperation::FileRead => Some(FileInterceptionOperationKind::Read),
        InterceptionOperation::FileMutation => Some(FileInterceptionOperationKind::Mutation),
        _ => None,
    }
}

fn missing_payload(operation: InterceptionOperation, payload: &'static str) -> RoutedInterception {
    let operation = operation_name(operation);
    RoutedInterception::Unrouted {
        rule_id: "erebor-runtime-interception-broker-invalid-operation-payload",
        reason: format!("interception request for {operation} is missing `{payload}` payload"),
    }
}

fn invalid_payload(
    operation: InterceptionOperation,
    payload: &'static str,
    reason: &'static str,
) -> RoutedInterception {
    let operation = operation_name(operation);
    RoutedInterception::Unrouted {
        rule_id: "erebor-runtime-interception-broker-invalid-operation-payload",
        reason: format!("interception request for {operation} has invalid `{payload}`: {reason}"),
    }
}

fn unrouted_operation(operation: &'static str) -> RoutedInterception {
    let rule_id = if operation == "process_exec" {
        "erebor-runtime-interception-broker-unrouted-process-exec"
    } else {
        "erebor-runtime-interception-broker-unrouted-operation"
    };
    RoutedInterception::Unrouted {
        rule_id,
        reason: format!("no surface is registered for {operation} interception"),
    }
}

impl fmt::Debug for SessionInterceptionRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionInterceptionRouter")
            .field(
                "process_exec",
                &self.process_exec.as_ref().map(|handler| handler.surface()),
            )
            .field(
                "file_operation",
                &self
                    .file_operation
                    .as_ref()
                    .map(|handler| handler.surface()),
            )
            .field(
                "socket_connect",
                &self
                    .socket_connect
                    .as_ref()
                    .map(|handler| handler.surface()),
            )
            .field(
                "codex_invocation_lease_owner",
                &self.codex_invocation_lease_owner.is_some(),
            )
            .field("lifecycle", &self.lifecycle.is_some())
            .finish()
    }
}
