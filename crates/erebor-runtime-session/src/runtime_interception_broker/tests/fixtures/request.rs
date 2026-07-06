use erebor_runtime_ipc::v1::{
    FileOperation, FileOperationKind, InterceptionOperation, InterceptionRequest,
    InterceptionSource, ProcessExecOperation, SocketOperation, SocketOperationKind,
};

pub(crate) struct InterceptionRequestFixture;

impl InterceptionRequestFixture {
    pub(crate) fn process(handler_id: &str) -> InterceptionRequest {
        Self::process_with_argv(handler_id, &[String::from("tool")])
    }

    pub(crate) fn process_with_argv(handler_id: &str, argv: &[String]) -> InterceptionRequest {
        InterceptionRequest {
            request_id: 7,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Shim as i32,
            pid: 100,
            ppid: 99,
            executable: argv
                .first()
                .cloned()
                .unwrap_or_else(|| String::from("tool")),
            argv: argv.to_vec(),
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: handler_id.to_owned(),
            timestamp: String::from("unix:1"),
            operation: InterceptionOperation::ProcessExec as i32,
            process_exec: Some(ProcessExecOperation {
                executable: argv
                    .first()
                    .cloned()
                    .unwrap_or_else(|| String::from("tool")),
                argv: argv.to_vec(),
                requested_endpoint: None,
                matched_handler_id: handler_id.to_owned(),
            }),
            file: None,
            socket: None,
        }
    }

    pub(crate) fn file(kind: FileOperationKind, path: &str) -> InterceptionRequest {
        InterceptionRequest {
            request_id: 11,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Ptrace as i32,
            pid: 100,
            ppid: 99,
            executable: String::new(),
            argv: Vec::new(),
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: String::new(),
            timestamp: String::from("unix:1"),
            operation: match kind {
                FileOperationKind::Open => InterceptionOperation::FileOpen,
                FileOperationKind::Read => InterceptionOperation::FileRead,
                FileOperationKind::Mutation => InterceptionOperation::FileMutation,
                FileOperationKind::Unspecified => InterceptionOperation::Unspecified,
            } as i32,
            process_exec: None,
            file: Some(FileOperation {
                kind: kind as i32,
                path: path.to_owned(),
                resolved_identity: None,
            }),
            socket: None,
        }
    }

    pub(crate) fn socket_connect(host: &str, port: u32) -> InterceptionRequest {
        InterceptionRequest {
            request_id: 12,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Ptrace as i32,
            pid: 100,
            ppid: 99,
            executable: String::new(),
            argv: Vec::new(),
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: String::new(),
            timestamp: String::from("unix:1"),
            operation: InterceptionOperation::SocketConnect as i32,
            process_exec: None,
            file: None,
            socket: Some(SocketOperation {
                kind: SocketOperationKind::Connect as i32,
                scheme: String::from("tcp"),
                host: host.to_owned(),
                port,
                path: String::new(),
            }),
        }
    }
}
