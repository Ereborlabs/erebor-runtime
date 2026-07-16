use crate::v1;

use super::{
    super::{
        request::{encode_guard_hello, encode_guard_lifecycle_event, encode_interception_request},
        FileIdentity, FileOperation, FileOperationKind, GuardHello, GuardLifecycleEvent,
        GuardLifecycleEventKind, InterceptionOperation, InterceptionRequest, InterceptionSource,
    },
    decode_prost,
};

#[test]
fn standalone_guard_hello_encoding_matches_canonical_prost_contract() -> Result<(), String> {
    let hello = GuardHello {
        session_id: String::from("session-fixture"),
        actor_id: String::from("openclaw"),
        guard_pid: 42,
        runner_kind: String::from("linux_host"),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    };

    let decoded: v1::GuardHello = decode_prost(&encode_guard_hello(&hello))?;

    assert_eq!(decoded.protocol_version, v1::PROTOCOL_VERSION);
    assert_eq!(decoded.session_id, hello.session_id);
    assert_eq!(decoded.actor_id, hello.actor_id);
    assert_eq!(decoded.guard_pid, hello.guard_pid);
    assert_eq!(decoded.runner_kind, hello.runner_kind);
    assert_eq!(decoded.platform, hello.platform);
    assert_eq!(decoded.capabilities, hello.capabilities);
    Ok(())
}

#[test]
fn interception_request_encoding_omits_session_identity() {
    let request = InterceptionRequest {
        request_id: 7,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Shim,
        pid: 10,
        ppid: 9,
        executable: String::from("google-chrome"),
        argv: vec![String::from("google-chrome")],
        cwd: String::from("/tmp"),
        matched_handler_id: String::from("managed-browser"),
        timestamp: String::from("unix:1"),
        operation: InterceptionOperation::ProcessExec,
        file: None,
    };

    let encoded = encode_interception_request(&request);

    assert!(encoded
        .windows("openclaw".len())
        .any(|window| window == b"openclaw"));
    assert!(!encoded
        .windows("session".len())
        .any(|window| window == b"session"));
}

#[test]
fn file_interception_request_encodes_operation_and_identity() {
    let request = InterceptionRequest {
        request_id: 8,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace,
        pid: 11,
        ppid: 10,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        matched_handler_id: String::new(),
        timestamp: String::from("unix:2"),
        operation: InterceptionOperation::FileRead,
        file: Some(FileOperation {
            kind: FileOperationKind::Read,
            path: String::from("/workspace/secret.txt"),
            resolved_identity: Some(FileIdentity {
                device: 123,
                inode: 456,
            }),
        }),
    };

    let encoded = encode_interception_request(&request);

    assert!(encoded
        .windows("secret.txt".len())
        .any(|window| window == b"secret.txt"));
    assert!(encoded
        .windows(2)
        .any(|window| window == [13 << 3, InterceptionOperation::FileRead.as_i32() as u8]));
}

#[test]
fn standalone_interception_request_encoding_matches_canonical_prost_contract() -> Result<(), String>
{
    let request = InterceptionRequest {
        request_id: 8,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace,
        pid: 11,
        ppid: 10,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        matched_handler_id: String::new(),
        timestamp: String::from("unix:2"),
        operation: InterceptionOperation::FileRead,
        file: Some(FileOperation {
            kind: FileOperationKind::Read,
            path: String::from("/workspace/secret.txt"),
            resolved_identity: Some(FileIdentity {
                device: 123,
                inode: 456,
            }),
        }),
    };

    let decoded: v1::InterceptionRequest = decode_prost(&encode_interception_request(&request))?;
    let file = decoded
        .file
        .ok_or_else(|| String::from("missing decoded file operation"))?;
    let identity = file
        .resolved_identity
        .ok_or_else(|| String::from("missing decoded file identity"))?;

    assert_eq!(decoded.request_id, request.request_id);
    assert_eq!(decoded.actor_id, request.actor_id);
    assert_eq!(decoded.source, v1::InterceptionSource::Ptrace as i32);
    assert_eq!(decoded.pid, request.pid);
    assert_eq!(decoded.ppid, request.ppid);
    assert_eq!(decoded.cwd, request.cwd);
    assert_eq!(decoded.timestamp, request.timestamp);
    assert_eq!(
        decoded.operation,
        v1::InterceptionOperation::FileRead as i32
    );
    assert_eq!(file.kind, v1::FileOperationKind::Read as i32);
    assert_eq!(file.path, "/workspace/secret.txt");
    assert_eq!(identity.device, 123);
    assert_eq!(identity.inode, 456);
    Ok(())
}

#[test]
fn standalone_guard_lifecycle_event_encoding_matches_canonical_prost_contract() -> Result<(), String>
{
    let event = GuardLifecycleEvent {
        request_id: 19,
        kind: GuardLifecycleEventKind::Exec,
        pid: 401,
        exec_history: vec![
            String::from("/bin/sh"),
            String::from("/usr/lib/erebor/hook"),
        ],
        parent_pid: 400,
        child_pid: 0,
        exited_successfully: false,
    };

    let decoded: v1::GuardLifecycleEvent = decode_prost(&encode_guard_lifecycle_event(&event))?;

    assert_eq!(decoded.request_id, event.request_id);
    assert_eq!(decoded.event, v1::GuardLifecycleEventKind::Exec as i32);
    assert_eq!(decoded.pid, event.pid);
    assert_eq!(decoded.exec_history, event.exec_history);
    assert_eq!(decoded.parent_pid, event.parent_pid);
    assert_eq!(decoded.child_pid, event.child_pid);
    assert!(!decoded.exited_successfully);
    Ok(())
}
