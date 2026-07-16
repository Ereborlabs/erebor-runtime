use super::{
    codec::{write_bytes_field, write_string_field, write_varint_field, PROTOCOL_VERSION},
    file, GuardHello, GuardLifecycleEvent, InterceptionOperation, InterceptionRequest,
};

pub(super) const KIND_GUARD_HELLO: &str = "erebor.runtime.ipc.v1.GuardHello";
pub(super) const KIND_INTERCEPTION_REQUEST: &str = "erebor.runtime.ipc.v1.InterceptionRequest";
pub(super) const KIND_GUARD_LIFECYCLE_EVENT: &str = "erebor.runtime.ipc.v1.GuardLifecycleEvent";

pub(super) fn encode_guard_hello(hello: &GuardHello) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, PROTOCOL_VERSION as u64);
    write_string_field(&mut output, 2, &hello.session_id);
    write_string_field(&mut output, 3, &hello.actor_id);
    write_varint_field(&mut output, 4, hello.guard_pid as u64);
    write_string_field(&mut output, 5, &hello.runner_kind);
    write_string_field(&mut output, 6, &hello.platform);
    for capability in &hello.capabilities {
        write_string_field(&mut output, 7, capability);
    }
    output
}

pub(super) fn encode_interception_request(request: &InterceptionRequest) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, request.request_id);
    write_string_field(&mut output, 2, &request.actor_id);
    write_varint_field(&mut output, 3, request.source.as_i32() as u64);
    write_varint_field(&mut output, 4, request.pid as u64);
    write_varint_field(&mut output, 5, request.ppid as u64);
    write_string_field(&mut output, 6, &request.executable);
    for argument in &request.argv {
        write_string_field(&mut output, 7, argument);
    }
    write_string_field(&mut output, 8, &request.cwd);
    write_string_field(&mut output, 11, &request.matched_handler_id);
    write_string_field(&mut output, 12, &request.timestamp);
    if request.operation != InterceptionOperation::Unspecified {
        write_varint_field(&mut output, 13, request.operation.as_i32() as u64);
    }
    if let Some(file) = request.file.as_ref() {
        write_bytes_field(&mut output, 15, &file::encode_file_operation(file));
    }
    output
}

pub(super) fn encode_guard_lifecycle_event(event: &GuardLifecycleEvent) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, event.request_id);
    write_varint_field(&mut output, 2, event.kind.as_i32() as u64);
    write_varint_field(&mut output, 3, event.pid as u64);
    for executable in &event.exec_history {
        write_string_field(&mut output, 4, executable);
    }
    if event.parent_pid != 0 {
        write_varint_field(&mut output, 5, event.parent_pid as u64);
    }
    if event.child_pid != 0 {
        write_varint_field(&mut output, 6, event.child_pid as u64);
    }
    if event.exited_successfully {
        write_varint_field(&mut output, 7, 1);
    }
    output
}
