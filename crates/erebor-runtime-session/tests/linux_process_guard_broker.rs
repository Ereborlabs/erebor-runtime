#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use erebor_runtime_ipc::{
    v1::{
        AllowDecision, DecisionKind, Envelope, GuardHelloAck, GuardLifecycleEvent,
        GuardLifecycleEventKind, GuardLifecycleReply, GuardLifecycleReplyKind,
        InterceptionDecision, KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, KIND_GUARD_LIFECYCLE_EVENT,
        KIND_GUARD_LIFECYCLE_REPLY, KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST,
        PROTOCOL_VERSION,
    },
    EreborIpcFrame, HEADER_LEN,
};

#[test]
fn process_guard_uses_one_broker_socket_for_lifecycle_and_physical_effects(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let socket_path = root.path().join("broker.sock");
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let marker = root.path().join("effect-after-hook-exit");
    let hook_tracked = root.path().join("hook-tracked");
    let server_marker = marker.clone();
    let server_hook_tracked = hook_tracked.clone();
    let server =
        thread::spawn(move || serve_guard_connection(listener, server_marker, server_hook_tracked));

    let guard_path = env!("EREBOR_BUILD_LINUX_PROCESS_GUARD");
    let script = format!(
        "/usr/bin/sleep 0.4 & while [ ! -e {} ]; do :; done; /usr/bin/touch {}",
        shell_word(&hook_tracked),
        shell_word(&marker),
    );
    let mut child = Command::new(guard_path)
        .args(["/bin/sh", "-c", &script])
        .env("EREBOR_RUNTIME_INTERCEPTION_PATH", &socket_path)
        .env("EREBOR_RUNTIME_INTERCEPTION_TOKEN", "test-token")
        .env("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS", "5000")
        .env("EREBOR_SESSION_ID", "guard-one-socket-test")
        .env("EREBOR_ACTOR_ID", "test-agent")
        .env(
            "EREBOR_GUARD_INTERCEPTION_OPERATIONS",
            "process_exec,file_mutation",
        )
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _result = child.kill();
            return Err("process guard did not release the held physical effect".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let evidence = server
        .join()
        .map_err(|_error| "guard broker test server panicked")?
        .map_err(|error| error.to_string())?;

    assert!(status.success());
    assert!(evidence.saw_hello);
    assert!(evidence.saw_lifecycle_exec);
    assert!(evidence.saw_lifecycle_exit);
    assert!(evidence.saw_physical_effect_request);
    assert!(evidence.marker_absent_at_hook_exit);
    assert_eq!(evidence.accepted_connections, 1);
    assert!(fs::metadata(marker).is_ok());
    Ok(())
}

#[derive(Default)]
struct GuardEvidence {
    accepted_connections: usize,
    saw_hello: bool,
    saw_lifecycle_exec: bool,
    saw_lifecycle_exit: bool,
    saw_physical_effect_request: bool,
    marker_absent_at_hook_exit: bool,
}

fn serve_guard_connection(
    listener: UnixListener,
    marker: PathBuf,
    hook_tracked: PathBuf,
) -> Result<GuardEvidence, Box<dyn std::error::Error + Send + Sync>> {
    let (mut stream, _address) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(6)))?;
    let mut evidence = GuardEvidence {
        accepted_connections: 1,
        ..GuardEvidence::default()
    };
    let mut tracked_hook_pid = None;

    while let Ok(envelope) = read_envelope(&mut stream) {
        match envelope.message_kind.as_str() {
            KIND_GUARD_HELLO => {
                evidence.saw_hello = true;
                write_envelope(
                    &mut stream,
                    Envelope::wrap_message(
                        envelope.message_id.saturating_add(1),
                        envelope.message_id,
                        KIND_GUARD_HELLO_ACK,
                        &GuardHelloAck {
                            protocol_version: PROTOCOL_VERSION,
                            broker_id: String::from("test-broker"),
                            accepted: true,
                            reason: String::from("accepted"),
                        },
                    )?,
                )?;
            }
            KIND_GUARD_LIFECYCLE_EVENT => {
                let event: GuardLifecycleEvent =
                    envelope.decode_typed_payload(KIND_GUARD_LIFECYCLE_EVENT)?;
                let kind = GuardLifecycleEventKind::try_from(event.event).ok();
                let reply_kind = match kind {
                    Some(GuardLifecycleEventKind::Exec)
                        if event
                            .exec_history
                            .last()
                            .is_some_and(|path| path.ends_with("/sleep")) =>
                    {
                        evidence.saw_lifecycle_exec = true;
                        tracked_hook_pid = Some(event.pid);
                        fs::write(&hook_tracked, "tracked")?;
                        GuardLifecycleReplyKind::Hold
                    }
                    Some(GuardLifecycleEventKind::Exit)
                        if Some(event.pid) == tracked_hook_pid && event.exited_successfully =>
                    {
                        evidence.saw_lifecycle_exit = true;
                        evidence.marker_absent_at_hook_exit = !marker.exists();
                        GuardLifecycleReplyKind::Release
                    }
                    _ => GuardLifecycleReplyKind::Ignore,
                };
                write_envelope(
                    &mut stream,
                    Envelope::wrap_message(
                        envelope.message_id.saturating_add(1),
                        event.request_id,
                        KIND_GUARD_LIFECYCLE_REPLY,
                        &GuardLifecycleReply {
                            request_id: event.request_id,
                            decision: reply_kind as i32,
                            reason: String::from("test lifecycle reply"),
                        },
                    )?,
                )?;
            }
            KIND_INTERCEPTION_REQUEST => {
                evidence.saw_physical_effect_request = true;
                let request: erebor_runtime_ipc::v1::InterceptionRequest =
                    envelope.decode_typed_payload(KIND_INTERCEPTION_REQUEST)?;
                write_envelope(
                    &mut stream,
                    Envelope::wrap_message(
                        envelope.message_id.saturating_add(1),
                        request.request_id,
                        KIND_INTERCEPTION_DECISION,
                        &InterceptionDecision {
                            request_id: request.request_id,
                            decision: DecisionKind::Allow as i32,
                            rule_id: String::from("test-allow"),
                            reason: String::from("test broker allowed physical effect"),
                            timeout_ms: 25,
                            allow: Some(AllowDecision {
                                exec_target: String::new(),
                            }),
                            deny: None,
                            mediate: None,
                        },
                    )?,
                )?;
            }
            other => return Err(format!("unexpected guard message `{other}`").into()),
        }
    }

    listener.set_nonblocking(true)?;
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_stream, _address)) => evidence.accepted_connections += 1,
        Err(error) => return Err(error.into()),
    }
    Ok(evidence)
}

fn read_envelope(
    stream: &mut UnixStream,
) -> Result<Envelope, Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header)?;
    let payload_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_LEN + payload_len, 0);
    stream.read_exact(&mut frame[HEADER_LEN..])?;
    Ok(EreborIpcFrame::decode(&frame)?.decode_payload()?)
}

fn write_envelope(
    stream: &mut UnixStream,
    envelope: Envelope,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.write_all(&envelope.into_frame()?.encode()?)?;
    Ok(())
}

fn shell_word(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}
