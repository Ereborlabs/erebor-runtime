mod docker;
mod linux;
mod output;
mod workload;

use std::{
    io::{BufRead, Write},
    sync::mpsc,
    thread,
    time::Duration,
};

use erebor_runtime_core::{
    DaemonFailureMode, SessionHelperCommand, SessionHelperEvent, SessionHelperHandoff,
    SessionRunnerKind, SESSION_HELPER_PROTOCOL_VERSION,
};
use snafu::ResultExt;

use crate::{
    error::session_helper::{CommandChannelSnafu, InvalidHandoffSnafu, ProtocolSnafu},
    session_helper::{output::HelperOutput, workload::HelperWorkload},
    SessionHelperError,
};

pub fn run_session_helper() -> Result<(), SessionHelperError> {
    let standard_input = std::io::stdin();
    let handoff: SessionHelperHandoff = read_json_line(&mut standard_input.lock())?;
    validate_handoff(&handoff)?;
    let output = HelperOutput::open(&handoff)?;
    let mut workload = HelperWorkload::start(&handoff, &output)?;
    output.record_event(
        "workload_started",
        serde_json::json!({"stable_identity": workload.stable_identity()}),
    )?;
    write_event(&SessionHelperEvent::Started {
        stable_identity: workload.stable_identity().to_owned(),
        helper_pid: std::process::id(),
    })?;

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let standard_input = std::io::stdin();
        command_reader(standard_input.lock(), sender);
    });
    let mut control_connected = true;
    loop {
        if let Some(failure) = workload.take_output_failure() {
            fail_closed_for_output(&mut workload, failure, control_connected);
            return Ok(());
        }
        if let Some(exit) = workload.try_wait()? {
            if let Some(failure) = workload.take_output_failure() {
                fail_closed_for_output(&mut workload, failure, control_connected);
                return Ok(());
            }
            output.finish(exit.exit_code, exit.signal)?;
            if control_connected {
                write_event(&SessionHelperEvent::Exited {
                    exit_code: exit.exit_code,
                    signal: exit.signal,
                })?;
            }
            return Ok(());
        }
        match receiver.try_recv() {
            Ok(ControlInput::Command(command)) => {
                if let Some(exit) = apply_command(&mut workload, command)? {
                    if let Some(failure) = workload.take_output_failure() {
                        fail_closed_for_output(&mut workload, failure, control_connected);
                        return Ok(());
                    }
                    output.finish(exit.exit_code, exit.signal)?;
                    if control_connected {
                        write_event(&SessionHelperEvent::Exited {
                            exit_code: exit.exit_code,
                            signal: exit.signal,
                        })?;
                    }
                    return Ok(());
                }
            }
            Ok(ControlInput::Eof) => {
                control_connected = false;
                output.record_event("daemon_control_lost", serde_json::json!({}))?;
                if handoff.spec.daemon_failure_mode() == DaemonFailureMode::Terminate {
                    let exit =
                        workload.stop(Duration::from_secs(handoff.spec.loss_grace_seconds()))?;
                    output.finish(exit.exit_code, exit.signal)?;
                    return Ok(());
                }
            }
            Ok(ControlInput::Failed(reason)) => {
                return InvalidHandoffSnafu {
                    reason: format!("control channel failed: {reason}"),
                }
                .fail();
            }
            Err(mpsc::TryRecvError::Disconnected) if control_connected => {
                return CommandChannelSnafu.fail();
            }
            Err(mpsc::TryRecvError::Disconnected | mpsc::TryRecvError::Empty) => {}
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn fail_closed_for_output(
    workload: &mut HelperWorkload,
    failure: SessionHelperError,
    control_connected: bool,
) {
    let _result = workload.kill(erebor_runtime_core::ActiveSessionSignal::Kill);
    if control_connected {
        let _result = write_event(&SessionHelperEvent::Failed {
            reason: failure.to_string(),
        });
    }
}

fn apply_command(
    workload: &mut HelperWorkload,
    command: SessionHelperCommand,
) -> Result<Option<workload::WorkloadExit>, SessionHelperError> {
    match command {
        SessionHelperCommand::Stop { grace_period_ms } => {
            let exit = workload.stop(Duration::from_millis(grace_period_ms))?;
            Ok(Some(exit))
        }
        SessionHelperCommand::Kill { signal } => {
            let exit = workload.kill(signal)?;
            Ok(Some(exit))
        }
        SessionHelperCommand::Health => {
            write_event(&SessionHelperEvent::Health {
                running: workload.try_wait()?.is_none(),
            })?;
            Ok(None)
        }
    }
}

fn validate_handoff(handoff: &SessionHelperHandoff) -> Result<(), SessionHelperError> {
    if handoff.protocol_version != SESSION_HELPER_PROTOCOL_VERSION {
        return InvalidHandoffSnafu {
            reason: format!("unsupported protocol version {}", handoff.protocol_version),
        }
        .fail();
    }
    handoff.spec.validate().map_err(|error| {
        InvalidHandoffSnafu {
            reason: error.to_string(),
        }
        .build()
    })?;
    if handoff.spec.runner_capability().runner() == SessionRunnerKind::LinuxHost
        && !cfg!(all(target_os = "linux", target_arch = "x86_64"))
    {
        return InvalidHandoffSnafu {
            reason: String::from("Linux-host helper is unavailable on this platform"),
        }
        .fail();
    }
    Ok(())
}

enum ControlInput {
    Command(SessionHelperCommand),
    Eof,
    Failed(String),
}

fn command_reader(mut input: impl BufRead, sender: mpsc::Sender<ControlInput>) {
    loop {
        let mut line = String::new();
        match input.read_line(&mut line) {
            Ok(0) => {
                let _result = sender.send(ControlInput::Eof);
                return;
            }
            Ok(_) => match serde_json::from_str(&line) {
                Ok(command) => {
                    if sender.send(ControlInput::Command(command)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _result = sender.send(ControlInput::Failed(error.to_string()));
                    return;
                }
            },
            Err(error) => {
                let _result = sender.send(ControlInput::Failed(error.to_string()));
                return;
            }
        }
    }
}

fn read_json_line<T: for<'de> serde::Deserialize<'de>>(
    reader: &mut impl BufRead,
) -> Result<T, SessionHelperError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|source| SessionHelperError::Io {
            action: "reading startup handoff",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    serde_json::from_str(&line).context(ProtocolSnafu)
}

fn write_event(event: &SessionHelperEvent) -> Result<(), SessionHelperError> {
    let standard_output = std::io::stdout();
    let mut output = standard_output.lock();
    serde_json::to_writer(&mut output, event).context(ProtocolSnafu)?;
    output
        .write_all(b"\n")
        .map_err(|source| SessionHelperError::Io {
            action: "writing helper control event",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    output.flush().map_err(|source| SessionHelperError::Io {
        action: "flushing helper control event",
        path: std::path::PathBuf::from("<inherited-control>"),
        source,
        location: snafu::Location::default(),
    })
}
