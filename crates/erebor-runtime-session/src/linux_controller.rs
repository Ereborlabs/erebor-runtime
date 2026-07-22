use std::{
    io::{BufRead, Write},
    sync::mpsc,
    thread,
    time::Duration,
};

use erebor_runtime_core::DaemonFailureMode;
use snafu::ResultExt;

use crate::{
    controller_support::{linux::LinuxWorkload, output::HelperOutput, workload::WorkloadExit},
    error::session_controller::{CommandChannelSnafu, InvalidHandoffSnafu, ProtocolSnafu},
    runners::linux::{
        LinuxControllerCommand, LinuxControllerEvent, LinuxControllerHandoff,
        LINUX_CONTROLLER_PROTOCOL_VERSION,
    },
    SessionControllerError,
};

pub fn run_linux_session_controller() -> Result<(), SessionControllerError> {
    let standard_input = std::io::stdin();
    let handoff: LinuxControllerHandoff = read_json_line(&mut standard_input.lock())?;
    validate_handoff(&handoff)?;
    let output = HelperOutput::open(&handoff)?;
    let mut workload = LinuxWorkload::start(&handoff, &output)?;
    output.record_event(
        "workload_started",
        serde_json::json!({"stable_identity": workload.stable_identity()}),
    )?;
    write_event(&LinuxControllerEvent::Started {
        workload_identity: workload.stable_identity().to_owned(),
        controller_pid: std::process::id(),
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
                write_event(&LinuxControllerEvent::Exited {
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
                        write_event(&LinuxControllerEvent::Exited {
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
    workload: &mut LinuxWorkload,
    failure: SessionControllerError,
    control_connected: bool,
) {
    let _result = workload.kill(erebor_runtime_core::ActiveSessionSignal::Kill);
    if control_connected {
        let _result = write_event(&LinuxControllerEvent::Failed {
            reason: failure.to_string(),
        });
    }
}

fn apply_command(
    workload: &mut LinuxWorkload,
    command: LinuxControllerCommand,
) -> Result<Option<WorkloadExit>, SessionControllerError> {
    match command {
        LinuxControllerCommand::Stop { grace_period_ms } => {
            let exit = workload.stop(Duration::from_millis(grace_period_ms))?;
            Ok(Some(exit))
        }
        LinuxControllerCommand::Kill { signal } => {
            let exit = workload.kill(signal)?;
            Ok(Some(exit))
        }
        LinuxControllerCommand::Input { data } => {
            let accepted_bytes = u32::try_from(data.len()).map_err(|_error| {
                SessionControllerError::InvalidHandoff {
                    reason: String::from("interactive input exceeds the controller protocol limit"),
                    location: snafu::Location::default(),
                }
            })?;
            workload.write_input(&data)?;
            write_event(&LinuxControllerEvent::InputAccepted { accepted_bytes })?;
            Ok(None)
        }
        LinuxControllerCommand::CloseInput => {
            workload.close_input();
            write_event(&LinuxControllerEvent::InputClosed)?;
            Ok(None)
        }
        LinuxControllerCommand::Health => {
            write_event(&LinuxControllerEvent::Health {
                running: workload.try_wait()?.is_none(),
            })?;
            Ok(None)
        }
    }
}

fn validate_handoff(handoff: &LinuxControllerHandoff) -> Result<(), SessionControllerError> {
    if handoff.protocol_version != LINUX_CONTROLLER_PROTOCOL_VERSION {
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
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return InvalidHandoffSnafu {
            reason: String::from("Linux-host controller is unavailable on this platform"),
        }
        .fail();
    }
    Ok(())
}

enum ControlInput {
    Command(LinuxControllerCommand),
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
) -> Result<T, SessionControllerError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|source| SessionControllerError::Io {
            action: "reading startup handoff",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    serde_json::from_str(&line).context(ProtocolSnafu)
}

fn write_event(event: &LinuxControllerEvent) -> Result<(), SessionControllerError> {
    let standard_output = std::io::stdout();
    let mut output = standard_output.lock();
    serde_json::to_writer(&mut output, event).context(ProtocolSnafu)?;
    output
        .write_all(b"\n")
        .map_err(|source| SessionControllerError::Io {
            action: "writing controller event",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    output.flush().map_err(|source| SessionControllerError::Io {
        action: "flushing controller event",
        path: std::path::PathBuf::from("<inherited-control>"),
        source,
        location: snafu::Location::default(),
    })
}
