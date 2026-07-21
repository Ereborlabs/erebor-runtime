use std::{
    io::{BufRead, Write},
    sync::mpsc,
    thread,
    time::Duration,
};

use erebor_runtime_core::DaemonFailureMode;
use snafu::ResultExt;

use crate::{
    controller_support::{docker::DockerWorkload, output::HelperOutput, workload::WorkloadExit},
    error::session_controller::{CommandChannelSnafu, InvalidHandoffSnafu, ProtocolSnafu},
    runners::docker::{
        DockerControllerCommand, DockerControllerEvent, DockerControllerHandoff,
        DOCKER_CONTROLLER_PROTOCOL_VERSION,
    },
    SessionControllerError,
};

pub fn run_docker_session_controller() -> Result<(), SessionControllerError> {
    let standard_input = std::io::stdin();
    let handoff: DockerControllerHandoff = read_json_line(&mut standard_input.lock())?;
    validate_handoff(&handoff)?;
    let output = HelperOutput::open_docker(&handoff)?;
    let mut workload = DockerWorkload::start(&handoff, &output)?;
    output.record_event(
        "workload_started",
        serde_json::json!({"container_id": workload.stable_identity()}),
    )?;
    write_event(&DockerControllerEvent::Started {
        container_id: workload.stable_identity().to_owned(),
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
                write_event(&DockerControllerEvent::Exited {
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
                        write_event(&DockerControllerEvent::Exited {
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
    workload: &mut DockerWorkload,
    failure: SessionControllerError,
    control_connected: bool,
) {
    let _result = workload.kill(erebor_runtime_core::ActiveSessionSignal::Kill);
    if control_connected {
        let _result = write_event(&DockerControllerEvent::Failed {
            reason: failure.to_string(),
        });
    }
}

fn apply_command(
    workload: &mut DockerWorkload,
    command: DockerControllerCommand,
) -> Result<Option<WorkloadExit>, SessionControllerError> {
    match command {
        DockerControllerCommand::Stop { grace_period_ms } => workload
            .stop(Duration::from_millis(grace_period_ms))
            .map(Some),
        DockerControllerCommand::Kill { signal } => workload.kill(signal).map(Some),
        DockerControllerCommand::Health => {
            write_event(&DockerControllerEvent::Health {
                running: workload.try_wait()?.is_none(),
            })?;
            Ok(None)
        }
    }
}

fn validate_handoff(handoff: &DockerControllerHandoff) -> Result<(), SessionControllerError> {
    if handoff.protocol_version != DOCKER_CONTROLLER_PROTOCOL_VERSION {
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
    })
}

enum ControlInput {
    Command(DockerControllerCommand),
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
            action: "reading Docker controller startup handoff",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    serde_json::from_str(&line).context(ProtocolSnafu)
}

fn write_event(event: &DockerControllerEvent) -> Result<(), SessionControllerError> {
    let standard_output = std::io::stdout();
    let mut output = standard_output.lock();
    serde_json::to_writer(&mut output, event).context(ProtocolSnafu)?;
    output
        .write_all(b"\n")
        .map_err(|source| SessionControllerError::Io {
            action: "writing Docker controller event",
            path: std::path::PathBuf::from("<inherited-control>"),
            source,
            location: snafu::Location::default(),
        })?;
    output.flush().map_err(|source| SessionControllerError::Io {
        action: "flushing Docker controller event",
        path: std::path::PathBuf::from("<inherited-control>"),
        source,
        location: snafu::Location::default(),
    })
}
