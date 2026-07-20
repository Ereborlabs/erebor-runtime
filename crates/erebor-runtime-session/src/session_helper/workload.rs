use std::{
    io::Read,
    process::Child,
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use erebor_runtime_core::{ActiveSessionSignal, SessionHelperHandoff, SessionRunnerKind};

use crate::{DurableStreamStore, SessionHelperError};

use super::{
    docker::DockerWorkload,
    linux::LinuxWorkload,
    output::{unix_time_ms, HelperOutput},
};

#[derive(Clone, Copy, Debug)]
pub(super) struct WorkloadExit {
    pub(super) exit_code: Option<i32>,
    pub(super) signal: Option<i32>,
}

pub(super) enum HelperWorkload {
    Linux(LinuxWorkload),
    Docker(DockerWorkload),
}

impl HelperWorkload {
    pub(super) fn start(
        handoff: &SessionHelperHandoff,
        output: &HelperOutput,
    ) -> Result<Self, SessionHelperError> {
        match handoff.spec.runner_capability().runner() {
            SessionRunnerKind::LinuxHost => LinuxWorkload::start(handoff, output).map(Self::Linux),
            SessionRunnerKind::Docker => DockerWorkload::start(handoff, output).map(Self::Docker),
        }
    }

    pub(super) fn stable_identity(&self) -> &str {
        match self {
            Self::Linux(workload) => workload.stable_identity(),
            Self::Docker(workload) => workload.stable_identity(),
        }
    }

    pub(super) fn try_wait(&mut self) -> Result<Option<WorkloadExit>, SessionHelperError> {
        match self {
            Self::Linux(workload) => workload.try_wait(),
            Self::Docker(workload) => workload.try_wait(),
        }
    }

    pub(super) fn stop(&mut self, grace: Duration) -> Result<WorkloadExit, SessionHelperError> {
        match self {
            Self::Linux(workload) => workload.stop(grace),
            Self::Docker(workload) => workload.stop(grace),
        }
    }

    pub(super) fn kill(
        &mut self,
        signal: ActiveSessionSignal,
    ) -> Result<WorkloadExit, SessionHelperError> {
        match self {
            Self::Linux(workload) => workload.kill(signal),
            Self::Docker(workload) => workload.kill(signal),
        }
    }

    pub(super) fn take_output_failure(&self) -> Option<SessionHelperError> {
        match self {
            Self::Linux(workload) => workload.take_output_failure(),
            Self::Docker(workload) => workload.take_output_failure(),
        }
    }
}

pub(super) struct OutputFailureMonitor {
    receiver: mpsc::Receiver<SessionHelperError>,
}

impl OutputFailureMonitor {
    pub(super) fn new() -> (Self, mpsc::Sender<SessionHelperError>) {
        let (sender, receiver) = mpsc::channel();
        (Self { receiver }, sender)
    }

    pub(super) fn take_failure(&self) -> Option<SessionHelperError> {
        self.receiver.try_recv().ok()
    }
}

pub(super) fn pump_output(
    mut source: impl Read + Send + 'static,
    sink: Arc<DurableStreamStore>,
    source_name: &'static str,
    failure_sender: mpsc::Sender<SessionHelperError>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let required = sink.required();
        let mut buffer = [0_u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) => return,
                Err(source) => {
                    if required {
                        let _result = failure_sender.send(SessionHelperError::Io {
                            action: "reading governed workload output",
                            path: std::path::PathBuf::from(format!("<{source_name}>")),
                            source,
                            location: snafu::Location::default(),
                        });
                    }
                    return;
                }
                Ok(bytes) => {
                    if let Err(source) =
                        sink.append(unix_time_ms(), source_name, buffer[..bytes].to_vec())
                    {
                        if required {
                            let _result = failure_sender.send(SessionHelperError::Output {
                                source,
                                location: snafu::Location::default(),
                            });
                        }
                        return;
                    }
                }
            }
        }
    })
}

pub(super) fn child_exit(status: std::process::ExitStatus) -> WorkloadExit {
    use std::os::unix::process::ExitStatusExt;

    WorkloadExit {
        exit_code: status.code(),
        signal: status.signal(),
    }
}

pub(super) fn wait_child(child: &mut Child) -> Result<WorkloadExit, SessionHelperError> {
    let status = child.wait().map_err(|source| SessionHelperError::Io {
        action: "waiting for governed workload",
        path: std::path::PathBuf::from("<workload>"),
        source,
        location: snafu::Location::default(),
    })?;
    Ok(child_exit(status))
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use tempfile::TempDir;

    use crate::{DurableStreamStore, StreamKind};

    use super::{pump_output, OutputFailureMonitor};

    #[test]
    fn required_stream_write_failure_reaches_the_helper_monitor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let sink = Arc::new(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            128,
            128,
            true,
        )?);
        let (monitor, sender) = OutputFailureMonitor::new();
        let pump = pump_output(Cursor::new(vec![b'x'; 256]), sink, "stdout", sender);

        pump.join().map_err(|_panic| "output pump panicked")?;
        let failure = monitor
            .take_failure()
            .ok_or("required output failure was not reported")?;
        assert!(matches!(failure, crate::SessionHelperError::Output { .. }));
        Ok(())
    }

    #[test]
    fn optional_stream_write_failure_does_not_fail_the_helper(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let sink = Arc::new(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            128,
            128,
            false,
        )?);
        let (monitor, sender) = OutputFailureMonitor::new();
        let pump = pump_output(Cursor::new(vec![b'x'; 256]), sink, "stdout", sender);

        pump.join().map_err(|_panic| "output pump panicked")?;
        assert!(monitor.take_failure().is_none());
        Ok(())
    }
}
