use std::{io::Read, process::Child, sync::Arc, thread, time::Duration};

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
}

pub(super) fn pump_output(
    mut source: impl Read + Send + 'static,
    sink: Arc<DurableStreamStore>,
    source_name: &'static str,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(bytes) => {
                    if sink
                        .append(unix_time_ms(), source_name, buffer[..bytes].to_vec())
                        .is_err()
                    {
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
