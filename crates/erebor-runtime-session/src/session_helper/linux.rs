use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

mod prepared;

use erebor_runtime_core::{ActiveSessionSignal, SessionHelperHandoff};
use rustix::process::{kill_process_group, Pid, Signal};
#[allow(deprecated)]
use rustix::thread::unshare;
use rustix::{
    fs::{openat, Mode, OFlags},
    mount::{mount, mount_bind, mount_change, MountFlags, MountPropagationFlags},
    thread::UnshareFlags,
};

use crate::{SessionHelperError, StreamKind};

use self::prepared::PreparedLinuxExecution;
use super::{
    output::HelperOutput,
    workload::{child_exit, pump_output, wait_child, OutputFailureMonitor, WorkloadExit},
};

pub(super) struct LinuxWorkload {
    child: Child,
    process_group: Pid,
    stable_identity: String,
    output_pumps: Vec<thread::JoinHandle<()>>,
    output_failures: OutputFailureMonitor,
}

impl LinuxWorkload {
    pub(super) fn start(
        handoff: &SessionHelperHandoff,
        output: &HelperOutput,
    ) -> Result<Self, SessionHelperError> {
        let host_proc = File::open("/proc").map_err(|source| SessionHelperError::Io {
            action: "opening host proc before session namespace isolation",
            path: PathBuf::from("/proc"),
            source,
            location: snafu::Location::default(),
        })?;
        let prepared = PreparedLinuxExecution::open(handoff)?;
        let runtime_environment = prepare_private_namespace(handoff)?;
        let admitted_command = prepared.admitted_command(handoff);
        let mut command = Command::new(&handoff.process_guard_path);
        command
            .args(&admitted_command)
            .env_clear()
            .envs(handoff.spec.environment().iter().cloned())
            .envs(runtime_environment)
            .env("EREBOR_PRIVATE_SESSION_NAMESPACE", "1")
            .env("EREBOR_SESSION_ID", handoff.spec.session_id().as_str())
            .env("EREBOR_ACTOR_ID", "agent")
            .env("EREBOR_SESSION_RUNNER", "linux_host")
            .env("EREBOR_TARGET_UID", handoff.spec.owner().uid().to_string())
            .env("EREBOR_TARGET_GID", handoff.spec.owner().gid().to_string())
            .env(
                "EREBOR_TARGET_SUPPLEMENTARY_GROUPS",
                handoff
                    .spec
                    .workload_privileges()
                    .supplementary_groups()
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .env(
                "EREBOR_TARGET_UMASK",
                handoff.spec.workload_privileges().umask().to_string(),
            )
            .env(
                "EREBOR_TARGET_MAX_OPEN_FILES",
                handoff
                    .spec
                    .workload_privileges()
                    .maximum_open_files()
                    .to_string(),
            )
            .env(
                "EREBOR_TARGET_MAX_PROCESSES",
                handoff
                    .spec
                    .workload_privileges()
                    .maximum_processes()
                    .to_string(),
            )
            .env(
                "EREBOR_TARGET_MAX_CORE_BYTES",
                handoff
                    .spec
                    .workload_privileges()
                    .maximum_core_bytes()
                    .to_string(),
            )
            .current_dir(prepared.workspace_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().map_err(|source| SessionHelperError::Io {
            action: "starting Linux process guard",
            path: handoff.process_guard_path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let pid =
            Pid::from_raw(child.id() as i32).ok_or_else(|| SessionHelperError::InvalidHandoff {
                reason: String::from("process guard returned an invalid pid"),
                location: snafu::Location::default(),
            })?;
        let start_time = process_start_time(&host_proc, child.id()).unwrap_or(0);
        let stable_identity = format!("linux:pid={}:start={start_time}", child.id());
        let mut output_pumps = Vec::new();
        let (output_failures, failure_sender) = OutputFailureMonitor::new();
        if let Some(stdout) = child.stdout.take() {
            output_pumps.push(pump_output(
                stdout,
                Arc::clone(&output.stdout),
                StreamKind::Stdout.as_str(),
                failure_sender.clone(),
            ));
        }
        if let Some(stderr) = child.stderr.take() {
            output_pumps.push(pump_output(
                stderr,
                Arc::clone(&output.stderr),
                StreamKind::Stderr.as_str(),
                failure_sender,
            ));
        }
        Ok(Self {
            child,
            process_group: pid,
            stable_identity,
            output_pumps,
            output_failures,
        })
    }

    pub(super) fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    pub(super) fn take_output_failure(&self) -> Option<SessionHelperError> {
        self.output_failures.take_failure()
    }

    pub(super) fn try_wait(&mut self) -> Result<Option<WorkloadExit>, SessionHelperError> {
        let exit = self
            .child
            .try_wait()
            .map_err(|source| SessionHelperError::Io {
                action: "observing Linux process guard",
                path: std::path::PathBuf::from("<process-guard>"),
                source,
                location: snafu::Location::default(),
            })?
            .map(child_exit);
        if exit.is_some() {
            self.join_output_pumps()?;
        }
        Ok(exit)
    }

    pub(super) fn stop(&mut self, grace: Duration) -> Result<WorkloadExit, SessionHelperError> {
        signal_group(self.process_group, Signal::TERM)?;
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if let Some(exit) = self.try_wait()? {
                return Ok(exit);
            }
            thread::sleep(Duration::from_millis(10));
        }
        signal_group(self.process_group, Signal::KILL)?;
        let exit = wait_child(&mut self.child)?;
        self.join_output_pumps()?;
        Ok(exit)
    }

    pub(super) fn kill(
        &mut self,
        signal: ActiveSessionSignal,
    ) -> Result<WorkloadExit, SessionHelperError> {
        let signal = match signal {
            ActiveSessionSignal::Terminate => Signal::TERM,
            ActiveSessionSignal::Kill => Signal::KILL,
            ActiveSessionSignal::Interrupt => Signal::INT,
        };
        signal_group(self.process_group, signal)?;
        let exit = wait_child(&mut self.child)?;
        self.join_output_pumps()?;
        Ok(exit)
    }

    fn join_output_pumps(&mut self) -> Result<(), SessionHelperError> {
        for pump in self.output_pumps.drain(..) {
            pump.join()
                .map_err(|_panic| SessionHelperError::InvalidHandoff {
                    reason: String::from("Linux workload output pump panicked"),
                    location: snafu::Location::default(),
                })?;
        }
        Ok(())
    }
}

impl Drop for LinuxWorkload {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _result = kill_process_group(self.process_group, Signal::KILL);
            let _result = self.child.wait();
        }
        for pump in self.output_pumps.drain(..) {
            let _result = pump.join();
        }
    }
}

use std::sync::Arc;

fn signal_group(process_group: Pid, signal: Signal) -> Result<(), SessionHelperError> {
    kill_process_group(process_group, signal).map_err(|source| SessionHelperError::Io {
        action: "signaling Linux session process group",
        path: std::path::PathBuf::from(format!(
            "<process-group:{}>",
            process_group.as_raw_nonzero()
        )),
        source: source.into(),
        location: snafu::Location::default(),
    })
}

fn process_start_time(host_proc: &File, pid: u32) -> Option<u64> {
    let path = format!("{pid}/stat");
    let mut stat = String::new();
    File::from(
        openat(
            host_proc,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?,
    )
    .read_to_string(&mut stat)
    .ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    after_name
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

fn prepare_private_namespace(
    handoff: &SessionHelperHandoff,
) -> Result<Vec<(String, String)>, SessionHelperError> {
    #[allow(deprecated)]
    unshare(UnshareFlags::NEWNS)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionHelperError::Io {
            action: "creating Linux session mount namespace",
            path: PathBuf::from("<session-namespace>"),
            source,
            location: snafu::Location::default(),
        })?;
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionHelperError::Io {
        action: "making Linux session mounts private",
        path: PathBuf::from("/"),
        source,
        location: snafu::Location::default(),
    })?;

    let guard_host_path = environment_value(
        &handoff.runtime_environment,
        "EREBOR_RUNTIME_INTERCEPTION_PATH",
    );
    let projection_source = guard_host_path
        .is_some()
        .then(|| handoff.evidence_path.join("runtime-guard-projection.sock"));
    if let (Some(source), Some(target)) = (guard_host_path.as_ref(), projection_source.as_ref()) {
        File::create(target).map_err(|source_error| SessionHelperError::Io {
            action: "creating private runtime guard projection",
            path: target.clone(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
        mount_bind(Path::new(source), target)
            .map_err(std::io::Error::from)
            .map_err(|source_error| SessionHelperError::Io {
                action: "holding runtime guard socket before hiding host runtime",
                path: target.clone(),
                source: source_error,
                location: snafu::Location::default(),
            })?;
    }

    std::fs::create_dir_all("/run/erebor").map_err(|source| SessionHelperError::Io {
        action: "creating private Erebor runtime mountpoint",
        path: PathBuf::from("/run/erebor"),
        source,
        location: snafu::Location::default(),
    })?;
    let data = CString::new("mode=0711,size=65536").map_err(|error| {
        SessionHelperError::InvalidHandoff {
            reason: error.to_string(),
            location: snafu::Location::default(),
        }
    })?;
    mount(
        "tmpfs",
        "/run/erebor",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        Some(data.as_c_str()),
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionHelperError::Io {
        action: "hiding the host Erebor runtime in the session namespace",
        path: PathBuf::from("/run/erebor"),
        source,
        location: snafu::Location::default(),
    })?;

    let private_guard = PathBuf::from("/run/erebor/runtime-interception.sock");
    if let Some(source) = projection_source {
        File::create(&private_guard).map_err(|source_error| SessionHelperError::Io {
            action: "creating private runtime guard endpoint",
            path: private_guard.clone(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
        mount_bind(&source, &private_guard)
            .map_err(std::io::Error::from)
            .map_err(|source_error| SessionHelperError::Io {
                action: "projecting only the admitted runtime guard endpoint",
                path: private_guard.clone(),
                source: source_error,
                location: snafu::Location::default(),
            })?;
    }
    Ok(handoff
        .runtime_environment
        .iter()
        .map(|(key, value)| {
            if key == "EREBOR_RUNTIME_INTERCEPTION_PATH" {
                (key.clone(), private_guard.display().to_string())
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect())
}

fn environment_value(environment: &[(String, String)], key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(candidate, _value)| candidate == key)
        .map(|(_key, value)| value.clone())
}
