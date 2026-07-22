use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "linux/prepared.rs"]
mod prepared;

use erebor_runtime_core::ActiveSessionSignal;
use rustix::process::{kill_process_group, Pid, Signal};
#[allow(deprecated)]
use rustix::thread::unshare;
use rustix::{
    fs::{openat, Mode, OFlags},
    mount::{mount, mount_bind, mount_change, mount_remount, MountFlags, MountPropagationFlags},
    process::{ioctl_tiocsctty, setsid},
    pty::{grantpt, ioctl_tiocgptpeer, openpt, unlockpt, OpenptFlags},
    termios::tcsetpgrp,
    thread::UnshareFlags,
};

use crate::{runners::linux::LinuxControllerHandoff, SessionControllerError, StreamKind};

use self::prepared::PreparedLinuxExecution;
use super::{
    output::HelperOutput,
    workload::{child_exit, pump_output, wait_child, OutputFailureMonitor, WorkloadExit},
};

pub(crate) struct LinuxWorkload {
    child: Child,
    process_group: Pid,
    stable_identity: String,
    input: Option<LinuxWorkloadInput>,
    output_pumps: Vec<thread::JoinHandle<()>>,
    output_failures: OutputFailureMonitor,
}

enum LinuxWorkloadInput {
    Terminal(File),
    Pipe(ChildStdin),
}

impl LinuxWorkload {
    pub(crate) fn start(
        handoff: &LinuxControllerHandoff,
        output: &HelperOutput,
    ) -> Result<Self, SessionControllerError> {
        let host_proc = File::open("/proc").map_err(|source| SessionControllerError::Io {
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
            .env("EREBOR_TERMINAL_TTY", handoff.spec.tty().to_string());
        let (mut input, controlling_terminal) = if handoff.spec.tty() {
            setsid().map_err(|source| SessionControllerError::Io {
                action: "creating Linux pseudoterminal session",
                path: PathBuf::from("<pty-session>"),
                source: source.into(),
                location: snafu::Location::default(),
            })?;
            let (master, slave) = Self::open_pty()?;
            let controlling_terminal =
                slave
                    .try_clone()
                    .map_err(|source| SessionControllerError::Io {
                        action: "duplicating Linux pseudoterminal slave",
                        path: PathBuf::from("<pty-slave>"),
                        source,
                        location: snafu::Location::default(),
                    })?;
            ioctl_tiocsctty(&controlling_terminal).map_err(|source| {
                SessionControllerError::Io {
                    action: "setting Linux pseudoterminal controlling terminal",
                    path: PathBuf::from("<pty-slave>"),
                    source: source.into(),
                    location: snafu::Location::default(),
                }
            })?;
            let standard_input =
                slave
                    .try_clone()
                    .map_err(|source| SessionControllerError::Io {
                        action: "duplicating Linux pseudoterminal stdin",
                        path: PathBuf::from("<pty-slave>"),
                        source,
                        location: snafu::Location::default(),
                    })?;
            let standard_output =
                slave
                    .try_clone()
                    .map_err(|source| SessionControllerError::Io {
                        action: "duplicating Linux pseudoterminal stdout",
                        path: PathBuf::from("<pty-slave>"),
                        source,
                        location: snafu::Location::default(),
                    })?;
            command
                .stdin(Stdio::from(standard_input))
                .stdout(Stdio::from(standard_output))
                .stderr(Stdio::from(slave))
                .process_group(0);
            (
                Some(LinuxWorkloadInput::Terminal(master)),
                Some(controlling_terminal),
            )
        } else {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            (None, None)
        };
        let mut child = command
            .spawn()
            .map_err(|source| SessionControllerError::Io {
                action: "starting Linux process guard",
                path: handoff.process_guard_path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        if !handoff.spec.tty() {
            input = child.stdin.take().map(LinuxWorkloadInput::Pipe);
        }
        let pid = Pid::from_raw(child.id() as i32).ok_or_else(|| {
            SessionControllerError::InvalidHandoff {
                reason: String::from("process guard returned an invalid pid"),
                location: snafu::Location::default(),
            }
        })?;
        if let Some(terminal) = controlling_terminal {
            tcsetpgrp(&terminal, pid).map_err(|source| SessionControllerError::Io {
                action: "setting Linux pseudoterminal foreground process group",
                path: PathBuf::from("<pty-slave>"),
                source: source.into(),
                location: snafu::Location::default(),
            })?;
        }
        let start_time = process_start_time(&host_proc, child.id()).unwrap_or(0);
        let stable_identity = format!("linux:pid={}:start={start_time}", child.id());
        let mut output_pumps = Vec::new();
        let (output_failures, failure_sender) = OutputFailureMonitor::new();
        match input.as_ref() {
            Some(LinuxWorkloadInput::Terminal(terminal)) => {
                let output_terminal =
                    terminal
                        .try_clone()
                        .map_err(|source| SessionControllerError::Io {
                            action: "duplicating Linux pseudoterminal master for output",
                            path: PathBuf::from("<pty-master>"),
                            source,
                            location: snafu::Location::default(),
                        })?;
                output_pumps.push(pump_output(
                    output_terminal,
                    Arc::clone(&output.stdout),
                    StreamKind::Stdout.as_str(),
                    failure_sender,
                ));
            }
            Some(LinuxWorkloadInput::Pipe(_)) | None => {
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
            }
        }
        Ok(Self {
            child,
            process_group: pid,
            stable_identity,
            input,
            output_pumps,
            output_failures,
        })
    }

    fn open_pty() -> Result<(File, File), SessionControllerError> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
            .map_err(|source| SessionControllerError::Io {
                action: "opening Linux pseudoterminal master",
                path: PathBuf::from("/dev/ptmx"),
                source: source.into(),
                location: snafu::Location::default(),
            })?;
        grantpt(&master).map_err(|source| SessionControllerError::Io {
            action: "granting Linux pseudoterminal slave",
            path: PathBuf::from("<pty-master>"),
            source: source.into(),
            location: snafu::Location::default(),
        })?;
        unlockpt(&master).map_err(|source| SessionControllerError::Io {
            action: "unlocking Linux pseudoterminal slave",
            path: PathBuf::from("<pty-master>"),
            source: source.into(),
            location: snafu::Location::default(),
        })?;
        let slave = ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .map_err(|source| SessionControllerError::Io {
            action: "opening Linux pseudoterminal slave",
            path: PathBuf::from("<pty-master>"),
            source: source.into(),
            location: snafu::Location::default(),
        })?;
        Ok((File::from(master), File::from(slave)))
    }

    pub(crate) fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    pub(crate) fn take_output_failure(&self) -> Option<SessionControllerError> {
        self.output_failures.take_failure()
    }

    pub(crate) fn write_input(&mut self, data: &[u8]) -> Result<(), SessionControllerError> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: String::from("Linux workload stdin is unavailable"),
                location: snafu::Location::default(),
            })?;
        match input {
            LinuxWorkloadInput::Terminal(input) => {
                input.write_all(data).and_then(|()| input.flush())
            }
            LinuxWorkloadInput::Pipe(input) => input.write_all(data).and_then(|()| input.flush()),
        }
        .map_err(|source| SessionControllerError::Io {
            action: "writing Linux workload stdin",
            path: PathBuf::from("<workload-stdin>"),
            source,
            location: snafu::Location::default(),
        })
    }

    pub(crate) fn close_input(&mut self) {
        self.input.take();
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<WorkloadExit>, SessionControllerError> {
        let exit = self
            .child
            .try_wait()
            .map_err(|source| SessionControllerError::Io {
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

    pub(crate) fn stop(&mut self, grace: Duration) -> Result<WorkloadExit, SessionControllerError> {
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

    pub(crate) fn kill(
        &mut self,
        signal: ActiveSessionSignal,
    ) -> Result<WorkloadExit, SessionControllerError> {
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

    fn join_output_pumps(&mut self) -> Result<(), SessionControllerError> {
        for pump in self.output_pumps.drain(..) {
            pump.join()
                .map_err(|_panic| SessionControllerError::InvalidHandoff {
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

fn signal_group(process_group: Pid, signal: Signal) -> Result<(), SessionControllerError> {
    kill_process_group(process_group, signal).map_err(|source| SessionControllerError::Io {
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
    handoff: &LinuxControllerHandoff,
) -> Result<Vec<(String, String)>, SessionControllerError> {
    #[allow(deprecated)]
    unshare(UnshareFlags::NEWNS)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
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
    .map_err(|source| SessionControllerError::Io {
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
        File::create(target).map_err(|source_error| SessionControllerError::Io {
            action: "creating private runtime guard projection",
            path: target.clone(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
        mount_bind(Path::new(source), target)
            .map_err(std::io::Error::from)
            .map_err(|source_error| SessionControllerError::Io {
                action: "holding runtime guard socket before hiding host runtime",
                path: target.clone(),
                source: source_error,
                location: snafu::Location::default(),
            })?;
    }
    let endpoint_projections = hold_endpoint_projections(handoff)?;

    std::fs::create_dir_all("/run/erebor").map_err(|source| SessionControllerError::Io {
        action: "creating private Erebor runtime mountpoint",
        path: PathBuf::from("/run/erebor"),
        source,
        location: snafu::Location::default(),
    })?;
    let data = CString::new("mode=0711,size=65536").map_err(|error| {
        SessionControllerError::InvalidHandoff {
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
    .map_err(|source| SessionControllerError::Io {
        action: "hiding the host Erebor runtime in the session namespace",
        path: PathBuf::from("/run/erebor"),
        source,
        location: snafu::Location::default(),
    })?;

    let private_guard = PathBuf::from("/run/erebor/runtime-interception.sock");
    if let Some(source) = projection_source {
        File::create(&private_guard).map_err(|source_error| SessionControllerError::Io {
            action: "creating private runtime guard endpoint",
            path: private_guard.clone(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
        mount_bind(&source, &private_guard)
            .map_err(std::io::Error::from)
            .map_err(|source_error| SessionControllerError::Io {
                action: "projecting only the admitted runtime guard endpoint",
                path: private_guard.clone(),
                source: source_error,
                location: snafu::Location::default(),
            })?;
    }
    project_endpoints(&endpoint_projections)?;
    project_filesystems(handoff)?;
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

fn hold_endpoint_projections(
    handoff: &LinuxControllerHandoff,
) -> Result<Vec<(PathBuf, PathBuf)>, SessionControllerError> {
    let root = handoff.evidence_path.join("endpoint-projections");
    let mut held = Vec::new();
    for (index, endpoint) in handoff
        .spec
        .endpoint_projections()
        .iter()
        .filter(|endpoint| endpoint.service() != "runtime-guard")
        .enumerate()
    {
        fs::create_dir_all(&root).map_err(|source| SessionControllerError::Io {
            action: "creating daemon-owned endpoint projection directory",
            path: root.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let held_path = root.join(index.to_string());
        File::create(&held_path).map_err(|source| SessionControllerError::Io {
            action: "creating held endpoint projection mountpoint",
            path: held_path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        mount_bind(endpoint.host_path(), &held_path)
            .map_err(std::io::Error::from)
            .map_err(|source| SessionControllerError::Io {
                action: "holding admitted endpoint before hiding host runtime",
                path: endpoint.host_path().to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        held.push((held_path, endpoint.workload_path().to_path_buf()));
    }
    Ok(held)
}

fn project_endpoints(projections: &[(PathBuf, PathBuf)]) -> Result<(), SessionControllerError> {
    for (source, target) in projections {
        create_projection_target(target, false)?;
        mount_bind(source, target)
            .map_err(std::io::Error::from)
            .map_err(|error| SessionControllerError::Io {
                action: "projecting admitted daemon endpoint into the workload",
                path: target.clone(),
                source: error,
                location: snafu::Location::default(),
            })?;
    }
    Ok(())
}

fn project_filesystems(handoff: &LinuxControllerHandoff) -> Result<(), SessionControllerError> {
    if handoff.prepared_filesystem_projections.len() != handoff.spec.filesystem_projections().len()
    {
        return Err(SessionControllerError::InvalidHandoff {
            reason: String::from(
                "prepared filesystem projections do not match the admitted session",
            ),
            location: snafu::Location::default(),
        });
    }
    for (prepared, admitted) in handoff
        .prepared_filesystem_projections
        .iter()
        .zip(handoff.spec.filesystem_projections())
    {
        if prepared.workload_path() != admitted.workload_path()
            || prepared.read_only() != admitted.read_only()
        {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from(
                    "prepared filesystem projection does not match the admitted target",
                ),
                location: snafu::Location::default(),
            });
        }
        let directory = admitted.source().kind() == erebor_runtime_core::SafePathKind::Directory;
        create_projection_target(prepared.workload_path(), directory)?;
        mount_bind(prepared.staging_path(), prepared.workload_path())
            .map_err(std::io::Error::from)
            .map_err(|error| SessionControllerError::Io {
                action: "projecting held filesystem artifact into the workload",
                path: prepared.workload_path().to_path_buf(),
                source: error,
                location: snafu::Location::default(),
            })?;
        if prepared.read_only() {
            mount_remount(
                prepared.workload_path(),
                MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
                "",
            )
            .map_err(std::io::Error::from)
            .map_err(|error| SessionControllerError::Io {
                action: "locking filesystem projection read-only",
                path: prepared.workload_path().to_path_buf(),
                source: error,
                location: snafu::Location::default(),
            })?;
        }
    }
    Ok(())
}

fn create_projection_target(path: &Path, directory: bool) -> Result<(), SessionControllerError> {
    let private_runtime = Path::new("/run/erebor");
    if path.starts_with(private_runtime) {
        let parent = path
            .parent()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: format!("projection target `{}` has no parent", path.display()),
                location: snafu::Location::default(),
            })?;
        fs::create_dir_all(parent).map_err(|source| SessionControllerError::Io {
            action: "creating private projection parent",
            path: parent.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
        if directory {
            fs::create_dir_all(path).map_err(|source| SessionControllerError::Io {
                action: "creating private filesystem projection mountpoint",
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        } else {
            File::create(path).map_err(|source| SessionControllerError::Io {
                action: "creating private endpoint projection mountpoint",
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        }
        return Ok(());
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| SessionControllerError::Io {
        action: "checking preinstalled projection mountpoint",
        path: path.to_path_buf(),
        source,
        location: snafu::Location::default(),
    })?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
        return Err(SessionControllerError::InvalidHandoff {
            reason: format!(
                "projection target `{}` is not the required preinstalled {} mountpoint",
                path.display(),
                if directory { "directory" } else { "file" }
            ),
            location: snafu::Location::default(),
        });
    }
    Ok(())
}

fn environment_value(environment: &[(String, String)], key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(candidate, _value)| candidate == key)
        .map(|(_key, value)| value.clone())
}
