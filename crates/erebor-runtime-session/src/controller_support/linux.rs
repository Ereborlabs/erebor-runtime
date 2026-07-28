use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "linux/prepared.rs"]
mod prepared;

use erebor_runtime_core::{ActiveSessionSignal, FilesystemProjectionTarget, TerminalSize};
use rustix::process::{kill_process_group, Pid, Signal};
#[allow(deprecated)]
use rustix::thread::unshare;
use rustix::{
    fs::{openat, Mode, OFlags},
    mount::{
        mount, mount_bind, mount_change, mount_move, mount_remount, MountFlags,
        MountPropagationFlags,
    },
    process::{ioctl_tiocsctty, setsid},
    pty::{grantpt, ioctl_tiocgptpeer, openpt, unlockpt, OpenptFlags},
    termios::{tcsetpgrp, tcsetwinsize, Winsize},
    thread::UnshareFlags,
};
use users::os::unix::UserExt;

use crate::{runners::linux::LinuxControllerHandoff, SessionControllerError, StreamKind};

use self::prepared::PreparedLinuxExecution;
use super::{
    output::HelperOutput,
    workload::{child_exit, pump_output, wait_child, OutputFailureMonitor, WorkloadExit},
};

const PRIVATE_ADMITTED_EXECUTABLE_PATH: &str = "/run/erebor/admitted-executable";
const PRIVATE_WORKSPACE_PATH: &str = "/run/erebor/workspace";

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

struct PrivateLinuxNamespace {
    runtime_environment: Vec<(String, String)>,
    executable_path: Option<PathBuf>,
    workspace_path: PathBuf,
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
        let private_namespace = prepare_private_namespace(handoff, &prepared)?;
        let admitted_command =
            prepared.admitted_command(handoff, private_namespace.executable_path.as_deref());
        let mut command = Command::new(&handoff.process_guard_path);
        command
            .args(&admitted_command)
            .env_clear()
            .envs(handoff.spec.environment().iter().cloned())
            .envs(private_namespace.runtime_environment)
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
            .current_dir(private_namespace.workspace_path)
            .env("EREBOR_TERMINAL_TTY", handoff.spec.tty().to_string());
        let (mut input, controlling_terminal) = if handoff.spec.tty() {
            setsid().map_err(|source| SessionControllerError::Io {
                action: "creating Linux pseudoterminal session",
                path: PathBuf::from("<pty-session>"),
                source: source.into(),
                location: snafu::Location::default(),
            })?;
            let (master, slave) = Self::open_pty()?;
            let terminal_size = handoff.spec.terminal_size().ok_or_else(|| {
                SessionControllerError::InvalidHandoff {
                    reason: String::from("TTY session did not retain initial terminal geometry"),
                    location: snafu::Location::default(),
                }
            })?;
            Self::set_terminal_size(
                &slave,
                terminal_size,
                "setting initial Linux pseudoterminal size",
            )?;
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
                    true,
                    failure_sender,
                ));
            }
            Some(LinuxWorkloadInput::Pipe(_)) | None => {
                if let Some(stdout) = child.stdout.take() {
                    output_pumps.push(pump_output(
                        stdout,
                        Arc::clone(&output.stdout),
                        StreamKind::Stdout.as_str(),
                        false,
                        failure_sender.clone(),
                    ));
                }
                if let Some(stderr) = child.stderr.take() {
                    output_pumps.push(pump_output(
                        stderr,
                        Arc::clone(&output.stderr),
                        StreamKind::Stderr.as_str(),
                        false,
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

    pub(crate) fn resize_terminal(
        &mut self,
        terminal_size: TerminalSize,
    ) -> Result<(), SessionControllerError> {
        let input = self
            .input
            .as_ref()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: String::from("Linux workload terminal is unavailable"),
                location: snafu::Location::default(),
            })?;
        let LinuxWorkloadInput::Terminal(terminal) = input else {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from("Linux workload does not have a terminal"),
                location: snafu::Location::default(),
            });
        };
        Self::set_terminal_size(terminal, terminal_size, "resizing Linux pseudoterminal")
    }

    pub(crate) fn close_input(&mut self) {
        self.input.take();
    }

    fn set_terminal_size(
        terminal: &File,
        terminal_size: TerminalSize,
        action: &'static str,
    ) -> Result<(), SessionControllerError> {
        tcsetwinsize(
            terminal,
            Winsize {
                ws_row: terminal_size.rows(),
                ws_col: terminal_size.columns(),
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(|source| SessionControllerError::Io {
            action,
            path: PathBuf::from("<pty-master>"),
            source: source.into(),
            location: snafu::Location::default(),
        })
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
    prepared: &PreparedLinuxExecution,
) -> Result<PrivateLinuxNamespace, SessionControllerError> {
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

    hide_caller_home_for_session_view(handoff)?;

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
    let filesystem_projections = hold_filesystem_projections(handoff)?;
    let private_state_projection = hold_private_state_projection(handoff)?;
    let held_admitted_executable = hold_admitted_executable(handoff, prepared)?;
    let held_workspace = hold_workspace(handoff, prepared)?;

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
        // The private runtime intentionally hosts exact, read-only managed hooks.
        // They must remain executable so the guarded workload can invoke them.
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(data.as_c_str()),
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionControllerError::Io {
        action: "hiding the host Erebor runtime in the session namespace",
        path: PathBuf::from("/run/erebor"),
        source,
        location: snafu::Location::default(),
    })?;

    let private_executable_path = project_admitted_executable(held_admitted_executable.as_deref())?;
    let workspace_path = project_workspace(&held_workspace)?;

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
    install_session_overlay_projection_roots(handoff, &filesystem_projections)?;
    project_filesystems(&filesystem_projections)?;
    hide_unadmitted_codex_ipc(handoff)?;
    if let Some(projection) = private_state_projection.as_ref() {
        project_private_state(projection)?;
    }
    let mut environment = handoff
        .runtime_environment
        .iter()
        .map(|(key, value)| {
            if key == "EREBOR_RUNTIME_INTERCEPTION_PATH" {
                (key.clone(), private_guard.display().to_string())
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect::<Vec<_>>();
    if let Some(projection) = private_state_projection {
        environment.push((
            String::from("CODEX_HOME"),
            projection.target.display().to_string(),
        ));
    }
    Ok(PrivateLinuxNamespace {
        runtime_environment: environment,
        executable_path: private_executable_path,
        workspace_path,
    })
}

/// Holds the descriptor-verified workspace outside `/run/erebor` before that
/// host runtime path is hidden from the workload.
fn hold_workspace(
    handoff: &LinuxControllerHandoff,
    prepared: &PreparedLinuxExecution,
) -> Result<PathBuf, SessionControllerError> {
    let source = prepared.workspace_staging_path();
    let target = handoff.evidence_path.join("workspace");
    fs::create_dir_all(&target).map_err(|source_error| SessionControllerError::Io {
        action: "creating held workspace mountpoint",
        path: target.clone(),
        source: source_error,
        location: snafu::Location::default(),
    })?;
    mount_bind(source, &target)
        .map_err(std::io::Error::from)
        .map_err(|source_error| SessionControllerError::Io {
            action: "holding admitted workspace before hiding host runtime",
            path: source.to_path_buf(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
    Ok(target)
}

/// Moves the held workspace to its stable, workload-visible private path so
/// processes can resolve their current directory after the caller home is
/// hidden for a private agent-state projection.
fn project_workspace(source: &Path) -> Result<PathBuf, SessionControllerError> {
    let target = PathBuf::from(PRIVATE_WORKSPACE_PATH);
    fs::create_dir(&target).map_err(|source_error| SessionControllerError::Io {
        action: "creating private workspace mountpoint",
        path: target.clone(),
        source: source_error,
        location: snafu::Location::default(),
    })?;
    mount_move(source, &target)
        .map_err(std::io::Error::from)
        .map_err(|source_error| SessionControllerError::Io {
            action: "moving held workspace into the workload",
            path: source.to_path_buf(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
    Ok(target)
}

/// Holds the descriptor-verified, daemon-owned executable staging mount outside
/// `/run/erebor` before that host runtime path is hidden from the workload.
fn hold_admitted_executable(
    handoff: &LinuxControllerHandoff,
    prepared: &PreparedLinuxExecution,
) -> Result<Option<PathBuf>, SessionControllerError> {
    let Some(source) = prepared.executable_staging_path() else {
        return Ok(None);
    };
    let target = handoff.evidence_path.join("admitted-executable");
    File::create(&target).map_err(|source_error| SessionControllerError::Io {
        action: "creating held admitted executable mountpoint",
        path: target.clone(),
        source: source_error,
        location: snafu::Location::default(),
    })?;
    mount_bind(source, &target)
        .map_err(std::io::Error::from)
        .map_err(|source_error| SessionControllerError::Io {
            action: "holding admitted executable before hiding host runtime",
            path: source.to_path_buf(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
    Ok(Some(target))
}

/// Moves the held, descriptor-verified executable staging mount to its stable
/// private runtime path. Moving rather than duplicating the mount ensures a
/// program's `current_exe()` reports only the stable, workload-visible path,
/// not the root-only holding path.
fn project_admitted_executable(
    source: Option<&Path>,
) -> Result<Option<PathBuf>, SessionControllerError> {
    let Some(source) = source else {
        return Ok(None);
    };
    let target = PathBuf::from(PRIVATE_ADMITTED_EXECUTABLE_PATH);
    File::create(&target).map_err(|source_error| SessionControllerError::Io {
        action: "creating private admitted executable mountpoint",
        path: target.clone(),
        source: source_error,
        location: snafu::Location::default(),
    })?;
    mount_move(source, &target)
        .map_err(std::io::Error::from)
        .map_err(|source_error| SessionControllerError::Io {
            action: "moving held admitted executable into the workload",
            path: source.to_path_buf(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
    mount_remount(
        &target,
        MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
        "",
    )
    .map_err(std::io::Error::from)
    .map_err(|source_error| SessionControllerError::Io {
        action: "locking private admitted executable read-only",
        path: target.clone(),
        source: source_error,
        location: snafu::Location::default(),
    })?;
    Ok(Some(target))
}

/// Hides the caller's live home whenever the intrinsic filesystem Surface
/// supplies either an isolated private-state view or declared caller-home
/// projections. Workspace and executable access is held before the namespace
/// is created, so the workload receives only its admitted view.
fn hide_caller_home_for_session_view(
    handoff: &LinuxControllerHandoff,
) -> Result<(), SessionControllerError> {
    let home = users::get_user_by_uid(handoff.spec.owner().uid())
        .map(|user| user.home_dir().to_path_buf())
        .ok_or_else(|| SessionControllerError::InvalidHandoff {
            reason: format!(
                "session filesystem view cannot resolve a home directory for UID {}",
                handoff.spec.owner().uid()
            ),
            location: snafu::Location::default(),
        })?;
    let has_declared_home_projection = handoff
        .spec
        .filesystem_projections()
        .iter()
        .any(|projection| projection.target().session_overlay_root() == Some(home.as_path()));
    if handoff.prepared_private_state_projection.is_none() && !has_declared_home_projection {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&home).map_err(|source| SessionControllerError::Io {
        action: "checking caller home before hiding the session filesystem view",
        path: home.clone(),
        source,
        location: snafu::Location::default(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SessionControllerError::InvalidHandoff {
            reason: format!(
                "session filesystem view requires a non-symlink caller home directory, found `{}`",
                home.display()
            ),
            location: snafu::Location::default(),
        });
    }
    mount_private_state_mask(&home, "hiding caller home from session filesystem view")?;

    if handoff.prepared_private_state_projection.is_some() {
        if let Some(staged_state) = private_state_path_in_workspace(
            handoff.spec.workspace().requested_path(),
            &home,
            handoff
                .prepared_workspace
                .as_deref()
                .unwrap_or_else(|| handoff.spec.workspace().requested_path()),
        ) {
            mount_private_state_mask(
                &staged_state,
                "hiding caller private state from the admitted workspace",
            )?;
        }
    }
    Ok(())
}

/// A generic declared `.codex` directory is a filesystem tree, not a grant of
/// live IDE authority. Keep the live IPC directory out of the session until a
/// separately admitted binding owns that authority.
fn hide_unadmitted_codex_ipc(
    handoff: &LinuxControllerHandoff,
) -> Result<(), SessionControllerError> {
    let home = users::get_user_by_uid(handoff.spec.owner().uid())
        .map(|user| user.home_dir().to_path_buf())
        .ok_or_else(|| SessionControllerError::InvalidHandoff {
            reason: format!(
                "session filesystem view cannot resolve a home directory for UID {}",
                handoff.spec.owner().uid()
            ),
            location: snafu::Location::default(),
        })?;
    let codex_home = home.join(".codex");
    let codex_state_is_projected = handoff
        .spec
        .filesystem_projections()
        .iter()
        .any(|projection| projection.workload_path() == codex_home);
    if codex_state_is_projected {
        mount_private_state_mask(
            &codex_home.join("ipc"),
            "hiding unadmitted Codex IDE IPC from the session",
        )?;
    }
    Ok(())
}

/// Returns the staging path through which an admitted workspace would expose
/// the caller's private Codex state. A workspace outside the caller home does
/// not receive a mask because it has no lexical route to that state.
fn private_state_path_in_workspace(
    workspace: &Path,
    home: &Path,
    staged_workspace: &Path,
) -> Option<PathBuf> {
    home.join(".codex")
        .strip_prefix(workspace)
        .ok()
        .map(|relative| staged_workspace.join(relative))
}

fn mount_private_state_mask(
    path: &Path,
    action: &'static str,
) -> Result<(), SessionControllerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SessionControllerError::Io {
                action: "checking private state mask target",
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SessionControllerError::InvalidHandoff {
            reason: format!(
                "private state mask target `{}` is not a non-symlink directory",
                path.display()
            ),
            location: snafu::Location::default(),
        });
    }
    let data = CString::new("mode=0700,size=65536").map_err(|error| {
        SessionControllerError::InvalidHandoff {
            reason: error.to_string(),
            location: snafu::Location::default(),
        }
    })?;
    mount(
        "tmpfs",
        path,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(data.as_c_str()),
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionControllerError::Io {
        action,
        path: path.to_path_buf(),
        source,
        location: snafu::Location::default(),
    })
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
        create_preinstalled_projection_target(target, false)?;
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

struct HeldFilesystemProjection {
    source: PathBuf,
    workload_path: PathBuf,
    read_only: bool,
    directory: bool,
    target: FilesystemProjectionTarget,
}

struct HeldPrivateStateProjection {
    lower: PathBuf,
    upper: PathBuf,
    workdir: PathBuf,
    merged: PathBuf,
    target: PathBuf,
}

fn hold_private_state_projection(
    handoff: &LinuxControllerHandoff,
) -> Result<Option<HeldPrivateStateProjection>, SessionControllerError> {
    let Some(prepared) = handoff.prepared_private_state_projection.as_ref() else {
        return Ok(None);
    };
    let root = handoff.evidence_path.join("private-state-projection");
    fs::create_dir_all(&root).map_err(|source| SessionControllerError::Io {
        action: "creating daemon-owned private state hold directory",
        path: root.clone(),
        source,
        location: snafu::Location::default(),
    })?;
    let volume_root =
        prepared
            .lower()
            .parent()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: format!(
                    "private state lower path `{}` has no volume root",
                    prepared.lower().display()
                ),
                location: snafu::Location::default(),
            })?;
    mount_bind(volume_root, &root)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action: "holding the complete daemon-owned private state volume",
            path: volume_root.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
    mount_remount(
        &root,
        MountFlags::BIND | MountFlags::NOSUID | MountFlags::NODEV,
        "",
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionControllerError::Io {
        action: "locking daemon-owned private state volume mount flags",
        path: root.clone(),
        source,
        location: snafu::Location::default(),
    })?;
    let lower = held_private_state_path(&root, volume_root, prepared.lower())?;
    let upper = held_private_state_path(&root, volume_root, prepared.upper())?;
    let workdir = held_private_state_path(&root, volume_root, prepared.workdir())?;
    let merged = held_private_state_path(&root, volume_root, prepared.merged())?;
    Ok(Some(HeldPrivateStateProjection {
        lower,
        upper,
        workdir,
        merged,
        target: prepared.target().to_path_buf(),
    }))
}

fn held_private_state_path(
    held_volume_root: &Path,
    source_volume_root: &Path,
    source: &Path,
) -> Result<PathBuf, SessionControllerError> {
    let relative = source.strip_prefix(source_volume_root).map_err(|_error| {
        SessionControllerError::InvalidHandoff {
            reason: format!(
                "private state path `{}` escapes volume root `{}`",
                source.display(),
                source_volume_root.display()
            ),
            location: snafu::Location::default(),
        }
    })?;
    if relative.as_os_str().is_empty() {
        return Err(SessionControllerError::InvalidHandoff {
            reason: String::from("private state volume root cannot be an overlay component"),
            location: snafu::Location::default(),
        });
    }
    Ok(held_volume_root.join(relative))
}

fn project_private_state(
    projection: &HeldPrivateStateProjection,
) -> Result<(), SessionControllerError> {
    let options = private_state_overlay_options(projection)?;
    mount(
        "overlay",
        &projection.merged,
        "overlay",
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(options.as_c_str()),
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionControllerError::Io {
        action: "mounting the daemon-owned private state overlay",
        path: projection.merged.clone(),
        source,
        location: snafu::Location::default(),
    })?;
    create_preinstalled_projection_target(&projection.target, true)?;
    mount_bind(&projection.merged, &projection.target)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action: "projecting daemon-owned private state into the workload",
            path: projection.target.clone(),
            source,
            location: snafu::Location::default(),
        })?;
    mount_remount(
        &projection.target,
        MountFlags::BIND | MountFlags::NOSUID | MountFlags::NODEV,
        "",
    )
    .map_err(std::io::Error::from)
    .map_err(|source| SessionControllerError::Io {
        action: "locking private state projection mount flags",
        path: projection.target.clone(),
        source,
        location: snafu::Location::default(),
    })
}

fn private_state_overlay_options(
    projection: &HeldPrivateStateProjection,
) -> Result<CString, SessionControllerError> {
    overlay_options(&projection.lower, &projection.upper, &projection.workdir)
}

fn overlay_options(
    lower: &Path,
    upper: &Path,
    workdir: &Path,
) -> Result<CString, SessionControllerError> {
    let option_path = |path: &Path| {
        let value = path
            .to_str()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: format!(
                    "private state overlay path `{}` is not UTF-8",
                    path.display()
                ),
                location: snafu::Location::default(),
            })?;
        if value.contains(',') || value.contains(':') {
            return Err(SessionControllerError::InvalidHandoff {
                reason: format!(
                    "private state overlay path `{}` contains an unsupported mount-option delimiter",
                    path.display()
                ),
                location: snafu::Location::default(),
            });
        }
        Ok(value.to_owned())
    };
    CString::new(format!(
        "lowerdir={},upperdir={},workdir={}",
        option_path(lower)?,
        option_path(upper)?,
        option_path(workdir)?,
    ))
    .map_err(|source| SessionControllerError::InvalidHandoff {
        reason: format!("private state overlay options contain a NUL byte: {source}"),
        location: snafu::Location::default(),
    })
}

fn hold_filesystem_projections(
    handoff: &LinuxControllerHandoff,
) -> Result<Vec<HeldFilesystemProjection>, SessionControllerError> {
    if handoff.prepared_filesystem_projections.len() != handoff.spec.filesystem_projections().len()
    {
        return Err(SessionControllerError::InvalidHandoff {
            reason: String::from(
                "prepared filesystem projections do not match the admitted session",
            ),
            location: snafu::Location::default(),
        });
    }
    let root = handoff.evidence_path.join("filesystem-projections");
    let mut held = Vec::new();
    for (index, (prepared, admitted)) in handoff
        .prepared_filesystem_projections
        .iter()
        .zip(handoff.spec.filesystem_projections())
        .enumerate()
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
        fs::create_dir_all(&root).map_err(|source| SessionControllerError::Io {
            action: "creating daemon-owned filesystem projection directory",
            path: root.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let directory = admitted.source().kind() == erebor_runtime_core::SafePathKind::Directory;
        let source = root.join(index.to_string());
        if directory {
            fs::create_dir(&source)
        } else {
            File::create(&source).map(|_file| ())
        }
        .map_err(|source_error| SessionControllerError::Io {
            action: "creating held filesystem projection mountpoint",
            path: source.clone(),
            source: source_error,
            location: snafu::Location::default(),
        })?;
        mount_bind(prepared.staging_path(), &source)
            .map_err(std::io::Error::from)
            .map_err(|source_error| SessionControllerError::Io {
                action: "holding admitted filesystem artifact before hiding host runtime",
                path: prepared.staging_path().to_path_buf(),
                source: source_error,
                location: snafu::Location::default(),
            })?;
        held.push(HeldFilesystemProjection {
            source,
            workload_path: prepared.workload_path().to_path_buf(),
            read_only: prepared.read_only(),
            directory,
            target: admitted.target().clone(),
        });
    }
    Ok(held)
}

fn project_filesystems(
    projections: &[HeldFilesystemProjection],
) -> Result<(), SessionControllerError> {
    for projection in projections {
        create_projection_target(
            &projection.workload_path,
            projection.directory,
            &projection.target,
        )?;
        mount_bind(&projection.source, &projection.workload_path)
            .map_err(std::io::Error::from)
            .map_err(|source| SessionControllerError::Io {
                action: "projecting held filesystem artifact into the workload",
                path: projection.workload_path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        if projection.read_only {
            mount_remount(
                &projection.workload_path,
                MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
                "",
            )
            .map_err(std::io::Error::from)
            .map_err(|source| SessionControllerError::Io {
                action: "locking filesystem projection read-only",
                path: projection.workload_path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        }
    }
    Ok(())
}

fn install_session_overlay_projection_roots(
    handoff: &LinuxControllerHandoff,
    projections: &[HeldFilesystemProjection],
) -> Result<(), SessionControllerError> {
    let roots = projections
        .iter()
        .filter_map(|projection| projection.target.session_overlay_root())
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();
    for (index, root) in roots.into_iter().enumerate() {
        let metadata =
            fs::symlink_metadata(&root).map_err(|source| SessionControllerError::Io {
                action: "checking session-overlay mount root",
                path: root.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SessionControllerError::InvalidHandoff {
                reason: format!(
                    "session-overlay mount root `{}` is not a non-symlink directory",
                    root.display()
                ),
                location: snafu::Location::default(),
            });
        }
        let storage = handoff
            .evidence_path
            .join("filesystem-projection-overlays")
            .join(index.to_string());
        let upper = storage.join("upper");
        let workdir = storage.join("work");
        fs::create_dir_all(&upper).map_err(|source| SessionControllerError::Io {
            action: "creating session-overlay upper directory",
            path: upper.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        fs::create_dir_all(&workdir).map_err(|source| SessionControllerError::Io {
            action: "creating session-overlay work directory",
            path: workdir.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let options = overlay_options(&root, &upper, &workdir)?;
        mount(
            "overlay",
            &root,
            "overlay",
            MountFlags::NOSUID | MountFlags::NODEV,
            Some(options.as_c_str()),
        )
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action: "mounting session-overlay projection root",
            path: root.clone(),
            source,
            location: snafu::Location::default(),
        })?;
    }
    Ok(())
}

fn create_projection_target(
    path: &Path,
    directory: bool,
    target: &FilesystemProjectionTarget,
) -> Result<(), SessionControllerError> {
    if target.session_overlay_root().is_some() {
        return create_session_overlay_projection_target(path, directory);
    }
    create_preinstalled_projection_target(path, directory)
}

fn create_preinstalled_projection_target(
    path: &Path,
    directory: bool,
) -> Result<(), SessionControllerError> {
    let private_runtime = Path::new("/run/erebor");
    if path.starts_with(private_runtime) {
        let parent = path
            .parent()
            .ok_or_else(|| SessionControllerError::InvalidHandoff {
                reason: format!("projection target `{}` has no parent", path.display()),
                location: snafu::Location::default(),
            })?;
        create_private_projection_parent(private_runtime, parent)?;
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

fn create_session_overlay_projection_target(
    path: &Path,
    directory: bool,
) -> Result<(), SessionControllerError> {
    let parent = path
        .parent()
        .ok_or_else(|| SessionControllerError::InvalidHandoff {
            reason: format!(
                "session-overlay projection target `{}` has no parent",
                path.display()
            ),
            location: snafu::Location::default(),
        })?;
    fs::create_dir_all(parent).map_err(|source| SessionControllerError::Io {
        action: "creating session-overlay projection parent",
        path: parent.to_path_buf(),
        source,
        location: snafu::Location::default(),
    })?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() == directory => {
            Ok(())
        }
        Ok(_) => Err(SessionControllerError::InvalidHandoff {
            reason: format!(
                "session-overlay projection target `{}` has the wrong type or is a symlink",
                path.display()
            ),
            location: snafu::Location::default(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => if directory {
            fs::create_dir(path)
        } else {
            File::create(path).map(|_file| ())
        }
        .map_err(|source| SessionControllerError::Io {
            action: "creating session-overlay projection mountpoint",
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }),
        Err(source) => Err(SessionControllerError::Io {
            action: "checking session-overlay projection mountpoint",
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }),
    }
}

/// Private runtime projections are root-owned, but their declared paths are
/// deliberately usable by the workload.  The daemon service may have a
/// restrictive umask, so make each newly created parent searchable without
/// making it listable or writable by the workload user.
fn create_private_projection_parent(
    private_runtime: &Path,
    parent: &Path,
) -> Result<(), SessionControllerError> {
    fs::create_dir_all(parent).map_err(|source| SessionControllerError::Io {
        action: "creating private projection parent",
        path: parent.to_path_buf(),
        source,
        location: snafu::Location::default(),
    })?;
    let relative = parent.strip_prefix(private_runtime).map_err(|_error| {
        SessionControllerError::InvalidHandoff {
            reason: format!(
                "private projection parent `{}` escaped `{}`",
                parent.display(),
                private_runtime.display()
            ),
            location: snafu::Location::default(),
        }
    })?;
    let mut current = private_runtime.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        current.push(component);
        fs::set_permissions(&current, fs::Permissions::from_mode(0o711)).map_err(|source| {
            SessionControllerError::Io {
                action: "making private projection parent searchable",
                path: current.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
    }
    Ok(())
}

fn environment_value(environment: &[(String, String)], key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(candidate, _value)| candidate == key)
        .map(|(_key, value)| value.clone())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use erebor_runtime_core::FilesystemProjectionTarget;

    use super::{
        create_private_projection_parent, create_projection_target, held_private_state_path,
        private_state_path_in_workspace,
    };

    #[test]
    fn private_projection_parents_are_searchable_but_not_listable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let runtime = temporary.path().join("erebor");
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o711))?;
        let parent = runtime.join("codex").join("hooks");

        create_private_projection_parent(&runtime, &parent)?;

        for directory in [runtime.join("codex"), parent] {
            assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o777, 0o711);
        }
        Ok(())
    }

    #[test]
    fn private_state_overlay_components_stay_beneath_one_held_volume_root(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let held = Path::new("/evidence/private-state");
        let source = Path::new("/state/session/filesystem/work/volumes/agent-state");

        assert_eq!(
            held_private_state_path(held, source, &source.join("lower-ro"))?,
            held.join("lower-ro")
        );
        assert_eq!(
            held_private_state_path(held, source, &source.join("overlay/upper"))?,
            held.join("overlay/upper")
        );
        assert!(held_private_state_path(held, source, Path::new("/outside/upper")).is_err());
        Ok(())
    }

    #[test]
    fn private_state_inside_an_admitted_home_workspace_is_masked_at_staging() {
        assert_eq!(
            private_state_path_in_workspace(
                Path::new("/home/agent"),
                Path::new("/home/agent"),
                Path::new("/run/erebor/1000/session/staging/workspace"),
            ),
            Some(Path::new("/run/erebor/1000/session/staging/workspace/.codex").to_path_buf())
        );
        assert_eq!(
            private_state_path_in_workspace(
                Path::new("/workspace/project"),
                Path::new("/home/agent"),
                Path::new("/run/erebor/1000/session/staging/workspace"),
            ),
            None
        );
    }

    #[test]
    fn session_overlay_target_is_created_without_a_host_mountpoint(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("session-overlay");
        fs::create_dir(&root)?;
        let target = root.join("codex").join("requirements.toml");
        let projection = FilesystemProjectionTarget::SessionOverlay {
            mount_root: root.clone(),
        };

        create_projection_target(&target, false, &projection)?;

        assert!(target.is_file());
        Ok(())
    }
}
