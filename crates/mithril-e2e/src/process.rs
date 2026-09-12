#![allow(unsafe_code)]

#[cfg(test)]
mod tests;

use std::cell::RefCell;
#[cfg(test)]
use std::ffi::CString;
use std::ffi::OsStr;
#[cfg(test)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Write};
#[cfg(test)]
use std::os::fd::AsRawFd as _;
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

#[cfg(test)]
use linux_raw_sys::general::clone_args;
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use snafu::{ensure, OptionExt as _, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::Result;

const FIXTURE_DIR: &str = "crates/mithril-e2e/fixtures/process";
const LOG_LIMIT: usize = 8 * 1024;
#[cfg(test)]
const HELD: &[u8] = b"held\n";
const READY: &[u8] = b"native-fixture-ready\n";
const START_LIMIT: Duration = Duration::from_secs(30);
const STOP_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct ProcessFixture {
    child: Option<Child>,
    raw_pid: Option<u32>,
    actor_pid: u32,
    path: PathBuf,
    stdin: Option<Box<dyn Write + Send>>,
    stdout: Option<File>,
    stderr: Option<File>,
    #[cfg(test)]
    gate: Option<UnixStream>,
    group: Option<PathBuf>,
    tasks: Vec<(u32, OwnedFd)>,
    stopped: bool,
}

impl ProcessFixture {
    pub(crate) fn namespace_pid(pid: u32) -> Result<u32> {
        let path = PathBuf::from(format!("/proc/{pid}/status"));
        let status = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .and_then(|value| value.split_ascii_whitespace().last())
            .and_then(|value| value.parse().ok())
            .context(InvalidInputSnafu {
                path,
                reason: "the process status has no namespace PID",
            })
    }

    pub(crate) fn new(mut child: Child, path: &Path) -> Self {
        let actor_pid = child.id();
        Self {
            stdin: child
                .stdin
                .take()
                .map(|input| Box::new(input) as Box<dyn Write + Send>),
            stdout: child
                .stdout
                .take()
                .map(|output| File::from(OwnedFd::from(output))),
            stderr: child
                .stderr
                .take()
                .map(|output| File::from(OwnedFd::from(output))),
            #[cfg(test)]
            gate: None,
            group: None,
            tasks: Vec::new(),
            child: Some(child),
            raw_pid: None,
            actor_pid,
            path: path.to_owned(),
            stopped: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_pid(pid: u32, input: File, path: &Path) -> Self {
        Self {
            child: None,
            raw_pid: None,
            actor_pid: pid,
            path: path.to_owned(),
            stdin: Some(Box::new(input)),
            stdout: None,
            stderr: None,
            #[cfg(test)]
            gate: None,
            group: None,
            tasks: Vec::new(),
            stopped: false,
        }
    }

    pub(crate) fn script(root: &Path, name: &str) -> Result<PathBuf> {
        let path = root.join(FIXTURE_DIR).join(name);
        ensure!(
            path.is_file(),
            InvalidInputSnafu {
                path: &path,
                reason: "the process fixture program is missing",
            }
        );
        Ok(path)
    }

    pub(crate) fn fatal_exec(path: &Path) -> Result<()> {
        const PT_LOAD: u32 = 1;

        let source = Path::new("/bin/true");
        let mut bytes = fs::read(source).context(IoSnafu { path: source })?;
        ensure!(
            bytes.get(0..4) == Some(b"\x7fELF") && bytes.get(5) == Some(&1),
            InvalidInputSnafu {
                path: source,
                reason: "the post-PONR fixture requires a little-endian ELF",
            }
        );
        let (program_offset, entry_size, entry_count, filesz_offset, memsz_offset) =
            match bytes.get(4).copied() {
                Some(2) => (
                    read_u64_le(&bytes, 32, "ELF64 program-header offset")? as usize,
                    read_u16(&bytes, 54, "ELF64 program-header size")? as usize,
                    read_u16(&bytes, 56, "ELF64 program-header count")? as usize,
                    32,
                    40,
                ),
                Some(1) => (
                    read_u32(&bytes, 28, "ELF32 program-header offset")? as usize,
                    read_u16(&bytes, 42, "ELF32 program-header size")? as usize,
                    read_u16(&bytes, 44, "ELF32 program-header count")? as usize,
                    16,
                    20,
                ),
                class => {
                    return Err(bad_elf(format!(
                        "unsupported ELF class {class:?} for the post-PONR fixture"
                    )))
                }
            };
        let field_size = if bytes[4] == 2 { 8 } else { 4 };
        let mut patched = false;
        for index in 0..entry_count {
            let offset = program_offset
                .checked_add(index.saturating_mul(entry_size))
                .ok_or_else(|| bad_elf("ELF program-header offset overflowed"))?;
            if read_u32(&bytes, offset, "ELF program-header type")? != PT_LOAD {
                continue;
            }
            let filesz = read_uint(
                &bytes,
                offset + filesz_offset,
                field_size,
                "ELF PT_LOAD file size",
            )?;
            ensure!(
                filesz > 0,
                InvalidInputSnafu {
                    path: source,
                    reason: "the first ELF PT_LOAD segment has no file bytes",
                }
            );
            write_uint(
                &mut bytes,
                offset + memsz_offset,
                field_size,
                filesz - 1,
                "ELF PT_LOAD memory size",
            )?;
            patched = true;
            break;
        }
        ensure!(
            patched,
            InvalidInputSnafu {
                path: source,
                reason: "the source ELF has no PT_LOAD segment",
            }
        );
        fs::write(path, bytes).context(IoSnafu { path })?;
        let mut mode = fs::metadata(path).context(IoSnafu { path })?.permissions();
        mode.set_mode(0o700);
        fs::set_permissions(path, mode).context(IoSnafu { path })
    }

    pub(crate) fn python<I, S>(root: &Path, name: &str, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let mut command = Command::new("python3");
        command.arg(&script).args(args);
        Self::start(&mut command, &script)
    }

    pub(crate) fn unshare<I, S>(root: &Path, name: &str, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--pid", "--fork", "python3"])
            .arg(&script)
            .args(args);
        Self::start(&mut command, &script)
    }

    #[cfg(test)]
    pub(crate) fn pidns<I, S>(root: &Path, name: &str, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--pid", "--fork", "--mount-proc", "/usr/bin/python3"])
            .arg(&script)
            .args(args);
        Self::start(&mut command, &script)
    }

    #[cfg(test)]
    pub(crate) fn held_pidns<I, S>(
        root: &Path,
        name: &str,
        args: I,
        cgroup: &Path,
        rootfs: &Path,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let python = c"/usr/bin/python3".to_owned();
        let actor = cstring(&Path::new("/fixtures").join(name))?;
        let root_c = cstring(rootfs)?;
        let mut values = vec![python.clone(), actor];
        for arg in args {
            values.push(cstring(Path::new(arg.as_ref()))?);
        }
        let mut argv = values
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        argv.push(std::ptr::null());
        let group = File::open(cgroup).context(IoSnafu { path: cgroup })?;
        let pipe = || {
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: &script })
        };
        let (child_in, input) = pipe()?;
        let output_path = rootfs.join("work/actor.stdout");
        let error_path = rootfs.join("work/actor.stderr");
        let child_out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output_path)
            .context(IoSnafu { path: &output_path })?;
        let child_err = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&error_path)
            .context(IoSnafu { path: &error_path })?;
        let output = File::open(&output_path).context(IoSnafu { path: &output_path })?;
        let errors = File::open(&error_path).context(IoSnafu { path: &error_path })?;
        let (gate, child_gate) = UnixStream::pair().context(IoSnafu { path: &script })?;
        let clone = clone_args {
            flags: linux_raw_sys::general::CLONE_INTO_CGROUP
                | u64::from(linux_raw_sys::general::CLONE_NEWPID),
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: group.as_raw_fd() as u64,
        };
        let result =
            unsafe { libc::syscall(libc::SYS_clone3, &raw const clone, size_of::<clone_args>()) };
        if result == 0 {
            run_held(
                &python,
                &argv,
                &child_in,
                &child_out,
                &child_err,
                &child_gate,
                &root_c,
            );
        }
        ensure!(
            result > 0,
            InvalidInputSnafu {
                path: &script,
                reason: format!(
                    "clone3 held actor failed: {}",
                    std::io::Error::last_os_error()
                ),
            }
        );
        drop((child_in, child_out, child_err, child_gate));
        let pid = u32::try_from(result).map_err(|source| {
            InvalidInputSnafu {
                path: &script,
                reason: format!("clone3 returned an invalid PID: {source}"),
            }
            .build()
        })?;
        let mut fixture = Self {
            child: None,
            raw_pid: Some(pid),
            actor_pid: pid,
            path: script,
            stdin: Some(Box::new(File::from(input))),
            stdout: Some(output),
            stderr: Some(errors),
            gate: Some(gate),
            group: Some(cgroup.to_owned()),
            tasks: Vec::new(),
            stopped: false,
        };
        fixture.set_init(pid)?;
        fixture.wait_held()?;
        Ok(fixture)
    }

    #[cfg(test)]
    fn wait_held(&mut self) -> Result<()> {
        let mut gate = self.gate.take().context(InvalidInputSnafu {
            path: &self.path,
            reason: "the process has no pre-exec gate",
        })?;
        let flags = rustix::fs::fcntl_getfl(&gate).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("read pre-exec gate flags: {source}"),
            }
            .build()
        })?;
        rustix::fs::fcntl_setfl(&gate, flags | rustix::fs::OFlags::NONBLOCK).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("make pre-exec gate nonblocking: {source}"),
            }
            .build()
        })?;
        let path = self.path.clone();
        let received = RefCell::new(Vec::new());
        let result = self.wait_path(
            &path,
            "held actor pre-exec readiness",
            START_LIMIT,
            || {
                let mut buffer = [0_u8; 16];
                match gate.read(&mut buffer) {
                    Ok(0) => Ok(None),
                    Ok(count) => {
                        let mut received = received.borrow_mut();
                        received.extend_from_slice(&buffer[..count]);
                        if received.as_slice() == HELD {
                            Ok(Some(()))
                        } else if HELD.starts_with(received.as_slice()) {
                            Ok(None)
                        } else {
                            InvalidInputSnafu {
                                path: &path,
                                reason: format!(
                                    "invalid pre-exec marker: {:?}",
                                    String::from_utf8_lossy(&received)
                                ),
                            }
                            .fail()
                        }
                    }
                    Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(None),
                    Err(source) => Err(source).context(IoSnafu { path: &path }),
                }
            },
            || {
                format!(
                    "received pre-exec bytes {:?}",
                    String::from_utf8_lossy(&received.borrow())
                )
            },
        );
        self.gate = Some(gate);
        result
    }

    #[cfg(test)]
    pub(crate) fn release(&mut self) -> Result<()> {
        self.gate
            .take()
            .context(InvalidInputSnafu {
                path: &self.path,
                reason: "the process is not held before exec",
            })?
            .write_all(b"1")
            .context(IoSnafu { path: &self.path })
    }

    pub(crate) fn start(command: &mut Command, path: &Path) -> Result<Self> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu { path })?;
        let mut fixture = Self::new(child, path);
        fixture.ready()?;
        Ok(fixture)
    }

    pub(crate) fn id(&self) -> u32 {
        self.actor_pid
    }

    #[cfg(test)]
    fn set_actor(&mut self, pid: u32) -> Result<()> {
        self.track(pid)?;
        self.actor_pid = pid;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_init(&mut self, pid: u32) -> Result<()> {
        ensure!(
            Self::namespace_pid(pid)? == 1,
            InvalidInputSnafu {
                path: &self.path,
                reason: "the initial actor is not PID 1",
            }
        );
        self.set_actor(pid)
    }

    pub(crate) fn track(&mut self, id: u32) -> Result<()> {
        if self.tasks.iter().any(|(known, _)| *known == id) {
            return Ok(());
        }
        let raw = i32::try_from(id).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("the tracked PID is invalid: {source}"),
            }
            .build()
        })?;
        let pid = Pid::from_raw(raw).context(InvalidInputSnafu {
            path: &self.path,
            reason: "PID zero cannot identify a tracked process",
        })?;
        let fd = pidfd_open(pid, PidfdFlags::empty()).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("open pidfd for {id}: {source}"),
            }
            .build()
        })?;
        self.tasks.push((id, fd));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_group(&mut self, path: &Path) {
        self.group = Some(path.to_owned());
    }

    pub(crate) fn signal(&self, id: u32, signal: Signal) -> Result<()> {
        let fd = self
            .tasks
            .iter()
            .find_map(|(known, fd)| (*known == id).then_some(fd))
            .context(InvalidInputSnafu {
                path: &self.path,
                reason: "the process is not tracked",
            })?;
        pidfd_send_signal(fd, signal).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("signal tracked process {id}: {source}"),
            }
            .build()
        })
    }

    pub(crate) fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.stdin
            .as_mut()
            .context(InvalidInputSnafu {
                path: &self.path,
                reason: "the process stdin is closed",
            })?
            .write_all(bytes)
            .context(IoSnafu { path: &self.path })
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(child) = self.child.as_mut() {
            return child
                .try_wait()
                .context(IoSnafu { path: &self.path })
                .inspect(|status| self.stopped |= status.is_some());
        }
        let pid = self.raw_pid.context(InvalidInputSnafu {
            path: &self.path,
            reason: "the external process has no child exit status",
        })?;
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid as libc::pid_t, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context(IoSnafu { path: &self.path });
        }
        if result == 0 {
            return Ok(None);
        }
        self.raw_pid = None;
        self.stopped = true;
        Ok(Some(ExitStatus::from_raw(status)))
    }

    #[cfg(test)]
    pub(crate) fn ensure_running(&mut self, operation: &str) -> Result<()> {
        let Some(status) = self.try_wait()? else {
            return Ok(());
        };
        let stderr = self.stderr()?;
        InvalidInputSnafu {
            path: &self.path,
            reason: format!(
                "the process exited with {status} before {operation}; stderr: {stderr:?}"
            ),
        }
        .fail()
    }

    pub(crate) fn wait_exit(&mut self, operation: &str, limit: Duration) -> Result<ExitStatus> {
        let path = self.path.clone();
        wait_for(
            &path,
            operation,
            limit,
            || self.try_wait(),
            || "the process is still running".to_owned(),
        )
    }

    pub(crate) fn wait_pid(&mut self, path: &Path, operation: &str) -> Result<u32> {
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                *last.borrow_mut() = text.trim().to_owned();
                if text.trim().is_empty() {
                    return Ok(None);
                }
                text.trim().parse::<u32>().map(Some).map_err(|source| {
                    InvalidInputSnafu {
                        path,
                        reason: format!("the actor wrote an invalid PID: {source}"),
                    }
                    .build()
                })
            },
            || format!("last PID value: {:?}", last.borrow()),
        )
    }

    pub(crate) fn wait_pair(&mut self, path: &Path, operation: &str) -> Result<[u32; 2]> {
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                *last.borrow_mut() = text.trim().to_owned();
                let ids = text
                    .split_ascii_whitespace()
                    .map(|value| {
                        value.parse::<u32>().map_err(|source| {
                            InvalidInputSnafu {
                                path,
                                reason: format!("the actor wrote an invalid PID: {source}"),
                            }
                            .build()
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                if ids.len() < 2 {
                    return Ok(None);
                }
                ensure!(
                    ids.len() == 2 && ids[0] != ids[1],
                    InvalidInputSnafu {
                        path,
                        reason: "the actor must report two distinct PIDs",
                    }
                );
                Ok(Some([ids[0], ids[1]]))
            },
            || format!("last PID values: {:?}", last.borrow()),
        )
    }

    #[cfg(test)]
    pub(crate) fn wait_child(&mut self, pid: u32, operation: &str) -> Result<u32> {
        let path = PathBuf::from(format!("/proc/{pid}/task/{pid}/children"));
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                *last.borrow_mut() = text.trim().to_owned();
                text.split_ascii_whitespace()
                    .next()
                    .map(|value| {
                        value.parse::<u32>().map_err(|source| {
                            InvalidInputSnafu {
                                path: &path,
                                reason: format!("the child PID is invalid: {source}"),
                            }
                            .build()
                        })
                    })
                    .transpose()
            },
            || format!("parent PID {pid}; last child PIDs: {:?}", last.borrow()),
        )
    }

    #[cfg(test)]
    pub(crate) fn wait_thread(&mut self, ns_tid: u32, operation: &str) -> Result<u32> {
        let pid = self.actor_pid;
        let path = PathBuf::from(format!("/proc/{pid}/task"));
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || {
                let entries = match fs::read_dir(&path) {
                    Ok(entries) => entries,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                let mut tids = Vec::new();
                for entry in entries {
                    let entry = entry.context(IoSnafu { path: &path })?;
                    let Some(tid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|value| value.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    tids.push(tid);
                    if tid != pid && Self::namespace_pid(tid)? == ns_tid {
                        return Ok(Some(tid));
                    }
                }
                *last.borrow_mut() = format!("{tids:?}");
                Ok(None)
            },
            || format!("namespace TID {ns_tid}; last host TIDs: {}", last.borrow()),
        )
    }

    pub(crate) fn wait_stop(&mut self, id: u32, operation: &str) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{id}/status"));
        let last = RefCell::new(String::from("State: <absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                *last.borrow_mut() = text
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .unwrap_or("State: <missing>")
                    .to_owned();
                Ok(text
                    .lines()
                    .any(|line| line.starts_with("State:\tT") || line.starts_with("State:\tt"))
                    .then_some(()))
            },
            || format!("process {id}; last {}", last.borrow()),
        )
    }

    pub(crate) fn wait_gone(&mut self, id: u32, operation: &str) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{id}/status"));
        let last = RefCell::new(String::from("State: <absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || match fs::read_to_string(&path) {
                Ok(text) => {
                    *last.borrow_mut() = text
                        .lines()
                        .find(|line| line.starts_with("State:"))
                        .unwrap_or("State: <missing>")
                        .to_owned();
                    Ok(None)
                }
                Err(source) if source.kind() == ErrorKind::NotFound => Ok(Some(())),
                Err(source) => Err(source).context(IoSnafu { path: &path }),
            },
            || format!("process {id}; last {}", last.borrow()),
        )
    }

    pub(crate) fn wait_path<T>(
        &mut self,
        path: &Path,
        operation: &str,
        limit: Duration,
        mut inspect: impl FnMut() -> Result<Option<T>>,
        state: impl Fn() -> String,
    ) -> Result<T> {
        let state = &state;
        wait_for(
            path,
            operation,
            limit,
            || {
                if let Some(value) = inspect()? {
                    return Ok(Some(value));
                }
                if !self.stopped {
                    if let Some(status) = self.try_wait()? {
                        return InvalidInputSnafu {
                            path,
                            reason: format!(
                                "the process exited with {status} before {operation}; {}; stderr: {:?}",
                                state(),
                                self.stderr()?
                            ),
                        }
                        .fail();
                    }
                }
                Ok(None)
            },
            state,
        )
    }

    pub(crate) fn stderr(&mut self) -> Result<String> {
        let Some(stderr) = self.stderr.as_mut() else {
            return Ok("<not captured>".to_owned());
        };
        let flags = rustix::fs::fcntl_getfl(&*stderr).map_err(|error| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("read stderr pipe flags: {error}"),
            }
            .build()
        })?;
        rustix::fs::fcntl_setfl(&*stderr, flags | rustix::fs::OFlags::NONBLOCK).map_err(
            |error| {
                InvalidInputSnafu {
                    path: &self.path,
                    reason: format!("make stderr pipe nonblocking: {error}"),
                }
                .build()
            },
        )?;
        let mut output = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count]);
                    if output.len() >= LOG_LIMIT {
                        output.drain(..output.len() - LOG_LIMIT);
                    }
                }
                Err(source) if source.kind() == ErrorKind::WouldBlock => break,
                Err(source) => return Err(source).context(IoSnafu { path: &self.path }),
            }
        }
        Ok(String::from_utf8_lossy(&output).trim().to_owned())
    }

    pub(crate) fn close(&mut self) {
        #[cfg(test)]
        {
            self.gate.take();
        }
        self.stdin.take();
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        self.close();
        let _ = self.wait_exit("graceful process cleanup", STOP_GRACE);
        let mut failed = None;
        let ids = self.tasks.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let killed = self.group.as_ref().is_some_and(|group| {
            let path = group.join("cgroup.kill");
            match fs::write(&path, "1") {
                Ok(()) => true,
                Err(source) if source.kind() == ErrorKind::NotFound => false,
                Err(source) => {
                    failed = Some(format!("kill actor cgroup {}: {source}", group.display()));
                    false
                }
            }
        });
        if !killed {
            for (id, fd) in &self.tasks {
                match pidfd_send_signal(fd, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(source) => {
                        failed = Some(format!("kill tracked process {id}: {source}"));
                    }
                }
            }
        }
        self.tasks.clear();
        if let Some(child) = self.child.as_mut() {
            if !self.stopped
                && child
                    .try_wait()
                    .context(IoSnafu { path: &self.path })?
                    .is_none()
            {
                child.kill().context(IoSnafu { path: &self.path })?;
                child.wait().context(IoSnafu { path: &self.path })?;
                self.stopped = true;
            }
        } else if let Some(pid) = self.raw_pid.take() {
            let mut status = 0;
            if unsafe { libc::waitpid(pid as libc::pid_t, &raw mut status, 0) } < 0 {
                failed = Some(format!(
                    "reap tracked process {pid}: {}",
                    std::io::Error::last_os_error()
                ));
            } else {
                self.stopped = true;
            }
        }
        let group = self.group.as_ref();
        if let Some(group) = group {
            let path = group.join("cgroup.procs");
            let last = RefCell::new(String::new());
            if let Err(source) = wait_for(
                &path,
                "actor cgroup cleanup",
                START_LIMIT,
                || {
                    let value = match fs::read_to_string(&path) {
                        Ok(value) => value,
                        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(Some(())),
                        Err(source) => return Err(source).context(IoSnafu { path: &path }),
                    };
                    *last.borrow_mut() = value;
                    Ok(last.borrow().trim().is_empty().then_some(()))
                },
                || format!("last cgroup.procs: {:?}", last.borrow()),
            ) {
                failed = Some(source.to_string());
            }
        } else {
            for id in ids {
                let path = PathBuf::from(format!("/proc/{id}"));
                if let Err(source) = wait_for(
                    &path,
                    "tracked process cleanup",
                    START_LIMIT,
                    || Ok((!path.exists()).then_some(())),
                    || format!("tracked process {id} still exists"),
                ) {
                    failed = Some(source.to_string());
                }
            }
        }
        match failed {
            Some(reason) => InvalidInputSnafu {
                path: &self.path,
                reason,
            }
            .fail(),
            None => Ok(()),
        }
    }

    pub(crate) fn ready(&mut self) -> Result<()> {
        let mut stdout = self.stdout.take().context(InvalidInputSnafu {
            path: &self.path,
            reason: "the process stdout is not captured",
        })?;
        let flags = rustix::fs::fcntl_getfl(&stdout).map_err(|error| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("read readiness pipe flags: {error}"),
            }
            .build()
        })?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK).map_err(
            |error| {
                InvalidInputSnafu {
                    path: &self.path,
                    reason: format!("make readiness pipe nonblocking: {error}"),
                }
                .build()
            },
        )?;

        let path = self.path.clone();
        let received = RefCell::new(Vec::new());
        let result = self.wait_path(
            &path,
            "the process input barrier",
            START_LIMIT,
            || {
                let mut buffer = [0_u8; 64];
                match stdout.read(&mut buffer) {
                    Ok(0) => Ok(None),
                    Ok(count) => {
                        let mut received = received.borrow_mut();
                        received.extend_from_slice(&buffer[..count]);
                        if received.as_slice() == READY {
                            Ok(Some(()))
                        } else if READY.starts_with(received.as_slice()) {
                            Ok(None)
                        } else {
                            InvalidInputSnafu {
                                path: &path,
                                reason: format!(
                                    "invalid readiness marker: {:?}",
                                    String::from_utf8_lossy(&received)
                                ),
                            }
                            .fail()
                        }
                    }
                    Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(None),
                    Err(source) => Err(source).context(IoSnafu { path: &path }),
                }
            },
            || {
                format!(
                    "received readiness bytes {:?}",
                    String::from_utf8_lossy(&received.borrow())
                )
            },
        );
        self.stdout = Some(stdout);
        result
    }
}

fn read_u16(bytes: &[u8], offset: usize, name: &str) -> Result<u16> {
    let value = bytes
        .get(offset..offset + size_of::<u16>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| bad_elf(format!("{name} is truncated")))?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize, name: &str) -> Result<u32> {
    let value = bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| bad_elf(format!("{name} is truncated")))?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| bad_elf(format!("{name} is truncated")))?;
    Ok(u64::from_le_bytes(value))
}

fn read_uint(bytes: &[u8], offset: usize, size: usize, name: &str) -> Result<u64> {
    match size {
        4 => read_u32(bytes, offset, name).map(u64::from),
        8 => read_u64_le(bytes, offset, name),
        _ => Err(bad_elf(format!("{name} has unsupported size {size}"))),
    }
}

fn write_uint(bytes: &mut [u8], offset: usize, size: usize, value: u64, name: &str) -> Result<()> {
    let encoded = match size {
        4 => u32::try_from(value)
            .map_err(|source| bad_elf(format!("{name} does not fit ELF32: {source}")))?
            .to_le_bytes()
            .to_vec(),
        8 => value.to_le_bytes().to_vec(),
        _ => return Err(bad_elf(format!("{name} has unsupported size {size}"))),
    };
    let target = bytes
        .get_mut(offset..offset + size)
        .ok_or_else(|| bad_elf(format!("{name} is truncated")))?;
    target.copy_from_slice(&encoded);
    Ok(())
}

fn bad_elf(reason: impl Into<String>) -> crate::Error {
    InvalidInputSnafu {
        path: Path::new("/bin/true"),
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
fn cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|source| {
        InvalidInputSnafu {
            path,
            reason: format!("the actor argument contains a null byte: {source}"),
        }
        .build()
    })
}

#[cfg(test)]
fn run_held(
    python: &CString,
    argv: &[*const libc::c_char],
    input: &OwnedFd,
    output: &File,
    errors: &File,
    gate: &UnixStream,
    rootfs: &CString,
) -> ! {
    unsafe {
        if libc::chroot(rootfs.as_ptr()) < 0 || libc::chdir(c"/".as_ptr()) < 0 {
            libc::_exit(125);
        }
        if libc::dup2(input.as_raw_fd(), libc::STDIN_FILENO) < 0
            || libc::dup2(output.as_raw_fd(), libc::STDOUT_FILENO) < 0
            || libc::dup2(errors.as_raw_fd(), libc::STDERR_FILENO) < 0
        {
            libc::_exit(126);
        }
        if libc::write(gate.as_raw_fd(), HELD.as_ptr().cast(), HELD.len()) != HELD.len() as isize {
            libc::_exit(126);
        }
        let mut release = 0_u8;
        if libc::read(gate.as_raw_fd(), (&raw mut release).cast(), 1) != 1 {
            libc::_exit(126);
        }
        libc::execv(python.as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        let _result = self.stop();
    }
}
