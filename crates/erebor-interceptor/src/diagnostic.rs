use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{IntoError as _, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu};
use crate::Result;

pub const MAX_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT_FRAMES: u64 = 4096;
pub const PREPARATION_LIMIT: Duration = Duration::from_secs(10);
pub const DRAIN_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticMode {
    Compile,
    Capture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticStop {
    Exited,
    Cancelled,
    Deadline,
    PreparationDeadline,
    OutputLimit,
    ConsumerSlow,
    PipeFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticFrame {
    pub sequence: u64,
    pub stderr: bool,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticResult {
    pub process_id: u32,
    pub stop: DiagnosticStop,
    pub exit_code: Option<i32>,
    pub forced_kill: bool,
    pub output_incomplete: bool,
    pub emitted_frames: u64,
    pub retained_bytes: usize,
    pub elapsed_ms: u64,
    pub attach_notification_ms: Option<u64>,
    pub program_ids: BTreeSet<u32>,
    pub map_ids: BTreeSet<u32>,
    pub cleanup_verified: Option<bool>,
    pub peak_rss_kib: Option<u64>,
}

pub struct DiagnosticBackend {
    executable: PathBuf,
    sha256: [u8; 32],
}

pub struct DiagnosticCapture {
    frames: mpsc::Receiver<DiagnosticFrame>,
    signals: Arc<DiagnosticSignals>,
    worker: Option<JoinHandle<Result<DiagnosticResult>>>,
}

#[derive(Default)]
struct DiagnosticSignals {
    cancelled: AtomicBool,
    process_id: AtomicU32,
}

impl DiagnosticBackend {
    pub fn new(executable: PathBuf, sha256: [u8; 32]) -> Result<Self> {
        if !executable.is_absolute() || sha256 == [0; 32] {
            return InvalidConfigurationSnafu {
                path: executable,
                reason: "diagnostic executable needs an absolute path and a pinned digest",
            }
            .fail();
        }
        Ok(Self { executable, sha256 })
    }

    pub fn start(
        &self,
        source: &[u8],
        cgroup_id: u64,
        mode: DiagnosticMode,
        collection: Duration,
    ) -> Result<DiagnosticCapture> {
        if source.is_empty()
            || source.len() > MAX_SOURCE_BYTES
            || source.contains(&0)
            || collection.is_zero()
            || collection > Duration::from_secs(300)
            || cgroup_id == 0
        {
            return InvalidConfigurationSnafu {
                path: &self.executable,
                reason: "diagnostic source, cgroup parameter, or duration is invalid",
            }
            .fail();
        }
        let executable = File::open(&self.executable).context(IoSnafu {
            action: "open diagnostic executable",
            path: &self.executable,
        })?;
        let mut hash = Sha256::new();
        std::io::copy(&mut &executable, &mut hash).context(IoSnafu {
            action: "hash diagnostic executable",
            path: &self.executable,
        })?;
        if <[u8; 32]>::from(hash.finalize()) != self.sha256 {
            return InvalidConfigurationSnafu {
                path: &self.executable,
                reason: "diagnostic executable digest changed",
            }
            .fail();
        }
        let source = source.to_vec();
        let path = self.executable.clone();
        DiagnosticCapture::spawn(&self.executable, move |signals, send| {
            let command = Self::command(&executable, cgroup_id, mode);
            SupervisedChild::run(command, &path, source, mode, collection, signals, send)
        })
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn start_fixture(
        mut command: Command,
        mode: DiagnosticMode,
        collection: Duration,
    ) -> Result<DiagnosticCapture> {
        let path = PathBuf::from(command.get_program());
        let run_path = path.clone();
        Self::set_child_io(&mut command);
        DiagnosticCapture::spawn(&path, move |signals, send| {
            SupervisedChild::run(
                command,
                &run_path,
                b"fixture".to_vec(),
                mode,
                collection,
                signals,
                send,
            )
        })
    }

    fn command(executable: &File, cgroup_id: u64, mode: DiagnosticMode) -> Command {
        // Execute the checked inode, not a second lookup of its configured path.
        let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("DEBUGINFOD_URLS", "")
            .env("__BPFTRACE_NOTIFY_PROBES_ATTACHED", "1")
            .env("BPFTRACE_MAX_MAP_KEYS", "4096")
            .env("BPFTRACE_MAX_PROBES", "16")
            .env("BPFTRACE_MAX_BPF_PROGS", "16")
            .env("BPFTRACE_PERF_RB_PAGES", "8")
            .env("BPFTRACE_MAX_CAT_BYTES", "1024")
            .current_dir("/");
        Self::set_child_io(&mut command);
        Self::isolate_filesystem(&mut command, mode);
        if mode == DiagnosticMode::Compile {
            command.arg("-d");
        }
        command.args(["-B", "none", "-f", "json", "-", &cgroup_id.to_string()]);
        command
    }

    fn set_child_io(command: &mut Command) {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        Self::set_child_lifetime(command);
    }

    #[allow(unsafe_code)]
    fn isolate_filesystem(command: &mut Command, mode: DiagnosticMode) {
        // SAFETY: The child uses fixed C strings and allocation-free syscalls.
        unsafe {
            command.pre_exec(move || {
                if !rustix::process::geteuid().is_root() {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                rustix::thread::unshare_unsafe(
                    rustix::thread::UnshareFlags::NEWNS | rustix::thread::UnshareFlags::NEWNET,
                )?;
                rustix::mount::mount_change(
                    c"/",
                    rustix::mount::MountPropagationFlags::PRIVATE
                        | rustix::mount::MountPropagationFlags::REC,
                )?;
                rustix::mount::mount_bind(c"/dev/null", c"/dev/null")?;
                let attributes = libc::mount_attr {
                    attr_set: libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NODEV,
                    attr_clr: 0,
                    propagation: 0,
                    userns_fd: 0,
                };
                if libc::syscall(
                    libc::SYS_mount_setattr,
                    libc::AT_FDCWD,
                    c"/".as_ptr(),
                    libc::AT_RECURSIVE,
                    &attributes,
                    std::mem::size_of::<libc::mount_attr>(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let null_attributes = libc::mount_attr {
                    attr_set: 0,
                    attr_clr: libc::MOUNT_ATTR_NODEV,
                    propagation: 0,
                    userns_fd: 0,
                };
                if libc::syscall(
                    libc::SYS_mount_setattr,
                    libc::AT_FDCWD,
                    c"/dev/null".as_ptr(),
                    0,
                    &null_attributes,
                    std::mem::size_of::<libc::mount_attr>(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                rustix::thread::set_no_new_privs(true)?;
                if mode == DiagnosticMode::Capture {
                    return Ok(());
                }
                rustix::thread::set_capabilities_secure_bits(
                    rustix::thread::CapabilitiesSecureBits::NO_ROOT
                        | rustix::thread::CapabilitiesSecureBits::NO_ROOT_LOCKED
                        | rustix::thread::CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
                        | rustix::thread::CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED,
                )?;
                rustix::thread::clear_ambient_capability_set()?;
                rustix::thread::set_capabilities(
                    None,
                    rustix::thread::CapabilitySets {
                        effective: rustix::thread::CapabilitySet::empty(),
                        permitted: rustix::thread::CapabilitySet::empty(),
                        inheritable: rustix::thread::CapabilitySet::empty(),
                    },
                )?;
                Ok(())
            });
        }
    }

    #[allow(unsafe_code)]
    fn set_child_lifetime(command: &mut Command) {
        let parent = rustix::process::getpid();
        // SAFETY: The child calls only allocation-free Linux syscalls before exec.
        unsafe {
            command.pre_exec(move || {
                rustix::process::set_parent_process_death_signal(Some(Signal::KILL))?;
                if rustix::process::getppid() != Some(parent) {
                    return Err(std::io::Error::from_raw_os_error(3));
                }
                rustix::thread::set_no_new_privs(true)?;
                rustix::process::setrlimit(
                    rustix::process::Resource::Core,
                    rustix::process::Rlimit {
                        current: Some(0),
                        maximum: Some(0),
                    },
                )?;
                Ok(())
            });
        }
    }
}

impl DiagnosticCapture {
    fn spawn(
        path: &Path,
        run: impl FnOnce(
                Arc<DiagnosticSignals>,
                mpsc::SyncSender<DiagnosticFrame>,
            ) -> Result<DiagnosticResult>
            + Send
            + 'static,
    ) -> Result<Self> {
        let signals = Arc::new(DiagnosticSignals::default());
        let cancel = Arc::clone(&signals);
        let (send, frames) = mpsc::sync_channel(256);
        let worker = thread::Builder::new()
            .name("araphor-diagnostic".into())
            .spawn(move || run(cancel, send))
            .context(IoSnafu {
                action: "start diagnostic supervisor",
                path,
            })?;
        Ok(Self {
            frames,
            signals,
            worker: Some(worker),
        })
    }

    pub fn frames(&self) -> &mpsc::Receiver<DiagnosticFrame> {
        &self.frames
    }

    pub fn cancel(&self) {
        self.signals.cancelled.store(true, Ordering::Release);
    }

    pub fn process_id(&self) -> Option<u32> {
        let pid = self.signals.process_id.load(Ordering::Acquire);
        (pid != 0 && !self.is_finished()).then_some(pid)
    }

    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub fn finish(mut self) -> Result<DiagnosticResult> {
        self.join()
    }

    fn join(&mut self) -> Result<DiagnosticResult> {
        let worker = self.worker.take().ok_or_else(|| {
            InvalidConfigurationSnafu {
                path: Path::new("diagnostic"),
                reason: "diagnostic result was already consumed",
            }
            .build()
        })?;
        worker.join().map_err(|_| {
            IoSnafu {
                action: "join diagnostic supervisor",
                path: Path::new("diagnostic"),
            }
            .into_error(std::io::Error::other("diagnostic supervisor panicked"))
        })?
    }
}

impl Drop for DiagnosticCapture {
    fn drop(&mut self) {
        self.cancel();
        if self.worker.is_some() {
            let _result = self.join();
        }
    }
}

struct SupervisedChild {
    child: Child,
    reaped: bool,
    fdinfo: BTreeMap<u32, File>,
}

impl SupervisedChild {
    fn run(
        mut command: Command,
        path: &Path,
        source: Vec<u8>,
        mode: DiagnosticMode,
        collection: Duration,
        signals: Arc<DiagnosticSignals>,
        send: mpsc::SyncSender<DiagnosticFrame>,
    ) -> Result<DiagnosticResult> {
        let start = Instant::now();
        let child = command.spawn().context(IoSnafu {
            action: "spawn diagnostic",
            path,
        })?;
        let mut owner = Self {
            child,
            reaped: false,
            fdinfo: BTreeMap::new(),
        };
        signals
            .process_id
            .store(owner.child.id(), Ordering::Release);
        let input = owner
            .child
            .stdin
            .take()
            .ok_or_else(|| Self::pipe_error(path))?;
        let mut stdout = owner
            .child
            .stdout
            .take()
            .ok_or_else(|| Self::pipe_error(path))?;
        let mut stderr = owner
            .child
            .stderr
            .take()
            .ok_or_else(|| Self::pipe_error(path))?;
        for fd in [&input as &dyn std::os::fd::AsFd, &stdout, &stderr] {
            rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK)
                .map_err(std::io::Error::from)
                .context(IoSnafu {
                    action: "bound diagnostic pipe",
                    path,
                })?;
        }
        let mut result = DiagnosticResult {
            process_id: owner.child.id(),
            stop: DiagnosticStop::Exited,
            exit_code: None,
            forced_kill: false,
            output_incomplete: false,
            emitted_frames: 0,
            retained_bytes: 0,
            elapsed_ms: 0,
            attach_notification_ms: None,
            program_ids: BTreeSet::new(),
            map_ids: BTreeSet::new(),
            cleanup_verified: None,
            peak_rss_kib: None,
        };
        let mut deadline = start + PREPARATION_LIMIT;
        let mut closing = None;
        let mut input_offset = 0;
        let mut input = Some(input);
        let mut buffers = [Vec::new(), Vec::new()];
        let mut eof = [false, false];
        let mut status = None;
        let mut resource_text = String::with_capacity(16 * 1024);
        let mut resource_bytes = [0; 16 * 1024];
        loop {
            owner.record_resources(&mut result, &mut resource_text, &mut resource_bytes);
            if let Some(writer) = &mut input {
                match writer.write(&source[input_offset..]) {
                    Ok(count) => input_offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        result.stop = DiagnosticStop::PipeFailure;
                        input = None;
                    }
                }
                if input_offset == source.len() {
                    input = None;
                }
            }
            for (index, pipe) in [&mut stdout as &mut dyn Read, &mut stderr]
                .into_iter()
                .enumerate()
            {
                let mut bytes = [0_u8; 8192];
                // Bound work per turn so continuous output cannot delay the deadline.
                for _ in 0..16 {
                    match pipe.read(&mut bytes) {
                        Ok(0) => {
                            eof[index] = true;
                            break;
                        }
                        Ok(count) => {
                            buffers[index].extend_from_slice(&bytes[..count]);
                            while let Some(end) =
                                buffers[index].iter().position(|byte| *byte == b'\n')
                            {
                                let line: Vec<_> = buffers[index].drain(..=end).collect();
                                if mode == DiagnosticMode::Capture
                                    && index == 1
                                    && line == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                                    && result.attach_notification_ms.is_none()
                                {
                                    result.attach_notification_ms = Some(
                                        start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                                    );
                                    deadline = Instant::now() + collection;
                                }
                                Self::emit(line, index == 1, &send, &mut result);
                            }
                            if buffers[index].len() > MAX_FRAME_BYTES {
                                buffers[index].clear();
                                result.stop = DiagnosticStop::OutputLimit;
                                result.output_incomplete = true;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            result.stop = DiagnosticStop::PipeFailure;
                            result.output_incomplete = true;
                            eof[index] = true;
                            break;
                        }
                    }
                }
            }
            if status.is_none() {
                status = rustix::process::waitid(
                    rustix::process::WaitId::Pid(Pid::from_child(&owner.child)),
                    rustix::process::WaitIdOptions::EXITED
                        | rustix::process::WaitIdOptions::NOHANG
                        | rustix::process::WaitIdOptions::NOWAIT,
                )
                .map_err(std::io::Error::from)
                .context(IoSnafu {
                    action: "inspect diagnostic exit",
                    path,
                })?;
            }
            if status.is_some() && eof.iter().all(|value| *value) {
                break;
            }
            if closing.is_none() {
                if result.stop == DiagnosticStop::Exited {
                    if signals.cancelled.load(Ordering::Acquire) {
                        result.stop = DiagnosticStop::Cancelled;
                    } else if Instant::now() >= deadline {
                        result.stop = if mode == DiagnosticMode::Capture
                            && result.attach_notification_ms.is_none()
                        {
                            DiagnosticStop::PreparationDeadline
                        } else {
                            DiagnosticStop::Deadline
                        };
                    }
                }
                if result.stop != DiagnosticStop::Exited || status.is_some() {
                    owner.signal(Signal::INT)?;
                    closing = Some(Instant::now());
                }
            }
            if closing.is_some_and(|time| time.elapsed() >= DRAIN_LIMIT) {
                owner.signal(Signal::KILL)?;
                result.forced_kill = true;
                result.output_incomplete = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        for (index, tail) in buffers.into_iter().enumerate() {
            if !tail.is_empty() {
                Self::emit(tail, index == 1, &send, &mut result);
            }
        }
        owner.signal(Signal::KILL)?;
        owner.fdinfo.clear();
        result.exit_code = owner
            .child
            .wait()
            .context(IoSnafu {
                action: "reap diagnostic",
                path,
            })?
            .code();
        owner.reaped = true;
        if result.exit_code.is_none() {
            result.output_incomplete = true;
        }
        if !result.program_ids.is_empty() || !result.map_ids.is_empty() {
            let cleanup_deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let removed = result.program_ids.iter().all(|id| {
                    matches!(libbpf_rs::Program::fd_from_id(*id), Err(error) if error.kind() == libbpf_rs::ErrorKind::NotFound)
                }) && result.map_ids.iter().all(|id| {
                    matches!(libbpf_rs::MapHandle::from_map_id(*id), Err(error) if error.kind() == libbpf_rs::ErrorKind::NotFound)
                });
                if removed || Instant::now() >= cleanup_deadline {
                    result.cleanup_verified = Some(removed);
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        result.elapsed_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        Ok(result)
    }

    fn record_resources(
        &mut self,
        result: &mut DiagnosticResult,
        text: &mut String,
        bytes: &mut [u8; 16 * 1024],
    ) {
        text.clear();
        if File::open(format!("/proc/{}/status", self.child.id()))
            .and_then(|mut file| file.read_to_string(text))
            .is_ok()
        {
            if let Some(rss) = text.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            }) {
                result.peak_rss_kib = Some(result.peak_rss_kib.unwrap_or(0).max(rss));
            }
        }
        let Ok(entries) = fs::read_dir(format!("/proc/{}/fdinfo", self.child.id())) else {
            self.fdinfo.clear();
            return;
        };
        let mut fds = [0_u32; 256];
        let mut count = 0;
        for entry in entries.take(fds.len()).flatten() {
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse().ok())
            {
                fds[count] = fd;
                count += 1;
            }
        }
        let fds = &mut fds[..count];
        fds.sort_unstable();
        self.fdinfo.retain(|fd, _| fds.binary_search(fd).is_ok());
        let mut previous = None;
        for &fd in fds.iter() {
            if previous == Some(fd) {
                continue;
            }
            previous = Some(fd);
            let file = match self.fdinfo.entry(fd) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let Ok(file) = File::open(format!("/proc/{}/fdinfo/{fd}", self.child.id()))
                    else {
                        continue;
                    };
                    entry.insert(file)
                }
            };
            let count = match Self::read_resource(file, text, bytes) {
                Ok(count) => count,
                Err(_) => {
                    self.fdinfo.remove(&fd);
                    continue;
                }
            };
            for line in text.lines() {
                if let Some(id) = line
                    .strip_prefix("prog_id:")
                    .and_then(|value| value.trim().parse().ok())
                {
                    result.program_ids.insert(id);
                }
                if let Some(id) = line
                    .strip_prefix("map_id:")
                    .and_then(|value| value.trim().parse().ok())
                {
                    result.map_ids.insert(id);
                }
            }
            if count == 16 * 1024 {
                self.fdinfo.remove(&fd);
            }
        }
    }

    fn read_resource(
        reader: &impl FileExt,
        text: &mut String,
        bytes: &mut [u8; 16 * 1024],
    ) -> std::io::Result<usize> {
        text.clear();
        let mut count = 0;
        let limit = bytes.len();
        while count < limit {
            match reader.read_at(&mut bytes[count..limit], count as u64) {
                Ok(0) => break,
                Ok(read) => count += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let current = std::str::from_utf8(&bytes[..count])
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        text.push_str(current);
        Ok(count)
    }

    fn emit(
        bytes: Vec<u8>,
        stderr: bool,
        send: &mpsc::SyncSender<DiagnosticFrame>,
        result: &mut DiagnosticResult,
    ) {
        if result.output_incomplete {
            return;
        }
        if bytes.len() > MAX_FRAME_BYTES
            || result.retained_bytes + bytes.len() > MAX_OUTPUT_BYTES
            || result.emitted_frames >= MAX_OUTPUT_FRAMES
        {
            result.stop = DiagnosticStop::OutputLimit;
            result.output_incomplete = true;
            return;
        }
        let count = bytes.len();
        if send
            .try_send(DiagnosticFrame {
                sequence: result.emitted_frames + 1,
                stderr,
                bytes,
            })
            .is_err()
        {
            result.stop = DiagnosticStop::ConsumerSlow;
            result.output_incomplete = true;
        } else {
            result.retained_bytes += count;
            result.emitted_frames += 1;
        }
    }

    fn signal(&self, signal: Signal) -> Result<()> {
        if let Some(pid) = Pid::from_raw(self.child.id() as i32) {
            match rustix::process::kill_process_group(pid, signal) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => {
                    return Err(std::io::Error::from(error)).context(IoSnafu {
                        action: "signal diagnostic group",
                        path: Path::new("diagnostic"),
                    })
                }
            }
        }
        Ok(())
    }

    fn pipe_error(path: &Path) -> crate::Error {
        InvalidConfigurationSnafu {
            path,
            reason: "diagnostic pipe is missing",
        }
        .build()
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        self.fdinfo.clear();
        if !self.reaped {
            let _signal = self.signal(Signal::KILL);
            let _wait = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    fn capture(script: &str) -> Result<DiagnosticCapture> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        DiagnosticBackend::start_fixture(command, DiagnosticMode::Compile, Duration::from_secs(1))
    }

    fn observe(script: &str, collection: Duration) -> Result<DiagnosticCapture> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        DiagnosticBackend::start_fixture(command, DiagnosticMode::Capture, collection)
    }

    #[test]
    fn observability_backend_resource_buffer() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resource");
        fs::write(&path, b"fixture")?;
        let mut held = File::open(&path)?;
        let native = PathBuf::from(format!("/proc/self/fdinfo/{}", held.as_raw_fd()));
        let mut resource = File::open(&native)?;
        let expected = fs::read_to_string(&native)?;
        let mut text = String::with_capacity(16 * 1024);
        let mut bytes = [0; 16 * 1024];
        text.push_str("prog_id:\t111\nmap_id:\t222\n");
        let capacity = text.capacity();
        let allocation = text.as_ptr();
        SupervisedChild::read_resource(&resource, &mut text, &mut bytes)?;
        assert_eq!(text, expected);
        assert_eq!(text.capacity(), capacity);
        assert_eq!(text.as_ptr(), allocation);
        held.read_exact(&mut [0; 1])?;
        resource.seek(std::io::SeekFrom::Start(9))?;
        SupervisedChild::read_resource(&resource, &mut text, &mut bytes)?;
        assert_eq!(text, fs::read_to_string(&native)?);
        assert_ne!(text, expected);
        assert_eq!(text.as_ptr(), allocation);
        assert_eq!(resource.stream_position()?, 9);
        assert!(SupervisedChild::read_resource(
            &File::open(directory.path())?,
            &mut text,
            &mut bytes
        )
        .is_err());
        assert!(text.is_empty());
        fs::write(&path, [0xff])?;
        assert!(
            SupervisedChild::read_resource(&File::open(&path)?, &mut text, &mut bytes).is_err()
        );
        fs::write(&path, b"map_id:\t23\n")?;
        SupervisedChild::read_resource(&File::open(&path)?, &mut text, &mut bytes)?;
        assert_eq!(text, "map_id:\t23\n");
        assert_eq!(text.as_ptr(), allocation);
        let mut bounded = vec![b' '; 16 * 1024];
        bounded.extend_from_slice(b"\nprog_id:\t99\n");
        fs::write(&path, bounded)?;
        assert_eq!(
            SupervisedChild::read_resource(&File::open(&path)?, &mut text, &mut bytes)?,
            16 * 1024
        );
        assert_eq!(text.len(), 16 * 1024);
        assert!(!text.contains("prog_id:"));
        Ok(())
    }

    #[test]
    fn observability_backend_resource_reads() -> std::io::Result<()> {
        struct ShortRead {
            calls: std::cell::Cell<usize>,
            fail: bool,
        }

        impl FileExt for ShortRead {
            fn read_at(&self, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
                let call = self.calls.get();
                self.calls.set(call + 1);
                if call == 0 {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                if self.fail && offset > 0 {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                let source = b"pos:\t1\nprog_id:\t23\nmap_id:\t45\n";
                let start = usize::try_from(offset).unwrap();
                let count = (source.len() - start).min(bytes.len()).min(3);
                bytes[..count].copy_from_slice(&source[start..start + count]);
                Ok(count)
            }

            fn write_at(&self, _bytes: &[u8], _offset: u64) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Unsupported.into())
            }
        }

        let mut text = String::from("prog_id:\t111\nmap_id:\t222\n");
        let mut bytes = [0; 16 * 1024];
        let reader = ShortRead {
            calls: std::cell::Cell::new(0),
            fail: false,
        };
        SupervisedChild::read_resource(&reader, &mut text, &mut bytes)?;
        assert_eq!(text, "pos:\t1\nprog_id:\t23\nmap_id:\t45\n");
        assert!(reader.calls.get() > 3);
        let reader = ShortRead {
            calls: std::cell::Cell::new(0),
            fail: true,
        };
        assert_eq!(
            SupervisedChild::read_resource(&reader, &mut text, &mut bytes)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(text.is_empty());
        assert_eq!(reader.calls.get(), 3);
        Ok(())
    }

    #[test]
    fn observability_backend_resource_handles(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::io::{BufRead as _, BufReader};

        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first");
        let replacement = directory.path().join("replacement");
        fs::write(&first, b"first")?;
        fs::write(&replacement, b"replacement")?;
        let mut command = Command::new("/bin/bash");
        command
            .args([
                "-c",
                r#"exec 3< "$1"
for ((fd = 10; fd < 310; fd++)); do eval "exec $fd</dev/null"; done
printf 'ready\n'
read -r gate
dd bs=1 count=1 <&3 >/dev/null 2>&1
printf 'moved\n'
read -r gate
exec 3< "$2"
for ((fd = 10; fd < 310; fd++)); do eval "exec $fd<&-"; done
printf 'reused\n'
read -r gate
exec 3<&-
printf 'closed\n'
read -r gate"#,
                "fdinfo",
            ])
            .arg(&first)
            .arg(&replacement);
        DiagnosticBackend::set_child_io(&mut command);
        let mut owner = SupervisedChild {
            child: command.spawn()?,
            reaped: false,
            fdinfo: BTreeMap::new(),
        };
        let mut input = owner.child.stdin.take().ok_or("input pipe absent")?;
        let mut output = BufReader::new(owner.child.stdout.take().ok_or("output pipe absent")?);
        let mut phase = String::new();
        output.read_line(&mut phase)?;
        assert_eq!(phase, "ready\n");
        let mut result = DiagnosticResult {
            process_id: owner.child.id(),
            stop: DiagnosticStop::Exited,
            exit_code: None,
            forced_kill: false,
            output_incomplete: false,
            emitted_frames: 0,
            retained_bytes: 0,
            elapsed_ms: 0,
            attach_notification_ms: None,
            program_ids: BTreeSet::new(),
            map_ids: BTreeSet::new(),
            cleanup_verified: None,
            peak_rss_kib: None,
        };
        let mut text = String::with_capacity(16 * 1024);
        let mut bytes = [0; 16 * 1024];
        owner.record_resources(&mut result, &mut text, &mut bytes);
        assert_eq!(owner.fdinfo.len(), 256);
        let held = owner.fdinfo.get(&3).ok_or("fdinfo absent")?.as_raw_fd();
        let path = PathBuf::from(format!("/proc/{}/fdinfo/3", owner.child.id()));
        let native = File::open(&path)?;
        SupervisedChild::read_resource(&native, &mut text, &mut bytes)?;
        let initial = text.clone();
        for expected in ["moved\n", "reused\n"] {
            input.write_all(b"next\n")?;
            phase.clear();
            output.read_line(&mut phase)?;
            assert_eq!(phase, expected);
            owner.record_resources(&mut result, &mut text, &mut bytes);
            assert!(owner.fdinfo.len() <= 256);
            let resource = owner.fdinfo.get_mut(&3).ok_or("fdinfo absent")?;
            assert_eq!(resource.as_raw_fd(), held);
            SupervisedChild::read_resource(resource, &mut text, &mut bytes)?;
            assert_eq!(text, fs::read_to_string(&path)?);
            assert_ne!(text, initial);
        }
        assert!(owner.fdinfo.len() < 256);
        owner.fdinfo.insert(3, File::open(directory.path())?);
        owner.record_resources(&mut result, &mut text, &mut bytes);
        assert!(!owner.fdinfo.contains_key(&3));
        owner.record_resources(&mut result, &mut text, &mut bytes);
        assert!(owner.fdinfo.contains_key(&3));
        input.write_all(b"next\n")?;
        phase.clear();
        output.read_line(&mut phase)?;
        assert_eq!(phase, "closed\n");
        owner.record_resources(&mut result, &mut text, &mut bytes);
        assert!(!owner.fdinfo.contains_key(&3));
        text.push_str("prog_id:\t111\nmap_id:\t222\n");
        assert!(SupervisedChild::read_resource(&native, &mut text, &mut bytes).is_err());
        assert!(text.is_empty());
        assert!(result.program_ids.is_empty());
        assert!(result.map_ids.is_empty());
        Ok(())
    }

    #[test]
    fn observability_backend_marker_source() -> Result<()> {
        let capture = observe(
            "cat >/dev/null; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n'; printf 'Attaching 1 probe...\\n__BPFTRACE_NOTIFY_PROBES_ATTACHED extra\\n' >&2",
            Duration::from_millis(100),
        )?;
        let frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(frames.len(), 3);
        assert_eq!(result.stop, DiagnosticStop::Exited);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.attach_notification_ms, None);
        assert_eq!(result.cleanup_verified, None);
        Ok(())
    }

    #[test]
    fn observability_backend_capture_deadline() -> Result<()> {
        let capture = observe(
            "cat >/dev/null; for n in $(seq 1 200); do printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; sleep 0.05; done",
            Duration::from_millis(100),
        )?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut frames = Vec::new();
        while !capture.is_finished() && Instant::now() < deadline {
            frames.extend(capture.frames().try_iter());
            thread::sleep(Duration::from_millis(10));
        }
        assert!(capture.is_finished());
        frames.extend(capture.frames().try_iter());
        let result = capture.finish()?;
        assert!(frames.iter().any(|frame| frame.stderr));
        assert_eq!(result.stop, DiagnosticStop::Deadline);
        assert!(result
            .attach_notification_ms
            .is_some_and(|attached| result.elapsed_ms >= attached + 100));
        assert!(!Path::new(&format!("/proc/{}", result.process_id)).exists());
        Ok(())
    }

    #[test]
    fn observability_backend_preparation_timeout() -> Result<()> {
        let capture = observe(
            "cat >/dev/null; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n'; exec sleep 60",
            Duration::from_millis(100),
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.stop, DiagnosticStop::PreparationDeadline);
        assert_eq!(result.attach_notification_ms, None);
        assert!(result.elapsed_ms >= PREPARATION_LIMIT.as_millis() as u64);
        assert!(result.elapsed_ms < 17_000);
        Ok(())
    }

    #[test]
    fn observability_backend_preparation_cancel() -> Result<()> {
        let capture = observe(
            "cat >/dev/null; printf 'preparing\\n'; exec sleep 60",
            Duration::from_secs(1),
        )?;
        assert!(capture
            .frames()
            .recv_timeout(Duration::from_secs(2))
            .is_ok());
        capture.cancel();
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.stop, DiagnosticStop::Cancelled);
        assert_eq!(result.attach_notification_ms, None);
        assert!(!result.forced_kill);
        assert!(!Path::new(&format!("/proc/{}", result.process_id)).exists());
        Ok(())
    }

    #[test]
    fn observability_backend_eof_output_and_nonzero_exit() -> Result<()> {
        let capture =
            capture("cat >/dev/null; printf 'one\\ntwo\\n'; printf 'diagnostic\\n' >&2; exit 7")?;
        let frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stop, DiagnosticStop::Exited);
        assert_eq!(result.emitted_frames, 3);
        assert!(!result.output_incomplete);
        assert!(frames.iter().any(|frame| frame.stderr));
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        Ok(())
    }

    #[test]
    fn observability_backend_slow_consumer_retains_terminal() -> Result<()> {
        let capture = capture("cat >/dev/null; while :; do printf 'output\\n'; done")?;
        while !capture.is_finished() {
            thread::sleep(Duration::from_millis(10));
        }
        let frames: Vec<_> = capture.frames().try_iter().collect();
        let result = capture.finish()?;
        assert_eq!(frames.len(), 256);
        assert_eq!(result.stop, DiagnosticStop::ConsumerSlow);
        assert!(result.output_incomplete);
        Ok(())
    }

    #[test]
    fn observability_backend_oversize_frame_stops() -> Result<()> {
        let capture = capture("cat >/dev/null; head -c 1048577 /dev/zero")?;
        let frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert!(frames.is_empty());
        assert_eq!(result.stop, DiagnosticStop::OutputLimit);
        assert!(result.output_incomplete);
        Ok(())
    }

    #[test]
    fn observability_backend_total_output_limit() -> Result<()> {
        let capture = capture("cat >/dev/null; for n in $(seq 1 17); do head -c 1048575 /dev/zero; printf '\\n'; done")?;
        let bytes: usize = capture.frames().iter().map(|frame| frame.bytes.len()).sum();
        let result = capture.finish()?;
        assert_eq!(result.stop, DiagnosticStop::OutputLimit);
        assert_eq!(bytes, MAX_OUTPUT_BYTES);
        assert!(result.output_incomplete);
        Ok(())
    }

    #[test]
    fn observability_backend_frame_count() -> Result<()> {
        let capture = capture("cat >/dev/null")?;
        let mut result = capture.finish()?;
        let (send, frames) = mpsc::sync_channel(1);
        for sequence in 1..=MAX_OUTPUT_FRAMES {
            SupervisedChild::emit(vec![b'x'], false, &send, &mut result);
            assert_eq!(frames.try_recv().map(|frame| frame.sequence), Ok(sequence));
        }
        assert!(!result.output_incomplete);
        SupervisedChild::emit(vec![b'x'], false, &send, &mut result);
        assert!(frames.try_recv().is_err());
        assert_eq!(result.emitted_frames, MAX_OUTPUT_FRAMES);
        assert_eq!(result.stop, DiagnosticStop::OutputLimit);
        assert!(result.output_incomplete);
        Ok(())
    }

    #[test]
    fn observability_backend_abort_does_not_report_complete_output() -> Result<()> {
        let capture = capture("cat >/dev/null; printf 'BUG: open(/dev/null): Permission denied\\n' >&2; kill -ABRT $$")?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.exit_code, None);
        assert!(result.output_incomplete);
        Ok(())
    }

    #[test]
    fn observability_backend_cancel_and_forced_kill() -> Result<()> {
        let capture =
            capture("trap '' INT; cat >/dev/null; printf 'ready\\n'; while :; do sleep 1; done")?;
        assert!(capture
            .frames()
            .recv_timeout(Duration::from_secs(2))
            .is_ok());
        capture.cancel();
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.stop, DiagnosticStop::Cancelled);
        assert!(result.forced_kill);
        assert!(result.output_incomplete);
        assert!(!Path::new(&format!("/proc/{}", result.process_id)).exists());
        Ok(())
    }

    #[test]
    fn observability_backend_compile_deadline() -> Result<()> {
        let capture = capture("cat >/dev/null; sleep 60")?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish()?;
        assert_eq!(result.stop, DiagnosticStop::Deadline);
        assert!(result.elapsed_ms >= PREPARATION_LIMIT.as_millis() as u64);
        assert!(result.elapsed_ms < 17_000);
        Ok(())
    }

    #[test]
    fn observability_backend_digest_and_source_validation() -> Result<()> {
        let backend = DiagnosticBackend::new(PathBuf::from("/bin/false"), [1; 32])?;
        assert!(backend
            .start(
                b"BEGIN {}",
                1,
                DiagnosticMode::Compile,
                Duration::from_secs(1)
            )
            .is_err());
        let hash = Sha256::digest(std::fs::read("/bin/false").context(IoSnafu {
            action: "read fixture executable",
            path: Path::new("/bin/false"),
        })?)
        .into();
        let backend = DiagnosticBackend::new(PathBuf::from("/bin/false"), hash)?;
        assert!(backend
            .start(&[], 1, DiagnosticMode::Compile, Duration::from_secs(1))
            .is_err());
        let capture = backend.start(
            b"BEGIN {}",
            1,
            DiagnosticMode::Capture,
            Duration::from_secs(1),
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        let result = capture.finish();
        if rustix::process::geteuid().is_root() {
            assert_eq!(result?.exit_code, Some(1));
        } else {
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn observability_backend_request_limits() -> Result<()> {
        let hash = Sha256::digest(std::fs::read("/bin/false").context(IoSnafu {
            action: "read fixture executable",
            path: Path::new("/bin/false"),
        })?)
        .into();
        let backend = DiagnosticBackend::new(PathBuf::from("/bin/false"), hash)?;
        let source = vec![b' '; MAX_SOURCE_BYTES];
        let oversize = vec![b' '; MAX_SOURCE_BYTES + 1];
        for (bytes, cgroup, seconds) in [
            (&[][..], 1, 1),
            (&b"\0"[..], 1, 1),
            (oversize.as_slice(), 1, 1),
            (source.as_slice(), 0, 1),
            (source.as_slice(), 1, 0),
            (source.as_slice(), 1, 301),
        ] {
            assert!(backend
                .start(
                    bytes,
                    cgroup,
                    DiagnosticMode::Capture,
                    Duration::from_secs(seconds),
                )
                .is_err());
        }
        assert!(backend
            .start(
                &source,
                1,
                DiagnosticMode::Capture,
                Duration::from_secs(300),
            )
            .is_ok());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture for the parent-death test"]
    fn observability_backend_parent_fixture() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let output =
            std::env::var_os("ARAPHOR_PARENT_DEATH_PID_FILE").ok_or("fixture path absent")?;
        let capture = capture("cat >/dev/null; exec sleep 60")?;
        let start = Instant::now();
        while capture.process_id().is_none() && start.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(
            output,
            capture.process_id().ok_or("child absent")?.to_string(),
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        capture.finish()?;
        Ok(())
    }

    #[test]
    fn observability_backend_parent_death_kills_child(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("pid");
        let mut parent = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "diagnostic::tests::observability_backend_parent_fixture",
                "--ignored",
            ])
            .env("ARAPHOR_PARENT_DEATH_PID_FILE", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let start = Instant::now();
        while !path.exists() && start.elapsed() < Duration::from_secs(3) {
            thread::sleep(Duration::from_millis(10));
        }
        let pid = std::fs::read_to_string(&path)?;
        parent.kill()?;
        parent.wait()?;
        let start = Instant::now();
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/status")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(status)
                    if status
                        .lines()
                        .any(|line| line.starts_with("State:") && line.contains("Z (zombie)")) =>
                {
                    break
                }
                _ if start.elapsed() < Duration::from_secs(3) => {
                    thread::sleep(Duration::from_millis(10))
                }
                _ => return Err("diagnostic child survived parent death".into()),
            }
        }
        Ok(())
    }
}
