use std::fs;
use std::io::Read as _;
use std::net::TcpStream;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

use super::mailbox::{SharedMailbox, EMPTY, READY, REQUEST, RESPONSE};

const CHILD_WAIT_LIMIT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Deserialize, Serialize)]
enum ChildRequest {
    Setup,
    Open {
        path: PathBuf,
    },
    Read {
        path: PathBuf,
    },
    OpenWrite {
        path: PathBuf,
    },
    PrepareWriteRace {
        path: PathBuf,
        count: u32,
    },
    WriteRace {
        path: PathBuf,
        count: u32,
    },
    OpenMany {
        path: PathBuf,
        count: u32,
    },
    PrepareFile {
        path: PathBuf,
    },
    ReadPrepared,
    MmapPrepared,
    PrepareMountRace {
        source: PathBuf,
        target: PathBuf,
        count: u32,
    },
    MountRace {
        source: PathBuf,
        target: PathBuf,
        count: u32,
    },
    Connect,
    PrepareHardClosed {
        truncate_path: PathBuf,
        exec_path: PathBuf,
    },
    HardClosed(HardClosedOperation),
    Exit,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum HardClosedOperation {
    Exec,
    AnonymousExec,
    Ioctl,
    Ipc,
    Ptrace,
    Signal,
    Namespace,
    Bpf,
    Create { path: PathBuf },
    Setattr { path: PathBuf },
    Truncate,
    Unlink { path: PathBuf },
    Link { source: PathBuf, target: PathBuf },
    Rename { source: PathBuf, target: PathBuf },
    SelfProtect { path: PathBuf },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum ChildResponse {
    Ready { pid: u32 },
    Paths(EffectPaths),
    Outcome(IoOutcome),
    Batch(BatchOutcome),
    Prepared,
    Failed { reason: String },
    Exited,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct EffectPaths {
    pub(super) source: PathBuf,
    pub(super) secret: PathBuf,
    pub(super) hard_link: PathBuf,
    pub(super) bind_alias: PathBuf,
    pub(super) benign: PathBuf,
    pub(super) exec_target: PathBuf,
    pub(super) mount_target: PathBuf,
    pub(super) mutation_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct IoOutcome {
    pub(super) allowed: bool,
    errno: Option<i32>,
}

impl IoOutcome {
    pub(super) fn denied(self) -> bool {
        !self.allowed
            && self.errno.is_some_and(|errno| {
                errno == rustix::io::Errno::ACCESS.raw_os_error()
                    || errno == rustix::io::Errno::PERM.raw_os_error()
            })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct BatchOutcome {
    pub(super) allowed: u32,
    pub(super) denied: u32,
    pub(super) other_errors: u32,
    pub(super) elapsed_ns: u64,
}

impl BatchOutcome {
    pub(super) fn average_ns(self) -> u64 {
        self.elapsed_ns / u64::from(self.allowed + self.denied + self.other_errors).max(1)
    }
}

pub(super) struct EffectProcessFixture {
    child: Child,
    mailbox: SharedMailbox,
    stderr: Option<ChildStderr>,
    pid: u32,
    stopped: bool,
}

impl EffectProcessFixture {
    pub(super) fn start(fixture_root: &Path) -> Result<Self> {
        let executable = std::env::current_exe().context(IoSnafu {
            path: Path::new("current executable"),
        })?;
        let mailbox_path = fixture_root.join("effect-mailbox");
        let mailbox = SharedMailbox::create(&mailbox_path)?;
        let mut child = Command::new("unshare")
            .args(["--mount", "--propagation", "private", "--"])
            .arg(executable)
            .arg("child")
            .arg("--fixture-root")
            .arg(fixture_root)
            .arg("--mailbox-path")
            .arg(&mailbox_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu {
                path: Path::new("unshare"),
            })?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid_state("effect child has no stderr pipe"))?;
        let mut fixture = Self {
            child,
            mailbox,
            stderr: Some(stderr),
            pid: 0,
            stopped: false,
        };
        fixture.wait_for_state(READY, "startup")?;
        let response = fixture.mailbox.read()?;
        fixture.mailbox.reset();
        let ChildResponse::Ready { pid } = response else {
            return Err(invalid_state("effect child did not report its PID"));
        };
        fixture.pid = pid;
        Ok(fixture)
    }

    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn setup(&mut self) -> Result<EffectPaths> {
        match self.request(&ChildRequest::Setup)? {
            ChildResponse::Paths(paths) => Ok(paths),
            _ => Err(invalid_state(
                "effect child returned the wrong setup response",
            )),
        }
    }

    pub(super) fn open(&mut self, path: &Path) -> Result<IoOutcome> {
        match self.request(&ChildRequest::Open {
            path: path.to_path_buf(),
        })? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong open response",
            )),
        }
    }

    pub(super) fn read(&mut self, path: &Path) -> Result<IoOutcome> {
        match self.request(&ChildRequest::Read {
            path: path.to_path_buf(),
        })? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong read response",
            )),
        }
    }

    pub(super) fn open_write(&mut self, path: &Path) -> Result<IoOutcome> {
        match self.request(&ChildRequest::OpenWrite {
            path: path.to_path_buf(),
        })? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong write-open response",
            )),
        }
    }

    pub(super) fn prepare_write_race(&mut self, path: &Path, count: u32) -> Result<()> {
        match self.request(&ChildRequest::PrepareWriteRace {
            path: path.to_path_buf(),
            count,
        })? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong write-race preparation response",
            )),
        }
    }

    pub(super) fn write_race(&mut self, path: &Path, count: u32) -> Result<BatchOutcome> {
        match self.request(&ChildRequest::WriteRace {
            path: path.to_path_buf(),
            count,
        })? {
            ChildResponse::Batch(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong write-race response",
            )),
        }
    }

    pub(super) fn open_many(&mut self, path: &Path, count: u32) -> Result<BatchOutcome> {
        match self.request(&ChildRequest::OpenMany {
            path: path.to_path_buf(),
            count,
        })? {
            ChildResponse::Batch(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong batch response",
            )),
        }
    }

    pub(super) fn prepare_file(&mut self, path: &Path) -> Result<()> {
        match self.request(&ChildRequest::PrepareFile {
            path: path.to_path_buf(),
        })? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong prepared-file response",
            )),
        }
    }

    pub(super) fn read_prepared(&mut self) -> Result<IoOutcome> {
        match self.request(&ChildRequest::ReadPrepared)? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong prepared-read response",
            )),
        }
    }

    pub(super) fn mmap_prepared(&mut self) -> Result<IoOutcome> {
        match self.request(&ChildRequest::MmapPrepared)? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong prepared-mmap response",
            )),
        }
    }

    pub(super) fn mount_race(
        &mut self,
        source: &Path,
        target: &Path,
        count: u32,
    ) -> Result<BatchOutcome> {
        match self.request(&ChildRequest::MountRace {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            count,
        })? {
            ChildResponse::Batch(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong mount response",
            )),
        }
    }

    pub(super) fn prepare_mount_race(
        &mut self,
        source: &Path,
        target: &Path,
        count: u32,
    ) -> Result<()> {
        match self.request(&ChildRequest::PrepareMountRace {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            count,
        })? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong mount preparation response",
            )),
        }
    }

    pub(super) fn connect(&mut self) -> Result<IoOutcome> {
        match self.request(&ChildRequest::Connect)? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong connect response",
            )),
        }
    }

    pub(super) fn prepare_hard_closed(
        &mut self,
        truncate_path: &Path,
        exec_path: &Path,
    ) -> Result<()> {
        match self.request(&ChildRequest::PrepareHardClosed {
            truncate_path: truncate_path.to_path_buf(),
            exec_path: exec_path.to_path_buf(),
        })? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong hard-close preparation response",
            )),
        }
    }

    pub(super) fn hard_closed(&mut self, operation: HardClosedOperation) -> Result<IoOutcome> {
        match self.request(&ChildRequest::HardClosed(operation))? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong hard-close response",
            )),
        }
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        ensure!(
            matches!(self.request(&ChildRequest::Exit)?, ChildResponse::Exited),
            InvalidInputSnafu {
                path: Path::new("effect child"),
                reason: "effect child did not acknowledge shutdown",
            }
        );
        let status = self.child.wait().context(IoSnafu {
            path: Path::new("effect child"),
        })?;
        ensure!(
            status.success(),
            InvalidInputSnafu {
                path: Path::new("effect child"),
                reason: format!("effect child exited with {status}"),
            }
        );
        self.stopped = true;
        Ok(())
    }

    fn request(&mut self, request: &ChildRequest) -> Result<ChildResponse> {
        ensure!(
            self.mailbox.state() == EMPTY,
            InvalidInputSnafu {
                path: Path::new("live effect state"),
                reason: "effect mailbox is not ready for a request",
            }
        );
        let operation = format!("{request:?}");
        self.mailbox.publish(REQUEST, request)?;
        self.wait_for_state(RESPONSE, &operation)?;
        let response = self.mailbox.read()?;
        self.mailbox.reset();
        match response {
            ChildResponse::Failed { reason } => Err(invalid_state(format!(
                "effect child failed {operation}: {reason}"
            ))),
            response => Ok(response),
        }
    }

    fn wait_for_state(&mut self, expected: u32, operation: &str) -> Result<()> {
        let start = Instant::now();
        loop {
            if self.mailbox.state() == expected {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().context(IoSnafu {
                path: Path::new("effect child"),
            })? {
                let mut stderr = String::new();
                if let Some(mut pipe) = self.stderr.take() {
                    pipe.read_to_string(&mut stderr).context(IoSnafu {
                        path: Path::new("effect child stderr"),
                    })?;
                }
                return Err(invalid_state(format!(
                    "effect child exited during {operation} with {status}: {}",
                    stderr.trim()
                )));
            }
            ensure!(
                start.elapsed() < CHILD_WAIT_LIMIT,
                InvalidInputSnafu {
                    path: Path::new("live effect state"),
                    reason: format!("timed out waiting for effect child during {operation}"),
                }
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for EffectProcessFixture {
    fn drop(&mut self) {
        if !self.stopped {
            let _result = self.child.kill();
            let _result = self.child.wait();
        }
    }
}

pub fn run_effect_child(fixture_root: &Path, mailbox_path: &Path) -> Result<()> {
    let mut mailbox = SharedMailbox::open(mailbox_path)?;
    let mut prepared_mount_race = None;
    let mut prepared_write_race = None;
    let mut prepared_file = None;
    let mut prepared_hard_closed = None;
    mailbox.publish(
        READY,
        &ChildResponse::Ready {
            pid: std::process::id(),
        },
    )?;
    loop {
        while mailbox.state() != REQUEST {
            thread::sleep(Duration::from_millis(1));
        }
        let request = mailbox.read()?;
        let (response, exit): (Result<ChildResponse>, bool) = match request {
            ChildRequest::Setup => (setup_paths(fixture_root).map(ChildResponse::Paths), false),
            ChildRequest::Open { path } => (Ok(ChildResponse::Outcome(open_outcome(&path))), false),
            ChildRequest::Read { path } => {
                (Ok(ChildResponse::Outcome(read_path_outcome(&path))), false)
            }
            ChildRequest::OpenWrite { path } => {
                (Ok(ChildResponse::Outcome(open_write_outcome(&path))), false)
            }
            ChildRequest::PrepareWriteRace { path, count } => {
                match PreparedWriteRace::new(path, count) {
                    Ok(prepared) => {
                        prepared_write_race = Some(prepared);
                        (Ok(ChildResponse::Prepared), false)
                    }
                    Err(error) => (Err(error), false),
                }
            }
            ChildRequest::WriteRace { path, count } => match prepared_write_race.take() {
                Some(prepared) => (prepared.run(&path, count).map(ChildResponse::Batch), false),
                None => (
                    Err(invalid_state("effect write race was not prepared")),
                    false,
                ),
            },
            ChildRequest::OpenMany { path, count } => {
                (Ok(ChildResponse::Batch(open_many(&path, count))), false)
            }
            ChildRequest::PrepareFile { path } => match fs::File::open(path) {
                Ok(file) => {
                    prepared_file = Some(file);
                    (Ok(ChildResponse::Prepared), false)
                }
                Err(error) => (
                    Err(invalid_state(format!("cannot prepare file: {error}"))),
                    false,
                ),
            },
            ChildRequest::ReadPrepared => (
                Ok(ChildResponse::Outcome(
                    prepared_file
                        .as_mut()
                        .map_or_else(missing_prepared_file, read_outcome),
                )),
                false,
            ),
            ChildRequest::MmapPrepared => (
                Ok(ChildResponse::Outcome(
                    prepared_file
                        .as_ref()
                        .map_or_else(missing_prepared_file, mmap_outcome),
                )),
                false,
            ),
            ChildRequest::PrepareMountRace {
                source,
                target,
                count,
            } => match PreparedMountRace::new(source, target, count) {
                Ok(prepared) => {
                    prepared_mount_race = Some(prepared);
                    (Ok(ChildResponse::Prepared), false)
                }
                Err(error) => (Err(error), false),
            },
            ChildRequest::MountRace {
                source,
                target,
                count,
            } => match prepared_mount_race.take() {
                Some(prepared) => (
                    prepared
                        .run(&source, &target, count)
                        .map(ChildResponse::Batch),
                    false,
                ),
                None => (
                    Err(invalid_state("effect mount race was not prepared")),
                    false,
                ),
            },
            ChildRequest::Connect => (Ok(ChildResponse::Outcome(connect_outcome())), false),
            ChildRequest::PrepareHardClosed {
                truncate_path,
                exec_path,
            } => match PreparedHardClosed::new(&truncate_path, &exec_path) {
                Ok(prepared) => {
                    prepared_hard_closed = Some(prepared);
                    (Ok(ChildResponse::Prepared), false)
                }
                Err(error) => (Err(error), false),
            },
            ChildRequest::HardClosed(operation) => (
                prepared_hard_closed.as_mut().map_or_else(
                    || Err(invalid_state("hard-close resources were not prepared")),
                    |prepared| Ok(ChildResponse::Outcome(prepared.run(operation))),
                ),
                false,
            ),
            ChildRequest::Exit => {
                prepared_hard_closed.take();
                (Ok(ChildResponse::Exited), true)
            }
        };
        let response = response.unwrap_or_else(|error| ChildResponse::Failed {
            reason: error.to_string(),
        });
        mailbox.publish(RESPONSE, &response)?;
        if exit {
            return Ok(());
        }
    }
}

fn setup_paths(root: &Path) -> Result<EffectPaths> {
    let source = root.join("source");
    let secret = source.join("secret");
    let hard_link = root.join("hard-link");
    let bind_directory = root.join("bind-alias");
    let bind_alias = bind_directory.join("secret");
    let benign = root.join("benign");
    let exec_target = root.join("exec-target");
    let mount_target = root.join("mount-target");
    let setattr_target = root.join("setattr-target");
    let truncate_target = root.join("truncate-target");
    let unlink_target = root.join("unlink-target");
    let mutation_source = root.join("mutation-source");
    fs::create_dir(&source).context(IoSnafu { path: &source })?;
    fs::write(&secret, b"restricted\n").context(IoSnafu { path: &secret })?;
    fs::hard_link(&secret, &hard_link).context(IoSnafu { path: &hard_link })?;
    fs::write(&benign, b"benign\n").context(IoSnafu { path: &benign })?;
    fs::copy("/bin/true", &exec_target).context(IoSnafu { path: &exec_target })?;
    fs::set_permissions(&exec_target, fs::Permissions::from_mode(0o755))
        .context(IoSnafu { path: &exec_target })?;
    fs::write(&setattr_target, b"mode\n").context(IoSnafu {
        path: &setattr_target,
    })?;
    fs::write(&truncate_target, b"truncate\n").context(IoSnafu {
        path: &truncate_target,
    })?;
    fs::set_permissions(&setattr_target, fs::Permissions::from_mode(0o600)).context(IoSnafu {
        path: &setattr_target,
    })?;
    fs::write(&unlink_target, b"unlink\n").context(IoSnafu {
        path: &unlink_target,
    })?;
    fs::write(&mutation_source, b"mutation\n").context(IoSnafu {
        path: &mutation_source,
    })?;
    fs::create_dir(&bind_directory).context(IoSnafu {
        path: &bind_directory,
    })?;
    fs::create_dir(&mount_target).context(IoSnafu {
        path: &mount_target,
    })?;
    rustix::mount::mount_bind(&source, &source)
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: &source })?;
    rustix::mount::mount_bind(&source, &bind_directory)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &bind_directory,
        })?;
    Ok(EffectPaths {
        source,
        secret,
        hard_link,
        bind_alias,
        benign,
        exec_target,
        mount_target,
        mutation_root: root.to_path_buf(),
    })
}

fn open_outcome(path: &Path) -> IoOutcome {
    match fs::File::open(path) {
        Ok(_) => IoOutcome {
            allowed: true,
            errno: None,
        },
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

fn open_write_outcome(path: &Path) -> IoOutcome {
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => IoOutcome {
            allowed: true,
            errno: None,
        },
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

fn read_path_outcome(path: &Path) -> IoOutcome {
    match fs::File::open(path) {
        Ok(mut file) => read_outcome(&mut file),
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

fn missing_prepared_file() -> IoOutcome {
    IoOutcome {
        allowed: false,
        errno: Some(rustix::io::Errno::BADF.raw_os_error()),
    }
}

fn read_outcome(file: &mut fs::File) -> IoOutcome {
    let mut byte = [0_u8; 1];
    match file.read(&mut byte) {
        Ok(1) => IoOutcome {
            allowed: true,
            errno: None,
        },
        Ok(_) => IoOutcome {
            allowed: false,
            errno: Some(rustix::io::Errno::IO.raw_os_error()),
        },
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

#[allow(unsafe_code)]
fn mmap_outcome(file: &fs::File) -> IoOutcome {
    // SAFETY: the fixture owns this immutable file until the mapping attempt
    // finishes; no process truncates or mutates it.
    match unsafe { memmap2::MmapOptions::new().map(file) } {
        Ok(map) if !map.is_empty() => IoOutcome {
            allowed: true,
            errno: None,
        },
        Ok(_) => IoOutcome {
            allowed: false,
            errno: Some(rustix::io::Errno::IO.raw_os_error()),
        },
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

fn open_many(path: &Path, count: u32) -> BatchOutcome {
    let start = Instant::now();
    let mut result = BatchOutcome {
        allowed: 0,
        denied: 0,
        other_errors: 0,
        elapsed_ns: 0,
    };
    for _ in 0..count {
        let outcome = open_outcome(path);
        if outcome.allowed {
            result.allowed += 1;
        } else if outcome.denied() {
            result.denied += 1;
        } else {
            result.other_errors += 1;
        }
    }
    result.elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    result
}

struct PreparedWriteRace {
    path: PathBuf,
    barrier: Arc<Barrier>,
    handles: Vec<std::thread::JoinHandle<IoOutcome>>,
}

impl PreparedWriteRace {
    fn new(path: PathBuf, count: u32) -> Result<Self> {
        let worker_count = usize::try_from(count).map_err(|error| {
            invalid_state(format!("effect write worker count is invalid: {error}"))
        })?;
        ensure!(
            worker_count > 0,
            InvalidInputSnafu {
                path: &path,
                reason: "effect write race needs at least one worker",
            }
        );
        let barrier = Arc::new(Barrier::new(worker_count + 1));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let worker_path = path.clone();
            let worker_barrier = Arc::clone(&barrier);
            handles.push(
                std::thread::Builder::new()
                    .spawn(move || {
                        worker_barrier.wait();
                        open_write_outcome(&worker_path)
                    })
                    .context(IoSnafu {
                        path: Path::new("effect write thread"),
                    })?,
            );
        }
        Ok(Self {
            path,
            barrier,
            handles,
        })
    }

    fn run(self, path: &Path, count: u32) -> Result<BatchOutcome> {
        ensure!(
            path == self.path && usize::try_from(count).ok() == Some(self.handles.len()),
            InvalidInputSnafu {
                path,
                reason: "effect write race differs from its prepared workers",
            }
        );
        let start = Instant::now();
        self.barrier.wait();
        let mut result = BatchOutcome {
            allowed: 0,
            denied: 0,
            other_errors: 0,
            elapsed_ns: 0,
        };
        for handle in self.handles {
            let outcome = handle
                .join()
                .map_err(|_| invalid_state("effect write thread panicked"))?;
            if outcome.allowed {
                result.allowed += 1;
            } else if outcome.denied() {
                result.denied += 1;
            } else {
                result.other_errors += 1;
            }
        }
        result.elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok(result)
    }
}

struct PreparedMountRace {
    source: PathBuf,
    target: PathBuf,
    barrier: Arc<Barrier>,
    handles: Vec<std::thread::JoinHandle<std::result::Result<(), rustix::io::Errno>>>,
}

impl PreparedMountRace {
    fn new(source: PathBuf, target: PathBuf, count: u32) -> Result<Self> {
        let worker_count = usize::try_from(count).map_err(|error| {
            invalid_state(format!("effect mount worker count is invalid: {error}"))
        })?;
        ensure!(
            worker_count > 0,
            InvalidInputSnafu {
                path: &target,
                reason: "effect mount race needs at least one worker",
            }
        );
        let barrier = Arc::new(Barrier::new(worker_count + 1));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let worker_source = source.clone();
            let worker_target = target.clone();
            let worker_barrier = Arc::clone(&barrier);
            handles.push(
                std::thread::Builder::new()
                    .spawn(move || {
                        worker_barrier.wait();
                        rustix::mount::mount_bind(worker_source, worker_target)
                    })
                    .context(IoSnafu {
                        path: Path::new("effect mount thread"),
                    })?,
            );
        }
        Ok(Self {
            source,
            target,
            barrier,
            handles,
        })
    }

    fn run(self, source: &Path, target: &Path, count: u32) -> Result<BatchOutcome> {
        ensure!(
            source == self.source
                && target == self.target
                && usize::try_from(count).ok() == Some(self.handles.len()),
            InvalidInputSnafu {
                path: target,
                reason: "effect mount race differs from its prepared workers",
            }
        );
        let start = Instant::now();
        self.barrier.wait();
        let mut result = BatchOutcome {
            allowed: 0,
            denied: 0,
            other_errors: 0,
            elapsed_ns: 0,
        };
        for handle in self.handles {
            match handle
                .join()
                .map_err(|_| invalid_state("effect mount thread panicked"))?
            {
                Ok(()) => result.allowed += 1,
                Err(error)
                    if error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::PERM =>
                {
                    result.denied += 1;
                }
                Err(_) => result.other_errors += 1,
            }
        }
        result.elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok(result)
    }
}

struct PreparedHardClosed {
    anonymous_exec: Option<memmap2::MmapMut>,
    exec_file: fs::File,
    ioctl_file: fs::File,
    truncate_file: fs::File,
    target: Child,
    target_stdin: Option<ChildStdin>,
    shared_memory_id: libc::c_int,
    shared_memory: *mut libc::c_void,
}

#[allow(unsafe_code)]
impl PreparedHardClosed {
    fn new(truncate_path: &Path, exec_path: &Path) -> Result<Self> {
        let anonymous_exec =
            memmap2::MmapOptions::new()
                .len(4096)
                .map_anon()
                .map_err(|source| crate::Error::Io {
                    path: "anonymous executable-memory fixture".into(),
                    source,
                    location: snafu::location!(),
                })?;
        let ioctl_file = fs::File::open("/dev/null").context(IoSnafu {
            path: Path::new("/dev/null"),
        })?;
        let exec_file = fs::File::open(exec_path).context(IoSnafu { path: exec_path })?;
        let truncate_file = fs::OpenOptions::new()
            .write(true)
            .open(truncate_path)
            .context(IoSnafu {
                path: truncate_path,
            })?;
        let mut target = Command::new("/bin/sh")
            .args(["-c", "read _"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(IoSnafu {
                path: Path::new("process-control target"),
            })?;
        let target_stdin = target
            .stdin
            .take()
            .ok_or_else(|| invalid_state("process-control target has no stdin"))?;

        // IPC_PRIVATE plus immediate IPC_RMID keeps the segment addressable for
        // the permission probe while making kernel cleanup automatic on exit.
        // SAFETY: the size and flags are ordinary shmget inputs.
        let shared_memory_id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, 0o600) };
        if shared_memory_id < 0 {
            return Err(invalid_state(format!(
                "cannot prepare SysV shared memory: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the returned address is checked against SHM_FAILED and retained
        // until the matching shmdt in Drop.
        let shared_memory =
            unsafe { libc::shmat(shared_memory_id, std::ptr::null(), libc::SHM_RDONLY) };
        if shared_memory == (-1_isize) as *mut libc::c_void {
            // SAFETY: shared_memory_id was just returned by shmget.
            unsafe {
                libc::shmctl(shared_memory_id, libc::IPC_RMID, std::ptr::null_mut());
            }
            return Err(invalid_state(format!(
                "cannot attach SysV shared memory: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: marking an attached private segment for deletion is the SysV
        // mechanism for ensuring it cannot survive this process.
        if unsafe { libc::shmctl(shared_memory_id, libc::IPC_RMID, std::ptr::null_mut()) } != 0 {
            // SAFETY: both values are live results from shmget/shmat above.
            unsafe {
                libc::shmdt(shared_memory);
                libc::shmctl(shared_memory_id, libc::IPC_RMID, std::ptr::null_mut());
            }
            return Err(invalid_state(format!(
                "cannot mark SysV shared memory for deletion: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            anonymous_exec: Some(anonymous_exec),
            exec_file,
            ioctl_file,
            truncate_file,
            target,
            target_stdin: Some(target_stdin),
            shared_memory_id,
            shared_memory,
        })
    }

    fn run(&mut self, operation: HardClosedOperation) -> IoOutcome {
        match operation {
            HardClosedOperation::Exec => self.exec_preopened(),
            HardClosedOperation::AnonymousExec => {
                self.anonymous_exec
                    .take()
                    .map_or_else(missing_prepared_file, |mapping| match mapping.make_exec() {
                        Ok(_) => allowed_outcome(),
                        Err(error) => error_outcome(error),
                    })
            }
            HardClosedOperation::Ioctl => {
                let mut bytes = 0_i32;
                // SAFETY: FIONREAD writes one int to the valid stack address.
                let result =
                    unsafe { libc::ioctl(self.ioctl_file.as_raw_fd(), libc::FIONREAD, &mut bytes) };
                libc_outcome(result.into())
            }
            HardClosedOperation::Ipc => {
                let mut info = std::mem::MaybeUninit::<libc::shmid_ds>::uninit();
                // SAFETY: info points to enough writable storage for IPC_STAT.
                let result = unsafe {
                    libc::shmctl(self.shared_memory_id, libc::IPC_STAT, info.as_mut_ptr())
                };
                libc_outcome(result.into())
            }
            HardClosedOperation::Ptrace => {
                // SAFETY: this is an ordinary PTRACE_ATTACH attempt against the
                // fixture-owned process; no pointer argument is dereferenced.
                let result = unsafe {
                    libc::ptrace(
                        libc::PTRACE_ATTACH,
                        libc::pid_t::try_from(self.target.id()).unwrap_or(libc::pid_t::MAX),
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                };
                libc_outcome(result)
            }
            HardClosedOperation::Signal => {
                // Signal zero performs the permission check without changing
                // the target process when the hook is absent.
                // SAFETY: target.id() is the live fixture-owned child PID.
                libc_outcome(
                    unsafe {
                        libc::kill(
                            libc::pid_t::try_from(self.target.id()).unwrap_or(libc::pid_t::MAX),
                            0,
                        )
                    }
                    .into(),
                )
            }
            HardClosedOperation::Namespace => {
                // SAFETY: CLONE_NEWUTS requests a private namespace for only
                // this disposable process.
                libc_outcome(unsafe { libc::unshare(libc::CLONE_NEWUTS) }.into())
            }
            HardClosedOperation::Bpf => bpf_map_create_outcome(),
            HardClosedOperation::Create { path } => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    Ok(_) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            HardClosedOperation::Setattr { path } => {
                match fs::set_permissions(path, fs::Permissions::from_mode(0o000)) {
                    Ok(()) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            HardClosedOperation::Truncate => match self.truncate_file.set_len(0) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
            HardClosedOperation::Unlink { path } | HardClosedOperation::SelfProtect { path } => {
                match fs::remove_file(path) {
                    Ok(()) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            HardClosedOperation::Link { source, target } => match fs::hard_link(source, target) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
            HardClosedOperation::Rename { source, target } => match fs::rename(source, target) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
        }
    }

    fn exec_preopened(&self) -> IoOutcome {
        const ARGUMENT: &[u8] = b"mithril-exec-probe\0";
        let arguments = [ARGUMENT.as_ptr().cast::<libc::c_char>(), std::ptr::null()];
        let environment = [std::ptr::null()];

        // SAFETY: the child calls only async-signal-safe libc functions before
        // either replacing itself or exiting; the parent waits for that child.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return error_outcome(std::io::Error::last_os_error());
        }
        if child == 0 {
            // SAFETY: the retained file descriptor and null-terminated vectors
            // remain valid across fork. A failed exec exits with its errno.
            unsafe {
                libc::fexecve(
                    self.exec_file.as_raw_fd(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                );
                libc::_exit(*libc::__errno_location());
            }
        }
        let mut status = 0;
        // SAFETY: `child` is the positive PID returned by fork and `status` is
        // valid writable storage for waitpid.
        if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
            return error_outcome(std::io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if code == 0 {
                allowed_outcome()
            } else {
                IoOutcome {
                    allowed: false,
                    errno: Some(code),
                }
            }
        } else {
            IoOutcome {
                allowed: false,
                errno: None,
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for PreparedHardClosed {
    fn drop(&mut self) {
        // SAFETY: shared_memory is the still-attached address returned by shmat.
        unsafe {
            libc::shmdt(self.shared_memory);
        }
        self.target_stdin.take();
        let _result = self.target.wait();
    }
}

#[allow(unsafe_code)]
fn bpf_map_create_outcome() -> IoOutcome {
    let mut options = libbpf_rs::libbpf_sys::bpf_map_create_opts::default();
    options.sz = std::mem::size_of_val(&options)
        .try_into()
        .unwrap_or_default();
    // SAFETY: libbpf receives a complete options struct and no map name. A
    // successful disposable fd is closed immediately.
    let fd = unsafe {
        libbpf_rs::libbpf_sys::bpf_map_create(
            libbpf_rs::libbpf_sys::BPF_MAP_TYPE_ARRAY,
            std::ptr::null(),
            4,
            4,
            1,
            &options,
        )
    };
    if fd >= 0 {
        // SAFETY: fd is the owned descriptor returned by bpf_map_create.
        unsafe {
            libc::close(fd);
        }
        allowed_outcome()
    } else {
        error_outcome(std::io::Error::last_os_error())
    }
}

fn allowed_outcome() -> IoOutcome {
    IoOutcome {
        allowed: true,
        errno: None,
    }
}

fn error_outcome(error: std::io::Error) -> IoOutcome {
    IoOutcome {
        allowed: false,
        errno: error.raw_os_error(),
    }
}

fn libc_outcome(result: libc::c_long) -> IoOutcome {
    if result >= 0 {
        allowed_outcome()
    } else {
        error_outcome(std::io::Error::last_os_error())
    }
}

fn connect_outcome() -> IoOutcome {
    match TcpStream::connect(("127.0.0.1", 9)) {
        Ok(_) => IoOutcome {
            allowed: true,
            errno: None,
        },
        Err(error) => IoOutcome {
            allowed: false,
            errno: error.raw_os_error(),
        },
    }
}

fn invalid_state(reason: impl Into<String>) -> crate::Error {
    InvalidInputSnafu {
        path: Path::new("live effect state"),
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};

    use super::{
        mmap_outcome, read_outcome, BatchOutcome, HardClosedOperation, IoOutcome,
        PreparedHardClosed, PreparedWriteRace,
    };

    #[test]
    fn hard_denial_accepts_only_permission_errors() {
        assert!(IoOutcome {
            allowed: false,
            errno: Some(rustix::io::Errno::ACCESS.raw_os_error()),
        }
        .denied());
        assert!(!IoOutcome {
            allowed: false,
            errno: Some(rustix::io::Errno::NOENT.raw_os_error()),
        }
        .denied());
    }

    #[test]
    fn batch_average_uses_every_attempt() {
        assert_eq!(
            BatchOutcome {
                allowed: 2,
                denied: 1,
                other_errors: 1,
                elapsed_ns: 40,
            }
            .average_ns(),
            10
        );
    }

    #[test]
    fn prepared_file_fixture_can_read_and_map_before_policy_activation() -> crate::Result<()> {
        let mut file = tempfile::tempfile().map_err(|source| crate::Error::Io {
            path: "prepared file fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        file.write_all(b"secret")
            .map_err(|source| crate::Error::Io {
                path: "prepared file fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| crate::Error::Io {
                path: "prepared file fixture".into(),
                source,
                location: snafu::location!(),
            })?;

        assert!(read_outcome(&mut file).allowed);
        assert!(mmap_outcome(&file).allowed);
        Ok(())
    }

    #[test]
    fn prepared_write_race_releases_every_preallocated_worker() -> crate::Result<()> {
        let file = tempfile::NamedTempFile::new().map_err(|source| crate::Error::Io {
            path: "prepared write fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let prepared = PreparedWriteRace::new(file.path().to_path_buf(), 8)?;
        let outcome = prepared.run(file.path(), 8)?;

        assert_eq!(outcome.allowed, 8);
        assert_eq!(outcome.denied, 0);
        assert_eq!(outcome.other_errors, 0);
        Ok(())
    }

    #[test]
    fn prepared_hard_close_controls_work_before_policy_activation() -> crate::Result<()> {
        let truncate = tempfile::NamedTempFile::new().map_err(|source| crate::Error::Io {
            path: "truncate control fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let mut prepared =
            PreparedHardClosed::new(truncate.path(), std::path::Path::new("/bin/true"))?;

        assert!(prepared.run(HardClosedOperation::Exec).allowed);
        assert!(prepared.run(HardClosedOperation::AnonymousExec).allowed);
        assert!(prepared.run(HardClosedOperation::Ipc).allowed);
        assert!(prepared.run(HardClosedOperation::Signal).allowed);
        assert!(!prepared.run(HardClosedOperation::Ioctl).denied());
        Ok(())
    }
}
