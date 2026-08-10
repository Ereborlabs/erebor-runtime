use std::fs;
use std::io::Read as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
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
    OpenMany {
        path: PathBuf,
        count: u32,
    },
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
    Exit,
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
    pub(super) mount_target: PathBuf,
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
            ChildRequest::OpenMany { path, count } => {
                (Ok(ChildResponse::Batch(open_many(&path, count))), false)
            }
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
            ChildRequest::Exit => (Ok(ChildResponse::Exited), true),
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
    let mount_target = root.join("mount-target");
    fs::create_dir(&source).context(IoSnafu { path: &source })?;
    fs::write(&secret, b"restricted\n").context(IoSnafu { path: &secret })?;
    fs::hard_link(&secret, &hard_link).context(IoSnafu { path: &hard_link })?;
    fs::write(&benign, b"benign\n").context(IoSnafu { path: &benign })?;
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
        mount_target,
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
        let barrier = Arc::new(Barrier::new(worker_count.saturating_add(1)));
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
            source == self.source && target == self.target && usize::try_from(count).ok() == Some(self.handles.len()),
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
    use super::{BatchOutcome, IoOutcome};

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
}
