use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

use super::fixture_syscalls;
use super::mailbox::{SharedMailbox, EMPTY, READY, REQUEST, RESPONSE};

const CHILD_WAIT_LIMIT: Duration = Duration::from_secs(120);
const UNIX_STREAM_FAILURE_BASE: u32 = 1 << 16;
const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const QUALIFIED_TIOCGPTN_IOCTL: libc::c_ulong = 2_147_767_344;
static UNIX_STREAM_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

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
    OpenSamples {
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
        allowed_exec_path: PathBuf,
        script_path: PathBuf,
        deleted_exec_path: PathBuf,
        secret_path: PathBuf,
        benign_path: PathBuf,
        mount_source: PathBuf,
        move_mount_target: PathBuf,
    },
    PrepareLabeledTargets,
    PrepareUnixStreamTarget,
    ReceivePassedSecret,
    ReceivePassedBenign,
    Prepared(PreparedOperation),
    Exit,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum PreparedOperation {
    Exec,
    Execve,
    Execveat,
    Fexecve,
    ScriptExec,
    DeletedExec,
    MemfdExec,
    NonLeaderExec,
    AllowedExec,
    AnonymousExec,
    AnonymousExecutableMmap,
    AnonymousReadMmap,
    PkeyExecutableMprotect,
    PkeyReadMprotect,
    SecretMmapWrite,
    SecretMmapExec,
    SecretMprotectReadExec,
    SecretMprotectWriteExec,
    DeletedMprotectExec,
    MemfdMprotectExec,
    BenignMmapRead,
    PassedSecretRead,
    PassedBenignRead,
    ProcFdOpen,
    MoveMount,
    MountSetattr,
    MountPropagation,
    Ioctl,
    IoctlUnsupported,
    Ipc,
    UnixStream,
    UnixStreamStalePeer,
    UnixStreamUnmatched,
    Ptrace,
    Signal,
    SignalUnmatched,
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

pub(super) use PreparedOperation as HardClosedOperation;

#[derive(Clone, Debug, Deserialize, Serialize)]
enum ChildResponse {
    Ready { pid: u32 },
    Paths(Box<EffectPaths>),
    Outcome(IoOutcome),
    Batch(BatchOutcome),
    Samples(SampledBatchOutcome),
    Prepared,
    PreparedProcess { pid: u32 },
    DescriptorTransfer(DescriptorTransferOutcome),
    Failed { reason: String },
    Exited,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct EffectPaths {
    pub(super) source: PathBuf,
    pub(super) secret: PathBuf,
    pub(super) hard_link: PathBuf,
    pub(super) symlink_alias: PathBuf,
    pub(super) bind_alias: PathBuf,
    pub(super) benign: PathBuf,
    pub(super) exec_target: PathBuf,
    pub(super) allowed_exec_target: PathBuf,
    pub(super) script_target: PathBuf,
    pub(super) deleted_exec_target: PathBuf,
    pub(super) mount_target: PathBuf,
    pub(super) move_mount_target: PathBuf,
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
pub(super) struct DescriptorTransferOutcome {
    pub(super) payload_received: bool,
    pub(super) control_truncated: bool,
    pub(super) installed_descriptors: u32,
    pub(super) read_allowed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct BatchOutcome {
    pub(super) allowed: u32,
    pub(super) denied: u32,
    pub(super) other_errors: u32,
    pub(super) elapsed_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct SampledBatchOutcome {
    pub(super) batch: BatchOutcome,
    pub(super) raw_samples_ns: Vec<u64>,
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
        let mut command = Command::new(executable);
        command
            .arg("child")
            .arg("--fixture-root")
            .arg(fixture_root)
            .arg("--mailbox-path")
            .arg(&mailbox_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context(IoSnafu {
            path: Path::new("effect child"),
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
            ChildResponse::Paths(paths) => Ok(*paths),
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

    pub(super) fn open_samples(&mut self, path: &Path, count: u32) -> Result<SampledBatchOutcome> {
        match self.request(&ChildRequest::OpenSamples {
            path: path.to_path_buf(),
            count,
        })? {
            ChildResponse::Samples(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong sampled-open response",
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

    pub(super) fn prepare_operations(
        &mut self,
        paths: &EffectPaths,
        truncate_path: &Path,
    ) -> Result<()> {
        match self.request(&ChildRequest::PrepareHardClosed {
            truncate_path: truncate_path.to_path_buf(),
            exec_path: paths.exec_target.clone(),
            allowed_exec_path: paths.allowed_exec_target.clone(),
            script_path: paths.script_target.clone(),
            deleted_exec_path: paths.deleted_exec_target.clone(),
            secret_path: paths.secret.clone(),
            benign_path: paths.benign.clone(),
            mount_source: paths.source.clone(),
            move_mount_target: paths.move_mount_target.clone(),
        })? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong hard-close preparation response",
            )),
        }
    }

    pub(super) fn run_prepared(&mut self, operation: PreparedOperation) -> Result<IoOutcome> {
        match self.request(&ChildRequest::Prepared(operation))? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong hard-close response",
            )),
        }
    }

    pub(super) fn prepare_labeled_targets(&mut self) -> Result<()> {
        match self.request(&ChildRequest::PrepareLabeledTargets)? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong labeled-target response",
            )),
        }
    }

    pub(super) fn prepare_unix_stream_target(&mut self) -> Result<u32> {
        match self.request(&ChildRequest::PrepareUnixStreamTarget)? {
            ChildResponse::PreparedProcess { pid } => Ok(pid),
            _ => Err(invalid_state(
                "effect child returned the wrong Unix-stream target response",
            )),
        }
    }

    pub(super) fn receive_passed_secret(&mut self) -> Result<DescriptorTransferOutcome> {
        match self.request(&ChildRequest::ReceivePassedSecret)? {
            ChildResponse::DescriptorTransfer(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong denied descriptor response",
            )),
        }
    }

    pub(super) fn receive_passed_benign(&mut self) -> Result<DescriptorTransferOutcome> {
        match self.request(&ChildRequest::ReceivePassedBenign)? {
            ChildResponse::DescriptorTransfer(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong allowed descriptor response",
            )),
        }
    }

    pub(super) fn hard_closed(&mut self, operation: PreparedOperation) -> Result<IoOutcome> {
        self.run_prepared(operation)
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
        if !self.stopped && self.stop().is_err() && self.child.kill().is_ok() {
            let _result = self.child.wait();
        }
    }
}

pub fn run_effect_child(fixture_root: &Path, mailbox_path: &Path) -> Result<()> {
    enter_private_mount_namespace()?;
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
            ChildRequest::Setup => (
                setup_paths(fixture_root).map(|paths| ChildResponse::Paths(Box::new(paths))),
                false,
            ),
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
            ChildRequest::OpenSamples { path, count } => (
                Ok(ChildResponse::Samples(open_samples(&path, count))),
                false,
            ),
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
                allowed_exec_path,
                script_path,
                deleted_exec_path,
                secret_path,
                benign_path,
                mount_source,
                move_mount_target,
            } => match PreparedOperations::new(
                &truncate_path,
                &exec_path,
                &allowed_exec_path,
                &script_path,
                &deleted_exec_path,
                &secret_path,
                &benign_path,
                &mount_source,
                &move_mount_target,
            ) {
                Ok(prepared) => {
                    prepared_hard_closed = Some(prepared);
                    (Ok(ChildResponse::Prepared), false)
                }
                Err(error) => (Err(error), false),
            },
            ChildRequest::PrepareLabeledTargets => match prepared_hard_closed.as_mut() {
                Some(prepared) => match prepared.prepare_labeled_targets() {
                    Ok(()) => (Ok(ChildResponse::Prepared), false),
                    Err(error) => (Err(error), false),
                },
                None => (
                    Err(invalid_state(
                        "effect-operation resources were not prepared",
                    )),
                    false,
                ),
            },
            ChildRequest::PrepareUnixStreamTarget => match prepared_hard_closed.as_mut() {
                Some(prepared) => match prepared.prepare_unix_stream_target() {
                    Ok(pid) => (Ok(ChildResponse::PreparedProcess { pid }), false),
                    Err(error) => (Err(error), false),
                },
                None => (
                    Err(invalid_state(
                        "effect-operation resources were not prepared",
                    )),
                    false,
                ),
            },
            ChildRequest::ReceivePassedSecret => match prepared_hard_closed.as_mut() {
                Some(prepared) => (
                    prepared
                        .receive_passed_secret()
                        .map(ChildResponse::DescriptorTransfer),
                    false,
                ),
                None => (
                    Err(invalid_state(
                        "effect-operation resources were not prepared",
                    )),
                    false,
                ),
            },
            ChildRequest::ReceivePassedBenign => match prepared_hard_closed.as_mut() {
                Some(prepared) => (
                    prepared
                        .receive_passed_benign()
                        .map(ChildResponse::DescriptorTransfer),
                    false,
                ),
                None => (
                    Err(invalid_state(
                        "effect-operation resources were not prepared",
                    )),
                    false,
                ),
            },
            ChildRequest::Prepared(operation) => (
                prepared_hard_closed.as_mut().map_or_else(
                    || {
                        Err(invalid_state(
                            "effect-operation resources were not prepared",
                        ))
                    },
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

#[allow(deprecated)]
fn enter_private_mount_namespace() -> Result<()> {
    rustix::thread::unshare(rustix::thread::UnshareFlags::NEWNS)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: Path::new("mount namespace"),
        })?;
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        path: Path::new("private mount propagation"),
    })
}

fn setup_paths(root: &Path) -> Result<EffectPaths> {
    let source = root.join("source");
    let secret = source.join("secret");
    let hard_link = root.join("hard-link");
    let symlink_alias = root.join("symlink-alias");
    let bind_directory = root.join("bind-alias");
    let bind_alias = bind_directory.join("secret");
    let benign = root.join("benign");
    let exec_target = root.join("exec-target");
    let allowed_exec_target = root.join("allowed-exec-target");
    let script_target = root.join("script-target");
    let deleted_exec_target = root.join("deleted-exec-target");
    let mount_target = root.join("mount-target");
    let move_mount_target = root.join("move-mount-target");
    let setattr_target = root.join("setattr-target");
    let truncate_target = root.join("truncate-target");
    let unlink_target = root.join("unlink-target");
    let mutation_source = root.join("mutation-source");
    fs::create_dir(&source).context(IoSnafu { path: &source })?;
    fs::write(&secret, b"restricted\n").context(IoSnafu { path: &secret })?;
    fs::hard_link(&secret, &hard_link).context(IoSnafu { path: &hard_link })?;
    symlink(&secret, &symlink_alias).context(IoSnafu {
        path: &symlink_alias,
    })?;
    fs::write(&benign, b"benign\n").context(IoSnafu { path: &benign })?;
    fs::copy("/bin/sh", &exec_target).context(IoSnafu { path: &exec_target })?;
    fs::set_permissions(&exec_target, fs::Permissions::from_mode(0o755))
        .context(IoSnafu { path: &exec_target })?;
    fs::copy("/bin/busybox", &allowed_exec_target).context(IoSnafu {
        path: &allowed_exec_target,
    })?;
    fs::set_permissions(&allowed_exec_target, fs::Permissions::from_mode(0o755)).context(
        IoSnafu {
            path: &allowed_exec_target,
        },
    )?;
    fs::write(&script_target, b"#!/bin/sh\nexit 0\n").context(IoSnafu {
        path: &script_target,
    })?;
    fs::set_permissions(&script_target, fs::Permissions::from_mode(0o755)).context(IoSnafu {
        path: &script_target,
    })?;
    fs::copy("/bin/sh", &deleted_exec_target).context(IoSnafu {
        path: &deleted_exec_target,
    })?;
    fs::set_permissions(&deleted_exec_target, fs::Permissions::from_mode(0o755)).context(
        IoSnafu {
            path: &deleted_exec_target,
        },
    )?;
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
    fs::create_dir(&move_mount_target).context(IoSnafu {
        path: &move_mount_target,
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
        symlink_alias,
        bind_alias,
        benign,
        exec_target,
        allowed_exec_target,
        script_target,
        deleted_exec_target,
        mount_target,
        move_mount_target,
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

fn missing_process_target() -> IoOutcome {
    IoOutcome {
        allowed: false,
        errno: Some(rustix::io::Errno::NOENT.raw_os_error()),
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

fn open_samples(path: &Path, count: u32) -> SampledBatchOutcome {
    let batch_start = Instant::now();
    let mut batch = BatchOutcome {
        allowed: 0,
        denied: 0,
        other_errors: 0,
        elapsed_ns: 0,
    };
    let mut raw_samples_ns = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let started = Instant::now();
        let outcome = open_outcome(path);
        raw_samples_ns.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        if outcome.allowed {
            batch.allowed += 1;
        } else if outcome.denied() {
            batch.denied += 1;
        } else {
            batch.other_errors += 1;
        }
    }
    batch.elapsed_ns = u64::try_from(batch_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    SampledBatchOutcome {
        batch,
        raw_samples_ns,
    }
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

struct PreparedOperations {
    anonymous_exec: Option<memmap2::MmapMut>,
    exec_path: PathBuf,
    script_path: PathBuf,
    exec_file: fs::File,
    allowed_exec_file: fs::File,
    deleted_exec_file: fs::File,
    memfd_exec_file: fs::File,
    secret_file: fs::File,
    benign_file: fs::File,
    secret_read_mapping: Option<memmap2::Mmap>,
    secret_write_mapping: Option<memmap2::MmapMut>,
    deleted_read_mapping: Option<memmap2::Mmap>,
    memfd_read_mapping: Option<memmap2::Mmap>,
    passed_secret_file: fs::File,
    passed_benign_file: fs::File,
    mount_source: PathBuf,
    move_mount_target: PathBuf,
    mount_tree: fs::File,
    ioctl_file: fs::File,
    unsupported_ioctl_file: fs::File,
    truncate_file: fs::File,
    process_target: Option<ProcessControlTarget>,
    unix_stream_path: PathBuf,
    unix_stream_signal: Option<SharedMailbox>,
    unix_stream_signal_path: PathBuf,
    unix_stream_target: Option<UnixStreamTarget>,
    shared_memory_id: libc::c_int,
    shared_memory: *mut libc::c_void,
}

#[allow(unsafe_code)]
impl PreparedOperations {
    #[allow(clippy::too_many_arguments)]
    fn new(
        truncate_path: &Path,
        exec_path: &Path,
        allowed_exec_path: &Path,
        script_path: &Path,
        deleted_exec_path: &Path,
        secret_path: &Path,
        benign_path: &Path,
        mount_source: &Path,
        move_mount_target: &Path,
    ) -> Result<Self> {
        let anonymous_exec =
            memmap2::MmapOptions::new()
                .len(4096)
                .map_anon()
                .map_err(|source| crate::Error::Io {
                    path: "anonymous executable-memory fixture".into(),
                    source,
                    location: snafu::location!(),
                })?;
        let ioctl_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/pts/ptmx")
            .context(IoSnafu {
                path: Path::new("/dev/pts/ptmx"),
            })?;
        let unsupported_ioctl_file = fs::File::open("/dev/zero").context(IoSnafu {
            path: Path::new("/dev/zero"),
        })?;
        let exec_file = fs::File::open(exec_path).context(IoSnafu { path: exec_path })?;
        let allowed_exec_file = fs::File::open(allowed_exec_path).context(IoSnafu {
            path: allowed_exec_path,
        })?;
        let deleted_exec_file = fs::File::open(deleted_exec_path).context(IoSnafu {
            path: deleted_exec_path,
        })?;
        let memfd_exec_file =
            fixture_syscalls::memfd_copy(exec_path).map_err(|source| crate::Error::Io {
                path: "memfd executable fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        let secret_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(secret_path)
            .context(IoSnafu { path: secret_path })?;
        let benign_file = fs::File::open(benign_path).context(IoSnafu { path: benign_path })?;
        // SAFETY: each file stays open for the mapping lifetime. The deleted
        // executable path is unlinked only after this mapping is ready.
        let secret_read_mapping =
            unsafe { memmap2::MmapOptions::new().map_copy_read_only(&secret_file) }.map_err(
                |source| crate::Error::Io {
                    path: "secret read mapping fixture".into(),
                    source,
                    location: snafu::location!(),
                },
            )?;
        // SAFETY: MAP_PRIVATE keeps this transition fixture from changing the file.
        let secret_write_mapping = unsafe { memmap2::MmapOptions::new().map_copy(&secret_file) }
            .map_err(|source| crate::Error::Io {
                path: "secret write mapping fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        // SAFETY: both executable fixture files remain open for the mapping lifetime.
        let deleted_read_mapping =
            unsafe { memmap2::MmapOptions::new().map_copy_read_only(&deleted_exec_file) }.map_err(
                |source| crate::Error::Io {
                    path: "deleted executable mapping fixture".into(),
                    source,
                    location: snafu::location!(),
                },
            )?;
        // SAFETY: memfd_exec_file remains open for the mapping lifetime.
        let memfd_read_mapping =
            unsafe { memmap2::MmapOptions::new().map_copy_read_only(&memfd_exec_file) }.map_err(
                |source| crate::Error::Io {
                    path: "memfd executable mapping fixture".into(),
                    source,
                    location: snafu::location!(),
                },
            )?;
        let passed_secret_file =
            fixture_syscalls::receive_file_from_actor(secret_path).map_err(|source| {
                crate::Error::Io {
                    path: "SCM_RIGHTS secret fixture".into(),
                    source,
                    location: snafu::location!(),
                }
            })?;
        let passed_benign_file =
            fixture_syscalls::receive_file_from_actor(benign_path).map_err(|source| {
                crate::Error::Io {
                    path: "SCM_RIGHTS benign fixture".into(),
                    source,
                    location: snafu::location!(),
                }
            })?;
        let mount_tree =
            fixture_syscalls::open_mount_tree(mount_source).map_err(|source| crate::Error::Io {
                path: "open_tree fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        let truncate_file = fs::OpenOptions::new()
            .write(true)
            .open(truncate_path)
            .context(IoSnafu {
                path: truncate_path,
            })?;
        let unix_stream_path =
            PathBuf::from(format!("/tmp/mithril-effect-{}.sock", std::process::id()));
        let unix_stream_signal_path = secret_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join(".mithril-unix-stream-state");
        let unix_stream_signal = SharedMailbox::create(&unix_stream_signal_path)?;
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
            exec_path: exec_path.to_path_buf(),
            script_path: script_path.to_path_buf(),
            exec_file,
            allowed_exec_file,
            deleted_exec_file,
            memfd_exec_file,
            secret_file,
            benign_file,
            secret_read_mapping: Some(secret_read_mapping),
            secret_write_mapping: Some(secret_write_mapping),
            deleted_read_mapping: Some(deleted_read_mapping),
            memfd_read_mapping: Some(memfd_read_mapping),
            passed_secret_file,
            passed_benign_file,
            mount_source: mount_source.to_path_buf(),
            move_mount_target: move_mount_target.to_path_buf(),
            mount_tree,
            ioctl_file,
            unsupported_ioctl_file,
            truncate_file,
            process_target: None,
            unix_stream_path,
            unix_stream_signal: Some(unix_stream_signal),
            unix_stream_signal_path,
            unix_stream_target: None,
            shared_memory_id,
            shared_memory,
        })
    }

    fn prepare_labeled_targets(&mut self) -> Result<()> {
        ensure!(
            self.process_target.is_none(),
            InvalidInputSnafu {
                path: Path::new("labeled effect targets"),
                reason: "labeled effect targets were already prepared",
            }
        );
        let process_target = ProcessControlTarget::spawn().context(IoSnafu {
            path: Path::new("process-control target"),
        })?;
        self.process_target = Some(process_target);
        if self.unix_stream_target.is_none() {
            self.prepare_unix_stream_target()?;
        }
        Ok(())
    }

    fn prepare_unix_stream_target(&mut self) -> Result<u32> {
        ensure!(
            self.unix_stream_target.is_none(),
            InvalidInputSnafu {
                path: &self.unix_stream_path,
                reason: "Unix-stream target was already prepared",
            }
        );
        let signal = self
            .unix_stream_signal
            .take()
            .ok_or_else(|| invalid_state("Unix-stream shared state was already consumed"))?;
        let target = UnixStreamTarget::spawn_with_files(
            signal,
            self.unix_stream_signal_path.clone(),
            self.secret_file.as_raw_fd(),
            self.benign_file.as_raw_fd(),
        )
        .context(IoSnafu {
            path: &self.unix_stream_path,
        })?;
        let pid = target.pid();
        self.unix_stream_target = Some(target);
        Ok(pid)
    }

    fn receive_passed_secret(&mut self) -> Result<DescriptorTransferOutcome> {
        self.unix_stream_target
            .as_mut()
            .ok_or_else(|| invalid_state("Unix-stream target was not prepared"))?
            .receive_file()
            .context(IoSnafu {
                path: Path::new("SCM_RIGHTS denied acquisition"),
            })
    }

    fn receive_passed_benign(&mut self) -> Result<DescriptorTransferOutcome> {
        self.unix_stream_target
            .as_mut()
            .ok_or_else(|| invalid_state("Unix-stream target was not prepared"))?
            .receive_file()
            .context(IoSnafu {
                path: Path::new("SCM_RIGHTS allowed acquisition"),
            })
    }

    fn run(&mut self, operation: PreparedOperation) -> IoOutcome {
        match operation {
            PreparedOperation::Exec => {
                io_outcome(fixture_syscalls::exec_fd(self.exec_file.as_raw_fd(), false))
            }
            PreparedOperation::Execve => {
                io_outcome(fixture_syscalls::exec_path(&self.exec_path, false))
            }
            PreparedOperation::Execveat => {
                io_outcome(fixture_syscalls::exec_path(&self.exec_path, true))
            }
            PreparedOperation::Fexecve => {
                io_outcome(fixture_syscalls::exec_fd(self.exec_file.as_raw_fd(), false))
            }
            PreparedOperation::ScriptExec => {
                io_outcome(fixture_syscalls::exec_path(&self.script_path, false))
            }
            PreparedOperation::DeletedExec => io_outcome(fixture_syscalls::exec_fd(
                self.deleted_exec_file.as_raw_fd(),
                false,
            )),
            PreparedOperation::MemfdExec => io_outcome(fixture_syscalls::exec_fd(
                self.memfd_exec_file.as_raw_fd(),
                false,
            )),
            PreparedOperation::NonLeaderExec => {
                io_outcome(fixture_syscalls::exec_fd(self.exec_file.as_raw_fd(), true))
            }
            PreparedOperation::AllowedExec => io_outcome(fixture_syscalls::exec_fd(
                self.allowed_exec_file.as_raw_fd(),
                false,
            )),
            PreparedOperation::AnonymousExec => {
                self.anonymous_exec
                    .take()
                    .map_or_else(missing_prepared_file, |mapping| match mapping.make_exec() {
                        Ok(_) => allowed_outcome(),
                        Err(error) => error_outcome(error),
                    })
            }
            PreparedOperation::AnonymousExecutableMmap => {
                io_outcome(fixture_syscalls::map_anonymous(libc::PROT_EXEC))
            }
            PreparedOperation::AnonymousReadMmap => {
                io_outcome(fixture_syscalls::map_anonymous(libc::PROT_READ))
            }
            PreparedOperation::PkeyExecutableMprotect => io_outcome(
                fixture_syscalls::pkey_mprotect_anonymous(libc::PROT_READ | libc::PROT_EXEC),
            ),
            PreparedOperation::PkeyReadMprotect => {
                io_outcome(fixture_syscalls::pkey_mprotect_anonymous(libc::PROT_READ))
            }
            PreparedOperation::SecretMmapWrite => {
                mmap_protection_outcome(&self.secret_file, libc::PROT_WRITE, libc::MAP_SHARED, None)
            }
            PreparedOperation::SecretMmapExec => {
                mmap_protection_outcome(&self.secret_file, libc::PROT_EXEC, libc::MAP_PRIVATE, None)
            }
            PreparedOperation::SecretMprotectReadExec => self
                .secret_read_mapping
                .take()
                .map_or_else(missing_prepared_file, |mapping| {
                    fixture_syscalls::make_mapping_exec(&mapping)
                        .map_or_else(error_outcome, |_| allowed_outcome())
                }),
            PreparedOperation::SecretMprotectWriteExec => self
                .secret_write_mapping
                .take()
                .map_or_else(missing_prepared_file, |mapping| {
                    mapping
                        .make_exec()
                        .map_or_else(error_outcome, |_| allowed_outcome())
                }),
            PreparedOperation::DeletedMprotectExec => {
                self.deleted_read_mapping
                    .take()
                    .map_or_else(missing_prepared_file, |mapping| {
                        fixture_syscalls::make_mapping_exec(&mapping)
                            .map_or_else(error_outcome, |_| allowed_outcome())
                    })
            }
            PreparedOperation::MemfdMprotectExec => {
                self.memfd_read_mapping
                    .take()
                    .map_or_else(missing_prepared_file, |mapping| {
                        fixture_syscalls::make_mapping_exec(&mapping)
                            .map_or_else(error_outcome, |_| allowed_outcome())
                    })
            }
            PreparedOperation::BenignMmapRead => mmap_outcome(&self.benign_file),
            PreparedOperation::PassedSecretRead => read_outcome(&mut self.passed_secret_file),
            PreparedOperation::PassedBenignRead => read_outcome(&mut self.passed_benign_file),
            PreparedOperation::ProcFdOpen => open_outcome(&PathBuf::from(format!(
                "/proc/self/fd/{}",
                self.secret_file.as_raw_fd()
            ))),
            PreparedOperation::MoveMount => io_outcome(fixture_syscalls::move_mount(
                self.mount_tree.as_raw_fd(),
                &self.move_mount_target,
            )),
            PreparedOperation::MountSetattr => {
                io_outcome(fixture_syscalls::set_mount_read_only(&self.mount_source))
            }
            PreparedOperation::MountPropagation => {
                io_outcome(fixture_syscalls::make_mount_shared(&self.mount_source))
            }
            PreparedOperation::Ioctl => ptmx_number_outcome(&self.ioctl_file),
            PreparedOperation::IoctlUnsupported => {
                let mut pty_number = u32::MAX;
                // SAFETY: TIOCGPTN writes one u32 to the valid stack address.
                let result = unsafe {
                    libc::ioctl(
                        self.unsupported_ioctl_file.as_raw_fd(),
                        QUALIFIED_TIOCGPTN_IOCTL,
                        &mut pty_number,
                    )
                };
                libc_outcome(result.into())
            }
            PreparedOperation::Ipc => {
                let mut info = std::mem::MaybeUninit::<libc::shmid_ds>::uninit();
                // SAFETY: info points to enough writable storage for IPC_STAT.
                let result = unsafe {
                    libc::shmctl(self.shared_memory_id, libc::IPC_STAT, info.as_mut_ptr())
                };
                libc_outcome(result.into())
            }
            PreparedOperation::UnixStream => self
                .unix_stream_target
                .as_mut()
                .map_or_else(missing_process_target, UnixStreamTarget::roundtrip),
            PreparedOperation::UnixStreamStalePeer => self
                .unix_stream_target
                .as_mut()
                .map_or_else(missing_process_target, UnixStreamTarget::stale_send),
            PreparedOperation::UnixStreamUnmatched => {
                self.unix_stream_target
                    .as_mut()
                    .map_or_else(missing_process_target, |target| {
                        target
                            .restart()
                            .map_or_else(error_outcome, |()| target.roundtrip())
                    })
            }
            PreparedOperation::Ptrace => {
                self.process_target
                    .as_ref()
                    .map_or_else(missing_process_target, |target| {
                        // SAFETY: this is an ordinary PTRACE_ATTACH attempt against the
                        // fixture-owned process; no pointer argument is dereferenced.
                        let result = unsafe {
                            libc::ptrace(
                                libc::PTRACE_ATTACH,
                                target.pid,
                                std::ptr::null_mut::<libc::c_void>(),
                                std::ptr::null_mut::<libc::c_void>(),
                            )
                        };
                        if result == 0 {
                            let mut status = 0;
                            // SAFETY: a successful attach makes this child waitable; detach
                            // restores it so a failed enforcement assertion can still clean up.
                            unsafe {
                                libc::waitpid(target.pid, &mut status, 0);
                                libc::ptrace(
                                    libc::PTRACE_DETACH,
                                    target.pid,
                                    std::ptr::null_mut::<libc::c_void>(),
                                    std::ptr::null_mut::<libc::c_void>(),
                                );
                            }
                        }
                        libc_outcome(result)
                    })
            }
            PreparedOperation::Signal => {
                self.process_target
                    .as_ref()
                    .map_or_else(missing_process_target, |target| {
                        // Signal zero performs the permission check without changing the target.
                        // SAFETY: pid names the live fixture-owned fork child.
                        libc_outcome(unsafe { libc::kill(target.pid, 0) }.into())
                    })
            }
            PreparedOperation::SignalUnmatched => {
                self.process_target
                    .as_ref()
                    .map_or_else(missing_process_target, |target| {
                        // SIGCONT has no effect on this running target. It proves that an
                        // unlisted signal argument uses the signed wildcard denial.
                        // SAFETY: pid names the live fixture-owned fork child.
                        libc_outcome(unsafe { libc::kill(target.pid, libc::SIGCONT) }.into())
                    })
            }
            PreparedOperation::Namespace => {
                // SAFETY: CLONE_NEWUTS requests a private namespace for only
                // this disposable process.
                libc_outcome(unsafe { libc::unshare(libc::CLONE_NEWUTS) }.into())
            }
            PreparedOperation::Bpf => bpf_map_create_outcome(),
            PreparedOperation::Create { path } => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    Ok(_) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            PreparedOperation::Setattr { path } => {
                match fs::set_permissions(path, fs::Permissions::from_mode(0o000)) {
                    Ok(()) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            PreparedOperation::Truncate => match self.truncate_file.set_len(0) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
            PreparedOperation::Unlink { path } | PreparedOperation::SelfProtect { path } => {
                match fs::remove_file(path) {
                    Ok(()) => allowed_outcome(),
                    Err(error) => error_outcome(error),
                }
            }
            PreparedOperation::Link { source, target } => match fs::hard_link(source, target) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
            PreparedOperation::Rename { source, target } => match fs::rename(source, target) {
                Ok(()) => allowed_outcome(),
                Err(error) => error_outcome(error),
            },
        }
    }
}

#[allow(unsafe_code)]
impl Drop for PreparedOperations {
    fn drop(&mut self) {
        // SAFETY: shared_memory is the still-attached address returned by shmat.
        unsafe {
            libc::shmdt(self.shared_memory);
        }
        self.unix_stream_target.take();
        self.process_target.take();
        let _cleanup = fs::remove_file(&self.unix_stream_signal_path);
    }
}

struct ProcessControlTarget {
    pid: libc::pid_t,
    release: Option<OwnedFd>,
}

#[allow(unsafe_code)]
impl ProcessControlTarget {
    fn spawn() -> io::Result<Self> {
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to storage for both returned descriptors.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the child uses only async-signal-safe syscalls before _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: both descriptors were returned by pipe2 and remain owned here.
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(error);
        }
        if pid == 0 {
            let mut wait = libc::pollfd {
                fd: pipe[0],
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: the fork child owns the read descriptor and wait is writable.
            unsafe {
                libc::close(pipe[1]);
                while libc::poll(&raw mut wait, 1, -1) < 0 {}
                libc::close(pipe[0]);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent owns both descriptors and transfers the write end.
        unsafe {
            libc::close(pipe[0]);
        }
        Ok(Self {
            pid,
            // SAFETY: pipe2 returned this live descriptor and ownership moves here.
            release: Some(unsafe { OwnedFd::from_raw_fd(pipe[1]) }),
        })
    }
}

#[allow(unsafe_code)]
impl Drop for ProcessControlTarget {
    fn drop(&mut self) {
        self.release.take();
        let mut status = 0;
        // SAFETY: pid is this process's live fork child and status is writable.
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
    }
}

struct UnixStreamTarget {
    pid: Option<libc::pid_t>,
    signal: SharedMailbox,
    signal_path: PathBuf,
    abstract_name: Vec<u8>,
    address: libc::sockaddr_un,
    address_length: libc::socklen_t,
    connected_stream: Option<UnixStream>,
    pending_transfers: u8,
    received_files: Vec<fs::File>,
}

#[allow(unsafe_code)]
impl UnixStreamTarget {
    fn spawn_with_files(
        signal: SharedMailbox,
        signal_path: PathBuf,
        first_file: libc::c_int,
        second_file: libc::c_int,
    ) -> io::Result<Self> {
        let abstract_name = format!(
            "mithril-effect-{}-{}",
            std::process::id(),
            UNIX_STREAM_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes();
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        if abstract_name.is_empty() || abstract_name.len() + 1 > address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix-stream fixture abstract name is too long",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, source) in address.sun_path[1..].iter_mut().zip(&abstract_name) {
            *target = *source as libc::c_char;
        }
        let address_length =
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + abstract_name.len() + 1)
                .try_into()
                .map_err(io::Error::other)?;
        let pid =
            spawn_unix_stream_server(&signal, &address, address_length, first_file, second_file)?;
        Ok(Self {
            pid: Some(pid),
            signal,
            signal_path,
            abstract_name,
            address,
            address_length,
            connected_stream: None,
            pending_transfers: u8::from(first_file >= 0) + u8::from(second_file >= 0),
            received_files: Vec::new(),
        })
    }

    fn pid(&self) -> u32 {
        self.pid.unwrap_or_default() as u32
    }

    fn roundtrip(&mut self) -> IoOutcome {
        self.signal.set_state(REQUEST);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.signal.state() == REQUEST {
            if Instant::now() >= deadline {
                let _result = self.wait();
                return error_outcome(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Unix-stream fixture server did not become ready",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
        if self.signal.state() != READY {
            let state = self.signal.state();
            let _result = self.wait();
            if state >= UNIX_STREAM_FAILURE_BASE {
                return error_outcome(io::Error::from_raw_os_error(
                    (state - UNIX_STREAM_FAILURE_BASE) as i32,
                ));
            }
            return error_outcome(io::Error::other(
                "Unix-stream fixture server failed before readiness",
            ));
        }
        let client_result = (|| -> io::Result<UnixStream> {
            let address = SocketAddr::from_abstract_name(&self.abstract_name)?;
            let mut stream = UnixStream::connect_addr(&address)?;
            stream.write_all(&[1])?;
            let mut response = [0_u8; 1];
            stream.read_exact(&mut response)?;
            if response != [2] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unix-stream fixture received the wrong response",
                ));
            }
            Ok(stream)
        })();
        match client_result {
            Ok(stream) => {
                self.connected_stream = Some(stream);
                if self.pending_transfers == 0 {
                    self.wait()
                        .map_or_else(error_outcome, |()| allowed_outcome())
                } else {
                    allowed_outcome()
                }
            }
            Err(error) => {
                let _result = self.wait();
                error_outcome(error)
            }
        }
    }

    fn stale_send(&mut self) -> IoOutcome {
        self.connected_stream
            .take()
            .map_or_else(missing_process_target, |mut stream| {
                stream
                    .write_all(&[3])
                    .map_or_else(error_outcome, |()| allowed_outcome())
            })
    }

    fn receive_file(&mut self) -> io::Result<DescriptorTransferOutcome> {
        if self.pending_transfers == 0 {
            return Err(io::Error::other("SCM_RIGHTS transfer fixture is empty"));
        }
        let mut received = fixture_syscalls::receive_file_descriptor(
            self.connected_stream
                .as_ref()
                .ok_or_else(|| io::Error::other("Unix-stream fixture is not connected"))?
                .as_raw_fd(),
        )?;
        let installed_descriptors = u32::from(received.file.is_some());
        let read_allowed = received
            .file
            .as_mut()
            .is_some_and(|file| read_outcome(file).allowed);
        if let Some(file) = received.file {
            self.received_files.push(file);
        }
        self.pending_transfers -= 1;
        if self.pending_transfers == 0 {
            self.connected_stream
                .as_mut()
                .ok_or_else(|| io::Error::other("Unix-stream fixture is not connected"))?
                .write_all(&[3])?;
            self.wait()?;
        }
        Ok(DescriptorTransferOutcome {
            payload_received: received.payload_received,
            control_truncated: received.control_truncated,
            installed_descriptors,
            read_allowed,
        })
    }

    fn restart(&mut self) -> io::Result<()> {
        if self.pid.is_some() || self.connected_stream.is_some() {
            return Err(io::Error::other("Unix-stream target is still active"));
        }
        self.signal.reset();
        self.pid = Some(spawn_unix_stream_server(
            &self.signal,
            &self.address,
            self.address_length,
            -1,
            -1,
        )?);
        self.pending_transfers = 0;
        Ok(())
    }

    fn wait(&mut self) -> io::Result<()> {
        let Some(pid) = self.pid.take() else {
            return Ok(());
        };
        let mut status = 0;
        loop {
            // SAFETY: pid is this process's fixture child and status is writable.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Unix-stream fixture server failed with wait status {status}"
            )))
        }
    }
}

#[allow(unsafe_code)]
fn spawn_unix_stream_server(
    signal: &SharedMailbox,
    address: &libc::sockaddr_un,
    address_length: libc::socklen_t,
    first_file: libc::c_int,
    second_file: libc::c_int,
) -> io::Result<libc::pid_t> {
    // SAFETY: the child calls only async-signal-safe libc functions before _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: the child owns inherited mappings and input buffers.
        unsafe {
            unix_stream_server_child(signal, address, address_length, first_file, second_file);
        }
    }
    Ok(pid)
}

#[allow(unsafe_code)]
impl Drop for UnixStreamTarget {
    fn drop(&mut self) {
        if self.signal.state() == EMPTY {
            self.signal.set_state(RESPONSE);
        }
        self.connected_stream.take();
        let _result = self.wait();
        let _cleanup = fs::remove_file(&self.signal_path);
    }
}

#[allow(unsafe_code)]
unsafe fn unix_stream_server_child(
    signal: &SharedMailbox,
    address: &libc::sockaddr_un,
    address_length: libc::socklen_t,
    first_file: libc::c_int,
    second_file: libc::c_int,
) -> ! {
    // SAFETY: the shared mapping and pointers come from the prepared parent process.
    unsafe {
        while signal.state() == EMPTY {
            std::hint::spin_loop();
        }
        if signal.state() != REQUEST {
            libc::_exit(0);
        }
        let listener = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if listener < 0 {
            signal.set_state(UNIX_STREAM_FAILURE_BASE + *libc::__errno_location() as u32);
            libc::_exit(11);
        }
        if libc::bind(listener, std::ptr::from_ref(address).cast(), address_length) != 0 {
            signal.set_state(UNIX_STREAM_FAILURE_BASE + *libc::__errno_location() as u32);
            libc::_exit(11);
        }
        if libc::listen(listener, 1) != 0 {
            signal.set_state(UNIX_STREAM_FAILURE_BASE + *libc::__errno_location() as u32);
            libc::_exit(11);
        }
        signal.set_state(READY);
        let mut poll = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&raw mut poll, 1, 2_000) <= 0 {
            libc::_exit(13);
        }
        let stream = libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        );
        if stream < 0 {
            libc::_exit(14);
        }
        let mut request = [0_u8];
        if libc::read(stream, request.as_mut_ptr().cast(), 1) != 1 || request != [1] {
            libc::_exit(15);
        }
        let response = [2_u8];
        if libc::write(stream, response.as_ptr().cast(), 1) != 1 {
            libc::_exit(16);
        }
        for file in [first_file, second_file] {
            if file >= 0 && fixture_syscalls::send_fd(stream, file).is_err() {
                libc::_exit(17);
            }
        }
        if first_file >= 0 || second_file >= 0 {
            let mut complete = [0_u8];
            if libc::read(stream, complete.as_mut_ptr().cast(), 1) != 1 || complete != [3] {
                libc::_exit(18);
            }
        }
        libc::close(stream);
        libc::close(listener);
        libc::_exit(0);
    }
}

#[allow(unsafe_code)]
fn bpf_map_create_outcome() -> IoOutcome {
    let attributes = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    };
    // SAFETY: the attributes are the initial BPF_MAP_CREATE fields from the
    // Linux UAPI. The kernel copies the supplied 16 bytes during this call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &raw const attributes,
            std::mem::size_of_val(&attributes),
        )
    };
    if fd >= 0 {
        // SAFETY: a successful BPF_MAP_CREATE result is a new C file descriptor.
        unsafe {
            libc::close(fd as libc::c_int);
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

fn io_outcome(result: std::io::Result<()>) -> IoOutcome {
    match result {
        Ok(()) => allowed_outcome(),
        Err(error) => error_outcome(error),
    }
}

#[allow(unsafe_code)]
fn ptmx_number_outcome(file: &fs::File) -> IoOutcome {
    let mut pty_number = u32::MAX;
    // SAFETY: TIOCGPTN writes one u32 to the valid stack address.
    let result =
        unsafe { libc::ioctl(file.as_raw_fd(), QUALIFIED_TIOCGPTN_IOCTL, &mut pty_number) };
    if result == 0 && pty_number != u32::MAX {
        allowed_outcome()
    } else if result < 0 {
        error_outcome(std::io::Error::last_os_error())
    } else {
        IoOutcome {
            allowed: false,
            errno: None,
        }
    }
}

#[allow(unsafe_code)]
fn mmap_protection_outcome(
    file: &fs::File,
    initial_protection: libc::c_int,
    flags: libc::c_int,
    changed_protection: Option<libc::c_int>,
) -> IoOutcome {
    let length = 4096;
    // SAFETY: the returned mapping is checked and released before this call returns.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            initial_protection,
            flags,
            file.as_raw_fd(),
            0,
        )
    };
    if address == libc::MAP_FAILED {
        return error_outcome(std::io::Error::last_os_error());
    }
    let outcome = changed_protection.map_or_else(allowed_outcome, |protection| {
        // SAFETY: address and length describe the live mapping above.
        libc_outcome(unsafe { libc::mprotect(address, length, protection) }.into())
    });
    // SAFETY: address and length describe the live mapping above.
    unsafe {
        libc::munmap(address, length);
    }
    outcome
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
    use std::fs;
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    use std::mem::{offset_of, size_of};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    use super::{
        invalid_state, mmap_outcome, ptmx_number_outcome, read_outcome, BatchOutcome,
        BpfMapCreateAttr, IoOutcome, PreparedWriteRace, ProcessControlTarget, UnixStreamTarget,
        BPF_MAP_TYPE_ARRAY,
    };
    use crate::effect::fixture_syscalls;
    use crate::effect::mailbox::SharedMailbox;

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
    fn ptmx_ioctl_requires_success_and_kernel_output() -> crate::Result<()> {
        let ptmx_path = std::path::Path::new("/dev/pts/ptmx");
        let ptmx = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(ptmx_path)
            .map_err(|source| crate::Error::Io {
                path: ptmx_path.to_path_buf(),
                source,
                location: snafu::location!(),
            })?;
        assert!(ptmx_number_outcome(&ptmx).allowed);

        let null_path = std::path::Path::new("/dev/null");
        let null = fs::File::open(null_path).map_err(|source| crate::Error::Io {
            path: null_path.to_path_buf(),
            source,
            location: snafu::location!(),
        })?;
        assert!(!ptmx_number_outcome(&null).allowed);
        Ok(())
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
    fn raw_bpf_map_create_attributes_match_the_linux_uapi_prefix() {
        assert_eq!(size_of::<BpfMapCreateAttr>(), 16);
        assert_eq!(offset_of!(BpfMapCreateAttr, map_type), 0);
        assert_eq!(offset_of!(BpfMapCreateAttr, key_size), 4);
        assert_eq!(offset_of!(BpfMapCreateAttr, value_size), 8);
        assert_eq!(offset_of!(BpfMapCreateAttr, max_entries), 12);
        assert_eq!(BPF_MAP_TYPE_ARRAY, 2);
    }

    #[test]
    #[allow(unsafe_code)]
    fn deleted_executable_fixture_retains_its_descriptor_and_mapping() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "deleted executable fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let path = directory.path().join("executable");
        std::fs::write(&path, b"fixture").map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;
        let file = std::fs::File::open(&path).map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;
        // SAFETY: file remains open and unchanged for the mapping lifetime.
        let mapping = unsafe { memmap2::MmapOptions::new().map_copy(&file) }.map_err(|source| {
            crate::Error::Io {
                path: path.clone(),
                source,
                location: snafu::location!(),
            }
        })?;

        std::fs::remove_file(&path).map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;
        let descriptor_len = file.metadata().map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;

        assert!(!path.exists());
        assert_eq!(descriptor_len.len(), 7);
        assert_eq!(&mapping[..], b"fixture");
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
    #[allow(unsafe_code)]
    fn process_control_target_is_live_until_its_owner_releases_it() -> crate::Result<()> {
        let target = ProcessControlTarget::spawn().map_err(|source| crate::Error::Io {
            path: "process-control target fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        // Signal zero does not change the child. It only proves that the PID is live.
        // SAFETY: target.pid is owned by target until it is dropped below.
        assert_eq!(unsafe { libc::kill(target.pid, 0) }, 0);
        drop(target);
        Ok(())
    }

    #[test]
    fn abstract_unix_stream_control_does_not_create_a_file() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "Unix-stream control fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let signal_path = directory.path().join("signal");
        let signal = SharedMailbox::create(&signal_path)?;
        let mut target =
            UnixStreamTarget::spawn_with_files(signal, signal_path, -1, -1).map_err(|source| {
                crate::Error::Io {
                    path: "Unix-stream control fixture".into(),
                    source,
                    location: snafu::location!(),
                }
            })?;

        let outcome = target.roundtrip();
        if outcome.errno == Some(rustix::io::Errno::PERM.raw_os_error()) {
            eprintln!("skipping abstract Unix-stream control because the host sandbox blocks bind");
            return Ok(());
        }
        assert!(outcome.allowed, "{outcome:?}");
        let _stale_outcome = target.stale_send();
        target.restart().map_err(|source| crate::Error::Io {
            path: "restarted Unix-stream control fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        assert!(target.roundtrip().allowed);
        Ok(())
    }

    #[test]
    fn queued_descriptor_controls_arrive_in_declared_order() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "SCM_RIGHTS order fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let first_path = directory.path().join("first");
        let second_path = directory.path().join("second");
        std::fs::write(&first_path, b"1").map_err(|source| crate::Error::Io {
            path: first_path.clone(),
            source,
            location: snafu::location!(),
        })?;
        std::fs::write(&second_path, b"2").map_err(|source| crate::Error::Io {
            path: second_path.clone(),
            source,
            location: snafu::location!(),
        })?;
        let first = std::fs::File::open(&first_path).map_err(|source| crate::Error::Io {
            path: first_path,
            source,
            location: snafu::location!(),
        })?;
        let second = std::fs::File::open(&second_path).map_err(|source| crate::Error::Io {
            path: second_path,
            source,
            location: snafu::location!(),
        })?;
        let signal_path = directory.path().join("signal");
        let signal = SharedMailbox::create(&signal_path)?;
        let mut target = UnixStreamTarget::spawn_with_files(
            signal,
            signal_path,
            first.as_raw_fd(),
            second.as_raw_fd(),
        )
        .map_err(|source| crate::Error::Io {
            path: "SCM_RIGHTS order fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let outcome = target.roundtrip();
        if outcome.errno == Some(rustix::io::Errno::PERM.raw_os_error()) {
            eprintln!("skipping SCM_RIGHTS order control because the host sandbox blocks bind");
            return Ok(());
        }
        assert!(outcome.allowed, "{outcome:?}");
        let stream_fd = target
            .connected_stream
            .as_ref()
            .ok_or_else(|| invalid_state("SCM_RIGHTS control stream did not connect"))?
            .as_raw_fd();
        let mut first_received = fixture_syscalls::receive_file_descriptor(stream_fd)
            .map_err(|source| crate::Error::Io {
                path: "first SCM_RIGHTS order fixture".into(),
                source,
                location: snafu::location!(),
            })?
            .file
            .ok_or_else(|| invalid_state("first SCM_RIGHTS control descriptor is absent"))?;
        let mut second_received = fixture_syscalls::receive_file_descriptor(stream_fd)
            .map_err(|source| crate::Error::Io {
                path: "second SCM_RIGHTS order fixture".into(),
                source,
                location: snafu::location!(),
            })?
            .file
            .ok_or_else(|| invalid_state("second SCM_RIGHTS control descriptor is absent"))?;
        target
            .connected_stream
            .as_mut()
            .ok_or_else(|| invalid_state("SCM_RIGHTS control stream disconnected"))?
            .write_all(&[3])
            .map_err(|source| crate::Error::Io {
                path: "SCM_RIGHTS completion fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        target.wait().map_err(|source| crate::Error::Io {
            path: "SCM_RIGHTS server fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let mut first_byte = [0_u8];
        let mut second_byte = [0_u8];
        first_received
            .read_exact(&mut first_byte)
            .map_err(|source| crate::Error::Io {
                path: "first SCM_RIGHTS order fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        second_received
            .read_exact(&mut second_byte)
            .map_err(|source| crate::Error::Io {
                path: "second SCM_RIGHTS order fixture".into(),
                source,
                location: snafu::location!(),
            })?;
        assert_eq!(first_byte, [b'1']);
        assert_eq!(second_byte, [b'2']);
        Ok(())
    }

    #[test]
    fn native_exec_and_descriptor_transfer_controls_work_without_policy() -> crate::Result<()> {
        let mut received =
            fixture_syscalls::receive_file_from_actor(std::path::Path::new("/bin/busybox"))
                .map_err(|source| crate::Error::Io {
                    path: "SCM_RIGHTS control fixture".into(),
                    source,
                    location: snafu::location!(),
                })?;
        assert!(read_outcome(&mut received).allowed);
        fixture_syscalls::exec_fd(received.as_raw_fd(), false).map_err(|source| {
            crate::Error::Io {
                path: "fexecve control fixture".into(),
                source,
                location: snafu::location!(),
            }
        })?;
        Ok(())
    }

    #[test]
    fn anonymous_mapping_controls_work_without_policy() -> crate::Result<()> {
        fixture_syscalls::map_anonymous(libc::PROT_READ).map_err(|source| crate::Error::Io {
            path: "anonymous mmap control fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        fixture_syscalls::pkey_mprotect_anonymous(libc::PROT_READ).map_err(|source| {
            crate::Error::Io {
                path: "pkey_mprotect control fixture".into(),
                source,
                location: snafu::location!(),
            }
        })?;
        Ok(())
    }
}
