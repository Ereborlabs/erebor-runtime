use std::fs;
use std::io::{self, Read as _, Seek as _, Write as _};
use std::mem::size_of;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{symlink, FileExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixListener, UnixStream};
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
const SHARED_MMAP_PROTECTED_REQUEST: u32 = 10;
const SHARED_MMAP_BENIGN_REQUEST: u32 = 11;
const SHARED_MMAP_EXIT_REQUEST: u32 = 12;
const SHARED_MMAP_ALLOWED: u32 = 20;
const SHARED_MMAP_FAILURE_BASE: u32 = 1 << 16;
const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const QUALIFIED_TIOCGPTN_IOCTL: libc::c_ulong = 2_147_767_344;
const QUALIFIED_TIOCGPTPEER_IOCTL: libc::c_ulong = 0x5441;
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
    PreparePropagationPeer {
        shared_mount: PathBuf,
        benign: PathBuf,
        propagated_marker: PathBuf,
    },
    PropagationPeerOpen,
    PropagationPeerHasMarker,
    Connect,
    NetworkConnect {
        address: SocketAddr,
    },
    NetworkSend {
        payload: Vec<u8>,
    },
    NetworkSendMsg {
        payload: Vec<u8>,
    },
    NetworkSendFile {
        path: PathBuf,
    },
    NetworkSplice {
        path: PathBuf,
    },
    NetworkReceive,
    NetworkSetNoDelay,
    NetworkShutdown,
    NetworkClose,
    NetworkEnterNamespace,
    NetworkListen {
        address: SocketAddr,
    },
    NetworkAccept,
    NetworkPreparePassReceiver {
        path: PathBuf,
    },
    NetworkPass {
        path: PathBuf,
    },
    NetworkReceivePassed,
    NetworkAllowPtracer {
        pid: u32,
    },
    NetworkDescriptor,
    NetworkDuplicateSocket {
        pid: u32,
        descriptor: i32,
    },
    NetworkClone,
    NetworkCloneSend {
        payload: Vec<u8>,
    },
    NetworkForkSend {
        payload: Vec<u8>,
    },
    NetworkUdpSend {
        address: SocketAddr,
        payload: Vec<u8>,
        connected: bool,
    },
    NetworkSocket {
        family: i32,
        socket_type: i32,
        protocol: i32,
    },
    NetworkSetMark {
        value: u32,
    },
    NetworkIoUringSqpoll,
    NetworkTunTap,
    NetworkBpfSetup,
    NetworkPrepareProxy {
        path: PathBuf,
    },
    NetworkProxyRequest {
        path: PathBuf,
        request_id: String,
        address: SocketAddr,
    },
    NetworkProxyOnce,
    NetworkReadResults {
        path: PathBuf,
    },
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
    SharedMmapTargetPid,
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
    IndependentSecretMmapWrite,
    SecretMmapExec,
    SecretMprotectReadExec,
    SecretMprotectWriteExec,
    DeletedMprotectExec,
    MemfdMprotectExec,
    BenignMmapRead,
    IndependentBenignMmapRead,
    PassedSecretRead,
    PassedBenignRead,
    IoUringSecretRead,
    IoUringBenignRead,
    IoUringSqpoll,
    ProcFdOpen,
    DetachedMountOpen,
    MoveMount,
    MountSetattr,
    MountPropagation,
    Ioctl,
    IoctlDerivedPeer,
    IoctlUnsupported,
    Ipc,
    UnixStream,
    InheritedUnixStreamSend,
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
    Bool(bool),
    DescriptorTransfer(DescriptorTransferOutcome),
    Descriptor { descriptor: i32 },
    NetworkListen(NetworkListenOutcome),
    Proxy(NetworkProxyOutcome),
    NetworkReadResults(NetworkReadResultsOutcome),
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
    pub(super) second_bind_alias: PathBuf,
    pub(super) benign: PathBuf,
    pub(super) exec_target: PathBuf,
    pub(super) allowed_exec_target: PathBuf,
    pub(super) script_target: PathBuf,
    pub(super) deleted_exec_target: PathBuf,
    pub(super) mount_target: PathBuf,
    pub(super) move_mount_target: PathBuf,
    pub(super) propagation_source: PathBuf,
    pub(super) propagation_target: PathBuf,
    pub(super) propagation_marker: PathBuf,
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

    pub(super) fn failed(self) -> bool {
        !self.allowed && self.errno.is_some()
    }
}

impl TryFrom<ChildResponse> for IoOutcome {
    type Error = crate::Error;

    fn try_from(response: ChildResponse) -> Result<Self> {
        match response {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong I/O response",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct DescriptorTransferOutcome {
    pub(super) payload_received: bool,
    pub(super) control_truncated: bool,
    pub(super) installed_descriptors: u32,
    pub(super) read_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct NetworkProxyOutcome {
    pub(super) request_id: String,
    pub(super) connect: IoOutcome,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct NetworkListenOutcome {
    pub(super) address: Option<SocketAddr>,
    pub(super) outcome: IoOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct NetworkReadResultsOutcome {
    pub(super) zero_byte: bool,
    pub(super) end_of_file: bool,
    pub(super) io_error: bool,
    pub(super) partial_positive: bool,
    pub(super) mapped: bool,
    pub(super) inherited_descriptor: bool,
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

    pub(super) fn prepare_propagation_peer(&mut self, paths: &EffectPaths) -> Result<u32> {
        match self.request(&ChildRequest::PreparePropagationPeer {
            shared_mount: paths.source.clone(),
            benign: paths.benign.clone(),
            propagated_marker: paths.propagation_marker.clone(),
        })? {
            ChildResponse::PreparedProcess { pid } => Ok(pid),
            _ => Err(invalid_state(
                "effect child returned the wrong propagation-peer response",
            )),
        }
    }

    pub(super) fn propagation_peer_open(&mut self) -> Result<IoOutcome> {
        match self.request(&ChildRequest::PropagationPeerOpen)? {
            ChildResponse::Outcome(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong propagation-peer open response",
            )),
        }
    }

    pub(super) fn propagation_peer_has_marker(&mut self) -> Result<bool> {
        match self.request(&ChildRequest::PropagationPeerHasMarker)? {
            ChildResponse::Bool(value) => Ok(value),
            _ => Err(invalid_state(
                "effect child returned the wrong propagation-peer marker response",
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

    pub(super) fn network_connect(&mut self, address: SocketAddr) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkConnect { address })?
            .try_into()
    }

    pub(super) fn network_send(&mut self, payload: &[u8]) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSend {
            payload: payload.to_vec(),
        })?
        .try_into()
    }

    pub(super) fn network_sendmsg(&mut self, payload: &[u8]) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSendMsg {
            payload: payload.to_vec(),
        })?
        .try_into()
    }

    pub(super) fn network_sendfile(&mut self, path: &Path) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSendFile {
            path: path.to_path_buf(),
        })?
        .try_into()
    }

    pub(super) fn network_splice(&mut self, path: &Path) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSplice {
            path: path.to_path_buf(),
        })?
        .try_into()
    }

    pub(super) fn network_receive(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkReceive)?.try_into()
    }

    pub(super) fn network_set_nodelay(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSetNoDelay)?.try_into()
    }

    pub(super) fn network_shutdown(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkShutdown)?.try_into()
    }

    pub(super) fn network_close(&mut self) -> Result<()> {
        match self.request(&ChildRequest::NetworkClose)? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong network-close response",
            )),
        }
    }

    pub(super) fn network_enter_namespace(&mut self) -> Result<()> {
        match self.request(&ChildRequest::NetworkEnterNamespace)? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong network-namespace response",
            )),
        }
    }

    pub(super) fn network_listen(&mut self, address: SocketAddr) -> Result<NetworkListenOutcome> {
        match self.request(&ChildRequest::NetworkListen { address })? {
            ChildResponse::NetworkListen(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong network-listen response",
            )),
        }
    }

    pub(super) fn network_accept(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkAccept)?.try_into()
    }

    pub(super) fn network_prepare_pass_receiver(&mut self, path: &Path) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkPreparePassReceiver {
            path: path.to_path_buf(),
        })?
        .try_into()
    }

    pub(super) fn network_pass(&mut self, path: &Path) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkPass {
            path: path.to_path_buf(),
        })?
        .try_into()
    }

    pub(super) fn network_receive_passed(&mut self) -> Result<DescriptorTransferOutcome> {
        match self.request(&ChildRequest::NetworkReceivePassed)? {
            ChildResponse::DescriptorTransfer(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong passed-socket response",
            )),
        }
    }

    pub(super) fn network_allow_ptracer(&mut self, pid: u32) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkAllowPtracer { pid })?
            .try_into()
    }

    pub(super) fn network_descriptor(&mut self) -> Result<i32> {
        match self.request(&ChildRequest::NetworkDescriptor)? {
            ChildResponse::Descriptor { descriptor } => Ok(descriptor),
            _ => Err(invalid_state("effect child returned no network descriptor")),
        }
    }

    pub(super) fn network_duplicate_socket(
        &mut self,
        pid: u32,
        descriptor: i32,
    ) -> Result<DescriptorTransferOutcome> {
        match self.request(&ChildRequest::NetworkDuplicateSocket { pid, descriptor })? {
            ChildResponse::DescriptorTransfer(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong pidfd socket response",
            )),
        }
    }

    pub(super) fn network_clone(&mut self) -> Result<()> {
        match self.request(&ChildRequest::NetworkClone)? {
            ChildResponse::Prepared => Ok(()),
            _ => Err(invalid_state(
                "effect child returned the wrong socket-clone response",
            )),
        }
    }

    pub(super) fn network_clone_send(&mut self, payload: &[u8]) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkCloneSend {
            payload: payload.to_vec(),
        })?
        .try_into()
    }

    pub(super) fn network_fork_send(&mut self, payload: &[u8]) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkForkSend {
            payload: payload.to_vec(),
        })?
        .try_into()
    }

    pub(super) fn network_udp_send(
        &mut self,
        address: SocketAddr,
        payload: &[u8],
        connected: bool,
    ) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkUdpSend {
            address,
            payload: payload.to_vec(),
            connected,
        })?
        .try_into()
    }

    pub(super) fn network_socket(
        &mut self,
        family: i32,
        socket_type: i32,
        protocol: i32,
    ) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSocket {
            family,
            socket_type,
            protocol,
        })?
        .try_into()
    }

    pub(super) fn network_set_mark(&mut self, value: u32) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkSetMark { value })?
            .try_into()
    }

    pub(super) fn network_io_uring_sqpoll(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkIoUringSqpoll)?
            .try_into()
    }

    pub(super) fn network_tun_tap(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkTunTap)?.try_into()
    }

    pub(super) fn network_bpf_setup(&mut self) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkBpfSetup)?.try_into()
    }

    pub(super) fn network_prepare_proxy(&mut self, path: &Path) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkPrepareProxy {
            path: path.to_path_buf(),
        })?
        .try_into()
    }

    pub(super) fn network_proxy_request(
        &mut self,
        path: &Path,
        request_id: &str,
        address: SocketAddr,
    ) -> Result<IoOutcome> {
        self.request(&ChildRequest::NetworkProxyRequest {
            path: path.to_path_buf(),
            request_id: request_id.to_owned(),
            address,
        })?
        .try_into()
    }

    pub(super) fn network_proxy_once(&mut self) -> Result<NetworkProxyOutcome> {
        match self.request(&ChildRequest::NetworkProxyOnce)? {
            ChildResponse::Proxy(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong delegated-connect response",
            )),
        }
    }

    pub(super) fn network_read_results(
        &mut self,
        path: &Path,
    ) -> Result<NetworkReadResultsOutcome> {
        match self.request(&ChildRequest::NetworkReadResults {
            path: path.to_path_buf(),
        })? {
            ChildResponse::NetworkReadResults(outcome) => Ok(outcome),
            _ => Err(invalid_state(
                "effect child returned the wrong read-result response",
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

    pub(super) fn shared_mmap_target_pid(&mut self) -> Result<u32> {
        match self.request(&ChildRequest::SharedMmapTargetPid)? {
            ChildResponse::PreparedProcess { pid } => Ok(pid),
            _ => Err(invalid_state(
                "effect child returned the wrong shared-mmap target response",
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
    let mut prepared_network_clone = None;
    let mut prepared_network_listener = None;
    let mut prepared_network_pass_listener = None;
    let mut prepared_network_pass_path = None;
    let mut prepared_network_proxy_listener = None;
    let mut prepared_network_proxy_path = None;
    let mut prepared_network_stream = None;
    let mut propagation_peer = None;
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
            ChildRequest::PreparePropagationPeer {
                shared_mount,
                benign,
                propagated_marker,
            } => match PreparedPropagationPeer::new(&shared_mount, benign, propagated_marker) {
                Ok(peer) => {
                    let pid = peer.pid();
                    propagation_peer = Some(peer);
                    (Ok(ChildResponse::PreparedProcess { pid }), false)
                }
                Err(error) => (Err(error), false),
            },
            ChildRequest::PropagationPeerOpen => match propagation_peer.as_mut() {
                Some(peer) => (peer.open().map(ChildResponse::Outcome), false),
                None => (
                    Err(invalid_state("propagation peer is not prepared")),
                    false,
                ),
            },
            ChildRequest::PropagationPeerHasMarker => match propagation_peer.as_mut() {
                Some(peer) => (peer.has_marker().map(ChildResponse::Bool), false),
                None => (
                    Err(invalid_state("propagation peer is not prepared")),
                    false,
                ),
            },
            ChildRequest::Connect => (Ok(ChildResponse::Outcome(connect_outcome())), false),
            ChildRequest::NetworkConnect { address } => match network_connect(address) {
                Ok(stream) => {
                    prepared_network_stream = Some(stream);
                    (Ok(ChildResponse::Outcome(allowed_outcome())), false)
                }
                Err(error) => (Ok(ChildResponse::Outcome(error_outcome(error))), false),
            },
            ChildRequest::NetworkSend { payload } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_mut()
                        .map_or_else(missing_prepared_network, |stream| {
                            io_outcome(stream.write_all(&payload))
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkSendMsg { payload } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            network_sendmsg(stream.as_raw_fd(), &payload)
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkSendFile { path } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            network_sendfile(stream.as_raw_fd(), &path)
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkSplice { path } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            network_splice(stream.as_raw_fd(), &path)
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkReceive => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream.as_mut().map_or_else(
                        missing_prepared_network,
                        |stream| {
                            let mut byte = [0_u8; 1];
                            io_outcome(stream.read_exact(&mut byte))
                        },
                    ),
                )),
                false,
            ),
            ChildRequest::NetworkSetNoDelay => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            io_outcome(stream.set_nodelay(true))
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkShutdown => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            io_outcome(stream.shutdown(Shutdown::Write))
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkClose => {
                prepared_network_clone = None;
                prepared_network_stream = None;
                (Ok(ChildResponse::Prepared), false)
            }
            ChildRequest::NetworkEnterNamespace => (
                enter_private_network_namespace().map(|()| ChildResponse::Prepared),
                false,
            ),
            ChildRequest::NetworkListen { address } => (
                Ok(match network_listener(address) {
                    Ok(listener) => match listener.local_addr() {
                        Ok(address) => {
                            prepared_network_listener = Some(listener);
                            ChildResponse::NetworkListen(NetworkListenOutcome {
                                address: Some(address),
                                outcome: allowed_outcome(),
                            })
                        }
                        Err(error) => ChildResponse::NetworkListen(NetworkListenOutcome {
                            address: None,
                            outcome: error_outcome(error),
                        }),
                    },
                    Err(error) => ChildResponse::NetworkListen(NetworkListenOutcome {
                        address: None,
                        outcome: error_outcome(error),
                    }),
                }),
                false,
            ),
            ChildRequest::NetworkAccept => (
                prepared_network_listener.as_ref().map_or_else(
                    || Err(invalid_state("network listener is not prepared")),
                    |listener| match listener.accept() {
                        Ok((stream, _)) => {
                            prepared_network_stream = Some(stream);
                            Ok(ChildResponse::Outcome(allowed_outcome()))
                        }
                        Err(error) => Ok(ChildResponse::Outcome(error_outcome(error))),
                    },
                ),
                false,
            ),
            ChildRequest::NetworkPreparePassReceiver { path } => (
                Ok(ChildResponse::Outcome(
                    match network_unix_address(&path)
                        .and_then(|address| UnixListener::bind_addr(&address))
                    {
                        Ok(listener) => {
                            prepared_network_pass_listener = Some(listener);
                            prepared_network_pass_path = Some(path);
                            allowed_outcome()
                        }
                        Err(error) => error_outcome(error),
                    },
                )),
                false,
            ),
            ChildRequest::NetworkPass { path } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream.as_ref().map_or_else(
                        missing_prepared_network,
                        |stream| match network_unix_address(&path)
                            .and_then(|address| UnixStream::connect_addr(&address))
                        {
                            Ok(transport) => io_outcome(fixture_syscalls::send_fd(
                                transport.as_raw_fd(),
                                stream.as_raw_fd(),
                            )),
                            Err(error) => error_outcome(error),
                        },
                    ),
                )),
                false,
            ),
            ChildRequest::NetworkReceivePassed => (
                prepared_network_pass_listener.as_ref().map_or_else(
                    || Err(invalid_state("socket-pass receiver is not prepared")),
                    |listener| {
                        let (transport, _) = listener.accept().context(IoSnafu {
                            path: Path::new("socket-pass receiver"),
                        })?;
                        let received =
                            fixture_syscalls::receive_file_descriptor(transport.as_raw_fd())
                                .context(IoSnafu {
                                    path: Path::new("socket-pass receiver"),
                                })?;
                        let installed_descriptors = u32::from(received.file.is_some());
                        if let Some(file) = received.file {
                            let fd: OwnedFd = file.into();
                            prepared_network_stream = Some(TcpStream::from(fd));
                        }
                        Ok(ChildResponse::DescriptorTransfer(
                            DescriptorTransferOutcome {
                                payload_received: received.payload_received,
                                control_truncated: received.control_truncated,
                                installed_descriptors,
                                read_allowed: installed_descriptors == 1,
                            },
                        ))
                    },
                ),
                false,
            ),
            ChildRequest::NetworkAllowPtracer { pid } => (
                Ok(ChildResponse::Outcome(network_allow_ptracer(pid))),
                false,
            ),
            ChildRequest::NetworkDescriptor => (
                prepared_network_stream.as_ref().map_or_else(
                    || Err(invalid_state("network socket is not prepared")),
                    |stream| {
                        Ok(ChildResponse::Descriptor {
                            descriptor: stream.as_raw_fd(),
                        })
                    },
                ),
                false,
            ),
            ChildRequest::NetworkDuplicateSocket { pid, descriptor } => (
                Ok(ChildResponse::DescriptorTransfer(
                    match duplicate_process_descriptor(pid, descriptor) {
                        Ok(descriptor) => {
                            prepared_network_stream = Some(TcpStream::from(descriptor));
                            DescriptorTransferOutcome {
                                payload_received: true,
                                control_truncated: false,
                                installed_descriptors: 1,
                                read_allowed: true,
                            }
                        }
                        Err(_) => DescriptorTransferOutcome {
                            payload_received: false,
                            control_truncated: false,
                            installed_descriptors: 0,
                            read_allowed: false,
                        },
                    },
                )),
                false,
            ),
            ChildRequest::NetworkClone => (
                prepared_network_stream.as_ref().map_or_else(
                    || Err(invalid_state("network stream is not prepared")),
                    |stream| {
                        prepared_network_clone = Some(stream.try_clone().context(IoSnafu {
                            path: Path::new("network socket clone"),
                        })?);
                        Ok(ChildResponse::Prepared)
                    },
                ),
                false,
            ),
            ChildRequest::NetworkCloneSend { payload } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_clone
                        .as_mut()
                        .map_or_else(missing_prepared_network, |stream| {
                            io_outcome(stream.write_all(&payload))
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkForkSend { payload } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            forked_network_send(stream.as_raw_fd(), &payload)
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkUdpSend {
                address,
                payload,
                connected,
            } => (
                Ok(ChildResponse::Outcome(network_udp_send(
                    address, &payload, connected,
                ))),
                false,
            ),
            ChildRequest::NetworkSocket {
                family,
                socket_type,
                protocol,
            } => (
                Ok(ChildResponse::Outcome(network_socket_outcome(
                    family,
                    socket_type,
                    protocol,
                ))),
                false,
            ),
            ChildRequest::NetworkSetMark { value } => (
                Ok(ChildResponse::Outcome(
                    prepared_network_stream
                        .as_ref()
                        .map_or_else(missing_prepared_network, |stream| {
                            network_set_mark(stream.as_raw_fd(), value)
                        }),
                )),
                false,
            ),
            ChildRequest::NetworkIoUringSqpoll => (
                Ok(ChildResponse::Outcome(io_outcome(
                    fixture_syscalls::io_uring_sqpoll_setup(),
                ))),
                false,
            ),
            ChildRequest::NetworkTunTap => (Ok(ChildResponse::Outcome(network_tun_tap())), false),
            ChildRequest::NetworkBpfSetup => {
                (Ok(ChildResponse::Outcome(bpf_map_create_outcome())), false)
            }
            ChildRequest::NetworkPrepareProxy { path } => (
                Ok(ChildResponse::Outcome(
                    match network_unix_address(&path)
                        .and_then(|address| UnixListener::bind_addr(&address))
                    {
                        Ok(listener) => {
                            prepared_network_proxy_listener = Some(listener);
                            prepared_network_proxy_path = Some(path);
                            allowed_outcome()
                        }
                        Err(error) => error_outcome(error),
                    },
                )),
                false,
            ),
            ChildRequest::NetworkProxyRequest {
                path,
                request_id,
                address,
            } => (
                Ok(ChildResponse::Outcome(network_proxy_request(
                    &path,
                    &request_id,
                    address,
                ))),
                false,
            ),
            ChildRequest::NetworkProxyOnce => (
                prepared_network_proxy_listener.as_ref().map_or_else(
                    || Err(invalid_state("network proxy is not prepared")),
                    |listener| {
                        let (mut request, _) = listener.accept().context(IoSnafu {
                            path: Path::new("network proxy"),
                        })?;
                        let mut bytes = Vec::new();
                        std::io::Read::by_ref(&mut request)
                            .take(513)
                            .read_to_end(&mut bytes)
                            .context(IoSnafu {
                                path: Path::new("network proxy request"),
                            })?;
                        ensure!(
                            bytes.len() <= 512,
                            InvalidInputSnafu {
                                path: Path::new("network proxy request"),
                                reason: "delegated request exceeds 512 bytes",
                            }
                        );
                        let request = std::str::from_utf8(&bytes).map_err(|error| {
                            invalid_state(format!("delegated request is not UTF-8: {error}"))
                        })?;
                        let mut fields = request.lines();
                        let request_id = fields.next().unwrap_or_default();
                        let address = fields.next().unwrap_or_default();
                        ensure!(
                            !request_id.is_empty()
                                && request_id
                                    .chars()
                                    .all(|value| value.is_ascii_alphanumeric() || value == '-'),
                            InvalidInputSnafu {
                                path: Path::new("network proxy request"),
                                reason: "delegated request ID is invalid",
                            }
                        );
                        ensure!(
                            fields.next().is_none(),
                            InvalidInputSnafu {
                                path: Path::new("network proxy request"),
                                reason: "delegated request has extra fields",
                            }
                        );
                        let address = address.parse::<SocketAddr>().map_err(|error| {
                            invalid_state(format!("delegated network address is invalid: {error}"))
                        })?;
                        let connect = match network_connect(address) {
                            Ok(stream) => {
                                prepared_network_stream = Some(stream);
                                allowed_outcome()
                            }
                            Err(error) => error_outcome(error),
                        };
                        Ok(ChildResponse::Proxy(NetworkProxyOutcome {
                            request_id: request_id.to_owned(),
                            connect,
                        }))
                    },
                ),
                false,
            ),
            ChildRequest::NetworkReadResults { path } => (
                network_read_results(&path).map(ChildResponse::NetworkReadResults),
                false,
            ),
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
            ChildRequest::SharedMmapTargetPid => match prepared_hard_closed.as_ref() {
                Some(prepared) => (
                    Ok(ChildResponse::PreparedProcess {
                        pid: prepared.shared_mmap_target.pid(),
                    }),
                    false,
                ),
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
                propagation_peer.take();
                if let Some(path) = prepared_network_pass_path.take() {
                    let _result = fs::remove_file(path);
                }
                if let Some(path) = prepared_network_proxy_path.take() {
                    let _result = fs::remove_file(path);
                }
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

pub fn run_mount_setattr_child(namespace: &Path, path: &Path, read_only: bool) -> Result<()> {
    let namespace = fs::File::open(namespace).context(IoSnafu { path: namespace })?;
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Mount),
    )
    .map_err(io::Error::from)
    .context(IoSnafu {
        path: Path::new("mount namespace"),
    })?;
    if read_only {
        fixture_syscalls::set_mount_read_only(path)
    } else {
        fixture_syscalls::set_mount_read_write(path)
    }
    .context(IoSnafu { path })
}

pub fn run_mount_reconfigure_child(namespace: &Path, path: &Path) -> Result<()> {
    let namespace = fs::File::open(namespace).context(IoSnafu { path: namespace })?;
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Mount),
    )
    .map_err(io::Error::from)
    .context(IoSnafu {
        path: Path::new("mount namespace"),
    })?;
    fixture_syscalls::reconfigure_mount(path).context(IoSnafu { path })
}

pub fn run_mount_move_child(source: &Path, target: &Path) -> Result<()> {
    let tree = fixture_syscalls::open_mount_tree(source).context(IoSnafu { path: source })?;
    fixture_syscalls::move_mount(tree.as_raw_fd(), target).context(IoSnafu { path: target })
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

#[allow(deprecated)]
fn enter_private_network_namespace() -> Result<()> {
    rustix::thread::unshare(rustix::thread::UnshareFlags::NEWNET)
        .map_err(io::Error::from)
        .context(IoSnafu {
            path: Path::new("network namespace"),
        })
}

fn setup_paths(root: &Path) -> Result<EffectPaths> {
    let source = root.join("source");
    let secret = source.join("secret");
    let hard_link = root.join("hard-link");
    let symlink_alias = root.join("symlink-alias");
    let bind_directory = root.join("bind-alias");
    let bind_alias = bind_directory.join("secret");
    let second_bind_directory = root.join("second-bind-alias");
    let second_bind_alias = second_bind_directory.join("secret");
    let benign = root.join("benign");
    let exec_target = root.join("exec-target");
    let allowed_exec_target = root.join("allowed-exec-target");
    let script_target = root.join("script-target");
    let deleted_exec_target = root.join("deleted-exec-target");
    let mount_target = root.join("mount-target");
    let move_mount_target = root.join("move-mount-target");
    let propagation_source = root.join("propagation-source");
    let propagation_target = source.join("propagation-target");
    let propagation_marker = propagation_target.join("propagated-marker");
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
    fs::create_dir(&second_bind_directory).context(IoSnafu {
        path: &second_bind_directory,
    })?;
    fs::create_dir(&mount_target).context(IoSnafu {
        path: &mount_target,
    })?;
    fs::create_dir(&move_mount_target).context(IoSnafu {
        path: &move_mount_target,
    })?;
    fs::create_dir(&propagation_source).context(IoSnafu {
        path: &propagation_source,
    })?;
    fs::write(
        propagation_source.join("propagated-marker"),
        b"propagated\n",
    )
    .context(IoSnafu {
        path: propagation_source.join("propagated-marker"),
    })?;
    fs::create_dir(&propagation_target).context(IoSnafu {
        path: &propagation_target,
    })?;
    rustix::mount::mount_bind(&source, &source)
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: &source })?;
    rustix::mount::mount_bind(&source, &bind_directory)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &bind_directory,
        })?;
    rustix::mount::mount_bind(&source, &second_bind_directory)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &second_bind_directory,
        })?;
    rustix::mount::mount_bind(&mount_target, &mount_target)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &mount_target,
        })?;
    Ok(EffectPaths {
        source,
        secret,
        hard_link,
        symlink_alias,
        bind_alias,
        second_bind_alias,
        benign,
        exec_target,
        allowed_exec_target,
        script_target,
        deleted_exec_target,
        mount_target,
        move_mount_target,
        propagation_source,
        propagation_target,
        propagation_marker,
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

fn missing_prepared_network() -> IoOutcome {
    IoOutcome {
        allowed: false,
        errno: Some(rustix::io::Errno::NOTCONN.raw_os_error()),
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

struct PreparedPropagationPeer {
    process: libc::pid_t,
    control: SharedMailbox,
}

impl PreparedPropagationPeer {
    fn new(shared_mount: &Path, benign: PathBuf, propagated_marker: PathBuf) -> Result<Self> {
        rustix::mount::mount_change(shared_mount, rustix::mount::MountPropagationFlags::SHARED)
            .map_err(io::Error::from)
            .context(IoSnafu { path: shared_mount })?;
        let control_path = benign
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join(".mithril-propagation-mailbox");
        let control = SharedMailbox::create(&control_path)?;
        let process = match fixture_syscalls::fork_process().context(IoSnafu {
            path: Path::new("propagation peer fork"),
        })? {
            fixture_syscalls::ForkResult::Parent(process) => process,
            fixture_syscalls::ForkResult::Child => {
                let code =
                    propagation_peer_loop(control, &benign, &propagated_marker).map_or(1, |()| 0);
                fixture_syscalls::exit_process(code)
            }
        };
        let mut peer = Self { process, control };
        let ready = peer.exchange(b'r')?;
        ensure!(
            ready == 0,
            InvalidInputSnafu {
                path: Path::new("propagation peer"),
                reason: "propagation peer did not enter its copied mount namespace",
            }
        );
        Ok(peer)
    }

    fn pid(&self) -> u32 {
        self.process as u32
    }

    fn open(&mut self) -> Result<IoOutcome> {
        let errno = self.exchange(b'o')?;
        Ok(IoOutcome {
            allowed: errno == 0,
            errno: (errno != 0).then_some(errno),
        })
    }

    fn has_marker(&mut self) -> Result<bool> {
        Ok(self.exchange(b'm')? == 0)
    }

    fn exchange(&mut self, command: u8) -> Result<i32> {
        ensure!(
            self.control.state() == EMPTY,
            InvalidInputSnafu {
                path: Path::new("propagation peer mailbox"),
                reason: "propagation peer mailbox is not ready",
            }
        );
        self.control.publish(REQUEST, &command)?;
        let start = Instant::now();
        while self.control.state() != RESPONSE {
            ensure!(
                start.elapsed() < CHILD_WAIT_LIMIT,
                InvalidInputSnafu {
                    path: Path::new("propagation peer mailbox"),
                    reason: "timed out waiting for the propagation peer",
                }
            );
            thread::sleep(Duration::from_millis(1));
        }
        let response = self.control.read()?;
        self.control.reset();
        Ok(response)
    }
}

impl Drop for PreparedPropagationPeer {
    fn drop(&mut self) {
        let _result = self.exchange(b'x');
        let _result = fixture_syscalls::wait_process(self.process);
    }
}

fn propagation_peer_loop(
    mut control: SharedMailbox,
    benign: &Path,
    propagated_marker: &Path,
) -> io::Result<()> {
    #[allow(deprecated)]
    rustix::thread::unshare(rustix::thread::UnshareFlags::NEWNS).map_err(io::Error::from)?;
    loop {
        while control.state() != REQUEST {
            thread::sleep(Duration::from_millis(1));
        }
        let command = control
            .read::<u8>()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let errno = match command {
            b'r' => 0,
            b'o' => open_outcome(benign).errno.unwrap_or_default(),
            b'm' => fs::metadata(propagated_marker)
                .err()
                .and_then(|error| error.raw_os_error())
                .unwrap_or_default(),
            b'x' => 0,
            _ => libc::EINVAL,
        };
        control
            .publish(RESPONSE, &errno)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if command == b'x' {
            return Ok(());
        }
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
    shared_mmap_target: SharedMmapTarget,
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
        unlock_ptmx(&ioctl_file).context(IoSnafu {
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
        let shared_mmap_signal_path = secret_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join(".mithril-shared-mmap-state");
        let shared_mmap_signal = SharedMailbox::create(&shared_mmap_signal_path)?;
        let shared_mmap_target = SharedMmapTarget::spawn(
            shared_mmap_signal,
            shared_mmap_signal_path,
            secret_file.as_raw_fd(),
            benign_file.as_raw_fd(),
        )
        .context(IoSnafu {
            path: Path::new("shared-mmap target"),
        })?;

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
            shared_mmap_target,
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
            PreparedOperation::IndependentSecretMmapWrite => {
                self.shared_mmap_target.mmap_protected()
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
            PreparedOperation::IndependentBenignMmapRead => self.shared_mmap_target.mmap_benign(),
            PreparedOperation::PassedSecretRead => read_outcome(&mut self.passed_secret_file),
            PreparedOperation::PassedBenignRead => read_outcome(&mut self.passed_benign_file),
            PreparedOperation::IoUringSecretRead => io_outcome(
                fixture_syscalls::io_uring_read_one(self.secret_file.as_raw_fd(), b'r'),
            ),
            PreparedOperation::IoUringBenignRead => io_outcome(
                fixture_syscalls::io_uring_read_one(self.benign_file.as_raw_fd(), b'b'),
            ),
            PreparedOperation::IoUringSqpoll => {
                io_outcome(fixture_syscalls::io_uring_sqpoll_setup())
            }
            PreparedOperation::ProcFdOpen => open_outcome(&PathBuf::from(format!(
                "/proc/self/fd/{}",
                self.secret_file.as_raw_fd()
            ))),
            PreparedOperation::DetachedMountOpen => {
                io_outcome(fixture_syscalls::open_detached_mount_file(
                    self.mount_tree.as_raw_fd(),
                    Path::new("secret"),
                ))
            }
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
            PreparedOperation::IoctlDerivedPeer => ptmx_peer_outcome(&self.ioctl_file),
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
            PreparedOperation::InheritedUnixStreamSend => self
                .unix_stream_target
                .as_ref()
                .map_or_else(missing_process_target, UnixStreamTarget::forked_send),
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

struct SharedMmapTarget {
    pid: libc::pid_t,
    signal: SharedMailbox,
    signal_path: PathBuf,
}

#[allow(unsafe_code)]
impl SharedMmapTarget {
    fn spawn(
        signal: SharedMailbox,
        signal_path: PathBuf,
        protected_file: libc::c_int,
        benign_file: libc::c_int,
    ) -> io::Result<Self> {
        // SAFETY: the child uses inherited mappings and async-signal-safe calls.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            drop(signal);
            let _cleanup = fs::remove_file(&signal_path);
            return Err(error);
        }
        if pid == 0 {
            // SAFETY: the child owns the inherited signal mapping and file descriptors.
            unsafe { shared_mmap_target_child(&signal, protected_file, benign_file) };
        }
        Ok(Self {
            pid,
            signal,
            signal_path,
        })
    }

    fn pid(&self) -> u32 {
        self.pid as u32
    }

    fn mmap_protected(&mut self) -> IoOutcome {
        self.request(SHARED_MMAP_PROTECTED_REQUEST)
    }

    fn mmap_benign(&mut self) -> IoOutcome {
        self.request(SHARED_MMAP_BENIGN_REQUEST)
    }

    fn request(&mut self, request: u32) -> IoOutcome {
        self.signal.set_state(request);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let state = self.signal.state();
            if state == SHARED_MMAP_ALLOWED {
                self.signal.reset();
                return allowed_outcome();
            }
            if state >= SHARED_MMAP_FAILURE_BASE {
                self.signal.reset();
                return error_outcome(io::Error::from_raw_os_error(
                    (state - SHARED_MMAP_FAILURE_BASE) as i32,
                ));
            }
            if Instant::now() >= deadline {
                return error_outcome(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "shared-mmap target did not respond",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[allow(unsafe_code)]
impl Drop for SharedMmapTarget {
    fn drop(&mut self) {
        self.signal.set_state(SHARED_MMAP_EXIT_REQUEST);
        let mut status = 0;
        // SAFETY: pid is this process's live fork child and status is writable.
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        let _cleanup = fs::remove_file(&self.signal_path);
    }
}

#[allow(unsafe_code)]
unsafe fn shared_mmap_target_child(
    signal: &SharedMailbox,
    protected_file: libc::c_int,
    benign_file: libc::c_int,
) -> ! {
    loop {
        let request = signal.state();
        if request == SHARED_MMAP_EXIT_REQUEST {
            // SAFETY: this terminates only the fork child.
            unsafe { libc::_exit(0) };
        }
        let (file, protection) = match request {
            SHARED_MMAP_PROTECTED_REQUEST => (protected_file, libc::PROT_WRITE),
            SHARED_MMAP_BENIGN_REQUEST => (benign_file, libc::PROT_READ),
            _ => {
                std::hint::spin_loop();
                continue;
            }
        };
        // SAFETY: the inherited descriptor remains open for the life of this child.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                protection,
                libc::MAP_SHARED,
                file,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            // SAFETY: errno is thread-local to this single-threaded fork child.
            let errno = unsafe { *libc::__errno_location() } as u32;
            signal.set_state(SHARED_MMAP_FAILURE_BASE.saturating_add(errno));
        } else {
            // SAFETY: address and length describe the live mapping above.
            unsafe {
                libc::munmap(address, 4096);
            }
            signal.set_state(SHARED_MMAP_ALLOWED);
        }
        while signal.state() != EMPTY {
            if signal.state() == SHARED_MMAP_EXIT_REQUEST {
                // SAFETY: this terminates only the fork child.
                unsafe { libc::_exit(0) };
            }
            std::hint::spin_loop();
        }
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
            let address = UnixSocketAddr::from_abstract_name(&self.abstract_name)?;
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

    fn forked_send(&self) -> IoOutcome {
        self.connected_stream
            .as_ref()
            .map_or_else(missing_process_target, |stream| {
                io_outcome(fixture_syscalls::forked_write_one(stream.as_raw_fd(), 4))
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

#[allow(unsafe_code)]
fn forked_network_send(fd: libc::c_int, payload: &[u8]) -> IoOutcome {
    // SAFETY: the child uses only the inherited descriptor and payload before _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return error_outcome(io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: payload points to initialized bytes for the duration of send.
        let sent = unsafe {
            libc::send(
                fd,
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        let status = if sent == payload.len() as isize {
            0
        } else {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
                .clamp(1, 255)
        };
        // SAFETY: the child exits without running inherited destructors.
        unsafe { libc::_exit(status) };
    }
    let mut status = 0;
    // SAFETY: child is a live direct child and status points to writable storage.
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        return error_outcome(io::Error::last_os_error());
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        allowed_outcome()
    } else if libc::WIFEXITED(status) {
        IoOutcome {
            allowed: false,
            errno: Some(libc::WEXITSTATUS(status)),
        }
    } else {
        IoOutcome {
            allowed: false,
            errno: None,
        }
    }
}

#[allow(unsafe_code)]
fn network_sendmsg(fd: libc::c_int, payload: &[u8]) -> IoOutcome {
    let mut iovec = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &raw mut iovec,
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    // SAFETY: message references one initialized iovec for the call duration.
    let sent = unsafe { libc::sendmsg(fd, &raw const message, libc::MSG_NOSIGNAL) };
    if sent == payload.len() as isize {
        allowed_outcome()
    } else if sent < 0 {
        error_outcome(io::Error::last_os_error())
    } else {
        IoOutcome {
            allowed: false,
            errno: None,
        }
    }
}

#[allow(unsafe_code)]
fn network_sendfile(fd: libc::c_int, path: &Path) -> IoOutcome {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return error_outcome(error),
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len().try_into().unwrap_or(usize::MAX),
        Err(error) => return error_outcome(error),
    };
    // SAFETY: both descriptors are live and the kernel owns the implicit input offset.
    let sent = unsafe { libc::sendfile(fd, file.as_raw_fd(), std::ptr::null_mut(), length) };
    if sent == length as isize {
        allowed_outcome()
    } else if sent < 0 {
        error_outcome(io::Error::last_os_error())
    } else {
        IoOutcome {
            allowed: false,
            errno: None,
        }
    }
}

#[allow(unsafe_code)]
fn network_splice(fd: libc::c_int, path: &Path) -> IoOutcome {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return error_outcome(error),
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len().try_into().unwrap_or(usize::MAX),
        Err(error) => return error_outcome(error),
    };
    let mut pipe = [-1_i32; 2];
    // SAFETY: pipe points to storage for two returned descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return error_outcome(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new owned descriptors.
    let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: pipe2 returned two new owned descriptors.
    let pipe_write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    // SAFETY: all descriptors are live and offsets are implicit.
    let loaded = unsafe {
        libc::splice(
            file.as_raw_fd(),
            std::ptr::null_mut(),
            pipe_write.as_raw_fd(),
            std::ptr::null_mut(),
            length,
            0,
        )
    };
    if loaded < 0 {
        return error_outcome(io::Error::last_os_error());
    }
    // SAFETY: all descriptors are live and offsets are implicit.
    let sent = unsafe {
        libc::splice(
            pipe_read.as_raw_fd(),
            std::ptr::null_mut(),
            fd,
            std::ptr::null_mut(),
            loaded.try_into().unwrap_or(usize::MAX),
            libc::SPLICE_F_MOVE,
        )
    };
    if sent == loaded {
        allowed_outcome()
    } else if sent < 0 {
        error_outcome(io::Error::last_os_error())
    } else {
        IoOutcome {
            allowed: false,
            errno: None,
        }
    }
}

#[allow(unsafe_code)]
fn network_udp_send(address: SocketAddr, payload: &[u8], connected: bool) -> IoOutcome {
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: the arguments create one owned UDP socket.
    let descriptor = unsafe {
        libc::socket(
            family,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if descriptor < 0 {
        return error_outcome(io::Error::last_os_error());
    }
    // SAFETY: descriptor is a new owned descriptor.
    let socket = UdpSocket::from(unsafe { OwnedFd::from_raw_fd(descriptor) });
    let result = if connected {
        socket.connect(address).and_then(|()| socket.send(payload))
    } else {
        socket.send_to(payload, address)
    };
    match result {
        Ok(length) if length == payload.len() => allowed_outcome(),
        Ok(_) => IoOutcome {
            allowed: false,
            errno: None,
        },
        Err(error) => error_outcome(error),
    }
}

#[allow(unsafe_code)]
fn network_tun_tap() -> IoOutcome {
    let device = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        Ok(device) => device,
        Err(error) => return error_outcome(error),
    };
    let mut request = [0_u8; libc::IFNAMSIZ + 24];
    request[..8].copy_from_slice(b"mithril0");
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    request[libc::IFNAMSIZ..libc::IFNAMSIZ + size_of::<i16>()]
        .copy_from_slice(&flags.to_ne_bytes());
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    // SAFETY: request contains the Linux ifreq name and flags fields.
    let result = unsafe { libc::ioctl(device.as_raw_fd(), TUNSETIFF, request.as_mut_ptr()) };
    if result == 0 {
        allowed_outcome()
    } else {
        error_outcome(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn network_socket_outcome(family: i32, socket_type: i32, protocol: i32) -> IoOutcome {
    // SAFETY: socket receives integer UAPI values and returns a new descriptor on success.
    let fd = unsafe { libc::socket(family, socket_type | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        error_outcome(io::Error::last_os_error())
    } else {
        // SAFETY: fd is the live descriptor returned by socket.
        unsafe { libc::close(fd) };
        allowed_outcome()
    }
}

#[allow(unsafe_code)]
fn network_set_mark(fd: libc::c_int, value: u32) -> IoOutcome {
    // SAFETY: value is a live u32 and its size matches SO_MARK.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        allowed_outcome()
    } else {
        error_outcome(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn network_allow_ptracer(pid: u32) -> IoOutcome {
    let pid = libc::c_ulong::from(pid);
    // SAFETY: PR_SET_PTRACER reads the exact process ID value and no pointer.
    let result = unsafe { libc::prctl(libc::PR_SET_PTRACER, pid, 0, 0, 0) };
    if result == 0 {
        allowed_outcome()
    } else {
        error_outcome(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn duplicate_process_descriptor(pid: u32, descriptor: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open returns one owned descriptor or a negative error.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pidfd is a new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    // SAFETY: pidfd_getfd duplicates descriptor from the exact target process.
    let duplicated =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), descriptor, 0) } as i32;
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: duplicated is a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }
}

fn network_proxy_request(path: &Path, request_id: &str, address: SocketAddr) -> IoOutcome {
    if request_id.is_empty()
        || !request_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-')
    {
        return IoOutcome {
            allowed: false,
            errno: Some(rustix::io::Errno::INVAL.raw_os_error()),
        };
    }
    match network_unix_address(path)
        .and_then(|address| UnixStream::connect_addr(&address))
        .and_then(|mut stream| {
            writeln!(stream, "{request_id}")?;
            writeln!(stream, "{address}")
        }) {
        Ok(()) => allowed_outcome(),
        Err(error) => error_outcome(error),
    }
}

fn network_unix_address(path: &Path) -> io::Result<UnixSocketAddr> {
    UnixSocketAddr::from_abstract_name(path.as_os_str().as_bytes())
}

fn network_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = network_socket(address, rustix::net::SocketFlags::CLOEXEC)?;
    rustix::net::bind(&socket, &address).map_err(io::Error::from)?;
    rustix::net::listen(&socket, 128).map_err(io::Error::from)?;
    Ok(socket.into())
}

fn network_connect(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = network_socket(
        address,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
    )?;
    match rustix::net::connect(&socket, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            let mut events = [rustix::event::PollFd::new(
                &socket,
                rustix::event::PollFlags::OUT,
            )];
            let timeout = rustix::event::Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            };
            if rustix::event::poll(&mut events, Some(&timeout)).map_err(io::Error::from)? == 0 {
                return Err(rustix::io::Errno::TIMEDOUT.into());
            }
            if let Err(error) =
                rustix::net::sockopt::socket_error(&socket).map_err(io::Error::from)?
            {
                return Err(error.into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let flags = rustix::fs::fcntl_getfl(&socket).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(&socket, flags - rustix::fs::OFlags::NONBLOCK)
        .map_err(io::Error::from)?;
    Ok(socket.into())
}

fn network_socket(address: SocketAddr, flags: rustix::net::SocketFlags) -> io::Result<OwnedFd> {
    let family = if address.is_ipv4() {
        rustix::net::AddressFamily::INET
    } else {
        rustix::net::AddressFamily::INET6
    };
    rustix::net::socket_with(
        family,
        rustix::net::SocketType::STREAM,
        flags,
        Some(rustix::net::ipproto::TCP),
    )
    .map_err(io::Error::from)
}

#[allow(unsafe_code)]
fn network_read_results(path: &Path) -> Result<NetworkReadResultsOutcome> {
    let mut zero_file = fs::File::open(path).context(IoSnafu { path })?;
    let zero_byte = zero_file.read(&mut []).context(IoSnafu { path })? == 0;

    let mut eof_file = fs::File::open(path).context(IoSnafu { path })?;
    eof_file
        .seek(std::io::SeekFrom::End(0))
        .context(IoSnafu { path })?;
    let mut byte = [0_u8; 1];
    let end_of_file = eof_file.read(&mut byte).context(IoSnafu { path })? == 0;

    let mut partial_file = fs::File::open(path).context(IoSnafu { path })?;
    let mut buffer = [0_u8; 32];
    let partial = partial_file.read(&mut buffer).context(IoSnafu { path })?;
    let partial_positive = partial > 0 && partial < buffer.len();

    let mapped_file = fs::File::open(path).context(IoSnafu { path })?;
    // SAFETY: the fixture retains mapped_file while it checks the private read-only mapping.
    let mapping = unsafe { memmap2::MmapOptions::new().map_copy_read_only(&mapped_file) }.map_err(
        |source| crate::Error::Io {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        },
    )?;
    let mapped = !mapping.is_empty() && mapping[0] == buffer[0];

    let inherited_file = fs::File::open(path).context(IoSnafu { path })?;
    let inherited_descriptor = inherited_file_read(inherited_file.as_raw_fd(), buffer[0]);

    let memory = fs::File::open("/proc/self/mem").context(IoSnafu {
        path: Path::new("/proc/self/mem"),
    })?;
    let io_error = memory
        .read_at(&mut byte, 0)
        .is_err_and(|error| error.raw_os_error() == Some(libc::EIO));

    Ok(NetworkReadResultsOutcome {
        zero_byte,
        end_of_file,
        io_error,
        partial_positive,
        mapped,
        inherited_descriptor,
    })
}

#[allow(unsafe_code)]
fn inherited_file_read(fd: libc::c_int, expected: u8) -> bool {
    // SAFETY: the child reads only the inherited descriptor before _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        let mut byte = 0_u8;
        // SAFETY: byte points to one writable byte and fd is inherited.
        let result = unsafe { libc::pread(fd, (&raw mut byte).cast(), 1, 0) };
        // SAFETY: the child exits without running inherited destructors.
        unsafe { libc::_exit(i32::from(result != 1 || byte != expected)) };
    }
    let mut status = 0;
    // SAFETY: child is a live direct child and status points to writable storage.
    (unsafe { libc::waitpid(child, &mut status, 0) == child })
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0
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
fn unlock_ptmx(file: &fs::File) -> io::Result<()> {
    let mut locked: libc::c_int = 0;
    // SAFETY: TIOCSPTLCK reads one int from the valid stack address.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCSPTLCK, &mut locked) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn ptmx_peer_outcome(file: &fs::File) -> IoOutcome {
    // SAFETY: TIOCGPTPEER returns a new descriptor or a negative errno result.
    let result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            QUALIFIED_TIOCGPTPEER_IOCTL,
            libc::O_RDWR | libc::O_NOCTTY,
        )
    };
    if result >= 0 {
        // SAFETY: a successful TIOCGPTPEER result is a new owned descriptor.
        let _peer = unsafe { OwnedFd::from_raw_fd(result) };
        allowed_outcome()
    } else {
        error_outcome(io::Error::last_os_error())
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
        invalid_state, mmap_outcome, network_read_results, ptmx_number_outcome, ptmx_peer_outcome,
        read_outcome, unlock_ptmx, BatchOutcome, BpfMapCreateAttr, IoOutcome, PreparedWriteRace,
        ProcessControlTarget, SharedMmapTarget, UnixStreamTarget, BPF_MAP_TYPE_ARRAY,
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
    fn network_chain_keeps_file_read_results_separate() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "temporary read-result fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let path = directory.path().join("token");
        fs::write(&path, b"token").map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::location!(),
        })?;

        let result = network_read_results(&path)?;
        assert!(result.zero_byte);
        assert!(result.end_of_file);
        assert!(result.io_error);
        assert!(result.partial_positive);
        assert!(result.mapped);
        assert!(result.inherited_descriptor);
        Ok(())
    }

    #[test]
    fn ptmx_ioctl_requires_success_and_kernel_output() -> crate::Result<()> {
        let ptmx_path = std::path::Path::new("/dev/ptmx");
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
        unlock_ptmx(&ptmx).map_err(|source| crate::Error::Io {
            path: ptmx_path.to_path_buf(),
            source,
            location: snafu::location!(),
        })?;
        assert!(ptmx_peer_outcome(&ptmx).allowed);

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
    fn shared_mmap_target_reports_both_unrestricted_controls() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "shared-mmap target fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let protected_path = directory.path().join("protected");
        let benign_path = directory.path().join("benign");
        fs::write(&protected_path, vec![0_u8; 4096]).map_err(|source| crate::Error::Io {
            path: protected_path.clone(),
            source,
            location: snafu::location!(),
        })?;
        fs::write(&benign_path, vec![0_u8; 4096]).map_err(|source| crate::Error::Io {
            path: benign_path.clone(),
            source,
            location: snafu::location!(),
        })?;
        let protected = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&protected_path)
            .map_err(|source| crate::Error::Io {
                path: protected_path,
                source,
                location: snafu::location!(),
            })?;
        let benign = fs::File::open(&benign_path).map_err(|source| crate::Error::Io {
            path: benign_path,
            source,
            location: snafu::location!(),
        })?;
        let signal_path = directory.path().join("signal");
        let signal = SharedMailbox::create(&signal_path)?;
        let mut target = SharedMmapTarget::spawn(
            signal,
            signal_path,
            protected.as_raw_fd(),
            benign.as_raw_fd(),
        )
        .map_err(|source| crate::Error::Io {
            path: "shared-mmap target fixture".into(),
            source,
            location: snafu::location!(),
        })?;

        assert!(target.pid() > 0);
        assert!(target.mmap_protected().allowed);
        assert!(target.mmap_benign().allowed);
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
