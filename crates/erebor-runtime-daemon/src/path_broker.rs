#![allow(unsafe_code)]

use std::{
    fs::File,
    io::{IoSlice, IoSliceMut, Read},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use erebor_runtime_core::{SafePathBinding, SafePathKind};
use erebor_runtime_session::{ResolvedSessionPath, SessionPathResolver, SessionPathResolverError};
use rustix::{
    cmsg_space,
    fs::{
        makedev, open, openat2, statx, AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags,
    },
    io::{fcntl_getfd, fcntl_setfd, FdFlags},
    net::{
        recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
    process::{getegid, geteuid, Gid, Uid},
    thread::{
        set_no_new_privs, set_thread_groups, set_thread_res_gid, set_thread_res_uid,
        unshare_unsafe, UnshareFlags,
    },
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{InvalidRequestSnafu, IoSnafu},
    Result,
};

const MAX_RESPONSE_BYTES: usize = 4096;
const BROKER_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct DescriptorBroker {
    executable: PathBuf,
}

pub(crate) struct ResolvedDescriptor {
    descriptor: File,
    binding: SafePathBinding,
}

#[derive(Deserialize, Serialize)]
struct BrokerResponse {
    error: Option<String>,
    device: u64,
    inode: u64,
    mount_id: u64,
    owner_uid: u32,
    owner_gid: u32,
    effective_uid: u32,
    effective_gid: u32,
    supplementary_group_count: usize,
    network_namespace_inode: u64,
    remaining_unrelated_descriptor_count: usize,
}

impl DescriptorBroker {
    pub(crate) fn installed() -> Self {
        Self {
            executable: PathBuf::from("/usr/libexec/erebor/erebor-path-broker"),
        }
    }

    pub(crate) fn resolve(
        &self,
        uid: u32,
        gid: u32,
        path: &Path,
        kind: SafePathKind,
    ) -> Result<ResolvedDescriptor> {
        if !path.is_absolute() {
            return InvalidRequestSnafu {
                reason: format!("path `{}` must be absolute", path.display()),
            }
            .fail();
        }
        let (parent, child) = UnixStream::pair().context(IoSnafu {
            action: "creating descriptor broker socketpair",
            path: &self.executable,
        })?;
        let parent_network_namespace = network_namespace_inode()?;
        fcntl_setfd(&child, FdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "preparing descriptor broker socket",
                path: &self.executable,
            })?;
        let socket_fd = child.as_raw_fd().to_string();
        let uid_arg = uid.to_string();
        let gid_arg = gid.to_string();
        let kind_name = kind_name(kind);
        let mut child_process = Command::new(&self.executable)
            .args([
                "--socket-fd",
                &socket_fd,
                "--uid",
                &uid_arg,
                "--gid",
                &gid_arg,
                "--kind",
                kind_name,
                "--path",
            ])
            .arg(path)
            .env_clear()
            .env("RUST_BACKTRACE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| crate::DaemonError::Io {
                action: "starting descriptor broker",
                path: self.executable.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        drop(child);
        parent
            .set_read_timeout(Some(BROKER_TIMEOUT))
            .context(IoSnafu {
                action: "setting descriptor broker response deadline",
                path: &self.executable,
            })?;
        let received = match receive_descriptor(&parent) {
            Ok(received) => received,
            Err(error) => {
                let _status = child_process.wait();
                let mut diagnostics = String::new();
                if let Some(stderr) = child_process.stderr.as_mut() {
                    let _result = stderr
                        .take(MAX_RESPONSE_BYTES as u64)
                        .read_to_string(&mut diagnostics);
                }
                if diagnostics.trim().is_empty() {
                    return Err(error);
                }
                return InvalidRequestSnafu {
                    reason: format!("descriptor broker failed: {}", diagnostics.trim()),
                }
                .fail();
            }
        };
        let deadline = Instant::now() + BROKER_TIMEOUT;
        let status = loop {
            if let Some(status) = child_process.try_wait().context(IoSnafu {
                action: "observing descriptor broker completion",
                path: &self.executable,
            })? {
                break status;
            }
            if Instant::now() >= deadline {
                let _result = child_process.kill();
                let _result = child_process.wait();
                return InvalidRequestSnafu {
                    reason: String::from("descriptor broker exceeded its execution deadline"),
                }
                .fail();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !status.success() {
            return InvalidRequestSnafu {
                reason: received
                    .response
                    .error
                    .unwrap_or_else(|| String::from("descriptor broker rejected the path")),
            }
            .fail();
        }
        if received.response.effective_uid != uid
            || received.response.effective_gid != gid
            || received.response.supplementary_group_count != 0
            || received.response.remaining_unrelated_descriptor_count != 0
            || (geteuid().is_root()
                && received.response.network_namespace_inode == parent_network_namespace)
        {
            return InvalidRequestSnafu {
                reason: String::from(
                    "descriptor broker did not prove privilege, network, or descriptor isolation",
                ),
            }
            .fail();
        }
        let descriptor = received.descriptor.ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("descriptor broker returned no held descriptor"),
            }
            .build()
        })?;
        let binding = SafePathBinding::new(
            path.to_path_buf(),
            received.response.device,
            received.response.inode,
            received.response.mount_id,
            received.response.owner_uid,
            received.response.owner_gid,
            kind,
        )
        .map_err(|source| {
            InvalidRequestSnafu {
                reason: source.to_string(),
            }
            .build()
        })?;
        Ok(ResolvedDescriptor {
            descriptor: File::from(descriptor),
            binding,
        })
    }
}

impl ResolvedDescriptor {
    pub(crate) fn binding(&self) -> &SafePathBinding {
        &self.binding
    }

    fn into_parts(self) -> (File, SafePathBinding) {
        (self.descriptor, self.binding)
    }
}

impl SessionPathResolver for DescriptorBroker {
    fn resolve(
        &self,
        uid: u32,
        gid: u32,
        path: &Path,
        kind: SafePathKind,
    ) -> std::result::Result<ResolvedSessionPath, SessionPathResolverError> {
        DescriptorBroker::resolve(self, uid, gid, path, kind)
            .map(|resolved| {
                let (descriptor, binding) = resolved.into_parts();
                ResolvedSessionPath::new(descriptor, binding)
            })
            .map_err(|source| Box::new(source) as SessionPathResolverError)
    }
}

struct ReceivedDescriptor {
    response: BrokerResponse,
    descriptor: Option<OwnedFd>,
}

fn receive_descriptor(socket: &UnixStream) -> Result<ReceivedDescriptor> {
    let mut payload = [0_u8; MAX_RESPONSE_BYTES];
    let mut payload_slice = [IoSliceMut::new(&mut payload)];
    let mut ancillary_space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let received = recvmsg(
        socket,
        &mut payload_slice,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        action: "receiving descriptor broker response",
        path: Path::new("<private-socketpair>"),
    })?;
    if received.bytes == 0 || received.bytes > payload.len() {
        return InvalidRequestSnafu {
            reason: String::from("descriptor broker returned an empty or oversized response"),
        }
        .fail();
    }
    let mut descriptor = None;
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(mut descriptors) = message {
            descriptor = descriptors.next();
            for extra in descriptors {
                drop(extra);
            }
        }
    }
    let response = serde_json::from_slice(&payload[..received.bytes]).map_err(|source| {
        crate::DaemonError::InvalidConfig {
            path: PathBuf::from("<descriptor-broker-response>"),
            source,
            location: snafu::Location::default(),
        }
    })?;
    Ok(ReceivedDescriptor {
        response,
        descriptor,
    })
}

pub fn run_path_broker() -> Result<()> {
    let arguments = BrokerArguments::parse()?;
    let socket = unsafe { UnixStream::from_raw_fd(arguments.socket_fd) };
    let result = broker_resolve(&arguments);
    match result {
        Ok((descriptor, response)) => {
            send_response(&socket, &response, Some(descriptor.as_fd()))?;
            Ok(())
        }
        Err(error) => {
            let response = BrokerResponse {
                error: Some(error.to_string()),
                device: 0,
                inode: 0,
                mount_id: 0,
                owner_uid: 0,
                owner_gid: 0,
                effective_uid: 0,
                effective_gid: 0,
                supplementary_group_count: usize::MAX,
                network_namespace_inode: 0,
                remaining_unrelated_descriptor_count: usize::MAX,
            };
            let _result = send_response(&socket, &response, None);
            Err(error)
        }
    }
}

struct BrokerArguments {
    socket_fd: i32,
    uid: u32,
    gid: u32,
    kind: SafePathKind,
    path: PathBuf,
}

impl BrokerArguments {
    fn parse() -> Result<Self> {
        let values = std::env::args_os().skip(1).collect::<Vec<_>>();
        if values.len() != 10
            || values[0] != "--socket-fd"
            || values[2] != "--uid"
            || values[4] != "--gid"
            || values[6] != "--kind"
            || values[8] != "--path"
        {
            return InvalidRequestSnafu {
                reason: String::from("descriptor broker arguments are invalid"),
            }
            .fail();
        }
        let parse_number = |index: usize, name: &str| -> Result<u32> {
            values[index]
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| {
                    InvalidRequestSnafu {
                        reason: format!("descriptor broker {name} is invalid"),
                    }
                    .build()
                })
        };
        let socket_fd = parse_number(1, "socket fd")?;
        let socket_fd = i32::try_from(socket_fd).map_err(|_error| {
            InvalidRequestSnafu {
                reason: String::from("descriptor broker socket fd is out of range"),
            }
            .build()
        })?;
        let uid = parse_number(3, "uid")?;
        let gid = parse_number(5, "gid")?;
        let kind = match values[7].to_str() {
            Some("directory") => SafePathKind::Directory,
            Some("executable") => SafePathKind::Executable,
            Some("file") => SafePathKind::File,
            _ => {
                return InvalidRequestSnafu {
                    reason: String::from("descriptor broker path kind is invalid"),
                }
                .fail();
            }
        };
        Ok(Self {
            socket_fd,
            uid,
            gid,
            kind,
            path: PathBuf::from(&values[9]),
        })
    }
}

fn broker_resolve(arguments: &BrokerArguments) -> Result<(OwnedFd, BrokerResponse)> {
    if geteuid().as_raw() != 0 && geteuid().as_raw() != arguments.uid {
        return InvalidRequestSnafu {
            reason: String::from("descriptor broker must start as root"),
        }
        .fail();
    }
    if geteuid().as_raw() == 0 {
        unsafe { unshare_unsafe(UnshareFlags::NEWNET) }
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "isolating descriptor broker network namespace",
                path: &arguments.path,
            })?;
        set_thread_groups(&[])
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "clearing descriptor broker supplementary groups",
                path: &arguments.path,
            })?;
        let gid = Gid::from_raw(arguments.gid);
        set_thread_res_gid(gid, gid, gid)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "dropping descriptor broker group privileges",
                path: &arguments.path,
            })?;
        let uid = Uid::from_raw(arguments.uid);
        set_thread_res_uid(uid, uid, uid)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "dropping descriptor broker user privileges",
                path: &arguments.path,
            })?;
    }
    set_no_new_privs(true)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "locking descriptor broker privileges",
            path: &arguments.path,
        })?;
    if geteuid().as_raw() != arguments.uid || getegid().as_raw() != arguments.gid {
        return InvalidRequestSnafu {
            reason: String::from("descriptor broker privilege drop could not be verified"),
        }
        .fail();
    }
    close_unrelated_descriptors(arguments.socket_fd)?;
    let remaining_unrelated_descriptor_count = unrelated_descriptor_count(arguments.socket_fd)?;
    let root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        action: "opening descriptor broker root",
        path: &arguments.path,
    })?;
    let relative = arguments.path.strip_prefix("/").map_err(|_error| {
        InvalidRequestSnafu {
            reason: String::from("descriptor broker path must be absolute"),
        }
        .build()
    })?;
    let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if arguments.kind == SafePathKind::Directory {
        flags |= OFlags::DIRECTORY;
    }
    let descriptor = openat2(
        &root,
        relative,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        action: "resolving descriptor-relative path without symlinks",
        path: &arguments.path,
    })?;
    let status = statx(
        &descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        action: "observing held descriptor identity",
        path: &arguments.path,
    })?;
    let file_type = FileType::from_raw_mode(status.stx_mode.into());
    let valid_kind = match arguments.kind {
        SafePathKind::Directory => file_type.is_dir(),
        SafePathKind::Executable => file_type.is_file() && status.stx_mode & 0o111 != 0,
        SafePathKind::File => file_type.is_file(),
    };
    if !valid_kind {
        return InvalidRequestSnafu {
            reason: String::from("held descriptor has the wrong admitted path kind"),
        }
        .fail();
    }
    Ok((
        descriptor,
        BrokerResponse {
            error: None,
            device: makedev(status.stx_dev_major, status.stx_dev_minor),
            inode: status.stx_ino,
            mount_id: status.stx_mnt_id,
            owner_uid: status.stx_uid,
            owner_gid: status.stx_gid,
            effective_uid: geteuid().as_raw(),
            effective_gid: getegid().as_raw(),
            supplementary_group_count: 0,
            network_namespace_inode: network_namespace_inode()?,
            remaining_unrelated_descriptor_count,
        },
    ))
}

fn unrelated_descriptor_count(socket_fd: i32) -> Result<usize> {
    let mut descriptors = std::fs::read_dir("/proc/self/fd")
        .context(IoSnafu {
            action: "verifying descriptor broker file descriptor closure",
            path: Path::new("/proc/self/fd"),
        })?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| *fd > 2 && *fd != socket_fd)
        .collect::<Vec<_>>();
    descriptors.sort_unstable();
    descriptors.dedup();
    Ok(descriptors.len().saturating_sub(1))
}

fn network_namespace_inode() -> Result<u64> {
    std::fs::metadata("/proc/self/ns/net")
        .map(|metadata| metadata.ino())
        .context(IoSnafu {
            action: "observing descriptor broker network namespace",
            path: Path::new("/proc/self/ns/net"),
        })
}

fn close_unrelated_descriptors(socket_fd: i32) -> Result<()> {
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .context(IoSnafu {
            action: "enumerating descriptor broker file descriptors",
            path: Path::new("/proc/self/fd"),
        })?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| *fd > 2 && *fd != socket_fd)
        .collect::<Vec<_>>();
    for descriptor in descriptors {
        let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
        if fcntl_getfd(borrowed).is_ok() {
            unsafe {
                rustix::io::close(descriptor);
            }
        }
    }
    Ok(())
}

fn send_response(
    socket: &UnixStream,
    response: &BrokerResponse,
    descriptor: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<()> {
    let encoded =
        serde_json::to_vec(response).map_err(|source| crate::DaemonError::InvalidConfig {
            path: PathBuf::from("<descriptor-broker-response>"),
            source,
            location: snafu::Location::default(),
        })?;
    let slices = [IoSlice::new(&encoded)];
    let descriptors = descriptor.into_iter().collect::<Vec<_>>();
    let mut ancillary_space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return InvalidRequestSnafu {
            reason: String::from("descriptor broker ancillary buffer is too small"),
        }
        .fail();
    }
    sendmsg(socket, &slices, &mut ancillary, SendFlags::empty())
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "sending descriptor broker response",
            path: Path::new("<private-socketpair>"),
        })?;
    Ok(())
}

const fn kind_name(kind: SafePathKind) -> &'static str {
    match kind {
        SafePathKind::Directory => "directory",
        SafePathKind::Executable => "executable",
        SafePathKind::File => "file",
    }
}
