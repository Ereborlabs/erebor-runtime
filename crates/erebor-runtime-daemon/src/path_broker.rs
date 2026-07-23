#![allow(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File},
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
use erebor_runtime_packages::PolicyPackageRevision;
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
use sha2::{Digest, Sha256};
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPackageConfig {
    name: String,
}

#[derive(Deserialize, Serialize)]
struct BrokerResponse {
    error: Option<String>,
    device: u64,
    inode: u64,
    mount_id: u64,
    owner_uid: u32,
    owner_gid: u32,
    content_sha256: Option<String>,
    effective_uid: u32,
    effective_gid: u32,
    supplementary_group_count: usize,
    network_namespace_inode: u64,
    remaining_unrelated_descriptor_count: usize,
}

impl DescriptorBroker {
    pub(crate) fn installed() -> Self {
        Self::new(PathBuf::from("/usr/libexec/erebor/erebor-path-broker"))
    }

    pub(crate) const fn new(executable: PathBuf) -> Self {
        Self { executable }
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
                // A timed-out or malformed broker response must not leave the
                // daemon control handler blocked in `wait` behind a child that
                // is still running. The caller receives the bounded broker
                // failure instead of an unrelated client read timeout.
                let _result = child_process.kill();
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
        .and_then(|binding| match received.response.content_sha256 {
            Some(digest) => binding.with_content_sha256(digest),
            None => Ok(binding),
        })
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

    pub(crate) fn read_policy_package(
        &self,
        uid: u32,
        gid: u32,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<PolicyPackageRevision> {
        let resolved = self.resolve(uid, gid, path, SafePathKind::Directory)?;
        PolicyPackageDirectoryReader::new(resolved.descriptor, path, maximum_bytes).read()
    }
}

impl ResolvedDescriptor {
    pub(crate) const fn binding(&self) -> &SafePathBinding {
        &self.binding
    }

    pub(crate) fn mode(&self) -> Result<u32> {
        self.descriptor
            .metadata()
            .map(|metadata| metadata.mode())
            .context(IoSnafu {
                action: "observing held descriptor mode",
                path: self.binding.requested_path(),
            })
    }

    fn into_parts(self) -> (File, SafePathBinding) {
        (self.descriptor, self.binding)
    }
}

struct PolicyPackageDirectoryReader {
    root: File,
    source: PathBuf,
    maximum_bytes: u64,
    bytes_read: u64,
}

impl PolicyPackageDirectoryReader {
    fn new(root: File, source: &Path, maximum_bytes: u64) -> Self {
        Self {
            root,
            source: source.to_path_buf(),
            maximum_bytes,
            bytes_read: 0,
        }
    }

    fn read(mut self) -> Result<PolicyPackageRevision> {
        self.validate_root_layout()?;
        let policy_config = self.read_file("policy.toml")?;
        let config_source = std::str::from_utf8(&policy_config).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("policy.toml is not UTF-8: {error}"),
            }
            .build()
        })?;
        let config: PolicyPackageConfig = toml::from_str(config_source).map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("policy.toml is invalid: {error}"),
            }
            .build()
        })?;
        PolicyPackageRevision::new(
            config.name,
            policy_config,
            self.read_directory("rules")?,
            self.read_directory("examples")?,
            self.read_directory("tests")?,
            self.read_file("README.md")?,
        )
        .map_err(|error| {
            InvalidRequestSnafu {
                reason: format!("policy package has invalid immutable contents: {error}"),
            }
            .build()
        })
    }

    fn validate_root_layout(&self) -> Result<()> {
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", self.root.as_raw_fd()));
        let entries = fs::read_dir(&descriptor_path).context(IoSnafu {
            action: "enumerating held policy package root",
            path: &self.source,
        })?;
        let mut names = BTreeMap::new();
        for entry in entries {
            let entry = entry.context(IoSnafu {
                action: "enumerating held policy package root entry",
                path: &self.source,
            })?;
            let name = entry.file_name().into_string().map_err(|_name| {
                InvalidRequestSnafu {
                    reason: String::from("policy package root has a non-UTF-8 entry"),
                }
                .build()
            })?;
            if !Self::safe_file_name(&name) || names.insert(name.clone(), ()).is_some() {
                return InvalidRequestSnafu {
                    reason: format!("policy package root has an unsafe entry `{name}`"),
                }
                .fail();
            }
        }
        let expected = ["README.md", "examples", "policy.toml", "rules", "tests"];
        if names.keys().map(String::as_str).ne(expected) {
            return InvalidRequestSnafu {
                reason: String::from(
                    "policy package must contain exactly policy.toml, rules/, examples/, tests/, and README.md",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn read_directory(&mut self, name: &str) -> Result<BTreeMap<String, Vec<u8>>> {
        let directory = self.open_relative(name, true)?;
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let entries = fs::read_dir(&descriptor_path).context(IoSnafu {
            action: "enumerating held policy package directory",
            path: &self.source,
        })?;
        let mut files = BTreeMap::new();
        for entry in entries {
            let entry = entry.context(IoSnafu {
                action: "enumerating held policy package directory entry",
                path: &self.source,
            })?;
            let name = entry.file_name().into_string().map_err(|_name| {
                InvalidRequestSnafu {
                    reason: format!("policy package directory `{}` has a non-UTF-8 entry", name),
                }
                .build()
            })?;
            if !Self::safe_file_name(&name) {
                return InvalidRequestSnafu {
                    reason: format!(
                        "policy package directory `{}` has an unsafe entry `{name}`",
                        name
                    ),
                }
                .fail();
            }
            let file = self.open_at(&directory, Path::new(&name), false)?;
            let contents = self.read_held_file(file, &name)?;
            if files.insert(name, contents).is_some() {
                return InvalidRequestSnafu {
                    reason: String::from("policy package has duplicate directory entries"),
                }
                .fail();
            }
        }
        Ok(files)
    }

    fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        let file = self.open_relative(name, false)?;
        self.read_held_file(file, name)
    }

    fn open_relative(&self, name: &str, directory: bool) -> Result<File> {
        self.open_at(&self.root, Path::new(name), directory)
    }

    fn open_at(&self, parent: &File, name: &Path, directory: bool) -> Result<File> {
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if directory {
            flags |= OFlags::DIRECTORY;
        }
        openat2(
            parent,
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "opening held policy package entry without symlinks",
            path: &self.source,
        })
    }

    fn read_held_file(&mut self, mut file: File, name: &str) -> Result<Vec<u8>> {
        let metadata = file.metadata().context(IoSnafu {
            action: "inspecting held policy package file",
            path: &self.source,
        })?;
        if !metadata.is_file() {
            return InvalidRequestSnafu {
                reason: format!("policy package entry `{name}` must be a regular file"),
            }
            .fail();
        }
        let remaining = self.maximum_bytes.saturating_sub(self.bytes_read);
        let mut contents = Vec::with_capacity(metadata.len().min(remaining) as usize);
        file.by_ref()
            .take(remaining.saturating_add(1))
            .read_to_end(&mut contents)
            .context(IoSnafu {
                action: "reading held policy package file",
                path: &self.source,
            })?;
        let count = contents.len() as u64;
        if count > remaining {
            return InvalidRequestSnafu {
                reason: format!(
                    "policy package exceeds the declared {}-byte upload limit",
                    self.maximum_bytes
                ),
            }
            .fail();
        }
        self.bytes_read = self.bytes_read.saturating_add(count);
        Ok(contents)
    }

    fn safe_file_name(name: &str) -> bool {
        !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
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
                content_sha256: None,
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
    let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if arguments.kind == SafePathKind::Directory {
        flags |= OFlags::PATH | OFlags::DIRECTORY;
    } else {
        flags |= OFlags::RDONLY;
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
    let content_sha256 = if matches!(
        arguments.kind,
        SafePathKind::Executable | SafePathKind::File
    ) {
        Some(digest_descriptor(&descriptor, &arguments.path)?)
    } else {
        None
    };
    Ok((
        descriptor,
        BrokerResponse {
            error: None,
            device: makedev(status.stx_dev_major, status.stx_dev_minor),
            inode: status.stx_ino,
            mount_id: status.stx_mnt_id,
            owner_uid: status.stx_uid,
            owner_gid: status.stx_gid,
            content_sha256,
            effective_uid: geteuid().as_raw(),
            effective_gid: getegid().as_raw(),
            supplementary_group_count: 0,
            network_namespace_inode: network_namespace_inode()?,
            remaining_unrelated_descriptor_count,
        },
    ))
}

fn digest_descriptor(descriptor: &OwnedFd, path: &Path) -> Result<String> {
    let duplicate = rustix::io::dup(descriptor)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "duplicating held executable for digesting",
            path,
        })?;
    let mut file = File::from(duplicate);
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest).context(IoSnafu {
        action: "digesting held executable",
        path,
    })?;
    Ok(format!("{:x}", digest.finalize()))
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

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix::fs::PermissionsExt,
        time::Instant,
    };

    use super::{DescriptorBroker, PolicyPackageDirectoryReader, SafePathKind, BROKER_TIMEOUT};

    #[test]
    fn descriptor_broker_timeout_stops_a_nonresponding_child(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let broker = root.path().join("nonresponding-broker");
        fs::write(&broker, "#!/bin/sh\nexec /bin/sleep 60\n")?;
        fs::set_permissions(&broker, fs::Permissions::from_mode(0o755))?;

        let resolver = DescriptorBroker::new(broker);
        let target = std::env::current_exe()?;
        let started = Instant::now();
        let result = resolver.resolve(
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            &target,
            SafePathKind::Executable,
        );

        assert!(result.is_err());
        assert!(
            started.elapsed() < BROKER_TIMEOUT + std::time::Duration::from_secs(3),
            "a broker response timeout must kill and reap the broker child"
        );
        Ok(())
    }

    #[test]
    fn held_directory_reader_accepts_the_fixed_policy_package_layout(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("policy.toml"), "name = \"example\"\n")?;
        fs::create_dir(root.path().join("rules"))?;
        fs::write(
            root.path().join("rules").join("terminal.json"),
            br#"{"rules":[{"id":"allow","match":{"surface":"terminal"},"decision":"allow"}]}"#,
        )?;
        fs::create_dir(root.path().join("examples"))?;
        fs::create_dir(root.path().join("tests"))?;
        fs::write(root.path().join("tests").join("terminal.json"), "{}")?;
        fs::write(root.path().join("README.md"), "# Example\n")?;

        let package =
            PolicyPackageDirectoryReader::new(File::open(root.path())?, root.path(), 4096)
                .read()?;
        assert_eq!(package.manifest().name(), "example");
        assert_eq!(package.rules().len(), 1);
        Ok(())
    }

    #[test]
    fn held_directory_reader_rejects_unrecognized_root_entries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("policy.toml"), "name = \"example\"\n")?;
        fs::create_dir(root.path().join("rules"))?;
        fs::write(
            root.path().join("rules").join("terminal.json"),
            br#"{"rules":[{"id":"allow","match":{"surface":"terminal"},"decision":"allow"}]}"#,
        )?;
        fs::create_dir(root.path().join("examples"))?;
        fs::create_dir(root.path().join("tests"))?;
        fs::write(root.path().join("tests").join("terminal.json"), "{}")?;
        fs::write(root.path().join("README.md"), "# Example\n")?;
        fs::write(root.path().join("unexpected.txt"), "nope")?;

        assert!(
            PolicyPackageDirectoryReader::new(File::open(root.path())?, root.path(), 4096)
                .read()
                .is_err()
        );
        Ok(())
    }
}
