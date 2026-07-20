use std::{
    fs::{self, File},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use erebor_runtime_ipc::{
    v1::{
        DaemonHello, DaemonHelloAck, Envelope, KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK,
        PROTOCOL_VERSION,
    },
    AsyncFrameCodec,
};
#[cfg(test)]
use rustix::process::{getegid, geteuid};
use rustix::{
    fs::{chown, flock, open, openat, FlockOperation, Mode, OFlags},
    process::{Gid, Uid},
};
use snafu::ResultExt;
use tokio::{net::UnixStream, time::timeout};

use crate::{
    error::{AlreadyRunningSnafu, IoSnafu, IpcSnafu, LockUnavailableSnafu, UnsafePathSnafu},
    Result,
};

const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct DaemonPaths {
    config: PathBuf,
    runtime: PathBuf,
    logs: PathBuf,
    state: PathBuf,
}

impl DaemonPaths {
    #[must_use]
    pub fn system() -> Self {
        Self {
            config: PathBuf::from("/etc/erebor/erebord.json"),
            runtime: PathBuf::from("/run/erebor"),
            logs: PathBuf::from("/var/log/erebor"),
            state: PathBuf::from("/var/lib/erebor"),
        }
    }

    #[must_use]
    pub fn for_testing(root: impl AsRef<Path>) -> Self {
        Self::for_development(root)
    }

    /// Uses a disposable root for a manually started local development daemon.
    ///
    /// The caller remains responsible for creating the root-controlled
    /// configuration file before starting `erebord` as root.
    #[must_use]
    pub fn for_development(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            config: root.join("etc/erebord.json"),
            runtime: root.join("run"),
            logs: root.join("log"),
            state: root.join("lib"),
        }
    }

    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.runtime.join("daemon.sock")
    }

    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.runtime.join("erebord.lock")
    }

    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.logs.join("daemon.jsonl")
    }

    #[must_use]
    pub fn idempotency_path(&self) -> PathBuf {
        self.state.join("daemon/control-idempotency")
    }

    pub(crate) fn prepare(&self, security: DaemonSecurity) -> Result<()> {
        self.ensure_directory(&self.runtime, 0o750, security)?;
        self.ensure_directory(&self.logs, 0o750, security)?;
        self.ensure_directory(&self.state, 0o700, security)?;
        self.ensure_directory(&self.idempotency_path(), 0o700, security)?;
        Ok(())
    }

    pub(crate) fn set_runtime_group(&self, security: DaemonSecurity) -> Result<()> {
        chown(
            &self.runtime,
            Some(Uid::from_raw(security.owner_uid)),
            Some(Gid::from_raw(security.socket_gid)),
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "setting daemon runtime directory ownership",
            path: &self.runtime,
        })
    }

    fn ensure_directory(&self, path: &Path, mode: u32, security: DaemonSecurity) -> Result<()> {
        if !path.exists() {
            fs::create_dir_all(path).context(IoSnafu {
                action: "creating daemon directory",
                path,
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).context(IoSnafu {
                action: "setting daemon directory permissions",
                path,
            })?;
        }
        let metadata = fs::symlink_metadata(path).context(IoSnafu {
            action: "inspecting daemon directory",
            path,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != security.owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("must be an owner-controlled non-symlink directory"),
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn open_config(&self, security: DaemonSecurity) -> Result<File> {
        let path = &self.config;
        let parent = path.parent().ok_or_else(|| {
            UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("has no parent directory"),
            }
            .build()
        })?;
        let file_name = path.file_name().ok_or_else(|| {
            UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("has no file name"),
            }
            .build()
        })?;
        let directory = File::from(
            open(
                parent,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "opening daemon configuration directory without following symlinks",
                path: parent,
            })?,
        );
        let directory_metadata = directory.metadata().context(IoSnafu {
            action: "inspecting daemon configuration directory",
            path: parent,
        })?;
        if !directory_metadata.is_dir()
            || directory_metadata.uid() != security.owner_uid
            || directory_metadata.mode() & 0o022 != 0
        {
            return UnsafePathSnafu {
                path: parent.to_path_buf(),
                reason: String::from("must be an owner-controlled non-writable directory"),
            }
            .fail();
        }
        let file = File::from(
            openat(
                &directory,
                file_name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "opening daemon configuration without following symlinks",
                path,
            })?,
        );
        self.require_config_file(
            path,
            &file.metadata().context(IoSnafu {
                action: "inspecting opened daemon configuration",
                path,
            })?,
            security,
        )?;
        Ok(file)
    }

    pub(crate) fn acquire_lock(&self, security: DaemonSecurity) -> Result<DaemonLock> {
        let path = self.lock_path();
        let file = self.open_or_create_secure(&path, 0o600, security, "opening daemon lock")?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(DaemonLock { file }),
            Err(_error) => LockUnavailableSnafu { path }.fail(),
        }
    }

    pub(crate) async fn remove_stale_socket(
        &self,
        _lock: &DaemonLock,
        security: DaemonSecurity,
    ) -> Result<()> {
        let socket = self.socket_path();
        let metadata = match fs::symlink_metadata(&socket) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(crate::DaemonError::Io {
                    action: "inspecting existing daemon socket",
                    path: socket,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return UnsafePathSnafu {
                path: socket,
                reason: String::from("existing daemon socket path is not a socket"),
            }
            .fail();
        }
        match timeout(SOCKET_PROBE_TIMEOUT, UnixStream::connect(&socket)).await {
            Ok(Ok(mut stream)) => {
                self.probe_live_socket(&mut stream, security).await?;
                AlreadyRunningSnafu { path: socket }.fail()
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                fs::remove_file(&socket).context(IoSnafu {
                    action: "removing stale daemon socket after refused connection",
                    path: socket,
                })
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(Err(_)) | Err(_) => AlreadyRunningSnafu { path: socket }.fail(),
        }
    }

    async fn probe_live_socket(
        &self,
        stream: &mut UnixStream,
        security: DaemonSecurity,
    ) -> Result<()> {
        let credentials = stream
            .peer_cred()
            .map_err(|source| crate::DaemonError::Io {
                action: "observing existing daemon socket peer credentials",
                path: self.socket_path(),
                source,
                location: snafu::Location::default(),
            })?;
        if credentials.uid() != security.owner_uid {
            return AlreadyRunningSnafu {
                path: self.socket_path(),
            }
            .fail();
        }
        let hello = Envelope::wrap_message(
            1,
            0,
            KIND_DAEMON_HELLO,
            &DaemonHello {
                protocol_version: PROTOCOL_VERSION,
                client_name: String::from("erebord stale-socket probe"),
                capabilities: Vec::new(),
            },
        )
        .context(IpcSnafu)?;
        let frame = hello.into_frame().context(IpcSnafu)?;
        timeout(
            SOCKET_PROBE_TIMEOUT,
            AsyncFrameCodec::write_frame(stream, &frame),
        )
        .await
        .map_err(|_elapsed| crate::DaemonError::AlreadyRunning {
            path: self.socket_path(),
            location: snafu::Location::default(),
        })?
        .context(IpcSnafu)?;
        let response = timeout(SOCKET_PROBE_TIMEOUT, AsyncFrameCodec::read_frame(stream))
            .await
            .map_err(|_elapsed| crate::DaemonError::AlreadyRunning {
                path: self.socket_path(),
                location: snafu::Location::default(),
            })?
            .context(IpcSnafu)?
            .decode_payload::<Envelope>()
            .context(IpcSnafu)?;
        if response.require_supported_protocol().is_err()
            || response.message_kind != KIND_DAEMON_HELLO_ACK
        {
            return AlreadyRunningSnafu {
                path: self.socket_path(),
            }
            .fail();
        }
        let hello: DaemonHelloAck = response
            .decode_typed_payload(KIND_DAEMON_HELLO_ACK)
            .context(IpcSnafu)?;
        if hello.protocol_version != PROTOCOL_VERSION {
            return AlreadyRunningSnafu {
                path: self.socket_path(),
            }
            .fail();
        }
        Ok(())
    }

    fn open_existing_secure(
        &self,
        path: &Path,
        security: DaemonSecurity,
        action: &'static str,
    ) -> Result<File> {
        let before = fs::symlink_metadata(path).context(IoSnafu { action, path })?;
        self.require_secure_file(path, &before, security)?;
        let file = File::from(
            open(
                path,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .context(IoSnafu { action, path })?,
        );
        self.require_same_file(path, &before, &file, action)?;
        Ok(file)
    }

    fn open_or_create_secure(
        &self,
        path: &Path,
        mode: u32,
        security: DaemonSecurity,
        action: &'static str,
    ) -> Result<File> {
        match open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from(mode),
        ) {
            Ok(file) => Ok(File::from(file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.open_existing_secure(path, security, action)
            }
            Err(source) => Err(crate::DaemonError::Io {
                action,
                path: path.to_path_buf(),
                source: source.into(),
                location: snafu::Location::default(),
            }),
        }
    }

    fn require_secure_file(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
        security: DaemonSecurity,
    ) -> Result<()> {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != security.owner_uid
            || metadata.mode() & 0o077 != 0
        {
            return UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("must be an owner-controlled mode-0600 regular file"),
            }
            .fail();
        }
        Ok(())
    }

    fn require_config_file(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
        security: DaemonSecurity,
    ) -> Result<()> {
        if !metadata.is_file()
            || metadata.uid() != security.owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("must be a root-owned non-world-writable regular file"),
            }
            .fail();
        }
        Ok(())
    }

    fn require_same_file(
        &self,
        path: &Path,
        before: &fs::Metadata,
        file: &File,
        action: &'static str,
    ) -> Result<()> {
        let after = file.metadata().context(IoSnafu { action, path })?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return UnsafePathSnafu {
                path: path.to_path_buf(),
                reason: String::from("changed while it was opened"),
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DaemonSecurity {
    pub owner_uid: u32,
    pub socket_gid: u32,
}

impl DaemonSecurity {
    #[cfg(test)]
    #[must_use]
    pub fn current_process() -> Self {
        Self {
            owner_uid: geteuid().as_raw(),
            socket_gid: getegid().as_raw(),
        }
    }
}

pub(crate) struct DaemonLock {
    file: File,
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _result = flock(&self.file, FlockOperation::Unlock);
    }
}
