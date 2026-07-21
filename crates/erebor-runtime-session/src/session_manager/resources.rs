use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use erebor_runtime_core::{OutputEndpoints, SafePathBinding, SafePathKind, SessionSpec};
use rustix::{
    fs::{makedev, open, statx, AtFlags, FileType, Mode, OFlags, StatxFlags},
    mount::{mount_bind, mount_remount, unmount, MountFlags, UnmountFlags},
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use uuid::Uuid;

use crate::{
    error::session_manager::{OutputSnafu, RuntimeGuardSnafu, RuntimeIoSnafu},
    DurableStreamCursor, RuntimeGuardService, SessionInterceptionRouter, SessionManagerError,
    SessionOutputStores, StreamKind,
};

use super::output_endpoints;

const GUARD_CREDENTIAL_FILE: &str = "runtime-guard.json";

pub type SessionPathResolverError = crate::error::session_manager::SessionPathResolverError;

pub trait SessionPathResolver: Send + Sync {
    fn resolve(
        &self,
        uid: u32,
        gid: u32,
        path: &Path,
        kind: SafePathKind,
    ) -> Result<ResolvedSessionPath, SessionPathResolverError>;
}

pub trait SessionInterceptionRouterFactory: Send + Sync {
    fn router(&self, spec: &SessionSpec) -> SessionInterceptionRouter;
}

pub struct ResolvedSessionPath {
    descriptor: File,
    binding: SafePathBinding,
}

impl ResolvedSessionPath {
    #[must_use]
    pub const fn new(descriptor: File, binding: SafePathBinding) -> Self {
        Self {
            descriptor,
            binding,
        }
    }

    #[must_use]
    pub const fn descriptor(&self) -> &File {
        &self.descriptor
    }

    #[must_use]
    pub const fn binding(&self) -> &SafePathBinding {
        &self.binding
    }
}

pub struct SessionRuntimeResources {
    state_root: PathBuf,
    runtime_root: PathBuf,
    guard: RuntimeGuardService,
    path_resolver: Arc<dyn SessionPathResolver>,
    router_factory: Arc<dyn SessionInterceptionRouterFactory>,
}

impl SessionRuntimeResources {
    pub fn new(
        state_root: PathBuf,
        runtime_root: PathBuf,
        path_resolver: Arc<dyn SessionPathResolver>,
        router_factory: Arc<dyn SessionInterceptionRouterFactory>,
    ) -> Result<Self, SessionManagerError> {
        let guard = RuntimeGuardService::new(&runtime_root).context(RuntimeGuardSnafu)?;
        Ok(Self {
            state_root,
            runtime_root,
            guard,
            path_resolver,
            router_factory,
        })
    }

    fn prepare_staging(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<(PathBuf, Option<PathBuf>), SessionManagerError> {
        let staging = self.staging_path(spec);
        let workspace = staging.join("workspace");
        let executable = spec.executable().map(|_| staging.join("executable"));
        if recovering {
            self.verify_staging(spec, &workspace, spec.workspace())?;
            if let (Some(path), Some(binding)) = (&executable, spec.executable()) {
                self.verify_staging(spec, path, binding)?;
            }
            return Ok((workspace, executable));
        }

        let workspace_source = self.resolve(spec, spec.workspace())?;
        if workspace_source.binding() != spec.workspace() {
            return self
                .invalid_runtime(spec, "workspace identity changed after session admission");
        }
        let executable_source = spec
            .executable()
            .map(|binding| {
                let source = self.resolve(spec, binding)?;
                if source.binding() != binding {
                    return self.invalid_runtime(
                        spec,
                        "executable identity changed after session admission",
                    );
                }
                Ok(source)
            })
            .transpose()?;

        fs::create_dir_all(&staging).context(RuntimeIoSnafu {
            action: "creating daemon-owned session staging directory",
            path: &staging,
        })?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).context(
            RuntimeIoSnafu {
                action: "protecting daemon-owned session staging directory",
                path: &staging,
            },
        )?;
        fs::create_dir(&workspace).context(RuntimeIoSnafu {
            action: "creating workspace staging mountpoint",
            path: &workspace,
        })?;
        bind_descriptor(workspace_source.descriptor(), &workspace, false)?;

        if let (Some(target), Some(source)) = (&executable, executable_source.as_ref()) {
            File::create(target).context(RuntimeIoSnafu {
                action: "creating executable staging mountpoint",
                path: target,
            })?;
            bind_descriptor(source.descriptor(), target, true)?;
        }
        Ok((workspace, executable))
    }

    fn resolve(
        &self,
        spec: &SessionSpec,
        binding: &SafePathBinding,
    ) -> Result<ResolvedSessionPath, SessionManagerError> {
        self.path_resolver
            .resolve(
                spec.owner().uid(),
                spec.owner().gid(),
                binding.requested_path(),
                binding.kind(),
            )
            .map_err(|source| SessionManagerError::PathResolution {
                uid: spec.owner().uid(),
                gid: spec.owner().gid(),
                path: binding.requested_path().to_path_buf(),
                source,
                location: snafu::Location::default(),
            })
    }

    fn verify_staging(
        &self,
        spec: &SessionSpec,
        path: &Path,
        binding: &SafePathBinding,
    ) -> Result<(), SessionManagerError> {
        let descriptor = open(path, OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
            .map_err(std::io::Error::from)
            .context(RuntimeIoSnafu {
                action: "opening persistent session staging mount",
                path,
            })?;
        let status = statx(
            &descriptor,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "verifying persistent session staging mount",
            path,
        })?;
        let parent = path
            .parent()
            .ok_or_else(|| SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!("staging mount `{}` has no parent", path.display()),
                location: snafu::Location::default(),
            })?;
        let parent_descriptor = open(parent, OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
            .map_err(std::io::Error::from)
            .context(RuntimeIoSnafu {
                action: "opening persistent session staging parent",
                path: parent,
            })?;
        let parent_status = statx(
            &parent_descriptor,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "verifying persistent session staging parent",
            path: parent,
        })?;
        let file_type = FileType::from_raw_mode(status.stx_mode.into());
        let valid_kind = match binding.kind() {
            SafePathKind::Directory => file_type.is_dir(),
            SafePathKind::Executable => file_type.is_file() && status.stx_mode & 0o111 != 0,
            SafePathKind::File => file_type.is_file(),
        };
        if makedev(status.stx_dev_major, status.stx_dev_minor) != binding.device()
            || status.stx_ino != binding.inode()
            || status.stx_uid != binding.owner_uid()
            || status.stx_gid != binding.owner_gid()
            || !valid_kind
            || status.stx_mnt_id == parent_status.stx_mnt_id
        {
            return Err(SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!(
                    "staging mount `{}` no longer matches its admitted identity",
                    path.display()
                ),
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn guard_credential(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<GuardCredential, SessionManagerError> {
        let path = self.guard_credential_path(spec);
        if recovering || path.exists() {
            let encoded = fs::read(&path).context(RuntimeIoSnafu {
                action: "reading runtime guard credential",
                path: &path,
            })?;
            return serde_json::from_slice(&encoded).map_err(|source| {
                SessionManagerError::InvalidRuntime {
                    session_id: spec.session_id().as_str().to_owned(),
                    reason: format!(
                        "runtime guard credential `{}` is invalid: {source}",
                        path.display()
                    ),
                    location: snafu::Location::default(),
                }
            });
        }
        let credential = GuardCredential {
            schema_version: 1,
            token: Uuid::new_v4().simple().to_string(),
        };
        self.write_guard_credential(spec, &path, &credential)?;
        Ok(credential)
    }

    fn write_guard_credential(
        &self,
        spec: &SessionSpec,
        path: &Path,
        credential: &GuardCredential,
    ) -> Result<(), SessionManagerError> {
        let parent = path
            .parent()
            .ok_or_else(|| SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!("credential path `{}` has no parent", path.display()),
                location: snafu::Location::default(),
            })?;
        fs::create_dir_all(parent).context(RuntimeIoSnafu {
            action: "creating runtime guard credential directory",
            path: parent,
        })?;
        let temporary = path.with_extension("tmp");
        let encoded = serde_json::to_vec(credential).map_err(|source| {
            SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!(
                    "runtime guard credential `{}` cannot be encoded: {source}",
                    path.display()
                ),
                location: snafu::Location::default(),
            }
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(RuntimeIoSnafu {
                action: "writing runtime guard credential",
                path: &temporary,
            })?;
        file.write_all(&encoded).context(RuntimeIoSnafu {
            action: "writing runtime guard credential",
            path: &temporary,
        })?;
        file.sync_all().context(RuntimeIoSnafu {
            action: "syncing runtime guard credential",
            path: &temporary,
        })?;
        fs::rename(&temporary, path).context(RuntimeIoSnafu {
            action: "publishing runtime guard credential",
            path,
        })?;
        File::open(parent)
            .context(RuntimeIoSnafu {
                action: "opening runtime guard credential directory",
                path: parent,
            })?
            .sync_all()
            .context(RuntimeIoSnafu {
                action: "syncing runtime guard credential directory",
                path: parent,
            })
    }

    fn output_stores(
        &self,
        spec: &SessionSpec,
    ) -> Result<SessionOutputStores, SessionManagerError> {
        SessionOutputStores::open(spec.output()).context(OutputSnafu)
    }

    fn cleanup_staging(&self, spec: &SessionSpec) -> Result<(), SessionManagerError> {
        let staging = self.staging_path(spec);
        for target in [staging.join("executable"), staging.join("workspace")] {
            match unmount(&target, UnmountFlags::NOFOLLOW) {
                Ok(()) => {}
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOENT) => {}
                Err(error) => {
                    return Err(std::io::Error::from(error)).context(RuntimeIoSnafu {
                        action: "unmounting terminal session staging",
                        path: target,
                    });
                }
            }
        }
        match fs::remove_dir_all(&staging) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(RuntimeIoSnafu {
                    action: "removing terminal session staging",
                    path: staging,
                });
            }
        }
        let session_runtime = self.session_runtime_path(spec);
        match fs::remove_dir(&session_runtime) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(source) => {
                return Err(source).context(RuntimeIoSnafu {
                    action: "removing terminal session runtime directory",
                    path: session_runtime,
                });
            }
        }
        Ok(())
    }

    fn guard_credential_path(&self, spec: &SessionSpec) -> PathBuf {
        self.state_root
            .join("users")
            .join(spec.owner().uid().to_string())
            .join("sessions")
            .join(spec.session_id().as_str())
            .join(GUARD_CREDENTIAL_FILE)
    }

    fn session_runtime_path(&self, spec: &SessionSpec) -> PathBuf {
        self.runtime_root
            .join(spec.owner().uid().to_string())
            .join(spec.session_id().as_str())
    }

    fn staging_path(&self, spec: &SessionSpec) -> PathBuf {
        self.session_runtime_path(spec).join("staging")
    }

    fn invalid_runtime<T>(
        &self,
        spec: &SessionSpec,
        reason: impl Into<String>,
    ) -> Result<T, SessionManagerError> {
        Err(SessionManagerError::InvalidRuntime {
            session_id: spec.session_id().as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        })
    }
}

pub(super) trait SessionRuntime: Send + Sync {
    fn prepare(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<OutputEndpoints, SessionManagerError>;

    fn cleanup(&self, spec: &SessionSpec) -> Result<(), SessionManagerError>;

    fn stream(
        &self,
        spec: &SessionSpec,
        kind: StreamKind,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<DurableStreamCursor, SessionManagerError>;
}

impl SessionRuntime for SessionRuntimeResources {
    fn prepare(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<OutputEndpoints, SessionManagerError> {
        let (workspace, executable) = self.prepare_staging(spec, recovering)?;
        let _stores = self.output_stores(spec)?;
        let mut output = output_endpoints(spec).with_prepared_execution(workspace, executable);
        if spec.runner_capability().physical_interception() {
            let credential = self.guard_credential(spec, recovering)?;
            let endpoint = self
                .guard
                .start_session_with_token(
                    spec.owner().uid(),
                    spec.owner().gid(),
                    spec.session_id().as_str(),
                    "agent",
                    self.router_factory.router(spec),
                    Some(credential.token),
                )
                .context(RuntimeGuardSnafu)?;
            output = output.with_runtime_environment(endpoint.environment());
        }
        Ok(output)
    }

    fn cleanup(&self, spec: &SessionSpec) -> Result<(), SessionManagerError> {
        self.guard
            .stop_session(spec.owner().uid(), spec.session_id().as_str())
            .context(RuntimeGuardSnafu)?;
        let credential = self.guard_credential_path(spec);
        match fs::remove_file(&credential) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(RuntimeIoSnafu {
                    action: "removing terminal runtime guard credential",
                    path: credential,
                });
            }
        }
        self.cleanup_staging(spec)
    }

    fn stream(
        &self,
        spec: &SessionSpec,
        kind: StreamKind,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<DurableStreamCursor, SessionManagerError> {
        self.output_stores(spec)?
            .stream(kind)
            .read_after(after_sequence, maximum_records)
            .context(OutputSnafu)
    }
}

#[derive(Deserialize, Serialize)]
struct GuardCredential {
    schema_version: u32,
    token: String,
}

fn bind_descriptor(
    descriptor: &File,
    target: &Path,
    read_only: bool,
) -> Result<(), SessionManagerError> {
    let source = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
    mount_bind(&source, target)
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "bind-mounting a held descriptor into session staging",
            path: target,
        })?;
    let mut flags = MountFlags::BIND | MountFlags::NOSUID | MountFlags::NODEV;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    mount_remount(target, flags, "")
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "locking session staging mount flags",
            path: target,
        })
}
