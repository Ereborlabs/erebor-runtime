use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream as StandardUnixStream;
use std::path::{Path, PathBuf};

use rustix::{
    fs::chown,
    process::{geteuid, Uid},
};
use snafu::{ensure, ResultExt as _};
use tokio::net::UnixListener;

use crate::error::{IdentityStateSnafu, IoSnafu};
use crate::Result;

/// This owner removes only the socket inode that it created.
pub(crate) struct UnixSocketPathOwner {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl UnixSocketPathOwner {
    pub(crate) fn bind(path: &Path, allowed_uid: u32) -> Result<(UnixListener, Self)> {
        let parent = path.parent().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "Unix socket has no parent directory".to_owned(),
            }
            .build()
        })?;
        fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        let parent_metadata = fs::metadata(parent).context(IoSnafu { path: parent })?;
        let process_uid = geteuid().as_raw();
        ensure!(
            parent_metadata.is_dir()
                && parent_metadata.uid() == process_uid
                && parent_metadata.mode() & 0o022 == 0,
            IdentityStateSnafu {
                reason: format!(
                    "Unix socket parent must be process-owned and not group-writable or world-writable (owner {}, process {}, mode {:o})",
                    parent_metadata.uid(),
                    process_uid,
                    parent_metadata.mode() & 0o777,
                ),
            }
        );
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == allowed_uid,
                IdentityStateSnafu {
                    reason: "Unix socket path is occupied by an unsafe object",
                }
            );
            remove_stale_socket(path)?;
        }
        let listener = UnixListener::bind(path).context(IoSnafu { path })?;
        chown(path, Some(Uid::from_raw(allowed_uid)), None)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).context(IoSnafu { path })?;
        let metadata = fs::symlink_metadata(path).context(IoSnafu { path })?;
        ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == allowed_uid
                && metadata.mode() & 0o777 == 0o600,
            IdentityStateSnafu {
                reason: "Unix socket ownership or mode is invalid",
            }
        );
        Ok((
            listener,
            Self {
                path: path.to_path_buf(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        ))
    }
}

impl Drop for UnixSocketPathOwner {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        // Packaging can unlink the old endpoint before a replacement binds.
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _result = fs::remove_file(&self.path);
        }
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    // A successful connect proves that another process still owns the listener.
    match StandardUnixStream::connect(path) {
        Ok(_stream) => IdentityStateSnafu {
            reason: "another Unix socket owner is active".to_owned(),
        }
        .fail(),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path).context(IoSnafu { path })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => IdentityStateSnafu {
            reason: format!("Unix socket ownership is not provable: {error}"),
        }
        .fail(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener as StandardUnixListener;

    use super::UnixSocketPathOwner;

    fn current_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[tokio::test]
    async fn stale_socket_is_recovered_and_live_owner_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("owner.sock");
        let stale = StandardUnixListener::bind(&socket)?;
        drop(stale);

        let (_listener, owner) = UnixSocketPathOwner::bind(&socket, current_uid())?;
        assert!(UnixSocketPathOwner::bind(&socket, current_uid()).is_err());
        drop(owner);
        assert!(!socket.exists());
        Ok(())
    }

    #[tokio::test]
    async fn old_owner_cannot_remove_a_replacement_inode() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("replacement.sock");
        let (_old_listener, old_owner) = UnixSocketPathOwner::bind(&socket, current_uid())?;
        fs::remove_file(&socket)?;
        let (_new_listener, new_owner) = UnixSocketPathOwner::bind(&socket, current_uid())?;

        drop(old_owner);
        assert!(socket.exists());
        drop(new_owner);
        assert!(!socket.exists());
        Ok(())
    }
}
