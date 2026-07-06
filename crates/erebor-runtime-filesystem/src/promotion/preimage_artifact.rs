use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{PromotionIoSnafu, PromotionPreimageBackendUnavailableSnafu},
    metadata::FilesystemPathMetadataCopier,
    FilesystemError, FilesystemPreimageBackendKind, Result,
};

use super::{manifest::FilesystemRegularPreimage, path::PromotionTargetPath};

pub(super) struct LinuxReflinkPreimageStore<'a> {
    work_root: &'a Path,
    volume_id: &'a str,
}

impl<'a> LinuxReflinkPreimageStore<'a> {
    pub(super) const fn new(work_root: &'a Path, volume_id: &'a str) -> Self {
        Self {
            work_root,
            volume_id,
        }
    }

    pub(super) fn capture_file(
        &self,
        artifact_root: &Path,
        path: &str,
        source: &Path,
        relative: &Path,
    ) -> Result<FilesystemRegularPreimage> {
        let artifact = artifact_root.join("files").join(relative);
        PromotionTargetPath::new(&artifact).create_parent()?;
        if artifact.exists() {
            fs::remove_file(&artifact).context(PromotionIoSnafu {
                action: "remove stale linux reflink preimage artifact",
                path: artifact.as_path(),
            })?;
        }

        self.reflink_file(path, source, &artifact)?;
        FilesystemPathMetadataCopier::new(source, &artifact).copy()?;
        let metadata = fs::symlink_metadata(&artifact).context(PromotionIoSnafu {
            action: "inspect linux reflink preimage artifact",
            path: artifact.as_path(),
        })?;
        Ok(FilesystemRegularPreimage::LinuxReflink {
            artifact: self.manifest_artifact_path(&artifact, path)?,
            size_bytes: metadata.len(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(super) fn validate_regular_preimage(
        &self,
        path: &str,
        preimage: &FilesystemRegularPreimage,
    ) -> Result<Option<PathBuf>> {
        match preimage {
            FilesystemRegularPreimage::OstreeBytes => Ok(None),
            FilesystemRegularPreimage::LinuxReflink {
                artifact,
                size_bytes,
                mtime_sec,
                mtime_nsec,
                device,
                inode,
            } => {
                let artifact_path = self.artifact_path(path, artifact)?;
                let metadata = fs::symlink_metadata(&artifact_path).map_err(|source| {
                    self.invalid_artifact(
                        path,
                        &artifact_path,
                        format!("artifact cannot be inspected: {source}"),
                    )
                })?;
                if !metadata.is_file() {
                    return Err(self.invalid_artifact(
                        path,
                        &artifact_path,
                        "artifact is not a regular file",
                    ));
                }
                if metadata.len() != *size_bytes
                    || metadata.mtime() != *mtime_sec
                    || metadata.mtime_nsec() != *mtime_nsec
                    || metadata.dev() != *device
                    || metadata.ino() != *inode
                {
                    return Err(self.invalid_artifact(
                        path,
                        &artifact_path,
                        "artifact metadata drifted",
                    ));
                }
                Ok(Some(artifact_path))
            }
        }
    }

    fn reflink_file(&self, path: &str, source: &Path, artifact: &Path) -> Result<()> {
        let source_file = File::open(source).context(PromotionIoSnafu {
            action: "open linux reflink preimage source",
            path: source,
        })?;
        let artifact_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(artifact)
            .context(PromotionIoSnafu {
                action: "create linux reflink preimage artifact",
                path: artifact,
            })?;

        match Self::clone_file_data(&artifact_file, &source_file) {
            Ok(()) => Ok(()),
            Err(reason) => {
                let _result = fs::remove_file(artifact);
                PromotionPreimageBackendUnavailableSnafu {
                    volume_id: self.volume_id.to_owned(),
                    path: path.to_owned(),
                    backend: FilesystemPreimageBackendKind::LinuxReflink.as_str(),
                    reason,
                }
                .fail()
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn clone_file_data(target: &File, source: &File) -> std::result::Result<(), String> {
        rustix::fs::ioctl_ficlone(target, source)
            .map_err(|error| format!("FICLONE failed: {}", std::io::Error::from(error)))
    }

    #[cfg(not(target_os = "linux"))]
    fn clone_file_data(_target: &File, _source: &File) -> std::result::Result<(), String> {
        Err(String::from("FICLONE is only supported on Linux"))
    }

    fn manifest_artifact_path(&self, artifact: &Path, path: &str) -> Result<String> {
        let relative = artifact.strip_prefix(self.work_root).map_err(|_| {
            PromotionPreimageBackendUnavailableSnafu {
                volume_id: self.volume_id.to_owned(),
                path: path.to_owned(),
                backend: FilesystemPreimageBackendKind::LinuxReflink.as_str(),
                reason: String::from("artifact is outside filesystem work root"),
            }
            .build()
        })?;
        relative.to_str().map(String::from).ok_or_else(|| {
            PromotionPreimageBackendUnavailableSnafu {
                volume_id: self.volume_id.to_owned(),
                path: path.to_owned(),
                backend: FilesystemPreimageBackendKind::LinuxReflink.as_str(),
                reason: String::from("artifact path is not valid UTF-8"),
            }
            .build()
        })
    }

    fn artifact_path(&self, path: &str, artifact: &str) -> Result<PathBuf> {
        let relative = Self::relative_artifact_path(artifact).map_err(|reason| {
            self.invalid_artifact(path, &self.work_root.join(artifact), reason)
        })?;
        Ok(self.work_root.join(relative))
    }

    fn relative_artifact_path(value: &str) -> std::result::Result<PathBuf, String> {
        let path = Path::new(value);
        if path.as_os_str().is_empty() {
            return Err(String::from("artifact path is empty"));
        }
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return Err(String::from("artifact path is not a safe relative path"));
                }
            }
        }
        Ok(relative)
    }

    fn invalid_artifact(
        &self,
        path: &str,
        artifact: &Path,
        reason: impl Into<String>,
    ) -> FilesystemError {
        FilesystemError::PromotionPreimageArtifactInvalid {
            volume_id: self.volume_id.to_owned(),
            path: path.to_owned(),
            artifact: artifact.to_path_buf(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }
}
