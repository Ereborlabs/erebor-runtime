use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use snafu::ResultExt as _;

use crate::{IoSnafu, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StorageUsageV1 {
    pub file_bytes: u64,
    pub allocated_bytes: u64,
    pub available_bytes: u64,
}

impl StorageUsageV1 {
    pub(super) fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self> {
        let allocated_bytes = metadata.blocks().checked_mul(512).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path,
                reason: "allocated data bytes overflow",
            }
            .build()
        })?;
        Ok(Self {
            file_bytes: metadata.len().max(allocated_bytes),
            allocated_bytes,
            available_bytes: 0,
        })
    }

    pub(super) fn add(&mut self, other: Self, path: &Path) -> Result<()> {
        let file_bytes = self.file_bytes.checked_add(other.file_bytes);
        let allocated_bytes = self.allocated_bytes.checked_add(other.allocated_bytes);
        let (Some(file_bytes), Some(allocated_bytes)) = (file_bytes, allocated_bytes) else {
            return crate::AnalysisStateSnafu {
                path,
                reason: "data file bytes overflow",
            }
            .fail();
        };
        self.file_bytes = file_bytes;
        self.allocated_bytes = allocated_bytes;
        Ok(())
    }

    pub(super) fn subtract(&mut self, other: Self, path: &Path) -> Result<()> {
        let file_bytes = self.file_bytes.checked_sub(other.file_bytes);
        let allocated_bytes = self.allocated_bytes.checked_sub(other.allocated_bytes);
        let (Some(file_bytes), Some(allocated_bytes)) = (file_bytes, allocated_bytes) else {
            return crate::AnalysisStateSnafu {
                path,
                reason: "data file bytes underflow",
            }
            .fail();
        };
        self.file_bytes = file_bytes;
        self.allocated_bytes = allocated_bytes;
        Ok(())
    }

    pub(super) fn free_bytes(root: &Path) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        volume.f_bavail.checked_mul(volume.f_frsize).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the available storage size is invalid",
            }
            .build()
        })
    }
}

impl StorageUsageV1 {
    pub(super) fn at(root: &Path) -> Result<StorageUsageV1> {
        Self::inspect(root, None)
    }

    pub(super) fn inspect(
        root: &Path,
        raw: Option<&super::raw::RawJournal>,
    ) -> Result<StorageUsageV1> {
        let mut usage = StorageUsageV1 {
            available_bytes: StorageUsageV1::free_bytes(root)?,
            ..Default::default()
        };
        let known = raw.map(|raw| raw.storage_summary()).transpose()?.flatten();
        let segment_root = root.join("segments");
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let entry = entry.context(IoSnafu { path: &directory })?;
                let path = entry.path();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                if metadata.is_dir() {
                    if path == segment_root {
                        if let Some((segment_usage, _, _)) = known {
                            usage.add(segment_usage, root)?;
                        } else {
                            pending.push(path.clone());
                        }
                    } else {
                        pending.push(path.clone());
                    }
                } else if !metadata.is_file() {
                    return crate::Error::reject_path(
                        root,
                        "the data directory contains a non-file entry",
                    );
                }
                usage.add(StorageUsageV1::from_metadata(&path, &metadata)?, root)?;
            }
        }
        Ok(usage)
    }
}
