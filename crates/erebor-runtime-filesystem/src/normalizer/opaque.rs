use std::{fs, path::Path};

use snafu::ResultExt;

use crate::{
    error::ReadLayerPathSnafu,
    manifest::{FilesystemLayerEntry, FilesystemLayerOperation},
    metadata::FilesystemMetadataReader,
    overlay::OverlayMarkerProbe,
    FilesystemLayerMetadata, Result,
};

pub(super) struct OpaqueLayerNormalizer<'a> {
    path: &'a Path,
    relative: &'a str,
    metadata: &'a fs::Metadata,
}

impl<'a> OpaqueLayerNormalizer<'a> {
    pub(super) const fn new(path: &'a Path, relative: &'a str, metadata: &'a fs::Metadata) -> Self {
        Self {
            path,
            relative,
            metadata,
        }
    }

    pub(super) fn operation(&self) -> Result<Option<FilesystemLayerOperation>> {
        let Some(marker) = OverlayMarkerProbe::new(self.path).opaque_marker()? else {
            return Ok(None);
        };
        let entry = FilesystemLayerEntry::Directory {
            metadata: self.layer_metadata()?,
        };
        Ok(Some(FilesystemLayerOperation::OpaqueReplace {
            path: self.relative.to_owned(),
            entry,
            marker,
            replacement_entry_count: self.count_visible_entries(self.path)?,
        }))
    }

    fn count_visible_entries(&self, directory: &Path) -> Result<u64> {
        let mut count = 0_u64;
        for entry in fs::read_dir(directory).context(ReadLayerPathSnafu { path: directory })? {
            let entry = entry.context(ReadLayerPathSnafu { path: directory })?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).context(ReadLayerPathSnafu { path: &path })?;
            if OverlayMarkerProbe::new(&path).is_whiteout_entry(&metadata)? {
                continue;
            }
            count = count.saturating_add(1);
            if metadata.is_dir() {
                count = count.saturating_add(self.count_visible_entries(&path)?);
            }
        }
        Ok(count)
    }

    fn layer_metadata(&self) -> Result<FilesystemLayerMetadata> {
        FilesystemMetadataReader::new(self.path, self.metadata).layer_metadata()
    }
}
