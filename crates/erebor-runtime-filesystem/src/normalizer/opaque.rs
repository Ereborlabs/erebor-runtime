use std::{fs, path::Path};

use snafu::ResultExt;

use crate::{
    error::ReadLayerPathSnafu,
    manifest::{FilesystemLayerEntry, FilesystemLayerOperation},
    metadata, overlay, FilesystemLayerMetadata, Result,
};

pub(super) fn opaque_operation(
    path: &Path,
    relative: &str,
    metadata: &fs::Metadata,
) -> Result<Option<FilesystemLayerOperation>> {
    let Some(marker) = overlay::opaque_marker(path)? else {
        return Ok(None);
    };
    let entry = FilesystemLayerEntry::Directory {
        metadata: layer_metadata(path, metadata)?,
    };
    Ok(Some(FilesystemLayerOperation::OpaqueReplace {
        path: relative.to_owned(),
        entry,
        marker,
        replacement_entry_count: count_visible_entries(path)?,
    }))
}

fn count_visible_entries(directory: &Path) -> Result<u64> {
    let mut count = 0_u64;
    for entry in fs::read_dir(directory).context(ReadLayerPathSnafu { path: directory })? {
        let entry = entry.context(ReadLayerPathSnafu { path: directory })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).context(ReadLayerPathSnafu { path: &path })?;
        if overlay::is_whiteout_entry(&path, &metadata)? {
            continue;
        }
        count = count.saturating_add(1);
        if metadata.is_dir() {
            count = count.saturating_add(count_visible_entries(&path)?);
        }
    }
    Ok(count)
}

fn layer_metadata(path: &Path, metadata: &fs::Metadata) -> Result<FilesystemLayerMetadata> {
    metadata::layer_metadata(path, metadata)
}
