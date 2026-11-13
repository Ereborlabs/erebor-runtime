use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt as _;

use super::NativeStore;
use crate::{AnalysisBackupFileV1, AnalysisBackupManifestV1, IoSnafu, NativeStateSnafu, Result};

impl NativeStore {
    pub(super) fn private_directory(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).context(IoSnafu { path })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return crate::Error::reject_path(path, "the backup directory is not private");
        }
        Ok(())
    }

    pub(super) fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path })
    }

    pub(super) fn bundle_file(path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .context(IoSnafu { path })?;
        let metadata = file.metadata().context(IoSnafu { path })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return crate::Error::reject_path(
                path,
                "the backup input is not a private regular file",
            );
        }
        Ok(file)
    }

    pub(super) fn copy_bundle_file(source: &Path, target: &Path, bytes: u64) -> Result<()> {
        let input = Self::bundle_file(source)?;
        if input.metadata().context(IoSnafu { path: source })?.len() != bytes {
            return crate::Error::reject_path(
                source,
                "the backup input size differs from its manifest",
            );
        }
        let bound = bytes.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "backup file size",
            }
            .build()
        })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
            .context(IoSnafu { path: target })?;
        if std::io::copy(&mut input.take(bound), &mut output).context(IoSnafu { path: target })?
            != bytes
        {
            return crate::Error::reject_path(source, "the backup input changed size during copy");
        }
        output
            .flush()
            .and_then(|()| output.sync_all())
            .context(IoSnafu { path: target })
    }

    pub(super) fn checkpoint_files(
        root: &Path,
        normalize: bool,
    ) -> Result<Vec<AnalysisBackupFileV1>> {
        let mut pending = vec![root.to_owned()];
        let mut directories = BTreeSet::new();
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            if normalize {
                let metadata =
                    fs::symlink_metadata(&directory).context(IoSnafu { path: &directory })?;
                if !metadata.is_dir() {
                    return crate::Error::reject_path(
                        &directory,
                        "the checkpoint directory is invalid",
                    );
                }
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                    .context(IoSnafu { path: &directory })?;
            }
            Self::private_directory(&directory)?;
            for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let path = entry.context(IoSnafu { path: &directory })?.path();
                let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
                let name = path
                    .strip_prefix(root)
                    .map_err(|_| {
                        NativeStateSnafu {
                            field: "checkpoint path",
                        }
                        .build()
                    })?
                    .to_str()
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "checkpoint file name",
                        }
                        .build()
                    })?
                    .to_owned();
                if metadata.is_dir() {
                    directories.insert(PathBuf::from(&name));
                    pending.push(path);
                } else if metadata.is_file() {
                    if normalize {
                        let file = OpenOptions::new()
                            .read(true)
                            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                            .open(&path)
                            .context(IoSnafu { path: &path })?;
                        file.set_permissions(fs::Permissions::from_mode(0o600))
                            .and_then(|()| file.sync_all())
                            .context(IoSnafu { path: &path })?;
                    }
                    let mut file = Self::bundle_file(&path)?;
                    let mut buffer = [0u8; 64 * 1024];
                    let mut bytes = 0u64;
                    let mut checksum = 0;
                    loop {
                        let count = file.read(&mut buffer).context(IoSnafu { path: &path })?;
                        if count == 0 {
                            break;
                        }
                        bytes = bytes.checked_add(count as u64).ok_or_else(|| {
                            NativeStateSnafu {
                                field: "checkpoint file size",
                            }
                            .build()
                        })?;
                        checksum = crc32c::crc32c_append(checksum, &buffer[..count]);
                    }
                    files.push(AnalysisBackupFileV1 {
                        file_name: name,
                        bytes,
                        crc32c: checksum,
                    });
                } else {
                    return crate::Error::reject_path(&path, "the checkpoint has a non-file entry");
                }
            }
            if normalize {
                Self::sync_directory(&directory)?;
            }
        }
        files.sort_unstable_by(|left, right| left.file_name.cmp(&right.file_name));
        if directories != Self::checkpoint_dirs(&files)? {
            return crate::Error::reject_path(
                root,
                "the checkpoint directory inventory differs from its files",
            );
        }
        Ok(files)
    }

    pub(super) fn checkpoint_dirs(files: &[AnalysisBackupFileV1]) -> Result<BTreeSet<PathBuf>> {
        let mut directories = BTreeSet::new();
        for file in files {
            let name = Path::new(&file.file_name);
            if name.as_os_str().is_empty()
                || !name
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                || name.to_str() != Some(&file.file_name)
            {
                return NativeStateSnafu {
                    field: "checkpoint relative path",
                }
                .fail();
            }
            let mut parent = name.parent();
            while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
                directories.insert(path.to_owned());
                parent = path.parent();
            }
            if let Some(tree) = name
                .parent()
                .filter(|path| path.parent() == Some(Path::new("keyspaces")))
            {
                directories.insert(tree.join("tables"));
                directories.insert(tree.join("blobs"));
            }
        }
        Ok(directories)
    }

    pub(super) fn validate_bundle(manifest: &AnalysisBackupManifestV1, root: &Path) -> Result<()> {
        if manifest.schema_version != crate::analysis::ANALYSIS_SCHEMA_VERSION as u32
            || uuid::Uuid::parse_str(&manifest.store_uuid).is_err()
            || manifest.recovery_epoch == 0
            || manifest.database_files.is_empty()
            || manifest
                .database_files
                .windows(2)
                .any(|pair| pair[0].file_name >= pair[1].file_name)
            || manifest
                .segments
                .windows(2)
                .any(|pair| pair[0].segment_id >= pair[1].segment_id)
            || manifest.segments.iter().any(|segment| {
                segment.segment_id == 0
                    || segment.bytes < 70
                    || segment.file_name
                        != format!("{:016x}.d.{:016x}.seg", segment.segment_id, segment.bytes)
            })
        {
            return crate::Error::reject_path(
                root,
                "the backup manifest identity or bounds are invalid",
            );
        }
        Self::private_directory(root)?;
        Self::private_directory(&root.join("segments"))?;
        let files = Self::checkpoint_files(&root.join("fjall"), false)?;
        if files != manifest.database_files
            || files
                .iter()
                .try_fold(0u64, |bytes, file| bytes.checked_add(file.bytes))
                != Some(manifest.database_bytes)
        {
            return crate::Error::reject_path(root, "the checkpoint differs from its manifest");
        }
        let committed = manifest
            .segments
            .iter()
            .map(|segment| (segment.segment_id, segment.bytes))
            .collect::<BTreeMap<_, _>>();
        let raw = crate::analysis::raw::RawJournal::read_sealed(root, &committed)?;
        if raw.index.revision > manifest.commit_revision
            || raw.segments.len() != manifest.segments.len()
            || raw
                .segments
                .iter()
                .zip(&manifest.segments)
                .any(|((id, raw), saved)| {
                    *id != saved.segment_id
                        || raw.end != saved.bytes
                        || raw.path.file_name().and_then(|name| name.to_str())
                            != Some(&saved.file_name)
                })
        {
            return crate::Error::reject_path(root, "the raw checkpoint differs from its manifest");
        }
        for entry in fs::read_dir(root).context(IoSnafu { path: root })? {
            let entry = entry.context(IoSnafu { path: root })?;
            if !matches!(
                entry.file_name().to_str(),
                Some("segments" | "fjall" | "manifest.json")
            ) {
                return crate::Error::reject_path(root, "the backup has an unlisted entry");
            }
        }
        Ok(())
    }
}
