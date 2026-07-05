use std::{fs, os::unix::fs::MetadataExt};

use super::manifest::FilesystemHostMetadata;

pub(super) fn host_metadata(metadata: &fs::Metadata) -> FilesystemHostMetadata {
    FilesystemHostMetadata {
        file_type: file_type(metadata),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn file_type(metadata: &fs::Metadata) -> String {
    if metadata.is_dir() {
        String::from("directory")
    } else if metadata.is_file() {
        String::from("regular")
    } else if metadata.file_type().is_symlink() {
        String::from("symlink")
    } else {
        String::from("special")
    }
}
