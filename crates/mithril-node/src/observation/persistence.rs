use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use snafu::ResultExt as _;

use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::Result;

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "evidence state path has no parent".to_owned(),
        }
        .build()
    })?;
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
        sync_directory(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    sync_directory(parent)
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .context(IoSnafu { path })?
        .sync_all()
        .context(IoSnafu { path })
}
