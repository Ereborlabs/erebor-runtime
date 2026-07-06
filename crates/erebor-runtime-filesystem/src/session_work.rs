use crate::{FilesystemSessionStorage, Result};

mod catalog;
mod commit;
mod id;
mod manifest;
mod rollback;
mod state;

#[cfg(test)]
mod tests;

pub use catalog::{
    FilesystemSessionWorkCatalog, FilesystemSessionWorkChange, FilesystemSessionWorkSubtransaction,
    FilesystemSessionWorkTarget, FilesystemSessionWorkTransaction,
    FilesystemSessionWorkTransactionState,
};
pub use commit::{
    FilesystemSessionWorkCommit, FilesystemSessionWorkCommitRequest,
    FilesystemSessionWorkCommitSource, FilesystemSessionWorkCommitter,
};
pub use manifest::{
    FilesystemSessionWorkManifest, FilesystemSessionWorkVolume, SESSION_WORK_MANIFEST_FILE,
    SESSION_WORK_MANIFEST_KIND,
};
pub use rollback::FilesystemSessionWorkRollback;
pub use state::FilesystemSessionWorkRename;

impl FilesystemSessionStorage {
    pub fn commit_session_work(
        &self,
        request: FilesystemSessionWorkCommitRequest,
    ) -> Result<FilesystemSessionWorkCommit> {
        FilesystemSessionWorkCommitter::commit(self, request)
    }
}
