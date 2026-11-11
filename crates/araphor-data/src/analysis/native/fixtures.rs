use std::path::Path;

use snafu::ResultExt as _;

use super::{records::Records, source::Sources, NativeStore, HEAD, SCHEMA};
use crate::{EvidenceIntakeIdentityV1, NativeStateSnafu, NativeStorageSnafu, Result};

pub enum StorageFault {
    Receipt(EvidenceIntakeIdentityV1, u64),
    Schema(u32),
    RawEnd(u64),
}

impl NativeStore {
    pub fn set_commit_hook(
        &self,
        stage: crate::AnalysisCommitStage,
        callback: impl FnOnce() -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let mut slot = self.commit_hook.lock()
            .map_err(|_| NativeStateSnafu { field: "commit hook lock" }.build())?;
        if slot.is_some() {
            return crate::Error::reject_path(&self.root, "a commit hook is already installed");
        }
        *slot = Some(crate::analysis::CommitHook { stage, callback: Box::new(callback) });
        Ok(())
    }

    pub(in crate::analysis::native) fn run_commit_hook(&self, stage: crate::AnalysisCommitStage) -> Result<()> {
        let mut slot = self.commit_hook.lock()
            .map_err(|_| NativeStateSnafu { field: "commit hook lock" }.build())?;
        let hook = if slot.as_ref().is_some_and(|hook| hook.stage == stage) {
            slot.take()
        } else { None };
        drop(slot);
        if let Some(hook) = hook { (hook.callback)()?; }
        Ok(())
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::analysis) fn crash_path(root: &Path, point: &str) {
        if std::env::var("ARAPHOR_CRASH_POINT").as_deref() == Ok(point)
            && std::env::var_os("ARAPHOR_CRASH_ROOT").is_some_and(|value| Path::new(&value) == root)
        { std::process::exit(73); }
    }

    pub fn corrupt_fixture(root: &Path, fault: &StorageFault) -> Result<()> {
        let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall")).open()
            .context(NativeStorageSnafu { operation: "open corruption fixture" })?;
        let branch = database.branch("data").context(NativeStorageSnafu { operation: "read corruption branch" })?
            .ok_or_else(|| NativeStateSnafu { field: "corruption branch" }.build())?;
        let mut tx = branch.write_tx().context(NativeStorageSnafu { operation: "begin corruption fixture" })?;
        let head = tx.get(HEAD).context(NativeStorageSnafu { operation: "read corruption cut" })?
            .ok_or_else(|| NativeStateSnafu { field: "corruption head" }.build())?;
        let head = Self::number(&head)?;
        match fault {
            StorageFault::Receipt(identity, cursor) => {
                let key = Sources::key(Sources::RECEIPTS, &identity.key());
                let bytes = Records::payload(&key, |key| Records::staged(key, &tx))?
                    .ok_or_else(|| NativeStateSnafu { field: "receipt corruption target" }.build())?;
                let mut receipt: crate::AnalysisSourceReceiptV1 = Records::decode(&bytes)?;
                receipt.contiguous_cursor = *cursor;
                Records::stage(&mut tx, key, Records::encode(&receipt)?);
            }
            StorageFault::Schema(version) => { tx.insert(SCHEMA, u64::from(*version).to_be_bytes()); }
            StorageFault::RawEnd(id) => {
                let key = Sources::key(Sources::ENDS, &id.to_be_bytes());
                if tx.get(&key).context(NativeStorageSnafu { operation: "read raw corruption target" })?.is_none() {
                    return NativeStateSnafu { field: "raw corruption target" }.fail();
                }
                tx.remove(key);
            }
        }
        tx.commit_stamped([Self::cut(head)]).context(NativeStorageSnafu { operation: "commit corruption fixture" })?;
        Ok(())
    }
}
