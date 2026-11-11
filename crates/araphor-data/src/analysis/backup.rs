use std::io::Read as _;
use std::path::Path;


use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate :: { IoSnafu , Result } ;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupManifestV1 {
    pub store_uuid: String,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
    pub database_bytes: u64,
    pub database_files: Vec<AnalysisBackupFileV1>,
    pub reserved_bytes: u64,
    pub reserved_entries: usize,
    pub segments: Vec<AnalysisBackupSegmentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupSegmentV1 {
    pub segment_id: u64,
    pub file_name: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupFileV1 {
    pub file_name: String,
    pub bytes: u64,
    pub crc32c: u32,
}

impl AnalysisBackupManifestV1 {
    pub(in crate::analysis) fn copy_bytes(&self, root: &Path, manifest_bytes: u64) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        self.database_files.iter().map(|file| file.bytes)
            .chain([manifest_bytes])
            .chain(self.segments.iter().map(|segment| segment.bytes))
            .try_fold(0_u64, |total, bytes| {
                total.checked_add(bytes.checked_next_multiple_of(volume.f_frsize)?)
            })
            .ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the backup allocation size is invalid",
                }
                .build()
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisRecoveryStatusV1 {
    Complete,
    Partial { first_cursor: u64, last_cursor: u64 },
}



#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;

    use super::*;
    use crate::{EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1};

    fn identity() -> EvidenceIntakeIdentityV1 {
        crate::analysis::tests::identity()
    }

    fn batch(cursor: u64) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 1_000_000_000,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        }
    }

    #[test]
    fn observability_backup_incomplete() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        use crate::{AnalysisReadControl, TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let intent = trace_intent()?;
        let trace = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let frame = TraceFrameV1 {
            execution_id: trace.execution_id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"output".to_vec(),
        };
        let mut input = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![frame.clone()],
            terminal: None,
        };
        let receipt = store.append_trace(trace, &input, 200)?;
        let before = store.read_trace(trace, 1, &AnalysisReadControl::default())?;
        let backup = root.join("backups/saved");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.segments.len(), 2);
        let trace_file = manifest
            .segments
            .iter()
            .find(|segment| segment.file_name.split('.').nth(1) == Some("d"))
            .ok_or("diagnostic backup segment absent")?;
        let path = super::super::raw::RawJournal::file_path(&backup, &trace_file.file_name)?;
        let moved = directory.path().join("saved-segment");
        fs::rename(&path, &moved)?;
        let target = directory.path().join("restored");
        assert!(AnalysisStore::restore(&backup, &target).is_err());
        assert!(!target.exists());
        fs::rename(&moved, &path)?;
        input.frames[0].sequence = 2;
        store.append_trace(trace, &input, 201)?;
        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
        assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
        assert_eq!(restored.trace_receipt(trace)?, Some(receipt));
        assert_eq!(
            restored
                .trace_intent(intent.tenant_id, intent.request_id)?
                .ok_or("intent absent")?
                .1,
            intent
        );
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame.clone()]);
        assert_eq!(page.positions, before.positions);
        assert_eq!(page.terminal, None);
        let terminal = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(1, 6)),
        };
        let receipt = restored.append_trace(trace, &terminal, 202)?;
        assert_eq!(
            store
                .trace_receipt(trace)?
                .ok_or("receipt absent")?
                .last_sequence,
            2
        );
        assert!(store
            .trace_receipt(trace)?
            .ok_or("receipt absent")?
            .terminal
            .is_none());
        drop(restored);
        let restored = AnalysisStore::open(&target)?;
        assert_eq!(restored.append_trace(trace, &terminal, 203)?, receipt);
        let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame]);
        assert_eq!(page.terminal, terminal.terminal);
        Ok(())
    }

    #[test]
    fn backup_manifest_limit_is_optional() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let mut store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let backup = root.join("backups/first");
        let manifest = store.backup(&backup)?;
        let bytes = fs::metadata(backup.join("manifest.json"))?.len();
        let limits = StorageLimitsV1 {
            manifest_max_bytes: Some(bytes - 1),
            ..Default::default()
        };
        store.storage = limits;
        let before = store.meta()?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "backup manifest bytes",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.meta()?, before);
        let restored = directory.path().join("restored");
        assert!(matches!(
            AnalysisStore::restore_with_limits(&backup, &restored, limits),
            Err(crate::Error::StorageCapacity {
                resource: "backup manifest bytes",
                ..
            })
        ));
        assert!(!restored.exists());
        let entries = StorageLimitsV1 {
            storage_entries: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            AnalysisStore::restore_with_limits(&backup, &restored, entries),
            Err(crate::Error::StorageCapacity {
                resource: "storage entries",
                ..
            })
        ));
        assert!(!restored.exists());
        let store = AnalysisStore::restore(&backup, &restored)?;
        assert_eq!(store.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn backup_accounts_manifest_allocation() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let mut store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let manifest = store.backup(&root.join("backups/first"))?;
        let bytes = serde_json::to_vec(&manifest)?.len() as u64;
        let block = rustix::fs::statvfs(&root)?.f_frsize;
        let allocated = bytes
            .checked_next_multiple_of(block)
            .ok_or("allocation overflow")?;
        assert!(allocated > bytes);
        let copied = manifest.copy_bytes(&root, 0)?;
        let actual = manifest.copy_bytes(&root, bytes)?;
        assert_eq!(
            actual,
            copied.checked_add(allocated).ok_or("copy overflow")?
        );
        let usage = store.storage_usage()?;
        let unrounded = copied.checked_add(bytes).ok_or("copy overflow")?;
        store.storage = StorageLimitsV1 {
            disk_max_bytes: Some(
                usage
                    .file_bytes
                    .checked_add(unrounded)
                    .ok_or("quota overflow")?,
            ),
            ..Default::default()
        };
        store.storage.check_backup(usage, unrounded)?;
        let before = store.meta()?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.meta()?, before);
        let usage = store.storage_usage()?;
        store.storage.disk_max_bytes = Some(
            usage
                .file_bytes
                .checked_add(actual)
                .ok_or("quota overflow")?,
        );
        store.storage.check_backup(usage, actual)?;
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert!(fs::read_dir(root.join("backups"))?.all(|entry| entry
            .is_ok_and(|entry| { !entry.file_name().to_string_lossy().starts_with(".backup-") })));
        let limits = StorageLimitsV1 {
            policy_reserve_bytes: Some(1),
            ..Default::default()
        };
        assert!(limits.check_copy(actual, actual).is_err());
        limits.check_copy(actual.checked_add(1).ok_or("reserve overflow")?, actual)?;
        Ok(())
    }

    #[test]
    fn observability_backup_reserve() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        use crate::{TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = StorageLimitsV1 {
            disk_max_bytes: Some(1024 * 1024 * 1024),
            ..StorageLimitsV1::fixture()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        let intent = trace_intent()?;
        let trace = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let input = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: trace.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        };
        let receipt = store.append_trace(trace, &input, 200)?;
        let manifest = store.backup(&root.join("backups/first"))?;
        let copy_bytes = manifest.copy_bytes(&root, serde_json::to_vec(&manifest)?.len() as u64)?;
        let usage = store.storage_usage()?;
        let padding = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("quota"))?;
        padding.set_len(
            limits.disk_max_bytes.ok_or("configured disk limit")?
                - 256 * 1024 * 1024
                - usage.file_bytes
                - copy_bytes
                - 8192,
        )?;
        limits.check_backup(store.storage_usage()?, copy_bytes)?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.trace_receipt(trace)?, Some(receipt.clone()));
        padding.set_len(0)?;
        let held = root.join("backups/held");
        DirBuilder::new().mode(0o700).create(&held)?;
        for index in 0..limits.diagnostic_entries.ok_or("configured entry limit")? - 3 {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(held.join(format!("{index:016x}.d.reserve")))?;
        }
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "diagnostic storage entries",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.trace_receipt(trace)?, Some(receipt));
        fs::rename(
            held.join("0000000000000000.d.reserve"),
            directory.path().join("saved-entry"),
        )?;
        store.backup(&blocked)?;
        assert_eq!(
            store.accept_validated_batch(identity(), batch(1))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let terminal = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(1, 1)),
        };
        assert_eq!(
            store.append_trace(trace, &terminal, 201)?.terminal,
            terminal.terminal
        );
        Ok(())
    }

    #[test]
    fn analysis_store_backup_quota() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = StorageLimitsV1 {
            disk_max_bytes: Some(1024 * 1024 * 1024),
            ..StorageLimitsV1::fixture()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        store.accept_validated_batch(identity(), batch(1))?;
        store.checkpoint()?;
        let before = store.storage_usage()?;
        let meta = store.meta()?;
        for invalid in [
            directory.path().join("outside.duckdb"),
            root.join("analysis.duckdb"),
            root.join("backups/nested/copy.duckdb"),
            root.join("backups/../escape.duckdb"),
            root.join("backups/copy.manifest.json"),
        ] {
            assert!(store.backup(&invalid).is_err());
        }
        let backup = root.join("backups/first");
        let manifest = store.backup(&backup)?;
        let saved = fs::read(backup.join("analysis.duckdb"))?;
        let usage = store.storage_usage()?;
        assert!(usage.file_bytes >= before.file_bytes + manifest.database_bytes);
        assert!(usage.allocated_bytes > before.allocated_bytes);
        assert_eq!(
            fs::metadata(root.join("backups"))?.permissions().mode() & 0o777,
            0o700
        );
        assert!(store.storage_with_entries(4096).is_err());
        let padding = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota"))?;
        padding.set_len(limits.disk_max_bytes.ok_or("configured disk limit")?)?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert!(!blocked.join("manifest.json").exists());
        assert_eq!(store.meta()?, meta);
        assert_eq!(fs::read(backup.join("analysis.duckdb"))?, saved);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        padding.set_len(0)?;
        store.backup(&blocked)?;
        let usage = store.storage_usage()?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        assert_eq!(store.storage_usage()?.file_bytes, usage.file_bytes);
        assert_eq!(store.meta()?, meta);
        let external = directory.path().join("external");
        fs::rename(&backup, &external)?;
        let restored = AnalysisStore::restore(&external, &directory.path().join("restored"))?;
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_backup_window() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::{sync::mpsc, thread, time::Duration};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let meta = store.meta()?;
        let backups = root.join("backups");
        let destination = backups.join("saved");
        let reader = store.reader()?;
        let (sender, receiver) = mpsc::channel();
        thread::scope(
            |scope| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let worker = scope.spawn(|| {
                    sender
                        .send(store.backup(&destination))
                        .map_err(|_| "backup receiver closed")
                });
                let pending = receiver.recv_timeout(Duration::from_millis(50));
                drop(reader);
                assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
                let manifest = receiver.recv_timeout(Duration::from_secs(10))??;
                assert_eq!(manifest.commit_revision, meta.commit_revision);
                worker.join().map_err(|_| "backup panicked")??;
                Ok(())
            },
        )?;
        assert_eq!(store.meta()?, meta);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        let saved = fs::read(destination.join("analysis.duckdb"))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(store.backup(&destination).is_err());
        assert_eq!(store.meta()?, meta);
        store.accept_validated_batch(identity(), batch(2))?;
        let restored = AnalysisStore::restore(&destination, &directory.path().join("restored"))?;
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
        let blocked = backups.join("blocked");
        DirBuilder::new().mode(0o700).create(&blocked)?;
        store.checkpoint()?;
        let before_failure = store.storage_usage()?;
        assert!(store.backup(&blocked).is_err());
        assert_eq!(store.storage_usage()?.file_bytes, before_failure.file_bytes);
        assert_eq!(fs::read_dir(&blocked)?.count(), 0);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
        assert!(AnalysisStore::restore(&blocked, &directory.path().join("invalid")).is_err());
        assert_eq!(fs::read(destination.join("analysis.duckdb"))?, saved);
        Ok(())
    }

    #[test]
    fn analysis_store_closed_access() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        store.checkpoint()?;
        let mut meta = store.meta()?;
        store.write_ready.store(false, Ordering::Release);
        store.readers.close(&store.root)?;
        drop(store.writer.lock().map_err(|_| "writer poisoned")?.take());
        assert!(store.meta().is_err());
        assert!(store.checkpoint().is_err());
        assert!(store.accept_validated_batch(identity(), batch(2)).is_err());
        assert!(store.read_page(&identity(), 1).is_err());
        assert!(!store.storage_health()?.write_ready);
        assert!(AnalysisStore::open(&root).is_err());
        meta.commit_revision += 1;
        assert!(store.reopen_backup(&meta).is_err());
        assert!(store.meta().is_err());
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_backup_restore() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("original"))?;
        let source = identity();
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(1))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let backup_dir = store.root.join("backups");
        let backup = backup_dir.join("saved");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.commit_revision, 1);
        assert_eq!(manifest.recovery_epoch, 1);
        assert_eq!(manifest.schema_version, ANALYSIS_SCHEMA_VERSION as u32);
        assert_eq!(
            manifest.database_bytes,
            fs::metadata(backup.join("analysis.duckdb"))?.len()
        );
        assert_eq!(manifest.segments.len(), 1);
        assert!(store.backup(&backup).is_err());
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(restored.meta()?.recovery_epoch, 2);
        assert_eq!(restored.meta()?.commit_revision, 1);
        assert_eq!(
            restored
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert_eq!(
            restored.record_recovery_floor(&source, 2)?,
            AnalysisRecoveryStatusV1::Partial {
                first_cursor: 2,
                last_cursor: 2,
            }
        );
        assert_eq!(restored.meta()?.commit_revision, 2);
        assert_eq!(
            restored.record_recovery_floor(&source, 2)?,
            AnalysisRecoveryStatusV1::Partial {
                first_cursor: 2,
                last_cursor: 2,
            }
        );
        assert_eq!(restored.meta()?.commit_revision, 2);
        assert_eq!(
            restored
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert!(AnalysisStore::restore(&backup, &directory.path().join("restored")).is_err());
        drop(restored);
        let mut output = OpenOptions::new()
            .append(true)
            .open(backup.join("analysis.duckdb"))?;
        output.write_all(b"corrupt")?;
        assert!(AnalysisStore::restore(&backup, &directory.path().join("corrupt")).is_err());
        assert!(!directory.path().join("corrupt").exists());
        Ok(())
    }

    #[test]
    fn large_segment_backup_restores() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("original");
        let store = AnalysisStore::open(&root)?;
        let payload = vec![7; 17 * 1_024 * 1_024];
        let mut input = batch(1);
        input.framed_records = payload.clone().into();
        input.frame_ends = vec![payload.len()];
        store.accept_validated_batch(identity(), input)?;
        store.accept_validated_batch(identity(), batch(2))?;
        let positions = store.read_page(&identity(), 1)?;
        assert_eq!(positions.records.len(), 1);
        assert_eq!(positions.records[0].framed_record, payload);
        assert_eq!(positions.next_cursor, Some(2));
        let tail = store.read_page(&identity(), 2)?;
        assert_eq!(tail.records.len(), 1);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.read_page(&identity(), 1)?, positions);
        let backup = root.join("backups/large");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.segments.len(), 2);
        assert!(manifest.segments[0].bytes > super::super::EVIDENCE_SEGMENT_BYTES as u64);
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        let restored_page = restored.read_page(&identity(), 1)?;
        assert_eq!(restored_page.records, positions.records);
        assert_eq!(restored_page.next_cursor, positions.next_cursor);
        assert_eq!(restored.read_page(&identity(), 2)?.records, tail.records);
        Ok(())
    }

    #[test]
    fn analysis_store_bundle_checks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let backup = root.join("backups/saved");
        let manifest = store.backup(&backup)?;
        let value = serde_json::to_value(&manifest)?;
        assert!(value.get("database_sha256").is_none());
        assert!(value["segments"][0].get("sha256").is_none());
        let segment =
            super::super::raw::RawJournal::file_path(&backup, &manifest.segments[0].file_name)?;
        let bytes = fs::read(&segment)?;
        let target = directory.path().join("restored");
        let rejected = || {
            assert!(AnalysisStore::restore(&backup, &target).is_err());
            assert!(!target.exists());
        };

        let moved = directory.path().join("saved-segment");
        fs::rename(&segment, &moved)?;
        rejected();
        symlink(&moved, &segment)?;
        rejected();
        fs::remove_file(&segment)?;
        fs::rename(&moved, &segment)?;

        let mut changed = bytes.clone();
        *changed.last_mut().ok_or("segment is empty")? ^= 1;
        fs::write(&segment, &changed)?;
        rejected();
        fs::write(&segment, &bytes)?;
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o644))?;
        rejected();
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o600))?;

        let unknown = backup.join("segments/unknown");
        fs::write(&unknown, b"do not remove")?;
        rejected();
        assert_eq!(fs::read(&unknown)?, b"do not remove");
        fs::remove_file(&unknown)?;
        let manifest_path = backup.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path)?;
        let mut changed = manifest.clone();
        changed.segments.push(changed.segments[0].clone());
        fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
        rejected();
        fs::write(&manifest_path, &manifest_bytes)?;

        let active_name = format!(
            "{}.open",
            manifest.segments[0]
                .file_name
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        );
        let active = segment.with_file_name(&active_name);
        fs::rename(&segment, &active)?;
        let mut changed = manifest.clone();
        changed.segments[0].file_name = active_name;
        fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
        rejected();
        assert_eq!(fs::read(&active)?, bytes);
        fs::rename(&active, &segment)?;
        fs::write(&manifest_path, &manifest_bytes)?;

        let database = backup.join("analysis.duckdb");
        let database_bytes = fs::read(&database)?;
        for sql in [
            "UPDATE source_versions SET contiguous_cursor = contiguous_cursor + 1",
            "DROP TABLE coverage",
        ] {
            let writer = duckdb::Connection::open(&database)?;
            writer.execute_batch(sql)?;
            writer.execute_batch("CHECKPOINT")?;
            drop(writer);
            let mut changed = manifest.clone();
            changed.database_bytes = fs::metadata(&database)?.len();
            fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
            rejected();
            fs::write(&database, &database_bytes)?;
            fs::write(&manifest_path, &manifest_bytes)?;
        }

        fs::set_permissions(&database, fs::Permissions::from_mode(0o400))?;
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o400))?;

        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(
            restored.read_page(&identity(), 1)?.records[0].framed_record,
            b"frame"
        );
        assert_eq!(fs::read(&segment)?, bytes);
        assert_eq!(fs::read(&manifest_path)?, manifest_bytes);
        assert_eq!(fs::read(&database)?, database_bytes);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

}
