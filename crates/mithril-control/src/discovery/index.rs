use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use prost::Message as _;
use rusqlite::{params, Connection, OptionalExtension as _, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::*;
use crate::{
    error::{DiscoveryDatabaseSnafu, DiscoverySnafu, IoSnafu},
    ControlStore, DiscoveryArtifactV1, DiscoveryContextJoinV1, DiscoveryHeadV1,
    EvidenceCpuBindingV1, EvidenceIntakeIdentityV1, EvidenceRecord, Result,
};

const MAX_INDEX_DISK_BYTES: u64 = 2 * crate::store::MAX_DISCOVERY_ACTIVE_INDEX_BYTES;
const MAX_INDEX_WAL_BYTES: u64 = 64 * 1024 * 1024;
const INDEX_TRANSACTION_RESERVE: u64 = 32 * 1024 * 1024;
mod feed;
mod recovery;
pub use feed::*;

const INDEX_SCHEMA_VERSION: i64 = 4;

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::discovery) fn resolved_page(
    ) -> std::result::Result<DiscoveryExportPageV1, Box<dyn std::error::Error>> {
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let record = &input.records[0];
        let binding = input
            .contexts
            .iter()
            .find(|context| context.record_id == record.id)
            .ok_or("context absent")?
            .clone();
        let workload = crate::WorkloadTargetFactV1 {
            node_id: record.id.stream.node_id.clone(),
            workload_binding_generation_digest: binding.subject_revision.clone(),
            execution_set_id: binding.static_key.execution_set_id.clone(),
            cluster_uid: "cluster".into(),
            namespace_uid: "namespace".into(),
            controller_uid: "controller".into(),
            service_account_uid: "account".into(),
            pod_uid: "pod".into(),
            container_id: "container".into(),
            container_name: "worker".into(),
            container_kind: crate::ContainerKindV1::Application,
            image_digest: binding.image_digest.clone(),
            pod_labels: Default::default(),
            kubernetes: None,
        };
        let context = crate::DiscoveryPinnedContextV1 {
            binding,
            workload,
            policy_source_revision_id: "source".into(),
            target_snapshot_digest: "target".into(),
            signed_profile_digest: "profile".into(),
            control_commit_index: 1,
        };
        let mut records = Vec::new();
        for cursor in 1..=3 {
            let mut pin = context.clone();
            pin.binding.record_id.durable_cursor = cursor;
            records.push(DiscoveryExportRecordV1 {
                wire_record: record.observation.to_wire_record()?.encode_to_vec(),
                context: DiscoveryContextJoinV1::Available(Box::new(pin)),
            });
        }
        Ok(DiscoveryExportPageV1 {
            schema_version: 1,
            stream: record.id.stream.clone(),
            cpu_binding: Some(EvidenceCpuBindingV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: 1,
            }),
            first_cursor: 1,
            expired_through: None,
            coverage_record: None,
            previous: None,
            records,
        })
    }

    #[test]
    fn discovery_index_counts_and_progress_rollback_together(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let mut page = resolved_page()?;
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: page.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"counts")?,
        };
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let first = store.commit_discovery_head(key.clone(), None, artifact)?;
        let original = index.apply_export(&first)?;
        assert_eq!((original.accepted_records, original.atom_count), (3, 1));
        let atoms = index.atoms(&first, None)?;
        assert_eq!(atoms.atoms.len(), 1);
        assert_eq!(atoms.atoms[0].count, 3);
        assert_eq!(atoms.atoms[0].evidence_sample.len(), 3);
        assert!(atoms.next.is_none());
        assert!(index
            .atoms(&first, Some(&atoms.atoms[0].id))?
            .atoms
            .is_empty());
        page.first_cursor = 4;
        page.previous = Some(first.clone());
        for record in &mut page.records {
            let DiscoveryContextJoinV1::Available(pin) = &mut record.context else {
                return Err("pin absent".into());
            };
            pin.binding.record_id.durable_cursor += 3;
        }
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let second = store.commit_discovery_head(key.clone(), Some(&first), artifact)?;
        assert!(index.atoms(&first, None).is_err());
        assert!(index.atoms(&second, None).is_err());
        index.writer.lock().map_err(|_| "writer poisoned")?.execute_batch(
            "CREATE TEMP TRIGGER fail_apply BEFORE INSERT ON input_record
                WHEN new.cursor=x'0000000000000005' BEGIN SELECT RAISE(ABORT,'injected apply failure'); END;"
        )?;
        assert!(index.apply_export(&second).is_err());
        assert_eq!(index.progress(key.tenant_id, &key.id)?, Some(original));
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            assert_eq!(
                writer.query_row("SELECT sum(n) FROM behavior_atom", [], |row| row
                    .get::<_, u64>(0))?,
                3
            );
            writer.execute_batch("DROP TRIGGER fail_apply")?;
        }
        let current = index.apply_export(&second)?;
        assert_eq!((current.accepted_records, current.atom_count), (6, 1));
        assert_eq!(index.apply_export(&second)?, current);
        let reader_one = index.readers[0].lock().map_err(|_| "reader poisoned")?;
        let reader_two = index.readers[1].lock().map_err(|_| "reader poisoned")?;
        assert!(index.progress(key.tenant_id, &key.id).is_err());
        drop(reader_one);
        assert_eq!(index.progress(key.tenant_id, &key.id)?, Some(current));
        drop(reader_two);
        Ok(())
    }

    #[test]
    fn discovery_context_complete_pin_limit_and_reader_deadline(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut page = resolved_page()?;
        let DiscoveryContextJoinV1::Available(pin) = &mut page.records[0].context else {
            return Err("pin absent".into());
        };
        pin.workload
            .pod_labels
            .insert("padding".into(), String::new());
        let bytes = serde_json::to_vec(&page.records[0].context)?.len();
        let DiscoveryContextJoinV1::Available(pin) = &mut page.records[0].context else {
            return Err("pin absent".into());
        };
        *pin.workload
            .pod_labels
            .get_mut("padding")
            .ok_or("padding absent")? = "x".repeat(MAX_DISCOVERY_PIN_BYTES - bytes);
        let at_limit = page.records[0].context.clone();
        assert_eq!(
            serde_json::to_vec(&at_limit)?.len(),
            MAX_DISCOVERY_PIN_BYTES
        );
        assert_eq!(at_limit.clone().into_bounded(), at_limit);
        let DiscoveryContextJoinV1::Available(pin) = &mut page.records[0].context else {
            return Err("pin absent".into());
        };
        pin.workload
            .pod_labels
            .get_mut("padding")
            .ok_or("padding absent")?
            .push('x');
        assert_eq!(
            page.records[0].context.clone().into_bounded(),
            DiscoveryContextJoinV1::Unresolved(crate::DiscoveryContextUnavailableV1::ContextLimit)
        );
        assert!(page.prepare().is_err());
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let started = Instant::now();
        let reader = index.reader()?;
        let result = reader.query_row("WITH RECURSIVE work(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM work WHERE n<1000000000) SELECT sum(n) FROM work", [], |row| row.get::<_, i64>(0));
        assert!(
            matches!(result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::OperationInterrupted)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(reader);
        assert!(index
            .progress([1; 16], &DiscoveryDigestV1([1; 32]))?
            .is_none());
        let usage = index.resource_usage()?;
        assert!(usage.sqlite_global_bytes > 0 && usage.resident_bytes > 0 && usage.index_bytes > 0);
        assert_eq!(store.commit_index(), 0);
        Ok(())
    }

    #[test]
    fn discovery_index_replays_only_committed_exports_without_duplicate_counts(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        assert!(DiscoveryIndex::open(store.clone()).is_err());
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let record = &input.records[0];
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: record.id.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"index-test")?,
        };
        let mut page = DiscoveryExportPageV1 {
            schema_version: 1,
            stream: record.id.stream.clone(),
            cpu_binding: None,
            first_cursor: 1,
            expired_through: None,
            coverage_record: None,
            previous: None,
            records: vec![
                DiscoveryExportRecordV1 {
                    wire_record: record.observation.to_wire_record()?.encode_to_vec(),
                    context: DiscoveryContextJoinV1::Unresolved(
                        crate::DiscoveryContextUnavailableV1::MissingDecisionCatalog
                    ),
                };
                3
            ],
        };
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let fake = DiscoveryHeadV1 {
            key: key.clone(),
            revision: 1,
            commit_index: 1,
            artifact: artifact.clone(),
        };
        assert!(index.apply_export(&fake).is_err());
        let first = store.commit_discovery_head(key.clone(), None, artifact)?;
        let progress = index.apply_export(&first)?;
        assert_eq!(
            (
                progress.next_cursor,
                progress.accepted_records,
                progress.atom_count
            ),
            (4, 3, 0)
        );
        assert_eq!(index.apply_export(&first)?, progress);
        assert!(index.progress([9; 16], &key.id)?.is_none());
        page.first_cursor = 4;
        page.previous = Some(first.clone());
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let second = store.commit_discovery_head(key.clone(), Some(&first), artifact)?;
        let progress = index.apply_export(&second)?;
        assert_eq!(progress.accepted_records, 6);
        assert_eq!(index.replay_interval(&second)?, progress);
        drop(index);
        let reopened = DiscoveryIndex::open(store.clone())?;
        assert_eq!(
            reopened.progress(key.tenant_id, &key.id)?,
            Some(progress.clone())
        );
        assert_eq!(store.evidence_cursor(&page.stream)?, 0);
        drop(reopened);
        fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let rebuilt = DiscoveryIndex::open(store)?;
        assert!(rebuilt.apply_export(&second).is_err());
        assert_eq!(rebuilt.replay_interval(&second)?, progress);
        {
            let writer = rebuilt.writer.lock().map_err(|_| "writer poisoned")?;
            let mut statement =
                writer.prepare("SELECT commit_index,ordinal FROM input_record ORDER BY cursor")?;
            let positions = statement
                .query_map([], |row| {
                    Ok((u64::from_be_bytes(row.get(0)?), row.get::<_, u32>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            assert_eq!(
                positions,
                vec![
                    (first.commit_index, 0),
                    (first.commit_index, 1),
                    (first.commit_index, 2),
                    (second.commit_index, 0),
                    (second.commit_index, 1),
                    (second.commit_index, 2)
                ]
            );
        }
        let permits = rebuilt.writes.try_acquire_many(9)?;
        assert!(rebuilt.apply_export(&second).is_err());
        drop(permits);
        assert_eq!(rebuilt.apply_export(&second)?, progress);
        rebuilt
            .writer
            .lock()
            .map_err(|_| "writer poisoned")?
            .execute(
                "UPDATE source_progress SET commit_index=?1",
                [u64::MAX.to_be_bytes()],
            )?;
        assert!(rebuilt.apply_export(&second).is_err());
        assert!(rebuilt.replay_interval(&second).is_err());
        Ok(())
    }

    #[test]
    fn discovery_index_native_constraints_preserve_progress_on_capacity_failure(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let mut page = resolved_page()?;
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: page.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"limits")?,
        };
        let first = store.commit_discovery_head(
            key.clone(),
            None,
            store.put_discovery_artifact(&page.artifact()?)?,
        )?;
        index.apply_export(&first)?;
        page.first_cursor = 4;
        page.previous = Some(first.clone());
        page.records.truncate(1);
        let DiscoveryContextJoinV1::Available(pin) = &mut page.records[0].context else {
            return Err("pin absent".into());
        };
        pin.binding.record_id.durable_cursor = 4;
        let second = store.commit_discovery_head(
            key.clone(),
            Some(&first),
            store.put_discovery_artifact(&page.artifact()?)?,
        )?;
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            writer.execute("UPDATE source_progress SET accepted=1000000", [])?;
            assert!(writer
                .execute("UPDATE source_progress SET accepted=1000001", [])
                .is_err());
            assert!(writer
                .execute("UPDATE source_progress SET accepted=1.5", [])
                .is_err());
            writer.execute("UPDATE source_progress SET input_bytes=268435456", [])?;
            assert!(writer
                .execute("UPDATE source_progress SET input_bytes=268435457", [])
                .is_err());
            writer.execute("UPDATE source_progress SET atom_count=50000", [])?;
            assert!(writer
                .execute("UPDATE source_progress SET atom_count=50001", [])
                .is_err());
            writer.execute("UPDATE source_progress SET atom_count=1,input_bytes=0", [])?;
        }
        let at_limit = index.progress(key.tenant_id, &key.id)?;
        assert!(index.apply_export(&second).is_err());
        assert_eq!(index.progress(key.tenant_id, &key.id)?, at_limit);
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            writer.execute(
                "UPDATE source_progress SET accepted=999999,input_bytes=?1",
                [MAX_DISCOVERY_INPUT_BYTES as u64 - page.input_bytes()? + 1],
            )?;
        }
        assert!(index.apply_export(&second).is_err());
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            writer.execute(
                "UPDATE source_progress SET input_bytes=?1",
                [MAX_DISCOVERY_INPUT_BYTES as u64 - page.input_bytes()?],
            )?;
            let pages: u64 = writer.pragma_query_value(None, "page_count", |row| row.get(0))?;
            writer.pragma_update(None, "max_page_count", pages)?;
            writer.execute_batch(
                "CREATE TEMP TRIGGER exhaust_index BEFORE INSERT ON input_record
                BEGIN UPDATE behavior_atom SET exact_key=zeroblob(1048576); END;",
            )?;
        }
        let before_full = index.progress(key.tenant_id, &key.id)?;
        let Err(failure) = index.apply_export(&second) else {
            return Err("the page bound did not reject growth".into());
        };
        assert!(
            matches!(failure, crate::Error::DiscoveryDatabase { source, .. } if source.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull))
        );
        assert_eq!(index.progress(key.tenant_id, &key.id)?, before_full);
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            writer.execute_batch("DROP TRIGGER exhaust_index; PRAGMA max_page_count=245760;")?;
            assert_eq!(
                writer.query_row("SELECT sum(n) FROM behavior_atom", [], |row| row
                    .get::<_, u64>(0))?,
                3
            );
        }
        let current = index.apply_export(&second)?;
        assert_eq!(current.accepted_records, 1_000_000);
        assert_eq!(index.apply_export(&second)?, current);
        Ok(())
    }

    #[test]
    fn discovery_index_lease_releases_after_last_owner_with_duplicate_descriptor(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let descriptor = index._lease.file.try_clone()?;
        let active = index._lease.clone();
        drop(index);
        assert!(DiscoveryIndex::open(store.clone()).is_err());
        drop(active);
        let reopened = DiscoveryIndex::open(store.clone())?;
        drop(descriptor);
        assert!(DiscoveryIndex::open(store).is_err());
        drop(reopened);
        Ok(())
    }

    #[test]
    fn discovery_index_rejects_future_schema_and_corrupt_files_without_changing_control(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        index
            .writer
            .lock()
            .map_err(|_| "writer poisoned")?
            .pragma_update(None, "user_version", INDEX_SCHEMA_VERSION + 1)?;
        drop(index);
        assert!(DiscoveryIndex::open(store.clone()).is_err());
        fs::write(
            directory.path().join("discovery-index.sqlite"),
            b"invalid SQLite header",
        )?;
        assert!(DiscoveryIndex::open(store).is_err());
        assert!(ControlStore::open(directory.path()).is_ok());
        Ok(())
    }

    #[test]
    fn discovery_index_seals_complete_and_partial_revisions_after_schema_upgrade(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let mut page = resolved_page()?;
        for (ordinal, retained) in page.records.iter_mut().enumerate() {
            let mut wire = EvidenceRecord::decode(retained.wire_record.as_slice())?;
            let object = crate::EvidenceExactFileObject {
                profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                mount_id_unique: 1,
                inode: 2,
                inode_generation: 3,
                mount_namespace_inode: 4,
                filesystem_device: 5,
            };
            wire.exact_object_id = object.observation_id(1).to_be_bytes().to_vec().into();
            wire.decision_context = Some(crate::EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: 101 + ordinal as u64,
                profile_generation_ref_id: object.profile_generation_ref_id,
                exact_file_object: Some(object),
                exact_object_key_id: 1,
                composite_atom_id: wire.policy_rule_id,
                ..Default::default()
            });
            retained.wire_record = wire.encode_to_vec();
        }
        let wire = EvidenceRecord::decode(page.records[0].wire_record.as_slice())?;
        let mut coverage = crate::CoverageReport {
            source_id: page.stream.source_id.to_vec(),
            source_epoch: page.stream.source_epoch,
            cpu_id: page.cpu_binding.ok_or("CPU absent")?.cpu_id,
            revision: 1,
            intervals: vec![crate::CoverageInterval {
                interval_id: wire.coverage_interval_id.to_vec(),
                source_epoch: page.stream.source_epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 101,
                last_sequence: Some(103),
                opening_counters: Some(crate::CoverageCounters::default()),
                closing_counters: Some(crate::CoverageCounters {
                    attempted: 3,
                    requested: 3,
                    emitted: 3,
                    next_sequence: 104,
                    ..Default::default()
                }),
                gap_reasons: Vec::new(),
                current: true,
            }],
        };
        page.coverage_record = Some(coverage.encode_to_vec());
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: page.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"sealing")?,
        };
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let first = store.commit_discovery_head(key.clone(), None, artifact)?;
        let progress = index.apply_export(&first)?;
        index
            .writer
            .lock()
            .map_err(|_| "writer poisoned")?
            .execute_batch("DROP TABLE profile_index; PRAGMA user_version=1;")?;
        drop(index);
        let index = DiscoveryIndex::open(store.clone())?;
        assert_eq!(index.progress(key.tenant_id, &key.id)?, Some(progress));
        assert_eq!(
            index
                .writer
                .lock()
                .map_err(|_| "writer poisoned")?
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?,
            INDEX_SCHEMA_VERSION
        );
        drop(index);
        drop(store);
        let store = ControlStore::open(directory.path())?;
        let owner = DiscoveryOwner::open(store.clone())?;
        let complete = owner.seal_interval(&first)?;
        let original = owner.read_snapshot(&complete, None)?;
        assert_eq!(original.profile.state, DiscoveryProfileStateV1::Complete);
        assert_eq!(
            original.profile.proof_kind,
            DiscoveryProofKindV1::RecordedInput
        );
        assert_eq!(
            (
                original.profile.accepted_records,
                original.profile.included_records
            ),
            (3, 3)
        );
        assert!(original.profile.partial_reasons.is_empty());
        assert_eq!(original.atoms.len(), 1);
        assert_eq!(original.atoms[0].count, 3);
        page.previous = Some(first);
        page.first_cursor = 4;
        let records = std::mem::take(&mut page.records);
        coverage.revision = 2;
        coverage.intervals[0].revision = 2;
        coverage.intervals[0].state = "CLOSED".into();
        coverage.intervals[0].current = false;
        let mut current_interval = coverage.intervals[0].clone();
        current_interval.interval_id = vec![254; 16];
        current_interval.state = "HEALTHY".into();
        current_interval.current = true;
        current_interval.first_sequence = 104;
        current_interval.last_sequence = None;
        current_interval.opening_counters = current_interval.closing_counters.take();
        coverage.intervals.push(current_interval);
        page.coverage_record = Some(coverage.encode_to_vec());
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let closed_export =
            store.commit_discovery_head(key.clone(), page.previous.as_ref(), artifact)?;
        let closed = owner.seal_interval(&closed_export)?;
        let closed_page = owner.read_snapshot(&closed, None)?;
        assert_eq!(closed_page.profile.state, DiscoveryProfileStateV1::Complete);
        assert_eq!(closed_page.profile.accepted_records, 3);
        assert_eq!(closed_page.profile.replaces, Some(complete.clone()));
        assert_eq!(closed_page.atoms, original.atoms);
        page.previous = Some(closed_export);
        page.records = records;
        for retained in &mut page.records {
            let DiscoveryContextJoinV1::Available(pin) = &mut retained.context else {
                return Err("pin absent".into());
            };
            pin.binding.record_id.durable_cursor += 3;
        }
        coverage.revision = 3;
        coverage.intervals[0].revision = 3;
        coverage.intervals[0].state = "GAPPED".into();
        coverage.intervals[0].current = true;
        coverage.intervals.truncate(1);
        coverage.intervals[0].gap_reasons.push("RING_LOSS".into());
        page.coverage_record = Some(coverage.encode_to_vec());
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let second = store.commit_discovery_head(key.clone(), page.previous.as_ref(), artifact)?;
        let partial = owner.seal_interval(&second)?;
        assert_ne!(partial, complete);
        let changed = owner.read_snapshot(&partial, None)?;
        assert_eq!(changed.profile.state, DiscoveryProfileStateV1::Partial);
        assert_eq!(changed.profile.accepted_records, 6);
        assert_eq!(
            changed.profile.partial_reasons,
            vec!["SOURCE_COVERAGE_GAPPED", "SOURCE_COVERAGE_UNPROVEN"]
        );
        page.previous = Some(second);
        page.first_cursor = 7;
        page.records.clear();
        coverage.revision = 4;
        coverage.intervals[0].revision = 4;
        coverage.intervals[0].state = "HEALTHY".into();
        coverage.intervals[0].gap_reasons.clear();
        page.coverage_record = Some(coverage.encode_to_vec());
        let artifact = store.put_discovery_artifact(&page.artifact()?)?;
        let third = store.commit_discovery_head(key, page.previous.as_ref(), artifact)?;
        let corrected = owner.seal_interval(&third)?;
        let corrected_page = owner.read_snapshot(&corrected, None)?;
        assert_eq!(
            corrected_page.profile.state,
            DiscoveryProfileStateV1::Partial
        );
        assert_eq!(corrected_page.profile.accepted_records, 6);
        assert_eq!(corrected_page.profile.replaces, Some(partial.clone()));
        assert!(corrected_page
            .profile
            .partial_reasons
            .iter()
            .any(|reason| reason == "SOURCE_COVERAGE_GAPPED"));
        assert_eq!(corrected_page.atoms, changed.atoms);
        assert_eq!(owner.read_snapshot(&partial, None)?, changed);
        assert_eq!(owner.read_snapshot(&complete, None)?, original);
        Ok(())
    }

    #[test]
    fn discovery_index_pages_fifty_thousand_atoms_and_rebuilds_the_same_cursors(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let mut page = resolved_page()?;
        let template = page.records[0].clone();
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: page.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"paging")?,
        };
        let mut head = None;
        for first in (1..=50_002_u64).step_by(256) {
            page.first_cursor = first;
            page.previous = head.clone();
            page.records.clear();
            for cursor in first..=50_002.min(first + 255) {
                let mut record = template.clone();
                let DiscoveryContextJoinV1::Available(pin) = &mut record.context else {
                    return Err("pin absent".into());
                };
                pin.binding.record_id.durable_cursor = cursor;
                pin.binding.role_id = if cursor == 50_002 { 1 } else { cursor as u32 };
                page.records.push(record);
            }
            let artifact = store.put_discovery_artifact(&page.artifact()?)?;
            let current = store.commit_discovery_head(key.clone(), head.as_ref(), artifact)?;
            index.apply_export(&current)?;
            head = Some(current);
        }
        let head = head.ok_or("head absent")?;
        let progress = index
            .progress(key.tenant_id, &key.id)?
            .ok_or("progress absent")?;
        assert_eq!(
            (progress.accepted_records, progress.atom_count),
            (50_002, 50_000)
        );
        {
            let writer = index.writer.lock().map_err(|_| "writer poisoned")?;
            assert_eq!(
                writer.query_row(
                    "SELECT count(*) FROM input_record WHERE unresolved='ATOM_LIMIT'",
                    [],
                    |row| row.get::<_, u64>(0)
                )?,
                1
            );
            let plan: String = writer.query_row("EXPLAIN QUERY PLAN SELECT atom FROM behavior_atom WHERE tenant=?1 AND build=?2 AND atom>?3 ORDER BY atom LIMIT 201", params![key.tenant_id,key.id.0,[0_u8;32]], |row| row.get(3))?;
            assert!(
                plan.contains("SEARCH behavior_atom USING PRIMARY KEY"),
                "{plan}"
            );
        }
        let pages = |index: &DiscoveryIndex| -> std::result::Result<Vec<DiscoveryDigestV1>, Box<dyn std::error::Error>> {
            let mut after = None;
            let mut last = None;
            let mut count = 0;
            let mut observations = 0;
            let mut digests = Vec::new();
            loop {
                let page = index.atoms(&head, after.as_ref())?;
                assert!(page.atoms.len() <= 200);
                assert!(serde_json::to_vec(&page)?.len() <= 1024 * 1024);
                for atom in &page.atoms {
                    assert!(last.as_ref().is_none_or(|last| last < &atom.id));
                    assert!(!atom.evidence_sample.is_empty() && atom.evidence_sample.len() <= 8);
                    last = Some(atom.id.clone());
                    count += 1;
                    observations += atom.count;
                }
                digests.push(DiscoveryDigestV1::of(&page)?);
                after = page.next;
                if after.is_none() { break; }
                assert!(digests.len() <= 500);
            }
            assert_eq!((count,observations), (50_000,50_001));
            Ok(digests)
        };
        let original = pages(&index)?;
        drop(index);
        fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let rebuilt = DiscoveryIndex::open(store)?;
        assert_eq!(rebuilt.replay_interval(&head)?, progress);
        assert_eq!(pages(&rebuilt)?, original);
        drop(rebuilt);
        let owner = DiscoveryOwner::open(ControlStore::open(directory.path())?)?;
        let snapshot = owner.seal_interval(&head)?;
        assert_eq!(owner.seal_interval(&head)?, snapshot);
        let snapshots = |owner: &DiscoveryOwner| -> std::result::Result<
            Vec<DiscoveryDigestV1>,
            Box<dyn std::error::Error>,
        > {
            let mut cursor = None;
            let mut count = 0;
            let mut observations = 0;
            let mut digests = Vec::new();
            loop {
                let page = owner.read_snapshot(&snapshot, cursor.as_ref())?;
                assert_eq!(page.profile.state, DiscoveryProfileStateV1::Partial);
                assert_eq!(page.profile.atom_count, 50_000);
                assert_eq!(page.profile.unresolved_records, 1);
                assert!(page.atoms.len() <= 200 && serde_json::to_vec(&page)?.len() <= 1024 * 1024);
                count += page.atoms.len();
                observations += page.atoms.iter().map(|atom| atom.count).sum::<u64>();
                digests.push(DiscoveryDigestV1::of(&page)?);
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
                assert!(digests.len() <= 500);
            }
            assert_eq!((count, observations), (50_000, 50_001));
            Ok(digests)
        };
        let original = snapshots(&owner)?;
        drop(owner);
        let owner = DiscoveryOwner::open(ControlStore::open(directory.path())?)?;
        assert_eq!(snapshots(&owner)?, original);
        drop(owner);
        fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let owner = DiscoveryOwner::open(ControlStore::open(directory.path())?)?;
        assert!(owner.read_snapshot(&snapshot, None).is_err());
        assert_eq!(owner.seal_interval(&head)?, snapshot);
        assert_eq!(snapshots(&owner)?, original);
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryExportRecordV1 {
    pub wire_record: Vec<u8>,
    pub context: DiscoveryContextJoinV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryExportPageV1 {
    pub schema_version: u32,
    pub stream: EvidenceIntakeIdentityV1,
    pub cpu_binding: Option<EvidenceCpuBindingV1>,
    pub first_cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired_through: Option<u64>,
    pub coverage_record: Option<Vec<u8>>,
    pub previous: Option<DiscoveryHeadV1>,
    pub records: Vec<DiscoveryExportRecordV1>,
}

struct IndexedRecord {
    cursor: u64,
    payload_digest: [u8; 32],
    atom: Option<(DiscoveryDigestV1, Vec<u8>)>,
    unresolved: Option<&'static str>,
}

impl DiscoveryExportPageV1 {
    pub(super) fn next_cursor(&self) -> Result<u64> {
        self.expired_through
            .map_or_else(
                || self.first_cursor.checked_add(self.records.len() as u64),
                |last| last.checked_add(1),
            )
            .ok_or_else(|| {
                DiscoverySnafu {
                    code: "EXPORT_LIMIT",
                    reason: "the export cursor is exhausted",
                }
                .build()
            })
    }

    pub(super) fn input_bytes(&self) -> Result<u64> {
        let mut counter = super::model::InputByteLimit(MAX_DISCOVERY_INPUT_BYTES);
        serde_json::to_writer(&mut counter, self).map_err(|error| {
            DiscoverySnafu {
                code: "EXPORT_LIMIT",
                reason: error.to_string(),
            }
            .build()
        })?;
        Ok((MAX_DISCOVERY_INPUT_BYTES - counter.0) as u64)
    }

    pub fn artifact(&self) -> Result<DiscoveryArtifactV1> {
        self.prepare()?;
        let payload = rmp_serde::to_vec_named(self).map_err(|error| {
            DiscoverySnafu {
                code: "EXPORT_ENCODING",
                reason: error.to_string(),
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(payload.len() <= 8 * 1024 * 1024, "EXPORT_LIMIT")?;
        Ok(DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: self.stream.tenant_id,
            dependencies: self
                .previous
                .iter()
                .map(|head| head.artifact.clone())
                .collect(),
            payload,
        })
    }

    fn prepare(&self) -> Result<Vec<IndexedRecord>> {
        DiscoveryInputManifestV1::require(
            self.schema_version == 1
                && self.stream.tenant_id != [0; 16]
                && !self.stream.node_id.is_empty()
                && self.stream.node_id.len() <= 256
                && self.stream.node_boot_id != [0; 16]
                && self.stream.source_id != [0; 16]
                && self.stream.label_epoch > 0
                && self.stream.source_epoch > 0
                && self.first_cursor > 0
                && self
                    .cpu_binding
                    .is_none_or(|binding| binding.first_cursor > 0)
                && self.expired_through.map_or(
                    !self.records.is_empty()
                        || (self.coverage_record.is_some() && self.previous.is_some()),
                    |last| self.records.is_empty() && last >= self.first_cursor && last < u64::MAX,
                )
                && self.records.len() <= 256
                && self
                    .first_cursor
                    .checked_add(self.records.len() as u64)
                    .is_some()
                && self
                    .records
                    .iter()
                    .map(|record| record.wire_record.len())
                    .sum::<usize>()
                    <= 1024 * 1024
                && self
                    .coverage_record
                    .as_ref()
                    .is_none_or(|record| record.len() <= 3 * 1024 * 1024),
            "EXPORT_SCHEMA",
        )?;
        if let Some(coverage) = &self.coverage_record {
            let coverage = crate::CoverageReport::decode(coverage.as_slice()).map_err(|error| {
                DiscoverySnafu {
                    code: "EXPORT_COVERAGE",
                    reason: error.to_string(),
                }
                .build()
            })?;
            DiscoveryInputManifestV1::require(
                coverage.source_id.as_slice() == self.stream.source_id
                    && coverage.source_epoch == self.stream.source_epoch
                    && coverage.revision > 0,
                "EXPORT_COVERAGE",
            )?;
        }
        self.records
            .iter()
            .enumerate()
            .map(|(ordinal, retained)| {
                DiscoveryInputManifestV1::require(
                    serde_json::to_writer(
                        InputByteLimit(MAX_DISCOVERY_PIN_BYTES),
                        &retained.context,
                    )
                    .is_ok(),
                    "EXPORT_CONTEXT_LIMIT",
                )?;
                let cursor = self.first_cursor + ordinal as u64;
                let wire =
                    EvidenceRecord::decode(retained.wire_record.as_slice()).map_err(|error| {
                        DiscoverySnafu {
                            code: "EXPORT_RECORD",
                            reason: error.to_string(),
                        }
                        .build()
                    })?;
                let payload_digest = Sha256::digest(&retained.wire_record).into();
                let Some(cpu) = self
                    .cpu_binding
                    .filter(|binding| cursor >= binding.first_cursor)
                else {
                    DiscoveryInputManifestV1::require(
                        matches!(retained.context, DiscoveryContextJoinV1::Unresolved(_)),
                        "EXPORT_UNKNOWN_CPU_CONTEXT",
                    )?;
                    return Ok(IndexedRecord {
                        cursor,
                        payload_digest,
                        atom: None,
                        unresolved: Some("UNKNOWN_SOURCE_CPU"),
                    });
                };
                let record = DiscoveryRecordV1::from_wire(&self.stream, cpu.cpu_id, cursor, &wire)?;
                let (atom, unresolved) = match &retained.context {
                    DiscoveryContextJoinV1::Available(pin) => {
                        let key = BehaviorAtomKeyV1::from_record(
                            &record,
                            &pin.binding,
                            DiscoveryProofKindV1::RecordedInput,
                        )?;
                        DiscoveryInputManifestV1::require(
                            key.generation != 0
                                && key.effect.exact_object_id.is_some_and(|id| !id.is_zero()),
                            "EXPORT_EXACT_CONTEXT",
                        )?;
                        let digest = DiscoveryDigestV1::of(&key)?;
                        let bytes = serde_json::to_vec(&key).map_err(|error| {
                            DiscoverySnafu {
                                code: "ATOM_ENCODING",
                                reason: error.to_string(),
                            }
                            .build()
                        })?;
                        (Some((digest, bytes)), None)
                    }
                    DiscoveryContextJoinV1::Unresolved(reason) => (
                        None,
                        Some(match reason {
                            crate::DiscoveryContextUnavailableV1::MissingSourceCpu => {
                                "UNKNOWN_SOURCE_CPU"
                            }
                            crate::DiscoveryContextUnavailableV1::ContextLimit => "CONTEXT_LIMIT",
                            crate::DiscoveryContextUnavailableV1::MissingDecisionCatalog => {
                                "MISSING_DECISION_CATALOG"
                            }
                            crate::DiscoveryContextUnavailableV1::MissingProcessLifetime => {
                                "MISSING_PROCESS_LIFETIME"
                            }
                            crate::DiscoveryContextUnavailableV1::MissingWorkloadFact => {
                                "MISSING_WORKLOAD_FACT"
                            }
                            crate::DiscoveryContextUnavailableV1::AmbiguousWorkloadFact => {
                                "AMBIGUOUS_WORKLOAD_FACT"
                            }
                            crate::DiscoveryContextUnavailableV1::PolicyContextMismatch => {
                                "POLICY_CONTEXT_MISMATCH"
                            }
                        }),
                    ),
                };
                Ok(IndexedRecord {
                    cursor,
                    payload_digest,
                    atom,
                    unresolved,
                })
            })
            .collect()
    }
}

pub struct DiscoveryIndex {
    store: ControlStore,
    path: PathBuf,
    writer: Mutex<Connection>,
    writes: tokio::sync::Semaphore,
    readers: [Mutex<Connection>; 2],
    _lease: Arc<crate::store::StoreLease>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryIndexProgressV1 {
    pub commit_index: u64,
    pub next_cursor: u64,
    pub accepted_records: u64,
    pub atom_count: u64,
    pub input_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryAtomPageV1 {
    pub export: DiscoveryHeadV1,
    pub atoms: Vec<BehaviorAtomV1>,
    pub next: Option<DiscoveryDigestV1>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryResourceUsageV1 {
    pub sqlite_global_bytes: u64,
    pub sqlite_global_peak_bytes: u64,
    pub resident_bytes: u64,
    pub peak_resident_bytes: u64,
    pub index_bytes: u64,
    pub wal_bytes: u64,
}

impl DiscoveryIndex {
    pub fn resource_usage(&self) -> Result<DiscoveryResourceUsageV1> {
        let status_path = Path::new("/proc/self/status");
        let status = fs::read_to_string(status_path).context(IoSnafu { path: status_path })?;
        let memory = |field: &str| -> Result<u64> {
            status
                .lines()
                .find(|line| line.starts_with(field))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|value| value.checked_mul(1024))
                .ok_or_else(|| {
                    DiscoverySnafu {
                        code: "INDEX_RESOURCE_STATUS",
                        reason: "the process memory counter is absent",
                    }
                    .build()
                })
        };
        // SAFETY: SQLite owns these thread-safe counters. No pointer or reset is supplied.
        #[allow(unsafe_code)]
        let (used, peak) = unsafe {
            (
                rusqlite::ffi::sqlite3_memory_used(),
                rusqlite::ffi::sqlite3_memory_highwater(0),
            )
        };
        let mut index_bytes = 0_u64;
        let mut wal_bytes = 0;
        for suffix in ["", "-wal", "-shm"] {
            let path = Self::sidecar(&self.path, suffix);
            let bytes = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(source) => return Err(source).context(IoSnafu { path }),
            };
            index_bytes = index_bytes.saturating_add(bytes);
            if suffix == "-wal" {
                wal_bytes = bytes;
            }
        }
        Ok(DiscoveryResourceUsageV1 {
            sqlite_global_bytes: used.max(0) as u64,
            sqlite_global_peak_bytes: peak.max(0) as u64,
            resident_bytes: memory("VmRSS:")?,
            peak_resident_bytes: memory("VmHWM:")?,
            index_bytes,
            wal_bytes,
        })
    }

    pub fn open(store: ControlStore) -> Result<Self> {
        let lease = Self::lease(&store)?;
        Self::finish_install(&store.root())?;
        let path = store.root().join("discovery-index.sqlite");
        Self::open_at(store, path, lease)
    }

    fn lease(store: &ControlStore) -> Result<Arc<crate::store::StoreLease>> {
        let root = store.root();
        let filesystem = rustix::fs::statfs(&root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &root })?;
        // These Linux types are ext4 and tmpfs. Other filesystems require qualification.
        DiscoveryInputManifestV1::require(
            matches!(filesystem.f_type, 0xef53 | 0x0102_1994),
            "INDEX_FILESYSTEM_UNQUALIFIED",
        )?;
        let lease_path = root.join("discovery-index.lock");
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lease_path)
            .context(IoSnafu { path: &lease_path })?;
        lease.try_lock().map_err(|error| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: error.to_string(),
            }
            .build()
        })?;
        Ok(Arc::new(crate::store::StoreLease::from_locked(lease)))
    }

    fn open_at(
        store: ControlStore,
        path: PathBuf,
        lease: Arc<crate::store::StoreLease>,
    ) -> Result<Self> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        }
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        DiscoveryInputManifestV1::require(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            "INDEX_FILE_PERMISSIONS",
        )?;
        let writer = Self::connection(&path, false)?;
        let version: i64 = writer
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context(DiscoveryDatabaseSnafu {
                operation: "read schema",
            })?;
        DiscoveryInputManifestV1::require(
            (0..=INDEX_SCHEMA_VERSION).contains(&version),
            "INDEX_SCHEMA",
        )?;
        writer.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS source_progress(
                tenant BLOB NOT NULL CHECK(length(tenant)=16), build BLOB NOT NULL CHECK(length(build)=32),
                stream BLOB NOT NULL, commit_index BLOB NOT NULL CHECK(length(commit_index)=8),
                next_cursor BLOB NOT NULL CHECK(length(next_cursor)=8), artifact BLOB NOT NULL CHECK(length(artifact)=32),
                accepted INTEGER NOT NULL CHECK(typeof(accepted)='integer' AND accepted BETWEEN 0 AND 1000000),
                atom_count INTEGER NOT NULL CHECK(typeof(atom_count)='integer' AND atom_count BETWEEN 0 AND 50000),
                input_bytes INTEGER NOT NULL CHECK(typeof(input_bytes)='integer' AND input_bytes BETWEEN 0 AND 268435456),
                PRIMARY KEY(tenant,build)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS behavior_atom(
                tenant BLOB NOT NULL, build BLOB NOT NULL, atom BLOB NOT NULL CHECK(length(atom)=32),
                exact_key BLOB NOT NULL, n INTEGER NOT NULL CHECK(typeof(n)='integer' AND n BETWEEN 1 AND 1000000),
                first_cursor BLOB NOT NULL CHECK(length(first_cursor)=8), last_cursor BLOB NOT NULL CHECK(length(last_cursor)=8),
                PRIMARY KEY(tenant,build,atom), FOREIGN KEY(tenant,build) REFERENCES source_progress(tenant,build)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS input_record(
                tenant BLOB NOT NULL, build BLOB NOT NULL, cursor BLOB NOT NULL CHECK(length(cursor)=8),
                payload BLOB NOT NULL CHECK(length(payload)=32), commit_index BLOB NOT NULL CHECK(length(commit_index)=8),
                ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), atom BLOB, unresolved TEXT,
                CHECK((atom IS NULL) != (unresolved IS NULL)), PRIMARY KEY(tenant,build,cursor),
                FOREIGN KEY(tenant,build) REFERENCES source_progress(tenant,build),
                FOREIGN KEY(tenant,build,atom) REFERENCES behavior_atom(tenant,build,atom)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS input_atom ON input_record(tenant,build,atom,cursor);
            CREATE INDEX IF NOT EXISTS input_position ON input_record(commit_index,ordinal,tenant,build);
            CREATE TABLE IF NOT EXISTS profile_index(
                tenant BLOB NOT NULL CHECK(length(tenant)=16), snapshot BLOB NOT NULL CHECK(length(snapshot)=32),
                commit_index BLOB NOT NULL CHECK(length(commit_index)=8), artifact BLOB NOT NULL CHECK(length(artifact)=32),
                PRIMARY KEY(tenant,snapshot)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS context_document(
                tenant BLOB NOT NULL CHECK(length(tenant)=16), id TEXT NOT NULL, revision BLOB NOT NULL CHECK(length(revision)=8),
                subject BLOB NOT NULL CHECK(length(subject)=32), lifetime BLOB NOT NULL CHECK(length(lifetime)=16),
                method BLOB NOT NULL CHECK(length(method)=32), imported BLOB NOT NULL CHECK(length(imported)=8),
                valid_from BLOB NOT NULL CHECK(length(valid_from)=8), valid_until BLOB,
                commit_index BLOB NOT NULL CHECK(length(commit_index)=8), head BLOB NOT NULL,
                PRIMARY KEY(tenant,id,revision), UNIQUE(tenant,commit_index)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS context_subject ON context_document(tenant,subject,lifetime,method,id,revision);
            CREATE TABLE IF NOT EXISTS context_progress(tenant BLOB PRIMARY KEY CHECK(length(tenant)=16), head BLOB NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS revision_origin(
                tenant BLOB NOT NULL CHECK(length(tenant)=16), commit_index BLOB NOT NULL CHECK(length(commit_index)=8),
                head BLOB NOT NULL, PRIMARY KEY(tenant,commit_index)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS revision_event(
                tenant BLOB NOT NULL CHECK(length(tenant)=16), id BLOB NOT NULL CHECK(length(id)=32),
                commit_index BLOB NOT NULL CHECK(length(commit_index)=8), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 257),
                payload_digest BLOB NOT NULL CHECK(length(payload_digest)=32), event BLOB NOT NULL,
                PRIMARY KEY(tenant,id), UNIQUE(tenant,commit_index,ordinal)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS revision_position ON revision_event(tenant,commit_index,ordinal);
            CREATE TABLE IF NOT EXISTS revision_prefix(id INTEGER PRIMARY KEY CHECK(id=1), commit_index BLOB NOT NULL CHECK(length(commit_index)=8));
            INSERT OR IGNORE INTO revision_prefix VALUES(1,x'0000000000000000');
            PRAGMA user_version=4; COMMIT;")
            .context(DiscoveryDatabaseSnafu { operation: "initialize schema" })?;
        let first = Self::connection(&path, true)?;
        let second = Self::connection(&path, true)?;
        let index = Self {
            store,
            path,
            writer: Mutex::new(writer),
            writes: tokio::sync::Semaphore::new(9),
            readers: [Mutex::new(first), Mutex::new(second)],
            _lease: lease,
        };
        index.check_disk(0)?;
        Ok(index)
    }

    fn connection(path: &Path, read_only: bool) -> Result<Connection> {
        let flags = if read_only {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        };
        let db = Connection::open_with_flags(
            path,
            flags
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context(DiscoveryDatabaseSnafu {
            operation: "open connection",
        })?;
        db.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .context(DiscoveryDatabaseSnafu {
                operation: "set defensive mode",
            })?;
        db.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            8 * 1024 * 1024,
        )
        .context(DiscoveryDatabaseSnafu {
            operation: "bound row bytes",
        })?;
        db.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0)
            .context(DiscoveryDatabaseSnafu {
                operation: "disable attached databases",
            })?;
        db.busy_timeout(Duration::from_millis(100))
            .context(DiscoveryDatabaseSnafu {
                operation: "set busy bound",
            })?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;",
        )
        .context(DiscoveryDatabaseSnafu {
            operation: "configure connection",
        })?;
        if read_only {
            db.execute_batch("PRAGMA cache_size=-8192; PRAGMA query_only=ON;")
                .context(DiscoveryDatabaseSnafu {
                    operation: "configure reader",
                })?;
        } else {
            db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA cache_size=-32768;
                PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=67108864; PRAGMA max_page_count=245760;")
                .context(DiscoveryDatabaseSnafu { operation: "configure writer" })?;
            let mode: String = db
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .context(DiscoveryDatabaseSnafu {
                    operation: "verify WAL",
                })?;
            let sync: i64 = db
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .context(DiscoveryDatabaseSnafu {
                    operation: "verify durability",
                })?;
            DiscoveryInputManifestV1::require(mode == "wal" && sync == 2, "INDEX_DURABILITY")?;
        }
        for (pragma, expected) in [
            ("page_size", 4096),
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("temp_store", 2),
            ("cache_size", if read_only { -8192 } else { -32768 }),
            ("query_only", i64::from(read_only)),
        ] {
            let actual: i64 = db
                .pragma_query_value(None, pragma, |row| row.get(0))
                .context(DiscoveryDatabaseSnafu {
                    operation: "verify connection limits",
                })?;
            DiscoveryInputManifestV1::require(actual == expected, "INDEX_CONFIGURATION")?;
        }
        Ok(db)
    }

    fn check_disk(&self, reserve: u64) -> Result<()> {
        let mut bytes = 0_u64;
        for suffix in ["", "-wal", "-shm"] {
            let path = Self::sidecar(&self.path, suffix);
            let length = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(source) => return Err(source).context(IoSnafu { path }),
            };
            bytes = bytes.saturating_add(length);
            DiscoveryInputManifestV1::require(
                suffix != "-wal" || length.saturating_add(reserve) <= MAX_INDEX_WAL_BYTES,
                "INDEX_WAL_LIMIT",
            )?;
        }
        DiscoveryInputManifestV1::require(
            bytes.saturating_add(reserve) <= MAX_INDEX_DISK_BYTES / 2,
            "INDEX_DISK_LIMIT",
        )?;
        let mut total = 0_u64;
        for name in [
            "discovery-index.sqlite",
            "discovery-index.rebuild.sqlite",
            "discovery-index.previous.sqlite",
        ] {
            for suffix in ["", "-wal", "-shm"] {
                let path = self.store.root().join(format!("{name}{suffix}"));
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        DiscoveryInputManifestV1::require(metadata.is_file(), "INDEX_FILE_TYPE")?;
                        total = total.saturating_add(metadata.len());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => return Err(source).context(IoSnafu { path }),
                }
            }
        }
        DiscoveryInputManifestV1::require(
            total.saturating_add(reserve) <= MAX_INDEX_DISK_BYTES,
            "INDEX_REPLACEMENT_LIMIT",
        )
    }

    fn reserve_write(&self, writer: &Connection) -> Result<()> {
        let wal = Self::sidecar(&self.path, "-wal");
        if fs::metadata(&wal)
            .is_ok_and(|metadata| metadata.len() > MAX_INDEX_WAL_BYTES - INDEX_TRANSACTION_RESERVE)
        {
            writer
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .context(DiscoveryDatabaseSnafu {
                    operation: "bound WAL before write",
                })?;
        }
        self.check_disk(INDEX_TRANSACTION_RESERVE)
    }

    pub(super) fn export(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryExportPageV1> {
        let artifact = self.store.read_discovery_artifact(&head.artifact)?;
        DiscoveryInputManifestV1::require(
            artifact.payload.len() <= 8 * 1024 * 1024 && artifact.tenant_id == head.key.tenant_id,
            "EXPORT_SCOPE",
        )?;
        let page: DiscoveryExportPageV1 =
            rmp_serde::from_slice(&artifact.payload).map_err(|error| {
                DiscoverySnafu {
                    code: "EXPORT_SCHEMA",
                    reason: error.to_string(),
                }
                .build()
            })?;
        DiscoveryInputManifestV1::require(
            page.stream.tenant_id == head.key.tenant_id
                && artifact.dependencies
                    == page
                        .previous
                        .iter()
                        .map(|head| head.artifact.clone())
                        .collect::<Vec<_>>()
                && head.commit_index > 0
                && page
                    .previous
                    .as_ref()
                    .map_or(head.revision == 1, |previous| {
                        previous.key == head.key
                            && previous.commit_index < head.commit_index
                            && previous.revision.checked_add(1) == Some(head.revision)
                    }),
            "EXPORT_CHAIN",
        )?;
        Ok(page)
    }

    pub fn apply_export(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryIndexProgressV1> {
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&head.key)?.as_ref() == Some(head),
            "EXPORT_NOT_COMMITTED",
        )?;
        self.apply_committed(head, &self.export(head)?, head.commit_index)
    }

    pub fn replay_interval(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryIndexProgressV1> {
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&head.key)?.as_ref() == Some(head),
            "EXPORT_NOT_COMMITTED",
        )?;
        let mut chain = Vec::new();
        let mut current = Some(head.clone());
        while let Some(head) = current {
            DiscoveryInputManifestV1::require(chain.len() < 8192, "EXPORT_CHAIN_LIMIT")?;
            current = self.export(&head)?.previous;
            chain.push(head);
        }
        let mut progress = None;
        for previous in chain.iter().rev() {
            progress =
                Some(self.apply_committed(previous, &self.export(previous)?, head.commit_index)?);
        }
        progress.ok_or_else(|| {
            DiscoverySnafu {
                code: "EXPORT_CHAIN",
                reason: "the committed export chain is empty",
            }
            .build()
        })
    }

    fn apply_committed(
        &self,
        head: &DiscoveryHeadV1,
        page: &DiscoveryExportPageV1,
        committed_tip: u64,
    ) -> Result<DiscoveryIndexProgressV1> {
        let records = page.prepare()?;
        let input_bytes = page.input_bytes()?;
        self.store
            .reserve_discovery_index_tenant(head.key.tenant_id)?;
        let mut writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        self.reserve_write(&writer)?;
        let transaction = writer.transaction().context(DiscoveryDatabaseSnafu {
            operation: "begin apply",
        })?;
        let tenant = head.key.tenant_id.as_slice();
        let build = head.key.id.0.as_slice();
        let stream = serde_json::to_vec(&page.stream).map_err(|error| {
            DiscoverySnafu {
                code: "EXPORT_STREAM",
                reason: error.to_string(),
            }
            .build()
        })?;
        let existing = transaction.query_row("SELECT stream,commit_index,next_cursor,artifact,accepted,atom_count,input_bytes FROM source_progress WHERE tenant=?1 AND build=?2", params![tenant, build], |row| Ok((row.get::<_,Vec<u8>>(0)?, row.get::<_,[u8;8]>(1)?, row.get::<_,[u8;8]>(2)?, row.get::<_,[u8;32]>(3)?, row.get::<_,u64>(4)?, row.get::<_,u64>(5)?,row.get::<_,u64>(6)?)))
            .optional().context(DiscoveryDatabaseSnafu { operation: "read progress" })?;
        if let Some((known_stream, commit, next, artifact, accepted, atoms, bytes)) = &existing {
            DiscoveryInputManifestV1::require(known_stream == &stream, "EXPORT_STREAM_CONFLICT")?;
            DiscoveryInputManifestV1::require(
                u64::from_be_bytes(*commit) <= committed_tip,
                "INDEX_AHEAD_OF_COMMIT",
            )?;
            if u64::from_be_bytes(*commit) >= head.commit_index {
                if u64::from_be_bytes(*commit) == head.commit_index {
                    DiscoveryInputManifestV1::require(
                        *artifact == head.artifact.sha256
                            && u64::from_be_bytes(*next) == page.next_cursor()?,
                        "EXPORT_COMMIT_CONFLICT",
                    )?;
                }
                return Ok(DiscoveryIndexProgressV1 {
                    commit_index: u64::from_be_bytes(*commit),
                    next_cursor: u64::from_be_bytes(*next),
                    accepted_records: *accepted,
                    atom_count: *atoms,
                    input_bytes: *bytes,
                });
            }
            DiscoveryInputManifestV1::require(
                page.previous.as_ref().is_some_and(|previous| {
                    previous.commit_index == u64::from_be_bytes(*commit)
                        && previous.artifact.sha256 == *artifact
                }) && u64::from_be_bytes(*next) == page.first_cursor,
                "EXPORT_PROGRESS_GAP",
            )?;
        } else {
            DiscoveryInputManifestV1::require(page.previous.is_none(), "INDEX_REPLAY_REQUIRED")?;
            transaction
                .execute(
                    "INSERT INTO source_progress VALUES(?1,?2,?3,?4,?5,?6,0,0,0)",
                    params![
                        tenant,
                        build,
                        stream,
                        0_u64.to_be_bytes(),
                        page.first_cursor.to_be_bytes(),
                        [0_u8; 32]
                    ],
                )
                .context(DiscoveryDatabaseSnafu {
                    operation: "create progress",
                })?;
        }
        let mut accepted = existing.as_ref().map_or(0, |row| row.4);
        let mut atoms = existing.as_ref().map_or(0, |row| row.5);
        for (ordinal, record) in records.iter().enumerate() {
            Self::insert_record(&transaction, head, record, ordinal, &mut atoms)?;
            accepted += 1;
        }
        let next = page.next_cursor()?;
        transaction.execute("UPDATE source_progress SET commit_index=?3,next_cursor=?4,artifact=?5,accepted=?6,atom_count=?7,input_bytes=input_bytes+?8 WHERE tenant=?1 AND build=?2", params![tenant,build,head.commit_index.to_be_bytes(),next.to_be_bytes(),head.artifact.sha256,accepted,atoms,input_bytes])
            .context(DiscoveryDatabaseSnafu { operation: "advance progress" })?;
        #[cfg(test)]
        super::test_crash_boundary("before-sql-commit");
        transaction.commit().context(DiscoveryDatabaseSnafu {
            operation: "commit apply",
        })?;
        #[cfg(test)]
        super::test_crash_boundary("sql-commit");
        Ok(DiscoveryIndexProgressV1 {
            commit_index: head.commit_index,
            next_cursor: next,
            accepted_records: accepted,
            atom_count: atoms,
            input_bytes: existing.as_ref().map_or(0, |row| row.6) + input_bytes,
        })
    }

    fn insert_record(
        transaction: &Transaction<'_>,
        head: &DiscoveryHeadV1,
        record: &IndexedRecord,
        ordinal: usize,
        atoms: &mut u64,
    ) -> Result<()> {
        let tenant = head.key.tenant_id.as_slice();
        let build = head.key.id.0.as_slice();
        let cursor = record.cursor.to_be_bytes();
        let mut atom_id = None;
        let mut unresolved = record.unresolved;
        if let Some((id, key)) = &record.atom {
            let previous: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT exact_key FROM behavior_atom WHERE tenant=?1 AND build=?2 AND atom=?3",
                    params![tenant, build, id.0],
                    |row| row.get(0),
                )
                .optional()
                .context(DiscoveryDatabaseSnafu {
                    operation: "read atom",
                })?;
            if previous.is_none() && *atoms == MAX_DISCOVERY_ATOMS as u64 {
                unresolved = Some("ATOM_LIMIT");
            } else {
                DiscoveryInputManifestV1::require(
                    previous.as_ref().is_none_or(|previous| previous == key),
                    "ATOM_DIGEST_COLLISION",
                )?;
                transaction.execute("INSERT INTO behavior_atom VALUES(?1,?2,?3,?4,1,?5,?5) ON CONFLICT(tenant,build,atom) DO UPDATE SET n=n+1,last_cursor=max(last_cursor,excluded.last_cursor)", params![tenant,build,id.0,key,cursor])
                    .context(DiscoveryDatabaseSnafu { operation: "aggregate record" })?;
                *atoms += u64::from(previous.is_none());
                atom_id = Some(id.0.to_vec());
            }
        }
        transaction
            .execute(
                "INSERT INTO input_record VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    tenant,
                    build,
                    cursor,
                    record.payload_digest,
                    head.commit_index.to_be_bytes(),
                    ordinal as u32,
                    atom_id,
                    unresolved
                ],
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "index accepted record",
            })?;
        Ok(())
    }

    pub fn progress(
        &self,
        tenant: [u8; 16],
        build: &DiscoveryDigestV1,
    ) -> Result<Option<DiscoveryIndexProgressV1>> {
        let reader = self.reader()?;
        reader.query_row("SELECT commit_index,next_cursor,accepted,atom_count,input_bytes FROM source_progress WHERE tenant=?1 AND build=?2", params![tenant,build.0], |row| Ok(DiscoveryIndexProgressV1 {
            commit_index: u64::from_be_bytes(row.get(0)?), next_cursor: u64::from_be_bytes(row.get(1)?), accepted_records: row.get(2)?, atom_count: row.get(3)?,input_bytes:row.get(4)?,
        })).optional().context(DiscoveryDatabaseSnafu { operation: "read interval progress" })
    }

    fn reader(&self) -> Result<MutexGuard<'_, Connection>> {
        let reader = self
            .readers
            .iter()
            .find_map(|reader| reader.try_lock().ok())
            .ok_or_else(|| {
                DiscoverySnafu {
                    code: "INDEX_READ_LIMIT",
                    reason: "both index readers are in use",
                }
                .build()
            })?;
        let started = Instant::now();
        reader
            .progress_handler(
                1000,
                Some(move || started.elapsed() >= Duration::from_secs(1)),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "set read deadline",
            })?;
        Ok(reader)
    }

    pub fn atoms(
        &self,
        head: &DiscoveryHeadV1,
        after: Option<&DiscoveryDigestV1>,
    ) -> Result<DiscoveryAtomPageV1> {
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&head.key)?.as_ref() == Some(head),
            "EXPORT_NOT_COMMITTED",
        )?;
        let mut reader = self.reader()?;
        let transaction = reader.transaction().context(DiscoveryDatabaseSnafu {
            operation: "begin atom page",
        })?;
        let tenant = head.key.tenant_id;
        let build = head.key.id.0;
        let indexed = transaction
            .query_row(
                "SELECT commit_index,artifact FROM source_progress WHERE tenant=?1 AND build=?2",
                params![tenant, build],
                |row| Ok((u64::from_be_bytes(row.get(0)?), row.get::<_, [u8; 32]>(1)?)),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "check atom page revision",
            })?;
        DiscoveryInputManifestV1::require(
            indexed == Some((head.commit_index, head.artifact.sha256)),
            "INDEX_REVISION_UNAVAILABLE",
        )?;
        let comparison = if after.is_some() { ">" } else { ">=" };
        let sql = format!("SELECT atom,exact_key,n,first_cursor,last_cursor FROM behavior_atom WHERE tenant=?1 AND build=?2 AND atom {comparison} ?3 ORDER BY atom LIMIT 201");
        let mut statement = transaction.prepare(&sql).context(DiscoveryDatabaseSnafu {
            operation: "prepare atom page",
        })?;
        let mut rows = statement
            .query(params![tenant, build, after.map_or([0; 32], |id| id.0)])
            .context(DiscoveryDatabaseSnafu {
                operation: "read atom page",
            })?;
        let mut atoms = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        let mut samples = transaction.prepare("SELECT cursor FROM input_record WHERE tenant=?1 AND build=?2 AND atom=?3 ORDER BY cursor LIMIT 8").context(DiscoveryDatabaseSnafu { operation: "prepare atom samples" })?;
        while let Some(row) = rows.next().context(DiscoveryDatabaseSnafu {
            operation: "advance atom page",
        })? {
            if atoms.len() == 200 {
                more = true;
                break;
            }
            let (digest, encoded, count, first, last) = (|| -> rusqlite::Result<_> {
                Ok((
                    row.get::<_, [u8; 32]>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u64>(2)?,
                    u64::from_be_bytes(row.get(3)?),
                    u64::from_be_bytes(row.get(4)?),
                ))
            })()
            .context(DiscoveryDatabaseSnafu {
                operation: "decode atom row",
            })?;
            DiscoveryInputManifestV1::require(encoded.len() <= 1024 * 1024, "ATOM_ROW_LIMIT")?;
            let key: BehaviorAtomKeyV1 = serde_json::from_slice(&encoded).map_err(|error| {
                DiscoverySnafu {
                    code: "ATOM_ENCODING",
                    reason: error.to_string(),
                }
                .build()
            })?;
            DiscoveryInputManifestV1::require(
                DiscoveryDigestV1::of(&key)?.0 == digest && key.stream.tenant_id == tenant,
                "ATOM_DIGEST_MISMATCH",
            )?;
            let cursors = samples
                .query_map(params![tenant, build, digest], |row| {
                    Ok(u64::from_be_bytes(row.get(0)?))
                })
                .context(DiscoveryDatabaseSnafu {
                    operation: "read atom samples",
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(DiscoveryDatabaseSnafu {
                    operation: "decode atom samples",
                })?;
            let evidence = cursors
                .into_iter()
                .map(|durable_cursor| DiscoveryRecordIdV1 {
                    stream: key.stream.clone(),
                    cpu_id: key.cpu_id,
                    durable_cursor,
                })
                .collect();
            let atom = BehaviorAtomV1::from_key(
                DiscoveryDigestV1(digest),
                key,
                count,
                first,
                last,
                evidence,
            );
            let mut budget = super::model::InputByteLimit(1024 * 1024);
            serde_json::to_writer(&mut budget, &atom).map_err(|error| {
                DiscoverySnafu {
                    code: "ATOM_ROW_LIMIT",
                    reason: error.to_string(),
                }
                .build()
            })?;
            let atom_bytes = 1024 * 1024 - budget.0;
            if bytes + atom_bytes > 1024 * 1024 - 4096 {
                DiscoveryInputManifestV1::require(!atoms.is_empty(), "ATOM_ROW_LIMIT")?;
                more = true;
                break;
            }
            bytes += atom_bytes;
            atoms.push(atom);
        }
        let next = more
            .then(|| atoms.last().map(|atom| atom.id.clone()))
            .flatten();
        Ok(DiscoveryAtomPageV1 {
            export: head.clone(),
            atoms,
            next,
        })
    }

    pub(super) fn publish_snapshot(&self, head: &DiscoveryHeadV1) -> Result<()> {
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&head.key)?.as_ref() == Some(head),
            "SNAPSHOT_NOT_COMMITTED",
        )?;
        self.store
            .reserve_discovery_index_tenant(head.key.tenant_id)?;
        let writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        self.reserve_write(&writer)?;
        writer.execute("INSERT INTO profile_index VALUES(?1,?2,?3,?4) ON CONFLICT(tenant,snapshot) DO NOTHING", params![head.key.tenant_id,head.key.id.0,head.commit_index.to_be_bytes(),head.artifact.sha256])
            .context(DiscoveryDatabaseSnafu { operation: "publish snapshot projection" })?;
        let stored = writer
            .query_row(
                "SELECT commit_index,artifact FROM profile_index WHERE tenant=?1 AND snapshot=?2",
                params![head.key.tenant_id, head.key.id.0],
                |row| Ok((u64::from_be_bytes(row.get(0)?), row.get::<_, [u8; 32]>(1)?)),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "check snapshot projection",
            })?;
        DiscoveryInputManifestV1::require(
            stored == (head.commit_index, head.artifact.sha256),
            "SNAPSHOT_INDEX_CONFLICT",
        )
    }

    pub(super) fn snapshot_visible(&self, head: &DiscoveryHeadV1) -> Result<bool> {
        let reader = self.reader()?;
        let stored = reader
            .query_row(
                "SELECT commit_index,artifact FROM profile_index WHERE tenant=?1 AND snapshot=?2",
                params![head.key.tenant_id, head.key.id.0],
                |row| Ok((u64::from_be_bytes(row.get(0)?), row.get::<_, [u8; 32]>(1)?)),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "read snapshot projection",
            })?;
        Ok(stored == Some((head.commit_index, head.artifact.sha256)))
    }

    pub(super) fn require_context(&self, head: &DiscoveryHeadV1) -> Result<()> {
        let reader = self.reader()?;
        let known: Option<Vec<u8>> = reader
            .query_row(
                "SELECT head FROM context_progress WHERE tenant=?1",
                [head.key.tenant_id],
                |row| row.get(0),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "read context progress",
            })?;
        DiscoveryInputManifestV1::require(
            known.as_deref() == Some(Self::encode_context_head(head)?.as_slice()),
            "CONTEXT_INDEX_UNAVAILABLE",
        )
    }

    pub(super) fn context_document_count(&self, tenant: crate::EvidenceIdV1) -> Result<u64> {
        self.reader()?
            .query_row(
                "SELECT count(DISTINCT id) FROM context_document WHERE tenant=?1",
                [tenant.to_be_bytes()],
                |row| row.get(0),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "count context documents",
            })
    }

    fn encode_context_head(head: &DiscoveryHeadV1) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(head).map_err(|error| {
            DiscoverySnafu {
                code: "CONTEXT_INDEX_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })
    }

    fn decode_context_head(bytes: &[u8]) -> Result<DiscoveryHeadV1> {
        rmp_serde::from_slice(bytes).map_err(|error| {
            DiscoverySnafu {
                code: "CONTEXT_INDEX_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })
    }

    pub(super) fn context_document(
        &self,
        tenant: crate::EvidenceIdV1,
        id: &str,
        cutoff: u64,
    ) -> Result<Option<DiscoveryHeadV1>> {
        let reader = self.reader()?;
        let bytes: Option<Vec<u8>> = reader.query_row("SELECT head FROM context_document WHERE tenant=?1 AND id=?2 AND imported<=?3 ORDER BY revision DESC LIMIT 1",
            params![tenant.to_be_bytes(), id, cutoff.to_be_bytes()], |row| row.get(0)).optional()
            .context(DiscoveryDatabaseSnafu { operation: "select context document" })?;
        bytes.as_deref().map(Self::decode_context_head).transpose()
    }

    pub(super) fn context_revision(&self, head: &DiscoveryHeadV1) -> Result<bool> {
        let reader = self.reader()?;
        let bytes: Option<Vec<u8>> = reader
            .query_row(
                "SELECT head FROM context_document WHERE tenant=?1 AND commit_index=?2",
                params![head.key.tenant_id, head.commit_index.to_be_bytes()],
                |row| row.get(0),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "check context revision",
            })?;
        Ok(bytes.as_deref() == Some(Self::encode_context_head(head)?.as_slice()))
    }

    pub(super) fn context_candidates(
        &self,
        access: &DiscoveryContextAccessV1,
        method: &DiscoveryMethodV1,
        cutoff: u64,
    ) -> Result<Vec<DiscoveryHeadV1>> {
        let reader = self.reader()?;
        let mut query = reader.prepare("SELECT c.head FROM context_document c
            WHERE c.tenant=?1 AND c.subject=?2 AND c.lifetime=?3 AND c.method=?4 AND c.imported<=?5
            AND NOT EXISTS(SELECT 1 FROM context_document n WHERE n.tenant=c.tenant AND n.id=c.id AND n.revision>c.revision AND n.imported<=?5)
            ORDER BY c.id LIMIT 1025").context(DiscoveryDatabaseSnafu { operation: "prepare context selection" })?;
        let rows = query
            .query_map(
                params![
                    access.tenant_id.to_be_bytes(),
                    DiscoveryDigestV1::of(&access.subject)?.0,
                    access.lifetime.to_be_bytes(),
                    DiscoveryDigestV1::of(method)?.0,
                    cutoff.to_be_bytes()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "select context",
            })?;
        let mut heads = Vec::new();
        for row in rows {
            heads.push(Self::decode_context_head(&row.context(
                DiscoveryDatabaseSnafu {
                    operation: "read selected context",
                },
            )?)?);
        }
        DiscoveryInputManifestV1::require(heads.len() <= 1024, "CONTEXT_DOCUMENT_COUNT")?;
        Ok(heads)
    }

    pub(super) fn replay_context(&self, tip: &DiscoveryHeadV1) -> Result<()> {
        self.store
            .reserve_discovery_index_tenant(tip.key.tenant_id)?;
        use super::context::ContextRevision;
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&tip.key)?.as_ref() == Some(tip),
            "CONTEXT_NOT_COMMITTED",
        )?;
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        let known = {
            let reader = self.reader()?;
            let bytes: Option<Vec<u8>> = reader
                .query_row(
                    "SELECT head FROM context_progress WHERE tenant=?1",
                    [tip.key.tenant_id],
                    |row| row.get(0),
                )
                .optional()
                .context(DiscoveryDatabaseSnafu {
                    operation: "read context progress",
                })?;
            bytes
                .as_deref()
                .map(Self::decode_context_head)
                .transpose()?
        };
        if known.as_ref() == Some(tip) {
            return Ok(());
        }
        let mut chain = Vec::new();
        let mut current = Some(tip.clone());
        while current != known {
            let head = current.ok_or_else(|| {
                DiscoverySnafu {
                    code: "CONTEXT_INDEX_CONFLICT",
                    reason: "the index progress is not in the committed chain",
                }
                .build()
            })?;
            DiscoveryInputManifestV1::require(chain.len() < 8192, "CONTEXT_REVISION_LIMIT")?;
            current = ContextRevision::read(&self.store, &head)?.previous;
            chain.push(head);
        }
        for head in chain.into_iter().rev() {
            let revision = ContextRevision::read(&self.store, &head)?;
            let document = &revision.document;
            let mut writer = self.writer.lock().map_err(|_| {
                DiscoverySnafu {
                    code: "INDEX_OWNER",
                    reason: "the writer is poisoned",
                }
                .build()
            })?;
            self.reserve_write(&writer)?;
            let transaction = writer.transaction().context(DiscoveryDatabaseSnafu {
                operation: "begin context projection",
            })?;
            let previous: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT head FROM context_progress WHERE tenant=?1",
                    [head.key.tenant_id],
                    |row| row.get(0),
                )
                .optional()
                .context(DiscoveryDatabaseSnafu {
                    operation: "check context predecessor",
                })?;
            DiscoveryInputManifestV1::require(
                previous
                    == revision
                        .previous
                        .as_ref()
                        .map(Self::encode_context_head)
                        .transpose()?,
                "CONTEXT_INDEX_CONFLICT",
            )?;
            let ids: u64 = transaction
                .query_row(
                    "SELECT count(DISTINCT id) FROM context_document WHERE tenant=?1",
                    [head.key.tenant_id],
                    |row| row.get(0),
                )
                .context(DiscoveryDatabaseSnafu {
                    operation: "bound context documents",
                })?;
            DiscoveryInputManifestV1::require(
                ids < 1024 || document.revision > 1,
                "CONTEXT_DOCUMENT_COUNT",
            )?;
            let encoded = Self::encode_context_head(&head)?;
            transaction
                .execute(
                    "INSERT INTO context_document VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        head.key.tenant_id,
                        document.id,
                        document.revision.to_be_bytes(),
                        DiscoveryDigestV1::of(&document.subject)?.0,
                        document.lifetime.to_be_bytes(),
                        DiscoveryDigestV1::of(&document.method)?.0,
                        revision.imported_utc_ns.to_be_bytes(),
                        document.valid_from_utc_ns.to_be_bytes(),
                        document.valid_until_utc_ns.map(u64::to_be_bytes),
                        head.commit_index.to_be_bytes(),
                        encoded
                    ],
                )
                .context(DiscoveryDatabaseSnafu {
                    operation: "index context document",
                })?;
            transaction.execute("INSERT INTO context_progress VALUES(?1,?2) ON CONFLICT(tenant) DO UPDATE SET head=excluded.head",
                params![head.key.tenant_id, encoded]).context(DiscoveryDatabaseSnafu { operation: "advance context projection" })?;
            transaction.commit().context(DiscoveryDatabaseSnafu {
                operation: "commit context projection",
            })?;
        }
        self.require_context(tip)
    }

    pub(super) fn input_counts(&self, head: &DiscoveryHeadV1) -> Result<(u64, u64)> {
        let mut reader = self.reader()?;
        let transaction = reader.transaction().context(DiscoveryDatabaseSnafu {
            operation: "begin count check",
        })?;
        let indexed = transaction
            .query_row(
                "SELECT commit_index,artifact FROM source_progress WHERE tenant=?1 AND build=?2",
                params![head.key.tenant_id, head.key.id.0],
                |row| Ok((u64::from_be_bytes(row.get(0)?), row.get::<_, [u8; 32]>(1)?)),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "check count revision",
            })?;
        DiscoveryInputManifestV1::require(
            indexed == Some((head.commit_index, head.artifact.sha256)),
            "INDEX_REVISION_UNAVAILABLE",
        )?;
        transaction.query_row("SELECT count(*),coalesce(sum(atom IS NULL),0) FROM input_record WHERE tenant=?1 AND build=?2", params![head.key.tenant_id,head.key.id.0], |row| Ok((row.get(0)?,row.get(1)?)))
            .context(DiscoveryDatabaseSnafu { operation: "check indexed input counts" })
    }
}
