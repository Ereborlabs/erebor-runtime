use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
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
    EvidenceCpuBindingV1, EvidenceIntakeIdentityV1, EvidenceRecord, ObservationEnvelopeV1, Result,
};

const MAX_INDEX_DISK_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_INDEX_WAL_BYTES: u64 = 64 * 1024 * 1024;
const INDEX_TRANSACTION_RESERVE: u64 = 32 * 1024 * 1024;
const INDEX_SCHEMA_VERSION: i64 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved_page() -> std::result::Result<DiscoveryExportPageV1, Box<dyn std::error::Error>> {
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
    fn discovery_index_rejects_future_schema_and_corrupt_files_without_changing_control(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        index
            .writer
            .lock()
            .map_err(|_| "writer poisoned")?
            .pragma_update(None, "user_version", 2)?;
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
    fn input_bytes(&self) -> Result<u64> {
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
                && !self.records.is_empty()
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
                let observation = ObservationEnvelopeV1::from_wire_record(
                    self.stream.tenant_id.into(),
                    self.stream.node_boot_id.into(),
                    self.stream.source_id.into(),
                    self.stream.source_epoch,
                    cursor,
                    cpu.cpu_id,
                    &wire,
                )
                .map_err(|error| {
                    DiscoverySnafu {
                        code: "EXPORT_RECORD",
                        reason: error.to_string(),
                    }
                    .build()
                })?;
                let record = DiscoveryRecordV1 {
                    id: DiscoveryRecordIdV1 {
                        stream: self.stream.clone(),
                        cpu_id: cpu.cpu_id,
                        durable_cursor: cursor,
                    },
                    original_kernel_sequence: wire
                        .decision_context
                        .as_ref()
                        .map(|context| context.original_kernel_sequence),
                    observation,
                };
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
    _lease: File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryIndexProgressV1 {
    pub commit_index: u64,
    pub next_cursor: u64,
    pub accepted_records: u64,
    pub atom_count: u64,
}

impl DiscoveryIndex {
    pub fn open(store: ControlStore) -> Result<Self> {
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
        let path = root.join("discovery-index.sqlite");
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
            version == 0 || version == INDEX_SCHEMA_VERSION,
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
            PRAGMA user_version=1; COMMIT;")
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
            let path = self
                .path
                .with_file_name(format!("discovery-index.sqlite{suffix}"));
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
        )
    }

    fn export(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryExportPageV1> {
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
        let mut writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        let wal = self.path.with_file_name("discovery-index.sqlite-wal");
        if fs::metadata(&wal)
            .is_ok_and(|metadata| metadata.len() > MAX_INDEX_WAL_BYTES - INDEX_TRANSACTION_RESERVE)
        {
            writer
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .context(DiscoveryDatabaseSnafu {
                    operation: "bound WAL before apply",
                })?;
        }
        self.check_disk(INDEX_TRANSACTION_RESERVE)?;
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
        let existing = transaction.query_row("SELECT stream,commit_index,next_cursor,artifact,accepted,atom_count FROM source_progress WHERE tenant=?1 AND build=?2", params![tenant, build], |row| Ok((row.get::<_,Vec<u8>>(0)?, row.get::<_,[u8;8]>(1)?, row.get::<_,[u8;8]>(2)?, row.get::<_,[u8;32]>(3)?, row.get::<_,u64>(4)?, row.get::<_,u64>(5)?)))
            .optional().context(DiscoveryDatabaseSnafu { operation: "read progress" })?;
        if let Some((known_stream, commit, next, artifact, accepted, atoms)) = &existing {
            DiscoveryInputManifestV1::require(known_stream == &stream, "EXPORT_STREAM_CONFLICT")?;
            DiscoveryInputManifestV1::require(
                u64::from_be_bytes(*commit) <= committed_tip,
                "INDEX_AHEAD_OF_COMMIT",
            )?;
            if u64::from_be_bytes(*commit) >= head.commit_index {
                if u64::from_be_bytes(*commit) == head.commit_index {
                    DiscoveryInputManifestV1::require(
                        *artifact == head.artifact.sha256
                            && u64::from_be_bytes(*next)
                                == page.first_cursor + records.len() as u64,
                        "EXPORT_COMMIT_CONFLICT",
                    )?;
                }
                return Ok(DiscoveryIndexProgressV1 {
                    commit_index: u64::from_be_bytes(*commit),
                    next_cursor: u64::from_be_bytes(*next),
                    accepted_records: *accepted,
                    atom_count: *atoms,
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
        let next = page.first_cursor + records.len() as u64;
        transaction.execute("UPDATE source_progress SET commit_index=?3,next_cursor=?4,artifact=?5,accepted=?6,atom_count=?7,input_bytes=input_bytes+?8 WHERE tenant=?1 AND build=?2", params![tenant,build,head.commit_index.to_be_bytes(),next.to_be_bytes(),head.artifact.sha256,accepted,atoms,input_bytes])
            .context(DiscoveryDatabaseSnafu { operation: "advance progress" })?;
        transaction.commit().context(DiscoveryDatabaseSnafu {
            operation: "commit apply",
        })?;
        Ok(DiscoveryIndexProgressV1 {
            commit_index: head.commit_index,
            next_cursor: next,
            accepted_records: accepted,
            atom_count: atoms,
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
        reader.query_row("SELECT commit_index,next_cursor,accepted,atom_count FROM source_progress WHERE tenant=?1 AND build=?2", params![tenant,build.0], |row| Ok(DiscoveryIndexProgressV1 {
            commit_index: u64::from_be_bytes(row.get(0)?), next_cursor: u64::from_be_bytes(row.get(1)?), accepted_records: row.get(2)?, atom_count: row.get(3)?,
        })).optional().context(DiscoveryDatabaseSnafu { operation: "read interval progress" })
    }
}
