use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use duckdb::{params, Config, Connection, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use uuid::Uuid;

use crate::{AnalysisDatabaseSnafu, AnalysisStateSnafu, IoSnafu, JsonSnafu};
use crate::{
    EvidenceIntakeIdentityV1, Result, MAX_EVIDENCE_BATCH_RECORDS,
    MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES, MAX_EVIDENCE_GRPC_MESSAGE_BYTES,
    MAX_PENDING_EVIDENCE_RECORDS,
};

mod admission;

pub const ANALYSIS_DUCKDB_BINDING_VERSION: &str = "1.4.4";
pub const ANALYSIS_SQLPARSER_VERSION: &str = "0.63.0";
const ANALYSIS_SCHEMA_VERSION: i64 = 1;

pub struct AnalysisStore {
    root: PathBuf,
    _lease: File,
    writer: Mutex<Connection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisStoreMetaV1 {
    pub store_uuid: Uuid,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorePositionV1 {
    pub commit_revision: u64,
    pub ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSourceReceiptV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub contiguous_cursor: u64,
    pub coverage_revision: u64,
    pub retained_floor: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedEvidenceBatchV1 {
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub framed_records: prost::bytes::Bytes,
    pub frame_ends: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCoverageV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub revision: u64,
    pub encoded_report: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStoreOutcomeV1 {
    Accepted,
    Pending,
}

impl AnalysisStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis path is not absolute".to_owned(),
            }
            .fail();
        }
        match DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: &root }),
        }
        let metadata = fs::symlink_metadata(&root).context(IoSnafu { path: &root })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis directory is not private".to_owned(),
            }
            .fail();
        }
        let filesystem = rustix::fs::statfs(&root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &root })?;
        if !matches!(filesystem.f_type, 0xef53 | 0x0102_1994) {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis filesystem is not qualified".to_owned(),
            }
            .fail();
        }

        let lease_path = root.join("analysis.lock");
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lease_path)
            .context(IoSnafu { path: &lease_path })?;
        let lease_metadata = lease.metadata().context(IoSnafu { path: &lease_path })?;
        if !lease_metadata.is_file() || lease_metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStateSnafu {
                path: lease_path,
                reason: "the analysis lease file is not private".to_owned(),
            }
            .fail();
        }
        lease.try_lock().map_err(|error| {
            AnalysisStateSnafu {
                path: root.clone(),
                reason: format!("the analysis writer is already owned: {error}"),
            }
            .build()
        })?;

        let path = root.join("analysis.duckdb");
        let existing = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return AnalysisStateSnafu {
                        path,
                        reason: "the analysis database file is not private".to_owned(),
                    }
                    .fail();
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };

        let config = Config::default()
            .enable_autoload_extension(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable extension loading",
            })?
            .enable_external_access(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable external access",
            })?;
        let mut writer = Connection::open_with_flags(&path, config)
            .context(AnalysisDatabaseSnafu { operation: "open" })?;
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        if !metadata.is_file() {
            return AnalysisStateSnafu {
                path,
                reason: "the analysis database path is not a file".to_owned(),
            }
            .fail();
        }
        if !existing {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .context(IoSnafu { path: &path })?;
        }
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin schema",
        })?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS store_meta (
                    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                    store_uuid VARCHAR NOT NULL,
                    schema_version INTEGER NOT NULL,
                    recovery_epoch UBIGINT NOT NULL,
                    commit_revision UBIGINT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS relation_revisions (
                    relation_name VARCHAR PRIMARY KEY,
                    last_changed_revision UBIGINT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_receipts (
                    stream_key BLOB PRIMARY KEY,
                    identity_json VARCHAR NOT NULL,
                    tenant_id BLOB NOT NULL,
                    cpu_id UINTEGER NOT NULL,
                    contiguous_cursor UBIGINT NOT NULL,
                    coverage_revision UBIGINT NOT NULL,
                    retained_floor UBIGINT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    durable_cursor UBIGINT NOT NULL,
                    cpu_id UINTEGER NOT NULL,
                    framed_record BLOB NOT NULL,
                    frame_sha256 BLOB NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    ordinal UINTEGER NOT NULL,
                    PRIMARY KEY (stream_key, durable_cursor)
                );
                CREATE TABLE IF NOT EXISTS coverage (
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    revision UBIGINT NOT NULL,
                    report BLOB NOT NULL,
                    report_sha256 BLOB NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    ordinal UINTEGER NOT NULL,
                    PRIMARY KEY (stream_key, revision)
                );",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "create schema",
            })?;
        let initial_uuid = Uuid::new_v4().hyphenated().to_string();
        transaction
            .execute(
                "INSERT INTO store_meta
                 SELECT true, ?, ?, 1, 0 WHERE NOT EXISTS (SELECT 1 FROM store_meta)",
                params![initial_uuid, ANALYSIS_SCHEMA_VERSION],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "initialize store identity",
            })?;
        let meta = Self::read_meta_from(&transaction, &path)?;
        if meta.schema_version != ANALYSIS_SCHEMA_VERSION as u32 {
            return AnalysisStateSnafu {
                path,
                reason: "the analysis schema version is unsupported".to_owned(),
            }
            .fail();
        }
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit schema",
        })?;
        Ok(Self {
            root,
            _lease: lease,
            writer: Mutex::new(writer),
        })
    }

    pub fn meta(&self) -> Result<AnalysisStoreMetaV1> {
        let writer = self.writer()?;
        Self::read_meta_from(&writer, &self.root.join("analysis.duckdb"))
    }

    pub fn source_receipt(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        let key = source_key(identity);
        let writer = self.writer()?;
        Self::read_receipt_from(&writer, &self.root, identity, &key)
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    pub fn accept_validated_batch(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.validate_batch(&identity, &batch)?;
        let key = source_key(&identity);
        let identity_json = serde_json::to_string(&identity).context(JsonSnafu {
            path: self.root.join("analysis.duckdb"),
        })?;
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin evidence",
        })?;
        let previous = Self::read_receipt_from(&transaction, &self.root, &identity, &key)?;
        if previous
            .as_ref()
            .is_some_and(|receipt| receipt.cpu_id != batch.cpu_id)
        {
            return self.reject("one evidence source epoch changed CPU identity");
        }
        let contiguous = previous
            .as_ref()
            .map_or(0, |receipt| receipt.contiguous_cursor);
        if batch.first_cursor > contiguous.saturating_add(1)
            && batch.last_cursor > contiguous.saturating_add(MAX_PENDING_EVIDENCE_RECORDS)
        {
            return self.reject("out-of-order evidence exceeds the pending window");
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let mut new_records = 0_u32;
        let mut frame_start = 0;
        for (index, frame_end) in batch.frame_ends.iter().copied().enumerate() {
            let frame = &batch.framed_records[frame_start..frame_end];
            frame_start = frame_end;
            let cursor = batch
                .first_cursor
                .checked_add(index as u64)
                .ok_or_else(|| self.state_error("the evidence cursor is exhausted"))?;
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT framed_record FROM events WHERE stream_key = ? AND durable_cursor = ?",
                    params![key.as_slice(), cursor],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read duplicate evidence",
                })?;
            if let Some(existing) = existing {
                if existing != frame {
                    return self.reject("an evidence retry has conflicting record content");
                }
                continue;
            }
            if cursor <= contiguous {
                return self.reject("an acknowledged evidence record is not retained");
            }
            let frame_digest: [u8; 32] = Sha256::digest(frame).into();
            transaction
                .execute(
                    "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        cursor,
                        batch.cpu_id,
                        frame,
                        frame_digest.as_slice(),
                        revision,
                        new_records,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert evidence",
                })?;
            new_records += 1;
        }
        if new_records == 0 {
            return Ok(if contiguous >= batch.last_cursor {
                EvidenceStoreOutcomeV1::Accepted
            } else {
                EvidenceStoreOutcomeV1::Pending
            });
        }
        let mut next_contiguous = contiguous;
        {
            let mut statement = transaction
                .prepare(
                    "SELECT durable_cursor FROM events WHERE stream_key = ?
                     AND durable_cursor > ? ORDER BY durable_cursor",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare contiguous evidence scan",
                })?;
            let mut rows = statement
                .query(params![key.as_slice(), contiguous])
                .context(AnalysisDatabaseSnafu {
                    operation: "scan contiguous evidence",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "scan contiguous evidence",
            })? {
                let cursor: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "read evidence cursor",
                })?;
                if next_contiguous.checked_add(1) != Some(cursor) {
                    break;
                }
                next_contiguous = cursor;
            }
        }
        if previous.is_some() {
            transaction
                .execute(
                    "UPDATE source_receipts SET contiguous_cursor = ? WHERE stream_key = ?",
                    params![next_contiguous, key.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance source receipt",
                })?;
        } else {
            transaction
                .execute(
                    "INSERT INTO source_receipts VALUES (?, ?, ?, ?, ?, 0, 0)",
                    params![
                        key.as_slice(),
                        identity_json,
                        identity.tenant_id.as_slice(),
                        batch.cpu_id,
                        next_contiguous,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert source receipt",
                })?;
        }
        for relation in ["events", "source_receipts"] {
            transaction
                .execute(
                    "INSERT INTO relation_revisions VALUES (?, ?)
                     ON CONFLICT (relation_name) DO UPDATE SET last_changed_revision = EXCLUDED.last_changed_revision",
                    params![relation, revision],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance relation revision",
                })?;
        }
        transaction
            .execute(
                "UPDATE store_meta SET commit_revision = ? WHERE singleton = true",
                params![revision],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance store revision",
            })?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit evidence",
        })?;
        Ok(if next_contiguous >= batch.last_cursor {
            EvidenceStoreOutcomeV1::Accepted
        } else {
            EvidenceStoreOutcomeV1::Pending
        })
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    pub fn accept_validated_coverage(&self, input: ValidatedCoverageV1) -> Result<u64> {
        let identity = &input.identity;
        if !valid_source_identity(identity)
            || input.revision == 0
            || input.encoded_report.is_empty()
            || input.encoded_report.len() > MAX_EVIDENCE_GRPC_MESSAGE_BYTES
        {
            return self.reject("the validated coverage identity or bounds are invalid");
        }
        let bytes = &input.encoded_report;
        let key = source_key(identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin coverage",
        })?;
        let previous = Self::read_receipt_from(&transaction, &self.root, identity, &key)?;
        if previous
            .as_ref()
            .is_some_and(|receipt| receipt.cpu_id != input.cpu_id)
        {
            return self.reject("coverage changed the bound evidence CPU identity");
        }
        let current_revision = previous
            .as_ref()
            .map_or(0, |receipt| receipt.coverage_revision);
        if input.revision <= current_revision {
            if input.revision == current_revision {
                let existing: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT report FROM coverage WHERE stream_key = ? AND revision = ?",
                        params![key.as_slice(), input.revision],
                        |row| row.get(0),
                    )
                    .optional()
                    .context(AnalysisDatabaseSnafu {
                        operation: "read duplicate coverage",
                    })?;
                if existing.as_deref() == Some(bytes.as_slice()) {
                    return Ok(current_revision);
                }
            }
            return self.reject("coverage evidence is stale or has conflicting content");
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        transaction
            .execute(
                "INSERT INTO coverage VALUES (?, ?, ?, ?, ?, ?, 0)",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    input.revision,
                    bytes.as_slice(),
                    digest.as_slice(),
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert coverage",
            })?;
        if previous.is_some() {
            transaction
                .execute(
                    "UPDATE source_receipts SET coverage_revision = ? WHERE stream_key = ?",
                    params![input.revision, key.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance coverage receipt",
                })?;
        } else {
            let identity_json = serde_json::to_string(identity).context(JsonSnafu {
                path: self.root.join("analysis.duckdb"),
            })?;
            transaction
                .execute(
                    "INSERT INTO source_receipts VALUES (?, ?, ?, ?, 0, ?, 0)",
                    params![
                        key.as_slice(),
                        identity_json,
                        identity.tenant_id.as_slice(),
                        input.cpu_id,
                        input.revision,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert coverage receipt",
                })?;
        }
        for relation in ["coverage", "source_receipts"] {
            transaction
                .execute(
                    "INSERT INTO relation_revisions VALUES (?, ?)
                     ON CONFLICT (relation_name) DO UPDATE SET last_changed_revision = EXCLUDED.last_changed_revision",
                    params![relation, revision],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance relation revision",
                })?;
        }
        transaction
            .execute(
                "UPDATE store_meta SET commit_revision = ? WHERE singleton = true",
                params![revision],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance store revision",
            })?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit coverage",
        })?;
        Ok(input.revision)
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    fn validate_batch(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &ValidatedEvidenceBatchV1,
    ) -> Result<()> {
        if !valid_source_identity(identity)
            || batch.first_cursor == 0
            || batch.frame_ends.is_empty()
            || batch.frame_ends.len() > MAX_EVIDENCE_BATCH_RECORDS
            || batch.framed_records.len() > MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES
            || batch.frame_ends.last().copied() != Some(batch.framed_records.len())
            || batch
                .frame_ends
                .iter()
                .scan(0, |prior, end| {
                    let increasing = *end > *prior;
                    *prior = *end;
                    Some(increasing)
                })
                .any(|increasing| !increasing)
            || batch
                .first_cursor
                .checked_add(batch.frame_ends.len() as u64 - 1)
                != Some(batch.last_cursor)
        {
            return self.reject("the validated evidence identity or bounds are invalid");
        }
        Ok(())
    }

    fn read_receipt_from(
        connection: &Connection,
        root: &Path,
        identity: &EvidenceIntakeIdentityV1,
        key: &[u8; 32],
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        let stored: Option<(String, Vec<u8>, u32, u64, u64, u64)> = connection
            .query_row(
                "SELECT identity_json, tenant_id, cpu_id, contiguous_cursor,
                        coverage_revision, retained_floor
                 FROM source_receipts WHERE stream_key = ?",
                params![key.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read source receipt",
            })?;
        stored
            .map(
                |(
                    identity_json,
                    tenant,
                    cpu_id,
                    contiguous_cursor,
                    coverage_revision,
                    retained_floor,
                )| {
                    let saved: EvidenceIntakeIdentityV1 = serde_json::from_str(&identity_json)
                        .context(JsonSnafu {
                            path: root.join("analysis.duckdb"),
                        })?;
                    if &saved != identity || tenant != identity.tenant_id {
                        return AnalysisStateSnafu {
                            path: root.join("analysis.duckdb"),
                            reason: "the source key does not match its durable identity".to_owned(),
                        }
                        .fail();
                    }
                    Ok(AnalysisSourceReceiptV1 {
                        identity: saved,
                        cpu_id,
                        contiguous_cursor,
                        coverage_revision,
                        retained_floor,
                    })
                },
            )
            .transpose()
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    fn reject<T>(&self, reason: &str) -> Result<T> {
        AnalysisStateSnafu {
            path: self.root.clone(),
            reason: reason.to_owned(),
        }
        .fail()
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    fn state_error(&self, reason: &str) -> crate::Error {
        AnalysisStateSnafu {
            path: self.root.clone(),
            reason: reason.to_owned(),
        }
        .build()
    }

    fn writer(&self) -> Result<MutexGuard<'_, Connection>> {
        self.writer.lock().map_err(|_| {
            AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the analysis writer lock is poisoned".to_owned(),
            }
            .build()
        })
    }

    fn read_meta_from(connection: &Connection, path: &Path) -> Result<AnalysisStoreMetaV1> {
        let (uuid, schema_version, recovery_epoch, commit_revision): (String, i64, u64, u64) =
            connection
                .query_row(
                    "SELECT store_uuid, schema_version, recovery_epoch, commit_revision
                     FROM store_meta WHERE singleton = true",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read store identity",
                })?;
        let store_uuid = Uuid::parse_str(&uuid).map_err(|error| {
            AnalysisStateSnafu {
                path: path.to_path_buf(),
                reason: format!("the store UUID is invalid: {error}"),
            }
            .build()
        })?;
        let schema_version = u32::try_from(schema_version).map_err(|error| {
            AnalysisStateSnafu {
                path: path.to_path_buf(),
                reason: format!("the schema version is invalid: {error}"),
            }
            .build()
        })?;
        Ok(AnalysisStoreMetaV1 {
            store_uuid,
            schema_version,
            recovery_epoch,
            commit_revision,
        })
    }
}

fn valid_source_identity(identity: &EvidenceIntakeIdentityV1) -> bool {
    crate::node_id_is_valid(&identity.node_id)
        && identity.tenant_id != [0; 16]
        && identity.node_boot_id != [0; 16]
        && identity.source_id != [0; 16]
        && identity.label_epoch != 0
        && identity.source_epoch != 0
}

fn source_key(identity: &EvidenceIntakeIdentityV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ARAPHOR-ANALYSIS-SOURCE-V1\0");
    hash.update(identity.tenant_id);
    hash.update((identity.node_id.len() as u64).to_be_bytes());
    hash.update(identity.node_id.as_bytes());
    hash.update(identity.node_boot_id);
    hash.update(identity.label_epoch.to_be_bytes());
    hash.update(identity.source_id);
    hash.update(identity.source_epoch.to_be_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
    }

    fn batch(first_cursor: u64, records: &[&[u8]]) -> ValidatedEvidenceBatchV1 {
        let mut framed_records = Vec::new();
        let mut frame_ends = Vec::new();
        for record in records {
            framed_records.extend_from_slice(record);
            frame_ends.push(framed_records.len());
        }
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor,
            last_cursor: first_cursor + records.len() as u64 - 1,
            framed_records: framed_records.into(),
            frame_ends,
        }
    }

    fn coverage(
        identity: &EvidenceIntakeIdentityV1,
        revision: u64,
        bytes: &[u8],
    ) -> ValidatedCoverageV1 {
        ValidatedCoverageV1 {
            identity: identity.clone(),
            cpu_id: 0,
            revision,
            encoded_report: bytes.to_vec(),
        }
    }

    #[test]
    fn analysis_store_identity_and_rollback_survive_reopen(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let initial = store.meta()?;
        assert_eq!(initial.schema_version, 1);
        assert_eq!(initial.commit_revision, 0);
        assert!(AnalysisStore::open(&root).is_err());
        {
            let mut writer = store.writer()?;
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin rollback proof",
            })?;
            transaction
                .execute("UPDATE store_meta SET commit_revision = 1", [])
                .context(AnalysisDatabaseSnafu {
                    operation: "write rollback proof",
                })?;
        }
        assert_eq!(store.meta()?, initial);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.meta()?, initial);
        let writer = reopened.writer()?;
        let version: String = writer
            .query_row("SELECT version()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read engine version",
            })?;
        assert!(version.contains(ANALYSIS_DUCKDB_BINDING_VERSION));
        assert!(writer
            .execute_batch("COPY (SELECT 1) TO '/tmp/araphor-analysis-forbidden.csv'")
            .is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_rejects_newer_schema_and_nonprivate_directory(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        {
            let writer = store.writer()?;
            writer.execute("UPDATE store_meta SET schema_version = 2", [])?;
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(AnalysisStore::open("relative-analysis").is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_evidence_receipt_is_atomic_and_gap_aware(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let first = b"first".as_slice();
        let second = b"second".as_slice();
        let third = b"third".as_slice();

        let pending = batch(2, &[second]);
        assert_eq!(
            store.accept_validated_batch(identity.clone(), pending.clone())?,
            EvidenceStoreOutcomeV1::Pending
        );
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            0
        );
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &[first]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(store.meta()?.commit_revision, 2);
        {
            let writer = store.writer()?;
            let key = source_key(&identity);
            let position: (u64, u32) = writer.query_row(
                "SELECT commit_revision, ordinal FROM events
                 WHERE stream_key = ? AND durable_cursor = 2",
                params![key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(position, (1, 0));
        }
        assert_eq!(
            store.accept_validated_batch(identity.clone(), pending)?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, 2);

        assert!(store
            .accept_validated_batch(identity.clone(), batch(2, &[b"changed"]))
            .is_err());
        assert_eq!(store.meta()?.commit_revision, 2);

        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(4, &[third]))?,
            EvidenceStoreOutcomeV1::Pending
        );
        assert!(store
            .accept_validated_batch(identity.clone(), batch(3, &[third, b"changed"]))
            .is_err());
        assert_eq!(store.meta()?.commit_revision, 3);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        {
            let writer = store.writer()?;
            let count: u64 =
                writer.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
            assert_eq!(count, 3);
        }
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(
            reopened
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(
            reopened.accept_validated_batch(identity.clone(), batch(3, &[third]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            reopened
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            4
        );
        Ok(())
    }

    #[test]
    fn analysis_store_coverage_receipt_is_atomic_and_idempotent(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let accepted = coverage(&identity, 1, b"coverage-1");
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 0);
        assert_eq!(receipt.coverage_revision, 1);
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);

        let conflicting = coverage(&identity, 1, b"changed");
        assert!(store.accept_validated_coverage(conflicting).is_err());
        assert_eq!(store.meta()?.commit_revision, 1);

        let newer = coverage(&identity, 3, b"coverage-3");
        assert_eq!(store.accept_validated_coverage(newer)?, 3);
        assert_eq!(store.meta()?.commit_revision, 2);
        let stale = coverage(&identity, 2, b"coverage-2");
        assert!(store.accept_validated_coverage(stale).is_err());
        assert_eq!(store.meta()?.commit_revision, 2);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.meta()?.commit_revision, 2);
        let receipt = reopened
            .source_receipt(&identity)?
            .ok_or("receipt absent")?;
        assert_eq!(receipt.coverage_revision, 3);
        assert_eq!(receipt.contiguous_cursor, 0);
        Ok(())
    }

    #[test]
    fn analysis_store_commit_before_ack_survives_process_exit(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let identity = identity();
        if let Some(root) = std::env::var_os("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT") {
            let store = AnalysisStore::open(PathBuf::from(root))?;
            assert_eq!(
                store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
                EvidenceStoreOutcomeV1::Accepted
            );
            std::process::exit(73);
        }

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let status = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("analysis::tests::analysis_store_commit_before_ack_survives_process_exit")
            .env("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT", &root)
            .status()?;
        assert_eq!(status.code(), Some(73));
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, 1);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent after crash")?
                .contiguous_cursor,
            1
        );
        assert_eq!(
            store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, 1);
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux bwrap and prlimit for the offline worker proof"]
    fn analysis_sql_worker_isolated_from_data_store(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let before = store.meta()?;
        let parent_net = std::fs::read_link("/proc/self/ns/net")?;
        let worker = std::env::current_exe()?;
        for (sql, expected_success) in [
            ("SELECT SUM(atom) FROM events WHERE id >= 2", true),
            ("COPY (SELECT * FROM events) TO '/tmp/forbidden'", false),
            ("SELECT read_text('/etc/passwd') FROM events", false),
        ] {
            let mut child = Command::new("/usr/bin/timeout")
                .args(["--kill-after=1s", "10s", "/usr/bin/bwrap"])
                .args([
                    "--unshare-all",
                    "--die-with-parent",
                    "--new-session",
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--symlink",
                    "usr/lib",
                    "/lib",
                    "--symlink",
                    "usr/lib64",
                    "/lib64",
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--tmpfs",
                    "/tmp",
                    "--ro-bind",
                ])
                .arg(&worker)
                .args([
                    "/worker",
                    "--clearenv",
                    "--setenv",
                    "ARAPHOR_QUERY_SQL",
                    sql,
                    "--",
                    "/usr/bin/prlimit",
                    "--as=1073741824",
                    "--cpu=5",
                    "--fsize=1048576",
                    "--nofile=32",
                    "--nproc=1",
                    "--",
                    "/worker",
                    "--exact",
                    "analysis::tests::analysis_sql_worker_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .ok_or("worker stdin is absent")?
                .write_all(b"1,2\n2,3\n3,4\n")?;
            let output = child.wait_with_output()?;
            assert_eq!(
                output.status.success(),
                expected_success,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if expected_success {
                let stdout = String::from_utf8(output.stdout)?;
                assert!(stdout.contains("ARAPHOR_QUERY_RESULT=7"), "{stdout}");
                assert!(!stdout.contains(&format!("ARAPHOR_NET_NS={}", parent_net.display())));
            }
            assert_eq!(store.meta()?, before);
        }
        Ok(())
    }

    #[test]
    #[ignore = "invoked only inside the offline query sandbox"]
    fn analysis_sql_worker_child() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;

        assert!(std::env::var_os("HOME").is_none());
        assert!(!Path::new("/home").exists());
        let sql = std::env::var("ARAPHOR_QUERY_SQL")?;
        let relations = admission::inspect_read_only_shape(&sql, &["events"])?;
        assert_eq!(relations.into_iter().collect::<Vec<_>>(), ["events"]);
        let config = Config::default()
            .enable_autoload_extension(false)?
            .enable_external_access(false)?;
        let mut connection = Connection::open_in_memory_with_flags(config)?;
        connection.execute_batch("CREATE TABLE events (id BIGINT, atom BIGINT)")?;
        let mut projection = String::new();
        std::io::stdin()
            .take(1024)
            .read_to_string(&mut projection)?;
        let transaction = connection.transaction()?;
        for line in projection.lines() {
            let (id, atom) = line.split_once(',').ok_or("invalid projection row")?;
            transaction.execute(
                "INSERT INTO events VALUES (?, ?)",
                params![id.parse::<i64>()?, atom.parse::<i64>()?],
            )?;
        }
        transaction.commit()?;
        let value: i64 = connection.query_row(&sql, [], |row| row.get(0))?;
        println!("ARAPHOR_QUERY_RESULT={value}");
        println!(
            "ARAPHOR_NET_NS={}",
            std::fs::read_link("/proc/self/ns/net")?.display()
        );
        Ok(())
    }
}
