use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use duckdb::{params, Config, Connection, OptionalExt as _};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use uuid::Uuid;

use crate::error::{AnalysisDatabaseSnafu, AnalysisStateSnafu, IoSnafu, JsonSnafu};
use crate::{
    CoverageReportInputV1, DiscoveryDigestV1, EvidenceBatchInputV1, EvidenceIntakeIdentityV1,
    EvidenceStoreOutcomeV1, Result, MAX_EVIDENCE_BATCH_RECORDS, MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES,
    MAX_EVIDENCE_GRPC_MESSAGE_BYTES, MAX_PENDING_EVIDENCE_RECORDS,
};

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
        let key = DiscoveryDigestV1::of(identity)?;
        let writer = self.writer()?;
        Self::read_receipt_from(&writer, &self.root, identity, &key.0)
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    pub(crate) fn accept_validated_batch(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: EvidenceBatchInputV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.validate_batch(&identity, &batch)?;
        let key = DiscoveryDigestV1::of(&identity)?.0;
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
    pub(crate) fn accept_validated_coverage(&self, input: CoverageReportInputV1) -> Result<u64> {
        let identity = &input.identity;
        let report = &input.report;
        if report.source_id.as_slice() != identity.source_id
            || report.source_epoch != identity.source_epoch
            || report.revision == 0
            || report.encoded_len() > MAX_EVIDENCE_GRPC_MESSAGE_BYTES
        {
            return self.reject("the validated coverage identity or bounds are invalid");
        }
        let bytes = report.encode_to_vec();
        let key = DiscoveryDigestV1::of(identity)?.0;
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin coverage",
        })?;
        let previous = Self::read_receipt_from(&transaction, &self.root, identity, &key)?;
        if previous
            .as_ref()
            .is_some_and(|receipt| receipt.cpu_id != report.cpu_id)
        {
            return self.reject("coverage changed the bound evidence CPU identity");
        }
        let current_revision = previous
            .as_ref()
            .map_or(0, |receipt| receipt.coverage_revision);
        if report.revision <= current_revision {
            if report.revision == current_revision {
                let existing: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT report FROM coverage WHERE stream_key = ? AND revision = ?",
                        params![key.as_slice(), report.revision],
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
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        transaction
            .execute(
                "INSERT INTO coverage VALUES (?, ?, ?, ?, ?, ?, 0)",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    report.revision,
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
                    params![report.revision, key.as_slice()],
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
                        report.cpu_id,
                        report.revision,
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
        Ok(report.revision)
    }

    #[allow(dead_code, reason = "offline proof precedes live intake cutover")]
    fn validate_batch(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &EvidenceBatchInputV1,
    ) -> Result<()> {
        if !crate::node_id_is_valid(&identity.node_id)
            || identity.tenant_id == [0; 16]
            || identity.node_boot_id == [0; 16]
            || identity.source_id == [0; 16]
            || identity.label_epoch == 0
            || identity.source_epoch == 0
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoverageCounters, CoverageInterval, CoverageReport, DiscoveryInputManifestV1};

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
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let identity = input.records[0].id.stream.clone();
        let first = input.records[0].observation.to_wire_record()?;
        let second = input.records[1].observation.to_wire_record()?;
        let third = input.records[2].observation.to_wire_record()?;

        let pending = EvidenceBatchInputV1::encode(2, vec![second.clone()])?;
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
            store.accept_validated_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(1, vec![first])?
            )?,
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
            let key = DiscoveryDigestV1::of(&identity)?.0;
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

        let mut conflicting_second = input.records[1].observation.clone();
        conflicting_second.ingested_utc_ns += 1;
        assert!(store
            .accept_validated_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(2, vec![conflicting_second.to_wire_record()?])?
            )
            .is_err());
        assert_eq!(store.meta()?.commit_revision, 2);

        assert_eq!(
            store.accept_validated_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(4, vec![third.clone()])?
            )?,
            EvidenceStoreOutcomeV1::Pending
        );
        let mut conflicting_fourth = input.records[2].observation.clone();
        conflicting_fourth.ingested_utc_ns += 1;
        assert!(store
            .accept_validated_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(
                    3,
                    vec![third.clone(), conflicting_fourth.to_wire_record()?]
                )?
            )
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
            reopened.accept_validated_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(3, vec![third])?
            )?,
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
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let identity = input.records[0].id.stream.clone();
        let report = CoverageReport {
            source_id: identity.source_id.to_vec(),
            source_epoch: identity.source_epoch,
            revision: 1,
            intervals: vec![CoverageInterval {
                interval_id: vec![1; 16],
                source_epoch: identity.source_epoch,
                revision: 1,
                state: "COMPLETE".to_owned(),
                first_sequence: 1,
                last_sequence: Some(3),
                opening_counters: Some(CoverageCounters::default()),
                closing_counters: Some(CoverageCounters {
                    attempted: 3,
                    requested: 3,
                    emitted: 3,
                    next_sequence: 4,
                    ..CoverageCounters::default()
                }),
                current: true,
                ..CoverageInterval::default()
            }],
            ..CoverageReport::default()
        };
        let accepted = CoverageReportInputV1 {
            identity: identity.clone(),
            report: report.clone(),
        };
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 0);
        assert_eq!(receipt.coverage_revision, 1);
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);

        let mut conflicting = accepted.clone();
        conflicting.report.intervals[0].state = "GAPPED".to_owned();
        assert!(store.accept_validated_coverage(conflicting).is_err());
        assert_eq!(store.meta()?.commit_revision, 1);

        let mut newer = accepted.clone();
        newer.report.revision = 3;
        newer.report.intervals[0].revision = 3;
        assert_eq!(store.accept_validated_coverage(newer)?, 3);
        assert_eq!(store.meta()?.commit_revision, 2);
        let mut stale = accepted;
        stale.report.revision = 2;
        stale.report.intervals[0].revision = 2;
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
}
