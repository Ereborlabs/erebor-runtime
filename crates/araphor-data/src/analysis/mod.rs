use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

use duckdb::{params, Connection, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tokio::sync::watch;
use uuid::Uuid;

use crate::{AnalysisDatabaseSnafu, AnalysisStateSnafu, IoSnafu, JsonSnafu};
use crate::{
    EvidenceIntakeIdentityV1, Result, MAX_EVIDENCE_BATCH_RECORDS,
    MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES, MAX_EVIDENCE_GRPC_MESSAGE_BYTES,
    MAX_PENDING_EVIDENCE_RECORDS,
};

mod admission;
mod backup;
mod capacity;
mod connection;
mod context;
#[cfg(test)]
mod crash;
mod health;
mod progress;
mod quota;
mod read;
mod retention;
mod retirement;
mod schema;
mod segment_file;
mod segments;

pub use backup::{AnalysisBackupManifestV1, AnalysisRecoveryStatusV1};
pub use capacity::{StorageLimitsV1, StorageUsageV1};
pub use context::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};
pub use health::{ProcessorHealthV1, ProcessorStateV1, StorageHealthV1};
pub use progress::{
    AnalysisContextRefV1, AnalysisGapV1, AnalysisResultCommitV1, AnalysisResultReceiptV1,
    AnalysisWitnessV1, ProcessorClassV1, ProcessorScopeV1,
};
pub use retention::{
    EvidenceRetentionOwner, RetentionLimitsV1, RetentionResultV1, RetentionSweepV1,
};
pub use retirement::ProcessorRetirementV1;
pub use segment_file::{SegmentFile, MAX_EVIDENCE_SEGMENT_BYTES};

pub const ANALYSIS_DUCKDB_BINDING_VERSION: &str = "1.10505.0";
pub const ANALYSIS_SQLPARSER_VERSION: &str = "0.63.0";
const ANALYSIS_SCHEMA_VERSION: i64 = 6;
pub const MAX_ANALYSIS_PAGE_RECORDS: usize = 256;
pub const MAX_ANALYSIS_PAGE_BYTES: usize = 1024 * 1024;

pub struct AnalysisStore {
    root: PathBuf,
    // Close the cloned readers before their owning writer.
    readers: [Mutex<Option<Connection>>; 2],
    writer: Mutex<Option<Connection>>,
    write_slots: tokio::sync::Semaphore,
    read_slots: tokio::sync::Semaphore,
    read_next: AtomicUsize,
    maintenance: RwLock<()>,
    revision: watch::Sender<u64>,
    retention_healthy: AtomicBool,
    write_ready: AtomicBool,
    retention: RetentionLimitsV1,
    storage: StorageLimitsV1,
    // Release the lease after the database connection closes.
    _lease: connection::AnalysisLease,
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
pub struct AnalysisRecordV1 {
    pub cursor: u64,
    pub framed_record: Vec<u8>,
    pub position: StorePositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisReadPageV1 {
    pub first_cursor: u64,
    pub records: Vec<AnalysisRecordV1>,
    pub encoded_bytes: usize,
    pub next_cursor: Option<u64>,
    pub read_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSourceReceiptV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub contiguous_cursor: u64,
    pub coverage_revision: u64,
    pub retained_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSourceStatusV1 {
    pub receipt: AnalysisSourceReceiptV1,
    pub retained_event_count: u64,
    pub latest_coverage_report: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedEvidenceBatchV1 {
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    /// Positive UTC time at durable intake.
    pub intake_utc_ns: u64,
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
    AlreadyAcceptedExpired,
}

impl AnalysisStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(root, Default::default(), Default::default())
    }

    pub fn open_with_limits(
        root: impl AsRef<Path>,
        retention: RetentionLimitsV1,
        storage: StorageLimitsV1,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !storage.valid() {
            return AnalysisStateSnafu {
                path: root,
                reason: "the storage capacity limits are invalid".to_owned(),
            }
            .fail();
        }
        if retention.raw_max_age_ns == 0 || retention.raw_max_bytes == 0 {
            return AnalysisStateSnafu {
                path: root,
                reason: "the raw retention limits must be positive".to_owned(),
            }
            .fail();
        }
        let lease = connection::AnalysisLease::acquire(&root)?;
        let pending = root.join("restore.pending");
        match fs::symlink_metadata(&pending) {
            Ok(_) => {
                return Self::reject_path(
                    &root,
                    "the analysis restore is incomplete; restore into a new directory",
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source).context(IoSnafu { path: &pending }),
        }
        Self::open_leased(root, retention, storage, lease)
    }

    fn open_leased(
        root: PathBuf,
        retention: RetentionLimitsV1,
        storage: StorageLimitsV1,
        lease: connection::AnalysisLease,
    ) -> Result<Self> {
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

        let mut writer = Self::open_native(&path)?;
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
        let prior = existing
            .then(|| Self::read_meta_from(&writer, &path))
            .transpose()?;
        if let Some(meta) = &prior {
            if meta.schema_version != ANALYSIS_SCHEMA_VERSION as u32 {
                return AnalysisStateSnafu {
                    path,
                    reason: "the analysis schema version is unsupported".to_owned(),
                }
                .fail();
            }
            Self::validate_tables(&writer)?;
            Self::validate_state(&writer, &root)?;
            Self::recover_segments(&mut writer, &root)?;
        }
        if !existing {
            Self::segment_directory(&root)?;
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
                    commit_revision UBIGINT NOT NULL,
                    next_segment_id UBIGINT NOT NULL
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
                CREATE TABLE IF NOT EXISTS source_bindings (
                    epoch_key BLOB PRIMARY KEY,
                    tenant_id BLOB NOT NULL,
                    node_boot_id BLOB NOT NULL,
                    label_epoch UBIGINT NOT NULL
                );
                CREATE TABLE segments (
                    segment_id UBIGINT PRIMARY KEY,
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    identity_json VARCHAR NOT NULL,
                    cpu_id UINTEGER NOT NULL,
                    stream_kind VARCHAR NOT NULL,
                    state VARCHAR NOT NULL CHECK (state IN ('Reserved', 'Live', 'Deleting')),
                    sealed BOOLEAN NOT NULL,
                    committed_end UBIGINT NOT NULL
                );
                CREATE TABLE batch_ranges (
                    segment_id UBIGINT NOT NULL,
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    byte_start UBIGINT NOT NULL,
                    byte_end UBIGINT NOT NULL,
                    first_cursor UBIGINT NOT NULL,
                    last_cursor UBIGINT NOT NULL,
                    frame_ends UINTEGER[] NOT NULL,
                    content_sha256 BLOB NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    ordinal UINTEGER NOT NULL,
                    intake_utc_ns UBIGINT NOT NULL,
                    PRIMARY KEY (tenant_id, stream_key, first_cursor)
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
                );
                CREATE TABLE IF NOT EXISTS context_versions (
                    tenant_id BLOB NOT NULL,
                    owner_id VARCHAR NOT NULL,
                    entity_key BLOB NOT NULL,
                    lifetime_key BLOB NOT NULL,
                    owner_revision UBIGINT NOT NULL,
                    valid_from_utc_ns UBIGINT,
                    valid_until_utc_ns UBIGINT,
                    sensitivity VARCHAR NOT NULL,
                    body BLOB NOT NULL,
                    content_sha256 BLOB NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    PRIMARY KEY (tenant_id, owner_id, entity_key, lifetime_key, owner_revision)
                );
                CREATE TABLE IF NOT EXISTS processor_progress (
                    processor_id VARCHAR NOT NULL,
                    method_version UBIGINT NOT NULL,
                    tenant_id BLOB NOT NULL,
                    stream_key BLOB NOT NULL,
                    class VARCHAR NOT NULL,
                    consumed_cursor UBIGINT NOT NULL,
                    resume_floor UBIGINT NOT NULL,
                    coverage_revision UBIGINT NOT NULL,
                    context_revision UBIGINT NOT NULL,
                    start_cursor UBIGINT NOT NULL,
                    required_floor UBIGINT NOT NULL,
                    retired BOOLEAN NOT NULL,
                    retirement_id VARCHAR NOT NULL,
                    retirement_reason VARCHAR NOT NULL,
                    retirement_cursor UBIGINT NOT NULL,
                    retirement_revision UBIGINT NOT NULL,
                    PRIMARY KEY (processor_id, method_version, tenant_id, stream_key)
                );
                CREATE TABLE IF NOT EXISTS evidence_refs (
                    ref_id VARCHAR NOT NULL,
                    tenant_id BLOB NOT NULL,
                    stream_key BLOB NOT NULL,
                    durable_cursor UBIGINT NOT NULL,
                    expires_utc_ns UBIGINT NOT NULL,
                    frame_sha256 BLOB NOT NULL,
                    PRIMARY KEY (ref_id, stream_key, durable_cursor)
                );
                CREATE TABLE IF NOT EXISTS context_refs (
                    ref_id VARCHAR NOT NULL,
                    tenant_id BLOB NOT NULL,
                    owner_id VARCHAR NOT NULL,
                    entity_key BLOB NOT NULL,
                    lifetime_key BLOB NOT NULL,
                    owner_revision UBIGINT NOT NULL,
                    content_sha256 BLOB NOT NULL,
                    PRIMARY KEY (ref_id, tenant_id, owner_id, entity_key, lifetime_key, owner_revision)
                );
                CREATE TABLE IF NOT EXISTS analysis_results (
                    result_id VARCHAR PRIMARY KEY,
                    tenant_id BLOB NOT NULL,
                    processor_id VARCHAR NOT NULL,
                    body BLOB NOT NULL,
                    body_sha256 BLOB NOT NULL,
                    request_sha256 BLOB NOT NULL,
                    commit_revision UBIGINT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS processor_gaps (
                    processor_id VARCHAR NOT NULL,
                    method_version UBIGINT NOT NULL,
                    tenant_id BLOB NOT NULL,
                    stream_key BLOB NOT NULL,
                    first_cursor UBIGINT NOT NULL,
                    last_cursor UBIGINT NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    PRIMARY KEY (processor_id, method_version, tenant_id, stream_key, first_cursor)
                );
                CREATE TABLE IF NOT EXISTS recovery_gaps (
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    first_cursor UBIGINT NOT NULL,
                    last_cursor UBIGINT NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    PRIMARY KEY (stream_key, first_cursor)
                );
                CREATE TABLE IF NOT EXISTS expired_ranges (
                    stream_key BLOB NOT NULL,
                    tenant_id BLOB NOT NULL,
                    first_cursor UBIGINT NOT NULL,
                    last_cursor UBIGINT NOT NULL,
                    commit_revision UBIGINT NOT NULL,
                    PRIMARY KEY (stream_key, first_cursor)
                );",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "create schema",
            })?;
            let initial_uuid = Uuid::new_v4().hyphenated().to_string();
            transaction
                .execute(
                    "INSERT INTO store_meta
                 SELECT true, ?, ?, 1, 0, 1 WHERE NOT EXISTS (SELECT 1 FROM store_meta)",
                    params![initial_uuid, ANALYSIS_SCHEMA_VERSION],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "initialize store identity",
                })?;
            transaction.commit().context(AnalysisDatabaseSnafu {
                operation: "commit schema",
            })?;
        }
        let meta = Self::read_meta_from(&writer, &path)?;
        let (revision, _) = watch::channel(meta.commit_revision);
        let readers = [
            Mutex::new(Some(writer.try_clone().context(AnalysisDatabaseSnafu {
                operation: "open first trusted reader",
            })?)),
            Mutex::new(Some(writer.try_clone().context(AnalysisDatabaseSnafu {
                operation: "open second trusted reader",
            })?)),
        ];
        Ok(Self {
            root,
            _lease: lease,
            writer: Mutex::new(Some(writer)),
            readers,
            write_slots: tokio::sync::Semaphore::new(9),
            read_slots: tokio::sync::Semaphore::new(16),
            read_next: AtomicUsize::new(0),
            maintenance: RwLock::new(()),
            revision,
            retention_healthy: AtomicBool::new(true),
            write_ready: AtomicBool::new(true),
            retention,
            storage,
        })
    }

    pub fn retention_healthy(&self) -> bool {
        self.retention_healthy.load(Ordering::Acquire)
    }

    pub fn retention_limits(&self) -> RetentionLimitsV1 {
        self.retention
    }

    fn require_retention(&self) -> Result<()> {
        if !self.retention_healthy() {
            self.require_capacity(true)?;
            return crate::RetentionUnavailableSnafu.fail();
        }
        Ok(())
    }

    pub fn subscribe_revision(&self) -> watch::Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn meta(&self) -> Result<AnalysisStoreMetaV1> {
        let writer_guard = self.reader()?;
        let writer = writer_guard.get()?;
        Self::read_meta_from(writer, &self.root.join("analysis.duckdb"))
    }

    pub fn source_receipt(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        let key = source_key(identity);
        let writer_guard = self.reader()?;
        let writer = writer_guard.get()?;
        Self::read_receipt_from(writer, &self.root, identity, &key)
    }

    pub fn source_status(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<AnalysisSourceStatusV1>> {
        let key = source_key(identity);
        let mut reader_guard = self.reader()?;
        let reader = reader_guard.get_mut()?;
        let writer = reader.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin source snapshot",
        })?;
        let Some(receipt) = Self::read_receipt_from(&writer, &self.root, identity, &key)? else {
            return Ok(None);
        };
        let retained_event_count = writer
            .query_row(
                "SELECT COALESCE(SUM(b.last_cursor::HUGEINT - b.first_cursor + 1), 0)::UBIGINT
                 FROM batch_ranges b JOIN segments s USING (segment_id)
                 WHERE b.stream_key = ? AND b.tenant_id = ? AND s.state = 'Live'",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count retained source events",
            })?;
        let latest_coverage_report = if receipt.coverage_revision == 0 {
            None
        } else {
            let stored: Option<(Vec<u8>, Vec<u8>)> = writer
                .query_row(
                    "SELECT report, report_sha256 FROM coverage
                     WHERE stream_key = ? AND tenant_id = ? AND revision = ?",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        receipt.coverage_revision
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read retained coverage",
                })?;
            let Some((report, digest)) = stored else {
                return self.reject("the source coverage receipt has no retained report");
            };
            if Sha256::digest(&report).as_slice() != digest {
                return self.reject("the retained coverage digest does not match its report");
            }
            Some(report)
        };
        Ok(Some(AnalysisSourceStatusV1 {
            receipt,
            retained_event_count,
            latest_coverage_report,
        }))
    }

    pub fn accept_validated_batch(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.require_retention()?;
        if batch.intake_utc_ns == 0 {
            return self.reject("live evidence has no intake time");
        }
        self.commit_evidence(identity, batch)
    }

    fn commit_evidence(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.validate_batch(&identity, &batch)?;
        let key = source_key(&identity);
        let identity_json = serde_json::to_string(&identity).context(JsonSnafu {
            path: self.root.join("analysis.duckdb"),
        })?;
        let mut writer_guard = self.maintenance_writer()?;
        let writer = writer_guard.get_mut()?;
        self.require_retention()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin evidence",
        })?;
        Self::bind_source(&transaction, &self.root, &identity)?;
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
        if let Some(receipt) = previous
            .as_ref()
            .filter(|receipt| batch.first_cursor <= receipt.retained_floor)
        {
            if batch.last_cursor <= receipt.retained_floor {
                return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
            }
            return self.reject("an evidence retry crosses an expired range boundary");
        }
        let expired: Option<(u64, u64)> = transaction
            .query_row(
                "SELECT first_cursor, last_cursor FROM expired_ranges
                 WHERE stream_key = ? AND tenant_id = ?
                 AND first_cursor <= ? AND last_cursor >= ? LIMIT 1",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    batch.last_cursor,
                    batch.first_cursor,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "check expired evidence retry",
            })?;
        if let Some((first, last)) = expired {
            if first <= batch.first_cursor
                && last >= batch.last_cursor
                && batch.last_cursor <= contiguous
            {
                return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
            }
            return self.reject("an evidence retry crosses an expired range boundary");
        }
        if batch.first_cursor > contiguous.saturating_add(1)
            && batch.last_cursor > contiguous.saturating_add(MAX_PENDING_EVIDENCE_RECORDS)
        {
            return self.reject("out-of-order evidence exceeds the pending window");
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let pending = self.prepare_batch(&transaction, &identity, &batch, contiguous)?;
        if pending.records == 0 {
            return Ok(if contiguous >= batch.last_cursor {
                EvidenceStoreOutcomeV1::Accepted
            } else {
                EvidenceStoreOutcomeV1::Pending
            });
        }
        drop(transaction);
        self.require_capacity(false)?;
        let append = self.reserve_segment(writer, &identity, batch.cpu_id, pending.bytes.len())?;
        let mut commit_attempted = false;
        let result = (|| {
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin segment publication",
            })?;
            let bound = Self::bind_source(&transaction, &self.root, &identity)?;
            pending.insert(
                &transaction,
                &identity,
                &append,
                revision,
                batch.intake_utc_ns,
            )?;
            self.check_required(&transaction, &identity, batch.intake_utc_ns)?;
            let mut next_contiguous = contiguous;
            {
                let mut statement = transaction
                    .prepare(
                        "SELECT first_cursor, last_cursor FROM batch_ranges
                     WHERE stream_key = ? AND tenant_id = ? AND last_cursor > ?
                     ORDER BY first_cursor",
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare contiguous evidence scan",
                    })?;
                let mut rows = statement
                    .query(params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        contiguous
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "scan contiguous evidence",
                    })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "scan contiguous evidence",
                })? {
                    let first: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                        operation: "read evidence cursor",
                    })?;
                    let last: u64 = row.get(1).context(AnalysisDatabaseSnafu {
                        operation: "read evidence cursor end",
                    })?;
                    if first > next_contiguous.saturating_add(1) {
                        break;
                    }
                    next_contiguous = next_contiguous.max(last);
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
            let mut relations = vec!["events", "source_receipts"];
            if bound {
                relations.push("source_bindings");
            }
            self.check_logical(&transaction, identity.tenant_id, false)?;
            self.check_witnesses(&transaction, identity.tenant_id, batch.intake_utc_ns)?;
            Self::record_revision(&transaction, revision, &relations)?;
            self.write_ready.store(false, Ordering::Release);
            self.sync_append(&append, &identity, &pending.bytes)?;
            #[cfg(test)]
            self.crash_at("evidence.before");
            commit_attempted = true;
            transaction.commit().context(AnalysisDatabaseSnafu {
                operation: "commit evidence",
            })?;
            #[cfg(test)]
            self.crash_at("evidence.after");
            self.write_ready.store(true, Ordering::Release);
            self.revision.send_replace(revision);
            Ok(if next_contiguous >= batch.last_cursor {
                EvidenceStoreOutcomeV1::Accepted
            } else {
                EvidenceStoreOutcomeV1::Pending
            })
        })();
        if result.is_err() && !commit_attempted {
            self.write_ready.store(false, Ordering::Release);
            if append.reserved {
                Self::remove_segment(writer, &self.root, append.segment_id, "Reserved")?;
            } else {
                SegmentFile::open(&segments::SegmentRange::path(&self.root, append.segment_id))?
                    .discard_tail(append.byte_start)?;
            }
            self.write_ready.store(true, Ordering::Release);
        }
        result
    }

    pub fn accept_validated_coverage(&self, input: ValidatedCoverageV1) -> Result<u64> {
        self.require_retention()?;
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
        let mut writer_guard = self.maintenance_writer()?;
        let writer = writer_guard.get_mut()?;
        self.require_retention()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin coverage",
        })?;
        let bound = Self::bind_source(&transaction, &self.root, identity)?;
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
        self.require_capacity(false)?;
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
        let mut relations = vec!["coverage", "source_receipts"];
        if bound {
            relations.push("source_bindings");
        }
        self.check_logical(&transaction, identity.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &relations)?;
        #[cfg(test)]
        self.crash_at("coverage.before");
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit coverage",
        })?;
        #[cfg(test)]
        self.crash_at("coverage.after");
        self.revision.send_replace(revision);
        Ok(input.revision)
    }

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

    fn reject<T>(&self, reason: &str) -> Result<T> {
        AnalysisStateSnafu {
            path: self.root.clone(),
            reason: reason.to_owned(),
        }
        .fail()
    }

    fn state_error(&self, reason: &str) -> crate::Error {
        AnalysisStateSnafu {
            path: self.root.clone(),
            reason: reason.to_owned(),
        }
        .build()
    }

    fn record_revision(
        transaction: &duckdb::Transaction<'_>,
        revision: u64,
        relations: &[&str],
    ) -> Result<()> {
        for relation in relations {
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
        Ok(())
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
    use duckdb::Config;

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
            intake_utc_ns: 1_000_000_000,
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
    fn analysis_store_reopen_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let initial = store.meta()?;
        assert_eq!(initial.schema_version, 6);
        assert_eq!(initial.commit_revision, 0);
        assert!(AnalysisStore::open(&root).is_err());
        {
            let mut writer_guard = store.writer()?;
            let writer = writer_guard.get_mut()?;
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
        let writer_guard = reopened.writer()?;
        let writer = writer_guard.get()?;
        let version: String = writer
            .query_row("SELECT version()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read engine version",
            })?;
        assert_eq!(version, "v1.5.5");
        assert!(writer
            .execute_batch("COPY (SELECT 1) TO '/tmp/araphor-analysis-forbidden.csv'")
            .is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_schema_permissions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for version in [0, 2, 3, 4, 5, 7] {
            let root = directory.path().join(format!("schema-{version}"));
            let store = AnalysisStore::open(&root)?;
            {
                let writer_guard = store.writer()?;
                let writer = writer_guard.get()?;
                writer.execute("UPDATE store_meta SET schema_version = ?", params![version])?;
            }
            drop(store);
            assert!(AnalysisStore::open(&root).is_err());
        }
        let root = directory.path().join("nonprivate");
        let store = AnalysisStore::open(&root)?;
        drop(store);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(AnalysisStore::open("relative-analysis").is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_batch_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
            let writer_guard = store.writer()?;
            let writer = writer_guard.get()?;
            let changed: u64 = writer.query_row(
                "SELECT COUNT(*) FROM relation_revisions WHERE last_changed_revision = 2",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(changed, 2);
            assert!(writer.prepare("SELECT * FROM events").is_err());
        }
        assert_eq!(
            store.read_page(&identity, 2)?.records[0].position,
            StorePositionV1 {
                commit_revision: 1,
                ordinal: 0
            }
        );
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
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            3
        );
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
        let mut relabeled = identity.clone();
        relabeled.label_epoch += 1;
        assert!(reopened
            .accept_validated_batch(relabeled, batch(1, &[b"first"]))
            .is_err());
        reopened.accept_validated_batch(identity.clone(), batch(5, &[first, second, third]))?;
        assert_eq!(
            reopened
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            7
        );
        let reader = reopened.reader()?;
        let count: u64 =
            reader
                .get()?
                .query_row("SELECT COUNT(*) FROM batch_ranges", [], |row| row.get(0))?;
        assert_eq!(count, 5);
        Ok(())
    }

    #[test]
    fn analysis_store_bulk_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let maximum = MAX_EVIDENCE_BATCH_RECORDS;
        store.accept_validated_batch(identity.clone(), batch(maximum as u64, &[b"frame"]))?;
        let before = store.meta()?;
        let mut changes = store.subscribe_revision();
        let _revision = *changes.borrow_and_update();
        let mut records = vec![b"frame".as_slice(); maximum];
        records[maximum - 1] = b"conflict";
        assert!(store
            .accept_validated_batch(identity.clone(), batch(1, &records))
            .is_err());
        assert_eq!(store.meta()?, before);
        assert!(!changes.has_changed()?);
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            1
        );
        records[maximum - 1] = b"frame";
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
        let revision = store.meta()?.commit_revision;
        store.accept_validated_batch(identity.clone(), batch(1, &records))?;
        assert_eq!(store.meta()?.commit_revision, revision);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let status = reopened.source_status(&identity)?.ok_or("source absent")?;
        assert_eq!(status.retained_event_count, maximum as u64);
        assert_eq!(status.receipt.contiguous_cursor, maximum as u64);
        Ok(())
    }

    #[test]
    fn analysis_store_bounded_read() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let mut changed = store.subscribe_revision();
        assert_eq!(*changed.borrow_and_update(), 0);
        let records = vec![b"one".as_slice(); 2 * MAX_ANALYSIS_PAGE_RECORDS + 1];
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert!(changed.has_changed()?);
        assert_eq!(*changed.borrow_and_update(), 1);
        let page = store.read_page(&identity, 1)?;
        assert_eq!(page.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(page.encoded_bytes, 3 * MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(page.next_cursor, Some(257));
        assert_eq!(page.read_revision, 1);
        assert_eq!(page.records[0].position.commit_revision, 1);
        assert_eq!(page.records[0].position.ordinal, 0);
        assert_eq!(page.records[255].position.ordinal, 255);
        let middle = store.read_page(&identity, 257)?;
        assert_eq!(middle.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(middle.records[0].cursor, 257);
        assert_eq!(middle.records[255].cursor, 512);
        assert_eq!(middle.next_cursor, Some(513));
        let last = store.read_page(&identity, 513)?;
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.next_cursor, None);
        let empty = store.read_page(&identity, 514)?;
        assert!(empty.records.is_empty());
        assert_eq!(empty.next_cursor, None);
        assert!(store.read_page(&identity, 0).is_err());
        assert!(store.read_page(&identity, 515).is_err());
        let mut foreign = identity.clone();
        foreign.tenant_id = [4; 16];
        assert!(store.read_page(&foreign, 1).is_err());
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert!(!changed.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(*reopened.subscribe_revision().borrow(), 1);
        assert_eq!(reopened.read_page(&identity, 257)?, middle);
        assert_eq!(reopened.read_page(&identity, 513)?, last);
        let mut large = identity.clone();
        large.source_epoch = 2;
        let frame = vec![42; MAX_ANALYSIS_PAGE_BYTES / 8];
        let frames = vec![frame.as_slice(); 9];
        reopened.accept_validated_batch(large.clone(), batch(1, &frames))?;
        let page = reopened.read_page(&large, 1)?;
        assert_eq!(page.records.len(), 8);
        assert_eq!(page.encoded_bytes, MAX_ANALYSIS_PAGE_BYTES);
        assert_eq!(page.next_cursor, Some(9));
        assert_eq!(
            reopened.read_page(&large, 9)?.records[0].framed_record,
            frame
        );
        {
            let writer = reopened.writer()?;
            writer.get()?.execute(
                "DELETE FROM events WHERE stream_key = ? AND durable_cursor = 257",
                params![source_key(&identity).as_slice()],
            )?;
        }
        assert!(matches!(
            reopened.read_page(&identity, 1),
            Err(crate::Error::AnalysisState { reason, .. })
                if reason == "the accepted evidence range has a missing record"
        ));
        Ok(())
    }

    #[test]
    fn analysis_store_coverage_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        assert_eq!(store.source_status(&identity)?, None);
        let accepted = coverage(&identity, 1, b"coverage-1");
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 0);
        assert_eq!(receipt.coverage_revision, 1);
        let status = store.source_status(&identity)?.ok_or("status absent")?;
        assert_eq!(status.receipt, receipt);
        assert_eq!(status.retained_event_count, 0);
        assert_eq!(status.latest_coverage_report, Some(b"coverage-1".to_vec()));
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
        let status = reopened.source_status(&identity)?.ok_or("status absent")?;
        assert_eq!(status.receipt, receipt);
        assert_eq!(status.latest_coverage_report, Some(b"coverage-3".to_vec()));
        {
            let writer_guard = reopened.writer()?;
            let writer = writer_guard.get()?;
            let changed: u64 = writer.query_row(
                "SELECT COUNT(*) FROM relation_revisions WHERE last_changed_revision = 2",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(changed, 2);
            writer.execute(
                "UPDATE coverage SET report_sha256 = ? WHERE revision = 3",
                params![vec![0_u8; 32]],
            )?;
        }
        assert!(reopened.source_status(&identity).is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_limit_edges() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut source = identity();
        source.node_id = "n".repeat(crate::MAX_NODE_ID_BYTES);
        let mut max_batch = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: MAX_EVIDENCE_BATCH_RECORDS as u64,
            intake_utc_ns: 1_000_000_000,
            framed_records: vec![1; MAX_EVIDENCE_BATCH_RECORDS].into(),
            frame_ends: (1..=MAX_EVIDENCE_BATCH_RECORDS).collect(),
        };
        store.validate_batch(&source, &max_batch)?;
        max_batch.last_cursor += 1;
        max_batch.framed_records = vec![1; MAX_EVIDENCE_BATCH_RECORDS + 1].into();
        max_batch.frame_ends.push(MAX_EVIDENCE_BATCH_RECORDS + 1);
        assert!(store.validate_batch(&source, &max_batch).is_err());
        source.node_id.push('n');
        assert!(store
            .validate_batch(&source, &batch(1, &[b"first"]))
            .is_err());
        source.node_id.pop();

        assert_eq!(
            store.accept_validated_batch(
                source.clone(),
                batch(MAX_PENDING_EVIDENCE_RECORDS, &[b"gap"])
            )?,
            EvidenceStoreOutcomeV1::Pending
        );
        let revision = store.meta()?.commit_revision;
        assert!(store
            .accept_validated_batch(
                source.clone(),
                batch(MAX_PENDING_EVIDENCE_RECORDS + 1, &[b"too-far"])
            )
            .is_err());
        assert_eq!(store.meta()?.commit_revision, revision);

        store.accept_validated_coverage(coverage(
            &source,
            1,
            &vec![1; MAX_EVIDENCE_GRPC_MESSAGE_BYTES],
        ))?;
        let revision = store.meta()?.commit_revision;
        assert!(store
            .accept_validated_coverage(coverage(
                &source,
                2,
                &vec![1; MAX_EVIDENCE_GRPC_MESSAGE_BYTES + 1],
            ))
            .is_err());
        assert_eq!(store.meta()?.commit_revision, revision);
        Ok(())
    }

    #[test]
    fn analysis_store_crash_replay() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
            .arg("analysis::tests::analysis_store_crash_replay")
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
    fn analysis_duckdb_cancel_query() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let worker = Connection::open_in_memory_with_flags(
            Config::default()
                .enable_autoload_extension(false)?
                .enable_external_access(false)?,
        )?;
        let interrupt = worker.interrupt_handle();
        let (started, running) = std::sync::mpsc::channel();
        let query = std::thread::spawn(move || {
            let _ = started.send(());
            worker.query_row(
                "SELECT COUNT(*) FROM range(1000000000000) t(i) WHERE hash(i) % 2 = 0",
                [],
                |row| row.get::<_, u64>(0),
            )
        });
        running.recv()?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        interrupt.interrupt();
        assert!(query.join().map_err(|_| "query thread panicked")?.is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux bwrap and prlimit for the offline worker proof"]
    fn analysis_sql_worker_isolation() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
