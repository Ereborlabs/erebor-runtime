use std::mem::size_of;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use duckdb::types::Value;
use serde::{Deserialize, Serialize};
use snafu::IntoError as _;

use super::budget::QueryLease;
use super::input::SCHEMAS;
use super::{
    QueryLimits, QueryOperation, QueryPlan, QueryResult, QueryTemplate, QUERY_SCHEMA_VERSION,
};
use crate::{
    AnalysisGapV1, AnalysisReadControl, AnalysisSourceReceiptV1, AnalysisSourceSnapshotV1,
    AnalysisStore, AnalysisStoreMetaV1, Result, StorePositionV1,
};

pub const QUERY_CHECKPOINT_BYTES: usize = 1024;

pub(super) struct QueryReadScope {
    store: Arc<AnalysisStore>,
    tenant: [u8; 16],
    requests: Vec<[u8; 16]>,
    timeout: Duration,
    _lease: QueryLease,
}

impl std::fmt::Debug for QueryReadScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueryReadScope")
            .field("requests", &self.requests.len())
            .finish()
    }
}

impl QueryReadScope {
    pub(super) fn allocation_for(requests: &Vec<[u8; 16]>) -> usize {
        size_of::<Self>() + 2 * size_of::<usize>() + requests.capacity() * size_of::<[u8; 16]>()
    }

    pub(super) fn new(
        store: Arc<AnalysisStore>,
        tenant: [u8; 16],
        requests: Vec<[u8; 16]>,
        timeout: Duration,
        lease: QueryLease,
    ) -> Result<Self> {
        let bytes = Self::allocation_for(&requests);
        Ok(Self {
            store,
            tenant,
            requests,
            timeout,
            _lease: lease.output(bytes)?,
        })
    }

    pub(super) fn allocation_bytes(&self) -> usize {
        Self::allocation_for(&self.requests)
    }

    pub(super) async fn check(self: &Arc<Self>, stream: Option<Arc<QueryLease>>) -> Result<()> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query read runtime",
            }
            .build()
        })?;
        let control = Arc::new(AnalysisReadControl::with_timeout(self.timeout)?);
        let permit = self.store.reserve_reader()?;
        let scope = self.clone();
        let stage = control.clone();
        let mut task = super::QueryTask {
            control,
            running: true,
        };
        let result = runtime
            .spawn_blocking(move || {
                let _stream = stream;
                scope
                    .store
                    .check_trace_reads(scope.tenant, &scope.requests, &stage, permit)
            })
            .await;
        task.running = false;
        result.map_err(|source| crate::QueryExecutionSnafu.into_error(source))?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryCoverageState {
    Unknown,
    Reported,
    Gapped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryCoverage {
    pub receipt: AnalysisSourceReceiptV1,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
    pub pending: Vec<AnalysisGapV1>,
    pub state: QueryCoverageState,
}

impl From<AnalysisSourceSnapshotV1> for QueryCoverage {
    fn from(source: AnalysisSourceSnapshotV1) -> Self {
        let state = if !source.expired.is_empty()
            || !source.recovery.is_empty()
            || !source.pending.is_empty()
        {
            QueryCoverageState::Gapped
        } else if source.coverage_report.is_some() {
            QueryCoverageState::Reported
        } else {
            QueryCoverageState::Unknown
        };
        Self {
            receipt: source.receipt,
            expired: source.expired,
            recovery: source.recovery,
            pending: source.pending,
            state,
        }
    }
}

impl QueryCoverage {
    /// Heap bytes only. The containing vector accounts for this value.
    pub(crate) fn allocation_bytes(&self) -> Result<usize> {
        [&self.expired, &self.recovery, &self.pending]
            .into_iter()
            .try_fold(self.receipt.identity.node_id.capacity(), |bytes, gaps| {
                gaps.capacity()
                    .checked_mul(size_of::<AnalysisGapV1>())
                    .and_then(|owned| bytes.checked_add(owned))
                    .ok_or_else(|| {
                        crate::QueryLimitSnafu {
                            resource: "query output bytes",
                            limit: usize::MAX,
                        }
                        .build()
                    })
            })
    }
}

#[derive(Debug)]
pub struct QueryCoverageRows {
    rows: Vec<QueryCoverage>,
    _lease: QueryLease,
}

impl QueryCoverageRows {
    pub(super) fn new(rows: Vec<QueryCoverage>, lease: QueryLease) -> Result<Self> {
        let bytes = Self::allocation_bytes_for(&rows)?;
        Ok(Self {
            rows,
            _lease: lease.output(bytes)?,
        })
    }

    pub(super) fn allocation_bytes_for(rows: &Vec<QueryCoverage>) -> Result<usize> {
        let overflow = || {
            crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: usize::MAX,
            }
            .build()
        };
        // The Arc allocation includes its strong and weak reference counts.
        let bytes = rows
            .capacity()
            .checked_mul(size_of::<QueryCoverage>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .ok_or_else(overflow)?;
        rows.iter().try_fold(bytes, |bytes, row| {
            bytes
                .checked_add(row.allocation_bytes()?)
                .ok_or_else(overflow)
        })
    }

    pub(super) fn allocation_bytes(&self) -> Result<usize> {
        Self::allocation_bytes_for(&self.rows)
    }
}

impl Deref for QueryCoverageRows {
    type Target = [QueryCoverage];

    fn deref(&self) -> &Self::Target {
        &self.rows
    }
}

/// An internal resume position. It grants no authority and retains no history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCheckpoint {
    schema_version: u32,
    store_uuid: [u8; 16],
    recovery_epoch: u64,
    operation: QueryOperation,
    position: Option<StorePositionV1>,
    read_revision: u64,
}

impl QueryCheckpoint {
    pub(super) fn new(
        plan: &QueryPlan,
        meta: &AnalysisStoreMetaV1,
        position: StorePositionV1,
    ) -> Result<Self> {
        let checkpoint = Self {
            schema_version: QUERY_SCHEMA_VERSION,
            store_uuid: *meta.store_uuid.as_bytes(),
            recovery_epoch: meta.recovery_epoch,
            operation: plan.operation(),
            position: (plan.operation() == QueryOperation::Append).then_some(position),
            read_revision: meta.commit_revision,
        };
        checkpoint.validate(plan, meta, None)?;
        Ok(checkpoint)
    }

    pub(super) fn from_result(plan: &QueryPlan, result: &QueryResult) -> Result<Self> {
        Self::new(plan, &result.meta, result.scanned_through)
    }

    pub(super) fn validate(
        &self,
        plan: &QueryPlan,
        meta: &AnalysisStoreMetaV1,
        floor: Option<StorePositionV1>,
    ) -> Result<Option<StorePositionV1>> {
        self.check()?;
        if self.store_uuid != *meta.store_uuid.as_bytes()
            || self.recovery_epoch != meta.recovery_epoch
            || self.operation != plan.operation()
            || self.read_revision > meta.commit_revision
        {
            return crate::QueryInvalidSnafu {
                field: "checkpoint binding",
            }
            .fail();
        }
        if let (Some(position), Some(floor)) = (self.position, floor) {
            if position < floor {
                return crate::QueryCursorExpiredSnafu { position, floor }.fail();
            }
        }
        Ok(self.position)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
        if encoded.len() > QUERY_CHECKPOINT_BYTES {
            return crate::QueryInvalidSnafu {
                field: "checkpoint size",
            }
            .fail();
        }
        Ok(encoded)
    }

    pub fn position(&self) -> Option<StorePositionV1> {
        self.position
    }

    pub fn read_revision(&self) -> u64 {
        self.read_revision
    }

    fn check(&self) -> Result<()> {
        if self.schema_version != QUERY_SCHEMA_VERSION
            || self.store_uuid == [0; 16]
            || (self.operation == QueryOperation::Append) != self.position.is_some()
            || self
                .position
                .is_some_and(|position| position.commit_revision > self.read_revision)
        {
            return crate::QueryInvalidSnafu {
                field: "checkpoint",
            }
            .fail();
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for QueryCheckpoint {
    type Error = crate::Error;

    fn try_from(encoded: &[u8]) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > QUERY_CHECKPOINT_BYTES {
            return crate::QueryInvalidSnafu {
                field: "checkpoint size",
            }
            .fail();
        }
        let checkpoint: Self = serde_json::from_slice(encoded).map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "checkpoint encoding",
            }
            .build()
        })?;
        checkpoint.check()?;
        Ok(checkpoint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryColumn {
    pub name: String,
    pub data_type: String,
    pub units: &'static str,
    pub null_meaning: &'static str,
    pub join_keys: &'static str,
    pub owner: &'static str,
    pub readiness: &'static str,
}

#[derive(Debug)]
pub struct QueryMetadata {
    pub columns: Vec<QueryColumn>,
    pub evaluated_utc_ns: u64,
    pub dependency_revision: u64,
    pub row_limit: usize,
    pub byte_limit: usize,
    pub moving_resolution_ns: Option<u64>,
    pub resume_semantics: &'static str,
    pub coverage: Arc<QueryCoverageRows>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryErrorCode {
    InvalidQuery,
    InvalidCheckpoint,
    Unsupported,
    InputTooLarge,
    ResultTooLarge,
    CursorExpired,
    Cancelled,
    DeadlineExceeded,
    Busy,
    Denied,
    StorageUnavailable,
    OutputTimeout,
    EvaluationFailed,
}

impl QueryErrorCode {
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidQuery => "The query is invalid.",
            Self::InvalidCheckpoint => "The checkpoint does not match this query or store.",
            Self::Unsupported => "A required query relation is unavailable.",
            Self::InputTooLarge => "The complete query input exceeds its bound.",
            Self::ResultTooLarge => "The query output exceeds its bound.",
            Self::CursorExpired => "The checkpoint cannot replay retained history.",
            Self::Cancelled => "The query was cancelled.",
            Self::DeadlineExceeded => "The query reached its deadline.",
            Self::Busy => "Query admission is full.",
            Self::Denied => "Query disclosure is not authorized.",
            Self::StorageUnavailable => "Query storage is unavailable.",
            Self::OutputTimeout => "The query output wait reached its deadline.",
            Self::EvaluationFailed => "The query evaluation failed.",
        }
    }
}

impl From<&crate::Error> for QueryErrorCode {
    fn from(error: &crate::Error) -> Self {
        match error {
            crate::Error::QueryInvalid { field, .. } if field.starts_with("checkpoint") => {
                Self::InvalidCheckpoint
            }
            crate::Error::QueryInvalid { .. } => Self::InvalidQuery,
            crate::Error::QueryDenied { .. } => Self::Denied,
            crate::Error::QueryUnsupported { .. } => Self::Unsupported,
            crate::Error::AnalysisInputTooLarge { .. } => Self::InputTooLarge,
            crate::Error::QueryLimit { resource, .. } if resource.contains("input") => {
                Self::InputTooLarge
            }
            crate::Error::QueryLimit { .. } => Self::ResultTooLarge,
            crate::Error::QueryCursorExpired { .. } | crate::Error::RetainedRangeExpired { .. } => {
                Self::CursorExpired
            }
            crate::Error::AnalysisReadCancelled { .. } => Self::Cancelled,
            crate::Error::AnalysisReadDeadline { .. } => Self::DeadlineExceeded,
            crate::Error::AnalysisBusy { .. } => Self::Busy,
            crate::Error::RetentionUnavailable { .. }
            | crate::Error::StorageCapacity { .. }
            | crate::Error::ProtectedInputCapacity { .. } => Self::StorageUnavailable,
            _ => Self::EvaluationFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryTerminalReason {
    Completed,
    Cancelled,
    OutputTimeout,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryHealth {
    pub write_ready: bool,
    pub retention_healthy: bool,
    pub intake_capacity: bool,
    pub maintenance_capacity: bool,
    pub usage: Option<crate::StorageUsageV1>,
}

impl From<crate::StorageHealthV1> for QueryHealth {
    fn from(health: crate::StorageHealthV1) -> Self {
        Self {
            write_ready: health.write_ready,
            retention_healthy: health.retention_healthy,
            intake_capacity: health.intake_capacity,
            maintenance_capacity: health.maintenance_capacity,
            usage: Some(health.usage),
        }
    }
}

#[derive(Debug)]
pub enum QueryPayload {
    Metadata(QueryMetadata),
    Append {
        result: QueryResult,
    },
    Replace {
        result: QueryResult,
    },
    Checkpoint {
        checkpoint: QueryCheckpoint,
        exhausted: bool,
        coverage: Option<Arc<QueryCoverageRows>>,
    },
    Health {
        dependency_revision: u64,
        storage_health: QueryHealth,
        coverage: Option<Arc<QueryCoverageRows>>,
    },
    Error {
        code: QueryErrorCode,
        reason: &'static str,
        position: Option<StorePositionV1>,
        floor: Option<StorePositionV1>,
        last_checkpoint: Option<QueryCheckpoint>,
        coverage: Option<Arc<QueryCoverageRows>>,
    },
    Terminal {
        reason: QueryTerminalReason,
        last_checkpoint: Option<QueryCheckpoint>,
        coverage: Option<Arc<QueryCoverageRows>>,
    },
}

#[derive(Debug)]
pub struct QueryFrame {
    pub schema_version: u32,
    pub operation: QueryOperation,
    pub store_uuid: [u8; 16],
    pub recovery_epoch: u64,
    pub read_revision: u64,
    pub clock_changed: bool,
    pub payload: QueryPayload,
    pub(super) reads: Option<Arc<QueryReadScope>>,
    _lease: Option<QueryLease>,
}

impl QueryFrame {
    /// Check current trace read state before each disclosure from this frame.
    pub async fn check_read(&self) -> Result<()> {
        self.check_stream(None).await
    }

    pub(super) async fn check_stream(&self, stream: Option<Arc<QueryLease>>) -> Result<()> {
        if let Some(scope) = &self.reads {
            scope.check(stream).await?;
        }
        Ok(())
    }

    pub fn coverage(&self) -> &[QueryCoverage] {
        self.coverage_owner().map_or(&[], Deref::deref)
    }

    fn coverage_owner(&self) -> Option<&QueryCoverageRows> {
        match &self.payload {
            QueryPayload::Append { result, .. } | QueryPayload::Replace { result, .. } => {
                Some(&result.sources)
            }
            QueryPayload::Metadata(metadata) => Some(&metadata.coverage),
            QueryPayload::Checkpoint { coverage, .. }
            | QueryPayload::Health { coverage, .. }
            | QueryPayload::Error { coverage, .. }
            | QueryPayload::Terminal { coverage, .. } => coverage.as_deref(),
        }
    }

    pub(super) fn owned_bytes(&self) -> usize {
        match &self.payload {
            QueryPayload::Append { .. } | QueryPayload::Replace { .. } => {
                size_of::<Self>() - size_of::<QueryResult>()
            }
            QueryPayload::Metadata(metadata) => metadata.columns.iter().fold(
                size_of::<Self>().saturating_add(
                    metadata
                        .columns
                        .capacity()
                        .saturating_mul(size_of::<QueryColumn>()),
                ),
                |bytes, column| {
                    bytes
                        .saturating_add(column.name.capacity())
                        .saturating_add(column.data_type.capacity())
                },
            ),
            _ => size_of::<Self>(),
        }
    }

    pub(super) fn total_bytes(&self) -> Result<usize> {
        let shared = match &self.payload {
            QueryPayload::Append { result, .. } | QueryPayload::Replace { result, .. } => {
                return Ok(result.output_bytes);
            }
            _ => self
                .coverage_owner()
                .map(QueryCoverageRows::allocation_bytes)
                .transpose()?
                .unwrap_or(0),
        };
        Ok(self.owned_bytes().saturating_add(shared).saturating_add(
            self.reads
                .as_ref()
                .map_or(0, |scope| scope.allocation_bytes()),
        ))
    }

    pub(super) fn attach_lease(mut self, lease: QueryLease) -> Result<Self> {
        if self._lease.is_some() {
            return crate::QueryInvalidSnafu {
                field: "query frame lease",
            }
            .fail();
        }
        self._lease = Some(lease.output(self.owned_bytes())?);
        Ok(self)
    }

    pub(super) fn metadata_bytes(result: &QueryResult, limits: &QueryLimits) -> Result<usize> {
        let bytes = result.columns.iter().fold(
            size_of::<Self>().saturating_add(
                result
                    .columns
                    .len()
                    .saturating_mul(size_of::<QueryColumn>()),
            ),
            |bytes, column| {
                bytes
                    .saturating_add(column.name.len())
                    .saturating_add(column.data_type.len())
            },
        );
        if bytes
            .saturating_add(result.sources.allocation_bytes()?)
            .saturating_add(
                result
                    .reads
                    .as_ref()
                    .map_or(0, |scope| scope.allocation_bytes()),
            )
            > limits.output_bytes
        {
            return crate::QueryLimitSnafu {
                resource: "query metadata output bytes",
                limit: limits.output_bytes,
            }
            .fail();
        }
        Ok(bytes)
    }

    pub(super) fn metadata(
        plan: &QueryPlan,
        result: &QueryResult,
        limits: &QueryLimits,
        dependency_revision: u64,
    ) -> Result<Self> {
        let bytes = Self::metadata_bytes(result, limits)?;
        result.check_rows()?;
        let mut columns = Vec::with_capacity(result.columns.len());
        for column in &result.columns {
            columns.push(QueryColumn::new(plan, &column.name, &column.data_type)?);
        }
        let mut frame = Self::new(
            plan,
            &result.meta,
            QueryPayload::Metadata(QueryMetadata {
                columns,
                evaluated_utc_ns: result.evaluated_utc_ns,
                dependency_revision,
                row_limit: limits.output_rows,
                byte_limit: limits.output_bytes,
                moving_resolution_ns: plan.moving_seconds().map(|_| 1_000_000_000),
                resume_semantics: match plan.operation() {
                    QueryOperation::Append => {
                        "Replay later retained positions; delivery is at least once."
                    }
                    QueryOperation::Replace => {
                        "Evaluate current state; intermediate states can be omitted."
                    }
                },
                coverage: result.sources.clone(),
            }),
        );
        frame.reads = result.reads.clone();
        if frame.owned_bytes() > bytes || frame.total_bytes()? > limits.output_bytes {
            return crate::QueryLimitSnafu {
                resource: "query metadata output bytes",
                limit: limits.output_bytes,
            }
            .fail();
        }
        Ok(frame)
    }

    pub(super) fn data(plan: &QueryPlan, result: QueryResult) -> Result<Self> {
        result.check_rows()?;
        let meta = result.meta.clone();
        let reads = result.reads.clone();
        let payload = match plan.operation() {
            QueryOperation::Append => {
                result.check_positions()?;
                QueryPayload::Append { result }
            }
            QueryOperation::Replace => {
                if result.limited
                    && !matches!(&plan.template, QueryTemplate::Client(sql) if !sql.follow())
                {
                    return crate::QueryLimitSnafu {
                        resource: "complete replacement output",
                        limit: result.output_bytes,
                    }
                    .fail();
                }
                QueryPayload::Replace { result }
            }
        };
        let mut frame = Self::new(plan, &meta, payload);
        frame.reads = reads;
        Ok(frame)
    }

    pub(super) fn checkpoint(
        checkpoint: QueryCheckpoint,
        coverage: Option<Arc<QueryCoverageRows>>,
        exhausted: bool,
    ) -> Result<Self> {
        checkpoint.check()?;
        Ok(Self {
            schema_version: QUERY_SCHEMA_VERSION,
            operation: checkpoint.operation,
            store_uuid: checkpoint.store_uuid,
            recovery_epoch: checkpoint.recovery_epoch,
            read_revision: checkpoint.read_revision,
            clock_changed: false,
            payload: QueryPayload::Checkpoint {
                checkpoint,
                coverage,
                exhausted,
            },
            _lease: None,
            reads: None,
        })
    }

    pub(super) fn health(
        plan: &QueryPlan,
        meta: &AnalysisStoreMetaV1,
        dependency_revision: u64,
        coverage: Option<Arc<QueryCoverageRows>>,
        storage_health: crate::StorageHealthV1,
        clock_changed: bool,
    ) -> Result<Self> {
        let mut storage_health = QueryHealth::from(storage_health);
        if plan.grant().is_some() {
            storage_health.usage = None;
        }
        let mut frame = Self::new(
            plan,
            meta,
            QueryPayload::Health {
                dependency_revision,
                storage_health,
                coverage,
            },
        );
        frame.clock_changed = clock_changed;
        Ok(frame)
    }

    pub(super) fn error(
        plan: &QueryPlan,
        meta: &AnalysisStoreMetaV1,
        error: &crate::Error,
        last_checkpoint: Option<QueryCheckpoint>,
        coverage: Option<Arc<QueryCoverageRows>>,
    ) -> Result<Self> {
        if let Some(checkpoint) = &last_checkpoint {
            checkpoint.check()?;
        }
        let code = QueryErrorCode::from(error);
        let (position, floor) = match error {
            crate::Error::QueryCursorExpired {
                position, floor, ..
            } => (Some(*position), Some(*floor)),
            _ => (None, None),
        };
        Ok(Self::new(
            plan,
            meta,
            QueryPayload::Error {
                code,
                reason: code.reason(),
                position,
                floor,
                last_checkpoint,
                coverage,
            },
        ))
    }

    pub(super) fn terminal(
        plan: &QueryPlan,
        meta: &AnalysisStoreMetaV1,
        reason: QueryTerminalReason,
        last_checkpoint: Option<QueryCheckpoint>,
        coverage: Option<Arc<QueryCoverageRows>>,
    ) -> Result<Self> {
        if let Some(checkpoint) = &last_checkpoint {
            checkpoint.check()?;
        }
        Ok(Self::new(
            plan,
            meta,
            QueryPayload::Terminal {
                reason,
                last_checkpoint,
                coverage,
            },
        ))
    }

    fn new(plan: &QueryPlan, meta: &AnalysisStoreMetaV1, payload: QueryPayload) -> Self {
        Self {
            schema_version: QUERY_SCHEMA_VERSION,
            operation: plan.operation(),
            store_uuid: *meta.store_uuid.as_bytes(),
            recovery_epoch: meta.recovery_epoch,
            read_revision: meta.commit_revision,
            clock_changed: false,
            payload,
            _lease: None,
            reads: None,
        }
    }
}

impl QueryColumn {
    fn new(plan: &QueryPlan, name: &str, data_type: &str) -> Result<Self> {
        if let QueryTemplate::Client(sql) = &plan.template {
            let (units, null_meaning, join_keys, owner, readiness) = match sql.source_column(name) {
                Some((schema, field)) => (
                    field.2,
                    field.3,
                    schema.join_keys,
                    schema.owner,
                    schema.readiness,
                ),
                _ => (
                    "SQL-derived value; source field units are not inferred",
                    "SQL expression can return NULL",
                    "",
                    "araphor-data.QueryOwner",
                    "available",
                ),
            };
            return Ok(Self {
                name: name.into(),
                data_type: data_type.into(),
                units,
                null_meaning,
                join_keys,
                owner,
                readiness,
            });
        }
        let relation = match plan.template {
            QueryTemplate::Coverage => "coverage",
            QueryTemplate::RevisionDifference | QueryTemplate::ContextVersions => {
                "context_versions"
            }
            QueryTemplate::Catalog => "catalog",
            _ => "events",
        };
        let schema = SCHEMAS
            .iter()
            .find(|schema| schema.name == relation)
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "result relation",
                }
                .build()
            })?;
        let (units, null_meaning) = match name {
            "event_count" => ("retained evidence row count, not physical-action count", ""),
            "window_start" => ("UTC microseconds; inclusive intake bucket start", ""),
            "old_revision" | "new_revision" => ("owner revision, not store revision", ""),
            "changed" => ("exact context body difference", ""),
            _ => schema
                .columns
                .iter()
                .find(|field| field.0 == name)
                .map(|field| (field.2, field.3))
                .ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "result column",
                    }
                    .build()
                })?,
        };
        Ok(Self {
            name: name.into(),
            data_type: data_type.into(),
            units,
            null_meaning,
            join_keys: schema.join_keys,
            owner: schema.owner,
            readiness: schema.readiness,
        })
    }
}

impl QueryResult {
    fn check_rows(&self) -> Result<()> {
        for row in &self.rows {
            if row.len() != self.columns.len() {
                return crate::QueryInvalidSnafu {
                    field: "result row",
                }
                .fail();
            }
            for value in row {
                if !matches!(
                    value,
                    Value::Null
                        | Value::Boolean(_)
                        | Value::TinyInt(_)
                        | Value::SmallInt(_)
                        | Value::Int(_)
                        | Value::BigInt(_)
                        | Value::HugeInt(_)
                        | Value::UHugeInt(_)
                        | Value::UTinyInt(_)
                        | Value::USmallInt(_)
                        | Value::UInt(_)
                        | Value::UBigInt(_)
                        | Value::Float(_)
                        | Value::Double(_)
                        | Value::Decimal(_)
                        | Value::Timestamp(..)
                        | Value::Text(_)
                        | Value::Blob(_)
                        | Value::Date32(_)
                        | Value::Time64(..)
                        | Value::Interval { .. }
                ) {
                    return crate::QueryUnsupportedSnafu {
                        relation: "query value type",
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }

    fn check_positions(&self) -> Result<()> {
        if !self.positions.is_empty() {
            if self.positions.len() != self.rows.len() {
                return crate::QueryInvalidSnafu {
                    field: "append position",
                }
                .fail();
            }
            let mut previous = None;
            for position in &self.positions {
                if previous.is_some_and(|previous| previous >= *position)
                    || *position > self.scanned_through
                    || position.commit_revision > self.meta.commit_revision
                {
                    return crate::QueryInvalidSnafu {
                        field: "append order",
                    }
                    .fail();
                }
                previous = Some(*position);
            }
            return Ok(());
        }
        if self.rows.is_empty() {
            return Ok(());
        }
        let revision = self
            .columns
            .iter()
            .position(|column| column.name == "commit_revision");
        let ordinal = self
            .columns
            .iter()
            .position(|column| column.name == "ordinal");
        let (Some(revision), Some(ordinal)) = (revision, ordinal) else {
            return crate::QueryInvalidSnafu {
                field: "append schema",
            }
            .fail();
        };
        let mut previous = None;
        for row in &self.rows {
            let (Some(Value::UBigInt(commit_revision)), Some(Value::UInt(ordinal))) =
                (row.get(revision), row.get(ordinal))
            else {
                return crate::QueryInvalidSnafu {
                    field: "append position",
                }
                .fail();
            };
            let position = StorePositionV1 {
                commit_revision: *commit_revision,
                ordinal: *ordinal,
            };
            if previous.is_some_and(|previous| previous >= position)
                || position > self.scanned_through
                || position.commit_revision > self.meta.commit_revision
            {
                return crate::QueryInvalidSnafu {
                    field: "append order",
                }
                .fail();
            }
            previous = Some(position);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;
    use std::sync::Arc;

    use duckdb::types::TimeUnit;

    use super::*;
    use crate::query::budget::QueryBudget;
    use crate::{AnalysisSelectionV1, Column, EvidenceIntakeIdentityV1};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    struct FrameFixture {
        plan: QueryPlan,
        meta: AnalysisStoreMetaV1,
        budget: Arc<QueryBudget>,
    }

    impl FrameFixture {
        fn new() -> Result<Self> {
            let source = Self::source(None);
            Ok(Self {
                plan: QueryPlan::new(
                    AnalysisSelectionV1::new([1; 16], vec![source.receipt.identity]),
                    QueryTemplate::Events { operation: None },
                )?,
                meta: AnalysisStoreMetaV1 {
                    store_uuid: uuid::Uuid::from_bytes([4; 16]),
                    schema_version: 1,
                    recovery_epoch: 1,
                    commit_revision: 9,
                },
                budget: QueryBudget::new(QueryLimits {
                    output_capacity: QueryLimits::default().output_bytes,
                    ..Default::default()
                }),
            })
        }

        fn source(report: Option<Vec<u8>>) -> AnalysisSourceSnapshotV1 {
            AnalysisSourceSnapshotV1 {
                receipt: AnalysisSourceReceiptV1 {
                    identity: EvidenceIntakeIdentityV1 {
                        tenant_id: [1; 16],
                        node_id: "frame-node".into(),
                        node_boot_id: [2; 16],
                        label_epoch: 1,
                        source_id: [3; 16],
                        source_epoch: 1,
                    },
                    cpu_id: 2,
                    contiguous_cursor: 20,
                    coverage_revision: u64::from(report.is_some()),
                    retained_floor: 0,
                },
                expired: Vec::new(),
                recovery: Vec::new(),
                pending: Vec::new(),
                coverage_report: report,
            }
        }

        fn result(&self) -> Result<QueryResult> {
            let mut lease = self.budget.evaluate([1; 16])?;
            let sources = vec![Self::source(None).into()];
            let bytes = QueryCoverageRows::allocation_bytes_for(&sources)?;
            let sources = Arc::new(QueryCoverageRows::new(sources, lease.split(bytes)?)?);
            let mut result = QueryResult {
                columns: vec![
                    Column {
                        name: "operation".into(),
                        data_type: "UInteger".into(),
                    },
                    Column {
                        name: "commit_revision".into(),
                        data_type: "UBigint".into(),
                    },
                    Column {
                        name: "ordinal".into(),
                        data_type: "UInteger".into(),
                    },
                ],
                rows: vec![vec![Value::UInt(7), Value::UBigInt(3), Value::UInt(4)]],
                meta: self.meta.clone(),
                sources,
                missing_contexts: Vec::new(),
                graph_traversal: None,
                scanned_bytes: Some(64),
                input_rows: 1,
                input_bytes: Some(128),
                output_bytes: 0,
                evaluated_utc_ns: 10_000_000_000,
                scanned_through: StorePositionV1 {
                    commit_revision: self.meta.commit_revision,
                    ordinal: u32::MAX,
                },
                exhausted: true,
                limited: false,
                next_expiry_ns: None,
                positions: Vec::new(),
                reads: None,
                _lease: lease,
            };
            result.output_bytes = result.allocation_bytes()?;
            let owned =
                result.output_bytes - bytes - (size_of::<QueryFrame>() - size_of::<QueryResult>());
            result._lease = result._lease.output(owned)?;
            Ok(result)
        }
    }

    #[test]
    fn query_follow_checkpoint_bounds() -> TestResult {
        let fixture = FrameFixture::new()?;
        let position = StorePositionV1 {
            commit_revision: 3,
            ordinal: 4,
        };
        let checkpoint = QueryCheckpoint::new(&fixture.plan, &fixture.meta, position)?;
        let encoded = checkpoint.encode()?;
        assert!(encoded.len() < QUERY_CHECKPOINT_BYTES);
        assert_eq!(QueryCheckpoint::try_from(encoded.as_slice())?, checkpoint);
        assert_eq!(checkpoint.position(), Some(position));
        assert_eq!(checkpoint.read_revision(), 9);
        assert_eq!(
            checkpoint.validate(&fixture.plan, &fixture.meta, Some(position))?,
            Some(position)
        );
        let floor = StorePositionV1 {
            ordinal: 5,
            ..position
        };
        assert!(matches!(
            checkpoint.validate(&fixture.plan, &fixture.meta, Some(floor)),
            Err(crate::Error::QueryCursorExpired { position: rejected, floor: captured, .. })
                if rejected == position && captured == floor
        ));

        for change in 0..3 {
            let mut selection = fixture.plan.base_selection().clone();
            let mut template = fixture.plan.template.clone();
            match change {
                0 => template = QueryTemplate::Events { operation: Some(7) },
                1 => {
                    selection
                        .sources
                        .exact_mut()
                        .ok_or("exact sources absent")?[0]
                        .source_epoch += 1
                }
                _ => selection.received_from = Bound::Excluded(10),
            }
            let plan = QueryPlan::new(selection, template)?;
            assert_eq!(
                checkpoint.validate(&plan, &fixture.meta, None)?,
                Some(position),
                "{change}"
            );
        }
        for change in 0..3 {
            let mut meta = fixture.meta.clone();
            match change {
                0 => meta.store_uuid = uuid::Uuid::from_bytes([5; 16]),
                1 => meta.recovery_epoch += 1,
                _ => meta.commit_revision -= 1,
            }
            assert!(
                checkpoint.validate(&fixture.plan, &meta, None).is_err(),
                "{change}"
            );
        }
        let mut current = fixture.meta.clone();
        current.commit_revision += 1;
        assert_eq!(
            checkpoint.validate(&fixture.plan, &current, None)?,
            Some(position)
        );
        let mut replace = fixture.plan.clone();
        replace.template = QueryTemplate::OperationCounts;
        assert!(checkpoint.validate(&replace, &current, None).is_err());
        let replacement = QueryCheckpoint::new(&replace, &fixture.meta, position)?;
        assert_eq!(replacement.validate(&replace, &current, Some(floor))?, None);

        let mut padded = encoded.clone();
        padded.resize(QUERY_CHECKPOINT_BYTES, b' ');
        assert_eq!(QueryCheckpoint::try_from(padded.as_slice())?, checkpoint);
        padded.push(b' ');
        assert!(QueryCheckpoint::try_from(padded.as_slice()).is_err());
        assert!(QueryCheckpoint::try_from(&[][..]).is_err());
        assert!(QueryCheckpoint::try_from(&b"not a checkpoint"[..]).is_err());
        let mut value = serde_json::to_value(&checkpoint)?;
        value["sql"] = serde_json::Value::String("private text".into());
        assert!(QueryCheckpoint::try_from(serde_json::to_vec(&value)?.as_slice()).is_err());
        for change in 0..3 {
            let mut invalid = checkpoint.clone();
            match change {
                0 => invalid.schema_version += 1,
                1 => invalid.position = None,
                _ => invalid.read_revision = position.commit_revision - 1,
            }
            assert!(invalid.encode().is_err());
            assert!(QueryCheckpoint::try_from(serde_json::to_vec(&invalid)?.as_slice()).is_err());
            assert!(QueryFrame::checkpoint(invalid.clone(), None, false).is_err());
            assert!(QueryFrame::error(
                &fixture.plan,
                &fixture.meta,
                &crate::QueryInvalidSnafu {
                    field: "checkpoint"
                }
                .build(),
                Some(invalid.clone()),
                None,
            )
            .is_err());
            assert!(QueryFrame::terminal(
                &fixture.plan,
                &fixture.meta,
                QueryTerminalReason::Closed,
                Some(invalid),
                None,
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn query_follow_frame_rows() -> TestResult {
        let fixture = FrameFixture::new()?;
        let first = QueryFrame::data(&fixture.plan, fixture.result()?)?;
        assert_eq!(first.schema_version, QUERY_SCHEMA_VERSION);
        assert_eq!(first.operation, QueryOperation::Append);
        assert_eq!(first.store_uuid, *fixture.meta.store_uuid.as_bytes());
        assert_eq!(first.recovery_epoch, fixture.meta.recovery_epoch);
        assert_eq!(first.read_revision, fixture.meta.commit_revision);
        let QueryPayload::Append { result } = &first.payload else {
            return Err("append absent".into());
        };
        let rows = result.rows.clone();
        let scanned = result.scanned_through;
        drop(first);
        let mut same = fixture.result()?;
        same.meta.commit_revision += 1;
        same.evaluated_utc_ns += 100;
        same.scanned_through.commit_revision += 1;
        let same = QueryFrame::data(&fixture.plan, same)?;
        assert_eq!(same.read_revision, fixture.meta.commit_revision + 1);
        let QueryPayload::Append { result } = &same.payload else {
            return Err("append absent".into());
        };
        assert_eq!(result.rows, rows);
        assert_eq!(result.scanned_through.ordinal, scanned.ordinal);
        assert_eq!(
            result.scanned_through.commit_revision,
            scanned.commit_revision + 1
        );
        drop(same);
        for change in 0..3 {
            let mut result = fixture.result()?;
            match change {
                0 => result.rows[0][0] = Value::UInt(8),
                1 => result.rows[0][2] = Value::UInt(5),
                _ => result.meta.recovery_epoch += 1,
            }
            let rows = result.rows.clone();
            let epoch = result.meta.recovery_epoch;
            let frame = QueryFrame::data(&fixture.plan, result)?;
            assert_eq!(frame.recovery_epoch, epoch);
            let QueryPayload::Append { result } = &frame.payload else {
                return Err("append absent".into());
            };
            assert_eq!(result.rows, rows);
        }
        let mut unordered = fixture.result()?;
        unordered.rows.push(unordered.rows[0].clone());
        assert!(QueryFrame::data(&fixture.plan, unordered).is_err());
        let mut unscanned = fixture.result()?;
        unscanned.scanned_through = StorePositionV1 {
            commit_revision: 2,
            ordinal: u32::MAX,
        };
        assert!(QueryFrame::data(&fixture.plan, unscanned).is_err());

        let mut replace = fixture.plan.clone();
        replace.template = QueryTemplate::OperationCounts;
        for change in 0..2 {
            let mut result = fixture.result()?;
            if change == 0 {
                result.meta.commit_revision += 1;
            } else {
                result.evaluated_utc_ns += 1;
            }
            let revision = result.meta.commit_revision;
            let evaluated = result.evaluated_utc_ns;
            let frame = QueryFrame::data(&replace, result)?;
            assert_eq!(frame.operation, QueryOperation::Replace);
            assert_eq!(frame.read_revision, revision);
            let QueryPayload::Replace { result } = &frame.payload else {
                return Err("replacement absent".into());
            };
            assert_eq!(result.evaluated_utc_ns, evaluated);
            assert_eq!(result.rows, rows);
        }
        let mut partial = fixture.result()?;
        partial.limited = true;
        assert!(QueryFrame::data(&replace, partial).is_err());

        let result = fixture.result()?;
        let rows = result.rows.as_ptr();
        let coverage = result.sources.as_ptr();
        let frame = QueryFrame::data(&fixture.plan, result)?;
        assert_eq!(frame.coverage().as_ptr(), coverage);
        assert!(fixture.budget.evaluate([1; 16]).is_err());
        let QueryPayload::Append { result, .. } = &frame.payload else {
            return Err("append absent".into());
        };
        assert_eq!(result.rows.as_ptr(), rows);
        drop(frame);
        drop(fixture.budget.evaluate([1; 16])?);
        Ok(())
    }

    #[test]
    fn query_follow_frame_validation() -> TestResult {
        let fixture = FrameFixture::new()?;
        for change in 0..3 {
            let mut result = fixture.result()?;
            let expected = match change {
                0 => {
                    result.columns.pop();
                    "result row"
                }
                1 => {
                    result.rows[0].pop();
                    "result row"
                }
                _ => {
                    result.rows[0][0] = Value::List(vec![Value::Null]);
                    "query value type"
                }
            };
            assert!(matches!(
                QueryFrame::metadata(&fixture.plan, &result, &QueryLimits::default(), 7),
                Err(crate::Error::QueryInvalid { field, .. }
                    | crate::Error::QueryUnsupported { relation: field, .. }) if field == expected
            ));
            assert!(matches!(
                QueryFrame::data(&fixture.plan, result),
                Err(crate::Error::QueryInvalid { field, .. }
                    | crate::Error::QueryUnsupported { relation: field, .. }) if field == expected
            ));
        }
        for value in [
            Value::Null,
            Value::Boolean(true),
            Value::TinyInt(i8::MIN),
            Value::SmallInt(i16::MIN),
            Value::Int(i32::MIN),
            Value::BigInt(i64::MIN),
            Value::HugeInt(i128::MIN),
            Value::UHugeInt(u128::MAX),
            Value::UTinyInt(u8::MAX),
            Value::USmallInt(u16::MAX),
            Value::UInt(u32::MAX),
            Value::UBigInt(u64::MAX),
            Value::Float(f32::INFINITY),
            Value::Double(f64::NAN),
            Value::Decimal(duckdb::types::Decimal::new(38, 5, -12345)?),
            Value::Timestamp(TimeUnit::Nanosecond, i64::MIN),
            Value::Text("a\0b".into()),
            Value::Blob(vec![0, 255]),
            Value::Date32(i32::MIN),
            Value::Time64(TimeUnit::Microsecond, i64::MAX),
            Value::Interval {
                months: i32::MIN,
                days: i32::MAX,
                nanos: i64::MIN,
            },
        ] {
            let mut result = fixture.result()?;
            result.rows[0][0] = value;
            QueryFrame::metadata(&fixture.plan, &result, &QueryLimits::default(), 7)?;
            QueryFrame::data(&fixture.plan, result)?;
        }
        Ok(())
    }

    #[test]
    fn query_frame_borrowed_rows() -> TestResult {
        let fixture = FrameFixture::new()?;
        let mut result = fixture.result()?;
        result.columns = vec![
            Column {
                name: "a".into(),
                data_type: "Varchar".into(),
            },
            Column {
                name: "b".into(),
                data_type: "Blob".into(),
            },
        ];
        result.rows = vec![vec![Value::Text("a\0b".into()), Value::Blob(vec![0, 255])]];
        let rows = result.rows.as_ptr();
        let [Value::Text(text), Value::Blob(blob)] = result.rows[0].as_slice() else {
            return Err("row values absent".into());
        };
        let owned = (text.as_ptr(), blob.as_ptr());
        result.check_rows()?;
        assert_eq!(result.rows.as_ptr(), rows);
        let [Value::Text(text), Value::Blob(blob)] = result.rows[0].as_slice() else {
            return Err("row values absent".into());
        };
        assert_eq!((text.as_ptr(), blob.as_ptr()), owned);
        result.rows[0][0] = Value::List(vec![Value::Null]);
        assert!(matches!(
            result.check_rows(),
            Err(crate::Error::QueryUnsupported {
                relation: "query value type",
                ..
            })
        ));
        result.rows[0][0] = Value::Null;
        result.rows[0].pop();
        assert!(matches!(
            result.check_rows(),
            Err(crate::Error::QueryInvalid {
                field: "result row",
                ..
            })
        ));
        result.columns.pop();
        result.check_rows()?;
        Ok(())
    }

    #[test]
    fn query_follow_coverage_summary() -> TestResult {
        let unknown = QueryCoverage::from(FrameFixture::source(None));
        assert_eq!(unknown.state, QueryCoverageState::Unknown);
        let reported = QueryCoverage::from(FrameFixture::source(Some(vec![0; 4096])));
        assert_eq!(reported.state, QueryCoverageState::Reported);
        assert_eq!(reported.receipt.coverage_revision, 1);
        assert_eq!(unknown.allocation_bytes()?, reported.allocation_bytes()?);
        for kind in 0..3 {
            let mut source = FrameFixture::source(None);
            source.receipt.coverage_revision = 17;
            let gaps = match kind {
                0 => &mut source.expired,
                1 => &mut source.recovery,
                _ => &mut source.pending,
            };
            gaps.push(AnalysisGapV1 {
                first_cursor: 1,
                last_cursor: 10,
                commit_revision: 3,
            });
            let pointer = gaps.as_ptr();
            let summary = QueryCoverage::from(source);
            assert_eq!(summary.state, QueryCoverageState::Gapped);
            assert_eq!(summary.receipt.coverage_revision, 17);
            let moved = match kind {
                0 => &summary.expired,
                1 => &summary.recovery,
                _ => &summary.pending,
            };
            assert_eq!(moved.as_ptr(), pointer);
            assert_eq!(moved[0].last_cursor, 10);
            assert_eq!(
                summary.allocation_bytes()?,
                unknown.allocation_bytes()? + moved.capacity() * size_of::<AnalysisGapV1>()
            );
        }
        let mut missing = FrameFixture::source(None);
        missing.receipt.coverage_revision = 17;
        assert_eq!(
            QueryCoverage::from(missing).state,
            QueryCoverageState::Unknown
        );
        Ok(())
    }

    #[test]
    fn query_follow_shared_output() -> TestResult {
        let fixture = FrameFixture::new()?;
        let result = fixture.result()?;
        let coverage = result.sources.as_ptr();
        let shared_bytes = result.sources.allocation_bytes()?;
        let result_bytes = result.output_bytes;
        let metadata = QueryFrame::metadata(&fixture.plan, &result, &QueryLimits::default(), 7)?;
        let metadata_bytes = metadata.owned_bytes();
        assert_eq!(metadata.total_bytes()?, metadata_bytes + shared_bytes);
        let metadata = metadata.attach_lease(fixture.budget.output(metadata_bytes)?)?;
        let checkpoint = QueryFrame::checkpoint(
            QueryCheckpoint::from_result(&fixture.plan, &result)?,
            Some(result.sources.clone()),
            result.exhausted,
        )?;
        let checkpoint_bytes = checkpoint.owned_bytes();
        assert_eq!(checkpoint_bytes, size_of::<QueryFrame>());
        let checkpoint = checkpoint.attach_lease(fixture.budget.output(checkpoint_bytes)?)?;
        let data = QueryFrame::data(&fixture.plan, result)?;
        assert_eq!(data.total_bytes()?, result_bytes);
        assert_eq!(
            data.owned_bytes(),
            size_of::<QueryFrame>() - size_of::<QueryResult>()
        );
        let data_bytes = data.owned_bytes();
        let data = data.attach_lease(fixture.budget.output(data_bytes)?)?;
        for frame in [&metadata, &checkpoint, &data] {
            assert_eq!(frame.coverage().as_ptr(), coverage);
        }
        drop(data);
        let limit = QueryLimits::default().output_bytes;
        let available = fixture
            .budget
            .output(limit - shared_bytes - metadata_bytes - checkpoint_bytes)?;
        assert!(fixture.budget.output(1).is_err());
        drop(available);
        drop(metadata);
        let available = fixture
            .budget
            .output(limit - shared_bytes - checkpoint_bytes)?;
        assert!(fixture.budget.output(1).is_err());
        drop(available);
        drop(checkpoint);
        drop(fixture.budget.output(limit)?);
        Ok(())
    }

    #[test]
    fn query_follow_metadata_bounds() -> TestResult {
        let fixture = FrameFixture::new()?;
        let result = fixture.result()?;
        let owned = QueryFrame::metadata_bytes(&result, &QueryLimits::default())?;
        let bytes = owned + result.sources.allocation_bytes()?;
        let mut limits = QueryLimits {
            output_bytes: bytes,
            ..Default::default()
        };
        let frame = QueryFrame::metadata(&fixture.plan, &result, &limits, 7)?;
        assert_eq!(frame.owned_bytes(), owned);
        assert_eq!(frame.total_bytes()?, bytes);
        limits.output_bytes -= 1;
        assert!(matches!(
            QueryFrame::metadata_bytes(&result, &limits),
            Err(crate::Error::QueryLimit {
                resource: "query metadata output bytes",
                ..
            })
        ));
        assert!(QueryFrame::metadata(&fixture.plan, &result, &limits, 7).is_err());
        let mut limits = QueryLimits {
            output_bytes: size_of::<QueryFrame>(),
            ..Default::default()
        };
        limits.validate()?;
        limits.output_bytes -= 1;
        assert!(limits.validate().is_err());
        Ok(())
    }

    #[test]
    fn query_follow_frame_envelopes() -> TestResult {
        let fixture = FrameFixture::new()?;
        {
            let result = fixture.result()?;
            let limits = QueryLimits::default();
            let metadata = QueryFrame::metadata(&fixture.plan, &result, &limits, 7)?;
            assert_eq!(metadata.schema_version, QUERY_SCHEMA_VERSION);
            assert_eq!(metadata.operation, QueryOperation::Append);
            assert_eq!(metadata.store_uuid, *fixture.meta.store_uuid.as_bytes());
            assert_eq!(metadata.read_revision, fixture.meta.commit_revision);
            assert_eq!(metadata.coverage(), &**result.sources);
            let QueryPayload::Metadata(metadata) = &metadata.payload else {
                return Err("metadata absent".into());
            };
            assert_eq!(metadata.dependency_revision, 7);
            assert_eq!(metadata.row_limit, limits.output_rows);
            assert_eq!(metadata.byte_limit, limits.output_bytes);
            assert_eq!(metadata.moving_resolution_ns, None);
            assert_eq!(metadata.columns[1].units, "store revision");
            assert_eq!(metadata.columns[0].null_meaning, "");
            assert_eq!(metadata.columns[0].readiness, "available");
            assert!(QueryFrame::metadata(
                &fixture.plan,
                &result,
                &QueryLimits {
                    output_bytes: 1,
                    ..limits
                },
                7
            )
            .is_err());

            let checkpoint = QueryCheckpoint::from_result(&fixture.plan, &result)?;
            let frame = QueryFrame::checkpoint(
                checkpoint.clone(),
                Some(result.sources.clone()),
                result.exhausted,
            )?;
            assert_eq!(frame.coverage(), &**result.sources);
            let QueryPayload::Checkpoint {
                checkpoint: captured,
                ..
            } = frame.payload
            else {
                return Err("checkpoint absent".into());
            };
            assert_eq!(captured, checkpoint);
            let storage_health = crate::StorageHealthV1 {
                write_ready: false,
                retention_healthy: false,
                intake_capacity: false,
                maintenance_capacity: true,
                usage: crate::StorageUsageV1 {
                    file_bytes: 1,
                    allocated_bytes: 2,
                    available_bytes: 3,
                },
            };
            let health = QueryFrame::health(
                &fixture.plan,
                &fixture.meta,
                7,
                Some(result.sources.clone()),
                storage_health,
                true,
            )?;
            assert!(health.clock_changed);
            assert_eq!(health.coverage()[0].state, QueryCoverageState::Unknown);
            assert!(
                matches!(health.payload, QueryPayload::Health { dependency_revision: 7, storage_health: captured, .. } if captured == QueryHealth::from(storage_health))
            );
            let raw = crate::AnalysisStateSnafu {
                path: std::path::Path::new("/private/store"),
                reason: "private native SQL details",
            }
            .build();
            let error = QueryFrame::error(
                &fixture.plan,
                &fixture.meta,
                &raw,
                Some(checkpoint.clone()),
                Some(result.sources.clone()),
            )?;
            let QueryPayload::Error {
                code,
                reason,
                position,
                floor,
                last_checkpoint,
                ..
            } = error.payload
            else {
                return Err("error absent".into());
            };
            assert_eq!(code, QueryErrorCode::EvaluationFailed);
            assert_eq!(reason, code.reason());
            assert!(!reason.contains("private"));
            assert_eq!((position, floor), (None, None));
            assert_eq!(last_checkpoint, Some(checkpoint.clone()));
            let terminal = QueryFrame::terminal(
                &fixture.plan,
                &fixture.meta,
                QueryTerminalReason::Closed,
                Some(checkpoint.clone()),
                Some(result.sources.clone()),
            )?;
            assert!(
                matches!(terminal.payload, QueryPayload::Terminal { reason: QueryTerminalReason::Closed, last_checkpoint: Some(ref captured), .. } if *captured == checkpoint)
            );
            drop(result);
            assert!(fixture.result().is_err());
        }

        let mut moving = fixture.plan.clone();
        moving.template = QueryTemplate::MovingCount { seconds: 60 };
        let mut count = fixture.result()?;
        count.columns = vec![Column {
            name: "event_count".into(),
            data_type: "Bigint".into(),
        }];
        count.rows = vec![vec![Value::BigInt(2)]];
        let metadata = QueryFrame::metadata(&moving, &count, &QueryLimits::default(), 7)?;
        let QueryPayload::Metadata(metadata) = metadata.payload else {
            return Err("metadata absent".into());
        };
        assert_eq!(metadata.moving_resolution_ns, Some(1_000_000_000));
        assert!(metadata.resume_semantics.contains("current state"));
        Ok(())
    }
}
