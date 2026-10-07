use std::sync::Arc;
use std::time::Duration;

use duckdb::types::Value;
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisReadControl, AnalysisStore, AnalysisStoreMetaV1, Result,
    StorePositionV1,
};

mod adapter;
mod admission;
mod authorization;
#[cfg(test)]
mod authorization_tests;
mod budget;
#[cfg(test)]
mod client_tests;
mod discovery;
mod evaluation;
mod follow;
#[cfg(test)]
mod follow_tests;
mod frame;
mod input;
#[cfg(test)]
mod owner_tests;
mod plan;
#[cfg(test)]
mod tests;

pub use admission::{QueryBinding, QuerySql};
use authorization::QuerySession;
pub use authorization::{QueryAuthorization, QueryGrant};
use budget::{QueryBudget, QueryLease};
pub use follow::{QueryClock, QueryStream, SystemQueryClock};
pub use frame::{
    QueryCheckpoint, QueryColumn, QueryCoverage, QueryCoverageRows, QueryCoverageState,
    QueryErrorCode, QueryFrame, QueryHealth, QueryMetadata, QueryPayload, QueryTerminalReason,
    QUERY_CHECKPOINT_BYTES,
};
use input::{InputRelations, InputRow};
pub use plan::{QueryOperation, QueryPlan, QueryTemplate, QUERY_SCHEMA_VERSION};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueryLimits {
    pub scan_bytes: usize,
    pub input_bytes: usize,
    pub output_rows: usize,
    pub output_bytes: usize,
    pub extract_timeout: Duration,
    pub evaluate_timeout: Duration,
    pub global_evaluations: usize,
    pub tenant_evaluations: usize,
    pub global_streams: usize,
    pub tenant_streams: usize,
    pub input_capacity: usize,
    pub output_capacity: usize,
    pub replace_interval: Duration,
    pub heartbeat: Duration,
    pub output_timeout: Duration,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            scan_bytes: 256 * 1024 * 1024,
            input_bytes: 64 * 1024 * 1024,
            output_rows: 200,
            output_bytes: 1024 * 1024,
            extract_timeout: Duration::from_secs(1),
            evaluate_timeout: Duration::from_secs(1),
            global_evaluations: 2,
            tenant_evaluations: 1,
            global_streams: 16,
            tenant_streams: 4,
            input_capacity: 128 * 1024 * 1024,
            output_capacity: 16 * 1024 * 1024,
            replace_interval: Duration::from_millis(500),
            heartbeat: Duration::from_secs(15),
            output_timeout: Duration::from_secs(10),
        }
    }
}

impl QueryLimits {
    fn client_capacity(&self) -> Result<()> {
        if self.output_rows > 200 || self.output_bytes > 1024 * 1024 {
            return crate::QueryInvalidSnafu {
                field: "client query limits",
            }
            .fail();
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.scan_bytes == 0
            || self.input_bytes == 0
            || self.output_rows == 0
            || self.output_rows == usize::MAX
            || self.output_bytes < std::mem::size_of::<QueryFrame>()
            || self.extract_timeout.is_zero()
            || self.evaluate_timeout.is_zero()
            || self.global_evaluations == 0
            || self.tenant_evaluations == 0
            || self.tenant_evaluations > self.global_evaluations
            || self.global_streams == 0
            || self.tenant_streams == 0
            || self.tenant_streams > self.global_streams
            || self.input_capacity < self.input_bytes
            || self.output_capacity < self.output_bytes
            || self.replace_interval < Duration::from_millis(500)
            || self.heartbeat.is_zero()
            || self.heartbeat > Duration::from_secs(15)
            || self.output_timeout.is_zero()
            || self.output_timeout > Duration::from_secs(10)
        {
            return crate::QueryInvalidSnafu {
                field: "query limits",
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub types: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub meta: AnalysisStoreMetaV1,
    pub sources: Arc<QueryCoverageRows>,
    pub missing_contexts: Vec<AnalysisContextKeyV1>,
    /// Internal counters are absent from client results.
    pub scanned_bytes: Option<usize>,
    pub input_bytes: Option<usize>,
    pub input_rows: usize,
    pub output_bytes: usize,
    pub evaluated_utc_ns: u64,
    pub scanned_through: StorePositionV1,
    pub exhausted: bool,
    pub limited: bool,
    pub next_expiry_ns: Option<u64>,
    pub positions: Vec<StorePositionV1>,
    reads: Option<Arc<frame::QueryReadScope>>,
    _lease: QueryLease,
}

pub struct QueryOwner {
    store: Arc<AnalysisStore>,
    identity: AnalysisStoreMetaV1,
    limits: QueryLimits,
    budget: Arc<QueryBudget>,
    #[cfg(test)]
    input_refs: std::sync::Mutex<Vec<std::sync::Weak<adapter::InputTable>>>,
    #[cfg(test)]
    scan_gate: std::sync::Mutex<Option<adapter::ScanGate>>,
    #[cfg(test)]
    native_failed: std::sync::atomic::AtomicBool,
}

struct QueryTask {
    control: Arc<AnalysisReadControl>,
    running: bool,
}

enum QueryRead {
    Snapshot,
    Append(Option<StorePositionV1>),
}

impl Drop for QueryTask {
    fn drop(&mut self) {
        if self.running {
            let _cancelled = self.control.cancel();
        }
    }
}

impl QueryOwner {
    pub fn new(store: Arc<AnalysisStore>, limits: QueryLimits) -> Result<Self> {
        limits.validate()?;
        let budget = QueryBudget::new(limits.clone());
        let identity = store.meta()?;
        Ok(Self {
            store,
            identity,
            limits,
            budget,
            #[cfg(test)]
            input_refs: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            scan_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            native_failed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Evaluate a code-owned plan at one trusted intake-time instant.
    pub fn query_at(&self, plan: &QueryPlan, now_ns: u64) -> Result<QueryResult> {
        let control = AnalysisReadControl::with_timeout(self.limits.extract_timeout)?;
        self.query_cancel(plan, now_ns, &control)
    }

    pub fn query_cancel(
        &self,
        plan: &QueryPlan,
        now_ns: u64,
        control: &AnalysisReadControl,
    ) -> Result<QueryResult> {
        if plan.grant.is_some() {
            return crate::QueryDeniedSnafu.fail();
        }
        let control = control.within(self.limits.extract_timeout)?;
        self.evaluate(
            plan,
            now_ns,
            QueryRead::Snapshot,
            &control,
            self.reserve(plan)?,
        )
    }

    pub async fn query_client(
        self: &Arc<Self>,
        plan: QueryPlan,
        authority: Arc<dyn QueryAuthorization>,
        now_ns: u64,
        control: Arc<AnalysisReadControl>,
    ) -> Result<QueryResult> {
        let grant = plan
            .grant
            .clone()
            .ok_or_else(|| crate::QueryDeniedSnafu.build())?;
        authority.check(&grant)?;
        let stage = Arc::new(control.within(self.limits.extract_timeout)?);
        let lease = self.reserve(&plan)?;
        let result = self
            .evaluate_reserved(
                plan,
                now_ns,
                QueryRead::Snapshot,
                stage,
                lease,
                Some(QuerySession {
                    authority: authority.clone(),
                    grant: grant.clone(),
                }),
            )
            .await?;
        authority.check(&grant)?;
        if let Some(scope) = &result.reads {
            scope.check(None).await?;
        }
        authority.check(&grant)?;
        Ok(result)
    }

    async fn evaluate_reserved(
        self: &Arc<Self>,
        plan: QueryPlan,
        now_ns: u64,
        read: QueryRead,
        control: Arc<AnalysisReadControl>,
        lease: QueryLease,
        session: Option<QuerySession>,
    ) -> Result<QueryResult> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query runtime",
            }
            .build()
        })?;
        let stage = control.within(self.limits.extract_timeout)?;
        let owner = self.clone();
        let mut task = QueryTask {
            control,
            running: true,
        };
        let result = runtime
            .spawn_blocking(move || {
                stage.check()?;
                if let Some(session) = &session {
                    session.check()?;
                }
                owner.evaluate(&plan, now_ns, read, &stage, lease)
            })
            .await;
        task.running = false;
        result.context(crate::QueryExecutionSnafu)?
    }

    fn reserve(&self, plan: &QueryPlan) -> Result<QueryLease> {
        if plan.grant.is_some() {
            self.limits.client_capacity()?;
        }
        self.budget.evaluate(plan.selection.tenant_id)
    }

    async fn reserve_wait(&self, plan: &QueryPlan) -> Result<QueryLease> {
        if plan.grant.is_some() {
            self.limits.client_capacity()?;
        }
        self.budget.wait(plan.selection.tenant_id).await
    }

    fn evaluate(
        &self,
        plan: &QueryPlan,
        now_ns: u64,
        read: QueryRead,
        control: &AnalysisReadControl,
        mut lease: QueryLease,
    ) -> Result<QueryResult> {
        let selection = plan.dependencies(now_ns)?;
        let project = |input: crate::AnalysisInputV1<'_>| {
            let relation = match &input {
                crate::AnalysisInputV1::Event { .. } => "events",
                crate::AnalysisInputV1::Context(_) => "context_versions",
                crate::AnalysisInputV1::DiscoveryContext(_) => "context",
                crate::AnalysisInputV1::Behavior { .. } => "behaviors",
                crate::AnalysisInputV1::Target { .. } => "targets",
                crate::AnalysisInputV1::Trace { .. } => "traces",
                crate::AnalysisInputV1::TraceOutput { .. } => "trace_output",
                crate::AnalysisInputV1::TraceMeasurement { .. } => "trace_measurements",
                crate::AnalysisInputV1::Result { .. } => "results",
            };
            if matches!(&plan.template, QueryTemplate::Client(sql) if !sql.dependencies().contains(relation))
            {
                return Ok(None);
            }
            let row = InputRow::try_from(input)?;
            let bytes = row.allocation_bytes()?;
            Ok(Some((row, bytes)))
        };
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self.limits.input_bytes,
            ..Default::default()
        };
        let mut page = if let QueryRead::Append(after) = read {
            self.store
                .position_rows(&selection, after, bounds, control, project)?
        } else if plan.reads_raw() {
            self.store
                .extract_rows(&selection, bounds, control, project)?
        } else {
            self.store
                .metadata_rows(&selection, bounds, control, project)?
        };
        let next_expiry_ns = match plan.moving_seconds() {
            Some(seconds) => page
                .extraction
                .pages
                .iter()
                .filter(|page| page.relation == crate::AnalysisRelationV1::Events)
                .flat_map(|page| &page.rows)
                .filter_map(|row| match row.0.get(10) {
                    Some(Value::UBigInt(time)) => Some(*time),
                    _ => None,
                })
                .min()
                .and_then(|time| time.checked_add(u64::from(seconds) * 1_000_000_000))
                .and_then(|time| time.checked_add(1_000_000_000))
                .map(|time| time / 1_000_000_000 * 1_000_000_000),
            _ => None,
        };
        let input_rows = page
            .extraction
            .pages
            .iter()
            .map(|page| page.rows.len())
            .sum();
        let input = InputRelations::new(
            &mut page.extraction,
            self.limits.input_bytes,
            &plan.template,
        )?;
        let input = if plan.grant.is_some() && plan.operation() == QueryOperation::Append {
            input.append_positions(self.limits.input_bytes)?
        } else {
            input
        };
        page.extraction.input_bytes = input.allocation_bytes();
        #[cfg(test)]
        self.input_refs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(input.references());
        #[cfg(test)]
        input.set_scan_gate(
            self.scan_gate
                .lock()
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "test scan gate",
                    }
                    .build()
                })?
                .take(),
        )?;
        let sources: Vec<_> = std::mem::take(&mut page.extraction.sources)
            .into_iter()
            .map(QueryCoverage::from)
            .collect();
        let coverage_bytes = QueryCoverageRows::allocation_bytes_for(&sources)?;
        self.check_output(coverage_bytes)?;
        let sources = Arc::new(QueryCoverageRows::new(
            sources,
            lease.split(coverage_bytes)?,
        )?);
        let requests = std::mem::take(&mut page.extraction.trace_reads);
        let read_bytes = if requests.is_empty() {
            0
        } else {
            frame::QueryReadScope::allocation_for(&requests)
        };
        let reads = if requests.is_empty() {
            None
        } else {
            Some(Arc::new(frame::QueryReadScope::new(
                self.store.clone(),
                selection.tenant_id,
                requests,
                self.limits.extract_timeout,
                lease.split(read_bytes)?,
            )?))
        };
        let mut summary_bytes = coverage_bytes + read_bytes + std::mem::size_of::<QueryFrame>();
        summary_bytes = summary_bytes.saturating_add(
            page.extraction
                .missing_contexts
                .capacity()
                .saturating_mul(std::mem::size_of::<AnalysisContextKeyV1>()),
        );
        for key in &page.extraction.missing_contexts {
            summary_bytes = summary_bytes
                .saturating_add(key.owner_id.capacity())
                .saturating_add(key.entity_key.capacity())
                .saturating_add(key.lifetime_key.capacity());
        }
        self.check_output(summary_bytes)?;
        let evaluation = control.stage(self.limits.evaluate_timeout)?;
        let (sql, parameters) = plan.evaluation_at(now_ns)?;
        let output = evaluation::QueryEvaluation::run(
            &input,
            &sql,
            &parameters,
            evaluation::EvaluationLimits {
                rows: self.limits.output_rows,
                bytes: self.limits.output_bytes,
                summary_bytes,
                operation: plan.operation(),
                complete: match &plan.template {
                    QueryTemplate::Client(client) => client.follow(),
                    _ => true,
                },
            },
            page.scanned_through,
            &evaluation,
            #[cfg(test)]
            Some(&self.native_failed),
        )?;
        drop(input);
        let evaluation::EvaluationResult {
            mut columns,
            mut types,
            mut rows,
            output_bytes,
            limited,
            scanned_through,
        } = output;
        let positions = if plan.grant.is_some() && plan.operation() == QueryOperation::Append {
            QueryResult::take_positions(&mut columns, &mut types, &mut rows)?
        } else {
            Vec::new()
        };
        let mut result = QueryResult {
            columns,
            types,
            rows,
            meta: page.extraction.meta,
            sources,
            missing_contexts: page.extraction.missing_contexts,
            scanned_bytes: plan
                .grant
                .is_none()
                .then_some(page.extraction.scanned_bytes),
            input_bytes: plan.grant.is_none().then_some(page.extraction.input_bytes),
            input_rows,
            output_bytes,
            evaluated_utc_ns: now_ns,
            scanned_through,
            exhausted: page.exhausted && !limited,
            limited,
            next_expiry_ns,
            positions,
            reads,
            _lease: lease,
        };
        result.output_bytes = result.allocation_bytes()?;
        self.check_output(result.output_bytes)?;
        let owned = result.output_bytes
            - coverage_bytes
            - read_bytes
            - (std::mem::size_of::<QueryFrame>() - std::mem::size_of::<QueryResult>());
        result._lease = result._lease.output(owned)?;
        Ok(result)
    }

    fn check_output(&self, bytes: usize) -> Result<()> {
        if bytes > self.limits.output_bytes {
            return crate::QueryLimitSnafu {
                resource: "query output bytes",
                limit: self.limits.output_bytes,
            }
            .fail();
        }
        Ok(())
    }

    fn coverage(
        &self,
        plan: &QueryPlan,
        now_ns: u64,
        control: &AnalysisReadControl,
        mut lease: QueryLease,
    ) -> Result<(
        AnalysisStoreMetaV1,
        Arc<QueryCoverageRows>,
        crate::StorageHealthV1,
    )> {
        let mut selection = plan.dependencies(now_ns)?;
        selection.contexts.clear();
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self.limits.input_bytes,
            ..Default::default()
        };
        let page = self
            .store
            .metadata_rows::<InputRow>(&selection, bounds, control, |_| Ok(None))?;
        let extraction = page.extraction;
        let sources = extraction
            .sources
            .into_iter()
            .map(QueryCoverage::from)
            .collect();
        let bytes = QueryCoverageRows::allocation_bytes_for(&sources)?;
        self.check_output(bytes.saturating_add(std::mem::size_of::<QueryFrame>()))?;
        let sources = Arc::new(QueryCoverageRows::new(sources, lease.split(bytes)?)?);
        let health = self.store.storage_health()?;
        control.check()?;
        Ok((extraction.meta, sources, health))
    }

    fn before_row(row: &duckdb::Row<'_>) -> Result<StorePositionV1> {
        let revision: u64 = row
            .get("__araphor_commit_revision")
            .or_else(|_| row.get("commit_revision"))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read query commit position",
            })?;
        let ordinal: u32 = row
            .get("__araphor_ordinal")
            .or_else(|_| row.get("ordinal"))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read query ordinal",
            })?;
        match ordinal.checked_sub(1) {
            Some(ordinal) => Ok(StorePositionV1 {
                commit_revision: revision,
                ordinal,
            }),
            None => Ok(StorePositionV1 {
                commit_revision: revision.checked_sub(1).ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "append position",
                    }
                    .build()
                })?,
                ordinal: u32::MAX,
            }),
        }
    }
}

impl QueryResult {
    fn take_positions(
        columns: &mut Vec<String>,
        types: &mut Vec<String>,
        rows: &mut [Vec<Value>],
    ) -> Result<Vec<StorePositionV1>> {
        if columns.len() < 2
            || columns.len() != types.len()
            || columns[columns.len() - 2] != "__araphor_commit_revision"
            || columns[columns.len() - 1] != "__araphor_ordinal"
        {
            return crate::QueryInvalidSnafu {
                field: "query cursor output",
            }
            .fail();
        }
        let width = columns.len();
        let mut positions = Vec::with_capacity(rows.len());
        for row in rows {
            if row.len() != width {
                return crate::QueryInvalidSnafu {
                    field: "query cursor output",
                }
                .fail();
            }
            let ordinal = row.pop();
            let revision = row.pop();
            let (Some(Value::UBigInt(commit_revision)), Some(Value::UInt(ordinal))) =
                (revision, ordinal)
            else {
                return crate::QueryInvalidSnafu {
                    field: "query cursor output",
                }
                .fail();
            };
            positions.push(StorePositionV1 {
                commit_revision,
                ordinal,
            });
        }
        columns.truncate(width - 2);
        types.truncate(width - 2);
        Ok(positions)
    }

    fn allocation_bytes(&self) -> Result<usize> {
        let mut bytes = std::mem::size_of::<QueryFrame>();
        bytes = bytes.saturating_add(
            self.positions
                .capacity()
                .saturating_mul(std::mem::size_of::<StorePositionV1>()),
        );
        bytes = bytes.saturating_add(self.sources.allocation_bytes()?);
        bytes = bytes.saturating_add(
            self.reads
                .as_ref()
                .map_or(0, |scope| scope.allocation_bytes()),
        );
        bytes = bytes.saturating_add(
            self.missing_contexts
                .capacity()
                .saturating_mul(std::mem::size_of::<AnalysisContextKeyV1>()),
        );
        for key in &self.missing_contexts {
            bytes = bytes
                .saturating_add(key.owner_id.capacity())
                .saturating_add(key.entity_key.capacity())
                .saturating_add(key.lifetime_key.capacity());
        }
        for fields in [&self.columns, &self.types] {
            bytes = bytes.saturating_add(
                fields
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            );
            for field in fields {
                bytes = bytes.saturating_add(field.capacity());
            }
        }
        bytes = bytes.saturating_add(
            self.rows
                .capacity()
                .saturating_mul(std::mem::size_of::<Vec<Value>>()),
        );
        for row in &self.rows {
            bytes =
                bytes.saturating_add(row.capacity().saturating_mul(std::mem::size_of::<Value>()));
            for value in row {
                bytes = bytes.saturating_add(match value {
                    Value::Text(value) => value.capacity(),
                    Value::Blob(value) => value.capacity(),
                    _ => 0,
                });
            }
        }
        Ok(bytes)
    }
}
