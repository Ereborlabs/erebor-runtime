use std::sync::Arc;
use std::time::Duration;

use duckdb::types::{Value, ValueRef};
use duckdb::{params_from_iter, Config, Connection};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisReadControl, AnalysisStore, AnalysisStoreMetaV1, Result,
    StorePositionV1,
};

mod adapter;
mod budget;
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

use budget::{QueryBudget, QueryLease};
pub use follow::{QueryClock, QueryStream, SystemQueryClock};
pub use frame::{
    QueryCheckpoint, QueryColumn, QueryCoverage, QueryCoverageRows, QueryCoverageState,
    QueryErrorCode, QueryFrame, QueryMetadata, QueryPayload, QueryTerminalReason,
    QUERY_CHECKPOINT_BYTES,
};
use input::{InputRelations, InputRow};
pub use plan::{QueryOperation, QueryPlan, QueryTemplate, QUERY_SCHEMA_VERSION};

#[derive(Clone, Debug)]
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
    pub scanned_bytes: usize,
    pub input_bytes: usize,
    pub input_rows: usize,
    pub output_bytes: usize,
    pub evaluated_utc_ns: u64,
    pub scanned_through: StorePositionV1,
    pub exhausted: bool,
    pub limited: bool,
    pub next_expiry_ns: Option<u64>,
    _lease: QueryLease,
}

pub struct QueryOwner {
    store: Arc<AnalysisStore>,
    identity: AnalysisStoreMetaV1,
    limits: QueryLimits,
    budget: Arc<QueryBudget>,
    #[cfg(test)]
    input_refs: std::sync::Mutex<Vec<std::sync::Weak<adapter::InputTable>>>,
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
        let control = control.within(self.limits.extract_timeout)?;
        self.evaluate(plan, now_ns, None, false, &control)
    }

    fn evaluate(
        &self,
        plan: &QueryPlan,
        now_ns: u64,
        after: Option<StorePositionV1>,
        paged: bool,
        control: &AnalysisReadControl,
    ) -> Result<QueryResult> {
        let mut lease = self.budget.evaluate(plan.selection.tenant_id)?;
        let selection = plan.dependencies(now_ns);
        let project = |input: crate::AnalysisInputV1<'_>| {
            let row = InputRow::try_from(input)?;
            let bytes = row.allocation_bytes()?;
            Ok(Some((row, bytes)))
        };
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self.limits.input_bytes,
            ..Default::default()
        };
        let mut page = if paged {
            self.store
                .position_rows(&selection, after, bounds, control, project)?
        } else if plan.reads_events() {
            self.store
                .extract_rows(&selection, bounds, control, project)?
        } else {
            self.store
                .metadata_rows(&selection, bounds, control, project)?
        };
        let next_expiry_ns = match plan.template {
            QueryTemplate::MovingCount { seconds } => page
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
        #[cfg(test)]
        self.input_refs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(input.references());
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
        let mut summary_bytes = coverage_bytes + std::mem::size_of::<QueryFrame>();
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
        let config = Config::default()
            .with("temp_directory", "")
            .and_then(|config| config.enable_external_access(false))
            .and_then(|config| config.enable_autoload_extension(false))
            .and_then(|config| config.threads(1))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "configure trusted query",
            })?;
        let mut config = config;
        for (name, value) in [
            ("autoinstall_known_extensions", "false"),
            ("allow_unsigned_extensions", "false"),
            ("memory_limit", "64MiB"),
        ] {
            config = config
                .with(name, value)
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "bound trusted query",
                })?;
        }
        let connection = Connection::open_in_memory_with_flags(config).context(
            crate::AnalysisDatabaseSnafu {
                operation: "open trusted query",
            },
        )?;
        let mut scanned_through = page.scanned_through;
        let (columns, types, rows, output_bytes, limited) =
            evaluation.query_run(&connection, || {
                input.register(&connection)?;
                let sql = format!(
                    "SELECT * FROM ({}) AS query_result LIMIT {}",
                    plan.sql(),
                    self.limits.output_rows + 1
                );
                let mut statement =
                    connection
                        .prepare(&sql)
                        .context(crate::AnalysisDatabaseSnafu {
                            operation: "prepare trusted query",
                        })?;
                let parameters = plan.parameters(now_ns);
                let mut result = statement
                    .query(params_from_iter(parameters.iter()))
                    .context(crate::AnalysisDatabaseSnafu {
                        operation: "execute trusted query",
                    })?;
                let schema = result.as_ref().ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "query result schema",
                    }
                    .build()
                })?;
                let columns = schema.column_names();
                let types: Vec<_> = (0..schema.column_count())
                    .map(|index| format!("{:?}", schema.column_logical_type(index).id()))
                    .collect();
                let mut rows = Vec::new();
                let mut output_bytes = summary_bytes;
                for fields in [&columns, &types] {
                    output_bytes = output_bytes.saturating_add(
                        fields
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>()),
                    );
                    for field in fields {
                        output_bytes = output_bytes.saturating_add(field.capacity());
                    }
                }
                self.check_output(output_bytes)?;
                let mut limited = false;
                while let Some(row) = result.next().context(crate::AnalysisDatabaseSnafu {
                    operation: "read trusted query",
                })? {
                    evaluation.check()?;
                    if rows.len() == self.limits.output_rows {
                        limited = true;
                        if plan.operation() == QueryOperation::Append {
                            scanned_through = Self::before_row(row)?;
                        }
                        break;
                    }
                    let count = row.as_ref().column_count();
                    let mut row_bytes = count.saturating_mul(std::mem::size_of::<Value>());
                    let descriptor = if rows.len() == rows.capacity() {
                        std::mem::size_of::<Vec<Value>>()
                    } else {
                        0
                    };
                    if output_bytes
                        .saturating_add(row_bytes)
                        .saturating_add(descriptor)
                        > self.limits.output_bytes
                    {
                        if rows.is_empty() {
                            return crate::QueryLimitSnafu {
                                resource: "query output bytes",
                                limit: self.limits.output_bytes,
                            }
                            .fail();
                        }
                        limited = true;
                        if plan.operation() == QueryOperation::Append {
                            scanned_through = Self::before_row(row)?;
                        }
                        break;
                    }
                    let mut values = Vec::with_capacity(count);
                    for index in 0..count {
                        let value = row.get_ref(index).context(crate::AnalysisDatabaseSnafu {
                            operation: "read query value",
                        })?;
                        let bytes = match &value {
                            ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                            _ => 0,
                        };
                        row_bytes = row_bytes.saturating_add(bytes);
                        if output_bytes
                            .saturating_add(row_bytes)
                            .saturating_add(descriptor)
                            > self.limits.output_bytes
                        {
                            limited = true;
                            break;
                        }
                        values.push(value.to_owned());
                    }
                    if limited {
                        if rows.is_empty() {
                            return crate::QueryLimitSnafu {
                                resource: "query output bytes",
                                limit: self.limits.output_bytes,
                            }
                            .fail();
                        }
                        if plan.operation() == QueryOperation::Append {
                            scanned_through = Self::before_row(row)?;
                        }
                        break;
                    }
                    let capacity = rows.capacity();
                    rows.try_reserve_exact(1).map_err(|_| {
                        crate::QueryLimitSnafu {
                            resource: "query output allocation",
                            limit: self.limits.output_bytes,
                        }
                        .build()
                    })?;
                    output_bytes += row_bytes
                        + (rows.capacity() - capacity) * std::mem::size_of::<Vec<Value>>();
                    if output_bytes > self.limits.output_bytes {
                        return crate::QueryLimitSnafu {
                            resource: "query output allocation",
                            limit: self.limits.output_bytes,
                        }
                        .fail();
                    }
                    rows.push(values);
                }
                drop(result);
                if limited && plan.operation() == QueryOperation::Replace {
                    return crate::QueryLimitSnafu {
                        resource: "complete replacement output",
                        limit: self.limits.output_bytes,
                    }
                    .fail();
                }
                Ok((columns, types, rows, output_bytes, limited))
            })?;
        drop(connection);
        drop(input);
        let mut result = QueryResult {
            columns,
            types,
            rows,
            meta: page.extraction.meta,
            sources,
            missing_contexts: page.extraction.missing_contexts,
            scanned_bytes: page.extraction.scanned_bytes,
            input_bytes: page.extraction.input_bytes,
            input_rows,
            output_bytes,
            evaluated_utc_ns: now_ns,
            scanned_through,
            exhausted: page.exhausted && !limited,
            limited,
            next_expiry_ns,
            _lease: lease,
        };
        result.output_bytes = result.allocation_bytes()?;
        self.check_output(result.output_bytes)?;
        let owned = result.output_bytes
            - coverage_bytes
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
    ) -> Result<(
        AnalysisStoreMetaV1,
        Arc<QueryCoverageRows>,
        crate::StorageHealthV1,
    )> {
        let mut lease = self.budget.evaluate(plan.selection.tenant_id)?;
        let mut selection = plan.dependencies(now_ns);
        selection.contexts.clear();
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self.limits.input_bytes,
            ..Default::default()
        };
        let page = self
            .store
            .metadata_rows::<InputRow>(&selection, bounds, control, |_| Ok(None))?;
        let sources = page
            .extraction
            .sources
            .into_iter()
            .map(QueryCoverage::from)
            .collect();
        let bytes = QueryCoverageRows::allocation_bytes_for(&sources)?;
        self.check_output(bytes.saturating_add(std::mem::size_of::<QueryFrame>()))?;
        let sources = Arc::new(QueryCoverageRows::new(sources, lease.split(bytes)?)?);
        let health = self.store.storage_health()?;
        control.check()?;
        Ok((page.extraction.meta, sources, health))
    }

    fn before_row(row: &duckdb::Row<'_>) -> Result<StorePositionV1> {
        let revision: u64 = row
            .get("commit_revision")
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read query commit position",
            })?;
        let ordinal: u32 = row.get("ordinal").context(crate::AnalysisDatabaseSnafu {
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
    fn allocation_bytes(&self) -> Result<usize> {
        let mut bytes = std::mem::size_of::<QueryFrame>();
        bytes = bytes.saturating_add(self.sources.allocation_bytes()?);
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
