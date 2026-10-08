use std::ops::Bound;
use std::sync::Arc;

use duckdb::types::Value;

use super::{QueryGrant, QuerySql};
use crate::{AnalysisSelectionV1, Result, Selection};

pub const QUERY_SCHEMA_VERSION: u32 = 1;

/// Trusted templates and client SQL that passed the closed binder.
#[derive(Clone, Debug, PartialEq)]
pub enum QueryTemplate {
    Events { operation: Option<u32> },
    OperationCounts,
    ExactMatch { operation: u32, object_id: [u8; 16] },
    MovingCount { seconds: u32 },
    FixedBuckets { seconds: u32 },
    SubjectSequence { first: u32, second: u32 },
    RevisionDifference,
    Coverage,
    ContextVersions,
    Catalog,
    Client(QuerySql),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum QueryOperation {
    Append,
    Replace,
}

#[derive(Clone, Debug)]
pub struct QueryPlan {
    scope: QueryScope,
    pub(super) template: QueryTemplate,
}

#[derive(Clone, Debug)]
enum QueryScope {
    Trusted(Arc<AnalysisSelectionV1>),
    Client(Arc<QueryGrant>),
}

impl QueryPlan {
    pub fn new(selection: AnalysisSelectionV1, template: QueryTemplate) -> Result<Self> {
        if matches!(template, QueryTemplate::Client(_)) {
            return crate::QueryDeniedSnafu.fail();
        }
        if !selection.valid() {
            return crate::QueryInvalidSnafu { field: "scope" }.fail();
        }
        if !selection.results.is_empty() {
            return crate::QueryUnsupportedSnafu {
                relation: "results",
            }
            .fail();
        }
        match template {
            QueryTemplate::MovingCount { seconds } => {
                if !(1..=86_400).contains(&seconds)
                    || selection.received_from != Bound::Unbounded
                    || selection.received_until != Bound::Unbounded
                {
                    return crate::QueryInvalidSnafu {
                        field: "moving window",
                    }
                    .fail();
                }
            }
            QueryTemplate::FixedBuckets { seconds: 0 } => {
                return crate::QueryInvalidSnafu {
                    field: "bucket width",
                }
                .fail();
            }
            QueryTemplate::RevisionDifference => {
                if selection.contexts.as_slice().len() != 2 {
                    return crate::QueryInvalidSnafu {
                        field: "context pair",
                    }
                    .fail();
                }
                let left = &selection.contexts.as_slice()[0];
                let right = &selection.contexts.as_slice()[1];
                if left.owner_id != right.owner_id
                    || left.entity_key != right.entity_key
                    || left.lifetime_key != right.lifetime_key
                {
                    return crate::QueryInvalidSnafu {
                        field: "context pair",
                    }
                    .fail();
                }
            }
            _ => {}
        }
        Ok(Self {
            scope: QueryScope::Trusted(Arc::new(selection)),
            template,
        })
    }

    pub fn client(grant: QueryGrant, sql: QuerySql) -> Result<Self> {
        grant.validate()?;
        if !grant.selection.results.is_empty() {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(Self {
            scope: QueryScope::Client(Arc::new(grant)),
            template: QueryTemplate::Client(sql),
        })
    }

    pub(super) fn base_selection(&self) -> &AnalysisSelectionV1 {
        match &self.scope {
            QueryScope::Trusted(selection) => selection,
            QueryScope::Client(grant) => &grant.selection,
        }
    }

    pub(super) fn grant(&self) -> Option<&Arc<QueryGrant>> {
        match &self.scope {
            QueryScope::Client(grant) => Some(grant),
            QueryScope::Trusted(_) => None,
        }
    }

    pub fn operation(&self) -> QueryOperation {
        match &self.template {
            QueryTemplate::Client(sql) => sql.operation(),
            QueryTemplate::Events { .. } | QueryTemplate::ExactMatch { .. } => {
                QueryOperation::Append
            }
            _ => QueryOperation::Replace,
        }
    }

    pub fn template(&self) -> &QueryTemplate {
        &self.template
    }

    pub(super) fn moving_seconds(&self) -> Option<u32> {
        match &self.template {
            QueryTemplate::MovingCount { seconds } => Some(*seconds),
            QueryTemplate::Client(sql) => sql.moving_seconds(),
            _ => None,
        }
    }

    pub(super) fn evaluation_at(&self, now_ns: u64) -> Result<(String, Vec<Value>)> {
        match &self.template {
            QueryTemplate::Client(sql) => {
                let bound = sql.bind_at(now_ns)?;
                Ok((bound.sql, bound.parameters))
            }
            _ => Ok((self.sql(), self.parameters(now_ns))),
        }
    }

    pub(super) fn reads_raw(&self) -> bool {
        if let QueryTemplate::Client(sql) = &self.template {
            return ["events", "trace_output", "trace_measurements"]
                .iter()
                .any(|relation| sql.dependencies().contains(*relation));
        }
        self.reads_events()
    }

    fn reads_events(&self) -> bool {
        if let QueryTemplate::Client(sql) = &self.template {
            return sql.dependencies().contains("events");
        }
        !matches!(
            self.template,
            QueryTemplate::Coverage
                | QueryTemplate::ContextVersions
                | QueryTemplate::RevisionDifference
                | QueryTemplate::Catalog
        )
    }

    pub(super) fn dependencies(&self, now_ns: u64) -> Result<AnalysisSelectionV1> {
        let mut selection = self.selection(now_ns);
        let trace_sql = matches!(&self.template, QueryTemplate::Client(sql) if ["traces", "trace_output", "trace_measurements"].iter().any(|relation| sql.dependencies().contains(*relation)));
        let target_sql = matches!(&self.template, QueryTemplate::Client(sql) if sql.dependencies().contains("targets"));
        let behavior_sql = matches!(&self.template, QueryTemplate::Client(sql) if sql.dependencies().contains("behaviors"));
        let context_sql = matches!(&self.template, QueryTemplate::Client(sql) if sql.dependencies().contains("context"));
        let graph_sql = matches!(&self.template, QueryTemplate::Client(sql) if super::graph::RELATIONS.iter().any(|relation| sql.dependencies().contains(*relation)));
        let notification_sql = matches!(&self.template, QueryTemplate::Client(sql) if sql.dependencies().contains("notifications"));
        selection.discovery = behavior_sql;
        selection.profiles.clear();
        selection.graph = graph_sql;
        selection.graphs.clear();
        selection.notifications = notification_sql;
        selection.obligations.clear();
        selection.targets = target_sql;
        selection.targets_only = matches!(&self.template, QueryTemplate::Client(sql) if target_sql && !context_sql && !sql.dependencies().contains("context_versions"));
        if !trace_sql {
            selection.traces = Selection::Exact(Vec::new());
        }
        match &self.template {
            QueryTemplate::Client(sql) => {
                let bound = sql.bind_at(now_ns)?;
                let (first, last) = selection.time_range().unwrap_or((1, 0));
                let from = match bound.received_from {
                    Bound::Included(value) => value.max(first),
                    Bound::Excluded(value) => value.saturating_add(1).max(first),
                    Bound::Unbounded => first,
                };
                let until = match bound.received_until {
                    Bound::Included(value) => value.min(last),
                    Bound::Excluded(value) => value.saturating_sub(1).min(last),
                    Bound::Unbounded => last,
                };
                selection.received_from = Bound::Included(from);
                selection.received_until = Bound::Included(until);
                if !sql.dependencies().contains("events")
                    && !sql.dependencies().contains("coverage")
                    && !behavior_sql
                    && !graph_sql
                    && !notification_sql
                {
                    selection.sources = Selection::Exact(Vec::new());
                    if !trace_sql && !target_sql {
                        selection.nodes.clear();
                        selection.binding_ids.clear();
                    }
                }
                if !sql.dependencies().contains("context_versions") && !context_sql && !target_sql {
                    selection.contexts = Selection::Exact(Vec::new());
                }
            }
            QueryTemplate::Catalog => {
                selection.sources = Selection::Exact(Vec::new());
                selection.contexts = Selection::Exact(Vec::new());
                selection.nodes.clear();
            }
            QueryTemplate::ContextVersions | QueryTemplate::RevisionDifference => {
                selection.sources = Selection::Exact(Vec::new());
                selection.nodes.clear();
            }
            QueryTemplate::Coverage => {
                selection.contexts = Selection::Exact(Vec::new());
                selection.received_from = Bound::Unbounded;
                selection.received_until = Bound::Unbounded;
            }
            _ => {}
        }
        Ok(selection)
    }

    pub(super) fn selection(&self, now_ns: u64) -> AnalysisSelectionV1 {
        let mut selection = self.base_selection().clone();
        if let QueryTemplate::MovingCount { seconds } = self.template {
            selection.received_from =
                Bound::Included(now_ns.saturating_sub(u64::from(seconds) * 1_000_000_000));
        }
        selection
    }

    pub(super) fn statement(&self) -> &'static str {
        match self.template {
            QueryTemplate::Events { .. } => "SELECT * FROM scoped_events WHERE (CAST(? AS UINTEGER) IS NULL OR operation = ?) ORDER BY commit_revision, ordinal",
            QueryTemplate::ExactMatch { .. } => "SELECT * FROM scoped_events WHERE operation = ? AND exact_object_id = ? ORDER BY commit_revision, ordinal",
            QueryTemplate::OperationCounts => "SELECT operation, COUNT(*) AS event_count FROM scoped_events GROUP BY operation ORDER BY operation",
            QueryTemplate::MovingCount { .. } => "SELECT COUNT(*) AS event_count FROM scoped_events",
            QueryTemplate::FixedBuckets { .. } => "SELECT time_bucket(CAST(? AS BIGINT) * INTERVAL '1 second', received_at, TIMESTAMP '1970-01-01 00:00:00') AS window_start, COUNT(*) AS event_count FROM scoped_events GROUP BY window_start ORDER BY window_start",
            QueryTemplate::SubjectSequence { .. } => "SELECT tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, task_cookie, source_cursor, commit_revision, ordinal FROM (SELECT *, lag(operation) OVER subject AS prior_operation, lag(temporal_coverage) OVER subject AS prior_coverage, lag(kernel_sequence) OVER subject AS prior_sequence FROM scoped_events WINDOW subject AS (PARTITION BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, task_cookie ORDER BY source_cursor)) ordered WHERE prior_operation = ? AND operation = ? AND task_cookie <> 0 AND temporal_coverage = 1 AND prior_coverage = 1 AND prior_sequence > 0 AND CAST(kernel_sequence AS HUGEINT) = CAST(prior_sequence AS HUGEINT) + 1 ORDER BY commit_revision, ordinal",
            QueryTemplate::RevisionDifference => "SELECT a.owner_revision AS old_revision, b.owner_revision AS new_revision, a.body <> b.body AS changed FROM context_versions a JOIN context_versions b ON a.tenant_id = b.tenant_id AND a.owner_id = b.owner_id AND a.entity_key = b.entity_key AND a.lifetime_key = b.lifetime_key WHERE a.owner_revision = ? AND b.owner_revision = ? ORDER BY old_revision, new_revision",
            QueryTemplate::Coverage => "SELECT * FROM coverage ORDER BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, kind, first_cursor, last_cursor, commit_revision, interval_id, interval_revision",
            QueryTemplate::ContextVersions => "SELECT * FROM context_versions ORDER BY owner_id, entity_key, lifetime_key, owner_revision",
            QueryTemplate::Catalog => "SELECT * FROM catalog ORDER BY relation, ordinal",
            QueryTemplate::Client(_) => "",
        }
    }

    pub(super) fn sql(&self) -> String {
        if self.reads_events() {
            format!("WITH scoped_events AS (SELECT * FROM events WHERE received_utc_ns >= ? AND received_utc_ns <= ?) {}", self.statement())
        } else {
            self.statement().into()
        }
    }

    pub(super) fn parameters(&self, now_ns: u64) -> Vec<Value> {
        let mut parameters = if self.reads_events() {
            let (first, last) = self.selection(now_ns).time_range().unwrap_or((1, 0));
            vec![Value::UBigInt(first), Value::UBigInt(last)]
        } else {
            Vec::new()
        };
        parameters.extend(match self.template {
            QueryTemplate::Events { operation } => {
                let operation = operation.map_or(Value::Null, Value::UInt);
                vec![operation.clone(), operation]
            }
            QueryTemplate::ExactMatch {
                operation,
                object_id,
            } => vec![Value::UInt(operation), Value::Blob(object_id.to_vec())],
            QueryTemplate::FixedBuckets { seconds } => vec![Value::BigInt(i64::from(seconds))],
            QueryTemplate::SubjectSequence { first, second } => {
                vec![Value::UInt(first), Value::UInt(second)]
            }
            QueryTemplate::RevisionDifference => self
                .base_selection()
                .contexts
                .as_slice()
                .iter()
                .map(|key| Value::UBigInt(key.owner_revision))
                .collect(),
            _ => Vec::new(),
        });
        parameters
    }
}
