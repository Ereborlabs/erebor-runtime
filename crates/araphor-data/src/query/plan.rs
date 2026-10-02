use std::ops::Bound;

use duckdb::types::Value;
use sha2::{Digest as _, Sha256};
use snafu::IntoError as _;

use crate::{AnalysisSelectionV1, Result};

pub const QUERY_SCHEMA_VERSION: u32 = 1;

/// Code-owned queries. This type has no SQL-string or deserialization entry point.
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum QueryOperation {
    Append,
    Replace,
}

#[derive(Clone, Debug)]
pub struct QueryPlan {
    pub(super) selection: AnalysisSelectionV1,
    pub(super) template: QueryTemplate,
}

impl QueryPlan {
    pub fn new(selection: AnalysisSelectionV1, template: QueryTemplate) -> Result<Self> {
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
                if selection.contexts.len() != 2 {
                    return crate::QueryInvalidSnafu {
                        field: "context pair",
                    }
                    .fail();
                }
                let left = &selection.contexts[0];
                let right = &selection.contexts[1];
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
            selection,
            template,
        })
    }

    pub fn operation(&self) -> QueryOperation {
        match self.template {
            QueryTemplate::Events { .. } | QueryTemplate::ExactMatch { .. } => {
                QueryOperation::Append
            }
            _ => QueryOperation::Replace,
        }
    }

    pub fn template(&self) -> &QueryTemplate {
        &self.template
    }

    pub(super) fn reads_events(&self) -> bool {
        !matches!(
            self.template,
            QueryTemplate::Coverage
                | QueryTemplate::ContextVersions
                | QueryTemplate::RevisionDifference
                | QueryTemplate::Catalog
        )
    }

    pub(super) fn dependencies(&self, now_ns: u64) -> AnalysisSelectionV1 {
        let mut selection = self.selection(now_ns);
        match self.template {
            QueryTemplate::Catalog => {
                selection.sources.clear();
                selection.contexts.clear();
            }
            QueryTemplate::ContextVersions | QueryTemplate::RevisionDifference => {
                selection.sources.clear()
            }
            QueryTemplate::Coverage => {
                selection.contexts.clear();
                selection.received_from = Bound::Unbounded;
                selection.received_until = Bound::Unbounded;
            }
            _ => {}
        }
        selection
    }

    pub(super) fn selection(&self, now_ns: u64) -> AnalysisSelectionV1 {
        let mut selection = self.selection.clone();
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
                .selection
                .contexts
                .iter()
                .map(|key| Value::UBigInt(key.owner_revision))
                .collect(),
            _ => Vec::new(),
        });
        parameters
    }

    pub(super) fn binding(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-INTERNAL-QUERY-V1\0");
        hash.update(QUERY_SCHEMA_VERSION.to_be_bytes());
        hash.update(self.sql().as_bytes());
        hash.update(self.selection.tenant_id);
        for source in &self.selection.sources {
            let bytes = serde_json::to_vec(source)
                .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        for key in &self.selection.contexts {
            let bytes = serde_json::to_vec(key)
                .map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        for bound in [
            &self.selection.received_from,
            &self.selection.received_until,
        ] {
            let (tag, value) = match bound {
                Bound::Unbounded => (0, 0),
                Bound::Included(value) => (1, *value),
                Bound::Excluded(value) => (2, *value),
            };
            hash.update([tag]);
            hash.update(value.to_be_bytes());
        }
        // These parameters contain only integers, null, or an exact object ID.
        for value in self.parameters(0) {
            match value {
                Value::Null => hash.update([0]),
                Value::UInt(value) => {
                    hash.update([1]);
                    hash.update(value.to_be_bytes());
                }
                Value::UBigInt(value) => {
                    hash.update([2]);
                    hash.update(value.to_be_bytes());
                }
                Value::BigInt(value) => {
                    hash.update([3]);
                    hash.update(value.to_be_bytes());
                }
                Value::Blob(value) => {
                    hash.update([4]);
                    hash.update((value.len() as u64).to_be_bytes());
                    hash.update(value);
                }
                _ => {
                    return crate::QueryInvalidSnafu {
                        field: "template parameters",
                    }
                    .fail()
                }
            }
        }
        if let QueryTemplate::MovingCount { seconds } = self.template {
            hash.update(seconds.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }
}
