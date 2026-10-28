use std::collections::BTreeSet;

use araphor_analysis_builtins::graph::{ContextSensitivityV1, FindingReasonV1, FindingV1};
use araphor_analysis_sdk as sdk;
use duckdb::{params, Appender, Connection, Row};
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;

use crate::error::{ContractSnafu, DatabaseSnafu, EncodingSnafu, InvalidSnafu};
use crate::Result;

#[cfg(test)]
mod tests;

pub struct FindingRows;

impl FindingRows {
    pub const SCHEMA: &'static str = include_str!("findings.sql");
    pub const COLUMNS: &'static str = "ordinal, tenant_id, finding_id, package_id, package_version,
        subject_id, state, window_start_utc_ns, window_end_utc_ns, evidence,
        required_coverage_interval_ids, policy_provenance, effects, reason, severity,
        sensitivity, required_action, limits";

    pub fn validate(writer: &Connection) -> Result<()> {
        let overlaps: bool = writer
            .query_row(
                "WITH ranges AS (
                    SELECT m.lineage_id, f.tenant_id, f.finding_id,
                        m.valid_from, m.valid_to,
                        lag(m.valid_from) OVER part AS prior_from,
                        lag(m.valid_to) OVER part AS prior_to
                    FROM graph_finding_membership m
                    JOIN graph_finding_values f USING (value_id)
                    WINDOW part AS (PARTITION BY m.lineage_id, f.tenant_id, f.finding_id
                        ORDER BY m.valid_from, m.value_id)
                ) SELECT EXISTS(SELECT 1 FROM ranges WHERE prior_from IS NOT NULL
                    AND (prior_to IS NULL OR prior_to > valid_from))",
                [],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "validate graph finding membership",
            })?;
        if overlaps {
            return InvalidSnafu {
                field: "overlapping graph finding membership",
            }
            .fail();
        }
        Ok(())
    }

    pub fn apply(
        writer: &Connection,
        tenant: [u8; 16],
        lineage: u64,
        revision: u64,
        findings: &[FindingV1],
    ) -> Result<()> {
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(value_id), 0) FROM graph_finding_values",
                [],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "read next graph finding value ID",
            })?;
        let mut selected = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut added = Vec::new();
        let mut candidates = writer
            .prepare(
                "SELECT value_id, tenant_id, finding_id, package_id, package_version,
                subject_id, state, window_start_utc_ns, window_end_utc_ns, evidence,
                required_coverage_interval_ids, policy_provenance, effects, reason, severity,
                sensitivity, required_action, limits
                FROM graph_finding_values WHERE tenant_id = ? AND finding_id = ?",
            )
            .context(DatabaseSnafu {
                operation: "prepare graph finding value lookup",
            })?;
        for finding in findings {
            if finding.tenant_id != tenant || !names.insert(finding.finding_id.as_str()) {
                return InvalidSnafu {
                    field: "graph finding identity",
                }
                .fail();
            }
            let mut rows = candidates
                .query(params![tenant.as_slice(), &finding.finding_id])
                .context(DatabaseSnafu {
                    operation: "read graph finding values",
                })?;
            let mut value_id = None;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance graph finding values",
            })? {
                if Self::decode(row)? == *finding {
                    if value_id.is_some() {
                        return InvalidSnafu {
                            field: "duplicate graph finding value",
                        }
                        .fail();
                    }
                    value_id = Some(Self::column(row, 0)?);
                }
            }
            let id = match value_id {
                Some(id) => id,
                None => {
                    next = next.checked_add(1).ok_or_else(|| {
                        InvalidSnafu {
                            field: "graph finding value ID",
                        }
                        .build()
                    })?;
                    added.push((next, finding));
                    next
                }
            };
            if !selected.insert(id) {
                return InvalidSnafu {
                    field: "graph finding membership",
                }
                .fail();
            }
        }
        drop(candidates);
        if !added.is_empty() {
            let mut appender = writer
                .appender("graph_finding_values")
                .context(DatabaseSnafu {
                    operation: "prepare graph finding value insert",
                })?;
            for (id, finding) in added {
                Self::insert(&mut appender, id, finding)?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush graph finding values",
            })?;
        }
        let mut active = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut statement = writer
            .prepare(
                "SELECT m.value_id, f.tenant_id, f.finding_id
                FROM graph_finding_membership m
                LEFT JOIN graph_finding_values f USING (value_id)
                WHERE m.lineage_id = ? AND m.valid_to IS NULL",
            )
            .context(DatabaseSnafu {
                operation: "prepare active graph findings",
            })?;
        let mut rows = statement.query(params![lineage]).context(DatabaseSnafu {
            operation: "read active graph findings",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance active graph findings",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let stored: Option<Vec<u8>> = Self::column(row, 1)?;
            let name: Option<String> = Self::column(row, 2)?;
            if stored.as_deref() != Some(tenant.as_slice())
                || name
                    .as_ref()
                    .is_none_or(|name| !identities.insert(name.clone()))
                || !active.insert(id)
            {
                return InvalidSnafu {
                    field: "active graph finding identity",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for id in active.difference(&selected) {
            let changed = writer
                .execute(
                    "UPDATE graph_finding_membership SET valid_to = ?
                    WHERE lineage_id = ? AND value_id = ? AND valid_to IS NULL",
                    params![revision, lineage, id],
                )
                .context(DatabaseSnafu {
                    operation: "close graph finding membership",
                })?;
            if changed != 1 {
                return InvalidSnafu {
                    field: "graph finding membership",
                }
                .fail();
            }
        }
        let mut appender = writer
            .appender("graph_finding_membership")
            .context(DatabaseSnafu {
                operation: "prepare graph finding membership insert",
            })?;
        for id in selected.difference(&active) {
            appender
                .append_row(params![lineage, id, revision, None::<u64>])
                .context(DatabaseSnafu {
                    operation: "insert graph finding membership",
                })?;
        }
        appender.flush().context(DatabaseSnafu {
            operation: "flush graph finding membership",
        })?;
        Ok(())
    }

    fn insert(writer: &mut Appender<'_>, id: u64, finding: &FindingV1) -> Result<()> {
        writer
            .append_row(params![
                id,
                finding.tenant_id.as_slice(),
                &finding.finding_id,
                &finding.package_id,
                finding.package_version,
                Self::json(&finding.subject_id)?,
                Self::scalar_label(&finding.state)?,
                finding.window_start_utc_ns,
                finding.window_end_utc_ns,
                Self::json(&finding.evidence)?,
                Self::json(&finding.required_coverage_interval_ids)?,
                Self::json(&finding.policy_provenance)?,
                Self::json(&finding.effects)?,
                Self::reason(&finding.reason)?,
                Self::scalar_label(&finding.severity)?,
                <&str>::from(finding.sensitivity),
                &finding.required_action,
                Self::json(&finding.limits)?
            ])
            .context(DatabaseSnafu {
                operation: "insert graph finding value",
            })?;
        Ok(())
    }

    pub fn decode(row: &Row<'_>) -> Result<FindingV1> {
        let tenant: Vec<u8> = Self::column(row, 1)?;
        let sensitivity: String = Self::column(row, 15)?;
        Ok(FindingV1 {
            tenant_id: tenant.try_into().map_err(|_| {
                InvalidSnafu {
                    field: "finding tenant bytes",
                }
                .build()
            })?,
            finding_id: Self::column(row, 2)?,
            package_id: Self::column(row, 3)?,
            package_version: Self::column(row, 4)?,
            subject_id: Self::json_column(row, 5)?,
            state: Self::label_column(row, 6)?,
            window_start_utc_ns: Self::column(row, 7)?,
            window_end_utc_ns: Self::column(row, 8)?,
            evidence: Self::json_column(row, 9)?,
            required_coverage_interval_ids: Self::json_column(row, 10)?,
            policy_provenance: Self::json_column(row, 11)?,
            effects: Self::json_column(row, 12)?,
            reason: Self::restore_reason(&Self::column::<String>(row, 13)?)?,
            severity: Self::label_column(row, 14)?,
            sensitivity: ContextSensitivityV1::try_from(sensitivity.as_str()).map_err(|_| {
                InvalidSnafu {
                    field: "finding sensitivity",
                }
                .build()
            })?,
            required_action: Self::column(row, 16)?,
            limits: Self::json_column(row, 17)?,
        })
    }

    pub fn reason_label(reason: &FindingReasonV1) -> Result<String> {
        match reason.label() {
            Ok(value) => Ok(value),
            Err(sdk::Error::Encoding { source, .. }) => Err(source).context(EncodingSnafu),
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Invalid,
                field,
                ..
            }) if field == "finding reason label" => InvalidSnafu {
                field: "finding reason label",
            }
            .fail(),
            Err(source) => Err(source).context(ContractSnafu),
        }
    }

    fn reason(reason: &FindingReasonV1) -> Result<String> {
        match reason {
            FindingReasonV1::Declared(_) => serde_json::to_string(reason).context(EncodingSnafu),
            _ => Self::reason_label(reason),
        }
    }

    fn restore_reason(value: &str) -> Result<FindingReasonV1> {
        if value.starts_with('{') {
            serde_json::from_str(value).context(EncodingSnafu)
        } else {
            serde_json::from_value(serde_json::Value::String(value.into())).context(EncodingSnafu)
        }
    }

    fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(DatabaseSnafu {
            operation: "decode graph finding columns",
        })
    }

    fn json(value: &impl Serialize) -> Result<Vec<u8>> {
        serde_json::to_vec(value).context(EncodingSnafu)
    }

    fn json_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        let value = row.get_ref(index).context(DatabaseSnafu {
            operation: "decode graph finding columns",
        })?;
        let bytes = value
            .as_blob()
            .map_err(|source| {
                duckdb::Error::FromSqlConversionFailure(index, value.data_type(), Box::new(source))
            })
            .context(DatabaseSnafu {
                operation: "decode graph finding columns",
            })?;
        serde_json::from_slice(bytes).context(EncodingSnafu)
    }

    fn scalar_label(value: &impl Serialize) -> Result<String> {
        match serde_json::to_value(value).context(EncodingSnafu)? {
            serde_json::Value::String(value) => Ok(value),
            _ => InvalidSnafu {
                field: "graph scalar label",
            }
            .fail(),
        }
    }

    fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        let label: String = Self::column(row, index)?;
        serde_json::from_value(serde_json::Value::String(label)).context(EncodingSnafu)
    }
}
