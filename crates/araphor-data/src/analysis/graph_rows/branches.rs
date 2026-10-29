use std::collections::BTreeMap;
use std::io::Cursor;

use duckdb::{params, Connection};
use serde::{Deserialize as _, Serialize as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, GraphBranchV1, GraphInvalidSnafu, Result};

impl GraphRows {
    pub(in crate::analysis) fn validate_branches(writer: &Connection) -> Result<()> {
        let invalid: bool = writer
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM graph_branch_values b
                    WHERE octet_length(b.tenant_id) <> 16
                        OR octet_length(b.value_hash) <> 32
                        OR octet_length(b.body) = 0
                    UNION ALL
                    SELECT 1 FROM graph_branch_values
                    GROUP BY tenant_id, value_hash, body HAVING count(*) > 1
                    UNION ALL
                    SELECT 1 FROM graph_branch_membership m
                    LEFT JOIN graph_branch_values b USING (branch_id)
                    LEFT JOIN graph_versions origin ON origin.lineage_id = m.lineage_id
                        AND origin.commit_revision = m.lineage_id
                    LEFT JOIN analysis_results r ON r.result_id = origin.result_id
                    LEFT JOIN graph_versions opened ON opened.lineage_id = m.lineage_id
                        AND opened.commit_revision = m.valid_from
                    LEFT JOIN graph_versions closed ON closed.lineage_id = m.lineage_id
                        AND closed.commit_revision = m.valid_to
                    WHERE b.branch_id IS NULL OR origin.result_id IS NULL
                        OR r.tenant_id <> b.tenant_id OR opened.result_id IS NULL
                        OR (m.valid_to IS NOT NULL AND closed.result_id IS NULL)
                        OR (m.valid_to IS NOT NULL AND m.valid_to <= m.valid_from)
                    UNION ALL
                    SELECT 1 FROM (
                        SELECT m.lineage_id, m.ordinal, m.valid_from,
                            lag(m.valid_from) OVER (
                                PARTITION BY m.lineage_id, m.ordinal
                                ORDER BY m.valid_from) AS prior_from,
                            lag(m.valid_to) OVER (
                                PARTITION BY m.lineage_id, m.ordinal
                                ORDER BY m.valid_from) AS prior_to
                        FROM graph_branch_membership m
                    ) ranges WHERE prior_from IS NOT NULL
                        AND (prior_to IS NULL OR prior_to > valid_from)
                )",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate graph branch rows",
            })?;
        if invalid {
            return GraphInvalidSnafu {
                field: "graph branch rows",
            }
            .fail();
        }
        let mut statement = writer
            .prepare("SELECT value_hash, body FROM graph_branch_values")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare graph branch value validation",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read graph branch values for validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance graph branch values for validation",
        })? {
            let hash: Vec<u8> = Self::column(row, 0)?;
            let body: Vec<u8> = Self::column(row, 1)?;
            if hash.as_slice() != Sha256::digest(&body).as_slice() {
                return GraphInvalidSnafu {
                    field: "graph branch value hash",
                }
                .fail();
            }
            Self::decode_branch(&body)?;
        }
        Ok(())
    }

    pub(super) fn insert_branches(
        writer: &Connection,
        tenant: [u8; 16],
        lineage: u64,
        revision: u64,
        branches: &[GraphBranchV1],
    ) -> Result<()> {
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(branch_id), 0) FROM graph_branch_values",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read next graph branch ID",
            })?;
        let mut candidates = writer
            .prepare(
                "SELECT branch_id, body FROM graph_branch_values
                 WHERE tenant_id = ? AND value_hash = ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare shared graph branches",
            })?;
        let mut selected = Vec::with_capacity(branches.len());
        let mut added = BTreeMap::<Vec<u8>, u64>::new();
        for branch in branches {
            let body = Self::encode_branch(branch)?;
            if let Some(id) = added.get(&body) {
                selected.push(*id);
                continue;
            }
            let hash = Sha256::digest(&body);
            let mut rows = candidates
                .query(params![tenant.as_slice(), hash.as_slice()])
                .context(AnalysisDatabaseSnafu {
                    operation: "read shared graph branches",
                })?;
            let mut matched = None;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance shared graph branches",
            })? {
                let id: u64 = Self::column(row, 0)?;
                let stored: Vec<u8> = Self::column(row, 1)?;
                if Self::decode_branch(&stored)? == *branch {
                    if matched.replace(id).is_some() {
                        return GraphInvalidSnafu {
                            field: "duplicate graph branch value",
                        }
                        .fail();
                    }
                }
            }
            let id = match matched {
                Some(id) => id,
                None => {
                    next = next.checked_add(1).ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph branch ID",
                        }
                        .build()
                    })?;
                    added.insert(body, next);
                    next
                }
            };
            selected.push(id);
        }
        drop(candidates);
        if !added.is_empty() {
            let mut appender =
                writer
                    .appender("graph_branch_values")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare shared graph branch insert",
                    })?;
            for (body, id) in &added {
                let hash = Sha256::digest(body);
                appender
                    .append_row(params![id, tenant.as_slice(), hash.as_slice(), body])
                    .context(AnalysisDatabaseSnafu {
                        operation: "insert shared graph branch",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush shared graph branches",
            })?;
        }

        let mut active = BTreeMap::new();
        let mut statement = writer
            .prepare(
                "SELECT ordinal, branch_id FROM graph_branch_membership
                 WHERE lineage_id = ? AND valid_to IS NULL ORDER BY ordinal",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare active graph branches",
            })?;
        let mut rows = statement
            .query(params![lineage])
            .context(AnalysisDatabaseSnafu {
                operation: "read active graph branches",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance active graph branches",
        })? {
            let ordinal: u32 = Self::column(row, 0)?;
            let id: u64 = Self::column(row, 1)?;
            if ordinal as usize != active.len() || active.insert(ordinal, id).is_some() {
                return GraphInvalidSnafu {
                    field: "graph branch membership",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for (ordinal, id) in &active {
            if selected.get(*ordinal as usize) == Some(id) {
                continue;
            }
            let changed = writer
                .execute(
                    "UPDATE graph_branch_membership SET valid_to = ?
                     WHERE lineage_id = ? AND ordinal = ? AND valid_to IS NULL",
                    params![revision, lineage, ordinal],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "close graph branch membership",
                })?;
            if changed != 1 {
                return GraphInvalidSnafu {
                    field: "graph branch membership",
                }
                .fail();
            }
        }
        let mut appender =
            writer
                .appender("graph_branch_membership")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare graph branch membership insert",
                })?;
        for (ordinal, id) in selected.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph branch ordinal",
                }
                .build()
            })?;
            if active.get(&ordinal) == Some(id) {
                continue;
            }
            appender
                .append_row(params![lineage, ordinal, id, revision, None::<u64>])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert graph branch membership",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush graph branch membership",
        })?;
        Ok(())
    }

    pub(super) fn read_branches(
        writer: &Connection,
        result_id: &str,
        tenant: [u8; 16],
        expected_count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphBranchV1>> {
        let mut statement = writer
            .prepare(
                "SELECT m.ordinal, m.branch_id, b.tenant_id, b.value_hash, b.body
                 FROM graph_versions v
                 LEFT JOIN graph_branch_membership m ON m.lineage_id = v.lineage_id
                     AND m.valid_from <= v.commit_revision
                     AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                 LEFT JOIN graph_branch_values b USING (branch_id)
                 WHERE v.result_id = ? ORDER BY m.ordinal, m.valid_from",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare historical graph branches",
            })?;
        let mut rows = statement
            .query(params![result_id])
            .context(AnalysisDatabaseSnafu {
                operation: "read historical graph branches",
            })?;
        let mut values = Vec::new();
        let mut version_found = false;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance historical graph branches",
        })? {
            if let Some(control) = control {
                control.check()?;
            }
            version_found = true;
            let ordinal: Option<u32> = Self::column(row, 0)?;
            let Some(ordinal) = ordinal else {
                if expected_count != 0 || !values.is_empty() {
                    return GraphInvalidSnafu {
                        field: "graph branch row count",
                    }
                    .fail();
                }
                continue;
            };
            let id: Option<u64> = Self::column(row, 1)?;
            let stored_tenant: Option<Vec<u8>> = Self::column(row, 2)?;
            let hash: Option<Vec<u8>> = Self::column(row, 3)?;
            let body: Option<Vec<u8>> = Self::column(row, 4)?;
            let (Some(_), Some(stored_tenant), Some(hash), Some(body)) =
                (id, stored_tenant, hash, body)
            else {
                return GraphInvalidSnafu {
                    field: "graph branch value reference",
                }
                .fail();
            };
            if ordinal as usize != values.len()
                || values.len() >= expected_count
                || stored_tenant.as_slice() != tenant.as_slice()
                || hash.as_slice() != Sha256::digest(&body).as_slice()
            {
                return GraphInvalidSnafu {
                    field: "graph branch value",
                }
                .fail();
            }
            values.push(Self::decode_branch(&body)?);
        }
        if !version_found || values.len() != expected_count {
            return GraphInvalidSnafu {
                field: "graph branch row count",
            }
            .fail();
        }
        Ok(values)
    }

    fn encode_branch(branch: &GraphBranchV1) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        branch
            .serialize(
                &mut rmp_serde::Serializer::new(&mut bytes)
                    .with_struct_map()
                    .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
            )
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph branch encoding",
                }
                .build()
            })?;
        Ok(bytes)
    }

    fn decode_branch(bytes: &[u8]) -> Result<GraphBranchV1> {
        let mut decoder = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let value = GraphBranchV1::deserialize(&mut decoder).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph branch encoding",
            }
            .build()
        })?;
        if decoder.position() != bytes.len() as u64 {
            return GraphInvalidSnafu {
                field: "graph branch trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }
}
