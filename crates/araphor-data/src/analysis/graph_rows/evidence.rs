use std::collections::{BTreeMap, BTreeSet};

use duckdb::{params, params_from_iter, types::Value, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, DiscoveryRecordIdV1, GraphInvalidSnafu,
    GraphSnapshotV1, Result, StorePositionV1,
};

pub(in crate::analysis) type GraphInputs = (
    Vec<DiscoveryRecordIdV1>,
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
);

impl GraphRows {
    pub(super) fn insert_inputs(
        graph: &GraphSnapshotV1,
        writer: &Connection,
        result_id: &str,
    ) -> Result<(u64, u64, BTreeMap<(u32, u64), u64>)> {
        let revision: u64 = writer
            .query_row(
                "SELECT commit_revision FROM analysis_results WHERE result_id = ?",
                params![result_id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read graph version revision",
            })?;
        let lineage = if let Some(previous) = &graph.previous_result_id {
            writer
                .query_row(
                    "SELECT lineage_id FROM graph_versions WHERE result_id = ?",
                    params![previous],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read previous graph lineage",
                })?
        } else {
            revision
        };
        writer
            .execute(
                "INSERT INTO graph_versions VALUES (?, ?, ?)",
                params![result_id, lineage, revision],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert graph version",
            })?;
        let key = graph.scope.identity.key();
        let valid: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_receipts
                 WHERE stream_key = ? AND tenant_id = ?)",
                params![key.as_slice(), graph.scope.identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read graph source identity",
            })?;
        if !valid {
            return GraphInvalidSnafu {
                field: "graph evidence source",
            }
            .fail();
        }
        let source_ref = match writer
            .query_row(
                "SELECT source_ref, tenant_id FROM graph_sources WHERE stream_key = ?",
                params![key.as_slice()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read graph source reference",
            })? {
            Some((id, tenant))
                if tenant.as_slice() == graph.scope.identity.tenant_id.as_slice() =>
            {
                id
            }
            Some(_) => {
                return GraphInvalidSnafu {
                    field: "graph evidence source",
                }
                .fail();
            }
            None => {
                let next: u64 = writer
                    .query_row(
                        "SELECT coalesce(max(source_ref), 0) FROM graph_sources",
                        [],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read next graph source reference",
                    })?;
                let id = next.checked_add(1).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph source reference",
                    }
                    .build()
                })?;
                writer
                    .execute(
                        "INSERT INTO graph_sources VALUES (?, ?, ?)",
                        params![
                            id,
                            key.as_slice(),
                            graph.scope.identity.tenant_id.as_slice()
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "insert graph source reference",
                    })?;
                id
            }
        };
        let mut existing = BTreeMap::new();
        for selected in graph
            .input_manifest
            .evidence
            .chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
        {
            let placeholders = std::iter::repeat_n("(?, ?)", selected.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut parameters = Vec::with_capacity(1 + selected.len() * 2);
            parameters.push(Value::UBigInt(source_ref));
            for record in selected {
                parameters.push(Value::UInt(record.cpu_id));
                parameters.push(Value::UBigInt(record.durable_cursor));
            }
            let mut statement = writer
                .prepare(&format!(
                    "SELECT evidence_id, cpu_id, durable_cursor FROM graph_evidence
                     WHERE source_ref = ? AND (cpu_id, durable_cursor) IN ({placeholders})"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare shared graph evidence",
                })?;
            let mut rows = statement
                .query(params_from_iter(parameters.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read shared graph evidence",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance shared graph evidence",
            })? {
                let id: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode shared graph evidence ID",
                })?;
                let cpu: u32 = row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode shared graph evidence CPU",
                })?;
                let cursor: u64 = row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode shared graph evidence cursor",
                })?;
                if existing.insert((cpu, cursor), id).is_some() {
                    return GraphInvalidSnafu {
                        field: "graph evidence identity",
                    }
                    .fail();
                }
            }
        }
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(evidence_id), 0) FROM graph_evidence",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read next graph evidence ID",
            })?;
        let mut evidence = Vec::new();
        evidence
            .try_reserve_exact(graph.input_manifest.evidence.len())
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
        {
            let mut appender =
                writer
                    .appender("graph_evidence")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare shared graph evidence insert",
                    })?;
            for record in &graph.input_manifest.evidence {
                if record.stream != graph.scope.identity {
                    return GraphInvalidSnafu {
                        field: "graph evidence source",
                    }
                    .fail();
                }
                let id = if let Some(id) = existing.get(&(record.cpu_id, record.durable_cursor)) {
                    *id
                } else {
                    next = next.checked_add(1).ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph evidence ID",
                        }
                        .build()
                    })?;
                    appender
                        .append_row(params![
                            next,
                            source_ref,
                            record.cpu_id,
                            record.durable_cursor
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "insert shared graph evidence",
                        })?;
                    existing.insert((record.cpu_id, record.durable_cursor), next);
                    next
                };
                evidence.push(id);
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush shared graph evidence",
            })?;
        }
        let current = evidence.iter().copied().collect::<BTreeSet<_>>();
        let mut previous = BTreeSet::new();
        let mut statement = writer
            .prepare(
                "SELECT evidence_id FROM graph_evidence_membership
                 WHERE lineage_id = ? AND valid_to IS NULL",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare active graph evidence",
            })?;
        let mut rows = statement
            .query(params![lineage])
            .context(AnalysisDatabaseSnafu {
                operation: "read active graph evidence",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance active graph evidence",
        })? {
            let id: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode active graph evidence",
            })?;
            if !previous.insert(id) {
                return GraphInvalidSnafu {
                    field: "graph evidence membership",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for id in previous.difference(&current) {
            let changed = writer
                .execute(
                    "UPDATE graph_evidence_membership SET valid_to = ?
                     WHERE lineage_id = ? AND evidence_id = ? AND valid_to IS NULL",
                    params![revision, lineage, id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "close graph evidence membership",
                })?;
            if changed != 1 {
                return GraphInvalidSnafu {
                    field: "graph evidence membership",
                }
                .fail();
            }
        }
        {
            let mut appender =
                writer
                    .appender("graph_evidence_membership")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare graph evidence membership insert",
                    })?;
            for id in current.difference(&previous) {
                appender
                    .append_row(params![lineage, id, revision, None::<u64>])
                    .context(AnalysisDatabaseSnafu {
                        operation: "insert graph evidence membership",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush graph evidence membership",
            })?;
        }
        let mut active = BTreeMap::new();
        let mut statement = writer
            .prepare(
                "SELECT rank, evidence_id, commit_revision, ordinal
                 FROM graph_input_positions WHERE lineage_id = ? AND valid_to IS NULL",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare active graph positions",
            })?;
        let mut rows = statement
            .query(params![lineage])
            .context(AnalysisDatabaseSnafu {
                operation: "read active graph positions",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance active graph positions",
        })? {
            let rank: u32 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode active graph position rank",
            })?;
            let value = (
                row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode active graph position evidence",
                })?,
                row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode active graph position revision",
                })?,
                row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "decode active graph position ordinal",
                })?,
            );
            if active.insert(rank, value).is_some() {
                return GraphInvalidSnafu {
                    field: "graph position membership",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        let mut selected = BTreeMap::new();
        for (rank, (record, position)) in graph.input_positions.iter().enumerate() {
            let id = *existing
                .get(&(record.cpu_id, record.durable_cursor))
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph input position",
                    }
                    .build()
                })?;
            if !current.contains(&id) || record.stream != graph.scope.identity {
                return GraphInvalidSnafu {
                    field: "graph input position",
                }
                .fail();
            }
            selected.insert(
                u32::try_from(rank).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph input position",
                    }
                    .build()
                })?,
                (id, position.commit_revision, position.ordinal),
            );
        }
        for (rank, value) in &active {
            if selected.get(rank) != Some(value) {
                let changed = writer
                    .execute(
                        "UPDATE graph_input_positions SET valid_to = ?
                         WHERE lineage_id = ? AND rank = ? AND valid_to IS NULL",
                        params![revision, lineage, rank],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "close graph input position",
                    })?;
                if changed != 1 {
                    return GraphInvalidSnafu {
                        field: "graph position membership",
                    }
                    .fail();
                }
            }
        }
        {
            let mut appender =
                writer
                    .appender("graph_input_positions")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare graph input position insert",
                    })?;
            for (rank, value) in &selected {
                if active.get(rank) != Some(value) {
                    appender
                        .append_row(params![
                            lineage,
                            value.0,
                            rank,
                            value.1,
                            value.2,
                            revision,
                            None::<u64>
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "insert graph input position",
                        })?;
                }
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush graph input positions",
            })?;
        }
        Ok((lineage, revision, existing))
    }

    pub(in crate::analysis) fn load_inputs(
        reader: &Connection,
        result_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<GraphInputs> {
        if let Some(control) = control {
            control.check()?;
        }
        let (lineage, revision, committed, key, tenant, method, first): (
            u64,
            u64,
            u64,
            Vec<u8>,
            Vec<u8>,
            u64,
            u64,
        ) = reader
            .query_row(
                "SELECT v.lineage_id, v.commit_revision, r.commit_revision,
                    r.stream_key, r.tenant_id, r.method_version, r.first_cursor
                 FROM graph_versions v JOIN analysis_results r USING (result_id)
                 WHERE v.result_id = ?",
                params![result_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph version",
            })?;
        header.check_index(
            tenant.as_slice().try_into().map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph version identity",
                }
                .build()
            })?,
            &key,
            method,
            first,
        )?;
        if revision != committed || lineage > revision {
            return GraphInvalidSnafu {
                field: "graph version identity",
            }
            .fail();
        }
        let origin: Option<(Vec<u8>, Vec<u8>, u64, u64)> = reader
            .query_row(
                "SELECT r.tenant_id, r.stream_key, r.method_version, r.first_cursor
                 FROM graph_versions v JOIN analysis_results r USING (result_id)
                 WHERE v.lineage_id = ? AND v.commit_revision = ?",
                params![lineage, lineage],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph lineage",
            })?;
        if origin != Some((tenant.clone(), key.clone(), method, first)) {
            return GraphInvalidSnafu {
                field: "graph version lineage",
            }
            .fail();
        }
        let (evidence_count, position_count): (u64, u64) = reader
            .query_row(
                "SELECT (SELECT count(*)::UBIGINT FROM graph_evidence_membership
                    WHERE lineage_id = ? AND valid_from <= ?
                        AND (valid_to IS NULL OR valid_to > ?)),
                    (SELECT count(*)::UBIGINT FROM graph_input_positions
                    WHERE lineage_id = ? AND valid_from <= ?
                        AND (valid_to IS NULL OR valid_to > ?))",
                params![lineage, revision, revision, lineage, revision, revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count native graph inputs",
            })?;
        if evidence_count != header.evidence_count as u64
            || position_count != header.position_count as u64
        {
            return GraphInvalidSnafu {
                field: "graph input counts",
            }
            .fail();
        }
        let source = &header.snapshot.scope.identity;
        if let Some(control) = control {
            control.check()?;
        }
        let receipt: bool = reader
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_receipts
                 WHERE stream_key = ? AND tenant_id = ?)",
                params![key.as_slice(), source.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read retained graph source",
            })?;
        if !receipt {
            return GraphInvalidSnafu {
                field: "graph evidence source",
            }
            .fail();
        }
        let mut evidence = Vec::new();
        if let Some(control) = control {
            control.check()?;
        }
        evidence
            .try_reserve_exact(header.evidence_count)
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
        let mut statement = reader
            .prepare(
                "SELECT e.cpu_id, e.durable_cursor
                 FROM graph_evidence_membership m JOIN graph_evidence e USING (evidence_id)
                 JOIN graph_sources s USING (source_ref)
                 WHERE m.lineage_id = ? AND m.valid_from <= ?
                    AND (m.valid_to IS NULL OR m.valid_to > ?)
                    AND s.stream_key = ? AND s.tenant_id = ?
                 ORDER BY e.cpu_id, e.durable_cursor",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native graph evidence read",
            })?;
        let mut rows = statement
            .query(params![
                lineage,
                revision,
                revision,
                key.as_slice(),
                tenant.as_slice()
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph evidence",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native graph evidence",
        })? {
            if let Some(control) = control {
                control.check()?;
            }
            evidence.push(DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph evidence CPU",
                })?,
                durable_cursor: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph evidence cursor",
                })?,
            });
        }
        drop(rows);
        drop(statement);
        if evidence.len() != header.evidence_count
            || evidence.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return GraphInvalidSnafu {
                field: "graph evidence membership",
            }
            .fail();
        }
        let mut positions = Vec::new();
        if let Some(control) = control {
            control.check()?;
        }
        positions
            .try_reserve_exact(header.position_count)
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
        let mut statement = reader
            .prepare(
                "SELECT p.rank, e.cpu_id, e.durable_cursor,
                    p.commit_revision, p.ordinal
                 FROM graph_input_positions p JOIN graph_evidence e USING (evidence_id)
                 JOIN graph_sources s USING (source_ref)
                 WHERE p.lineage_id = ? AND p.valid_from <= ?
                    AND (p.valid_to IS NULL OR p.valid_to > ?)
                    AND s.stream_key = ? AND s.tenant_id = ?
                 ORDER BY p.rank",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native graph positions read",
            })?;
        let mut rows = statement
            .query(params![
                lineage,
                revision,
                revision,
                key.as_slice(),
                tenant.as_slice()
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph positions",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native graph positions",
        })? {
            if let Some(control) = control {
                control.check()?;
            }
            let rank: u32 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode native graph position rank",
            })?;
            if rank as usize != positions.len() {
                return GraphInvalidSnafu {
                    field: "graph position membership",
                }
                .fail();
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph position CPU",
                })?,
                durable_cursor: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode native graph position cursor",
                })?,
            };
            if evidence.binary_search(&record).is_err() {
                return GraphInvalidSnafu {
                    field: "graph position evidence",
                }
                .fail();
            }
            positions.push((
                record,
                StorePositionV1 {
                    commit_revision: row.get(3).context(AnalysisDatabaseSnafu {
                        operation: "decode native graph position revision",
                    })?,
                    ordinal: row.get(4).context(AnalysisDatabaseSnafu {
                        operation: "decode native graph position ordinal",
                    })?,
                },
            ));
        }
        if positions.len() != header.position_count {
            return GraphInvalidSnafu {
                field: "graph position membership",
            }
            .fail();
        }
        Ok((evidence, positions))
    }
}
