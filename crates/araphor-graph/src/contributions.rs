use std::{collections::BTreeSet, sync::Arc};

use araphor_analysis_sdk::{
    arrow_array::{
        builder::{
            LargeBinaryBuilder, LargeStringBuilder, UInt32Builder, UInt64Builder, UInt8Builder,
        },
        ArrayRef, RecordBatch,
    },
    arrow_schema::{Field, Schema},
};
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::{
    error::{DatabaseSnafu, InvalidSnafu},
    Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub kind: u8,
    pub key: Vec<u8>,
    pub value: u64,
    pub record: Option<u64>,
    pub fact: Option<Vec<u8>>,
    pub reason: Option<String>,
    pub ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replacement {
    pub unit: Option<u64>,
    pub members: Vec<Member>,
}

pub struct Contributions;

struct Frontier {
    source: u64,
    kind: u8,
    counts: [u64; 4],
}

impl Contributions {
    /// Apply one contribution batch in the caller's transaction.
    /// Data must call this method once for each scope and version.
    /// The current version must exist and name the immediate previous version.
    pub fn apply(
        writer: &Connection,
        scope: u64,
        revision: u64,
        replacements: &[Replacement],
        reset: bool,
    ) -> Result<()> {
        Self::check_requests(replacements)?;
        let mut frontier = Self::frontier(writer, scope, revision)?;
        if frontier.kind != 0 && replacements.iter().any(|item| item.unit.is_some()) {
            return InvalidSnafu {
                field: "contribution publication unit",
            }
            .fail();
        }
        for member in replacements.iter().flat_map(|item| &item.members) {
            let allowed = match frontier.kind {
                0 => (2..=5).contains(&member.kind) && member.record.is_some(),
                1 => matches!(member.kind, 2..=4 | 6),
                2 => matches!(member.kind, 0..=1 | 7),
                _ => false,
            };
            if !allowed {
                return InvalidSnafu {
                    field: "contribution producer member",
                }
                .fail();
            }
        }
        writer
            .execute_batch(
                "CREATE TEMP TABLE graph_contribution_stage (
                    unit_ref UBIGINT NOT NULL, member_kind UTINYINT, member_key BLOB,
                    value_ref UBIGINT, anchor_record_id UBIGINT, anchor_fact BLOB,
                    reason_code VARCHAR, ordinal UINTEGER)",
            )
            .context(DatabaseSnafu {
                operation: "create contribution stage",
            })?;
        let result = (|| {
            Self::stage(writer, replacements)?;
            let (invalid_source, invalid_revision, duplicate_active) = writer
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM graph_contribution_stage input
                        LEFT JOIN graph_evidence unit ON unit.evidence_id = input.unit_ref
                        LEFT JOIN graph_evidence anchor ON anchor.evidence_id = input.anchor_record_id
                        WHERE (input.unit_ref <> 0 AND (unit.evidence_id IS NULL OR unit.source_ref <> ?))
                            OR (input.anchor_record_id IS NOT NULL
                                AND (anchor.evidence_id IS NULL OR anchor.source_ref <> ?))),
                        EXISTS(SELECT 1 FROM graph_producer_members m WHERE m.scope_id = ?
                            AND (m.valid_from >= ? OR m.valid_to >= ?)
                            AND (? OR m.unit_ref IN (SELECT unit_ref FROM graph_contribution_stage))),
                        EXISTS(SELECT 1 FROM graph_producer_members m WHERE m.scope_id = ?
                            AND m.valid_to IS NULL
                            AND (? OR m.unit_ref IN (SELECT unit_ref FROM graph_contribution_stage))
                            GROUP BY m.unit_ref, m.member_kind, m.member_key HAVING count(*) > 1)",
                    params![
                        frontier.source,
                        frontier.source,
                        scope,
                        revision,
                        revision,
                        reset,
                        scope,
                        reset
                    ],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, bool>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    },
                )
                .context(DatabaseSnafu {
                    operation: "check contribution source",
                })?;
            if invalid_source {
                return InvalidSnafu {
                    field: "contribution evidence source",
                }
                .fail();
            }
            if invalid_revision {
                return InvalidSnafu {
                    field: "contribution current revision",
                }
                .fail();
            }
            if duplicate_active {
                return InvalidSnafu {
                    field: "duplicate active contribution member",
                }
                .fail();
            }
            writer
                .execute(
                    "CREATE TEMP TABLE graph_contribution_diff AS
                    WITH selected AS (
                        SELECT m.* FROM graph_producer_members m
                        WHERE m.scope_id = ? AND m.valid_to IS NULL
                            AND (? OR m.unit_ref IN (SELECT unit_ref FROM graph_contribution_stage))
                    ), replacement AS (
                        SELECT * FROM graph_contribution_stage WHERE member_kind IS NOT NULL
                    )
                    SELECT coalesce(new.unit_ref, old.unit_ref) AS unit_ref,
                        coalesce(new.member_kind, old.member_kind) AS member_kind,
                        coalesce(new.member_key, old.member_key) AS member_key,
                        old.valid_from AS prior_from, new.value_ref, new.anchor_record_id,
                        new.anchor_fact, new.reason_code, new.ordinal
                    FROM selected old FULL JOIN replacement new USING(unit_ref, member_kind, member_key)
                    WHERE old.value_ref IS DISTINCT FROM new.value_ref
                        OR old.anchor_record_id IS DISTINCT FROM new.anchor_record_id
                        OR old.anchor_fact IS DISTINCT FROM new.anchor_fact
                        OR old.reason_code IS DISTINCT FROM new.reason_code
                        OR old.ordinal IS DISTINCT FROM new.ordinal",
                    params![scope, reset],
                )
                .context(DatabaseSnafu {
                    operation: "compare contribution members",
                })?;
            let (invalid, deltas) = writer
                .query_row(
                    "WITH previous AS (
                        SELECT m.unit_ref, m.member_kind, m.member_key, m.value_ref
                        FROM (SELECT DISTINCT member_kind, member_key FROM graph_contribution_diff) keys
                        JOIN graph_producer_members m USING(member_kind, member_key)
                        WHERE m.scope_id = ? AND m.valid_to IS NULL
                    ), selected AS (
                        SELECT old.member_kind, old.member_key, old.value_ref FROM previous old
                        WHERE NOT EXISTS(SELECT 1 FROM graph_contribution_diff diff
                            WHERE diff.unit_ref = old.unit_ref AND diff.member_kind = old.member_kind
                                AND diff.member_key = old.member_key AND diff.prior_from IS NOT NULL)
                        UNION ALL
                        SELECT member_kind, member_key, value_ref FROM graph_contribution_diff
                        WHERE value_ref IS NOT NULL
                    ), presence AS (
                        SELECT member_kind, member_key, bool_or(prior) AS prior, bool_or(current) AS current
                        FROM (
                            SELECT member_kind, member_key, true AS prior, false AS current FROM previous
                            UNION ALL
                            SELECT member_kind, member_key, false AS prior, true AS current FROM selected
                        ) members GROUP BY member_kind, member_key
                    )
                    SELECT EXISTS(SELECT 1 FROM selected GROUP BY member_kind, member_key
                            HAVING min(value_ref) <> max(value_ref)),
                        coalesce(sum(current::BIGINT - prior::BIGINT) FILTER(WHERE member_kind = 2), 0)::BIGINT,
                        coalesce(sum(current::BIGINT - prior::BIGINT) FILTER(WHERE member_kind = 3), 0)::BIGINT,
                        coalesce(sum(current::BIGINT - prior::BIGINT) FILTER(WHERE member_kind = 4), 0)::BIGINT,
                        coalesce(sum(current::BIGINT - prior::BIGINT) FILTER(WHERE member_kind = 5), 0)::BIGINT
                    FROM presence",
                    params![scope],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            [
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, i64>(4)?,
                            ],
                        ))
                    },
                )
                .context(DatabaseSnafu {
                    operation: "check contribution owners",
                })?;
            if invalid {
                return InvalidSnafu {
                    field: "contribution current value",
                }
                .fail();
            }
            for (count, delta) in frontier.counts.iter_mut().zip(deltas) {
                *count = u64::try_from(i128::from(*count) + i128::from(delta)).map_err(|_| {
                    InvalidSnafu {
                        field: "contribution member count",
                    }
                    .build()
                })?;
            }
            writer
                .execute(
                    "UPDATE graph_producer_members old SET valid_to = ?
                    FROM graph_contribution_diff diff WHERE old.scope_id = ? AND old.valid_to IS NULL
                        AND old.unit_ref = diff.unit_ref AND old.member_kind = diff.member_kind
                        AND old.member_key = diff.member_key AND old.valid_from = diff.prior_from",
                    params![revision, scope],
                )
                .context(DatabaseSnafu {
                    operation: "close contribution members",
                })?;
            writer
                .execute(
                    "INSERT INTO graph_producer_members
                        (scope_id, unit_ref, member_kind, member_key, value_ref, anchor_record_id,
                            anchor_fact, reason_code, ordinal, valid_from, valid_to)
                    SELECT ?, unit_ref, member_kind, member_key, value_ref, anchor_record_id,
                        anchor_fact, reason_code, ordinal, ?, NULL
                    FROM graph_contribution_diff WHERE value_ref IS NOT NULL",
                    params![scope, revision],
                )
                .context(DatabaseSnafu {
                    operation: "open contribution members",
                })?;
            writer
                .execute(
                    "UPDATE graph_producer_versions SET subject_count = ?, edge_count = ?,
                        finding_count = ?, progress_count = ? WHERE scope_id = ? AND commit_revision = ?",
                    params![
                        frontier.counts[0],
                        frontier.counts[1],
                        frontier.counts[2],
                        frontier.counts[3],
                        scope,
                        revision
                    ],
                )
                .context(DatabaseSnafu {
                    operation: "update contribution counts",
                })?;
            Ok(())
        })();
        let cleanup = writer
            .execute_batch(
                "DROP TABLE IF EXISTS graph_contribution_diff;
                DROP TABLE graph_contribution_stage",
            )
            .context(DatabaseSnafu {
                operation: "release contribution stage",
            });
        result?;
        cleanup?;
        Ok(())
    }

    fn check_requests(replacements: &[Replacement]) -> Result<()> {
        let mut units = BTreeSet::new();
        for replacement in replacements {
            if replacement.unit == Some(0) || !units.insert(replacement.unit) {
                return InvalidSnafu {
                    field: "duplicate or zero contribution unit",
                }
                .fail();
            }
            let mut keys = BTreeSet::new();
            for member in &replacement.members {
                if member.kind > 7
                    || member.key.is_empty()
                    || member.value == 0
                    || member.record == Some(0)
                    || (member.fact.is_some() && member.record.is_none())
                    || !keys.insert((member.kind, member.key.as_slice()))
                {
                    return InvalidSnafu {
                        field: "duplicate or invalid contribution member",
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }

    fn frontier(writer: &Connection, scope: u64, revision: u64) -> Result<Frontier> {
        let (source, kind, created, current, base, previous, prior, counts) = writer
            .query_row(
                "SELECT s.source_ref, s.producer_kind, s.created_revision, current.commit_revision,
                    current.base_result_id, previous.result_id, previous.commit_revision,
                    coalesce(previous.subject_count, 0), coalesce(previous.edge_count, 0),
                    coalesce(previous.finding_count, 0), coalesce(previous.progress_count, 0)
                FROM graph_producer_scopes s
                JOIN graph_producer_versions current ON current.scope_id = s.scope_id
                    AND current.commit_revision = (SELECT max(commit_revision)
                        FROM graph_producer_versions WHERE scope_id = s.scope_id)
                LEFT JOIN graph_producer_versions previous ON previous.scope_id = s.scope_id
                    AND previous.commit_revision = (SELECT max(commit_revision)
                        FROM graph_producer_versions WHERE scope_id = s.scope_id
                            AND commit_revision < current.commit_revision)
                WHERE s.scope_id = ?",
                params![scope],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u8>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<u64>>(6)?,
                        [row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?],
                    ))
                },
            )
            .optional()
            .context(DatabaseSnafu {
                operation: "read contribution frontier",
            })?
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "contribution producer version",
                }
                .build()
            })?;
        if revision == 0
            || current != revision
            || base != previous
            || match prior {
                Some(prior) => created > prior || prior >= revision,
                None => created != revision,
            }
        {
            return InvalidSnafu {
                field: "contribution producer base",
            }
            .fail();
        }
        Ok(Frontier {
            source,
            kind,
            counts,
        })
    }

    fn stage(writer: &Connection, replacements: &[Replacement]) -> Result<()> {
        let mut units = UInt64Builder::new();
        let mut kinds = UInt8Builder::new();
        let mut keys = LargeBinaryBuilder::new();
        let mut values = UInt64Builder::new();
        let mut records = UInt64Builder::new();
        let mut facts = LargeBinaryBuilder::new();
        let mut reasons = LargeStringBuilder::new();
        let mut ordinals = UInt32Builder::new();
        for replacement in replacements {
            let unit = replacement.unit.unwrap_or(0);
            if replacement.members.is_empty() {
                units.append_value(unit);
                kinds.append_null();
                keys.append_null();
                values.append_null();
                records.append_null();
                facts.append_null();
                reasons.append_null();
                ordinals.append_null();
            }
            for member in &replacement.members {
                units.append_value(unit);
                kinds.append_value(member.kind);
                keys.append_value(&member.key);
                values.append_value(member.value);
                records.append_option(member.record);
                facts.append_option(member.fact.as_deref());
                reasons.append_option(member.reason.as_deref());
                ordinals.append_value(member.ordinal);
            }
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(units.finish()),
            Arc::new(kinds.finish()),
            Arc::new(keys.finish()),
            Arc::new(values.finish()),
            Arc::new(records.finish()),
            Arc::new(facts.finish()),
            Arc::new(reasons.finish()),
            Arc::new(ordinals.finish()),
        ];
        let fields = [
            "unit_ref",
            "member_kind",
            "member_key",
            "value_ref",
            "anchor_record_id",
            "anchor_fact",
            "reason_code",
            "ordinal",
        ]
        .into_iter()
        .zip(&arrays)
        .map(|(name, array)| Field::new(name, array.data_type().clone(), name != "unit_ref"))
        .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).map_err(|_| {
            InvalidSnafu {
                field: "contribution native batch",
            }
            .build()
        })?;
        let mut appender = writer
            .appender("graph_contribution_stage")
            .context(DatabaseSnafu {
                operation: "open contribution appender",
            })?;
        appender.append_record_batch(batch).context(DatabaseSnafu {
            operation: "append contribution members",
        })?;
        appender.flush().context(DatabaseSnafu {
            operation: "flush contribution members",
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
