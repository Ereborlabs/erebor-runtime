mod state;
pub use state::{StateRows, StateValue};

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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

use crate::analysis::graph_rows::store::{
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
    kind: u8,
    counts: [u64; 7],
}

impl Contributions {
    /// Apply contribution batches in the caller's transaction.
    /// Each scope must have its current version and exact previous version.
    /// Return staged, inserted, and closed row counts for each scope.
    pub fn apply(
        writer: &Connection,
        revision: u64,
        batches: &BTreeMap<u64, (bool, Vec<Replacement>)>,
    ) -> Result<BTreeMap<u64, (u64, u64, u64)>> {
        if batches.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut frontiers = BTreeMap::new();
        let mut additive = BTreeMap::new();
        for (&scope, (reset, replacements)) in batches {
            Self::check_requests(replacements)?;
            let frontier = Self::frontier(writer, scope, revision)?;
            if frontier.kind == 1 && replacements.iter().any(|item| item.unit.is_some()) {
                return InvalidSnafu {
                    field: "contribution publication unit",
                }
                .fail();
            }
            for (replacement, member) in replacements
                .iter()
                .flat_map(|item| item.members.iter().map(move |member| (item, member)))
            {
                let allowed = match frontier.kind {
                    0 => {
                        (matches!(member.kind, 2..=4 | 8) && member.record.is_some())
                            || (matches!(member.kind, 9..=10)
                                && replacement.unit.is_some()
                                && member.record.is_some()
                                && member.fact.is_none()
                                && member.reason.is_none()
                                && member.ordinal == 0)
                    }
                    1 => matches!(member.kind, 2..=4 | 6),
                    2 => {
                        (matches!(member.kind, 0..=1 | 7) && member.record.is_none())
                            || (member.kind == 10
                                && member.record == replacement.unit
                                && member.fact.is_none()
                                && member.reason.is_none()
                                && member.ordinal == 0)
                    }
                    _ => false,
                };
                if !allowed {
                    return InvalidSnafu {
                        field: "contribution producer member",
                    }
                    .fail();
                }
            }
            let append = frontier.kind == 2
                && !reset
                && replacements.iter().any(|replacement| {
                    replacement.unit.is_none()
                        && !replacement.members.is_empty()
                        && replacement.members.iter().all(|member| member.kind == 10)
                });
            additive.insert(scope, append);
            frontiers.insert(scope, frontier);
        }
        writer
            .execute_batch(
                "CREATE TEMP TABLE graph_contribution_scopes (
                scope_id UBIGINT PRIMARY KEY, is_reset BOOLEAN, additive BOOLEAN);
             CREATE TEMP TABLE graph_contribution_stage (
                scope_id UBIGINT NOT NULL, unit_ref UBIGINT NOT NULL,
                member_kind UTINYINT, member_key BLOB, value_ref UBIGINT,
                anchor_record_id UBIGINT, anchor_fact BLOB, reason_code VARCHAR,
                ordinal UINTEGER)",
            )
            .context(DatabaseSnafu {
                operation: "create contribution stage",
            })?;
        let result = (|| {
            {
                let mut appender =
                    writer
                        .appender("graph_contribution_scopes")
                        .context(DatabaseSnafu {
                            operation: "open contribution scopes",
                        })?;
                for (&scope, (reset, _)) in batches {
                    appender
                        .append_row(params![scope, reset, additive[&scope]])
                        .context(DatabaseSnafu {
                            operation: "append contribution scope",
                        })?;
                }
                appender.flush().context(DatabaseSnafu {
                    operation: "flush contribution scopes",
                })?;
            }
            let staged = Self::stage(writer, batches)?;
            let (invalid_source, invalid_revision, duplicate_active) = writer.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM graph_contribution_stage input
                    JOIN graph_producer_scopes scope USING(scope_id)
                    LEFT JOIN graph_evidence unit ON unit.evidence_id=input.unit_ref
                    LEFT JOIN graph_evidence anchor ON anchor.evidence_id=input.anchor_record_id
                    WHERE (input.unit_ref<>0 AND (unit.evidence_id IS NULL
                            OR unit.source_ref<>scope.source_ref))
                        OR (input.anchor_record_id IS NOT NULL AND (anchor.evidence_id IS NULL
                            OR anchor.source_ref<>scope.source_ref))),
                    EXISTS(SELECT 1 FROM graph_producer_members m
                        JOIN graph_contribution_scopes scope USING(scope_id)
                        WHERE (m.valid_from>=? OR m.valid_to>=?)
                            AND (scope.is_reset OR EXISTS(SELECT 1 FROM graph_contribution_stage s
                                WHERE s.scope_id=m.scope_id AND s.unit_ref=m.unit_ref))
                            AND (NOT scope.additive OR m.unit_ref<>0 OR EXISTS(
                                SELECT 1 FROM graph_contribution_stage s WHERE s.scope_id=m.scope_id
                                    AND s.unit_ref=0 AND s.member_kind=m.member_kind
                                    AND s.member_key=m.member_key))),
                    EXISTS(SELECT 1 FROM graph_producer_members m
                        JOIN graph_contribution_scopes scope USING(scope_id)
                        WHERE m.valid_to IS NULL
                            AND (scope.is_reset OR EXISTS(SELECT 1 FROM graph_contribution_stage s
                                WHERE s.scope_id=m.scope_id AND s.unit_ref=m.unit_ref))
                            AND (NOT scope.additive OR m.unit_ref<>0 OR EXISTS(
                                SELECT 1 FROM graph_contribution_stage s WHERE s.scope_id=m.scope_id
                                    AND s.unit_ref=0 AND s.member_kind=m.member_kind
                                    AND s.member_key=m.member_key))
                        GROUP BY m.scope_id,m.unit_ref,m.member_kind,m.member_key HAVING count(*)>1)",
                params![revision, revision],
                |row| Ok((row.get::<_,bool>(0)?, row.get::<_,bool>(1)?, row.get::<_,bool>(2)?)),
            ).context(DatabaseSnafu { operation: "check contribution source" })?;
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
            let conflict: bool = writer
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM graph_contribution_stage input
                    JOIN graph_contribution_scopes scope USING(scope_id)
                    JOIN graph_producer_members old ON old.scope_id=input.scope_id
                        AND old.unit_ref=input.unit_ref AND old.member_kind=input.member_kind
                        AND old.member_key=input.member_key AND old.valid_to IS NULL
                    WHERE scope.additive AND input.unit_ref=0 AND input.member_kind=10
                        AND old.value_ref<>input.value_ref)",
                    [],
                    |row| row.get(0),
                )
                .context(DatabaseSnafu {
                    operation: "check immutable global contribution ref",
                })?;
            if conflict {
                return InvalidSnafu {
                    field: "contribution global ref revision",
                }
                .fail();
            }
            let mut states = BTreeMap::new();
            for (&scope, (reset, _)) in batches {
                states.insert(
                    scope,
                    (
                        StateRows::prior(writer, scope, revision)?,
                        StateRows::staged(writer, scope, *reset)?,
                    ),
                );
            }
            writer
                .execute_batch(
                    "CREATE TEMP TABLE graph_contribution_diff AS
                 WITH selected AS (
                    SELECT m.* FROM graph_producer_members m
                    JOIN graph_contribution_scopes scope USING(scope_id)
                    WHERE m.valid_to IS NULL
                        AND (scope.is_reset OR EXISTS(SELECT 1 FROM graph_contribution_stage s
                            WHERE s.scope_id=m.scope_id AND s.unit_ref=m.unit_ref))
                        AND (NOT scope.additive OR m.unit_ref<>0 OR EXISTS(
                            SELECT 1 FROM graph_contribution_stage s WHERE s.scope_id=m.scope_id
                                AND s.unit_ref=0 AND s.member_kind=m.member_kind
                                AND s.member_key=m.member_key))
                 ), replacement AS (
                    SELECT * FROM graph_contribution_stage WHERE member_kind IS NOT NULL
                 ) SELECT coalesce(new.scope_id,old.scope_id) AS scope_id,
                    coalesce(new.unit_ref,old.unit_ref) AS unit_ref,
                    coalesce(new.member_kind,old.member_kind) AS member_kind,
                    coalesce(new.member_key,old.member_key) AS member_key,
                    old.valid_from AS prior_from,new.value_ref,new.anchor_record_id,
                    new.anchor_fact,new.reason_code,new.ordinal
                 FROM selected old FULL JOIN replacement new
                    USING(scope_id,unit_ref,member_kind,member_key)
                 WHERE old.value_ref IS DISTINCT FROM new.value_ref
                    OR old.anchor_record_id IS DISTINCT FROM new.anchor_record_id
                    OR old.anchor_fact IS DISTINCT FROM new.anchor_fact
                    OR old.reason_code IS DISTINCT FROM new.reason_code
                    OR old.ordinal IS DISTINCT FROM new.ordinal",
                )
                .context(DatabaseSnafu {
                    operation: "compare contribution members",
                })?;
            let mut statement = writer.prepare(
                "WITH previous AS (
                    SELECT m.scope_id,m.unit_ref,m.member_kind,m.member_key,m.value_ref
                    FROM (SELECT DISTINCT scope_id,member_kind,member_key
                        FROM graph_contribution_diff) keys
                    JOIN graph_producer_members m USING(scope_id,member_kind,member_key)
                    WHERE m.valid_to IS NULL
                 ), selected AS (
                    SELECT old.scope_id,old.member_kind,old.member_key,old.value_ref
                    FROM previous old WHERE NOT EXISTS(
                        SELECT 1 FROM graph_contribution_diff diff WHERE diff.scope_id=old.scope_id
                            AND diff.unit_ref=old.unit_ref AND diff.member_kind=old.member_kind
                            AND diff.member_key=old.member_key AND diff.prior_from IS NOT NULL)
                    UNION ALL SELECT scope_id,member_kind,member_key,value_ref
                        FROM graph_contribution_diff WHERE value_ref IS NOT NULL
                 ), presence AS (
                    SELECT scope_id,member_kind,member_key,bool_or(prior) AS prior,
                        bool_or(current) AS current
                    FROM (
                        SELECT scope_id,member_kind,member_key,true AS prior,false AS current
                            FROM previous
                        UNION ALL SELECT scope_id,member_kind,member_key,false AS prior,true AS current
                            FROM selected
                    ) members GROUP BY scope_id,member_kind,member_key
                 ), invalid AS (
                    SELECT DISTINCT scope_id FROM selected GROUP BY scope_id,member_kind,member_key
                        HAVING min(value_ref)<>max(value_ref)
                 ) SELECT scope.scope_id,invalid.scope_id IS NOT NULL,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=2),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=3),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=4),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=8),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=0),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=1),0)::BIGINT,
                    coalesce(sum(current::BIGINT-prior::BIGINT) FILTER(WHERE member_kind=7),0)::BIGINT
                 FROM graph_contribution_scopes scope LEFT JOIN presence USING(scope_id)
                 LEFT JOIN invalid USING(scope_id) GROUP BY scope.scope_id,invalid.scope_id"
            ).context(DatabaseSnafu { operation: "check contribution owners" })?;
            let mut rows = statement.query([]).context(DatabaseSnafu {
                operation: "read contribution counts",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance contribution counts",
            })? {
                let scope: u64 = row.get(0).context(DatabaseSnafu {
                    operation: "decode contribution scope",
                })?;
                let invalid: bool = row.get(1).context(DatabaseSnafu {
                    operation: "decode contribution owners",
                })?;
                if invalid {
                    return InvalidSnafu {
                        field: "contribution current value",
                    }
                    .fail();
                }
                let frontier = frontiers.get_mut(&scope).ok_or_else(|| {
                    InvalidSnafu {
                        field: "contribution producer version",
                    }
                    .build()
                })?;
                for (index, count) in frontier.counts.iter_mut().enumerate() {
                    let delta: i64 = row.get(index + 2).context(DatabaseSnafu {
                        operation: "decode contribution delta",
                    })?;
                    *count =
                        u64::try_from(i128::from(*count) + i128::from(delta)).map_err(|_| {
                            InvalidSnafu {
                                field: "contribution member count",
                            }
                            .build()
                        })?;
                }
            }
            drop(rows);
            drop(statement);
            let mut work = batches
                .keys()
                .map(|&scope| (scope, (staged[&scope], 0, 0)))
                .collect::<BTreeMap<_, _>>();
            let mut statement = writer
                .prepare(
                    "SELECT scope_id,count(*) FILTER(WHERE value_ref IS NOT NULL),
                    count(*) FILTER(WHERE prior_from IS NOT NULL)
                 FROM graph_contribution_diff GROUP BY scope_id",
                )
                .context(DatabaseSnafu {
                    operation: "prepare contribution changes",
                })?;
            let mut rows = statement.query([]).context(DatabaseSnafu {
                operation: "read contribution changes",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance contribution changes",
            })? {
                let scope: u64 = row.get(0).context(DatabaseSnafu {
                    operation: "decode contribution scope",
                })?;
                let counts = work.get_mut(&scope).ok_or_else(|| {
                    InvalidSnafu {
                        field: "contribution producer version",
                    }
                    .build()
                })?;
                counts.1 = row.get(1).context(DatabaseSnafu {
                    operation: "decode contribution inserts",
                })?;
                counts.2 = row.get(2).context(DatabaseSnafu {
                    operation: "decode contribution closures",
                })?;
            }
            drop(rows);
            drop(statement);
            let closed = writer
                .execute(
                    "UPDATE graph_producer_members old SET valid_to=?
                 FROM graph_contribution_diff diff WHERE old.scope_id=diff.scope_id
                    AND old.valid_to IS NULL AND old.unit_ref=diff.unit_ref
                    AND old.member_kind=diff.member_kind AND old.member_key=diff.member_key
                    AND old.valid_from=diff.prior_from",
                    params![revision],
                )
                .context(DatabaseSnafu {
                    operation: "close contribution members",
                })?;
            let inserted = writer
                .execute(
                    "INSERT INTO graph_producer_members
                    (scope_id,unit_ref,member_kind,member_key,value_ref,anchor_record_id,
                        anchor_fact,reason_code,ordinal,valid_from,valid_to)
                 SELECT scope_id,unit_ref,member_kind,member_key,value_ref,anchor_record_id,
                    anchor_fact,reason_code,ordinal,?,NULL
                 FROM graph_contribution_diff WHERE value_ref IS NOT NULL",
                    params![revision],
                )
                .context(DatabaseSnafu {
                    operation: "open contribution members",
                })?;
            if work.values().map(|count| u128::from(count.1)).sum::<u128>() != inserted as u128
                || work.values().map(|count| u128::from(count.2)).sum::<u128>() != closed as u128
            {
                return InvalidSnafu {
                    field: "contribution changed count",
                }
                .fail();
            }
            for (&scope, frontier) in &frontiers {
                writer.execute(
                    "UPDATE graph_producer_versions SET subject_count=?,edge_count=?,finding_count=?,
                        state_count=?,evidence_count=?,position_count=?,fact_count=?
                     WHERE scope_id=? AND commit_revision=?",
                    params![frontier.counts[0],frontier.counts[1],frontier.counts[2],frontier.counts[3],
                        frontier.counts[4],frontier.counts[5],frontier.counts[6],scope,revision],
                ).context(DatabaseSnafu { operation: "update contribution counts" })?;
                let (prior, candidates) = states.remove(&scope).ok_or_else(|| {
                    InvalidSnafu {
                        field: "contribution producer version",
                    }
                    .build()
                })?;
                StateRows::advance(
                    writer,
                    scope,
                    revision,
                    prior,
                    candidates,
                    batches[&scope].0,
                )?;
            }
            Ok(work)
        })();
        let cleanup = writer
            .execute_batch(
                "DROP TABLE IF EXISTS graph_contribution_diff;
             DROP TABLE graph_contribution_stage;
             DROP TABLE graph_contribution_scopes",
            )
            .context(DatabaseSnafu {
                operation: "release contribution stage",
            });
        let work = result?;
        cleanup?;
        Ok(work)
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
                if !matches!(member.kind, 0..=4 | 6..=10)
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
        let (_source, kind, created, current, base, previous, prior, counts) = writer
            .query_row(
                "SELECT s.source_ref, s.producer_kind, s.created_revision, current.commit_revision,
                    current.base_result_id, previous.result_id, previous.commit_revision,
                    coalesce(previous.subject_count, 0), coalesce(previous.edge_count, 0),
                    coalesce(previous.finding_count, 0), coalesce(previous.state_count, 0),
                    coalesce(previous.evidence_count, 0), coalesce(previous.position_count, 0),
                    coalesce(previous.fact_count, 0)
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
                        [
                            row.get(7)?,
                            row.get(8)?,
                            row.get(9)?,
                            row.get(10)?,
                            row.get(11)?,
                            row.get(12)?,
                            row.get(13)?,
                        ],
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
        Ok(Frontier { kind, counts })
    }

    fn stage(
        writer: &Connection,
        batches: &BTreeMap<u64, (bool, Vec<Replacement>)>,
    ) -> Result<BTreeMap<u64, u64>> {
        let mut scopes = UInt64Builder::new();
        let mut staged = BTreeMap::new();
        let mut units = UInt64Builder::new();
        let mut kinds = UInt8Builder::new();
        let mut keys = LargeBinaryBuilder::new();
        let mut values = UInt64Builder::new();
        let mut records = UInt64Builder::new();
        let mut facts = LargeBinaryBuilder::new();
        let mut reasons = LargeStringBuilder::new();
        let mut ordinals = UInt32Builder::new();
        for (&scope, (_, replacements)) in batches {
            let mut count = 0;
            for replacement in replacements {
                let unit = replacement.unit.unwrap_or(0);
                if replacement.members.is_empty() {
                    scopes.append_value(scope);
                    count += 1;
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
                    scopes.append_value(scope);
                    count += 1;
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
            staged.insert(scope, count);
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(scopes.finish()),
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
            "scope_id",
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
        .map(|(name, array)| {
            Field::new(
                name,
                array.data_type().clone(),
                !matches!(name, "scope_id" | "unit_ref"),
            )
        })
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
        Ok(staged)
    }
}

#[cfg(test)]
mod tests;
