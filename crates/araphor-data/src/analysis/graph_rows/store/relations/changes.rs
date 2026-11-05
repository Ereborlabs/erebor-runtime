use std::collections::{BTreeMap, BTreeSet};

use duckdb::{params, types::Value};
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, Relations, Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipChange {
    pub kind: u8,
    pub key: Vec<u8>,
    pub before: Option<u64>,
    pub after: Option<u64>,
}

#[derive(Default)]
pub struct Changes {
    pub members: Vec<MembershipChange>,
    after_counts: Option<[u64; 3]>,
}

impl Relations<'_> {
    pub fn cuts(&self, result: &str) -> Result<Vec<(String, u64, u64)>> {
        let mut statement = self
            .transaction
            .prepare(
                "SELECT p.result_id,p.scope_id,p.commit_revision FROM graph_result_producers b
             JOIN graph_producer_versions p ON p.result_id=b.producer_result_id
             WHERE b.result_id=? ORDER BY p.scope_id",
            )
            .context(DatabaseSnafu {
                operation: "prepare Graph snapshot cuts",
            })?;
        let cuts = statement
            .query_map(params![result], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(DatabaseSnafu {
                operation: "read Graph snapshot cuts",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(DatabaseSnafu {
                operation: "decode Graph snapshot cuts",
            })?;
        if cuts.windows(2).any(|rows| rows[0].1 == rows[1].1)
            || cuts
                .iter()
                .any(|(id, scope, cut)| id.is_empty() || *scope == 0 || *cut == 0)
        {
            return Err(NativeRows::invalid("graph snapshot producer cuts"));
        }
        Ok(cuts)
    }

    pub fn changes(
        &self,
        before: &[(String, u64, u64)],
        after: &[(String, u64, u64)],
        touched: Option<&BTreeSet<(u8, Vec<u8>)>>,
    ) -> Result<Changes> {
        if before.is_empty() && after.is_empty() {
            return Ok(Changes {
                members: Vec::new(),
                after_counts: touched.is_none().then_some([0; 3]),
            });
        }
        let mut parameters = Vec::new();
        let mut cuts = Vec::with_capacity(before.len().saturating_add(after.len()));
        for (side, selected) in [(0u8, before), (1u8, after)] {
            let mut scopes = BTreeSet::new();
            for (id, scope, cut) in selected {
                if id.is_empty() || *scope == 0 || *cut == 0 || !scopes.insert(*scope) {
                    return Err(NativeRows::invalid("graph snapshot producer cuts"));
                }
                cuts.push("(?::UTINYINT,?::VARCHAR,?::UBIGINT,?::UBIGINT)");
                parameters.extend([
                    Value::UTinyInt(side),
                    Value::Text(id.clone()),
                    Value::UBigInt(*scope),
                    Value::UBigInt(*cut),
                ]);
            }
        }
        let mut query = format!(
            "WITH cuts(side,result_id,scope_id,cut) AS (VALUES {})",
            cuts.join(",")
        );
        if let Some(touched) = touched {
            let mut keys = Vec::with_capacity(touched.len());
            for (kind, key) in touched {
                keys.push("(?::UTINYINT,?::BLOB)");
                parameters.extend([Value::UTinyInt(*kind), Value::Blob(key.clone())]);
            }
            if keys.is_empty() {
                query.push_str(",touched(member_kind,member_key) AS (SELECT NULL::UTINYINT,NULL::BLOB WHERE false)");
            } else {
                query.push_str(&format!(
                    ",touched(member_kind,member_key) AS (VALUES {})",
                    keys.join(",")
                ));
            }
        }
        query.push_str(
            " SELECT c.side,m.member_kind,m.member_key,m.value_ref,
                coalesce(v.scope_id=c.scope_id AND v.commit_revision=c.cut,false) AS valid_cut
              FROM cuts c LEFT JOIN graph_producer_versions v ON v.result_id=c.result_id
              LEFT JOIN graph_producer_members m ON m.scope_id=c.scope_id
                AND m.valid_from<=c.cut AND (m.valid_to IS NULL OR m.valid_to>c.cut)
                AND m.member_kind IN (0,1,2,3,4,6,7)",
        );
        if touched.is_some() {
            query.push_str(" AND EXISTS (SELECT 1 FROM touched k WHERE k.member_kind=m.member_kind AND k.member_key=m.member_key)");
        }
        query.push_str(" GROUP BY c.side,m.member_kind,m.member_key,m.value_ref,valid_cut ORDER BY m.member_kind,m.member_key,c.side,m.value_ref");
        let mut statement = self.transaction.prepare(&query).context(DatabaseSnafu {
            operation: "prepare indexed Graph changes",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(DatabaseSnafu {
                operation: "read indexed Graph changes",
            })?;
        let mut selected = BTreeMap::<(u8, Vec<u8>), [Option<u64>; 2]>::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance indexed Graph changes",
        })? {
            if !NativeRows::column::<bool>(row, 4)? {
                return Err(NativeRows::invalid("graph snapshot producer cuts"));
            }
            if NativeRows::column::<Option<u8>>(row, 1)?.is_none() {
                continue;
            }
            let side = NativeRows::column::<u8>(row, 0)?;
            let kind = NativeRows::column::<u8>(row, 1)?;
            let key = NativeRows::column::<Vec<u8>>(row, 2)?;
            let value = NativeRows::column::<u64>(row, 3)?;
            let pair = selected.entry((kind, key)).or_default();
            let slot = pair
                .get_mut(usize::from(side))
                .ok_or_else(|| NativeRows::invalid("graph change side"))?;
            if value == 0 || slot.replace(value).is_some() {
                return Err(NativeRows::invalid("graph producer merge"));
            }
        }
        let after_counts = touched.is_none().then(|| {
            let mut values: [BTreeSet<u64>; 3] = Default::default();
            for ((kind, _), [_, after]) in &selected {
                if (2..=4).contains(kind) {
                    if let Some(value) = after {
                        values[usize::from(*kind - 2)].insert(*value);
                    }
                }
            }
            values.map(|values| values.len() as u64)
        });
        Ok(Changes {
            after_counts,
            members: selected
                .into_iter()
                .filter_map(|((kind, key), [before, after])| {
                    (before != after).then_some(MembershipChange {
                        kind,
                        key,
                        before,
                        after,
                    })
                })
                .collect(),
        })
    }

    pub fn check_union(&self, result: &str) -> Result<()> {
        let writer = self.transaction;
        let invalid:bool=writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_selected_members WHERE result_id=? AND member_kind IN (2,3,4) GROUP BY member_kind,member_key HAVING count(DISTINCT value_ref)>1) OR EXISTS(SELECT 1 FROM graph_selected_members m JOIN graph_edge_values e ON e.edge_id=m.value_ref WHERE m.result_id=? AND m.member_kind=3 AND (NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=e.from_ref) OR NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=e.to_ref))) OR EXISTS(SELECT 1 FROM graph_selected_members m JOIN graph_finding_values f ON f.value_id=m.value_ref WHERE m.result_id=? AND m.member_kind=4 AND NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=f.subject_ref))",params![result,result,result],|row|row.get(0)).context(DatabaseSnafu {operation:"validate Graph producer merge"})?;
        if invalid {
            return Err(NativeRows::invalid("graph producer merge"));
        }
        Ok(())
    }

    pub(super) fn check_changes(
        &self,
        result: &str,
        touched: &BTreeSet<(u8, Vec<u8>)>,
    ) -> Result<()> {
        if touched.is_empty() {
            return Ok(());
        }
        let mut parameters = Vec::new();
        let mut keys = Vec::with_capacity(touched.len());
        for (kind, key) in touched {
            keys.push("(?::UTINYINT,?::BLOB)");
            parameters.extend([Value::UTinyInt(*kind), Value::Blob(key.clone())]);
        }
        parameters.extend(std::iter::repeat_n(Value::Text(result.into()), 6));
        let query = format!(
            "WITH touched(member_kind,member_key) AS (VALUES {}),
             subjects AS (
                SELECT DISTINCT m.value_ref FROM graph_producer_members m
                JOIN touched k USING(member_kind,member_key)
                WHERE m.member_kind=2 AND m.scope_id IN (
                    SELECT v.scope_id FROM graph_result_producers b
                    JOIN graph_producer_versions v ON v.result_id=b.producer_result_id WHERE b.result_id=?
                )
             ), edges AS (
                SELECT DISTINCT e.from_ref,e.to_ref FROM graph_selected_members m
                JOIN graph_edge_values e ON e.edge_id=m.value_ref
                WHERE m.result_id=? AND m.member_kind=3 AND (
                    e.from_ref IN (SELECT value_ref FROM subjects)
                    OR e.to_ref IN (SELECT value_ref FROM subjects)
                    OR m.member_key IN (SELECT member_key FROM touched WHERE member_kind=3))
             ), findings AS (
                SELECT DISTINCT f.subject_ref FROM graph_selected_members m
                JOIN graph_finding_values f ON f.value_id=m.value_ref
                WHERE m.result_id=? AND m.member_kind=4 AND (
                    f.subject_ref IN (SELECT value_ref FROM subjects)
                    OR m.member_key IN (SELECT member_key FROM touched WHERE member_kind=4))
             ) SELECT EXISTS (
                SELECT 1 FROM edges e WHERE
                    NOT EXISTS (SELECT 1 FROM graph_selected_members s WHERE s.result_id=? AND s.member_kind=2 AND s.value_ref=e.from_ref)
                    OR NOT EXISTS (SELECT 1 FROM graph_selected_members s WHERE s.result_id=? AND s.member_kind=2 AND s.value_ref=e.to_ref)
             ) OR EXISTS (
                SELECT 1 FROM findings f WHERE
                    NOT EXISTS (SELECT 1 FROM graph_selected_members s WHERE s.result_id=? AND s.member_kind=2 AND s.value_ref=f.subject_ref)
             )",
            keys.join(",")
        );
        let orphan: bool = self
            .transaction
            .query_row(&query, duckdb::params_from_iter(parameters.iter()), |row| {
                row.get(0)
            })
            .context(DatabaseSnafu {
                operation: "validate changed Graph endpoints",
            })?;
        if orphan {
            return Err(NativeRows::invalid("graph changed endpoint"));
        }
        Ok(())
    }
}

impl Changes {
    pub fn counts(&self, mut counts: [u64; 3]) -> Result<[u64; 3]> {
        if let Some(counts) = self.after_counts {
            return Ok(counts);
        }
        for member in &self.members {
            if !(2..=4).contains(&member.kind) {
                continue;
            }
            let count = &mut counts[usize::from(member.kind - 2)];
            *count = match (member.before, member.after) {
                (None, Some(_)) => count.checked_add(1),
                (Some(_), None) => count.checked_sub(1),
                _ => Some(*count),
            }
            .ok_or_else(|| NativeRows::invalid("graph changed count"))?;
        }
        Ok(counts)
    }
}
