use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::graph_rows::store::source::DiscoveryRecordIdV1;
use crate::analysis::graph_rows::store::values::AnalysisContextKeyV1;
use duckdb::{params, types::Value};
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::{DatabaseSnafu, DecodingSnafu},
    native::NativeRows,
    GraphFactV1, GraphHead, GraphManifest, GraphValidate as _, Relations, Snapshot,
};

pub struct FrozenContext {
    pub key: AnalysisContextKeyV1,
    pub from: Option<u64>,
    pub until: Option<u64>,
    pub sensitivity: String,
    pub body: Vec<u8>,
    pub revision: u64,
}

pub struct FrozenProof {
    pub record: DiscoveryRecordIdV1,
    pub key: AnalysisContextKeyV1,
    pub revision: u64,
    pub opening: GraphHead,
}

pub struct FrozenInput<T> {
    pub summary: GraphManifest,
    pub restricted: Option<u64>,
    pub expired: bool,
    pub contexts: Vec<T>,
    pub proofs: Vec<FrozenProof>,
}

impl Relations<'_> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Data supplies the authority and resource checks."
    )]
    pub fn frozen<E, T>(
        &self,
        mut snapshot: Snapshot<'_>,
        records: Option<&BTreeSet<DiscoveryRecordIdV1>>,
        check: &mut impl FnMut() -> std::result::Result<(), E>,
        charge: &mut impl FnMut(usize, usize) -> std::result::Result<(), E>,
        context_key: &mut impl FnMut(&AnalysisContextKeyV1) -> std::result::Result<Vec<u8>, E>,
        verify_context: &mut impl FnMut(FrozenContext) -> std::result::Result<T, E>,
        verify_proof: &mut impl FnMut(&FrozenProof) -> std::result::Result<u64, E>,
    ) -> std::result::Result<FrozenInput<T>, E>
    where
        E: From<crate::analysis::graph_rows::store::Error>,
    {
        check()?;
        if !std::ptr::eq(snapshot.transaction, self.transaction) {
            return Err(E::from(NativeRows::invalid(
                "frozen Graph snapshot transaction",
            )));
        }
        let reader = self.transaction;
        let result = &snapshot.head.result_id;
        let revision = snapshot.head.commit_revision;
        let source = snapshot.header.snapshot.scope.identity.clone();
        let tenant = source.tenant_id;
        let (scope, cut, stored, restricted): (u64, u64, Vec<u8>, Option<u64>) = reader.query_row(
            "SELECT v.scope_id,v.commit_revision,s.stream_key,v.restricted_count FROM graph_versions g
             JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
             JOIN graph_producer_scopes p USING(scope_id) JOIN graph_sources s USING(source_ref)
             WHERE g.result_id=? AND g.commit_revision=? AND p.producer_kind=2 AND p.tenant_id=?",
            params![result,revision,tenant.as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).context(DatabaseSnafu { operation: "read frozen Graph metadata cut" })?;
        if scope == 0
            || cut != revision
            || stored != source.key()
            || records.is_some_and(|records| records.iter().any(|record| record.stream != source))
        {
            return Err(E::from(NativeRows::invalid("frozen Graph metadata cut")));
        }
        let mut summary = GraphManifest::from_snapshot(&snapshot.header.snapshot);
        summary.input_manifest.evidence.clear();
        summary.input_manifest.context.clear();
        summary.input_positions.clear();
        summary.facts.clear();
        let mut output = FrozenInput {
            summary,
            restricted,
            expired: snapshot.header.expired,
            contexts: Vec::new(),
            proofs: Vec::new(),
        };
        if records.is_some_and(BTreeSet::is_empty) {
            return Ok(output);
        }
        if restricted.is_none() {
            let length: u64 = reader.query_row(
                "SELECT COALESCE(SUM(octet_length(f.body)),0) FROM graph_selected_members m
                 JOIN graph_fact_values f ON f.fact_id=m.value_ref WHERE m.result_id=? AND m.member_kind=7",
                params![result], |row| row.get(0),
            ).context(DatabaseSnafu { operation: "bound initial frozen Graph facts" })?;
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            charge(
                length,
                length
                    .saturating_mul(2)
                    .saturating_add(
                        snapshot
                            .header
                            .evidence_count
                            .saturating_mul(std::mem::size_of::<DiscoveryRecordIdV1>()),
                    )
                    .saturating_add(snapshot.header.position_count.saturating_mul(
                        std::mem::size_of::<(
                            DiscoveryRecordIdV1,
                            crate::analysis::graph_rows::store::source::StorePositionV1,
                        )>(),
                    ))
                    .saturating_add(
                        snapshot
                            .header
                            .fact_count
                            .saturating_mul(std::mem::size_of::<GraphFactV1>()),
                    ),
            )?;
            self.metadata(result, &mut snapshot.header, false, check, context_key)?;
            let header = snapshot.header;
            let mut parameters = Vec::new();
            let mut keys = Vec::new();
            for key in &header.snapshot.input_manifest.context {
                let key = context_key(key)?;
                charge(
                    0,
                    std::mem::size_of::<Value>() + std::mem::size_of::<&str>() + key.capacity(),
                )?;
                keys.push("(?::BLOB)");
                parameters.push(Value::Blob(key));
            }
            if keys.is_empty() {
                return Ok(output);
            }
            let query = format!(
                "WITH requested(version_key) AS (VALUES {})
                 SELECT c.version_key,c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,
                    c.valid_from_utc_ns,c.valid_until_utc_ns,c.sensitivity,octet_length(c.body),c.body,c.commit_revision
                 FROM requested q LEFT JOIN context_versions c USING(version_key) ORDER BY c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision", keys.join(",")
            );
            charge(0, query.capacity())?;
            let mut statement = reader.prepare(&query).context(DatabaseSnafu {
                operation: "prepare direct frozen Graph contexts",
            })?;
            let mut rows = statement
                .query(duckdb::params_from_iter(parameters.iter()))
                .context(DatabaseSnafu {
                    operation: "read direct frozen Graph contexts",
                })?;
            let mut seen = BTreeSet::new();
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance direct frozen Graph contexts",
            })? {
                check()?;
                let context = Self::frozen_context(row, 1, charge)?;
                if NativeRows::column::<Vec<u8>>(row, 0)? != context_key(&context.key)?
                    || !header
                        .snapshot
                        .input_manifest
                        .context
                        .contains(&context.key)
                    || !seen.insert(context.key.clone())
                    || context.revision > revision
                {
                    return Err(E::from(NativeRows::invalid("frozen Graph context cut")));
                }
                let fact = (|| -> crate::analysis::graph_rows::store::Result<GraphFactV1> {
                    if !context.key.valid() || context.key.owner_revision == 0 {
                        return Err(NativeRows::invalid("graph context version"));
                    }
                    let fact = GraphFactV1::decode_context(&context.body).context(DecodingSnafu)?;
                    fact.validate()?;
                    if fact.record_id.stream.tenant_id != context.key.tenant_id {
                        return Err(NativeRows::invalid("graph context tenant"));
                    }
                    Ok(fact)
                })();
                let context = verify_context(context)?;
                let Ok(fact) = fact else {
                    continue;
                };
                if !header.snapshot.graph.facts.contains(&fact) {
                    return Err(E::from(NativeRows::invalid("frozen Graph context value")));
                }
                if records.is_none_or(|records| records.contains(&fact.record_id)) {
                    charge(0, std::mem::size_of::<T>())?;
                    output.contexts.try_reserve_exact(1).map_err(|_| {
                        crate::AnalysisInputTooLargeSnafu {
                            resource: "frozen Graph output",
                        }
                        .build()
                    })?;
                    output.contexts.push(context);
                }
            }
            if seen.len() != header.snapshot.input_manifest.context.len() {
                return Err(E::from(NativeRows::invalid("frozen Graph context count")));
            }
            return Ok(output);
        }
        let mut parameters = Vec::new();
        let mut keys = Vec::new();
        let mut selected = Vec::new();
        charge(
            0,
            records
                .map_or(snapshot.header.evidence_count, BTreeSet::len)
                .saturating_mul(std::mem::size_of::<(&DiscoveryRecordIdV1, u64)>()),
        )?;
        for record in records.into_iter().flatten() {
            check()?;
            if record.durable_cursor > snapshot.header.snapshot.last_cursor {
                continue;
            }
            let key = NativeRows::encode(record)?;
            charge(
                0,
                2 * std::mem::size_of::<Value>() + std::mem::size_of::<&str>() + key.capacity(),
            )?;
            keys.push("(?::UBIGINT,?::BLOB)");
            parameters.extend([Value::UBigInt(selected.len() as u64), Value::Blob(key)]);
            charge(0, record.allocated_bytes())?;
            selected.push(record.clone());
        }
        if records.is_some() && keys.is_empty() {
            return Ok(output);
        }
        let requested = if records.is_some() {
            format!(
                "WITH requested(record_ordinal,member_key) AS (VALUES {})",
                keys.join(",")
            )
        } else {
            "WITH requested AS (SELECT unit_ref AS record_ordinal,member_key FROM graph_producer_members
                WHERE scope_id=? AND member_kind=0 AND valid_from<=? AND (valid_to IS NULL OR valid_to>?))".into()
        };
        if records.is_none() {
            parameters.extend([
                Value::UBigInt(scope),
                Value::UBigInt(cut),
                Value::UBigInt(cut),
            ]);
        }
        let query = format!(
            "{requested} SELECT q.record_ordinal,m.unit_ref,m.value_ref,e.cpu_id,e.durable_cursor,
                s.stream_key,s.tenant_id,r.cpu_id,m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal,m.member_key
             FROM requested q JOIN graph_producer_members m ON m.member_key=q.member_key
             LEFT JOIN graph_evidence e ON e.evidence_id=m.value_ref
             LEFT JOIN graph_sources s USING(source_ref)
             LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id
             WHERE m.scope_id=? AND m.member_kind=0 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)"
        );
        parameters.extend([
            Value::UBigInt(scope),
            Value::UBigInt(cut),
            Value::UBigInt(cut),
        ]);
        let mut units = BTreeMap::new();
        let mut ordinals = BTreeSet::new();
        charge(0, query.capacity())?;
        let mut statement = reader.prepare(&query).context(DatabaseSnafu {
            operation: "prepare frozen Graph record units",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(DatabaseSnafu {
                operation: "read frozen Graph record units",
            })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance frozen Graph record units",
        })? {
            check()?;
            let ordinal = NativeRows::column::<u64>(row, 0)?;
            let record =
                if records.is_some() {
                    selected
                        .get(usize::try_from(ordinal).map_err(|_| {
                            E::from(NativeRows::invalid("frozen Graph record ordinal"))
                        })?)
                        .ok_or_else(|| E::from(NativeRows::invalid("frozen Graph record ordinal")))?
                        .clone()
                } else {
                    DiscoveryRecordIdV1 {
                        stream: source.clone(),
                        cpu_id: NativeRows::column(row, 3)?,
                        durable_cursor: NativeRows::column(row, 4)?,
                    }
                };
            charge(0, record.allocated_bytes())?;
            let unit = NativeRows::column::<u64>(row, 1)?;
            charge(
                0,
                std::mem::size_of::<(u64, &DiscoveryRecordIdV1)>()
                    + std::mem::size_of::<u64>()
                    + 6 * std::mem::size_of::<usize>(),
            )?;
            if unit == 0
                || unit != NativeRows::column::<u64>(row, 2)?
                || record.cpu_id != NativeRows::column::<u32>(row, 3)?
                || record.durable_cursor != NativeRows::column::<u64>(row, 4)?
                || stored != NativeRows::column::<Vec<u8>>(row, 5)?
                || tenant != NativeRows::column::<Vec<u8>>(row, 6)?.as_slice()
                || Some(record.cpu_id) != NativeRows::column::<Option<u32>>(row, 7)?
                || NativeRows::column::<Option<u64>>(row, 8)?.is_some()
                || NativeRows::column::<Option<Vec<u8>>>(row, 9)?.is_some()
                || NativeRows::column::<Option<String>>(row, 10)?.is_some()
                || NativeRows::column::<u32>(row, 11)? != 0
                || record.durable_cursor == 0
                || record.durable_cursor > snapshot.header.snapshot.last_cursor
                || NativeRows::column::<Vec<u8>>(row, 12)? != NativeRows::encode(&record)?
                || !ordinals.insert(ordinal)
                || units.insert(unit, record).is_some()
            {
                return Err(E::from(NativeRows::invalid("frozen Graph record unit")));
            }
        }
        drop(rows);
        drop(statement);
        if records.is_none() && units.len() != snapshot.header.evidence_count {
            return Err(E::from(NativeRows::invalid("frozen Graph record count")));
        }
        if units.is_empty() {
            return Ok(output);
        }
        charge(
            0,
            units
                .len()
                .saturating_mul(64 + 2 * std::mem::size_of::<u64>() + std::mem::size_of::<&str>()),
        )?;
        let requested = format!(
            "WITH requested(unit_ref) AS (VALUES {})",
            std::iter::repeat_n("(?::UBIGINT)", units.len())
                .collect::<Vec<_>>()
                .join(",")
        );
        let parameters = units
            .keys()
            .copied()
            .chain([scope, cut, cut])
            .collect::<Vec<_>>();
        let query = format!(
            "{requested} SELECT m.unit_ref,m.member_key,f.tenant_id,octet_length(f.body),f.body,
                c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,
                c.valid_from_utc_ns,c.valid_until_utc_ns,c.sensitivity,octet_length(c.body),c.body,c.commit_revision
             FROM requested q JOIN graph_producer_members m USING(unit_ref)
             LEFT JOIN graph_fact_values f ON f.fact_id=m.value_ref
             LEFT JOIN context_versions c ON c.version_key=m.member_key
             WHERE m.scope_id=? AND m.member_kind=7 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)
             ORDER BY c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision"
        );
        charge(0, query.capacity())?;
        let mut statement = reader.prepare(&query).context(DatabaseSnafu {
            operation: "prepare frozen Graph joined facts",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(DatabaseSnafu {
                operation: "read frozen Graph joined facts",
            })?;
        let mut seen = BTreeSet::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance frozen Graph joined facts",
        })? {
            check()?;
            let unit = NativeRows::column::<u64>(row, 0)?;
            let record = units
                .get(&unit)
                .ok_or_else(|| E::from(NativeRows::invalid("frozen Graph fact unit")))?;
            let length = usize::try_from(NativeRows::column::<u64>(row, 3)?).unwrap_or(usize::MAX);
            charge(length, length.saturating_mul(2))?;
            let fact: GraphFactV1 = NativeRows::decode(&NativeRows::column::<Vec<u8>>(row, 4)?)?;
            fact.validate().map_err(crate::Error::from)?;
            let context = Self::frozen_context(row, 5, charge)?;
            if NativeRows::column::<Vec<u8>>(row, 1)? != context_key(&context.key)?
                || NativeRows::column::<Vec<u8>>(row, 2)? != tenant
                || &fact.record_id != record
                || !seen.insert(context.key.clone())
                || context.key.tenant_id != tenant
                || !context.key.valid()
                || context.key.owner_revision == 0
                || context.revision == 0
                || context.revision > revision
                || GraphFactV1::decode_context(&context.body).context(DecodingSnafu)? != fact
            {
                return Err(E::from(NativeRows::invalid("frozen Graph native fact")));
            }
            charge(0, std::mem::size_of::<T>())?;
            output.contexts.try_reserve_exact(1).map_err(|_| {
                crate::AnalysisInputTooLargeSnafu {
                    resource: "frozen Graph output",
                }
                .build()
            })?;
            output.contexts.push(verify_context(context)?);
        }
        drop(rows);
        drop(statement);
        let query = format!(
            "{requested} SELECT m.unit_ref,c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,
                c.commit_revision,m.valid_from,m.anchor_record_id,g.result_id,r.ref_id
             FROM requested q JOIN graph_producer_members m USING(unit_ref)
             LEFT JOIN context_versions c ON c.version_key=m.member_key AND c.commit_revision=m.value_ref
             LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
             LEFT JOIN graph_versions g ON g.metadata_result_id=opened.result_id
             LEFT JOIN context_refs r ON r.ref_id=g.result_id AND r.tenant_id=c.tenant_id AND r.owner_id=c.owner_id
                AND r.entity_key=c.entity_key AND r.lifetime_key=c.lifetime_key AND r.owner_revision=c.owner_revision
             WHERE m.scope_id=? AND m.member_kind=10 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)"
        );
        charge(0, query.capacity())?;
        let mut statement = reader.prepare(&query).context(DatabaseSnafu {
            operation: "prepare frozen Graph joined proofs",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(DatabaseSnafu {
                operation: "read frozen Graph joined proofs",
            })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance frozen Graph joined proofs",
        })? {
            check()?;
            let unit = NativeRows::column::<u64>(row, 0)?;
            let record = units
                .get(&unit)
                .ok_or_else(|| E::from(NativeRows::invalid("frozen Graph proof unit")))?;
            let key = Self::frozen_key(row, 1)?;
            let bytes = std::mem::size_of::<FrozenProof>()
                + record.allocated_bytes()
                + key.owner_id.capacity()
                + key.entity_key.capacity()
                + key.lifetime_key.capacity();
            charge(bytes, bytes)?;
            let proof = FrozenProof {
                record: record.clone(),
                key,
                revision: NativeRows::column(row, 6)?,
                opening: GraphHead {
                    result_id: NativeRows::column(row, 9)?,
                    commit_revision: NativeRows::column(row, 7)?,
                },
            };
            charge(0, proof.opening.result_id.capacity())?;
            let captured = verify_proof(&proof)?;
            if proof.key.tenant_id != tenant
                || !proof.key.valid()
                || proof.revision == 0
                || proof.revision > captured
                || NativeRows::column::<Option<u64>>(row, 8)? != Some(unit)
                || NativeRows::column::<Option<String>>(row, 10)?.is_none()
            {
                return Err(E::from(NativeRows::invalid("frozen Graph proof ref")));
            }
            output.proofs.try_reserve_exact(1).map_err(|_| {
                crate::AnalysisInputTooLargeSnafu {
                    resource: "frozen Graph proof refs",
                }
                .build()
            })?;
            output.proofs.push(proof);
        }
        output.proofs.sort_by(|left, right| {
            left.record
                .cmp(&right.record)
                .then(left.key.cmp(&right.key))
        });
        if output
            .proofs
            .windows(2)
            .any(|pair| pair[0].record == pair[1].record && pair[0].key == pair[1].key)
        {
            return Err(E::from(NativeRows::invalid("frozen Graph duplicate proof")));
        }
        Ok(output)
    }

    fn frozen_key(
        row: &duckdb::Row<'_>,
        offset: usize,
    ) -> crate::analysis::graph_rows::store::Result<AnalysisContextKeyV1> {
        Ok(AnalysisContextKeyV1 {
            tenant_id: NativeRows::column::<Vec<u8>>(row, offset)?
                .try_into()
                .map_err(|_| NativeRows::invalid("frozen Graph context tenant"))?,
            owner_id: NativeRows::column(row, offset + 1)?,
            entity_key: NativeRows::column(row, offset + 2)?,
            lifetime_key: NativeRows::column(row, offset + 3)?,
            owner_revision: NativeRows::column(row, offset + 4)?,
        })
    }

    fn frozen_context<E>(
        row: &duckdb::Row<'_>,
        offset: usize,
        charge: &mut impl FnMut(usize, usize) -> std::result::Result<(), E>,
    ) -> std::result::Result<FrozenContext, E>
    where
        E: From<crate::analysis::graph_rows::store::Error>,
    {
        let key = Self::frozen_key(row, offset)?;
        let length =
            usize::try_from(NativeRows::column::<u64>(row, offset + 8)?).unwrap_or(usize::MAX);
        let bytes = length
            .saturating_mul(3)
            .saturating_add(std::mem::size_of::<FrozenContext>())
            .saturating_add(
                2 * (key.owner_id.capacity()
                    + key.entity_key.capacity()
                    + key.lifetime_key.capacity()),
            )
            .saturating_add(
                std::mem::size_of::<AnalysisContextKeyV1>() + 3 * std::mem::size_of::<usize>(),
            );
        charge(length, bytes)?;
        Ok(FrozenContext {
            key,
            from: NativeRows::column(row, offset + 5)?,
            until: NativeRows::column(row, offset + 6)?,
            sensitivity: NativeRows::column(row, offset + 7)?,
            body: NativeRows::column(row, offset + 9)?,
            revision: NativeRows::column(row, offset + 10)?,
        })
    }
}
