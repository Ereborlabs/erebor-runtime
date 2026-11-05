use std::collections::BTreeMap;

use crate::analysis::graph_rows::store::source::{DiscoveryRecordIdV1, StorePositionV1};
use crate::analysis::graph_rows::store::values::AnalysisContextKeyV1;
use duckdb::params;
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, GraphHeader, GraphValidate as _, Relations,
};

type GraphInputs = (
    Vec<DiscoveryRecordIdV1>,
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
);

impl Relations<'_> {
    pub fn metadata<E>(
        &self,
        result: &str,
        header: &mut GraphHeader,
        complete: bool,
        check: &mut impl FnMut() -> std::result::Result<(), E>,
        context_key: &mut impl FnMut(&AnalysisContextKeyV1) -> std::result::Result<Vec<u8>, E>,
    ) -> std::result::Result<(), E>
    where
        E: From<crate::analysis::graph_rows::store::Error>,
    {
        let reader = self.transaction;
        let tenant = header.snapshot.scope.identity.tenant_id;
        if complete {
            let counts:(u64,u64,u64)=reader.query_row("SELECT count(DISTINCT s.subject_id),count(DISTINCT e.edge_id),count(DISTINCT f.value_id) FROM graph_selected_members m LEFT JOIN graph_subject_values s ON m.member_kind=2 AND s.subject_id=m.value_ref LEFT JOIN graph_edge_values e ON m.member_kind=3 AND e.edge_id=m.value_ref LEFT JOIN graph_finding_values f ON m.member_kind=4 AND f.value_id=m.value_ref WHERE m.result_id=?",params![result],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).context(DatabaseSnafu {operation:"check Graph header counts"})?;
            header.check_shape(counts.0, counts.1, counts.2)?;
        }
        let (evidence, positions) = self.inputs(result, header, check)?;
        header.snapshot.input_manifest.evidence = evidence;
        header.snapshot.input_positions = positions;
        let mut facts = Vec::new();
        let mut keyed = BTreeMap::new();
        let mut statement=reader.prepare("SELECT v.body,v.tenant_id,m.ordinal,m.member_key,c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,c.body,c.commit_revision FROM graph_selected_members m LEFT JOIN graph_fact_values v ON v.fact_id=m.value_ref LEFT JOIN context_versions c ON c.version_key=m.member_key WHERE m.result_id=? AND m.member_kind=7 ORDER BY m.ordinal").context(DatabaseSnafu {operation:"prepare Graph facts"})?;
        let mut rows = statement.query(params![result]).context(DatabaseSnafu {
            operation: "read Graph facts",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph facts",
        })? {
            check()?;
            let body: Vec<u8> = NativeRows::column(row, 0)?;
            let stored: Vec<u8> = NativeRows::column(row, 1)?;
            if stored != tenant {
                return Err(E::from(NativeRows::invalid("graph fact value")));
            }
            let ordinal: u32 = NativeRows::column(row, 2)?;
            let key: Vec<u8> = NativeRows::column(row, 3)?;
            if !header.derive_branches
                && (ordinal as usize != facts.len()
                    || key != NativeRows::encode(&(ordinal as usize))?)
            {
                return Err(E::from(NativeRows::invalid("graph fact ordinal")));
            }
            let fact: crate::analysis::graph_rows::store::GraphFactV1 = NativeRows::decode(&body)?;
            fact.validate().map_err(crate::Error::from)?;
            if fact.record_id.stream != header.snapshot.scope.identity
                || header
                    .snapshot
                    .input_manifest
                    .evidence
                    .binary_search(&fact.record_id)
                    .is_err()
            {
                return Err(E::from(NativeRows::invalid("graph fact input")));
            }
            if header.derive_branches {
                let context = AnalysisContextKeyV1 {
                    tenant_id: NativeRows::column::<Vec<u8>>(row, 4)?
                        .try_into()
                        .map_err(|_| E::from(NativeRows::invalid("graph fact context tenant")))?,
                    owner_id: NativeRows::column(row, 5)?,
                    entity_key: NativeRows::column(row, 6)?,
                    lifetime_key: NativeRows::column(row, 7)?,
                    owner_revision: NativeRows::column(row, 8)?,
                };
                let canonical = crate::analysis::graph_rows::store::GraphFactV1::decode_context(
                    &NativeRows::column::<Vec<u8>>(row, 9)?,
                )
                .map_err(|_| E::from(NativeRows::invalid("graph fact context value")))?;
                let revision: u64 = NativeRows::column(row, 10)?;
                if ordinal != 0
                    || context_key(&context)? != key
                    || canonical != fact
                    || !context.valid()
                    || context.tenant_id != tenant
                    || revision == 0
                    || keyed.insert(context, fact).is_some()
                {
                    return Err(E::from(NativeRows::invalid("graph fact context identity")));
                }
            } else {
                facts.push(fact);
            }
        }
        if header.derive_branches {
            header.snapshot.input_manifest.context = keyed.keys().cloned().collect();
            facts = keyed.into_values().collect();
        }
        if facts.len() != header.fact_count {
            return Err(E::from(NativeRows::invalid("graph fact count")));
        }
        header.snapshot.graph.facts = facts;
        drop(rows);
        drop(statement);
        if complete && !header.derive_branches {
            let mut branches = Vec::new();
            let mut statement=reader.prepare("SELECT v.body,v.tenant_id,m.ordinal,m.member_key FROM graph_selected_members m LEFT JOIN graph_branch_values v ON v.branch_id=m.value_ref WHERE m.result_id=? AND m.member_kind=6 ORDER BY m.ordinal,m.member_key").context(DatabaseSnafu {operation:"prepare Graph branches"})?;
            let mut rows = statement.query(params![result]).context(DatabaseSnafu {
                operation: "read Graph branches",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance Graph branches",
            })? {
                check()?;
                let body: Vec<u8> = NativeRows::column(row, 0)?;
                let stored: Vec<u8> = NativeRows::column(row, 1)?;
                if stored != tenant {
                    return Err(E::from(NativeRows::invalid("graph branch value")));
                }
                {
                    let ordinal: u32 = NativeRows::column(row, 2)?;
                    let key: Vec<u8> = NativeRows::column(row, 3)?;
                    if ordinal as usize != branches.len()
                        || key != NativeRows::encode(&(ordinal as usize))?
                    {
                        return Err(E::from(NativeRows::invalid("graph branch ordinal")));
                    }
                }
                branches.push(NativeRows::decode(&body)?);
            }
            if branches.len() != header.branch_count {
                return Err(E::from(NativeRows::invalid("graph branch count")));
            }
            header.snapshot.graph.branches = branches;
            header.branches_loaded = true;
        }
        header.complete = complete;
        header.snapshot.validate().map_err(crate::Error::from)?;
        Ok(())
    }

    pub fn inputs<E>(
        &self,
        result: &str,
        header: &GraphHeader,
        check: &mut impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<GraphInputs, E>
    where
        E: From<crate::analysis::graph_rows::store::Error>,
    {
        let reader = self.transaction;
        let source = &header.snapshot.scope.identity;
        let mut evidence = Vec::new();
        let mut statement=reader.prepare("SELECT e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,r.cpu_id,m.member_key FROM graph_selected_members m LEFT JOIN graph_evidence e ON e.evidence_id=m.value_ref LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.result_id=? AND m.member_kind=0 ORDER BY e.cpu_id,e.durable_cursor").context(DatabaseSnafu {operation:"prepare Graph input identities"})?;
        let mut rows = statement.query(params![result]).context(DatabaseSnafu {
            operation: "read Graph input identities",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph input identities",
        })? {
            check()?;
            let key: Option<Vec<u8>> = NativeRows::column(row, 2)?;
            let tenant: Option<Vec<u8>> = NativeRows::column(row, 3)?;
            let retained: Option<Vec<u8>> = NativeRows::column(row, 4)?;
            let cpu: u32 = NativeRows::column(row, 0)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || NativeRows::column::<Option<u32>>(row, 5)? != Some(cpu)
            {
                return Err(E::from(NativeRows::invalid("graph evidence source")));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: cpu,
                durable_cursor: NativeRows::column(row, 1)?,
            };
            if NativeRows::column::<Vec<u8>>(row, 6)? != NativeRows::encode(&record)? {
                return Err(E::from(NativeRows::invalid(
                    "graph evidence member identity",
                )));
            }
            evidence.push(record);
        }
        drop(rows);
        drop(statement);
        let mut positions = Vec::new();
        let mut statement=reader.prepare("SELECT m.ordinal,p.commit_revision,p.ordinal,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,r.cpu_id,m.member_key FROM graph_selected_members m LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref LEFT JOIN graph_evidence e USING(evidence_id) LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.result_id=? AND m.member_kind=1 ORDER BY m.ordinal").context(DatabaseSnafu {operation:"prepare Graph input positions"})?;
        let mut rows = statement.query(params![result]).context(DatabaseSnafu {
            operation: "read Graph input positions",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph input positions",
        })? {
            check()?;
            if !header.derive_branches
                && NativeRows::column::<u32>(row, 0)? as usize != positions.len()
            {
                return Err(E::from(NativeRows::invalid("graph position ordinal")));
            }
            let key: Option<Vec<u8>> = NativeRows::column(row, 5)?;
            let tenant: Option<Vec<u8>> = NativeRows::column(row, 6)?;
            let retained: Option<Vec<u8>> = NativeRows::column(row, 7)?;
            let cpu: u32 = NativeRows::column(row, 3)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || NativeRows::column::<Option<u32>>(row, 8)? != Some(cpu)
            {
                return Err(E::from(NativeRows::invalid("graph evidence source")));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: cpu,
                durable_cursor: NativeRows::column(row, 4)?,
            };
            let expected = if header.derive_branches {
                NativeRows::encode(&record)?
            } else {
                NativeRows::encode(&positions.len())?
            };
            if NativeRows::column::<Vec<u8>>(row, 9)? != expected
                || (header.derive_branches && NativeRows::column::<u32>(row, 0)? != 0)
            {
                return Err(E::from(NativeRows::invalid(
                    "graph position member identity",
                )));
            }
            positions.push((
                record,
                StorePositionV1 {
                    commit_revision: NativeRows::column(row, 1)?,
                    ordinal: NativeRows::column(row, 2)?,
                },
            ));
        }
        if header.derive_branches {
            positions.sort_by(|left, right| left.0.cmp(&right.0));
        }
        if evidence.len() != header.evidence_count
            || positions.len() != header.position_count
            || evidence.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(E::from(NativeRows::invalid("graph input row counts")));
        }
        Ok((evidence, positions))
    }
}
