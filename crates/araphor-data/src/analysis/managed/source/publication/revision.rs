use super::*;
use crate::{AnalysisContextKeyV1, DiscoveryCoverageStateV1, GraphCoverageKeyV1, GraphRevisionV1};

impl AnalysisStore {
    pub(in crate::analysis) fn native_source_coverage(
        reader: &Connection, source: &crate::EvidenceIntakeIdentityV1, result: &str,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Vec<GraphCoverageKeyV1>> {
        let (count,reasons,bytes): (u64,u64,u64) = reader.query_row(
            "SELECT (SELECT count(*) FROM managed_source_coverage WHERE result_id=?),count(*),
                coalesce(sum(octet_length(encode(reason))),0)::UBIGINT
             FROM managed_source_reasons WHERE result_id=?",params![result,result],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).context(AnalysisDatabaseSnafu { operation:"bound native source coverage keys" })?;
        let bytes = usize::try_from(bytes).ok().and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(usize::try_from(reasons).ok()?.checked_mul(2*std::mem::size_of::<String>())?))
            .and_then(|bytes| bytes.checked_add(usize::try_from(count).ok()?.checked_mul(
                2*std::mem::size_of::<GraphCoverageKeyV1>()+source.node_id.len())?))
            .ok_or_else(|| Code::Limit.error("native source coverage memory"))?;
        charge(bytes,bytes)?;
        let mut keys = Vec::new();
        let mut query = reader.prepare(
            "SELECT ordinal,cpu_id,report_revision,interval_id,interval_revision,state
             FROM managed_source_coverage WHERE result_id=? ORDER BY ordinal",
        ).context(AnalysisDatabaseSnafu { operation:"prepare native source coverage keys" })?;
        let mut rows = query.query(params![result])
            .context(AnalysisDatabaseSnafu { operation:"read native source coverage keys" })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance native source coverage keys" })? {
            let (ordinal,cpu,report,id,revision,state): (u64,u32,u64,Vec<u8>,u64,u8) =
                (|| -> duckdb::Result<_> { Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)) })()
                    .context(AnalysisDatabaseSnafu { operation:"decode native source coverage key" })?;
            if usize::try_from(ordinal).ok()!=Some(keys.len()) { return Err(Code::Invalid.error("native source coverage ordinal")); }
            let interval_id = <[u8;16]>::try_from(id.as_slice())
                .map_err(|_| Code::Invalid.error("native source coverage identity"))?;
            let state = match state { 0=>DiscoveryCoverageStateV1::Healthy,1=>DiscoveryCoverageStateV1::Gapped,
                2=>DiscoveryCoverageStateV1::Unknown,3=>DiscoveryCoverageStateV1::Closed,
                _=>return Err(Code::Invalid.error("native source coverage state")) };
            keys.push(GraphCoverageKeyV1 { source:source.clone(),cpu_id:cpu,report_revision:report,
                interval_id,interval_revision:revision,state,gap_reasons:Vec::new() });
        }
        let mut query = reader.prepare("SELECT ordinal,reason FROM managed_source_reasons WHERE result_id=? ORDER BY ordinal,reason")
            .context(AnalysisDatabaseSnafu { operation:"prepare native source coverage reasons" })?;
        let mut rows = query.query(params![result])
            .context(AnalysisDatabaseSnafu { operation:"read native source coverage reasons" })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance native source coverage reasons" })? {
            let (ordinal,reason): (u64,String) = (|| -> duckdb::Result<_> { Ok((row.get(0)?,row.get(1)?)) })()
                .context(AnalysisDatabaseSnafu { operation:"decode native source coverage reason" })?;
            let key = usize::try_from(ordinal).ok().and_then(|index| keys.get_mut(index))
                .ok_or_else(|| Code::Invalid.error("native source coverage reason owner"))?;
            key.gap_reasons.push(reason);
        }
        if keys.windows(2).any(|pair| pair[0]>=pair[1]) { return Err(Code::Invalid.error("native source coverage order")); }
        Ok(keys)
    }

    pub(in crate::analysis) fn native_source_revision(
        reader: &Connection, tenant: [u8;16], result: &str,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Option<GraphRevisionV1>> {
        let Some(header) = Self::native_source_header_bound(reader,tenant,result,charge)? else { return Ok(None) };
        let source = &header.snapshot.scope.identity;
        let revision: u64 = reader.query_row("SELECT revision FROM managed_source_publications WHERE result_id=?",
            params![result],|row| row.get(0)).context(AnalysisDatabaseSnafu { operation:"read native source revision cut" })?;
        Self::native_source_cut(reader,tenant,&PackageResultRefV1 { result_id:result.into(),commit_revision:revision },None,None)?
            .ok_or_else(|| Code::Missing.error("native source revision owner"))?;
        let members = "SELECT member.* FROM managed_source_publications publication
            JOIN managed_source_members member ON member.tenant_id=publication.tenant_id
                AND member.instance_id=publication.instance_id AND member.stream_key=publication.stream_key
                AND member.valid_from<=publication.revision AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
            WHERE publication.result_id=?";
        let bytes = header.evidence_count.checked_mul(2*(std::mem::size_of::<crate::DiscoveryRecordIdV1>()+source.node_id.len()))
            .ok_or_else(|| Code::Limit.error("native source revision evidence memory"))?;
        charge(bytes,bytes)?;
        let mut evidence = reader.prepare(&format!("SELECT cpu_id,source_cursor FROM ({members}) member"))
            .and_then(|mut query| query.query_map(params![result],|row| Ok(crate::DiscoveryRecordIdV1 {
                stream:source.clone(),cpu_id:row.get(0)?,durable_cursor:row.get(1)?,
            }))?.collect::<duckdb::Result<Vec<_>>>())
            .context(AnalysisDatabaseSnafu { operation:"read native source revision evidence" })?;
        evidence.sort_unstable();
        if evidence.len()!=header.evidence_count || evidence.windows(2).any(|pair| pair[0]>=pair[1]) {
            return Err(Code::Conflict.error("native source revision evidence count"));
        }
        let contexts = format!("SELECT DISTINCT context.owner_id,context.entity_key,context.lifetime_key,context.owner_revision
            FROM ({members}) member JOIN context_refs pin ON pin.ref_id=member.origin_result_id
                AND pin.tenant_id=member.tenant_id
            JOIN context_versions context ON context.tenant_id=pin.tenant_id AND context.owner_id=pin.owner_id
                AND context.entity_key=pin.entity_key AND context.lifetime_key=pin.lifetime_key
                AND context.owner_revision=pin.owner_revision AND context.commit_revision=pin.commit_revision
            LEFT JOIN graph_fact_records fact ON fact.version_key=context.version_key
                AND fact.record_key=member.record_key AND fact.stream_key=member.stream_key AND fact.source_cursor=member.source_cursor
            LEFT JOIN managed_source_proofs proof ON proof.result_id=member.origin_result_id
                AND proof.record_key=member.record_key AND proof.version_key=context.version_key
                AND proof.revision=context.commit_revision AND proof.stream_key=member.stream_key
                AND proof.cpu_id=member.cpu_id AND proof.source_cursor=member.source_cursor
            WHERE fact.version_key IS NOT NULL OR proof.version_key IS NOT NULL");
        let (count,bytes): (u64,u64) = reader.query_row(&format!("SELECT count(*),coalesce(sum(
            octet_length(encode(owner_id))+octet_length(entity_key)+octet_length(lifetime_key)),0)::UBIGINT
            FROM ({contexts}) context"),params![result],|row| Ok((row.get(0)?,row.get(1)?)))
            .context(AnalysisDatabaseSnafu { operation:"bound native source revision contexts" })?;
        let bytes = usize::try_from(bytes).ok().and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(usize::try_from(count).ok()?.checked_mul(2*std::mem::size_of::<AnalysisContextKeyV1>())?))
            .ok_or_else(|| Code::Limit.error("native source revision context memory"))?;
        charge(bytes,bytes)?;
        let mut context = reader.prepare(&contexts).and_then(|mut query| query.query_map(params![result],|row|
            Ok(AnalysisContextKeyV1 { tenant_id:tenant,owner_id:row.get(0)?,entity_key:row.get(1)?,
                lifetime_key:row.get(2)?,owner_revision:row.get(3)? }))?.collect::<duckdb::Result<Vec<_>>>())
            .context(AnalysisDatabaseSnafu { operation:"read native source revision contexts" })?;
        context.sort_unstable();
        let coverage = header.snapshot.input_manifest.coverage;
        let revision = GraphRevisionV1 { evidence,coverage,context,missing_ranges:header.snapshot.missing_ranges };
        revision.validate(tenant)?;
        Ok(Some(revision))
    }
}
