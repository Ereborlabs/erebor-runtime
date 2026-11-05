use super::*;
use crate::analysis::graph_rows::GraphHeader;

impl AnalysisStore {
    pub(in crate::analysis) fn native_source_header(
        reader: &Connection, tenant: [u8;16], result: &str,
    ) -> Result<Option<GraphHeader>> {
        Self::native_source_header_bound(reader,tenant,result,&mut |_,_| Ok(()))
    }

    pub(in crate::analysis) fn native_source_header_bound(
        reader: &Connection, tenant: [u8;16], result: &str,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Option<GraphHeader>> {
        let bound: Option<(u64,u64)> = reader.query_row(
            "SELECT octet_length(encode(source.identity_json)),
                (SELECT count(*) FROM managed_source_gaps gap WHERE gap.result_id=publication.result_id)
             FROM managed_source_publications publication JOIN source_receipts source USING(stream_key)
             WHERE publication.result_id=? AND publication.tenant_id=?",
            params![result,tenant.as_slice()],|row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation:"bound native source publication header" })?;
        let Some((identity_bytes,gap_count)) = bound else { return Ok(None) };
        let identity_bytes = usize::try_from(identity_bytes).map_err(|_| Code::Limit.error("native source identity memory"))?;
        let gap_count = usize::try_from(gap_count).map_err(|_| Code::Limit.error("native source gap memory"))?;
        let gap_bytes = gap_count.checked_mul(std::mem::size_of::<(u64,u64)>())
            .ok_or_else(|| Code::Limit.error("native source gap memory"))?;
        let bytes = identity_bytes.checked_mul(4).and_then(|bytes| bytes.checked_add(gap_bytes.checked_mul(6)?))
            .and_then(|bytes| bytes.checked_add(3*std::mem::size_of::<GraphHeader>()))
            .ok_or_else(|| Code::Limit.error("native source header memory"))?;
        charge(identity_bytes.saturating_add(gap_bytes),bytes)?;
        let value = reader.query_row(
            "SELECT source.identity_json,publication.first_cursor,publication.last_cursor,
                publication.previous_result_id,publication.context_notice,publication.witness_deadline,
                publication.record_count,publication.restricted_count,publication.coverage_revision,
                publication.subject_count,publication.relationship_count,publication.finding_count,publication.expired
             FROM managed_source_publications publication JOIN source_receipts source USING(stream_key)
             JOIN analysis_results result ON result.result_id=publication.result_id
                AND result.tenant_id=publication.tenant_id AND result.processor_id='managed-definition-v1'
                AND result.commit_revision=publication.revision
             LEFT JOIN managed_graph_publications graph ON graph.result_id=publication.result_id
             LEFT JOIN managed_graphs owner ON owner.graph_id=graph.graph_id
             WHERE publication.result_id=? AND publication.tenant_id=? AND source.tenant_id=publication.tenant_id
                AND (graph.result_id IS NULL OR (graph.revision=publication.revision
                    AND owner.tenant_id=publication.tenant_id AND owner.instance_id=publication.instance_id))",
            params![result,tenant.as_slice()], |row| Ok((row.get::<_,String>(0)?,row.get::<_,u64>(1)?,
                row.get::<_,u64>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,u64>(4)?,row.get::<_,u64>(5)?,
                row.get::<_,u64>(6)?,row.get::<_,u64>(7)?,row.get::<_,u64>(8)?,
                row.get::<_,u64>(9)?,row.get::<_,u64>(10)?,row.get::<_,u64>(11)?,row.get::<_,bool>(12)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation:"read native source publication header" })?;
        let Some((identity,first,last,previous,notice,deadline,count,restricted,coverage,subjects,edges,findings,expired)) = value else {
            return Err(Code::Invalid.error("native source publication owner"));
        };
        let source: crate::EvidenceIntakeIdentityV1 = serde_json::from_str(&identity)
            .map_err(|_| Code::Invalid.error("native source catalog identity"))?;
        if !source.valid() || source.tenant_id != tenant || first == 0 || last < first {
            return Err(Code::Invalid.error("native source publication header"));
        }
        let mut query = reader.prepare("SELECT first_cursor,last_cursor FROM managed_source_gaps WHERE result_id=? ORDER BY first_cursor,last_cursor")
            .context(AnalysisDatabaseSnafu { operation:"prepare native source publication gaps" })?;
        let rows = query.query_map(params![result], |row| Ok((row.get::<_,u64>(0)?,row.get::<_,u64>(1)?)))
            .context(AnalysisDatabaseSnafu { operation:"read native source publication gaps" })?;
        let mut missing = Vec::with_capacity(gap_count);
        for row in rows {
            if missing.len()==gap_count { return Err(Code::Conflict.error("native source gap count")); }
            missing.push(row.context(AnalysisDatabaseSnafu { operation:"decode native source publication gap" })?);
        }
        if missing.len()!=gap_count { return Err(Code::Conflict.error("native source gap count")); }
        let count = usize::try_from(count).map_err(|_| Code::Limit.error("native source header count"))?;
        let convert = |value| usize::try_from(value).map_err(|_| Code::Limit.error("native Graph header count"));
        let coverage_keys = Self::native_source_coverage(reader,&source,result,charge)?;
        let manifest = crate::analysis::GraphManifest {
            schema_version:crate::GRAPH_SCHEMA_VERSION,
            scope:crate::ProcessorScopeV1 { processor_id:crate::GRAPH_PROCESSOR.into(),
                method_version:u64::from(crate::GRAPH_SCHEMA_VERSION),identity:source },
            first_cursor:first,last_cursor:last,
            input_manifest:crate::GraphRevisionV1 { evidence:Vec::new(),coverage:coverage_keys,context:Vec::new(),missing_ranges:missing.clone() },
            facts:Vec::new(),packages:Vec::new(),missing_ranges:missing,input_positions:Vec::new(),
            previous_result_id:previous,context_notice_revision:notice,witness_deadline_utc_ns:deadline,
        };
        Ok(Some(GraphHeader { snapshot:manifest.snapshot(),finding_value_ids:BTreeMap::new(),
            subject_count:convert(subjects)?,edge_count:convert(edges)?,finding_count:convert(findings)?,
            branch_count:0,branches_loaded:false,complete:false,derive_branches:true,
            evidence_count:count,position_count:count,fact_count:0,restricted_count:Some(restricted),
            notice:(notice,coverage),expired }))
    }

    pub(in crate::analysis) const SOURCE_OWNER: &'static str = "
        SELECT publication.* FROM managed_source_publications publication
        JOIN analysis_results result ON result.result_id=publication.result_id
            AND result.tenant_id=publication.tenant_id AND result.processor_id='managed-definition-v1'
            AND result.commit_revision=publication.revision
        JOIN managed_attempts attempt ON attempt.tenant_id=publication.tenant_id
            AND attempt.instance_id=publication.instance_id AND attempt.attempt_id=publication.attempt_id
            AND attempt.generation=publication.generation AND attempt.completed=publication.revision
        WHERE publication.captured_revision>0 AND publication.captured_revision<publication.revision";

    pub(in crate::analysis) fn native_source_cut(
        reader: &Connection, tenant: [u8;16], result: &PackageResultRefV1,
        reference: Option<&super::super::super::model::ManagedAttempt>, expected_call: Option<&str>,
    ) -> Result<Option<u64>> {
        let sql = format!("SELECT instance_id,stream_key,captured_revision,attempt_id,generation
            FROM ({}) publication WHERE result_id=? AND revision=? AND tenant_id=?",Self::SOURCE_OWNER);
        let row: Option<(String,Vec<u8>,u64,String,u64)> = reader.query_row(
            &sql,params![result.result_id,result.commit_revision,tenant.as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation:"read native source captured owner" })?;
        let Some((instance,stream,cut,attempt,generation)) = row else {
            let present: bool = reader.query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_source_publications WHERE result_id=?)",
                params![result.result_id],|row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check native source captured presence" })?;
            if present { return Err(Code::Conflict.error("native source publication capture")); }
            return Ok(None);
        };
        if let Some(call) = expected_call {
            let valid: bool = reader.query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_edges edge JOIN analysis_results result
                    ON result.result_id=edge.dependency_id AND result.tenant_id=edge.tenant_id
                    AND result.processor_id='managed-package-v1' AND result.commit_revision=edge.commit_revision
                 WHERE edge.result_id=? AND edge.tenant_id=? AND edge.dependency_id=? AND edge.commit_revision=?)",
                params![result.result_id,tenant.as_slice(),call,result.commit_revision],|row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check native source captured call" })?;
            if !valid { return Err(Code::Denied.error("native source captured call")); }
        }
        if reference.is_some_and(|reference| reference.0.capture.tenant!=tenant
            || reference.0.capture.instance!=instance || reference.1.spec.id!=instance
            || reference.1.spec.tenant!=tenant || reference.0.capture.generation!=generation
            || reference.0.capture.revision!=cut || reference.0.request.id!=attempt
            || !matches!(&reference.1.spec.destination, super::super::super::model::ManagedDestination::Graph { source, .. }
                if source.key()==stream)
            || reference.0.receipt.as_ref().is_none_or(|receipt| receipt.selected!=*result || receipt.graph.as_ref()!=Some(result)))
        { return Err(Code::Conflict.error("native source publication reference")); }
        Ok(Some(cut))
    }
}
