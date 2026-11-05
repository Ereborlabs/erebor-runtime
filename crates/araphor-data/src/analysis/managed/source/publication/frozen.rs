use super::*;
use crate::{AnalysisContextRefV1, AnalysisContextVersionV1, DiscoveryRecordIdV1, ManagedCapture};

type FrozenSource = (
    crate::analysis::graph::GraphSourceSummary,
    Vec<(AnalysisContextVersionV1,AnalysisContextRefV1)>,
    Vec<(DiscoveryRecordIdV1,AnalysisContextRefV1)>,
);

impl AnalysisStore {
    pub(in crate::analysis) fn native_source_records(
        &self, reader: &Connection, capture: &ManagedCapture, result: &PackageResultRefV1,
        control: &AnalysisReadControl, charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Option<Vec<DiscoveryRecordIdV1>>> {
        let tenant = capture.instance().spec.tenant;
        let Some(header) = Self::native_source_header_bound(reader, tenant, &result.result_id,charge)? else { return Ok(None) };
        let crate::ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination else {
            return Err(Code::Denied.error("native source reader destination"));
        };
        if &header.snapshot.scope.identity != source
            || Self::native_source_cut(reader,tenant,result,None,None)?.is_none()
        { return Err(Code::Denied.error("native source reader publication")); }
        let bytes: u64 = reader.query_row(
            "SELECT coalesce(sum(octet_length(member.record_key)),0)::UBIGINT
             FROM managed_source_publications publication JOIN managed_source_members member
                ON member.tenant_id=publication.tenant_id AND member.instance_id=publication.instance_id
                AND member.stream_key=publication.stream_key AND member.valid_from<=publication.revision
                AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
             WHERE publication.result_id=? AND publication.revision=?",
            params![result.result_id,result.commit_revision],|row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation:"bound native source identity keys" })?;
        let bytes = usize::try_from(bytes).ok().and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(header.evidence_count.checked_mul(
                2*std::mem::size_of::<DiscoveryRecordIdV1>()+2*source.node_id.len()+16*std::mem::size_of::<usize>())?))
            .ok_or_else(|| Code::Limit.error("native source identity memory"))?;
        charge(bytes,bytes)?;
        let mut query = reader.prepare(
            "SELECT member.record_key,member.cpu_id,member.source_cursor
             FROM managed_source_publications publication JOIN managed_source_members member
                ON member.tenant_id=publication.tenant_id AND member.instance_id=publication.instance_id
                AND member.stream_key=publication.stream_key AND member.valid_from<=publication.revision
                AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
             WHERE publication.result_id=? AND publication.revision=?",
        ).context(AnalysisDatabaseSnafu { operation:"prepare native source identities" })?;
        let mut rows = query.query(params![result.result_id,result.commit_revision])
            .context(AnalysisDatabaseSnafu { operation:"read native source identities" })?;
        let mut records = Vec::with_capacity(header.evidence_count);
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance native source identities" })? {
            control.check()?;
            let (key,cpu,cursor): (Vec<u8>,u32,u64) = (|| -> duckdb::Result<_> {
                Ok((row.get(0)?,row.get(1)?,row.get(2)?))
            })().context(AnalysisDatabaseSnafu { operation:"decode native source identity" })?;
            let record = DiscoveryRecordIdV1 { stream:source.clone(),cpu_id:cpu,durable_cursor:cursor };
            if cursor == 0 || araphor_analysis_types::DomainRelations::key(&record)
                .context(crate::AnalysisContractSnafu)? != key
            { return Err(Code::Invalid.error("native source identity index")); }
            records.push(record);
        }
        records.sort();
        if records.len() != header.evidence_count || records.windows(2).any(|pair| pair[0]>=pair[1]) {
            return Err(Code::Invalid.error("native source identity count"));
        }
        Ok(Some(records))
    }

    pub(in crate::analysis) fn native_source_facts(
        &self, reader: &Connection, capture: &ManagedCapture, result: &PackageResultRefV1,
        requested: Option<&BTreeSet<DiscoveryRecordIdV1>>, control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Option<FrozenSource>> {
        let tenant = capture.instance().spec.tenant;
        let Some(header) = Self::native_source_header_bound(reader,tenant,&result.result_id,charge)? else { return Ok(None) };
        let crate::ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination else {
            return Err(Code::Denied.error("native frozen source destination"));
        };
        if &header.snapshot.scope.identity != source
            || Self::native_source_cut(reader,tenant,result,None,None)?.is_none()
        { return Err(Code::Denied.error("native frozen source publication")); }
        let summary = crate::analysis::graph::GraphSourceSummary {
            manifest: crate::analysis::GraphManifest::from_snapshot(&header.snapshot),
            restricted_count: header.restricted_count,
            expired: header.expired,
        };
        if requested.is_some_and(BTreeSet::is_empty) {
            return Ok(Some((summary,Vec::new(),Vec::new())));
        }
        reader.execute_batch("CREATE TEMP TABLE native_source_wanted(record_key BLOB PRIMARY KEY)")
            .context(AnalysisDatabaseSnafu { operation:"create frozen source keys" })?;
        let output = (|| {
            if let Some(records) = requested {
                let mut append = reader.appender("native_source_wanted")
                    .context(AnalysisDatabaseSnafu { operation:"open frozen source keys" })?;
                for record in records {
                    control.check()?;
                    if &record.stream != source || record.durable_cursor == 0 {
                        return Err(Code::Denied.error("native frozen source key"));
                    }
                    let key = araphor_analysis_types::DomainRelations::key(record).context(crate::AnalysisContractSnafu)?;
                    charge(0,key.len()+8*std::mem::size_of::<usize>())?;
                    append.append_row(params![key]).context(AnalysisDatabaseSnafu { operation:"append frozen source key" })?;
                }
                append.flush().context(AnalysisDatabaseSnafu { operation:"flush frozen source keys" })?;
            } else {
                let (count,bytes): (u64,u64) = reader.query_row(
                    "SELECT count(*),coalesce(sum(octet_length(member.record_key)),0)::UBIGINT
                     FROM managed_source_publications publication JOIN managed_source_members member
                        ON member.tenant_id=publication.tenant_id AND member.instance_id=publication.instance_id
                        AND member.stream_key=publication.stream_key AND member.valid_from<=publication.revision
                        AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
                     WHERE publication.result_id=?",params![result.result_id],|row| Ok((row.get(0)?,row.get(1)?)),
                ).context(AnalysisDatabaseSnafu { operation:"bound all frozen source identities" })?;
                if usize::try_from(count).ok()!=Some(header.evidence_count) {
                    return Err(Code::Conflict.error("frozen source membership count"));
                }
                let bytes = usize::try_from(bytes).ok().and_then(|bytes| bytes.checked_mul(2))
                    .and_then(|bytes| bytes.checked_add(usize::try_from(count).ok()?.checked_mul(
                        8*std::mem::size_of::<usize>())?))
                    .ok_or_else(|| Code::Limit.error("frozen source identity memory"))?;
                charge(bytes,bytes)?;
                reader.execute(
                    "INSERT INTO native_source_wanted SELECT member.record_key
                     FROM managed_source_publications publication JOIN managed_source_members member
                        ON member.tenant_id=publication.tenant_id AND member.instance_id=publication.instance_id
                        AND member.stream_key=publication.stream_key AND member.valid_from<=publication.revision
                        AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
                     WHERE publication.result_id=?", params![result.result_id],
                ).context(AnalysisDatabaseSnafu { operation:"select all frozen source identities" })?;
            }
            reader.execute(
                "CREATE TEMP TABLE native_source_selected AS SELECT member.*
                 FROM native_source_wanted wanted JOIN managed_source_members member USING(record_key)
                 JOIN managed_source_publications publication ON publication.tenant_id=member.tenant_id
                    AND publication.instance_id=member.instance_id AND publication.stream_key=member.stream_key
                    AND member.valid_from<=publication.revision
                    AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
                 WHERE publication.result_id=? AND publication.revision=?",
                params![result.result_id,result.commit_revision],
            ).context(AnalysisDatabaseSnafu { operation:"bind frozen source selection" })?;
            let sql = format!("SELECT EXISTS(SELECT 1 FROM
                (SELECT DISTINCT origin_result_id,tenant_id,instance_id,stream_key FROM native_source_selected) selected
                LEFT JOIN ({}) publication ON publication.result_id=selected.origin_result_id
                    AND publication.tenant_id=selected.tenant_id AND publication.instance_id=selected.instance_id
                    AND publication.stream_key=selected.stream_key
                WHERE publication.result_id IS NULL)",Self::SOURCE_OWNER);
            let invalid: bool = reader.query_row(&sql,[],|row| row.get(0))
                .context(AnalysisDatabaseSnafu { operation:"check frozen source origin owners" })?;
            if invalid { return Err(Code::Denied.error("frozen source origin owner")); }
            let mut contexts = Vec::new();
            {
                let mut query = reader.prepare(
                    "SELECT DISTINCT context.tenant_id,context.owner_id,context.entity_key,context.lifetime_key,
                        context.owner_revision,context.valid_from_utc_ns,context.valid_until_utc_ns,
                        context.sensitivity,context.body,context.commit_revision,octet_length(context.body),
                        octet_length(context.tenant_id)+octet_length(encode(context.owner_id))+octet_length(context.entity_key)
                            +octet_length(context.lifetime_key)+octet_length(fact.record_key)+octet_length(fact.stream_key),
                        fact.record_key,fact.stream_key,fact.source_cursor,selected.cpu_id
                     FROM native_source_selected selected JOIN context_refs pin ON pin.ref_id=selected.origin_result_id
                     JOIN context_versions context ON context.tenant_id=pin.tenant_id AND context.owner_id=pin.owner_id
                        AND context.entity_key=pin.entity_key AND context.lifetime_key=pin.lifetime_key
                        AND context.owner_revision=pin.owner_revision AND context.commit_revision=pin.commit_revision
                     JOIN graph_fact_records fact ON fact.version_key=context.version_key
                        AND fact.record_key=selected.record_key AND fact.stream_key=selected.stream_key
                        AND fact.source_cursor=selected.source_cursor
                     ORDER BY context.tenant_id,context.owner_id,context.entity_key,context.lifetime_key,context.owner_revision",
                ).context(AnalysisDatabaseSnafu { operation:"prepare canonical frozen source facts" })?;
                let mut rows = query.query([]).context(AnalysisDatabaseSnafu { operation:"read canonical frozen source facts" })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance canonical frozen source facts" })? {
                    control.check()?;
                    let length: u64 = row.get(10).context(AnalysisDatabaseSnafu { operation:"bound canonical frozen source fact" })?;
                    let bytes = usize::try_from(length).map_err(|_| Code::Limit.error("frozen source fact memory"))?;
                    let keys: u64 = row.get(11).context(AnalysisDatabaseSnafu { operation:"bound frozen source fact keys" })?;
                    let keys = usize::try_from(keys).map_err(|_| Code::Limit.error("frozen source key memory"))?;
                    let retained = bytes.checked_mul(8).and_then(|bytes| bytes.checked_add(keys.checked_mul(4)?))
                        .and_then(|bytes| bytes.checked_add(4 * (std::mem::size_of::<AnalysisContextVersionV1>()
                            +std::mem::size_of::<AnalysisContextRefV1>()+std::mem::size_of::<crate::GraphFactV1>())))
                        .ok_or_else(|| Code::Limit.error("frozen source fact memory"))?;
                    charge(bytes.saturating_add(keys),retained)?;
                    let (key, value) = (|| -> duckdb::Result<_> {
                        let tenant: Vec<u8> = row.get(0)?;
                        Ok((crate::AnalysisContextKeyV1 { tenant_id:tenant.try_into()
                            .map_err(|_| duckdb::Error::InvalidColumnIndex(0))?,owner_id:row.get(1)?,entity_key:row.get(2)?,
                            lifetime_key:row.get(3)?,owner_revision:row.get(4)? },
                            (row.get::<_,Option<u64>>(5)?,row.get::<_,Option<u64>>(6)?,row.get::<_,String>(7)?,
                                row.get::<_,Vec<u8>>(8)?,row.get::<_,u64>(9)?)))
                    })().context(AnalysisDatabaseSnafu { operation:"decode canonical frozen source fact" })?;
                    Self::permit_source_context(capture,&key)?;
                    let (context,revision) = Self::decode_context_row(&self.root,key,value)?;
                    Self::validate_context_packages(reader,&context).map_err(crate::Error::stored_artifact)?;
                    let indexed = (|| -> duckdb::Result<_> {
                        Ok(crate::analysis::context::FactRecord { record:row.get(12)?,stream:row.get(13)?,cursor:row.get(14)? })
                    })().context(AnalysisDatabaseSnafu { operation:"decode frozen source fact index" })?;
                    if Self::fact_record(&context)?.as_ref()!=Some(&indexed) {
                        return Err(Code::Conflict.error("frozen source fact index"));
                    }
                    let fact = crate::GraphFactV1::try_from(&context)?;
                    let cpu: u32 = row.get(15).context(AnalysisDatabaseSnafu { operation:"decode frozen source fact CPU" })?;
                    if fact.record_id.stream!=*source || fact.record_id.cpu_id!=cpu {
                        return Err(Code::Denied.error("frozen source fact identity"));
                    }
                    let reference = AnalysisContextRefV1 { key:context.key.clone(),commit_revision:revision };
                    contexts.push((context,reference));
                }
            }
            let invalid: bool = reader.query_row(
                "SELECT EXISTS(SELECT 1 FROM native_source_selected selected JOIN managed_source_proofs proof
                    ON proof.result_id=selected.origin_result_id AND proof.record_key=selected.record_key
                 LEFT JOIN context_versions context ON context.version_key=proof.version_key AND context.commit_revision=proof.revision
                 LEFT JOIN context_refs pin ON pin.ref_id=selected.origin_result_id AND pin.tenant_id=context.tenant_id
                    AND pin.owner_id=context.owner_id AND pin.entity_key=context.entity_key AND pin.lifetime_key=context.lifetime_key
                    AND pin.owner_revision=context.owner_revision AND pin.commit_revision=context.commit_revision
                 WHERE context.version_key IS NULL OR pin.ref_id IS NULL OR proof.stream_key<>selected.stream_key
                    OR proof.cpu_id<>selected.cpu_id OR proof.source_cursor<>selected.source_cursor)", [],|row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check exact frozen source proof pins" })?;
            if invalid { return Err(Code::Conflict.error("frozen source proof pin")); }
            let mut proofs = Vec::new();
            {
                let mut query = reader.prepare(
                    "SELECT DISTINCT selected.cpu_id,selected.source_cursor,context.tenant_id,context.owner_id,
                        context.entity_key,context.lifetime_key,context.owner_revision,context.commit_revision,
                        octet_length(context.tenant_id)+octet_length(encode(context.owner_id))+octet_length(context.entity_key)+octet_length(context.lifetime_key)
                     FROM native_source_selected selected JOIN managed_source_proofs proof
                        ON proof.result_id=selected.origin_result_id AND proof.record_key=selected.record_key
                        AND proof.stream_key=selected.stream_key AND proof.cpu_id=selected.cpu_id
                        AND proof.source_cursor=selected.source_cursor
                     JOIN context_versions context ON context.version_key=proof.version_key AND context.commit_revision=proof.revision
                     JOIN context_refs pin ON pin.ref_id=selected.origin_result_id AND pin.tenant_id=context.tenant_id
                        AND pin.owner_id=context.owner_id AND pin.entity_key=context.entity_key
                        AND pin.lifetime_key=context.lifetime_key AND pin.owner_revision=context.owner_revision
                        AND pin.commit_revision=context.commit_revision",
                ).context(AnalysisDatabaseSnafu { operation:"prepare frozen source proof references" })?;
                let mut rows = query.query([]).context(AnalysisDatabaseSnafu { operation:"read frozen source proof references" })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance frozen source proof references" })? {
                    control.check()?;
                    let keys: u64 = row.get(8).context(AnalysisDatabaseSnafu { operation:"bound frozen source proof keys" })?;
                    let keys = usize::try_from(keys).map_err(|_| Code::Limit.error("frozen source proof memory"))?;
                    charge(keys,keys.saturating_mul(2).saturating_add(
                        2*std::mem::size_of::<(DiscoveryRecordIdV1,AnalysisContextRefV1)>()+source.node_id.len()))?;
                    let (cpu,cursor,key,revision) = (|| -> duckdb::Result<_> {
                        let tenant: Vec<u8> = row.get(2)?;
                        Ok((row.get(0)?,row.get(1)?,crate::AnalysisContextKeyV1 {
                            tenant_id:tenant.try_into().map_err(|_| duckdb::Error::InvalidColumnIndex(2))?,
                            owner_id:row.get(3)?,entity_key:row.get(4)?,lifetime_key:row.get(5)?,owner_revision:row.get(6)?,
                        },row.get(7)?))
                    })().context(AnalysisDatabaseSnafu { operation:"decode frozen source proof reference" })?;
                    Self::permit_source_context(capture,&key)?;
                    proofs.push((DiscoveryRecordIdV1 { stream:source.clone(),cpu_id:cpu,durable_cursor:cursor },
                        AnalysisContextRefV1 { key,commit_revision:revision }));
                }
            }
            proofs.sort_by(|left,right| (&left.0,&left.1.key).cmp(&(&right.0,&right.1.key)));
            Ok((summary,contexts,proofs))
        })();
        let cleanup = reader.execute_batch("DROP TABLE IF EXISTS native_source_selected; DROP TABLE native_source_wanted")
            .context(AnalysisDatabaseSnafu { operation:"release frozen source selection" });
        let value = output?;
        cleanup?;
        Ok(Some(value))
    }

    fn permit_source_context(capture: &ManagedCapture, key: &crate::AnalysisContextKeyV1) -> Result<()> {
        let selection = &capture.instance().grant.selection.contexts;
        if key.tenant_id != capture.instance().spec.tenant
            || !selection.is_all() && !selection.as_slice().contains(key)
        { return Err(Code::Denied.error("frozen source context scope")); }
        Ok(())
    }
}
