use super::*;
use crate::analysis::managed::model::{Attempt,Step};

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_source_step(
        reader: &Connection, attempt: &Attempt, result: &str, step: &Step, revision: u64,
    ) -> Result<()> {
        let stored: Option<(Vec<u8>,u64,u32,u64,u64,u64,Option<String>,String,u64)> = reader.query_row(
            "SELECT stream_key,captured_revision,captured_ordinal,first_cursor,last_cursor,witness_deadline,previous_result_id,attempt_id,generation
             FROM managed_source_publications WHERE result_id=? AND tenant_id=? AND instance_id=? AND revision=?",
            params![result,attempt.capture.tenant.as_slice(),step.instance,revision],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation:"read selected source contribution owner" })?;
        let present = stored.is_some();
        let (Some(source),Some((stream,cut,ordinal,first,last,deadline,base,owner,generation))) = (&step.source,stored) else {
            if step.source.is_none() && !present { return Ok(()); }
            return Err(Code::Invalid.error("selected source contribution presence"));
        };
        let spec = Self::managed_version_from(reader,attempt.capture.tenant,&step.instance,attempt.capture.generation)?;
        let crate::ManagedDestination::Graph { source: identity, .. } = &spec.destination else {
            return Err(Code::Denied.error("selected source contribution destination"));
        };
        if identity.key()!=stream || cut!=attempt.capture.revision || ordinal!=u32::MAX
            || owner!=attempt.request.id || owner!=step.attempt || generation!=attempt.capture.generation
            || source.first!=first || source.last!=last || source.deadline!=deadline
            || source.base.as_ref().map(|base| base.result_id.as_str())!=base.as_deref()
            || source.records.windows(2).any(|pair| pair[0].0>=pair[1].0)
            || source.derived.windows(2).any(|pair| pair[0].key>=pair[1].key)
            || source.origins.windows(2).any(|pair| pair[0].result_id>=pair[1].result_id)
            || source.proofs.windows(2).any(|pair| (&pair[0].0,&pair[0].1.key)>=(&pair[1].0,&pair[1].1.key))
        { return Err(Code::Invalid.error("selected source contribution scope")); }
        let parent: Option<PackageResultRefV1> = reader.query_row(
            "SELECT result_id,revision FROM managed_source_publications WHERE tenant_id=? AND instance_id=?
                AND stream_key=? AND revision<? ORDER BY revision DESC LIMIT 1",
            params![attempt.capture.tenant.as_slice(),step.instance,stream,revision],
            |row| Ok(PackageResultRefV1 { result_id:row.get(0)?,commit_revision:row.get(1)? }),
        ).optional().context(AnalysisDatabaseSnafu { operation:"check selected source parent reference" })?;
        if source.base!=parent { return Err(Code::Conflict.error("selected source parent reference")); }
        if Self::native_source_coverage(reader,identity,result,&mut |_,_| Ok(()))?!=source.coverage {
            return Err(Code::Conflict.error("selected source coverage pins"));
        }
        Self::check_source_coverage(reader,identity,result,cut,attempt.capture.time_utc_ns,source)?;
        let mut expected = BTreeMap::new();
        for (record,position) in &source.records {
            if &record.stream!=identity || !(first..=last).contains(&record.durable_cursor)
                || position.commit_revision==0 || *position>(StorePositionV1 { commit_revision:cut,ordinal })
                || step.witnesses.binary_search_by(|witness| match &witness.identity {
                    crate::AnalysisStreamIdentityV1::Evidence(identity) =>
                        (identity,witness.cursor).cmp(&(&record.stream,record.durable_cursor)),
                    crate::AnalysisStreamIdentityV1::Diagnostic(_) => std::cmp::Ordering::Greater,
                }).is_err()
            { return Err(Code::Denied.error("selected source record authority")); }
            expected.insert(araphor_analysis_types::DomainRelations::key(record).context(crate::AnalysisContractSnafu)?,
                (record.cpu_id,record.durable_cursor,position.commit_revision,position.ordinal));
        }
        let mut records = reader.prepare(
            "SELECT record_key,cpu_id,source_cursor,position_revision,position_ordinal FROM managed_source_members
             WHERE tenant_id=? AND instance_id=? AND stream_key=? AND valid_from=? AND origin_result_id=?",
        ).context(AnalysisDatabaseSnafu { operation:"prepare selected source membership pins" })?;
        let mut rows = records.query(params![attempt.capture.tenant.as_slice(),step.instance,stream,revision,result])
            .context(AnalysisDatabaseSnafu { operation:"read selected source membership pins" })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance selected source membership pins" })? {
            let (key,value) = (|| -> duckdb::Result<_> { Ok((row.get::<_,Vec<u8>>(0)?,
                (row.get::<_,u32>(1)?,row.get::<_,u64>(2)?,row.get::<_,u64>(3)?,row.get::<_,u32>(4)?))) })()
                .context(AnalysisDatabaseSnafu { operation:"decode selected source membership pin" })?;
            if expected.remove(&key)!=Some(value) { return Err(Code::Conflict.error("selected source membership pin")); }
        }
        if !expected.is_empty() { return Err(Code::Missing.error("selected source membership pin")); }
        let proofs = source.proofs.iter().map(|(_,reference)| (&reference.key,reference.commit_revision))
            .collect::<BTreeSet<_>>();
        reader.execute_batch("CREATE TEMP TABLE native_source_check(version_key BLOB PRIMARY KEY,revision UBIGINT,proof BOOLEAN,captured BOOLEAN)")
            .context(AnalysisDatabaseSnafu { operation:"create selected source reference check" })?;
        let checked = (|| {
            {
                let mut append = reader.appender("native_source_check")
                    .context(AnalysisDatabaseSnafu { operation:"open selected source reference check" })?;
                for reference in &source.derived {
                    append.append_row(params![crate::analysis::context::version_key(&reference.key)?,reference.commit_revision,
                        proofs.contains(&(&reference.key,reference.commit_revision)),attempt.capture.contexts.contains(reference)])
                        .context(AnalysisDatabaseSnafu { operation:"append selected source reference check" })?;
                }
                append.flush().context(AnalysisDatabaseSnafu { operation:"flush selected source reference check" })?;
            }
            let invalid: bool = reader.query_row(
                "SELECT EXISTS(SELECT 1 FROM native_source_check wanted
                 LEFT JOIN context_versions context ON context.version_key=wanted.version_key AND context.commit_revision=wanted.revision
                 LEFT JOIN graph_fact_records fact ON fact.version_key=wanted.version_key
                 LEFT JOIN managed_source_members member ON member.record_key=fact.record_key
                    AND member.stream_key=fact.stream_key AND member.source_cursor=fact.source_cursor
                    AND member.tenant_id=? AND member.instance_id=? AND member.valid_from=? AND member.origin_result_id=?
                 WHERE context.version_key IS NULL OR context.tenant_id<>?
                    OR (fact.version_key IS NOT NULL AND member.record_key IS NULL)
                    OR (fact.version_key IS NULL AND NOT wanted.proof AND NOT wanted.captured))",
                params![attempt.capture.tenant.as_slice(),step.instance,revision,result,attempt.capture.tenant.as_slice()],|row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check selected source reference authority" })?;
            if invalid { return Err(Code::Denied.error("selected source reference authority")); }
            Ok(())
        })();
        let cleanup = reader.execute_batch("DROP TABLE native_source_check")
            .context(AnalysisDatabaseSnafu { operation:"release selected source reference check" });
        checked?;
        cleanup?;
        for (record,reference) in &source.proofs {
            if source.records.binary_search_by(|(id,_)| id.cmp(record)).is_err()
                || source.derived.binary_search_by(|value| value.key.cmp(&reference.key))
                    .ok().is_none_or(|index| source.derived[index]!=*reference)
            { return Err(Code::Denied.error("selected source record proof")); }
        }
        Ok(())
    }

    fn check_source_coverage(
        reader: &Connection,source: &crate::EvidenceIntakeIdentityV1,result: &str,cut: u64,time: u64,
        step: &crate::analysis::managed::model::SourceStep,
    ) -> Result<()> {
        let (cpu,cursor,coverage,floor,published,report,expired): (u32,u64,u64,u64,u64,Option<Vec<u8>>,bool) = reader.query_row(
            "SELECT version.cpu_id,version.contiguous_cursor,version.coverage_revision,version.retained_floor,
                publication.coverage_revision,coverage.report,publication.expired
             FROM managed_source_publications publication JOIN source_versions version
                ON version.stream_key=publication.stream_key AND version.tenant_id=publication.tenant_id
                AND version.commit_revision<=?
             LEFT JOIN coverage ON coverage.stream_key=version.stream_key AND coverage.tenant_id=version.tenant_id
                AND coverage.revision=version.coverage_revision AND coverage.commit_revision<=?
             WHERE publication.result_id=? ORDER BY version.commit_revision DESC LIMIT 1",
            params![cut,cut,result],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).context(AnalysisDatabaseSnafu { operation:"check selected source coverage receipt" })?;
        if expired!=step.expired || expired!=(step.first<=floor || step.deadline<=time) {
            return Err(Code::Conflict.error("selected source expiry authority"));
        }
        if published!=coverage { return Err(Code::Conflict.error("selected source coverage revision")); }
        let receipt = crate::AnalysisSourceReceiptV1 { identity:source.clone(),cpu_id:cpu,
            contiguous_cursor:cursor,coverage_revision:coverage,retained_floor:floor };
        let report = report.map(|bytes| receipt.decode_coverage(&bytes,&mut |_| Ok(()))).transpose()?;
        if coverage!=0 && report.is_none() { return Err(Code::Missing.error("selected source coverage report")); }
        let mut intervals = BTreeMap::new();
        for interval in report.iter().flat_map(|report| &report.intervals) {
            if interval.source_epoch!=source.source_epoch { continue; }
            let id = <[u8;16]>::try_from(interval.interval_id.as_slice())
                .map_err(|_| Code::Invalid.error("selected source coverage interval"))?;
            if intervals.insert(id,interval).is_some() { return Err(Code::Invalid.error("selected source coverage duplicate")); }
        }
        for key in &step.coverage {
            let interval = intervals.get(&key.interval_id)
                .ok_or_else(|| Code::Denied.error("selected source coverage interval"))?;
            use crate::DiscoveryCoverageStateV1 as State;
            let state = match key.state {
                State::Healthy => interval.is_complete() && !interval.has_gap() && interval.state!="CLOSED",
                State::Closed => interval.is_complete() && !interval.has_gap() && interval.state=="CLOSED",
                State::Gapped => interval.has_gap(),
                State::Unknown => true,
            };
            let mut reasons = if !interval.gap_reasons.is_empty() { interval.gap_reasons.clone() }
                else if interval.has_gap() { vec!["SOURCE_COVERAGE_GAPPED".into()] }
                else if key.state==State::Unknown { vec!["COVERAGE_UNQUALIFIED".into()] } else { Vec::new() };
            reasons.sort();reasons.dedup();
            if key.source!=*source || key.cpu_id!=cpu || key.report_revision!=coverage
                || key.interval_revision!=interval.revision || !state || key.gap_reasons!=reasons
            { return Err(Code::Denied.error("selected source coverage authority")); }
        }
        Ok(())
    }
}
