use std::collections::{BTreeMap, BTreeSet, VecDeque};

use prost::Message as _;
use snafu::ResultExt as _;

use super::*;
use crate::{
    AnalysisContextRefV1, AnalysisResultCommitV1, AnalysisSourceStatusV1, AnalysisStreamIdentityV1,
    AnalysisWitnessV1, CoverageReport, EvidenceIntakeIdentityV1, GraphEncodingSnafu,
    GraphInvalidSnafu, ProcessorScopeV1,
};

impl GraphAndFindingOwner {
    pub fn process(&self, now: u64) -> Result<usize> {
        if now == 0 {
            return GraphInvalidSnafu { field: "clock" }.fail();
        }
        let mut after = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let mut sources = Vec::new();
        if let Some(source) = after.as_ref() {
            sources.extend(self.store.source_page(source.tenant_id, Some(source))?);
        }
        for tenant in self
            .store
            .tenant_page(after.as_ref().map(|source| source.tenant_id))?
        {
            sources.extend(self.store.source_page(tenant, None)?);
            if sources.len() >= crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                break;
            }
        }
        sources.truncate(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS);
        *after = sources.last().cloned();
        let mut count = 0;
        for source in sources {
            let result = self.process_source(&source, now);
            if result.is_err() {
                let _health = self.store.graph_set_health(&source, true);
            }
            let processed = result?;
            self.store.graph_set_health(&source, false)?;
            count += processed;
        }
        Ok(count)
    }

    fn process_source(&self, source: &EvidenceIntakeIdentityV1, now: u64) -> Result<usize> {
        self.store.register_graph(source)?;
        let scope = Self::scope(source);
        let health = self.store.processor_health(&scope)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "required processor",
            }
            .build()
        })?;
        let consumed = health.consumed_cursor.max(health.resume_floor);
        if consumed < health.accepted_cursor {
            let step = GRAPH_WINDOW_RECORDS / 2;
            let next = consumed / step * step;
            let first = next.saturating_sub(step) + 1;
            let last = next
                .checked_add(step)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "window cursor",
                    }
                    .build()
                })?
                .min(health.accepted_cursor);
            if self.commit_window(source, first, last, consumed, true, now, false)? {
                return Ok(1);
            }
        } else {
            return Ok(usize::from(self.refresh_source(source, now, false)?));
        }
        Ok(0)
    }

    pub fn refresh(&self, source: &EvidenceIntakeIdentityV1, now: u64) -> Result<bool> {
        if now == 0 || !source.valid() {
            return GraphInvalidSnafu {
                field: "refresh source",
            }
            .fail();
        }
        let _operation = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let result = self.refresh_source(source, now, true);
        if result.is_err() {
            let _health = self.store.graph_set_health(source, true);
        }
        let changed = result?;
        self.store.graph_set_health(source, false)?;
        Ok(changed)
    }

    fn refresh_source(
        &self,
        source: &EvidenceIntakeIdentityV1,
        now: u64,
        force: bool,
    ) -> Result<bool> {
        let health = self
            .store
            .processor_health(&Self::scope(source))?
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "required processor",
                }
                .build()
            })?;
        let consumed = health.consumed_cursor.max(health.resume_floor);
        let mut after = None;
        let mut changed = false;
        loop {
            let page = self.store.graph_snapshots(
                source.tenant_id,
                Some(source),
                after.as_deref(),
                true,
            )?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.0.clone());
            for (_, snapshot, _) in page {
                changed |= self.commit_window(
                    source,
                    snapshot.first_cursor,
                    snapshot.last_cursor,
                    consumed,
                    false,
                    now,
                    force,
                )?;
            }
        }
        Ok(changed)
    }

    pub(super) fn scope(source: &EvidenceIntakeIdentityV1) -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: u64::from(GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_window(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        force: bool,
    ) -> Result<bool> {
        let status = self.store.source_status(source)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "source status",
            }
            .build()
        })?;
        let notice = self.provider.revision(source)?;
        let mut heads = BTreeMap::new();
        let mut after = None;
        loop {
            let page = self.store.graph_snapshots(
                source.tenant_id,
                Some(source),
                after.as_deref(),
                true,
            )?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.0.clone());
            for row in page {
                if row.1.first_cursor <= last && row.1.last_cursor >= first {
                    heads.insert(row.1.first_cursor, row);
                }
            }
        }
        let previous = heads.get(&first);
        if !advance
            && !force
            && previous.as_ref().is_some_and(|(_, snapshot, _)| {
                snapshot.context_notice_revision == notice
                    && snapshot
                        .input_manifest
                        .coverage
                        .iter()
                        .map(|key| key.report_revision)
                        .max()
                        .unwrap_or(0)
                        == status.receipt.coverage_revision
            })
        {
            return Ok(false);
        }
        if let Some((id, snapshot, _)) = previous {
            if snapshot.witness_deadline_utc_ns <= now
                || snapshot.first_cursor <= status.receipt.retained_floor
            {
                let changed = self.expire_window(
                    id,
                    snapshot,
                    consumed,
                    status.receipt.coverage_revision,
                    notice,
                    now,
                )?;
                if advance {
                    return self.commit_window(
                        source,
                        consumed.saturating_add(1),
                        last,
                        consumed,
                        true,
                        now,
                        force,
                    );
                }
                return Ok(changed);
            }
        }
        let read_first = first.max(status.receipt.retained_floor.saturating_add(1));
        if read_first > first && previous.is_some() {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: last.min(status.receipt.retained_floor),
            }
            .fail();
        }
        let mut records = Vec::new();
        let mut positions = Vec::new();
        let mut cursor = read_first;
        while cursor <= last {
            let page = self.store.read_page(source, cursor)?;
            let mut read = 0;
            for accepted in page
                .records
                .into_iter()
                .take_while(|record| record.cursor <= last)
            {
                let record =
                    crate::DiscoveryRecordV1::try_from((source, status.receipt.cpu_id, &accepted))?;
                positions.push((record.id.clone(), accepted.position));
                cursor = accepted.cursor.checked_add(1).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "read cursor",
                    }
                    .build()
                })?;
                records.push(record);
                read += 1;
            }
            if read == 0 {
                return GraphInvalidSnafu {
                    field: "contiguous graph input",
                }
                .fail();
            }
        }
        let mut facts = BTreeMap::new();
        let record_ids: BTreeSet<_> = records.iter().map(|record| record.id.clone()).collect();
        for (_, snapshot, _) in heads.values() {
            for key in &snapshot.input_manifest.context {
                let fact = self.store.context_version(key)?.ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "frozen context version",
                    }
                    .build()
                })?;
                if record_ids.contains(&GraphFactV1::try_from(&fact)?.record_id) {
                    facts.insert(key.clone(), fact);
                }
            }
        }
        for record in &records {
            for fact in self.provider.facts(record)? {
                if facts
                    .insert(fact.key.clone(), fact.clone())
                    .is_some_and(|previous| previous != fact)
                {
                    return GraphInvalidSnafu {
                        field: "changed immutable context",
                    }
                    .fail();
                }
            }
        }
        let mut by_record: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for fact in facts.into_values() {
            by_record
                .entry(GraphFactV1::try_from(&fact)?.record_id)
                .or_default()
                .push(fact);
        }
        let mut chunks = VecDeque::new();
        let mut chunk = Vec::new();
        let mut context_count = 0;
        for record in records {
            let count = by_record.get(&record.id).map_or(0, Vec::len);
            if count > 256 {
                return GraphInvalidSnafu {
                    field: "one observation context bound",
                }
                .fail();
            }
            if !chunk.is_empty() && context_count + count > 256 {
                chunks.push_back(std::mem::take(&mut chunk));
                context_count = 0;
            }
            context_count += count;
            chunk.push(record);
        }
        if !chunk.is_empty() {
            chunks.push_back(chunk);
        }
        let mut changed = false;
        while let Some(records) = chunks.pop_front() {
            let chunk_first = records
                .first()
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "bounded window",
                    }
                    .build()
                })?
                .id
                .durable_cursor;
            let chunk_last = records
                .last()
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "bounded window",
                    }
                    .build()
                })?
                .id
                .durable_cursor;
            if advance && chunk_last <= consumed {
                continue;
            }
            let selected: BTreeSet<_> = records.iter().map(|record| record.id.clone()).collect();
            let facts = records
                .iter()
                .flat_map(|record| by_record.get(&record.id).into_iter().flatten().cloned())
                .collect();
            let positions = positions
                .iter()
                .filter(|(id, _)| selected.contains(id))
                .cloned()
                .collect();
            let prior = heads
                .get(&chunk_first)
                .or_else(|| (chunk_first == read_first).then_some(previous).flatten());
            let mut missing_ranges =
                prior.map_or_else(Vec::new, |(_, snapshot, _)| snapshot.missing_ranges.clone());
            if status.receipt.retained_floor >= first && previous.is_none() {
                missing_ranges.push((1, status.receipt.retained_floor));
            }
            if chunk_first > read_first {
                missing_ranges.push((read_first, chunk_first - 1));
            }
            missing_ranges.sort();
            missing_ranges.dedup();
            let deadline = heads
                .values()
                .filter(|(_, snapshot, _)| {
                    snapshot
                        .input_manifest
                        .evidence
                        .iter()
                        .any(|id| selected.contains(id))
                })
                .map(|(_, snapshot, _)| snapshot.witness_deadline_utc_ns)
                .min()
                .unwrap_or(now.checked_add(GRAPH_WITNESS_TTL_NS).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "witness deadline",
                    }
                    .build()
                })?);
            let header_first = if chunk_first == read_first {
                first
            } else {
                chunk_first
            };
            let frozen_coverage = heads
                .values()
                .flat_map(|(_, snapshot, _)| &snapshot.input_manifest.coverage)
                .cloned()
                .collect();
            let result = self.commit_bounded_window(
                &status,
                header_first,
                chunk_last,
                consumed,
                advance,
                now,
                notice,
                deadline,
                records.clone(),
                positions,
                facts,
                missing_ranges,
                frozen_coverage,
                prior,
            )?;
            let Some(committed) = result else {
                if records.len() < 2 {
                    return GraphInvalidSnafu {
                        field: "one observation result bound",
                    }
                    .fail();
                }
                let midpoint = records.len() / 2;
                let mut prefix = records;
                let tail = prefix.split_off(midpoint);
                chunks.push_front(tail);
                chunks.push_front(prefix);
                continue;
            };
            changed |= committed;
            if advance {
                break;
            }
        }
        Ok(changed)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_bounded_window(
        &self,
        status: &AnalysisSourceStatusV1,
        first: u64,
        last: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        notice: u64,
        deadline: u64,
        records: Vec<crate::DiscoveryRecordV1>,
        positions: Vec<(crate::DiscoveryRecordIdV1, crate::StorePositionV1)>,
        facts: Vec<crate::AnalysisContextVersionV1>,
        missing_ranges: Vec<(u64, u64)>,
        frozen_coverage: Vec<GraphCoverageKeyV1>,
        previous: Option<&(String, GraphSnapshotV1, u64)>,
    ) -> Result<Option<bool>> {
        let source = &status.receipt.identity;
        let (coverage, coverage_keys) = self.coverage(status, &records, &frozen_coverage)?;
        let input = GraphReplayInputV1 {
            source: source.clone(),
            records,
            coverage,
            coverage_keys,
            facts,
            missing_ranges,
        };
        let mut snapshot = Self::derive(&input)?;
        snapshot.first_cursor = first;
        snapshot.input_positions = positions;
        snapshot.context_notice_revision = notice;
        snapshot.witness_deadline_utc_ns = deadline;
        if previous.as_ref().is_some_and(|(_, previous, _)| {
            previous.input_manifest == snapshot.input_manifest
                && previous.graph == snapshot.graph
                && previous.findings == snapshot.findings
        }) {
            return Ok(Some(false));
        }
        snapshot.previous_result_id = previous.as_ref().map(|row| row.0.clone());
        snapshot.validate()?;
        let body = serde_json::to_vec(&snapshot).context(GraphEncodingSnafu)?;
        if body.len() > GRAPH_WINDOW_BYTES.min(crate::analysis::MAX_RESULT_BYTES) {
            return Ok(None);
        }
        let mut references = Vec::new();
        for fact in &input.facts {
            let commit_revision = self.store.commit_context(fact)?;
            references.push(AnalysisContextRefV1 {
                key: fact.key.clone(),
                commit_revision,
            });
        }
        references.sort_by(|left, right| left.key.cmp(&right.key));
        let expires = snapshot.witness_deadline_utc_ns;
        let witness_ids: BTreeSet<_> = snapshot.input_manifest.evidence.iter().cloned().collect();
        let witnesses = witness_ids
            .into_iter()
            .map(|id| AnalysisWitnessV1 {
                identity: AnalysisStreamIdentityV1::Evidence(id.stream),
                cursor: id.durable_cursor,
                expires_utc_ns: expires,
            })
            .collect();
        let commit = AnalysisResultCommitV1 {
            scope: Self::scope(source),
            expected_cursor: consumed,
            consumed_cursor: if advance { last } else { consumed },
            coverage_revision: status.receipt.coverage_revision,
            context_revision: references
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: format!("graph:{}", uuid::Uuid::new_v4()),
            body,
            created_utc_ns: now,
            witnesses,
            context_refs: references,
        };
        self.store.commit_graph(&commit, advance)?;
        Ok(Some(true))
    }

    fn expire_window(
        &self,
        result_id: &str,
        previous: &GraphSnapshotV1,
        consumed: u64,
        coverage_revision: u64,
        notice: u64,
        now: u64,
    ) -> Result<bool> {
        if previous.findings.iter().all(|finding| {
            finding
                .limits
                .iter()
                .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
        }) && previous
            .missing_ranges
            .contains(&(previous.first_cursor, previous.last_cursor))
        {
            return Ok(false);
        }
        let mut snapshot = previous.clone();
        snapshot.previous_result_id = Some(result_id.into());
        snapshot.context_notice_revision = notice;
        snapshot
            .missing_ranges
            .push((previous.first_cursor, previous.last_cursor));
        snapshot.missing_ranges.sort();
        snapshot.missing_ranges.dedup();
        snapshot.input_manifest.missing_ranges = snapshot.missing_ranges.clone();
        snapshot.graph.revision = snapshot.input_manifest.clone();
        for edge in &mut snapshot.graph.edges {
            edge.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            edge.key.cause = GraphCauseV1::Superseded;
        }
        snapshot
            .graph
            .edges
            .sort_by(|left, right| left.key.cmp(&right.key));
        snapshot
            .graph
            .edges
            .dedup_by(|left, right| left.key == right.key);
        for branch in &mut snapshot.graph.branches {
            branch.state = GraphBranchStateV1::CoverageUnknown;
            branch.missing_fields.push("RETAINED_INPUT_EXPIRED".into());
            branch.missing_fields.sort();
            branch.missing_fields.dedup();
        }
        for finding in &mut snapshot.findings {
            finding.revision = snapshot.input_manifest.clone();
            finding.state = FindingStateV1::CoverageInsufficient;
            finding.limits.push("RETAINED_INPUT_EXPIRED".into());
            finding
                .limits
                .push("LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into());
            finding.limits.sort();
            finding.limits.dedup();
            for effect in &mut finding.effects {
                effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            }
        }
        for package in &mut snapshot.packages {
            package.state = GraphPackageStateV1::CoverageInsufficient;
        }
        snapshot.validate()?;
        let mut references = Vec::new();
        for key in &snapshot.input_manifest.context {
            let fact = self.store.context_version(key)?.ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "expired graph context",
                }
                .build()
            })?;
            references.push(AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: self.store.commit_context(&fact)?,
            });
        }
        self.store.commit_graph(
            &AnalysisResultCommitV1 {
                scope: snapshot.scope.clone(),
                expected_cursor: consumed,
                consumed_cursor: consumed,
                coverage_revision,
                context_revision: references
                    .iter()
                    .map(|reference| reference.commit_revision)
                    .max()
                    .unwrap_or(0),
                result_id: format!("graph:{}", uuid::Uuid::new_v4()),
                body: serde_json::to_vec(&snapshot).context(GraphEncodingSnafu)?,
                created_utc_ns: now,
                witnesses: vec![],
                context_refs: references,
            },
            false,
        )?;
        Ok(true)
    }

    fn coverage(
        &self,
        status: &AnalysisSourceStatusV1,
        records: &[crate::DiscoveryRecordV1],
        frozen: &[GraphCoverageKeyV1],
    ) -> Result<(Vec<crate::DiscoveryCoverageV1>, Vec<GraphCoverageKeyV1>)> {
        let mut ranges = Vec::new();
        let mut keys = Vec::new();
        let intervals: BTreeSet<_> = records
            .iter()
            .filter_map(|record| {
                record
                    .decode()
                    .ok()
                    .and_then(|wire| <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).ok())
            })
            .collect();
        let revisions = frozen
            .iter()
            .filter(|key| {
                key.source == status.receipt.identity && intervals.contains(&key.interval_id)
            })
            .map(|key| key.report_revision)
            .collect();
        for (revision, bytes) in self
            .store
            .graph_coverage_versions(&status.receipt.identity, &revisions)?
        {
            let report =
                CoverageReport::decode(bytes.as_slice()).context(crate::EvidenceDecodeSnafu {
                    frame_bytes: bytes.len(),
                })?;
            if !report.intervals.iter().any(|interval| {
                <[u8; 16]>::try_from(interval.interval_id.as_slice())
                    .is_ok_and(|id| intervals.contains(&id))
            }) {
                continue;
            }
            let mut version = status.clone();
            version.receipt.coverage_revision = revision;
            version.latest_coverage_report = Some(bytes);
            let qualified = crate::DiscoveryOwner::coverage(&version, records)?;
            for range in &qualified {
                let interval_revision = report
                    .intervals
                    .iter()
                    .find(|interval| interval.interval_id.as_ref() == range.coverage_interval_id)
                    .map_or(0, |interval| interval.revision);
                let mut gaps = range.gap_reasons.clone();
                gaps.sort();
                gaps.dedup();
                keys.push(GraphCoverageKeyV1 {
                    source: status.receipt.identity.clone(),
                    cpu_id: range.cpu_id,
                    report_revision: revision,
                    interval_id: range.coverage_interval_id,
                    interval_revision,
                    state: range.state,
                    gap_reasons: gaps,
                });
            }
            ranges.extend(qualified);
        }
        if ranges.is_empty() {
            ranges = crate::DiscoveryOwner::coverage(status, records)?;
        }
        Ok((ranges, keys))
    }

    pub fn snapshot(&self, source: &EvidenceIntakeIdentityV1) -> Result<Option<GraphSnapshotV1>> {
        self.store
            .processor_result(&Self::scope(source))?
            .map(|result| GraphSnapshotV1::try_from(result.body.as_slice()))
            .transpose()
    }

    pub fn snapshot_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphSnapshotV1>> {
        self.store.graph_result(tenant, result_id)
    }

    pub fn findings(&self, tenant: [u8; 16]) -> Result<Vec<FindingV1>> {
        Ok(self
            .current_findings(tenant)?
            .into_iter()
            .map(|(_, finding)| finding)
            .collect())
    }

    pub fn current_findings(&self, tenant: [u8; 16]) -> Result<Vec<(String, FindingV1)>> {
        let _operation = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let mut findings = BTreeMap::new();
        let mut after = None;
        loop {
            let page = self
                .store
                .graph_snapshots(tenant, None, after.as_deref(), true)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.0.clone());
            for (result_id, snapshot, revision) in page {
                for finding in snapshot.findings {
                    let entry = findings.entry(finding.finding_id.clone()).or_insert((
                        revision,
                        result_id.clone(),
                        finding.clone(),
                    ));
                    if entry.0 < revision {
                        *entry = (revision, result_id.clone(), finding);
                    }
                }
            }
        }
        Ok(findings
            .into_values()
            .map(|(_, result_id, finding)| (result_id, finding))
            .collect())
    }

    pub fn finding_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingV1>> {
        if finding_id.is_empty() || finding_id.len() > 4096 {
            return GraphInvalidSnafu {
                field: "finding reference",
            }
            .fail();
        }
        Ok(self
            .store
            .graph_result(tenant, result_id)?
            .and_then(|snapshot| {
                snapshot
                    .findings
                    .into_iter()
                    .find(|finding| finding.finding_id == finding_id)
            }))
    }

    pub fn finding(
        &self,
        tenant: [u8; 16],
        id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
        revision.validate(tenant)?;
        let mut after = None;
        loop {
            let page = self
                .store
                .graph_snapshots(tenant, None, after.as_deref(), false)?;
            if page.is_empty() {
                return Ok(None);
            }
            after = page.last().map(|row| row.0.clone());
            for (_, snapshot, _) in page {
                if let Some(finding) = snapshot
                    .findings
                    .into_iter()
                    .find(|finding| finding.finding_id == id && &finding.revision == revision)
                {
                    return Ok(Some(finding));
                }
            }
        }
    }
}
