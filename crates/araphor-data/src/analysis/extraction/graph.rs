use snafu::ResultExt as _;

use super::super::graph_rows::{GraphHeader, GraphRows};
use super::*;

mod native;
#[cfg(test)]
mod tests;
mod traversal;

impl AnalysisExtractionV1 {
    pub(super) fn capture_graph(
        &mut self,
        id: &str,
        graph: &crate::GraphSnapshotV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut coverage = sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        };
        {
            let mut budget = self.sink(control);
            if graph.input_manifest.coverage.is_empty() {
                coverage.state = sdk::CoverageState::Unknown;
            }
            for range in &graph.input_manifest.coverage {
                budget.check()?;
                match range.state {
                    crate::DiscoveryCoverageStateV1::Gapped => {
                        coverage.state = sdk::CoverageState::Gapped
                    }
                    crate::DiscoveryCoverageStateV1::Unknown
                        if coverage.state != sdk::CoverageState::Gapped =>
                    {
                        coverage.state = sdk::CoverageState::Unknown
                    }
                    _ => {}
                }
                for reason in &range.gap_reasons {
                    if coverage.limits.contains(reason) {
                        continue;
                    }
                    budget.grow(&mut coverage.limits)?;
                    budget.charge(reason.len())?;
                    coverage.limits.push(reason.clone());
                }
            }
            if !graph.missing_ranges.is_empty() {
                coverage.state = sdk::CoverageState::Gapped;
                let reason = "GRAPH_INPUT_GAPS";
                if !coverage.limits.iter().any(|limit| limit == reason) {
                    budget.grow(&mut coverage.limits)?;
                    budget.charge(reason.len())?;
                    coverage.limits.push(reason.into());
                }
            }
        }
        coverage.limits.sort_unstable();
        self.charge(id.len())?;
        let added = Self::grow(
            &mut self.graph_coverage,
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.graph_coverage.push((id.into(), coverage));
        Ok(())
    }
}

impl AnalysisStore {
    pub(super) fn graph_contexts(
        &self,
        snapshot: &Connection,
        tenant: [u8; 16],
        result_id: &str,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<crate::AnalysisContextRefV1>> {
        control.check()?;
        if Self::native_graph_result(snapshot, result_id)? {
            let (count,bytes): (u64,u64) = snapshot.query_row(
                "SELECT count(*),coalesce(sum(octet_length(encode(owner_id))+octet_length(entity_key)
                    +octet_length(lifetime_key)),0)::UBIGINT FROM context_refs WHERE tenant_id=? AND ref_id=?",
                params![tenant.as_slice(),result_id],|row| Ok((row.get(0)?,row.get(1)?)),
            ).context(AnalysisDatabaseSnafu { operation:"bound native graph context references" })?;
            let bytes = usize::try_from(bytes)
                .ok()
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| {
                    bytes.checked_add(
                        usize::try_from(count)
                            .ok()?
                            .checked_mul(2 * std::mem::size_of::<crate::AnalysisContextRefV1>())?,
                    )
                })
                .ok_or_else(|| {
                    crate::PackageErrorCodeV1::Limit.error("native graph context references")
                })?;
            output.charge(bytes)?;
            let contexts = snapshot.prepare(
                "SELECT owner_id,entity_key,lifetime_key,owner_revision,commit_revision FROM context_refs
                 WHERE tenant_id=? AND ref_id=? ORDER BY owner_id,entity_key,lifetime_key,owner_revision",
            ).and_then(|mut query| query.query_map(params![tenant.as_slice(),result_id],|row| Ok(crate::AnalysisContextRefV1 {
                key: AnalysisContextKeyV1 { tenant_id:tenant,owner_id:row.get(0)?,entity_key:row.get(1)?,
                    lifetime_key:row.get(2)?,owner_revision:row.get(3)? },commit_revision:row.get(4)?,
            }))?.collect::<duckdb::Result<Vec<_>>>())
                .context(AnalysisDatabaseSnafu { operation:"read native graph context references" })?;
            return Ok(contexts);
        }
        let (metadata, revision): (Vec<u8>, u64) = snapshot
            .query_row(
                "SELECT request_meta,commit_revision FROM analysis_results
             WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                params![tenant.as_slice(), result_id, crate::GRAPH_PROCESSOR],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read captured graph attribution",
            })?;
        output.scan(metadata.len())?;
        output.charge(metadata.len())?;
        let (_, contexts) = Self::decode_evidence(
            snapshot,
            &super::super::PackageResultRefV1 {
                result_id: result_id.to_owned(),
                commit_revision: revision,
            },
            crate::GRAPH_PROCESSOR,
            &metadata,
            Some(control),
            &mut |scan, input| {
                output.scan(scan)?;
                output.charge(input)
            },
        )?;
        if contexts
            .iter()
            .any(|reference| reference.key.tenant_id != tenant)
        {
            return self.reject("the graph attribution has a foreign tenant");
        }
        Ok(contexts)
    }

    pub(super) fn extract_graph_state(
        &self,
        snapshot: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("graph_state").is_none() {
            return Ok(());
        }
        control.check()?;
        let source = &receipt.identity;
        let key = source.key();
        output.charge(key.capacity())?;
        let state = snapshot
            .query_row(
                "SELECT p.class, p.start_cursor, p.consumed_cursor, p.resume_floor,
                p.retired, NULLIF(p.result_id, '') FROM source_receipts s
             LEFT JOIN (SELECT * FROM processor_versions
                WHERE processor_id = ? AND method_version = ? AND tenant_id = ?
                    AND stream_key = ? AND commit_revision <= ?
                ORDER BY commit_revision DESC LIMIT 1) p
                ON p.tenant_id = s.tenant_id AND p.stream_key = s.stream_key
             WHERE s.tenant_id = ? AND s.stream_key = ?",
                params![
                    crate::GRAPH_PROCESSOR,
                    u64::from(crate::GRAPH_SCHEMA_VERSION),
                    source.tenant_id.as_slice(),
                    key.as_slice(),
                    output.meta.commit_revision,
                    source.tenant_id.as_slice(),
                    key.as_slice()
                ],
                |row| {
                    Ok(tables::GraphState {
                        class: row.get(0)?,
                        start: row.get(1)?,
                        consumed: row.get(2)?,
                        resumed: row.get(3)?,
                        retired: row.get(4)?,
                        result: row.get(5)?,
                    })
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read captured graph progress",
            })?;
        output.charge(
            state.class.as_ref().map_or(0, String::capacity)
                + state.result.as_ref().map_or(0, String::capacity),
        )?;
        capture.graph_state(receipt, &state, &mut output.sink(control))?;
        Ok(())
    }

    pub(super) fn extract_graph_coverage(
        &self,
        snapshot: &Connection,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("graph_coverage").is_none() {
            return Ok(());
        }
        let frozen = std::mem::take(&mut capture.graph_coverage);
        let sources = std::mem::take(&mut output.sources);
        for source in &sources {
            control.check()?;
            let selected = frozen
                .iter()
                .filter(|(identity, _)| *identity == source.receipt.identity)
                .map(|(_, revision)| *revision)
                .collect();
            let reports = self.graph_coverage_from(
                snapshot,
                &source.receipt.identity,
                &selected,
                |count, bytes| {
                    output.scan(bytes)?;
                    output.charge(
                        bytes
                            .checked_add(
                                count.checked_mul(size_of::<(u64, Vec<u8>)>()).ok_or_else(
                                    || self.state_error("the coverage allocation overflows"),
                                )?,
                            )
                            .ok_or_else(|| self.state_error("the coverage allocation overflows"))?,
                    )
                },
            )?;
            for (revision, bytes) in reports {
                control.check()?;
                let mut receipt = source.receipt.clone();
                receipt.coverage_revision = revision;
                let report =
                    tables::Capture::coverage_report(&bytes, &receipt, &mut output.sink(control))?;
                capture.coverage(
                    "graph_coverage",
                    &receipt,
                    ("receipt", "reported"),
                    None,
                    None,
                    &mut output.sink(control),
                )?;
                for interval in &report.intervals {
                    capture.coverage(
                        "graph_coverage",
                        &receipt,
                        ("interval", &interval.state),
                        None,
                        Some(interval),
                        &mut output.sink(control),
                    )?;
                }
            }
            if source.receipt.coverage_revision == 0 {
                capture.coverage(
                    "graph_coverage",
                    &source.receipt,
                    ("receipt", "unknown"),
                    None,
                    None,
                    &mut output.sink(control),
                )?;
            }
        }
        output.sources = sources;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The Graph read keeps its projection and scope checks explicit."
    )]
    pub(super) fn graph_input(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        result_id: &str,
        control: &AnalysisReadControl,
        read: &AnalysisTableRead<'_>,
        findings: bool,
        finding_value_ids: bool,
        output: &mut AnalysisExtractionV1,
    ) -> Result<GraphHeader> {
        control.check()?;
        let tenant = selection.tenant_id;
        let length:u64=snapshot.query_row("SELECT octet_length(body) FROM analysis_results WHERE tenant_id=? AND result_id=? AND processor_id=?",
            params![tenant.as_slice(),result_id,crate::GRAPH_PROCESSOR],|row|row.get(0))
            .context(AnalysisDatabaseSnafu {operation:"bound captured Graph header"})?;
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        output.scan(length)?;
        output.charge(length.saturating_mul(2))?;
        let complete = read.projects_field("graph_manifest", "snapshot");
        let full = complete
            || !selection.binding_ids.is_empty()
            || ["graph_revision", "metadata", "context_refs"]
                .iter()
                .any(|field| read.projects_field("graph_manifest", field))
            || ["graph_subjects", "relationships", "correlation_packages"]
                .iter()
                .any(|name| read.projected(name).is_some());
        let selected = if complete {
            GraphRows::read_header_control(snapshot, tenant, result_id, Some(control))?
        } else if !full {
            let summary = GraphRows::read_summary(snapshot, tenant, result_id, Some(control))?;
            if summary
                .as_ref()
                .is_some_and(|header| header.restricted_count.is_some())
            {
                summary
            } else {
                GraphRows::read_metadata_control(snapshot, tenant, result_id, Some(control))?
            }
        } else {
            GraphRows::read_metadata_control(snapshot, tenant, result_id, Some(control))?
        };
        let mut header =
            selected.ok_or_else(|| self.state_error("the selected graph header is absent"))?;
        if complete || findings {
            GraphRows::bound_findings(
                    &self.graph_engine,
                snapshot,
                result_id,
                None,
                &header.snapshot.scope.identity,
                &mut |scan, input| {
                    output.scan(scan)?;
                    output.charge(input)
                },
            )?;
        }
        if complete {
            let (graph, ids) = GraphRows::read_control_with_ids(
                snapshot,
                result_id,
                &header,
                Some(control),
                finding_value_ids,
            )?;
            header.snapshot = graph;
            header.finding_value_ids = ids;
        } else if findings {
            if finding_value_ids {
                let (findings, ids) =
                    GraphRows::read_findings_with_ids(snapshot, result_id, &header, Some(control))?;
                header.snapshot.findings = findings;
                header.finding_value_ids = ids;
            } else {
                header.snapshot.findings =
                    GraphRows::read_findings(snapshot, result_id, &header, Some(control))?;
            }
            if header.derive_branches {
                header.snapshot.graph.branches = GraphRows::branches(&header.snapshot.findings);
            }
        }
        if (complete || findings) && header.snapshot.findings.len() != header.finding_count {
            return self.reject("the selected graph finding count differs");
        }
        if findings && !complete && full {
            header.snapshot.validate()?;
        }
        Ok(header)
    }
}

impl AnalysisStore {
    pub(super) fn extract_graph_tables(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
    ) -> Result<()> {
        owners.check_reader(snapshot, selection.tenant_id)?;
        if let Some(request) = &selection.graph_traversal {
            self.traverse_graphs(
                snapshot,
                selection,
                request,
                output,
                control,
                capture,
                read.projects_field("findings", "finding_value_id"),
            )?;
        }
        let complete_graph = read.projects_field("graph_manifest", "snapshot");
        let graph_contexts = read.projects_field("graph_manifest", "context_refs");
        let graph_findings = ["findings", "policy_observations", "graph_branches"]
            .iter()
            .any(|name| read.projected(name).is_some())
            || !selection.binding_ids.is_empty();
        for id in selection
            .graphs
            .as_slice()
            .iter()
            .filter(|_| selection.graph_traversal.is_none())
        {
            control.check()?;
            let source: bool = snapshot
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_source_publications WHERE result_id=?)",
                    params![id],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "classify Graph publication scope",
                })?;
            if !source {
                if let Some(owner) =
                    owners.publication(snapshot, selection.tenant_id, id, &mut |scan, bytes| {
                        output.scan(scan)?;
                        output.charge(bytes)
                    })?
                {
                    self.extract_definition_graph(
                        snapshot,
                        scope,
                        id,
                        owner.revision(),
                        owner.grant(),
                        read,
                        output,
                        capture,
                        control,
                        owners,
                    )?;
                    continue;
                }
            }
            if let Some(header) = Self::native_source_header_bound(
                snapshot,
                selection.tenant_id,
                id,
                &mut |scan, bytes| {
                    output.scan(scan)?;
                    output.charge(bytes)
                },
            )? {
                if self.extract_native_graph(
                    snapshot, selection, id, &header, read, output, capture, control,
                )? {
                    continue;
                }
            }
            let (key, revision): (Vec<u8>, u64) = snapshot
                .query_row(
                    "SELECT stream_key, commit_revision FROM analysis_results
                 WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND result_id = ?
                    AND stream_key IS NOT NULL",
                    params![
                        selection.tenant_id.as_slice(),
                        crate::GRAPH_PROCESSOR,
                        crate::GRAPH_SCHEMA_VERSION,
                        id
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read graph result metadata",
                })?;
            let source = selection
                .sources
                .as_slice()
                .iter()
                .find(|source| source.key() == key)
                .ok_or_else(|| self.state_error("the graph result source is not selected"))?;
            let subjects = read.projected("graph_subjects").is_some();
            let edges = read.projected("relationships").is_some();
            let header = self.graph_input(
                snapshot,
                selection,
                id,
                control,
                read,
                graph_findings,
                read.projects_field("findings", "finding_value_id"),
                output,
            )?;
            let sensitivity = self.graph_sensitivity(snapshot, &header, control)?;
            let mut graph = header.snapshot;
            if graph.scope.identity != *source {
                return self.reject("the graph source differs from its index");
            }
            if !selection.permits_graph(&graph) {
                continue;
            }
            if (subjects || edges) && !complete_graph {
                graph.graph.subjects =
                    GraphRows::read_subjects(snapshot, id, header.subject_count, Some(control))?;
                if graph.graph.subjects.len() != header.subject_count {
                    return self.reject("the selected graph subject count differs");
                }
            }
            if edges && !complete_graph {
                graph.graph.edges =
                    GraphRows::read_edges(snapshot, id, header.edge_count, Some(control))?;
                if graph.graph.edges.len() != header.edge_count {
                    return self.reject("the selected graph relationship count differs");
                }
            }
            if !complete_graph && (subjects || edges) {
                graph.validate()?;
            }
            output.capture_graph(id, &graph, control)?;
            let contexts = if graph_contexts {
                self.graph_contexts(snapshot, selection.tenant_id, id, output, control)?
            } else {
                Vec::new()
            };
            output.reference_result(id, revision, AnalysisReferenceOriginV1::Graph)?;
            capture.graph(
                id,
                &graph,
                &header.finding_value_ids,
                header.subject_count,
                header.edge_count,
                revision,
                sensitivity,
                None,
                None,
                &contexts,
                header.notice,
                header.expired,
                header.restricted_count,
                &mut output.sink(control),
            )?;
        }
        self.extract_graph_coverage(snapshot, read, output, capture, control)?;
        Ok(())
    }
}
