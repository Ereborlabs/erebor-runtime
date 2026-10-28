use snafu::ResultExt as _;

use super::super::graph_rows::{GraphHeader, GraphRows};
use super::*;

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
        let length: u64 = snapshot
            .query_row(
                "SELECT octet_length(request_meta) FROM analysis_results
             WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                params![tenant.as_slice(), result_id, crate::GRAPH_PROCESSOR],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound captured graph attribution",
            })?;
        let length = usize::try_from(length)
            .map_err(|_| self.state_error("the graph attribution length is invalid"))?;
        output.scan(length)?;
        output.charge(length.saturating_mul(2))?;
        let metadata: Vec<u8> = snapshot
            .query_row(
                "SELECT request_meta FROM analysis_results
             WHERE tenant_id = ? AND result_id = ? AND processor_id = ?",
                params![tenant.as_slice(), result_id, crate::GRAPH_PROCESSOR],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read captured graph attribution",
            })?;
        let (_, contexts) = Self::decode_evidence(crate::GRAPH_PROCESSOR, &metadata)?;
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
             LEFT JOIN processor_progress p ON p.tenant_id = s.tenant_id
                AND p.stream_key = s.stream_key AND p.processor_id = ? AND p.method_version = ?
             WHERE s.tenant_id = ? AND s.stream_key = ?",
                params![
                    crate::GRAPH_PROCESSOR,
                    u64::from(crate::GRAPH_SCHEMA_VERSION),
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

    pub(super) fn graph_input(
        &self,
        snapshot: &Connection,
        tenant: [u8; 16],
        result_id: &str,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        complete: bool,
    ) -> Result<GraphHeader> {
        control.check()?;
        let length: u64 = snapshot
            .query_row(
                "SELECT octet_length(body) FROM analysis_results
             WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND result_id = ?
                AND stream_key IS NOT NULL",
                params![
                    tenant.as_slice(),
                    crate::GRAPH_PROCESSOR,
                    crate::GRAPH_SCHEMA_VERSION,
                    result_id
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read graph header length",
            })?;
        let length = usize::try_from(length)
            .map_err(|_| self.state_error("the graph header length is invalid"))?;
        output.scan(length)?;
        output.charge(length.saturating_mul(2))?;
        let mut header = GraphRows::read_header(snapshot, tenant, result_id)?
            .ok_or_else(|| self.state_error("the selected graph header is absent"))?;
        GraphRows::check_bytes(snapshot, result_id, &header)?;
        output.scan(header.row_bytes)?;
        output.charge(header.allocation_bytes()?)?;
        if complete {
            header.snapshot = GraphRows::read_control(snapshot, result_id, &header, Some(control))?;
        } else {
            header.snapshot.findings =
                GraphRows::read_findings(snapshot, result_id, &header, Some(control))?;
        }
        if header.snapshot.findings.len() != header.finding_count {
            return self.reject("the selected graph finding count differs");
        }
        if !complete {
            header.snapshot.validate()?;
        }
        Ok(header)
    }
}
